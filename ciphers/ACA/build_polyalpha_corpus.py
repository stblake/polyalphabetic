#!/usr/bin/env python3
"""Extract every polyalphabetic cipher colossus can attack from ACA_ciphers.csv into its
own directory and write a `<cipher>.txt` + `<cipher>.solution` pair, mirroring the layout
of ciphers/ACA/transposition/ and the substitution corpus (build_subst_corpus.py).

Covers the polyalphabetic block -- colossus's core engine: Vigenere, Beaufort, Porta,
Quagmire I-IV, the Variant (Vigenere with the encrypt/decrypt tableau swapped, -variant),
and the autokey family (Vig/Var Autokey -> auto, Bfort Autokey -> autobeau). Unlike the
substitution sieve these ride the default reward-only quadgram table -- NO -logprob (the
polyalpha optimal-cycleword / IoC pipeline wants the reward scale, exactly like Gronsfeld).

For each cipher we:
  1. slugify (type/year/author/con) into `<type>_<year>_<author>_<con>.txt`;
  2. normalise the ciphertext to a bare A..Z stream (mod 26, NO J->I merge -- the
     polyalpha primitives are full-26-letter, unlike the 5x5-square substitutions);
  3. run colossus blind (lengths NOT pinned -- the engine estimates the period by IoC and
     sweeps the keyword lengths) with the per-type tuned schedule, capturing an honest
     single-invocation CPU time (user+sys; the solver is single-threaded);
  4. classify by dictionary word coverage and emit a `.solution` file + per-dir manifest.csv.

Note: the engine's keyword-length floor is 5 (min_keyword_len, no CLI override), so blind
Quagmire keywords shorter than 5 are out of reach -- those land as "best attempt shown".
"""
import csv, os, re, subprocess, collections, argparse
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))                  # .../ciphers/ACA
SRC  = os.path.abspath(os.path.join(HERE, "..", ".."))            # repo root
BIN  = os.path.join(SRC, "colossus")
CSV  = os.path.join(SRC, "ACA_ciphers.csv")
QUAD = os.path.join(SRC, "english_quadgrams.txt")
DICT = os.path.join(SRC, "OxfordEnglishWords.txt")
SEED = "1234"

# CSV "Type" label -> (subdir, solver -type, extra solver args). All ride the default
# quadgram reward table (no -logprob). Lengths are left blind so the engine estimates the
# period (IoC) and sweeps keyword lengths; per-type budgets scale with the search space:
# Vigenere is only a cycleword search (cheap); Quagmire IV sweeps both keyword lengths
# (j x k) on top of the period (dear); autokey defeats IoC so the period is brute-forced
# (1..maxcyclewordlen) and the per-config climbs are short but very many.
# Straight-alphabet types (Vigenere/Beaufort/Porta/Variant) have a length-1 keyword, so
# with the default -optimalcycle the climber has nothing to perturb -- each restart just
# re-derives the same deterministic optimal cycleword (a 0.1s no-op that fails on short
# text). -stochasticcycle makes restarts actually explore the cycleword (matches the
# proven Porta regression args), so the period + key are searched, not just derived.
_STRAIGHT = ["-stochasticcycle", "-maxcyclewordlen", "15"]
# Quagmire is dear blind (a swept keyword length on top of the period); budgets are sized
# for a tractable sieve, not exhaustive recovery -- ~40-80s for q1/q2/q3. Quagmire IV is
# far slower because it sweeps the pt AND ct keyword lengths independently (~49 length
# pairs vs q3's ~7 with j==k), so it gets fewer restarts to keep per-cipher time bounded.
_QUAG = ["-nrestarts", "600", "-nhillclimbs", "2000"]
_AUTO = ["-maxcyclewordlen", "15", "-nrestarts", "5000", "-nhillclimbs", "800"]
SPEC = {
    "Vigenere":      dict(dir="vigenere",  solver="vig",
                          args=_STRAIGHT + ["-nrestarts", "500", "-nhillclimbs", "1200"]),
    "Beaufort":      dict(dir="beaufort",  solver="beau",
                          args=_STRAIGHT + ["-nrestarts", "500", "-nhillclimbs", "1200"]),
    "Porta":         dict(dir="porta",     solver="porta",
                          args=_STRAIGHT + ["-nrestarts", "600", "-nhillclimbs", "1200"]),
    # Quagmire: a keyed alphabet (keyword, length swept 5..11 -- the engine's floor) on top
    # of the cycleword/period. Two unknowns make blind recovery dear and unreliable on short
    # ACA text; many land as best-attempt. Big restart budget, lengths left blind.
    "Quagmire I":    dict(dir="quagmire1", solver="q1",  args=_QUAG),
    "Quagmire II":   dict(dir="quagmire2", solver="q2",  args=_QUAG),
    "Quagmire III":  dict(dir="quagmire3", solver="q3",  args=_QUAG),
    "Quagmire IV":   dict(dir="quagmire4", solver="q4",
                          args=["-nrestarts", "300", "-nhillclimbs", "1500"]),
    # Variant: Vigenere with the encrypt/decrypt tableau swapped (C = P - K) -> vig -variant.
    "Variant":       dict(dir="variant",   solver="vig",
                          args=_STRAIGHT + ["-variant", "-nrestarts", "500", "-nhillclimbs", "1200"]),
    # Autokey family: IoC is useless (the key is plaintext-extended), so the period is
    # brute-forced. Vig/Autokey -> auto; Var Autokey -> auto -variant; Bfort -> autobeau.
    "Autokey":       dict(dir="autokey",          solver="auto", args=_AUTO),
    "Vig Autokey":   dict(dir="autokey",          solver="auto", args=_AUTO),
    "Var Autokey":   dict(dir="autokey",          solver="auto", args=_AUTO + ["-variant"]),
    "Bfort Autokey": dict(dir="autokey_beaufort", solver="autobeau", args=_AUTO),
}

# coverage thresholds (fraction of plaintext coverable by dictionary words >=4). A correct
# polyalpha break yields ordinary full English with no null insertions, but ACA plaintexts
# are short and proper-noun heavy (same population as the Gronsfeld sieve, which used
# 0.45/0.30); 0.50/0.30 cleanly separates a real solve from a wrong-key gibberish climb.
THRESH = dict(clean=0.50, part=0.30)


def slug(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def normalise_ct(raw):
    """Bare A..Z stream, mod 26 (no J->I). Returns (ct_string, length)."""
    letters = re.sub(r"[^A-Za-z]", "", raw).upper()
    return letters, len(letters)


def load_words():
    ws = set()
    with open(DICT) as f:
        for line in f:
            w = line.strip().upper()
            if 4 <= len(w) <= 14 and w.isalpha():
                ws.add(w)
    return ws, max(len(w) for w in ws)


def coverage(pt, words, maxlen):
    pt = re.sub(r"[^A-Z]", "", pt.upper())
    n = len(pt)
    if n == 0:
        return 0.0
    best = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        best[i] = best[i + 1]
        hi = min(maxlen, n - i)
        for L in range(4, hi + 1):
            if pt[i:i + L] in words and L + best[i + L] > best[i]:
                best[i] = L + best[i + L]
    return best[0] / n


def classify(cov, is_xeno):
    # Xenocrypts are foreign-language puzzles (ACA con code starts with 'X' -- French,
    # Latin, German...). The English-word coverage metric is meaningless on them (a perfect
    # French solve covers ~0.05), so don't pass/fail by it -- flag the language instead and
    # leave the recovered plaintext + score in the .solution for a human to judge.
    if is_xeno:
        return "XENOCRYPT (foreign plaintext -- English coverage N/A)"
    if cov >= THRESH["clean"]:
        return "SOLVED (clean)"
    if cov >= THRESH["part"]:
        return "PARTIAL (words recovered)"
    return "UNSOLVED (best attempt shown)"


def extract():
    seen = collections.Counter()
    jobs = []
    with open(CSV, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 10:
                continue
            typ, ct = row[8], row[9]
            if typ not in SPEC or not ct.strip():
                continue
            spec = SPEC[typ]
            year, name, con, author = row[1], row[3], row[4], row[6]
            base = f"{slug(typ)}_{year}_{slug(author)}_{slug(con)}"
            seen[base] += 1
            if seen[base] > 1:
                base = f"{base}_{seen[base]}"
            ct_str, nsym = normalise_ct(ct)
            cdir = os.path.join(HERE, spec["dir"])
            os.makedirs(cdir, exist_ok=True)
            with open(os.path.join(cdir, base + ".txt"), "w") as out:
                out.write(ct_str + "\n")
            jobs.append(dict(base=base, dir=spec["dir"], typ=typ, solver=spec["solver"],
                             args=spec["args"], year=year, name=name, con=con,
                             author=author, ct=ct_str, n=nsym,
                             xeno=con.strip().upper().startswith("X")))
    return jobs


def cmd_str(j):
    rel = os.path.relpath(os.path.join(HERE, j["dir"], j["base"] + ".txt"), SRC)
    return ("./colossus -type %s -cipher %s -ngramsize 4 -ngramfile %s %s -seed %s"
            % (j["solver"], rel, os.path.basename(QUAD), " ".join(j["args"]), SEED))


def run(j):
    cpath = os.path.join(HERE, j["dir"], j["base"] + ".txt")
    args = (["/usr/bin/time", "-p", BIN, "-type", j["solver"], "-cipher", cpath,
             "-ngramsize", "4", "-ngramfile", QUAD] + j["args"] + ["-seed", SEED])
    p = subprocess.run(args, capture_output=True, text=True, timeout=900)
    score, pt = None, ""
    for line in p.stdout.splitlines():
        if line.startswith(">>> "):
            parts = [x.strip() for x in line[4:].split(", ")]
            score, pt = float(parts[0]), parts[-1]
    cpu = 0.0
    for line in p.stderr.splitlines():
        t = line.split()
        if len(t) == 2 and t[0] in ("user", "sys"):
            cpu += float(t[1])
    return score, pt, cpu


def write_solution(j, status, score, pt, cpu):
    out = os.path.join(HERE, j["dir"], j["base"] + ".solution")
    with open(out, "w") as f:
        f.write(f"# solution for {j['base']}.txt\n")
        f.write(f"status:      {status}\n")
        f.write(f"true_type:   {j['typ']}\n")
        f.write(f"solver:      {j['solver']}\n")
        f.write(f"length:      {j['n']}  (cipher letters)\n")
        f.write(f"score:       {score:.2f}\n" if score is not None else "score:       n/a\n")
        f.write(f"solve_time:  {cpu:.2f}s  (CPU user+sys, single-threaded)\n")
        f.write(f"command:     {cmd_str(j)}\n")
        f.write(f"ciphertext:  {j['ct']}\n")
        f.write(f"plaintext:   {pt}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0, help="cap jobs PER type (smoke test)")
    ap.add_argument("--types", default="",
                    help="comma-separated CSV type labels to restrict to (e.g. Vigenere)")
    a = ap.parse_args()

    jobs = extract()
    if a.types:
        keep = {t.strip() for t in a.types.split(",")}
        jobs = [j for j in jobs if j["typ"] in keep]
    if a.limit:
        per = collections.Counter()
        capped = []
        for j in jobs:
            if per[j["typ"]] < a.limit:
                per[j["typ"]] += 1
                capped.append(j)
        jobs = capped
    print(f"extracted {len(jobs)} ciphers "
          f"({dict(collections.Counter(j['typ'] for j in jobs))})", flush=True)

    words, maxlen = load_words()
    counts = collections.Counter()
    rows = collections.defaultdict(list)

    def work(j):
        score, pt, cpu = run(j)
        cov = coverage(pt, words, maxlen)
        status = classify(cov, j["xeno"])
        write_solution(j, status, score, pt, cpu)
        return j, status, cov, cpu

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for j, status, cov, cpu in ex.map(work, jobs):
            counts[status.split()[0]] += 1
            rows[j["dir"]].append([j["base"] + ".txt", j["typ"], "Russ + digital con",
                                   j["year"], j["name"], j["con"], j["author"],
                                   "labeled", j["n"]])
            print(f"  [{status.split()[0]:8}] cov={cov:.2f} {cpu:5.1f}s  {j['base']}",
                  flush=True)

    for d, rs in rows.items():
        rs.sort()
        with open(os.path.join(HERE, d, "manifest.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["filename", "type", "source", "year", "name", "con",
                        "author", "detection", "length"])
            w.writerows(rs)

    print(f"\nwrote {sum(counts.values())} .solution files: {dict(counts)}", flush=True)


if __name__ == "__main__":
    main()
