#!/usr/bin/env python3
"""Extract every Homophonic, Playfair, Bifid and Trifid cipher from ACA_ciphers.csv into its own
directory and write a `<cipher>.txt` + `<cipher>.solution` pair, mirroring the layout
of ciphers/ACA/transposition/.

For each cipher we:
  1. slugify (type/year/author/con) into the same filename convention the transposition
     corpus uses: `<type>_<year>_<author>_<con>.txt` (lowercase, alnum-only slugs);
  2. normalise the ciphertext to what the solver reads -- Playfair: spaces/period
     stripped to a bare A..Z (J->I) stream; Homophonic: 2-digit numeric tokens joined
     with commas (auto comma delimiter), or, for the rare letter-form puzzles, a bare
     letter stream (per-character tokenisation);
  3. run colossus once with the per-type tuned schedule (Playfair = the registry anneal
     profile; Homophonic = the Z408 cool-anneal schedule), capturing an honest single-
     invocation CPU time (user+sys; the solver is single-threaded);
  4. classify by dictionary word coverage (score scales differ under -logprob, coverage
     does not) and emit a human-readable `.solution` file + a per-dir manifest.csv.
"""
import csv, os, re, subprocess, sys, collections, argparse, math
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))                  # .../ciphers/ACA
SRC  = os.path.abspath(os.path.join(HERE, "..", ".."))            # repo root
BIN  = os.path.join(SRC, "colossus")
CSV  = os.path.join(SRC, "ACA_ciphers.csv")
QUINT = os.path.join(SRC, "english_quintgrams.txt")
QUAD  = os.path.join(SRC, "english_quadgrams.txt")
DICT = os.path.join(SRC, "OxfordEnglishWords.txt")
SEED = "1234"

# CSV "Type" label -> (subdir, solver -type, extra solver args). Quintgrams + -logprob
# for both (Playfair effectively requires it; quintgrams take homophonic to ~100%).
SPEC = {
    "Homophonic": dict(
        dir="homophonic", solver="homophonic",
        args=["-nrestarts", "200", "-nhillclimbs", "50000",
              "-inittemp", "0.02", "-weightmono", "1.5", "-backtrackprob", "0.15"]),
    "Playfair": dict(
        dir="playfair", solver="playfair",
        args=["-nrestarts", "20", "-nhillclimbs", "400000",
              "-inittemp", "0.08", "-backtrackprob", "0.3"]),
    # Bifid: fractionation over a 5x5 keyed square (J->I). Period unknown, so let the
    # estimator rank candidates and anneal the top -nperiods. ACA bifids are short
    # (~110-150 chars, below bifid's ~350-char cliff) so most land as best-attempt.
    "Bifid": dict(
        dir="bifid", solver="bifid",
        args=["-nrestarts", "12", "-nhillclimbs", "200000", "-nperiods", "8",
              "-inittemp", "0.08", "-backtrackprob", "0.3"]),
    # Trifid: Bifid lifted into 3D -- fractionation over a keyed 3x3x3 cube (27 cells:
    # A..Z + a 27th symbol, which ACA prints as '#' and the solver expects as '+'). The
    # larger permutation space gets a bigger per-period budget than Bifid. Same period-
    # estimate-and-anneal-top-K scheme. ACA trifids are short (~120-165 chars, below
    # trifid's ~450-char cliff) so most land as best-attempt.
    "Trifid": dict(
        dir="trifid", solver="trifid",
        args=["-nrestarts", "8", "-nhillclimbs", "300000", "-nperiods", "8",
              "-inittemp", "0.08", "-backtrackprob", "0.3"]),
    # Gronsfeld: a Vigenere with a numeric (0-9) key -- polyalphabetic, NOT a
    # substitution. It rides the polyalpha pipeline (IoC period estimation + the
    # deterministic optimal-cycleword frequency attack) and the default reward-only
    # quadgram table -- no -logprob, no quintgrams (overridden via ngram=). ACA
    # gronsfelds are short (~75-135 chars), so the digit-bounded search gets many
    # restarts. When it lands it recovers ordinary full English plaintext.
    # -stochasticcycle (not the default optimal-cycleword frequency attack): on short
    # text the deterministic per-column digit pick is marginal and lands a few key
    # digits off, but actually *searching* the bounded 0-9 cycleword space recovers the
    # key cleanly. Many restarts, short climbs.
    "Gronsfeld": dict(
        dir="gronsfeld", solver="gron",
        ngram=(4, QUAD, False),
        args=["-stochasticcycle", "-nrestarts", "4000", "-nhillclimbs", "3000"]),
}

# coverage thresholds (fraction of plaintext letters coverable by dictionary words >=4),
# per type. Playfair coverage is computed with X (its null/doubled-letter separator)
# stripped and caps lower than a substitution because proper nouns (ROOSEVELT,
# MACHIAVELLI...) aren't in the dictionary -- correct solves cluster 0.63-0.74 while the
# best wrong grid reaches only 0.36, so 0.55 cleanly separates them.
THRESH = {
    "Playfair":   dict(clean=0.55, part=0.30),
    "Homophonic": dict(clean=0.80, part=0.45),
    # Bifid plaintext is ordinary English with no null insertions, but ACA bifids are
    # short and proper-noun heavy; use the same conservative split as Playfair.
    "Bifid":      dict(clean=0.55, part=0.30),
    # Trifid: same conservative split as Bifid (ordinary short, proper-noun-heavy English).
    "Trifid":     dict(clean=0.55, part=0.30),
    # Gronsfeld: a correct break yields ordinary full English (no nulls), but ACA
    # gronsfelds are short and proper-noun heavy (BAVARIA, MUNICH, GRONSFELD itself),
    # so correct solves cover only 0.53-0.80 while a wrong digit-key is gibberish at
    # 0.22-0.35 -- 0.45 cleanly separates the two clusters.
    "Gronsfeld":  dict(clean=0.45, part=0.30),
}


def slug(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def normalise_ct(typ, raw):
    """Return (ct_string_for_txt, symbol_count). ct is exactly what colossus reads."""
    raw = raw.strip().rstrip(".").strip()
    if typ == "Gronsfeld":   # polyalphabetic: bare A..Z stream, no J->I merge (mod 26)
        letters = re.sub(r"[^A-Za-z]", "", raw).upper()
        return letters, len(letters)
    if typ in ("Playfair", "Bifid"):   # bare A..Z stream, J->I (both use a 5x5 square)
        letters = re.sub(r"[^A-Za-z]", "", raw).upper().replace("J", "I")
        return letters, len(letters)
    if typ == "Trifid":   # bare 27-symbol stream over a 3x3x3 cube; no J->I merge.
        # ACA prints the 27th symbol as '#'; the solver expects '+'. Keep A..Z and '#'.
        body = re.sub(r"[^A-Za-z#]", "", raw).upper().replace("#", "+")
        return body, len(body)
    # Homophonic
    if re.search(r"\d", raw):                       # numeric token form
        toks = raw.split()
        return ",".join(toks), len(toks)
    letters = re.sub(r"[^A-Za-z]", "", raw).upper() # rare letter form -> per-char
    return letters, len(letters)


def load_words():
    ws = set()
    with open(DICT) as f:
        for line in f:
            w = line.strip().upper()
            if 4 <= len(w) <= 14 and w.isalpha():
                ws.add(w)
    return ws, max(len(w) for w in ws)


def coverage(pt, words, maxlen, strip_x=False):
    pt = re.sub(r"[^A-Z]", "", pt.upper())
    if strip_x:                       # Playfair X = null / doubled-letter separator
        pt = pt.replace("X", "")
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


def classify(typ, cov):
    t = THRESH[typ]
    if cov >= t["clean"]:
        return "SOLVED (clean)"
    if cov >= t["part"]:
        return "PARTIAL (words recovered)"
    return "UNSOLVED (best attempt shown)"


def extract():
    """Return list of job dicts (one per cipher) and write each .txt file."""
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
            ct_str, nsym = normalise_ct(typ, ct)
            cdir = os.path.join(HERE, spec["dir"])
            with open(os.path.join(cdir, base + ".txt"), "w") as out:
                out.write(ct_str + "\n")
            jobs.append(dict(base=base, dir=spec["dir"], typ=typ, solver=spec["solver"],
                             args=spec["args"], year=year, name=name, con=con,
                             author=author, ct=ct_str, n=nsym))
    return jobs


def ngram_of(j):
    """(ngramsize, ngramfile, logprob) for this job -- default quintgrams + -logprob."""
    return SPEC[j["typ"]].get("ngram", (5, QUINT, True))


def cmd_str(j):
    rel = os.path.relpath(os.path.join(HERE, j["dir"], j["base"] + ".txt"), SRC)
    size, fpath, logprob = ngram_of(j)
    return ("./colossus -type %s -cipher %s -ngramsize %d -ngramfile %s%s %s -seed %s"
            % (j["solver"], rel, size, os.path.basename(fpath),
               " -logprob" if logprob else "", " ".join(j["args"]), SEED))


def run(j):
    cpath = os.path.join(HERE, j["dir"], j["base"] + ".txt")
    size, fpath, logprob = ngram_of(j)
    args = (["/usr/bin/time", "-p", BIN, "-type", j["solver"], "-cipher", cpath,
             "-ngramsize", str(size), "-ngramfile", fpath]
            + (["-logprob"] if logprob else [])
            + j["args"] + ["-seed", SEED])
    p = subprocess.run(args, capture_output=True, text=True, timeout=600)
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
        f.write(f"length:      {j['n']}  (cipher symbols)\n")
        f.write(f"score:       {score:.2f}\n" if score is not None else "score:       n/a\n")
        f.write(f"solve_time:  {cpu:.2f}s  (CPU user+sys, single-threaded)\n")
        f.write(f"command:     {cmd_str(j)}\n")
        f.write(f"ciphertext:  {j['ct']}\n")
        f.write(f"plaintext:   {pt}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--types", default="",
                    help="comma-separated CSV type labels to restrict to (e.g. Bifid)")
    a = ap.parse_args()

    jobs = extract()
    if a.types:
        keep = {t.strip() for t in a.types.split(",")}
        jobs = [j for j in jobs if j["typ"] in keep]
    if a.limit:
        jobs = jobs[:a.limit]
    print(f"extracted {len(jobs)} ciphers "
          f"({collections.Counter(j['typ'] for j in jobs)})", flush=True)

    words, maxlen = load_words()
    counts = collections.Counter()
    rows = collections.defaultdict(list)   # dir -> manifest rows

    def work(j):
        score, pt, cpu = run(j)
        cov = coverage(pt, words, maxlen, strip_x=(j["typ"] == "Playfair"))
        status = classify(j["typ"], cov)
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
