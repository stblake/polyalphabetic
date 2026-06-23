#!/usr/bin/env python3
"""Write a `<cipher>.solution` sibling for every corpus cipher.

For each cipher we pick the winning portfolio run (best CLEAN, else best PARTIAL, else
best-scoring attempt), RE-RUN that solver single-invocation to capture an honest,
contention-free CPU time (user+sys; the solver is single-threaded), and emit a
human-readable .solution file with the recovered plaintext + timing + exact command.
Same -seed => the re-run reproduces the identical plaintext recorded in the portfolio.
"""
import csv, os, subprocess, sys, collections, argparse
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_portfolio import BUDGETS, CORPUS, SRC, BIN, NGRAMS, SEED  # noqa

S_CLEAN, C_CLEAN = 3.05, 0.45
S_PART,  C_PART  = 3.10, 0.30

def classify(score, cov):
    if score is None: return "none"
    if score >= S_CLEAN and cov >= C_CLEAN: return "clean"
    if score >= S_PART and cov >= C_PART:   return "partial"
    return "none"

def pick_winner(runs):
    """runs: list of dicts. Return (status, run) for the canonical solution."""
    clean = [r for r in runs if classify(r["score"], r["cov4"]) == "clean"]
    part  = [r for r in runs if classify(r["score"], r["cov4"]) == "partial"]
    if clean: return "SOLVED (clean)",   max(clean, key=lambda r: r["cov4"])
    if part:  return "PARTIAL (words recovered, blocks may be shuffled)", max(part, key=lambda r: r["cov4"])
    ok = [r for r in runs if r["score"] is not None]
    if ok:    return "UNSOLVED (best attempt shown)", max(ok, key=lambda r: r["score"])
    return "UNSOLVED (no valid run)", runs[0]

def rerun(fn, solver):
    """Re-run one solver on one cipher; return (plaintext, cpu_s, wall_s, score)."""
    cpath = os.path.join(CORPUS, fn)
    args = ["/usr/bin/time", "-p", BIN, "-type", solver, "-cipher", cpath,
            "-ngramsize", "4", "-ngramfile", NGRAMS, "-seed", SEED] + BUDGETS[solver]
    p = subprocess.run(args, capture_output=True, text=True, timeout=300)
    score = None; pt = ""
    for line in p.stdout.splitlines():
        if line.startswith(">>> "):
            parts = [x.strip() for x in line[4:].split(", ")]
            score = float(parts[0]); pt = parts[-1]
    real = user = sysc = 0.0
    for line in p.stderr.splitlines():
        t = line.split()
        if len(t) == 2 and t[0] in ("real", "user", "sys"):
            v = float(t[1])
            if t[0] == "real": real = v
            elif t[0] == "user": user = v
            else: sysc = v
    return pt, user + sysc, real, score

def cmd_str(fn, solver):
    rel = os.path.relpath(os.path.join(CORPUS, fn), SRC)
    return ("./colossus -type %s -cipher %s -ngramsize 4 "
            "-ngramfile english_quadgrams.txt -seed %s %s"
            % (solver, rel, SEED, " ".join(BUDGETS[solver])))

def ciphertext(fn):
    with open(os.path.join(CORPUS, fn)) as f:
        return f.readline().strip()

def write_solution(job):
    fn, true_type, status, run = job
    solver = run["solver"]
    pt, cpu, wall, score = rerun(fn, solver)
    ct = ciphertext(fn)
    base = os.path.splitext(fn)[0]
    out = os.path.join(CORPUS, base + ".solution")
    with open(out, "w") as f:
        f.write(f"# solution for {fn}\n")
        f.write(f"status:      {status}\n")
        f.write(f"true_type:   {true_type}\n")
        f.write(f"solver:      {solver}\n")
        f.write(f"length:      {len(ct)}\n")
        f.write(f"score:       {score:.2f}\n" if score is not None else "score:       n/a\n")
        f.write(f"solve_time:  {cpu:.2f}s  (CPU user+sys, single-threaded)\n")
        f.write(f"command:     {cmd_str(fn, solver)}\n")
        f.write(f"ciphertext:  {ct}\n")
        f.write(f"plaintext:   {pt}\n")
    return status, cpu

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=15)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    truetype = {}
    with open(os.path.join(CORPUS, "manifest.csv")) as f:
        for row in csv.DictReader(f):
            truetype[row["filename"]] = row["type"]

    by = collections.defaultdict(list)
    for r in csv.DictReader(open(os.path.join(HERE, "results.csv"))):
        r["score"] = None if r["score"] == "" or r["plaintext"] in ("ERR", "TIMEOUT") else float(r["score"])
        r["cov4"]  = None if r["score"] is None else float(r["cov4"])
        by[r["file"]].append(r)

    jobs = []
    for fn, runs in by.items():
        status, run = pick_winner(runs)
        jobs.append((fn, truetype.get(fn, "UNKNOWN"), status, run))
    jobs.sort()
    if a.limit: jobs = jobs[:a.limit]

    counts = collections.Counter(); done = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for status, cpu in ex.map(write_solution, jobs):
            counts[status.split()[0]] += 1; done += 1
            if done % 100 == 0: print(f"  {done}/{len(jobs)}", flush=True)
    print(f"\nwrote {done} .solution files: {dict(counts)}")

if __name__ == "__main__":
    main()
