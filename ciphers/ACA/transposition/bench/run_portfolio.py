#!/usr/bin/env python3
"""Portfolio benchmark: run every transposition cipher in the corpus through every
feasible dedicated solver type, record n-gram score / dictionary coverage / time.

Usage: run_portfolio.py [--workers N] [--limit N] [--types t1,t2]
Outputs bench/results.csv (one row per (cipher, solver) job).
"""
import csv, math, os, subprocess, sys, time, argparse, threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))      # .../transposition/bench
CORPUS = os.path.dirname(HERE)                          # .../transposition
SRC = os.path.abspath(os.path.join(CORPUS, "..", "..", ".."))  # repo root
BIN = os.path.join(SRC, "colossus")
NGRAMS = os.path.join(SRC, "english_quadgrams.txt")
DICT = os.path.join(SRC, "OxfordEnglishWords.txt")
SEED = "1234"

# Per-type solver budgets (derived from the regression suite's known-cracking
# settings, trimmed where needed to keep the full portfolio tractable).
BUDGETS = {
    "railfence":  ["-nrestarts", "20",  "-nhillclimbs", "3000"],
    "redefence":  ["-maxcols", "9", "-nrestarts", "10", "-nhillclimbs", "2500"],
    "amsco":      ["-mincols", "2", "-maxcols", "12", "-nrestarts", "40", "-nhillclimbs", "5000"],
    "myszkowski": ["-nrestarts", "25", "-nhillclimbs", "3500"],
    "cadenus":    ["-nrestarts", "200", "-nhillclimbs", "6000"],
    "nihilist":   ["-nrestarts", "400", "-nhillclimbs", "6000"],
    "swagman":    ["-nrestarts", "150", "-nhillclimbs", "4000"],
    "grille":     ["-nrestarts", "300", "-nhillclimbs", "6000"],
    "route":      ["-nrestarts", "10", "-nhillclimbs", "1000"],
    "transcol":   ["-mincols", "2", "-maxcols", "15", "-nrestarts", "25", "-nhillclimbs", "6000"],
    "transcol2":  ["-mincols", "2", "-maxcols", "12", "-nrestarts", "150", "-nhillclimbs", "4000"],
}
ALL_TYPES = list(BUDGETS.keys())

def is_square(n):
    r = int(math.isqrt(n)); return r*r == n
def has_factor(n, lo, hi):
    return any(n % k == 0 for k in range(lo, min(hi, n-1)+1))

def feasible(t, n):
    """Length-feasibility filter (ATTACK_DESIGN sec.1 rule 1)."""
    if n < 12: return False
    if t in ("railfence", "redefence", "amsco", "myszkowski", "transcol", "transcol2"):
        return True
    if t == "nihilist": return is_square(n) or n == 128
    if t == "grille":   return is_square(n)
    if t == "cadenus":  return n % 25 == 0
    if t == "swagman":  return has_factor(n, 3, 8)
    if t == "route":    return has_factor(n, 2, n//2)   # composite
    return False

def load_words():
    ws = set()
    with open(DICT) as f:
        for line in f:
            w = line.strip().upper()
            if 4 <= len(w) <= 14 and w.isalpha():
                ws.add(w)
    maxlen = max(len(w) for w in ws)
    return ws, maxlen

def coverage(pt, words, maxlen):
    """Max fraction of letters coverable by (possibly gapped) dictionary words len>=4."""
    n = len(pt)
    if n == 0: return 0.0
    best = [0]*(n+1)               # best[i] = max letters covered in pt[i:]
    for i in range(n-1, -1, -1):
        best[i] = best[i+1]        # skip pt[i]
        hi = min(maxlen, n-i)
        for L in range(4, hi+1):
            if pt[i:i+L] in words:
                c = L + best[i+L]
                if c > best[i]: best[i] = c
    return best[0]/n

def cipher_len(path):
    with open(path) as f:
        return len(f.readline().strip())

def parse_line(out):
    for line in out.splitlines():
        if line.startswith(">>> "):
            parts = [p.strip() for p in line[4:].split(", ")]
            score = float(parts[0]); pt = parts[-1]
            return score, pt
    return None, None

def run_job(job, words, maxlen):
    f, true_type, n, t = job
    args = [BIN, "-type", t, "-cipher", os.path.join(CORPUS, f),
            "-ngramsize", "4", "-ngramfile", NGRAMS, "-seed", SEED] + BUDGETS[t]
    t0 = time.time()
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=180)
        secs = time.time() - t0
        score, pt = parse_line(r.stdout)
        if pt is None:
            return (f, true_type, n, t, "", "", round(secs,2), "ERR")
        cov = coverage(pt, words, maxlen)
        return (f, true_type, n, t, round(score,3), round(cov,3), round(secs,2), pt)
    except subprocess.TimeoutExpired:
        return (f, true_type, n, t, "", "", round(time.time()-t0,2), "TIMEOUT")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=15)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--types", default="")
    ap.add_argument("--out", default=os.path.join(HERE, "results.csv"))
    a = ap.parse_args()
    types = a.types.split(",") if a.types else ALL_TYPES

    # true type per file from manifest
    truetype = {}
    with open(os.path.join(CORPUS, "manifest.csv")) as f:
        for row in csv.DictReader(f):
            truetype[row["filename"]] = row["type"]

    files = sorted(fn for fn in os.listdir(CORPUS) if fn.endswith(".txt"))
    if a.limit: files = files[:a.limit]

    jobs = []
    for fn in files:
        n = cipher_len(os.path.join(CORPUS, fn))
        tt = truetype.get(fn, "UNKNOWN")
        for t in types:
            if feasible(t, n):
                jobs.append((fn, tt, n, t))

    print(f"{len(files)} ciphers, {len(jobs)} jobs over {len(types)} solver types, "
          f"{a.workers} workers", flush=True)

    words, maxlen = load_words()
    done = [0]; lock = threading.Lock(); t_start = time.time()
    with open(a.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file","true_type","n","solver","score","cov4","secs","plaintext"])
        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            for res in ex.map(lambda j: run_job(j, words, maxlen), jobs):
                w.writerow(res)
                with lock:
                    done[0] += 1
                    if done[0] % 200 == 0 or done[0] == len(jobs):
                        el = time.time()-t_start
                        rate = done[0]/el
                        eta = (len(jobs)-done[0])/rate if rate else 0
                        print(f"  {done[0]}/{len(jobs)}  {el:.0f}s elapsed  ETA {eta:.0f}s", flush=True)
                        fh.flush()
    print(f"DONE in {time.time()-t_start:.0f}s -> {a.out}", flush=True)

if __name__ == "__main__":
    main()
