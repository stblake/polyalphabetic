# CLAUDE.md

Guidance for working in this repository.

## Scope

This directory is the **entire project** and the git root. It tracks
`https://github.com/stblake/polyalphabetic` (branch `main`). Everything outside this
directory is out of scope — git can't see it, and neither should you. (The parent
folder holds unrelated experiment runs, logs, and candidate dumps; ignore it.)

## What this is

A polyalphabetic substitution cipher solver in C by Sam Blake (started 14 July 2023).
It attacks **Vigenère, Beaufort, Porta, Quagmire I–IV, and Autokey** ciphers (plus
their variants and Beaufort/Porta autokey tableaus), optionally composed with a
transposition stage. The engine is a **stochastic, slippery, shotgun-restarted hill
climber with backtracking**. Cipher conventions follow the American Cryptogram
Association (https://www.cryptogram.org/resource-area/cipher-types/). It exists to
crack the Kryptos sculpture's K1–K4. See `README.md` for the author's full writeup.

## Layout (flat — sources at the repo root)

```
polyalphabetic.c     # main(): arg parsing, solve_cipher(), hill climber, scoring, optimal-cycleword solver
polyalphabetic.h     # the single shared header: config struct, constants, all prototypes, inline RNG
parse.c              # parse_cipher_type(): string/int aliases -> cipher-type code
perioc.c             # estimate_cycleword_lengths(): IoC period estimation (Z-score + threshold)
vigenere.c beaufort.c porta.c quagmire.c autokey.c   # per-cipher encrypt/decrypt primitives
transpositions.c     # transperoffset() (periodic decimation), transmatrix() (K3-style double rotation)
dict.c               # dictionary load + word-finding (scores plaintext readability)
utils.c              # ord/print, IoC, chi-squared, entropy, gcd, rng_state def, etc.
makefile
README.md  LICENSE
example.sh           # canonical usage example
cipher.txt  crib.txt # sample ciphertext + crib
english_quadgrams.txt        # n-gram table (quadgrams)
OxfordEnglishWords.txt       # default dictionary (auto-loaded if present in cwd)
ciphers/kryptos/     # K1–K4 ciphertexts + run scripts
ciphers/tests/       # per-cipher test cases (cipher + expected solution)
```

## Build

```bash
make            # gcc -Wall -O3; builds ./polyalphabetic
make clean
```

Two caveats:
- The active `CC` line does **not** include `-lm`. Links on macOS (clang folds libm
  into libc) but fails on Linux — add `-lm` there.
- `make` also runs `cp polyalphabetic ..` (and `../quagmire`), copying the binary
  *outside* this directory. That predates the isolation of this repo; the in-tree
  `./polyalphabetic` is the one that matters here.

`make test` builds and runs the framework-free unit tests in
`tests/test_transpositions.c` (the transposition primitives, including the columnar
`decrypt_columnar`: known-answer, round-trip across complete/incomplete grids and both
read directions, double-columnar composition). `ciphers/tests/` additionally holds
end-to-end cases (ciphertext + `*_solution.txt`, plus `*_solve.sh` runners — e.g. the
`transcol_*_solve.sh` columnar recovery tests) you can run by hand.

`ciphers/tests/run_tests.sh` is the **accuracy regression suite**: a manifest of
21 end-to-end cases (Vigenère, Beaufort, Porta, Quagmire I–IV, autokey, the ACA
`q*_p1xx` puzzles, and pure-transposition types) that each solve to 100% with a
**fixed `-seed`** and quadgrams. It runs the solver, pulls the recovered plaintext
from the last field of the `>>>` CSV line, compares it character-for-character to a
sibling `<name>.solution` (bare A–Z plaintext), and prints per-test accuracy + time +
mean, exiting non-zero if any test drops below the threshold (default 99%). Because
the seed is fixed, a bit-identical refactor keeps every score at 100% and any
behavioural regression shows up immediately. Each test's `-nrestarts`/`-nhillclimbs`
are trimmed to the smallest that still lands on the solution at the seed, so the full
run is ~2 min (was ~45 before trimming). The manifest tags each case `fast` or `slow`:
`./run_tests.sh --fast` runs the 14-case fast tier in ~20s (use while iterating),
`--slow` the 7 heavier ciphers, no flag runs both. Add a case by appending a
`tier|name|type|cipher|args` line and running `./run_tests.sh --generate <name>`
once the recovered text is verified correct.

## Run

Run from this directory — the binary loads its n-gram table, dictionary, and
ciphertext from the current working directory.

```bash
./example.sh
# or, minimally:
./polyalphabetic -type q3 -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt
```

Required flags: `-type`, a cipher source (`-cipher <file>` or `-batch <file>`),
`-ngramsize`, and `-ngramfile`. Everything else has defaults (see `init_config`).
`-type` accepts aliases or integer codes: `vig`/`0`, `q1`..`q4`/`1`..`4`, `beau`/`5`,
`porta`/`6`, `auto`/`7`, `auto1`..`auto4`/`8`..`11`, `autobeau`, `autoporta`,
`transmatrix`/`14`, `transperoffset`/`15`, `transposition`/`16`, `transcol`/`17`,
`transcol2`/`18` (full list in `parse.c`; codes in `polyalphabetic.h`). Output is a
human-readable block followed by a `>>> ...` one-line CSV summary that batch runs
grep/sort.

Five **pure transposition** cipher types bypass the keyword/cycleword/period machinery
and are solved by optimization instead (all isolated from the polyalphabetic pipeline by
an early branch in `solve_cipher`):
- `transmatrix`/`transperoffset` → `solve_transposition()` +
  `shotgun_transposition_climber()`: optimize the transform's own small parameter vector
  (`transmatrix` → `w1,w2,direction`; `transperoffset` → `period d, offset n`) with the
  shotgun/slip hill climber and n-gram scoring.
- `transposition` → `solve_general_transposition()` + `shotgun_permutation_climber()`: an
  AZDecrypt-style solver that hill-climbs the **full permutation key** (`decrypted[i] =
  cipher[key[i]]`). Restarts are seeded from columnar layouts; a periodic-redundancy
  structure term (`key_structure_score`, weight `-weightstructure`, default 4) guards
  against n-gram-gaming; simulated-annealing acceptance; and a period-targeted column-swap
  move reorders whole columns. Stochastic — run more restarts/iterations for hard ciphers.
- `transcol`/`transcol2` → `solve_columnar()` + `shotgun_columnar_climber()`: a
  **dedicated columnar** solver that, unlike the general one, optimizes only the small
  per-stage **column-order permutation** (length `K` = column count) via the
  `decrypt_columnar()` primitive (`transpositions.c`). Single (`transcol`) sweeps the
  column count over `-mincols..-maxcols` (default 2..30); double (`transcol2`) randomises
  `(K1,K2)` per restart and anneals both keys. Read direction is opt-in via
  `-readdir tb|bt|both` (default `tb`); incomplete final rows are handled automatically.
  No structure-score guard is needed — every candidate is a genuine columnar layout. Move
  set is column swaps (dominant) + short reverses/block-moves with the same Metropolis
  annealing as the permutation climber.

These `-type` values are distinct from the `-transmatrix`/`-transperoffset` *post-decrypt
stage* flags, which apply a fixed, user-supplied transposition after a polyalphabetic solve.

## How the solver works (mental model)

`solve_cipher()` (in `polyalphabetic.c`) is the pipeline:

1. **Period estimation.** For periodic ciphers, `estimate_cycleword_lengths`
   (`perioc.c`) picks candidate cycleword lengths via columnar IoC Z-scores. For
   **autokey** and **transposition-composed** ciphers IoC is useless, so it
   brute-forces lengths `1..max_cycleword_len`.
2. **Shotgun loop.** Nested loops over `(cycleword_len, pt_keyword_len, ct_keyword_len)`.
   Per-cipher-type rules constrain which `(j,k)` keyword-length pairs are valid (e.g.
   Vigenère/Beaufort/Porta force straight alphabets → length 1; Q3/A3 force `j==k`).
   These are the dense `if (...) continue;` blocks.
3. **`shotgun_hill_climber()`.** Random restarts, per-iteration keyword perturbation,
   optional slip (accept-worse to escape local maxima), and backtracking to best.
   Two cycleword strategies:
   - **`-optimalcycle` (default)**: the cycleword is *not* perturbed;
     `derive_optimal_cycleword()` solves each column's key char deterministically by
     maximizing the dot product of decrypted-column letter frequencies vs English
     monograms. Preferred for crib-free attacks.
   - **`-stochasticcycle`**: the cycleword is perturbed randomly like the keyword.
4. **Scoring** (`state_score`): n-gram log-prob is the backbone; with cribs it blends
   in a partial-match `crib_score`. `weight_ioc`/`weight_entropy` default to 0.
5. **Reporting**: re-decrypts the best state, applies any transposition, counts
   dictionary words, prints results.

Text is carried internally as **0–25 integer index arrays**, not chars (`ord()` in,
`+ 'A'` out). A "keyword" is a 26-entry keyed-alphabet permutation; a "cycleword" is
the periodic key (sequence of shifts).

## Conventions & gotchas

- **One shared header.** Every `.c` includes `polyalphabetic.h`; no per-module
  headers. Add prototypes and constants there.
- **`rng_state`** is a global in `utils.c`; the RNG (`fast_rand`, `frand`, `rand_int`,
  `rand_bounded`) is `static inline` in the header, seeded once in `main`. The
  `srand()` call in `main` is dead code — nothing uses libc `rand()`.
- **Stack-heavy.** `solve_cipher` and the hill climber declare several
  `MAX_CIPHER_LENGTH` (10000) int arrays on the stack, and there is **no bounds check**
  after `fscanf("%s", ...)`, so inputs must stay under the limit.
- **`-variant`** swaps decryption for encryption in the Quagmire/Vigenère math
  (reciprocal tableau). **`-samekey`** ties keyword and cycleword together.
- **Transposition is a post-decrypt stage**: `-transperoffset <offset> <period>` or
  `-transmatrix <w1> <w2> <cw|ccw>`. Crib positions are un-mapped back through it via
  `map_crib_to_cipher_pos` so cribs still line up.

## Fixed issues (end-to-end tests in `ciphers/tests/bugfixes/`)

- The trailing partial-crib match line (the `_`/digit/`*` row) used to index the
  packed `crib_indices` array positionally (testing an uninitialized `-1`), printing
  garbage at every position. Now indexed by cipher position via `cribtext_str`.
  Test: `bug1_partial_crib.sh`.
- The `-transmatrix` `>>>` summary (no-dictionary branch) printed period/offset
  instead of `w1`/`w2`/`clockwise`. Fixed to match the dictionary branch.
  Test: `bug2_transmatrix_summary.sh`.
- `load_ngrams` looped on `while(!feof(fp))`, re-reading the final line and
  mis-assigning a stale `freq` on any trailing/malformed line. Now loops on
  `fscanf(...) == 2`. Test: `bug3_ngram_load.sh`.
- A cipher/ngram/crib path longer than `MAX_FILENAME_LEN` overflowed the fixed
  `char[]` in `PolyalphabeticConfig` (`main()` `strcpy`s the CLI arg in unbounded),
  corrupting the struct and crashing with SIGILL — any absolute path past the old
  100-byte limit triggered it. `MAX_FILENAME_LEN` raised to 4096.
  Test: `bug4_long_path.sh`.
- `int_pow` did a final `base *= base` after the result was already accumulated;
  `int_pow(26, ngram_size)` overflowed signed `int` (e.g. `26^4` squared). The UB
  was benign at `-O0` but `-O3` could exploit it. Now skips the unused final squaring.

## Working agreements

- Match the existing style: 4-space indent, `snake_case`, integer-index text arrays,
  explicit per-cipher-type `switch`/`if` ladders. The code favors explicitness over
  abstraction — don't refactor the cipher-type dispatch into clever generic code.
- The binary `polyalphabetic`, `*.o`, and `.DS_Store` are git-ignored.
- Don't commit or push unless asked.
