# CLAUDE.md

Guidance for working in this repository.

## Scope

This directory is the **entire project** and the git root. It tracks
`https://github.com/stblake/colossus` (branch `main`). Everything outside this
directory is out of scope — git can't see it, and neither should you. (The parent
folder holds unrelated experiment runs, logs, and candidate dumps; ignore it.)

## What this is

Colossus is a polyalphabetic substitution cipher solver in C by Sam Blake (started 14 July 2023).
It attacks **Vigenère, Beaufort, Porta, Quagmire I–IV, and Autokey** ciphers (plus
their variants and Beaufort/Porta autokey tableaus), optionally composed with a
transposition stage. The engine is a **stochastic, slippery, shotgun-restarted hill
climber with backtracking**. Cipher conventions follow the American Cryptogram
Association (https://www.cryptogram.org/resource-area/cipher-types/). It exists to
crack the Kryptos sculpture's K1–K4. See `README.md` for the author's full writeup.

## Layout (flat — sources at the repo root)

```
colossus.c     # main(): arg parsing, solve_cipher(), hill climber, scoring, optimal-cycleword solver
colossus.h     # the single shared header: config struct, constants, all prototypes, inline RNG
parse.c              # parse_cipher_type(): string/int aliases -> cipher-type code
perioc.c             # estimate_cycleword_lengths(): IoC period estimation (Z-score + threshold)
vigenere.c beaufort.c porta.c quagmire.c autokey.c   # per-cipher encrypt/decrypt primitives
transpositions.c     # transperoffset() (periodic decimation), transmatrix() (K3-style double rotation)
dict.c               # dictionary load + word-finding (scores plaintext readability)
utils.c              # ord/print, decode_cipher/print_cipher (symbol I/O), IoC, chi-squared, etc.
makefile
README.md  LICENSE
example.sh           # canonical usage example
cipher.txt  crib.txt # sample ciphertext + crib
tools/homophonic_gen.c       # standalone homophonic-cipher test-data generator (make homophonic_gen)
english_quadgrams.txt        # n-gram table (quadgrams); english_quintgrams.txt (5-grams) optional, with -logprob
OxfordEnglishWords.txt       # default dictionary (auto-loaded if present in cwd)
ciphers/kryptos/     # K1–K4 ciphertexts + run scripts
ciphers/tests/       # per-cipher test cases (cipher + expected solution)
```

## Build

```bash
make            # gcc -Wall -O3; builds ./colossus
make clean
```

Two caveats:
- The active `CC` line does **not** include `-lm`. Links on macOS (clang folds libm
  into libc) but fails on Linux — add `-lm` there.
- `make` also runs `cp colossus ..` (and `../quagmire`), copying the binary
  *outside* this directory. That predates the isolation of this repo; the in-tree
  `./colossus` is the one that matters here.

`make test` builds and runs the framework-free unit tests in
`tests/test_transpositions.c` (the transposition primitives, including the columnar
`decrypt_columnar`: known-answer, round-trip across complete/incomplete grids and both
read directions, double-columnar composition). `ciphers/tests/` additionally holds
end-to-end cases (ciphertext + `*_solution.txt`, plus `*_solve.sh` runners — e.g. the
`transcol_*_solve.sh` columnar recovery tests) you can run by hand.

`ciphers/tests/run_tests.sh` is the **accuracy regression suite**: a manifest of
31 end-to-end cases (Vigenère, Beaufort, Porta, Quagmire I–IV, autokey, the ACA
`q*_p1xx` puzzles, pure-transposition types, and a homophonic substitution) that each
solve to ~100% with a **fixed `-seed`** and quadgrams. It runs the solver, pulls the
recovered plaintext from the last field of the `>>>` CSV line, compares it
character-for-character to a sibling `<name>.solution` (bare A–Z plaintext), and prints
per-test accuracy + time + mean, exiting non-zero if any test drops below the threshold
(default 99%; the homophonic case lands ~99.9%). Because the seed is fixed, a
bit-identical refactor keeps every score at 100% and any behavioural regression shows up
immediately. Each test's `-nrestarts`/`-nhillclimbs` are trimmed to the smallest that
still lands on the solution at the seed, so the full run is ~2 min (was ~45 before
trimming). The manifest tags each case `fast` or `slow`:
`./run_tests.sh --fast` runs the 20-case fast tier in ~45s (use while iterating),
`--slow` the 11 heavier ciphers, no flag runs both. Add a case by appending a
`tier|name|type|cipher|args` line and running `./run_tests.sh --generate <name>`
once the recovered text is verified correct.

## Run

Run from this directory — the binary loads its n-gram table, dictionary, and
ciphertext from the current working directory.

```bash
./example.sh
# or, minimally:
./colossus -type q3 -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt
```

Required flags: `-type`, a cipher source (`-cipher <file>` or `-batch <file>`),
`-ngramsize`, and `-ngramfile`. Everything else has defaults (see `init_config`).
`-type` accepts aliases or integer codes: `vig`/`0`, `q1`..`q4`/`1`..`4`, `beau`/`5`,
`porta`/`6`, `auto`/`7`, `auto1`..`auto4`/`8`..`11`, `autobeau`, `autoporta`,
`transmatrix`/`14`, `transperoffset`/`15`, `transposition`/`16`, `transcol`/`17`,
`transcol2`/`18`, `indep`/`28`, `homophonic`/`29` (full list in `parse.c`; codes in
`colossus.h`). Output is a human-readable block followed by a `>>> ...` one-line CSV
summary that batch runs grep/sort.

**Tokenized symbol I/O.** Ciphertext is decoded by `decode_cipher()` (utils.c), not the
bare `ord()`. For every type except homophonic with no `-delimiter`, this is byte-for-byte
the historical per-character / 0..25-letter encoding (so the regression suite stays
bit-identical). For `homophonic` (or any type run with `-delimiter <char>`) it tokenizes
the input into a `SymbolTable` of distinct surface tokens and emits one **symbol id** per
position, so a ciphertext alphabet larger than A..Z -- comma-separated numbers
(`12,5,99,12`) or arbitrary ASCII symbols -- can be entered and displayed consistently
(`print_cipher()`). Default delimiter: auto (comma if the homophonic input contains one,
else per-character).

**`-logprob` (a.k.a. `-azdecrypt`).** Opt-in AZDecrypt / Practical-Cryptography n-gram
fitness: `load_ngrams` builds log10-probabilities with a floor that **penalises unseen
n-grams**, instead of the default reward-only normalized `log(1+count)` table (which
leaves unseen n-grams at 0). `ngram_score` keeps the score at scale 1 in this mode (a
mean log-probability). Default off => the table and every existing solve are unchanged.
Recommended with higher-order n-grams (e.g. `-ngramsize 5 -ngramfile english_quintgrams.txt`)
for hard substitution attacks; quintgrams take a homophonic solve from ~98% (quadgrams)
to ~100%.

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

The **homophonic** type (`solve_homophonic()`) is a `CipherModel` plugged into the shared
`run_solver()` engine just like every other type (`HOMOPHONIC_MODEL`, `SHAPE_ANNEAL`). Its
state is the many-to-one map `symbol_id -> plaintext letter` (carried in the `key` lane);
`decrypted[i] = key[cipher[i]]`. Unlike a 26->26 substitution (a bijection), a homophonic
map is free to fold many symbols onto E/T/A... to tile common n-grams -- a fixed point that
out-scores the true plaintext on raw n-grams. Two things prevent that collapse: (1) a
**monogram chi-squared penalty** on the decrypted letter distribution (`-weightmono`,
default 1.0), folded in via the decrypt hook's `score_adjust` and the greedy move; and (2) a
move set built around a **greedy coordinate step** (best plaintext letter for one symbol)
plus a **letter-class swap** (exchange the whole homophone classes of two letters, to cross
equal-frequency ambiguities like W<->M that single-symbol moves cannot). Seeds draw each
symbol's letter from the English monogram distribution. With quadgrams it recovers
~98%/~99%+ depending on homophone density; `-logprob` + quintgrams take it to ~100%.
Generate test ciphers with `tools/homophonic_gen.c` (`make homophonic_gen`).

## How the solver works (mental model)

`solve_cipher()` (in `colossus.c`) is the pipeline:

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
   in a partial-match `crib_score`. `weight_ioc`/`weight_entropy` default to 0. The
   n-gram table itself has two modes (`load_ngrams`): the default reward-only normalized
   `log(1+count)` (unseen n-grams contribute 0), or, under `-logprob`, AZDecrypt-style
   log10-probabilities with an unseen-n-gram floor penalty (`g_ngram_logprob`).
5. **Reporting**: re-decrypts the best state, applies any transposition, counts
   dictionary words, prints results.

Text is carried internally as **0–25 integer index arrays**, not chars (`ord()` in,
`+ 'A'` out). A "keyword" is a 26-entry keyed-alphabet permutation; a "cycleword" is
the periodic key (sequence of shifts).

## Conventions & gotchas

- **One shared header.** Every `.c` includes `colossus.h`; no per-module
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
  `char[]` in `ColossusConfig` (`main()` `strcpy`s the CLI arg in unbounded),
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
- The binary `colossus`, `*.o`, and `.DS_Store` are git-ignored.
- Don't commit or push unless asked.
