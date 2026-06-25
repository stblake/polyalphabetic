# CLAUDE.md

Guidance for working in this repository.

## Scope

This directory is the **entire project** and the git root. It tracks
`https://github.com/stblake/colossus` (branch `main`). Everything outside this
directory is out of scope — git can't see it, and neither should you. (The parent
folder holds unrelated experiment runs, logs, and candidate dumps; ignore it.)

## What this is

Colossus is a polyalphabetic substitution cipher solver in C by Sam Blake (started 14 July 2023).
It attacks **Vigenère, Gronsfeld, Beaufort, Porta, Quagmire I–IV, and Autokey** ciphers (plus
their variants and Beaufort/Porta autokey tableaus), optionally composed with a
transposition stage. The engine is a **stochastic, slippery, shotgun-restarted hill
climber with backtracking**. Cipher conventions follow the American Cryptogram
Association (https://www.cryptogram.org/resource-area/cipher-types/). It exists to
crack the Kryptos sculpture's K1–K4. See `README.md` for the author's full writeup.

## Layout (sources under `src/<cipher-class>/`)

The C sources are grouped by cipher class under `src/`; everything else (build,
tests, tools, data, ciphers) stays at the repo root. All local `#include`s are
**flat** (`#include "foo.h"`, no directory prefix) — the makefile resolves them
with one `-I` per `src/` subdir (the `INCLUDES` variable), so a header is found
regardless of which subdirectory it lives in. Add a new `src/` subdir → add it
to `INCLUDES`.

```
src/core/        # cipher-agnostic engine + shared infrastructure
  colossus.c       # main(): arg parsing, init_config(), solve_cipher() dispatcher
  colossus.h       # shared CORE header: config/ctx/model structs, constants, cipher-type
                   #   codes, globals, inline RNG, and the cipher-PRIMITIVE prototypes
  engine.c/.h      # cipher-agnostic search engine: run_solver(), run_one_config(),
                   #   make_solver_ctx(), the SearchDefaults registry + apply_cipher_defaults()
  scoring.c/.h     # state_score / ngram_score / crib_score, load_ngrams, keyword/cycleword RNG
  parse.c          # parse_cipher_type(): string/int aliases -> cipher-type code
  perioc.c         # estimate_cycleword_lengths(): IoC period estimation (Z-score + threshold)
  optimal_cycleword.c  # derive_optimal_cycleword(): deterministic per-column frequency attack
  dict.c           # dictionary load + word-finding (scores plaintext readability)
  utils.c          # ord/print, decode_cipher/print_cipher (symbol I/O), IoC, chi-squared, etc.

src/polyalphabetic/   # Vigenère family — searched inside POLYALPHA_MODEL
  polyalpha_solver.c/.h  # POLYALPHA_MODEL (vig/quag/beau/porta/autokey) + crib/cycleword helpers
                         #   + solve_polyalpha(); solve_cipher() dispatches the polyalpha types here
  vigenere.c gronsfeld.c beaufort.c porta.c quagmire.c autokey.c   # per-cipher encrypt/decrypt primitives

src/transposition/    # pure-transposition solvers + shared helpers
  trans_common.c/.h    # shared transposition-solver helpers: report_transposition(),
                       #   TransKeyOps seed/move, perm_move/seed, sweep no-ops, exact_isqrt
  transpositions.c     # transperoffset() (periodic decimation), transmatrix() (K3-style double rotation)
  transmatrix_solver.c/.h permutation_solver.c/.h columnar_solver.c/.h
  railfence_solver.c/.h route_solver.c/.h amsco_solver.c/.h myszkowski_solver.c/.h
  redefence_solver.c/.h cadenus_solver.c/.h nihilist_solver.c/.h swagman_solver.c/.h grille_solver.c/.h
  columnar_track_solver.c/.h   # transcol-L: columnar + within-column row permutation L (seam best-L);
                               #   also the structural -cribanchored block<->column matcher
  route_chain_solver.c/.h      # transroutecol: fixed read-route global + searched column key (seam best-L)
  tile_solver.c/.h             # transtile: sub-grid h x w tile transposition (joint column-order + tile perm)
  # trans_common.c also carries the shared exact-ordering helpers: held_karp_best_path()
  #   (max-weight Hamiltonian path) and seam_best_row_order() (exact best within-column
  #   track order L via a per-row + seam-delta decomposition), plus trans_word_set().

src/polygraphic/      # square/cube/matrix ciphers — each: primitive + a CipherModel solver
  playfair.c playfair_solver.c/.h   # Playfair: 5x5 keyed grid; grid build / prepare / encrypt / decrypt
  bifid.c    bifid_solver.c/.h      # Bifid: side-generic keyed Polybius square build / encrypt / decrypt
  trifid.c   trifid_solver.c/.h     # Trifid: side-generic keyed 3x3x3 cube build / encrypt / decrypt
  hill.c     hill_solver.c/.h       # Hill: matrix multiply / encrypt / decrypt / det+inverse mod 26 (generic k x k)
  phillips.c phillips_solver.c/.h   # Phillips: derive 8 squares from a base / encrypt / decrypt (side-generic, 3 variants)
  twosquare.c twosquare_solver.c/.h # Two-Square: two keyed squares, rectangle rule; horizontal (ACA) + vertical (self-inverse), one solver
  foursquare.c foursquare_solver.c/.h # Four-Square: 2 keyed + 2 fixed-standard squares / encrypt / decrypt (side-generic)
  adfgvx.c   adfgvx_solver.c/.h     # ADFGVX/ADFGX: keyed-square fractionation (reuses bifid square build/inverse) +
                                     #   keyed columnar (reuses decrypt_columnar); coordinate-space, side-generic 5x5/6x6

src/substitution/     # monoalphabetic / homophonic substitution solvers
  indep_solver.c/.h homophonic_solver.c/.h   # each: a CipherModel + solve_<type>()

makefile
README.md  LICENSE
example.sh           # canonical usage example
cipher.txt  crib.txt # sample ciphertext + crib
tools/homophonic_gen.c       # standalone homophonic-cipher test-data generator (make homophonic_gen)
tools/playfair_gen.c         # standalone Playfair test-data generator (make playfair_gen)
tools/bifid_gen.c            # standalone Bifid test-data generator (make bifid_gen)
tools/trifid_gen.c           # standalone Trifid test-data generator (make trifid_gen)
tools/hill_gen.c             # standalone Hill test-data generator (make hill_gen)
tools/gronsfeld_gen.c        # standalone Gronsfeld test-data generator (make gronsfeld_gen)
tools/phillips_gen.c         # standalone Phillips test-data generator (make phillips_gen)
tools/twosquare_gen.c        # standalone Two-Square test-data generator (make twosquare_gen)
tools/foursquare_gen.c       # standalone Four-Square test-data generator (make foursquare_gen)
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
- The translation-unit list lives in makefile variables, each path prefixed with the
  source-class dir vars (`$(CORE)`, `$(POLY)`, `$(TRANS)`, `$(GRAPH)`, `$(SUBST)`):
  `PRIMITIVES` (the cipher decrypt math + utils), `SOLVERS` (the engine/scoring/trans_common
  core + the per-cipher-type solver modules), and
  `SOLVER_SRC = $(PRIMITIVES) $(SOLVERS) $(CORE)/colossus.c` (used by both `all` and the
  `testopt` harnesses). Every compile also passes `$(INCLUDES)` (one `-I` per `src/` subdir).
  Add a new solver module to `SOLVERS` with its `src/<class>/` prefix.

`make test` builds and runs the framework-free unit tests in
`tests/test_transpositions.c` (the transposition primitives, including the columnar
`decrypt_columnar`: known-answer, round-trip across complete/incomplete grids and both
read directions, double-columnar composition), `tests/test_ciphers.c`,
`tests/test_optimal_cycleword.c`, and `tests/test_playfair.c` (the Playfair primitives:
the Wikipedia known-answer vector, the prepare/X-insertion rules, encrypt/decrypt
round-trips over random grids, and the cyclic row/column key-square equivalence), and
`tests/test_bifid.c` (the Bifid primitives: the Wikipedia known-answer vector, the keyed-
square build, encrypt/decrypt round-trips over random 5x5 and 6x6 squares × random
lengths/periods incl. incomplete blocks, and the period-1 identity), and
`tests/test_trifid.c` (the Trifid primitives: the Wikipedia known-answer vector — two
groups, AIDET→FMJFV and OILEC→OISSU, over the 27-symbol cube — the keyed-cube build,
encrypt/decrypt round-trips over random 3x3x3 cubes and side-generic 2x2x2/4x4x4 cubes ×
random lengths/periods incl. incomplete blocks, and the period-1 identity), and
`tests/test_hill.c` (the Hill primitives: the Wikipedia known-answer vector — key
GYBNQKURP, ACT→POH and CAT→FIN — the modular inverse over all residues mod 26, the
matrix inverse by M·inv==I and inv(inv)==M plus singular rejection, encrypt/decrypt
round-trips over random invertible keys for block sizes k=2..5 × random lengths incl.
non-multiples of k, and the k=1 edge cases), and
`tests/test_gronsfeld.c` (the Gronsfeld primitives: a known-answer vector pinning the
numeric-key convention — HELLOWORLD + key 12345 → IGOPTXQUPI — plus the zero-shift
identity and mod-26 wrap, encrypt/decrypt round-trips over random digit keys × random
lengths, exact agreement with `vigenere_*` fed the same digits as its cycleword, and the
keylen-1 / over-long-key edge cases), and
`tests/test_phillips.c` (the Phillips primitives: the full ACA `DIAGONALS` worked-example
known-answer vector — the 81-letter `squares one…is forty` → `KZWLY…GREYXO` — plus an
assertion pinning `phillips_build_squares`' 8-square Row table cell-for-cell against the
ACA's printed squares #1–#8, encrypt/decrypt round-trips over random base squares × random
lengths for ALL THREE variants and a side-generic 6x6, and the documented structural facts
— the column-rotation symmetry, its row-rotation dual, the #1≡#5 / #2≡#8 cyclic equivalences,
and that the 8 derived squares are distinct grids), and
`tests/test_twosquare.c` (the Two-Square primitives: the ACA worked-example known-answer
vector for the horizontal type — the two printed squares, `anothe…px` → `IRRTEHMKGIMEQGRUNMMZSV`
— and the Wikipedia worked-example for the vertical type — EXAMPLE/KEYWORD → `HEDLXW…` — plus
encrypt/decrypt round-trips over random squares × random lengths for BOTH arrangements and a
side-generic 6x6, the vertical type asserted SELF-INVERSE, and the documented transparencies
asserted directly — horizontal same-row → reversed pair, vertical same-column → unchanged), and
`tests/test_foursquare.c` (the Four-Square primitives: the Wikipedia worked-example known-answer
vector — keyed squares EXAMPLE/KEYWORD over the fixed standard squares, `HELP…` → `FYGMKY…` —
encrypt/decrypt round-trips over random keyed squares × random lengths and a side-generic 6x6,
and a degenerate identity-square check pinning the exact coordinate algebra), and
`tests/test_adfgvx.c` (the ADFGVX/ADFGX primitives: a HAND-COMPUTED known-answer vector pinning
the whole convention end to end — identity 5x5 square, `ATTACK` + keyword `KEY` → `AGADAGAFGGAX`
— the label tables, the K=1 (identity-columnar) edge case, and encrypt/decrypt round-trips over
random squares × random column counts × random lengths incl. ragged grids and both read
directions, for both the 5x5 (ADFGX) and the side-generic 6x6 (ADFGVX, 36 cells) squares).
`make testopt` additionally runs the in-process solver regressions
`tests/test_solver.c` (polyalphabetic), `tests/test_playfair_solver.c` (Playfair:
validates the per-type schedule registry, asserts an 800-char capability floor, and
prints recovery vs ciphertext length to characterize the short-text cliff),
`tests/test_bifid_solver.c` (Bifid: registry validation, the period-estimator top-K hit
rate, a capability floor with the period *estimated* end-to-end, and the length cliff),
`tests/test_trifid_solver.c` (Trifid: the same four checks over the 27-symbol cube),
`tests/test_hill_solver.c` (Hill: registry validation, block-size *selection* with
k swept, a k=2 and a k=3 capability floor, and the k=2 length cliff), and
`tests/test_gronsfeld_solver.c` (Gronsfeld: confirms it has *no* registry entry and rides
the polyalpha defaults, a capability floor with the period *estimated* end-to-end and again
pinned, and the length cliff), and
`tests/test_phillips_solver.c` (Phillips: registry validation for all three variant types
plus a non-registry type left untouched, a ~760-char capability floor for EACH variant — Row
through the registry default, Column/Row-Column at an explicit budget — and a Row length
cliff showing recovery from ~200 characters),
`tests/test_twosquare_solver.c` (Two-Square: registry validation for both arrangements plus a
non-registry type left untouched, a ~900-char capability floor — horizontal through the
registry default, vertical at an explicit budget — a horizontal length cliff, and the
extra-thorough additions: a transparency-rate measurement (~20% same-row digraphs) and a
multi-keyword sweep reporting mean/worst recovery), and
`tests/test_foursquare_solver.c` (Four-Square: registry validation, a ~900-char capability
floor with a PER-SQUARE recovery breakdown — even positions decrypt through the upper-right
square, odd through the lower-left — a length cliff, and a multi-keyword sweep), and
`tests/test_adfgvx_solver.c` (ADFGX/ADFGVX: registry validation for both types plus a
non-registry type left untouched; an ADFGX capability floor with the column count K pinned;
a BLIND K-selection test — K swept, the solver must report the true K, exercising the IoC
decoupling term; an ADFGX length cliff; an ADFGX multi-keyword sweep (mean/worst); and an
ADFGVX 6x6/36-symbol capability floor over the digit-bearing alphabet).
`ciphers/tests/` additionally holds
end-to-end cases (ciphertext + `*_solution.txt`, plus `*_solve.sh` runners — e.g. the
`transcol_*_solve.sh` columnar recovery tests and `playfair_solve.sh`) you can run by hand.

`ciphers/tests/run_tests.sh` is the **accuracy regression suite**: a manifest of
43 end-to-end cases (Vigenère, Gronsfeld, Beaufort, Porta, Quagmire I–IV, autokey, the ACA
`q*_p1xx` puzzles, pure-transposition types, a homophonic substitution, a Playfair
cipher, a Bifid cipher, a Trifid cipher, a Hill cipher, the three Phillips
variants — Row / Column / Row-Column — a Two-Square (horizontal + vertical), a
Four-Square cipher, and an ADFGX cipher (`adfgx_decl`, K pinned)) that each
solve to ~100% with a **fixed `-seed`** and quadgrams. It runs the solver, pulls the
recovered plaintext from the last field of the `>>>` CSV line, compares it
character-for-character to a sibling `<name>.solution` (bare A–Z plaintext), and prints
per-test accuracy + time + mean, exiting non-zero if any test drops below the threshold
(default 99%; the homophonic case lands ~99.9%). Because the seed is fixed, a
bit-identical refactor keeps every score at 100% and any behavioural regression shows up
immediately. Each test's `-nrestarts`/`-nhillclimbs` are trimmed to the smallest that
still lands on the solution at the seed, so the full run is ~2 min (was ~45 before
trimming). The manifest tags each case `fast` or `slow`:
`./run_tests.sh --fast` runs the 21-case fast tier in ~50s (use while iterating),
`--slow` the 21 heavier ciphers (incl. the ~24s Playfair, ~6s Bifid, ~18s Trifid, the
three ~13s Phillips solves, the two ~10s Two-Square solves, the ~17s Four-Square and the
~10s ADFGX), no flag runs both.
Add a case by appending a
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
`transcol2`/`18`, `indep`/`28`, `homophonic`/`29`, `playfair`/`pf`/`30`, `bifid`/`bf`/`31`,
`trifid`/`tf`/`tri`/`32`, `hill`/`33`, `gronsfeld`/`gron`/`34`,
`phillips`/`phil`/`35`, `phillips-c`/`36`, `phillips-rc`/`37`,
`twosquare`/`ts`/`38`, `twosquare-v`/`tsv`/`39`, `foursquare`/`fs`/`40`,
`transcol-l`/`coltrack`/`41`, `transroutecol`/`routecol`/`42`, `transtile`/`tile`/`43`,
`adfgx`/`44`, `adfgvx`/`adfg`/`45`
(full list in `parse.c`; codes in `colossus.h`). Output is a human-readable block followed by a
`>>> ...` one-line CSV summary that batch runs grep/sort.

By default only the **first line** of the `-cipher` file is read (the rest is ignored,
e.g. a trailing `plaintext = ...` annotation). Pass **`-multiline`** to read the whole
file, dropping newlines so a ciphertext laid out over several lines (e.g. a homophonic
grid like Zodiac-408) is concatenated into one symbol stream.

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

**Three additional transposition solvers** (added from the W168 toolkit review; see
`COLOSSUS_ADDITIONS.md`) extend the columnar family. All preserve spaces/periods as grid
cells and are isolated by their own early branch in `solve_cipher`:
- `transcol-l`/`coltrack`/`41` → `solve_columnar_track()` (`columnar_track_solver.c`): a
  **columnar with a within-column row permutation `L`** (the jarl / "dave transposition"
  scheme). The engine anneals the column order under the cheap **identity-L** reading (the
  within-row n-grams discriminate the order); the exact best `L` is recovered **once at
  report** via the Held-Karp **seam decomposition** (`seam_best_row_order`, `trans_common.c`)
  -- nesting best-L per eval is both slower and worse (it flattens the column-order contrast).
  Needs a complete grid (`len % K == 0`) for best-L; a ragged grid degrades to a plain
  columnar. Sweeps `K` over `-mincols..-maxcols`, optionally crossed with `-readdir` (column
  dir) and `-readrowdir lr|rl|both` (row dir, Rec 4). The reward-only quadgram table makes the
  seam ambiguous, so it effectively needs **`-logprob`** and/or the dictionary term.
  **`-cribanchored`** switches to a STRUCTURAL crib attack (a soft crib gives no gradient on a
  shallow many-column grid): the cipher's R-char blocks ARE the grid columns, a crib fixes some
  cells of each column, and a backtracking **block<->column matching** (most-constrained
  column first, n-gram + word-coverage tie-break) collapses the otherwise-intractable K-column
  search -- the only reliable attack on a shallow keyed columnar (assumes `L = identity`). This
  cracks all ten length-28 keyed columnars in `ciphers/W168/dave_tests/` from a 3-row crib
  (`ciphers/W168/dave_tests/solve_all.sh`, 10/10).
- `transroutecol`/`routecol`/`42` → `solve_route_chain()` (`route_chain_solver.c`): a two-stage
  **chain** -- a fixed geometric read-route global (`route_cells`, the 6 colossus routes)
  composed with a searched **column key**, read with the seam best-L. Sweeps the complete-grid
  rectangles and all routes; anneals the column key. Blind recovery is hard (the route adds a
  layer); best on short / favorable ciphers.
- `transtile`/`tile`/`43` → `solve_tile()` (`tile_solver.c`): a **sub-grid / tile
  transposition** -- every `h x w` tile of the grid is permuted by the same cell permutation
  (`-tile h w`, default 2x2), composed with a columnar column-order global. The engine
  **jointly** anneals the column order and the tile permutation; primitive `decrypt_tile`
  (`transpositions.c`). Complete grid only.

**Shared scoring additions (Rec 2, `dict.c`):** an optional `-weightword <f>` (default 0 =>
bit-identical) folds a length-weighted dictionary **word-coverage** reward into the
space-preserving transposition decrypt score (`word_set_build`/`word_coverage` + a fast hash
set); the same coverage breaks ties in the seam best-L. New raw additive n-gram sum
`ngram_sum_raw` (`scoring.c`) makes the seam decomposition exact. These are used only by the
new solvers; every existing solve is byte-for-byte unchanged. Note: `main()` no longer trims
trailing whitespace for the pure-transposition types (a trailing space is a real grid cell);
all existing transposition test ciphers are trailing-space free, so this is bit-identical.

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

The **Playfair** type (`solve_playfair()`, `PLAYFAIR_MODEL`, `SHAPE_ANNEAL`) is a
digraphic substitution over a **5x5 keyed grid** of 25 letters. The binary forces a
25-letter alphabet for `-type playfair` (J merged into I by ACA convention) via
`init_alphabet("J")` *before* `load_ngrams`, so the n-gram table is built over the same
25 letters (base-25 packing) and the grid is simply a permutation of `0..24` carried in
the `key` lane. The primitives live in `playfair.c` (`playfair_decrypt` is all the solver
needs; `encrypt`/`prepare`/`grid_from_keyword` serve the generator + unit tests). The
attack hill-climbs / anneals the grid with n-gram scoring (the classic SA Playfair
break): the move set is a single **cell swap** (dominant) plus **row/column swaps** and
**grid reflections** — the larger moves jump the local optima a cell swap can't escape;
cyclic row/column *rotations* are deliberately excluded (they re-encipher identically, so
the recovered grid is unique only up to such a rotation, but the recovered plaintext is
not). No anti-collapse penalty is needed (a grid is a bijection). Playfair is genuinely
near the limit of a quadgram attack: `-logprob` is effectively required, and recovery is
reliable from ~600+ characters and falls off a cliff below a few hundred (see
`tests/test_playfair_solver.c`, which prints the curve). Like every type it honours
`-method shotgun|anneal`; annealing is the default and far stronger here. Generate test
ciphers with `tools/playfair_gen.c` (`make playfair_gen`).

The **Bifid** type (`solve_bifid()`, `BIFID_MODEL`, `SHAPE_ANNEAL`) is Delastelle
fractionation over a **keyed Polybius square**: each letter splits into (row, col)
coordinates, the block's rows-then-cols coordinate stream is re-paired into ciphertext
letters, and the block size is the **period**. It defaults to the same 5x5, 25-letter,
J->I square as Playfair (`init_alphabet("J")` before `load_ngrams`), with the square a
permutation of `0..24` in the `key` lane; the primitives (`bifid.c`) are **side-generic**
(`side`/`n = side*side` parameters) so a 6x6 (36-cell) square works once a 36-letter
alphabet is active. The square attack is identical to Playfair's (cell-swap-dominated
anneal + row/column swaps and reflections, no anti-collapse penalty — a square is a
bijection). The extra dimension is the period: `bifid_estimate_periods()` ranks trial
periods by the **columnar Index of Coincidence** (the existing `mean_ioc()`), which peaks
at the true period because each within-block position becomes a coordinate-pure column.
The IoC also peaks at *multiples* of the true period, so the true period is not always
rank 1 — but it is reliably in the top-K, and the solver anneals the top `-nperiods` (default
5) candidates as separate engine configs and lets the n-gram score pick the winner (a wrong
period decrypts to gibberish). `-period N` pins a single period; `-maxperiod` bounds the
estimator's scan (default `min(20, len/2)`). Like Playfair it effectively needs `-logprob`
and recovers reliably from ~350+ characters (see `tests/test_bifid_solver.c`, which prints
the period-estimator hit rate and the length cliff). Generate test ciphers with
`tools/bifid_gen.c` (`make bifid_gen`).

The **Trifid** type (`solve_trifid()`, `TRIFID_MODEL`, `SHAPE_ANNEAL`) is Bifid lifted
into **three dimensions**: each letter splits into (layer, row, col) coordinates over a
**keyed 3x3x3 cube**, the block's layers-then-rows-then-cols coordinate stream is re-
grouped into consecutive *triples* that index new cube cells, and the block size is the
**period**. A 3x3x3 cube has **27 cells**, one more than the 26-letter alphabet, so Trifid
runs on a **27-symbol alphabet — A..Z plus a 27th symbol `+`** (`init_alphabet_trifid()`
before `load_ngrams`; the cube is a permutation of `0..26` in the `key` lane). This is the
one type whose runtime alphabet `g_alpha` exceeds 26: `ALPHABET_SIZE` (26) stays the
hardcoded mod base of the polyalphabetic primitives, and a separate `MAX_ALPHABET_SIZE`
(27) sizes only the runtime alphabet maps (`g_idx_to_char_arr`, `g_monograms`) and the
ciphertext-facing IoC scratch — everything indexable by a live symbol id. The `+` decodes
because `ord()`/`char_to_index()` consult `g_char_to_idx` for any registered ASCII char,
not just letters (bit-identical for A..Z input). The primitives (`trifid.c`) are
**side-generic** (`side`/`n = side^3`). The cube attack is the same anneal as Bifid/Playfair
(cell-swap-dominated + structured plane-swap/reflection moves along the cube's three axes,
no anti-collapse penalty — a cube is a bijection). The period is recovered exactly as
Bifid's (`trifid_estimate_periods()` over `mean_ioc()`, top-`-nperiods` annealed). Like
Bifid it effectively needs `-logprob` and recovers reliably from ~450+ characters (see
`tests/test_trifid_solver.c`). Generate test ciphers with `tools/trifid_gen.c`
(`make trifid_gen`).

The **Hill** type (`solve_hill()`, `HILL_MODEL`, `SHAPE_ANNEAL`) is a **polygraphic
substitution**: a block of `k` plaintext letters (a column vector) is multiplied by a
`k×k` key matrix **mod 26**, so it runs on the **full 26-letter alphabet unchanged**
(`ALPHABET_SIZE` is already the mod base — no `init_alphabet` forcing). The crucial design
choice: the state carried in the `key` lane **is the decryption matrix `D`**, applied
straight to the ciphertext (`plain = D·cipher mod 26`), so the hot path never inverts a
matrix; the true plaintext came from an invertible encryption key `K`, so the climb
converges on `D = K⁻¹`, and the matrix is inverted **only at report time**
(`hill_mat_inverse`, via a cofactor determinant + adjugate) to display the recovered
encryption key. The block size `k` has no IoC-style estimator, so the solver simply
**sweeps `k = 2..5`** (one engine config each, `-period` pins one; `cipher_len >= 2*k`
required) and the n-gram score picks the winner — a wrong `k` decrypts to gibberish. The
attack is a matrix anneal: ~85% change one element to a different random value (the
dominant fine move), ~10% randomize a whole row, ~5% add a random multiple of one row to
another mod 26 (a coarse jump). **A singular decryption matrix (det not coprime to 26) is
penalised** (`HILL_SINGULAR_PENALTY`, via the decrypt hook's `score_adjust`): unlike
Playfair/Bifid/Trifid a Hill matrix is a bijection *only* when invertible, and a singular
one folds the ciphertext onto a sub-lattice, decrypting to a low-entropy repetitive string
(the zero matrix → all `A`s) that out-scores real plaintext on n-grams and would otherwise
attract the climb into a collapse. Like the other near-the-limit types it effectively needs
`-logprob`. **The
search lever is restarts, not iterations**: the matrices are small (k=2 is only 26⁴ keys),
greedy climbs converge fast, and the landscape is rugged, so the schedule favours **many
short restarts**. k=2 and k=3 are reliably breakable ciphertext-only; k≥4 is exercised
only by the primitive round-trip/inverse tests (`tests/test_hill.c`), not asserted as a
ciphertext-only solve (`tests/test_hill_solver.c` characterizes the k=2/k=3 capability).
The primitives (`hill.c`) are **generic in `k`** (the determinant/inverse use cofactor
expansion, fine for `k <= HILL_MAX_K = 5`). Generate test ciphers with `tools/hill_gen.c`
(`make hill_gen`).

The **Gronsfeld** type (`gronsfeld`/`gron`/`34`) is a **Vigenère cipher with a numeric
key**: the per-column shift is a key digit `0..9` (`C = P + d`, `P = C − d`, mod 26), so
it is exactly Vigenère restricted to the 10 smallest shifts. Unlike Hill/Bifid/… it is
**not** a separate `CipherModel` — it is a type *inside* the shared `POLYALPHA_MODEL`
(`polyalpha_solver.c`), wired to behave like `VIGENERE` (straight pt/ct alphabets, only the
cycleword is searched) with one change: the **cycleword/shift domain is bounded to `0..9`**
(`GRONSFELD_DIGITS`) in the seed, perturb, and — crucially — the `derive_optimal_cycleword`
column search (`smax` in `optimal_cycleword.c`). So it reuses the whole polyalpha pipeline
(IoC period estimation, the deterministic optimal-cycleword frequency attack, crib
handling); the digit bound is a strong prior that makes recovery faster and reliable from
shorter text than an unconstrained Vigenère solve. The cycleword *is* the key, so the
decrypt path calls a tight direct primitive (`gronsfeld_decrypt`, `gronsfeld.c`) rather
than the Quagmire indirection, and the report prints the recovered key as digits. It rides
the polyalphabetic search defaults (no registry entry) and the default reward-only quadgram
table (no `-logprob` needed, like Vigenère). Generate test ciphers with
`tools/gronsfeld_gen.c` (`make gronsfeld_gen`; the key arg is a digit string, e.g. `31415926`).

The **Phillips** type (`solve_phillips()`, `PHILLIPS_MODEL`, `SHAPE_ANNEAL`) is a **periodic
monographic substitution over 8 keyed Polybius squares** derived from one base 5x5 square. The
plaintext is split into blocks of 5 letters; block `b` is enciphered with square `(b mod 8)`,
each letter going to the one diagonally **down-right with wrap** (`cipher = sq[(r+1)%5][(c+1)%5]`),
so the overall period is 40. The 8 squares are derived from the base by a fixed row-reinsertion
table (squares 1–5: base row 0 reinserted at row positions 0–4; squares 6–8: then row 1 reinserted
at positions 1–3) — verified cell-for-cell against the ACA worked example. It runs on the same
25-letter (J→I) grid as Playfair/Bifid (`init_alphabet("J")` before `load_ngrams`), with the base
square a permutation of `0..24` in the `key` lane. The only unknown is that base square, so the
attack is **identical to Playfair's** (cell-swap-dominated anneal + row/column swaps and grid
reflections, no anti-collapse penalty — every derived square, and hence the whole map, is a
bijection) — but *monographic* (no digraph prep) and with **no period to estimate** (block size 5
and the 8-square cycle are fixed → a single engine config). Because it carries more signal per
character than digraphic Playfair, it recovers reliably from **~200+ characters** (see
`tests/test_phillips_solver.c`) and rides a leaner registry budget than Playfair (`4×250000`).
Like the other near-the-limit square types it effectively needs `-logprob`. The cyclic-column
rotation of the base re-enciphers identically, so the recovered square is unique only up to that
(the plaintext is unique). **Three variants** select how the 8 squares are built, all sharing the
solver/primitive: `phillips` (the ACA-standard **Row** type), `phillips-c` (**Column** — the same
reinsertion applied to columns), and `phillips-rc` (**Row-Column** — rows for squares 2–5, columns
for 6–8). The primitives (`phillips.c`) are **side-generic** (`2·side−2` squares of `side` letters).
Generate test ciphers with `tools/phillips_gen.c` (`make phillips_gen`; the variant arg is
`row`/`col`/`rowcol`).

The **Two-Square** (`solve_twosquare()`, `TWOSQUARE_MODEL`) and **Four-Square**
(`solve_foursquare()`, `FOURSQUARE_MODEL`) types are digraphic substitutions over **two keyed
5x5 squares** (`SHAPE_ANNEAL`). They run on the same 25-letter (J→I) grid as Playfair
(`init_alphabet("J")` before `load_ngrams`), but the state is a **pair** of squares packed
back-to-back in the `key` lane (sq1 = `key[0..24]`, sq2 = `key[25..49]`) — **50 cells, double
Playfair's**. For each plaintext digraph the two letters span a rectangle and the cipher pair is
the rectangle's other two corners (`twosquare.c` / `foursquare.c`; verified cell-for-cell against
the ACA Two-Square and Wikipedia Four-Square worked examples). The attack is the **same SA square
break as Playfair** — cell-swap-dominated moves plus row/column swaps and reflections, no
anti-collapse penalty (every square is a bijection) — but each move perturbs **one of the two
squares** (chosen uniformly) and there is **no period to estimate** (a single engine config). The
only prep is padding an odd plaintext with one `X` (no doubled-letter handling, unlike Playfair).
The larger 50-cell state needs more text and a bigger budget; like the other square types it
effectively needs `-logprob`. **Two-Square has two arrangements** sharing the solver/primitive,
selected by `cfg->cipher_type`: `twosquare` (the ACA **horizontal**, squares side by side — a
same-ROW digraph maps to the reversed pair) and `twosquare-v` (**vertical**, squares stacked — a
same-COLUMN digraph maps to itself, and the whole cipher is **self-inverse** so decrypt ==
encrypt). About **20% of digraphs are such transparencies**, a documented weakness that leaks
plaintext and makes Two-Square recover from short text. **Four-Square** keeps the upper-left and
lower-right squares as the **fixed standard alphabet** (`foursquare_standard_square()`); only the
upper-right (UR) and lower-left (LL) squares are keyed, and the two are independent — making it
the hardest of the family (its report breaks recovery down per-square: even cipher positions
decrypt through UR, odd through LL). The primitives are **side-generic** (`side`/`n = side*side`).
Generate test ciphers with `tools/twosquare_gen.c` / `tools/foursquare_gen.c`
(`make twosquare_gen foursquare_gen`; the Two-Square variant arg is `h`/`v`).

The **ADFGVX** (`adfgvx`/`adfg`/`45`) and **ADFGX** (`adfgx`/`44`) types (`solve_adfgvx()`,
`ADFGVX_MODEL`, `SHAPE_ANNEAL`) are the classic WWI cipher: a **keyed Polybius-square
fractionation composed with a keyed columnar transposition** — the first
*fractionation-then-transposition* type, and the hardest of the polygraphic family because
the square and the column order must be recovered **jointly**. Each plaintext symbol becomes
its two cell coordinates, each a label from `{A,D,F,G,X}` (ADFGX, 5x5, 25 letters J→I) or
`{A,D,F,G,V,X}` (ADFGVX, 6x6, **36 symbols** A..Z + 0..9), so the ciphertext is **2N labels**
for an N-symbol plaintext; that 2N coordinate stream is then columnar-transposed under a
keyword of length K. ADFGX runs on the same 25-letter J→I alphabet as Playfair/Bifid;
ADFGVX forces a **36-symbol alphabet** (`init_alphabet_adfgvx()`, A..Z + digits, with the
digits at negligible monogram weight like the Trifid `+`), which is why `MAX_ALPHABET_SIZE`
is **36** (the largest runtime alphabet, sizing only the runtime alphabet maps + the IoC
scratch; the n-gram table is then base-36 — quadgrams 36⁴≈6.7M floats are fine, but **avoid
quintgrams** at base 36, ~240MB). The primitive (`adfgvx.c`) works in **coordinate space**
(the solver maps the label characters to coordinates 0..side-1 up front) and is **side-generic**,
reusing `bifid_grid_from_keyword`/`bifid_build_inverse` for the square and the exposed
`decrypt_columnar` for the transposition stage — so it adds almost no new cipher math.
The state carries the square (`key[0..n-1]`, a permutation) **and** the column order
(`key[n..n+K-1]`); one engine config is enumerated per column count K in `-mincols..-maxcols`,
the square move set is Bifid's, the column-order move set the columnar solver's, and a move
perturbs one or the other. **The key to making the coupled search tractable** is a
**structural IoC reward folded into `score_adjust`**: after undoing the *correct* columnar
the paired cell ids are a monoalphabetic image of the plaintext, so the decrypt's Index of
Coincidence is English (~0.066) — and that IoC depends ONLY on the column order, not the
square (a square just relabels cells). The reward therefore gives the column-order search a
gradient independent of the square, decoupling the two halves (the climb locks the column
order by IoC, then the n-gram score recovers the square). Like the other near-the-limit
square types it effectively needs `-logprob`; ADFGX recovers reliably from ~200+ characters,
ADFGVX (the 36-cell square) needs more text and a bigger budget. Cribs are not used (the crib
positions are over the ciphertext, which is 2x the plaintext). Generate test ciphers with
`tools/adfgvx_gen.c` (`make adfgvx_gen`; args are a square keyword, a transposition keyword,
and `adfgx`/`adfgvx`).

**Per-cipher-type search schedules (`SearchDefaults`, `apply_cipher_defaults`).** The
`init_config()` globals (`inittemp 0.10`, `1x1000`, ...) suit the polyalphabetic /
transposition reward-score scale; a type whose score lives on a very different scale
needs its own schedule. A small compiled-in registry (`g_search_defaults[]` in
`colossus.c`) keyed by cipher type carries a tuned profile for **both** search shapes
(anneal + shotgun). `main()` pre-scans `-type`/`-method` and overlays the matching profile
*before* the main arg loop, so precedence is **globals < registry < explicit CLI flags**.
Types with no entry keep the global defaults bit-for-bit (so the regression suite is
unaffected) — currently Playfair (`SHAPE_ANNEAL`, `6x400000`, `inittemp 0.08`,
`backtrack 0.30`), Bifid (`SHAPE_ANNEAL`, `4x200000` per period, `inittemp 0.08`,
`backtrack 0.30`), Trifid (`SHAPE_ANNEAL`, `6x300000` per period, `inittemp 0.08`,
`backtrack 0.30` — a larger budget for the 27-cell cube), Hill (`SHAPE_ANNEAL`,
`250x8000` per swept block size, `inittemp 0.10`, `backtrack 0.25` — many short restarts,
since the small matrix climbs converge fast), Phillips and its two variants
(`SHAPE_ANNEAL`, `4x250000`, `inittemp 0.08`, `backtrack 0.30` — a single config, leaner
than Playfair since monographic Phillips recovers from shorter text), Two-Square and its
vertical variant (`SHAPE_ANNEAL`, `8x600000`, `inittemp 0.08`, `backtrack 0.30`) and
Four-Square (`SHAPE_ANNEAL`, `12x700000` — the biggest budget, for its two independent
keyed squares), ADFGX (`SHAPE_ANNEAL`, `12x600000` per swept column count K) and ADFGVX
(`SHAPE_ANNEAL`, `16x800000` per K — more, for the 36-cell square; both anneal at
`inittemp 0.08`, `backtrack 0.30`) have tuned entries (the two/four-square budgets are
larger than Playfair's for the 50-cell two-square state; the ADFGVX budgets are the largest,
for the coupled square+columnar search).
This is the mechanism for moving the magic
per-type budgets out of the run scripts and into the binary; add tuned entries for other
types incrementally. The registry is validated end-to-end in `tests/test_playfair_solver.c`.

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

- **Shared core header + thin per-module headers.** `colossus.h` is the shared
  *core*: the config/ctx/model structs, constants, cipher-type codes, globals, inline
  RNG, and the cipher-*primitive* prototypes (`vigenere_decrypt`, `decrypt_columnar`,
  `playfair_decrypt`, …) — every `.c` includes it. The cipher-agnostic core (`engine`,
  `scoring`, `trans_common`) and each per-cipher-type solver also get a *thin* `.h`
  exposing only that module's public API (`solve_<type>()`, the engine/scoring entry
  points); a `.c` includes the module headers it calls into. Put new solver prototypes
  in the module header, new shared structs/constants/primitive prototypes in `colossus.h`.
  (The already-split primitive files — `vigenere.c`, `beaufort.c`, … — keep their
  prototypes in `colossus.h` rather than carrying their own headers.)
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
