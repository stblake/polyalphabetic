# Transposition attacks — design

Attack designs for every transposition-family cipher type in `ACA_ciphers.csv`,
built to plug into the solver's existing **shotgun hill-climber + n-gram scoring**
engine. Conventions follow the ACA (https://www.cryptogram.org/resource-area/cipher-types/).

## The 13 types in the database

| Type (CSV label)   | n   | ACA cipher              | Length fingerprint        | Engine        |
|--------------------|-----|-------------------------|---------------------------|---------------|
| Transposition      | 21  | Complete columnar       | composite (mult. of K)    | **exists**    |
| CC Tramp           | 13  | Complete columnar       | composite                 | **exists**    |
| IC Tramp           | 12  | Incomplete columnar     | any (incl. prime 73, 83)  | **exists**    |
| (Dbl Col Transp)\* | —   | Double columnar         | any                       | **exists**    |
| Amsco              | 30  | Amsco                   | any                       | new: columnar+fill |
| Myszkowski         | 16  | Myszkowski              | composite                 | new: ranked columnar |
| Railfence          | 17  | Rail fence              | any                       | new: enumerate |
| Variant Railfen    | 1   | Rail-fence variant      | any                       | new: enumerate |
| Redefence          | 12  | Keyed rail fence        | any                       | new: rail perm |
| Route Tramp        | 8   | Route transposition     | composite (R×C)           | new: enumerate |
| Cadenus            | 8   | Cadenus                 | **multiple of 25**        | new: keyword   |
| Nihilist Tramp     | 11  | Nihilist transposition  | **perfect square** N²     | new: single perm |
| Swagman            | 9   | Swagman                 | multiple of period N      | new: Latin sq. |
| Grille             | 12  | Turning grille          | **perfect square** N²     | new: hole map  |

\* not in our extracted set but present in the wider CSV; already covered by `transcol2`.

## Implementation status

| Type        | CLI `-type`            | Status        | Notes |
|-------------|------------------------|---------------|-------|
| Columnar    | `transcol` / `transcol2` | done (pre-existing) | complete/incomplete/double |
| Railfence   | `railfence` (`rail`, `varrailfence`) | **done** | enumerates rails (`-mincols`/`-maxcols`) × starting phase; subsumes Variant Railfence. Regression: `railfence_aca`. |
| Route       | `route` (`routetramp`) | **partial**   | solver + `-variant` done; route library now = {rows-snake, cols-snake, spiral-cw, spiral-ccw, diag-snake, diag} (6). ACA route transposition is a large family; some corpus Route Tramps still use routes outside the set (fragments recover but not the full order). Extend `route_cells()` / bump `N_ROUTES` to add more. |
| Amsco       | `amsco`                | **done**      | sweeps K × start-chunk {1,2}, climbs column order. 6/8 sampled corpus cases crack cleanly (two use a non-standard cut). Regression: `amsco_aca`. |
| Myszkowski  | `myszkowski` (`mysz`)  | **done**      | sweeps K, climbs the rank vector (ties). Regression: `myszkowski_aca`. |
| Redefence   | `redefence` (`rede`)   | **done**      | sweeps rails × phase, climbs the rail read-order. 3/3 sampled crack. Regression: `redefence_aca`. |
| Cadenus     | `cadenus`              | **done**      | K = len/25; climbs decoupled column order + per-column rotation (convention-agnostic). Regression: `cadenus_aca`. |
| Nihilist    | `nihilist` (`nihilisttramp`) | **done** | N = √len; climbs independent row+column perms × read-direction. Regression: `nihilist_aca`. Square grids share the block-order ambiguity (see note). |
| Swagman     | `swagman`              | **done**      | sweeps N∈[3,7] × read-mode; climbs the N×N key square (each column a permutation). 3/3 sampled crack. Regression: `swagman_aca`. |
| Grille      | `grille`               | **done**      | N = √len; climbs the per-rotation-orbit turn assignment {0..3} (handles even N and the odd-N centre orbit). 3/3 sampled crack. Regression: `grille_aca`. |

**Block-order ambiguity / cribs.** A few types (Amsco's start-parameter, Nihilist on square
grids) admit a near-solution that is the true plaintext cut into correct-English blocks
reordered — n-gram score cannot separate it from the exact solution, so the recovered text
has the right words in a shuffled block order. This is a scoring limit, not a solver bug;
supplying a `-crib` (honoured by every solver via `state_score`) pins the alignment and
resolves it.

The permutation-style solvers share `transposition_anneal()` (in `polyalphabetic.c`): a
shotgun/Metropolis key climber taking per-type `decrypt`/`move`/`seed` callbacks, so each
new type supplies only those three small functions. Every new type follows the same
modular slice: a `decrypt_<type>(…, int variant, int out[])` primitive in
`transpositions.c` (with a round-trip unit test in `tests/test_transpositions.c`), a
`solve_<type>()` in `polyalphabetic.c` sharing `report_transposition()` for output, a
`-type` alias in `parse.c`, a code in the header, and a banner + dispatch in
`main`/`solve_cipher`. `-variant` swaps the encrypt/decrypt direction per the global
convention (handled uniformly by the `apply_perm()` helper).

The 625 untyped, frequency-detected files (`transposition_*_digitalcons_*.txt`) have an
**unknown subtype** — see the auto-cascade (§4).

---

## 1. The shared engine (what every attack reuses)

The solver already isolates pure-transposition types in an early branch of
`solve_cipher()` and solves them by optimization, not the keyword/cycleword machinery.
Three solvers exist today (`polyalphabetic.c` / `transpositions.c`):

- `solve_columnar` / `shotgun_columnar_climber` — optimizes a **column-order
  permutation** (length `K`) via `decrypt_columnar()`; `transcol` sweeps `K` over
  `-mincols..-maxcols`, `transcol2` anneals two keys. Handles incomplete grids and
  `-readdir`.
- `solve_general_transposition` / `shotgun_permutation_climber` — the full permutation
  key with the `key_structure_score` guard and Metropolis annealing.
- `solve_transposition` / `shotgun_transposition_climber` — a small **parameter vector**
  (`transmatrix` w1,w2,dir; `transperoffset` d,n).

Every new attack below is one of exactly **three shapes**, all of which the existing
climber scaffolding already supports:

- **Shape A — enumerate.** Key space is tiny (≤ a few thousand). No hill-climbing:
  loop all keys, `ngram_score`, keep best. (Railfence, Route.)
- **Shape B — permutation climb.** Key is a permutation of length `K`/`R`/`N`. Reuse the
  column-swap annealing loop already in `shotgun_columnar_climber`. (Redefence, Amsco,
  Myszkowski, Cadenus, Nihilist, Swagman.)
- **Shape C — labeled-array climb.** Key is a fixed-length array over a small label set
  (e.g. grille cell→rotation 0–3). Same annealing loop, different move. (Grille.)

### Proposed factoring (idiomatic, not "clever generic")

Keep the explicit `switch (config->cipher_type)` dispatch in `solve_cipher`'s
transposition branch — one `solve_<type>()` per cipher, exactly like `solve_columnar`
exists today. Pull the *climbing scaffold* that `shotgun_columnar_climber` and
`shotgun_permutation_climber` already near-duplicate into one shared static helper:

```c
/* shotgun restarts + slip/backtrack + Metropolis cooling, shared by all key-climb types */
double transposition_anneal(int *best_key, int key_len,
                            void (*decrypt)(const int *ct, int n, const int *key, int *pt, const Dims *d),
                            void (*propose)(int *key, int key_len),   /* in-place neighbor move */
                            void (*seed)(int *key, int key_len),      /* random/structured restart */
                            const int *ct, int n, const Dims *dims,
                            const NgramCtx *ng, int nrestarts, int niters);
```

Each `solve_<type>()` supplies its `decrypt` / `propose` / `seed` and the inferred
`Dims`. This removes the duplication between the two existing climbers and gives every
new type the same battle-tested restart/anneal/backtrack behaviour for free. (A
function-pointer *descriptor table* is the alternative, but a per-type `solve_*` plus a
shared helper matches the codebase's "explicitness over abstraction" rule better.)

### Cross-cutting efficiency rules

1. **Infer dimensions from length first** — prune before any search. `infer_dims(n, type)`
   returns the candidate `K` / `(R,C)` / `N` list. Non-square ⇒ skip Nihilist & Grille;
   `n % 25 ⇒` skip Cadenus; prime `n ⇒` columnar is the only single-stage fit. This alone
   collapses most of the work.
2. **No structure-score guard for constrained types.** `key_structure_score`
   (`-weightstructure`) exists only to stop the *free* permutation solver gaming the
   n-gram score. Every type below emits a genuine layout for every key, so the guard is
   off — same reasoning the CLAUDE.md gives for `transcol`.
3. **Quadgram log-prob is the universal fitness.** Transposition keeps real English
   letters, so `ngram_score` separates solved/unsolved sharply even at the ~50–150 letter
   lengths typical here. Cribs blend in via the existing `crib_score` if supplied.
4. **Column-swap is the dominant move** (Shape B), mirroring the existing climbers; add
   short reverses/block-moves as secondary moves, also already present.
5. Text stays in **0–25 integer arrays** end to end (no char round-trips).

---

## 2. Already covered

- **Transposition / CC Tramp / IC Tramp** → `-type transcol`. Column-order permutation,
  `decrypt_columnar` already handles complete *and* incomplete final rows. Sweep
  `K = 2..30`. CC sets `n % K == 0`; IC allows the remainder. The 21+13+12 labeled cases
  and most of the 625 untyped fall here. **No new code.**
- **Double columnar (Dbl Col Transp)** → `-type transcol2`. **No new code.**

---

## 3. New per-type attacks

### Railfence (Shape A — enumerate)
- **Cipher:** plaintext written in a zigzag over `R` rails, read rail by rail.
- **Key space:** `R ∈ [2, 12]` × starting direction {down,up} ≈ 22 keys.
- **Attack:** `decrypt_railfence(ct, R)` rebuilds the zigzag row-index pattern
  `0,1,…,R-1,R-2,…,1,0,…`, fills rails from the ciphertext in rail order, reads back
  along the zigzag. Enumerate all `R`, `ngram_score`, keep best. O(R·n). Instant.
- **Variant Railfence:** same module, add a `variant ∈ {0,1}` flag (alternate corner
  turning); enumerate it too. Covers the lone `Variant Railfen` case.

### Redefence (Shape B — permutation over rails)
- **Cipher:** rail fence whose `R` rails are emitted in a **keyed order** (+ optional
  start offset).
- **Key space:** outer `R ∈ [3, 12]` × offset; inner = permutation of `R` rails (`R!`).
- **Attack:** for each `(R, offset)`, compute rail lengths from the zigzag, then
  `transposition_anneal` over the **length-`R` rail permutation** (reuse column-swap
  moves). Decrypt = place keyed rail-segments back onto the zigzag. Outer sweep is tiny;
  inner `R ≤ 12` climbs fast.

### Amsco (Shape B — columnar with alternating fill)
- **Cipher:** grid filled down columns with chunks alternating **1,2,1,2…** letters
  (start = 1 or 2), then read by a keyed column order.
- **Key space:** outer `K ∈ [2, 12]` × `start ∈ {1,2}`; inner = column permutation.
- **Attack:** `amsco_cells(n, K, start)` deterministically tabulates each column's
  character-group sizes (fixed by `K`, `start`, row parity — independent of the key). For
  each `(K,start)`, `transposition_anneal` over the **length-`K` column order**: slice
  ciphertext into columns of the known sizes in key order, lay down, read across rows.
  Reuses the columnar climber with an Amsco column-size table.

### Myszkowski (Shape B — ranked columnar with ties)
- **Cipher:** columnar whose keyword has **repeated letters**; equal-ranked columns are
  read together, interleaved row by row.
- **Key space:** a **rank vector** `r[0..K-1]`, values `1..M ≤ K` with repeats. Sweep `K`.
- **Attack:** `decrypt_myszkowski(ct, r, K, n)` = generalized columnar read honouring
  ties (distinct ranks → whole column; tied ranks → interleave their columns left-to-right
  per row). `transposition_anneal` with two moves: swap two ranks, or relabel one column's
  rank (merges/splits ties). Generalizes the columnar solver; degenerates to it when all
  ranks distinct.

### Cadenus (Shape B — keyword, 25 rows)
- **Cipher:** `K = n/25` columns, **25 rows**; a `K`-letter keyword both orders the
  columns (alphabetical rank) and cyclically shifts each column vertically by its key
  letter's alphabet position.
- **Key space:** the `K`-letter keyword = a permutation of `K` (order) that also fixes the
  per-column rotations. Only `K ∈ {4,5,6,10}` occur (n = 100…250).
- **Attack:** require `n % 25 == 0`. `transposition_anneal` over the `K`-letter key; the
  decrypt un-rotates each column by the key-letter offset, then un-permutes columns, then
  reads rows. Swap moves on the key letters.

### Nihilist transposition (Shape B — single perm, both axes)
- **Cipher:** plaintext into an `N×N` grid by rows; one key permutation `P` permutes the
  **columns**, the **same** `P` permutes the **rows**; read by rows. `N = √n`.
- **Key space:** a single permutation of length `N` (`N ≈ 6–11`).
- **Attack:** require perfect-square `n`. `transposition_anneal` over one length-`N`
  permutation; decrypt applies `P⁻¹` to rows and columns. (One DB case is 128 = 8×16, a
  rectangular variant — handle by allowing `N_r×N_c` with two perms if `√n` fails.)

### Route transposition (Shape A — enumerate)
- **Cipher:** grid `R×C` (`R·C = n`) filled by rows, read along a geometric **route**.
- **Key space:** factor pairs of `n` × route set {row/col boustrophedon, 4-corner ×
  2-direction spirals, diagonals} × start corner ≈ a few hundred.
- **Attack:** `decrypt_route(ct, R, C, route_id, corner)`; enumerate all
  factorization×route, `ngram_score`, keep best. No climbing. Cheap.

### Swagman (Shape B — Latin-square key)
- **Cipher:** text in rows of width `N`; an `N×N` **Latin-square** key (each digit `1..N`
  once per row & column) sends, per row, each letter to an output slot. Period `N` small.
- **Key space:** the generating permutation (length `N`, e.g. the first column) determines
  the square; `N ∈ [3, 8]`, `n % N == 0`.
- **Attack:** sweep `N`; `transposition_anneal` over the length-`N` generator; decrypt by
  inverting the Swagman square. Swap moves on the generator.

### Turning grille (Shape C — labeled array)
- **Cipher:** `N×N` grille (`N` even) with `N²/4` holes; plaintext written through holes
  over 4 quarter turns. `N = √n`.
- **Key:** for each of the `N²/4` fundamental-quadrant cells, **which rotation 0–3**
  exposes it (each cell is a hole in exactly one of the 4 turns). Array length `N²/4`
  over {0,1,2,3}.
- **Attack:** require even-square `n`. `transposition_anneal` (Shape C) over the
  assignment array; move = re-pick one cell's rotation. Decrypt reads the four rotations
  in order. Search is larger than the others (`4^{N²/4}`) — give it more restarts.
  Odd squares (the 81-length case) use the odd-grille variant with a fixed centre cell.

---

## 4. The untyped 625 — auto-cascade

Driver `solve_transposition_auto(ct)` for unknown subtype:

1. **Feasibility filter** by length (§1 rule 1): square ⇒ {Nihilist, Grille}; `%25==0` ⇒
   +Cadenus; small factors ⇒ +Route/Swagman; everything ⇒ {columnar, railfence,
   redefence, amsco, myszkowski}.
2. **Portfolio pass:** run each feasible type's `solve_*` with a *small* restart budget;
   track the global best `ngram_score`.
3. **Escalate:** re-run only the top-scoring type with the full budget.
4. Report best plaintext **and the winning type** (so a confirmed solve can be written
   back to the manifest's `detection`/`type` columns).

This is cheap because the length filter eliminates most types outright, the enumerate
types (railfence/route) cost almost nothing, and only the single leading candidate gets
the expensive budget.

---

## 5. Implementation map

- `transpositions.c` — new primitives: `decrypt_railfence`, `decrypt_redefence`,
  `amsco_cells`+`decrypt_amsco`, `decrypt_myszkowski`, `decrypt_cadenus`,
  `decrypt_nihilist`, `decrypt_route`, `decrypt_swagman`, `decrypt_grille`. Each a pure
  `(ct, key, dims) → pt` index-array function with a round-trip unit test in
  `tests/test_transpositions.c`.
- `polyalphabetic.c` — `transposition_anneal` shared helper (refactored out of the two
  existing climbers) + one `solve_<type>()` per cipher + `solve_transposition_auto`;
  hook them into the early transposition `switch` in `solve_cipher`.
- `parse.c` / `polyalphabetic.h` — new `-type` aliases & codes (`railfence`, `redefence`,
  `amsco`, `myszkowski`, `cadenus`, `nihilist`, `route`, `swagman`, `grille`,
  `transauto`), continuing from code 18.
- `ciphers/tests/run_tests.sh` — add one fixed-seed end-to-end case per new type, sourced
  from this corpus, with a verified `.solution` sibling.
