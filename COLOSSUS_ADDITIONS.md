# COLOSSUS_ADDITIONS.md

Recommended generalised solvers and engine features for colossus, distilled from a
review of the W168 attack toolkit in `ciphers/W168/` (≈60 Python prototypes, plus
`EXPERIMENTS.md` / `CONCLUSIONS.md`).

## Implementation status (all seven landed, opt-in, zero impact on existing solves)

All recommendations below were implemented as **optional additions**. The existing
regression suite stays **bit-identical** (44/44 at 100%, the 42 prior cases unchanged);
`make test` adds `test_held_karp` and tracked/tile round-trips. Summary:

| Rec | What | Status | Where |
|---|---|---|---|
| 7 | Held-Karp exact ordering + seam best-L + `ngram_sum_raw` | done, unit-tested | `trans_common.c`, `scoring.c`, `tests/test_held_karp.c` |
| 1 | `transcol-l` within-column track-perm columnar | done | `columnar_track_solver.c` |
| 4 | row read-direction freedom (`-readrowdir`) | done | (folded into transcol-l) |
| 2 | dictionary word-coverage (`-weightword`) + word-set | done | `dict.c` (`word_set_build`/`word_coverage`) |
| 3 | `-cribanchored` structural block<->column matcher | done | `columnar_track_solver.c` |
| 5 | `transroutecol` route + column-key chain | done (blind recovery hard) | `route_chain_solver.c` |
| 6 | `transtile` sub-grid / tile transposition | done | `tile_solver.c`, `decrypt_tile` |

**Headline result:** with Rec 1+2+3+7 together, `-type transcol-l -cribanchored` cracks **all
ten** length-28 keyed columnar ciphers in `ciphers/W168/dave_tests/` (Dave Oranchak's jarl
set) from a single 3-row crib — `ciphers/W168/dave_tests/solve_all.sh` reports 10/10. This is
the validated jarl recipe (the structural crib collapses the otherwise-intractable 28-column
search; a *soft* crib score gives no gradient and does not).

Honest limitations confirmed during implementation (all consistent with the W168 findings):
blind shallow-columnar recovery is inherently hard — `transcol-l` recovers a non-identity `L`
reliably only with few rows (unambiguous best-L) + `-logprob`, or with a crib; the seam best-L
needs the dictionary term on spaced text; and `transroutecol`'s blind recovery is weak (the
route adds a layer). The regression adds `transcol_l_test` and `transtile_test` (favorable
regimes); the crib-anchored jarl solve and `transroutecol` are exercised by standalone scripts.

---


## Why this document exists

The W168 campaign solved the **jarl** Rosetta pair (a 6×28 columnar with a within-column
cell permutation) and then threw a large, *validated* toolkit at W168 itself — every
named transposition family, every 168-grid shape, 2-D tile/sub-grid local stages, and
route+column-key chains. W168 stayed negative (best `word_frac` ≈0.31 conclusive / ≈0.41
gamed, vs English ≈0.83), so **none of this is a W168 solution**. But several of the
prototypes are *general-purpose transposition machinery that colossus currently lacks*,
and they were each verified end-to-end (round-trip exact, objective peaks at truth,
exhaustive-synthetic recovery, jarl→AZDECRYPT at known order). The value is bringing that
machinery into the C engine, where it will help on the broader ACA transposition corpus —
not just Kryptos/W168.

The C-side audit behind these recommendations (what already exists, so we don't duplicate):

| Capability | In colossus today? | Location |
|---|---|---|
| n-gram scorer skips word-boundary windows | yes | `scoring.c:85` (`ngram_score`) |
| dictionary coverage as a **search** objective | no — report-only | `dict.c:50`, used only in `trans_common.c:24` |
| columnar: column-order permutation | yes | `columnar_solver.c` |
| columnar: **within-column cell permutation (track order L)** | **no** | — |
| columnar: ragged/incomplete grids | yes | `transpositions.c:84` (`decrypt_columnar`) |
| columnar: read-direction variants | TB/BT only (no row-reverse) | `columnar_solver.c:34` |
| route solver (6 routes, keyless sweep) | yes | `route_solver.c`, `transpositions.c:197` |
| cribs in scoring | yes (positional partial/exact) | `scoring.c:31` (`crib_score`) |
| **crib-anchoring** (fix plaintext positions to collapse the search) | **no** | — |
| double-columnar joint two-stage search | yes | `columnar_solver.c:102` |
| **generic route+columnar chain search** | **no** | — |
| **sub-grid / tile (h×w) local transposition** | **no** | — |
| **exact best-permutation (Held–Karp / exhaustive)** | **no** — climb/anneal only | — |

---

## Recommendation 1 — Within-column track permutation `L` for the columnar solver (+ exact seam best-L)

**The single highest-value addition.** colossus's `transcol` optimises only the
column-*order* permutation; it cannot recover a cipher that *also* applies a uniform
permutation of the cells **inside** each column. That is exactly the jarl/"dave
transposition" scheme (read the grid by columns, then permute the 6 cells of every column
identically) — and it is a standard ACA construction (disrupted / complete columnar with a
row key). Today colossus would have to brute-force it as gibberish.

**What W168 built** (`solve3.py` → generalised in `gridlib.py`): for an `R×W` grid, jointly
recover the column order **and** a single within-column row permutation `L` (one of `R!`).
The decisive trick is that `L` can be found **exactly and cheaply** without nesting an `R!`
search inside the column climb:

- score each candidate row string individually (`rowscore`), and build an `R×R`
  **seam-delta matrix** `delta[a][b] = score(row_a ++ row_b) − score(row_a) − score(row_b)`;
- the best row order is then a **maximum-weight Hamiltonian path** over that matrix, solved
  by **Held–Karp** DP in `O(R² · 2^R)` (`gridlib.seam_best_L`) — exact for `R ≤ 14`, which
  covers every realistic columnar height.

This is *numerically identical* to brute-forcing all `R!` readings (verified to ~1e-13) but
fast enough to evaluate per candidate at small `R`, or as a one-shot refinement at larger
`R` (the cost-tiering in `gridlib.solve_width`: nested best-L for `R≤8`, identity-guided
climb + one best-L refinement for `9≤R≤14`, identity-only above).

**Integrate as:** a new mode/flag on the existing columnar solver (e.g. `-trackperm` on
`transcol`, or a new type `transcol-L`). The state is `(column order, L)`; the column climb
reuses today's move set (`columnar_solver.c`), and `L` is recovered by a new
`seam_best_L()` helper in `trans_common.c`. Add the seam-delta builder over the existing
`ngram_score`. Pairs naturally with Recommendation 4 (read-direction freedoms).

**Validated by:** `solve3.cont_obj` peaks uniquely at truth on synthetic 6×28 columnars
(0 single-swaps beat truth); `gridlib`/`gridsweep_validate.py` confirm round-trip + truth-peak
+ exhaustive-shape recovery + jarl→AZDECRYPT.

---

## Recommendation 2 — Dictionary word-fraction as a search objective and anti-gaming gate

**The campaign's most reusable methodological finding.** colossus computes n-gram fitness
during the search and only counts dictionary words *at report time* (`dict.c`,
`trans_common.c:24`). W168 repeatedly showed this is a trap for transposition over
**space-preserving** text: the general-permutation and large-width climbs **gamed the
n-gram score** to a high value (e.g. n-gram 5.2, or `word_frac` 0.41) with **no readable
words**. The robust discriminator was `word_frac` — the length-weighted fraction of
space/period-delimited tokens that are real dictionary words (`wordscore.py`), which pins
true English at ≈0.83 and cleanly separates it from gamed gibberish at ≈0.31.

**Two concrete additions:**

1. **An optional dictionary-coverage term in `state_score`** (weight-gated, default 0 so
   the regression suite stays bit-identical), only meaningful when spaces/periods are
   preserved as sentinels. Use the existing word-boundary tokenisation already in
   `ngram_score`/`dict.c`.
2. **An anti-gaming acceptance/report gate**: when ranking final candidates across a sweep,
   promote on `word_frac ≥ threshold` rather than raw n-gram score (`chains.py`'s "promote
   only if wf≥0.50" discipline). This stops a sweep from reporting a high-n-gram gibberish
   winner — a real failure mode seen in `portfolio_w168.csv`.

**Why it generalises:** any space-preserving transposition (a large slice of the ACA
corpus, and Kryptos K1–K3 plaintext) benefits; the length-weighting (cover more letters,
not just more tokens) is what makes it stable.

**Validated by:** `qscore_sp` (word-boundary n-grams) was the fix that made the synthetic
objective peak at truth at all (`EXPERIMENTS.md` E5); `word_frac` is the discriminator
behind every E10–E18 "conclusive negative".

---

## Recommendation 3 — Crib-anchored transposition search

colossus uses cribs only inside `crib_score` (`scoring.c:31`) — they nudge the score but do
**not** constrain the permutation. For a **shallow** columnar (few rows, many columns) the
per-pair statistics are too weak for blind search: SA, basin-hopping, 2-opt, beams, and a
memetic GA all *failed* to recover the exact column order even on a known synthetic of
jarl's shape (best ~80%). **A single crib word collapsed it instantly.**

**What W168 built** (`anchored.py`, `EXPERIMENTS.md` E7): place a crib, which pins a run of
columns to fixed plaintext positions, then optimise only the *remaining* columns' order
around the locked anchor (with the exact best-L objective). Once a few rows are read, every
remaining column is uniquely pinned by **bipartite matching** of column → plaintext slot —
**no optimiser needed**. This is the mechanism that solved jarl.

**Integrate as:** a crib-anchoring front-end for the transposition solvers — given a crib
and (swept) placement, fix the implied column/cell positions and restrict the climb to the
free columns. The bipartite-matching "finish" (assign remaining columns to remaining slots
by best n-gram fit) is a small new helper. Distinct from substitution cribs; it is a
*structural constraint* on the transposition key.

**Caveat / where it helps:** this is decisive for shallow columnars *with* a confidently
known crib. W168 itself stayed unsolved because it has no confirmed crib — but the
machinery is exactly what makes the columnar family tractable when one is available, which
is common in real attacks (Kryptos K1–K3 all had cribs/known phrases).

---

## Recommendation 4 — Read-direction freedoms for columnar (4 orientations)

Small, cheap, and folds into Recommendations 1/5. colossus's columnar supports only
top-down / bottom-up column reads (`COL_READ_TB`/`COL_READ_BT`, `columnar_solver.c:34`). The
W168 sweeps showed two independent freedoms matter: **column read direction** (top-down vs
bottom-up) **and** **row read direction** (L-to-R vs R-to-L) — 4 orientations
(`colsweep.py`, `gridlib.solve_width`'s `col_rev × row_rev`). Add the missing row-reverse as
a flag (`-readrowdir lr|rl|both`) so the existing TB/BT × the new LR/RL gives all four. It
costs one extra pass per orientation and catches genuine ACA route variants.

---

## Recommendation 5 — Generic two-stage transposition chain (route global + column key)

colossus jointly searches **double columnar** (`transcol2`, two `(K, order)` stages) but not
a chain whose stages come from *different* families. The most useful missing chain is a
**fixed read-route global composed with a searched column key**, read with best-L
(`routekey.py`, generalised in `chains.py`).

**What W168 built:** scatter the stream along one of 14 read-routes
(rows/cols/boustrophedon/diagonal/antidiagonal/spiral + reverses — colossus already has 6 of
these as primitives in `transpositions.c:197`), then permute columns by a searched key, then
read by rows with the exact best-L. It is a strict superset of both a pure route solve
(key = identity) and a pure columnar (route = `cols`), with an anti-gaming `word_frac` gate
and exhaustive column search where `W! ≤ cap`.

**Integrate as:** a new chained type (e.g. `transroutecol`) that loops the existing
`route_cells()` routes as the outer fixed stage and runs the columnar climb as the inner
searched stage — reusing `route_solver.c` + `columnar_solver.c` rather than new primitives.
This is the natural generalisation of `transcol2`'s two-stage machinery to a route+key chain.

**Validated by:** `routekey_validate.py` / `chains_validate.py` (superset equivalence, exact
inverse, blind synthetic recovery, route=`cols`→jarl). *Note:* it did **not** crack W168, so
ship it for the general corpus, not as a W168 fix.

---

## Recommendation 6 — Sub-grid / tile (h×w) local transposition primitive + solver

A genuinely **new cipher primitive** colossus has no form of: partition the grid into `h×w`
tiles and permute the cells of **every** tile by the **same** small permutation (`tiles.py`;
the `2×2` case is `subgrid.py`/`colsweep.py`). This models "disrupted"/grille-style local
scrambling that a column-order solver cannot touch. The solver searches the tile permutation
(one of `(h·w)!`) **jointly** with a global column order — exhaustive when `W!·(h·w)!` is
small, else basin-hopping (`tiles.solve`).

A useful extension already prototyped is a **non-uniform / periodic** tile key
(`tiles_nu.py`): the tile permutation cycles with a small period `k` across tile-columns (a
polyalphabetic-style local key; `k=1` is the uniform case).

**Integrate as:** a side-generic `tile_decrypt(grid, h, w, perm)` primitive in
`transpositions.c` plus a small `CipherModel`/solver in `src/transposition/`, mirroring how
the polygraphic square solvers are structured. The move set is just tile-perm swaps + the
existing column moves.

**Caveat:** the entire 2-D tile family was **exhaustively excluded for W168** (small widths
conclusive). Recommend it as a general capability and an ACA cipher type, **not** with any
expectation it bears on W168.

---

## Recommendation 7 — Exact small-permutation ordering as an engine primitive (Held–Karp / exhaustive)

A cross-cutting engine capability the campaign kept needing: everything in colossus's
transposition path is hill-climb/anneal, and the W168 work showed that for **shallow grids
the optimiser is the bottleneck, not the model** (known synthetics weren't solved exactly by
SA/GA/beam). Two exact tools fix this for the small instances that dominate transposition:

- **Held–Karp** max-weight Hamiltonian path for best row/column **ordering** under a pairwise
  (seam) score — `O(n²·2^n)`, practical to `n≈14` (`gridlib.seam_best_L`).
- **Exhaustive** permutation enumeration with an automatic fall-through to climb when `n!`
  exceeds a cap (`gridlib._search_columns`, `tiles.solve`, `chains.solve_route` all use the
  `factorial(n) ≤ cap ? exhaustive : basin-hop` pattern).

Adding these as shared helpers in `trans_common.c` lets the columnar/route/chain solvers
become **exact** for short keys (guaranteeing the global optimum, so a negative result is
*conclusive* rather than "the climb missed it") and only fall back to the stochastic climber
for large keys. This is what let the W168 sweeps claim conclusive exclusions for `W ≤ 8`.

---

## Lower-priority / supporting ideas

- **Grid-shape auto-sweep.** `gridsweep_w168.py` sweeps every width / 168-factorization +
  ragged shape automatically. colossus's `transcol` already sweeps `-mincols..-maxcols`;
  generalising that to "sweep all factorizations of `len` (and near-factorizations for ragged
  N) and pick by `word_frac`" is a convenience layer over Recommendation 1.
- **Memetic GA optimiser** (`ga2.py`) for the column-order search — a stronger optimiser than
  the current basin-hop for the hard shallow-grid cases. Lower priority than the *exact*
  Held–Karp route (Rec 7), which simply removes the need at small `n`.
- **Sentinel/word-boundary I/O is already present** in colossus (`scoring.c:85`,
  `utils.c:162`) — the Python `qscore_sp` lesson is already embodied in the C scorer; no
  action needed beyond exposing the dictionary term (Rec 2).

## Suggested implementation order

1. **Rec 2** (dictionary objective + anti-gaming gate) — small, cross-cutting, improves every
   space-preserving transposition solve immediately.
2. **Rec 7** (exact ordering helpers) + **Rec 1** (within-column best-L columnar) — these two
   together deliver the jarl-class "complete/disrupted columnar with a row key" solver, the
   biggest genuine capability gap.
3. **Rec 4** (read-direction freedoms) — trivial once Rec 1 lands.
4. **Rec 3** (crib-anchored transposition) — high payoff where a crib exists.
5. **Rec 5** (route+columnar chain) and **Rec 6** (tile transposition) — new cipher types for
   corpus coverage; ship with the caveat that both were W168-negative.

## Honest caveat on W168

None of the above solves W168 — the campaign's verdict is that W168 is **not** a single-stage
transposition of any named family at any 168-grid shape, nor a route+column-key chain, nor any
2-D tile-local scheme (small widths exhaustively excluded). The highest-value W168 unlock
remains a **confirmed ≥8-letter crib** (which would make Recommendation 3 decisive, as it was
for jarl), or revisiting the assumptions that the cipher is 168 cells with two end-pad blanks
and pure transposition. These recommendations are about harvesting reusable, validated solver
machinery for colossus's general transposition coverage — not a claim of progress on W168.
