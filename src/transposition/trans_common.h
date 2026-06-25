#ifndef TRANS_COMMON_H
#define TRANS_COMMON_H
#include "colossus.h"

// Shared helpers for the transposition-family solvers: result reporting, the
// short-key anneal seed/move dispatch (TransKeyOps), the generic permutation
// seed/move, the sweep-model no-op hooks, and an exact integer sqrt.
void report_transposition(ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len, int best_decrypted[],
    double best_score, char *cribtext_str, int n_cribs,
    const char *param_summary);
void report_transposition_verbose(const SolverCtx *ctx, double best_score,
    int best_decrypted[], const EngineStats *stats, const char *param_summary);

// Integer square root with exact-square test: returns N where N*N == x, else -1.
int exact_isqrt(int x);

// Cached dictionary word-set for the space-preserving transposition solvers (Rec 2):
// built once per loaded dictionary and reused. Returns NULL when no dictionary is
// loaded. The space-preserving columnar/chain/tile solvers use it to reward column
// orders that produce word-complete rows (the jarl recipe) and to break ties in the
// seam best-L row ordering.
WordSet *trans_word_set(SharedData *shared);

// =====================================================================
//  Exact small-permutation ordering (Held-Karp) -- shared engine helper
// =====================================================================
//
// Largest node count for which held_karp_best_path runs (2^R DP table). 14 keeps
// the table small (~1.8 MB) and the cost (O(R^2 2^R)) sub-millisecond; columnar
// row counts of interest (shallow grids) sit well inside this. R > the cap is not
// an error -- the caller is expected to fall back to identity ordering.
#define HELD_KARP_MAX_NODES 14

// Exact maximum-weight Hamiltonian PATH over R nodes. The objective of a visiting
// order v0,v1,...,v(R-1) is  sum_i indiv[v_i]  +  sum_i delta[v_i*R + v_{i+1}]  (an
// additive per-node term plus an additive consecutive-pair "seam" term). indiv is
// length R; delta is row-major R*R (delta[a*R + b] = bonus for a immediately before
// b). Fills order_out[0..R-1] with the optimal order and returns its total score.
// For R < 1 returns 0; for R == 1 returns indiv[0]; for R > HELD_KARP_MAX_NODES it
// fills the identity order and returns the identity-path score (the caller should
// guard and treat that as "exact best-L unavailable at this size").
double held_karp_best_path(int R, const double *indiv, const double *delta, int *order_out);

// Convenience seam objective over a set of R row-strings (each an int index array,
// possibly carrying negative space/punct sentinels). The per-row objective is the
// raw within-word n-gram sum (ngram_sum_raw) plus, when ws != NULL and wword != 0,
// wword * word_coverage(row) -- the dictionary word-coverage term that the W168 work
// found is REQUIRED for the seam to peak uniquely at the true row order on spaced
// text. Both terms are additive across a row join, so the seam decomposition stays
// exact. Builds indiv[r] and the seam delta into caller scratch, runs Held-Karp, and
// writes the best row order into order_out; returns the best total score. rows[r]
// points at row r's letters, rowlen[r] its length. R <= HELD_KARP_MAX_NODES; above
// that it returns the identity order. Scratch indiv_buf (>=R) / delta_buf (>=R*R) are
// caller-owned.
double seam_best_row_order(int R, int *const rows[], const int rowlen[],
    const float *ngram_data, int ngram_size, const WordSet *ws, double wword,
    double *indiv_buf, double *delta_buf, int *order_out);

// Short-integer-key anneal hooks (key length in cc->period). The per-type seed/move
// callbacks are supplied through a TransKeyOps placed in ctx->model_scratch.
typedef struct {
    void (*seed_cb)(int *key, int key_len);
    void (*move_cb)(int *key, int key_len);
} TransKeyOps;
void tkey_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st);
void tkey_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st, bool *fp);
void tkey_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst);

// Generic permutation seed/move shared by the permutation-key types.
void perm_move(int *key, int K);
void perm_seed(int *key, int K);

// Sweep-model hooks (key_len == 0 => no climb; no-op seed/copy).
int sweep_keylen(const SolverCtx *ctx, const SolverConfig *cc);
void sweep_noop_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st);
void sweep_noop_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst);
#endif
