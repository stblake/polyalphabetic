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
