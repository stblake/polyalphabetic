#include "cadenus_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Cadenus solver (TYPE cadenus) -- 25 rows, K = len/25 columns
// =====================================================================
//
// The climbed key packs two halves: key[0..K-1] is the column read-order
// permutation, key[K..2K-1] is the per-column upward rotation in [0,25). Decoupling
// them lets the search subsume any keyword/alphabet convention.

static void cadenus_seed(int *key, int key_len) {
    int K = key_len / 2;
    for (int i = 0; i < K; i++) key[i] = i;
    shuffle(key, K);
    for (int i = 0; i < K; i++) key[K + i] = rand_int(0, 25);   // Cadenus has 25 rows
}
static void cadenus_move(int *key, int key_len) {
    int K = key_len / 2;
    if (frand() < 0.55) perm_move(key, K);                       // reorder columns
    else key[K + rand_int(0, K)] = rand_int(0, 25);              // re-rotate one column
}

// Single config: K = len/25 columns, period = 2K packs column order + rotations.
static int cadenus_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    (void) cap;
    int len = ctx->cipher_len;
    if (len % 25 != 0) {
        printf("\n\nERROR: Cadenus needs a length that is a multiple of 25 (got %d).\n\n", len);
        return 0;
    }
    int K = len / 25;
    if (K < 2 || 2 * K > MAX_TRANS_KEY) {
        printf("\n\nERROR: Cadenus column count %d out of range.\n\n", K);
        return 0;
    }
    out[0].period = 2 * K; out[0].j = 0; out[0].k = 0;
    return 1;
}
static void cadenus_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                            int *out, double *adj) {
    (void) adj;
    int K = cc->period / 2;
    decrypt_cadenus(ctx->cipher, ctx->cipher_len, K, st->key, st->key + K,
        ctx->cfg->variant ? 1 : 0, out);
}
static void cadenus_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "K=%d%s", cc->period / 2, variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void cadenus_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                           double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int K = cc->period / 2;
    printf("\ncadenus: %d columns x 25 rows%s\norder:", K, variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < K; c++) printf(" %d", st->key[c]);
    printf("\nrot:");
    for (int c = 0; c < K; c++) printf(" %d", st->key[K + c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "K=%d%s", K, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps CADENUS_OPS = { cadenus_seed, cadenus_move };
static const CipherModel CADENUS_MODEL = {
    .name = "cadenus", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = cadenus_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = cadenus_decrypt, .report = cadenus_report,
    .report_verbose = cadenus_report_verbose,
};

void solve_cadenus(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &CADENUS_OPS;
    run_solver(&CADENUS_MODEL, &ctx);
}


