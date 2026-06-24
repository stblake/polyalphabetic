#include "amsco_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Amsco solver (TYPE amsco)
// =====================================================================

// period = K (column count = key length); aux[0] = start-chunk (1 or 2).
static int amsco_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int lo = max(2, ctx->cfg->min_cols), hi = min(ctx->cfg->max_cols, ctx->cipher_len / 2);
    if (hi < lo) hi = lo;
    int n = 0;
    for (int K = lo; K <= hi; K++)
        for (int start = 1; start <= 2 && n < cap; start++) {
            out[n].period = K; out[n].aux[0] = start; out[n].j = 0; out[n].k = 0;
            n++;
        }
    return n;
}
static void amsco_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                          int *out, double *adj) {
    (void) adj;
    decrypt_amsco(ctx->cipher, ctx->cipher_len, cc->period, st->key,
        cc->aux[0] /* start */, ctx->cfg->variant ? 1 : 0, out);
}
static void amsco_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "K=%d start=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void amsco_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                         double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int K = cc->period, start = cc->aux[0];
    printf("\namsco: %d columns, start-chunk %d%s\norder:", K, start,
        variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < K; c++) printf(" %d", st->key[c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "K=%d start=%d%s", K, start, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps AMSCO_OPS = { perm_seed, perm_move };
static const CipherModel AMSCO_MODEL = {
    .name = "amsco", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = amsco_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = amsco_decrypt, .report = amsco_report,
    .report_verbose = amsco_report_verbose,
};

void solve_amsco(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for an Amsco solve.\n\n");
        return ;
    }
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &AMSCO_OPS;
    run_solver(&AMSCO_MODEL, &ctx);
}


