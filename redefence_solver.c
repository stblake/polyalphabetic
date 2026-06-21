#include "redefence_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Redefence solver (TYPE redefence)
// =====================================================================

// period = rails (rail read-order permutation length); aux[0] = starting phase.
static int redefence_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int lo = max(2, ctx->cfg->min_cols), hi = min(ctx->cfg->max_cols, ctx->cipher_len - 1);
    if (hi < lo) hi = lo;
    int n = 0;
    for (int rails = lo; rails <= hi; rails++) {
        int P = 2 * (rails - 1);
        for (int offset = 0; offset < P && n < cap; offset++) {
            out[n].period = rails; out[n].aux[0] = offset; out[n].j = 0; out[n].k = 0;
            n++;
        }
    }
    return n;
}
static void redefence_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                              int *out, double *adj) {
    (void) adj;
    decrypt_redefence(ctx->cipher, ctx->cipher_len, cc->period /* rails */,
        cc->aux[0] /* offset */, st->key, ctx->cfg->variant ? 1 : 0, out);
}
static void redefence_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void redefence_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                             double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int rails = cc->period, offset = cc->aux[0];
    printf("\nredefence: %d rails, phase %d%s\norder:", rails, offset,
        variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < rails; c++) printf(" %d", st->key[c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s", rails, offset, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps REDEFENCE_OPS = { perm_seed, perm_move };
static const CipherModel REDEFENCE_MODEL = {
    .name = "redefence", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = redefence_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = redefence_decrypt, .report = redefence_report,
    .report_verbose = redefence_report_verbose,
};

void solve_redefence(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    if (cipher_len < 4) { printf("\n\nERROR: ciphertext too short for a redefence solve.\n\n"); return; }
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &REDEFENCE_OPS;
    run_solver(&REDEFENCE_MODEL, &ctx);
}


