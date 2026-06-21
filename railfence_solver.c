#include "railfence_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Rail fence solver (TYPE railfence) -- covers variant rail fence too
// =====================================================================
//
// The key space is tiny (rail count x starting phase), so we enumerate it
// exhaustively rather than hill-climb: for each rail count in [min_cols, max_cols]
// and every starting phase offset, invert the zigzag with decrypt_railfence and
// keep the highest-scoring plaintext. -variant swaps the read/write directions.
// SWEEP model: each (rails, offset) cell is one candidate (key_len 0 => no climb).
// period = rails, aux[0] = starting phase offset.
static int railfence_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int lo = max(2, ctx->cfg->min_cols);
    int hi = min(ctx->cfg->max_cols, ctx->cipher_len - 1);
    if (hi < lo) hi = lo;
    int n = 0;
    for (int rails = lo; rails <= hi; rails++) {
        int P = 2 * (rails - 1);                 // number of distinct phases
        for (int offset = 0; offset < P && n < cap; offset++) {
            out[n].period = rails; out[n].aux[0] = offset; out[n].j = 0; out[n].k = 0;
            n++;
        }
    }
    return n;
}

static void railfence_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                              int *out, double *adj) {
    (void) st; (void) adj;
    decrypt_railfence(ctx->cipher, ctx->cipher_len, cc->period, cc->aux[0],
        ctx->cfg->variant ? 1 : 0, out);
}
static void railfence_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void railfence_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                             double score, int *decrypted) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    printf("\nrailfence: %d rails, starting phase %d%s\n",
        cc->period, cc->aux[0], variant ? " (variant: read/write swapped)" : "");
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const CipherModel RAILFENCE_MODEL = {
    .name = "railfence", .shape = SHAPE_SHOTGUN, .needs_hist = false,
    .enumerate_configs = railfence_enumerate, .key_len = sweep_keylen,
    .seed = sweep_noop_seed, .perturb = NULL, .copy_state = sweep_noop_copy,
    .decrypt = railfence_decrypt, .report = railfence_report,
    .report_verbose = railfence_report_verbose,
};

void solve_railfence(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str; // ciphertext is carried as cipher_indices.

    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for a rail fence solve.\n\n");
        return ;
    }

    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    run_solver(&RAILFENCE_MODEL, &ctx);
}


