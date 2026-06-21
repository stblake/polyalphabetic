#include "route_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Route transposition solver (TYPE route)
// =====================================================================
//
// Enumerate every rectangular grid that can hold the text -- including ragged ones
// with a short final row -- by sweeping the column count C and taking R = ceil(len/C)
// rows (both >= 2), times every route in [0, N_ROUTES); invert each with decrypt_route
// and keep the best-scoring plaintext. -variant swaps read/write.
// SWEEP model: sweep column count C (R = ceil(len/C) rows) x route id. period = C,
// aux[0] = route_id; R is recomputed from C. Subsumes ragged (short final row) grids.
static int route_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int cipher_len = ctx->cipher_len;
    int n = 0;
    for (int C = 2; C <= cipher_len / 2; C++) {
        int R = (cipher_len + C - 1) / C;
        if (R < 2) continue;
        for (int route_id = 0; route_id < N_ROUTES && n < cap; route_id++) {
            out[n].period = C; out[n].aux[0] = route_id; out[n].j = 0; out[n].k = 0;
            n++;
        }
    }
    return n;
}
static void route_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                          int *out, double *adj) {
    (void) st; (void) adj;
    int C = cc->period;
    int R = (ctx->cipher_len + C - 1) / C;
    decrypt_route(ctx->cipher, ctx->cipher_len, R, C, cc->aux[0], ctx->cfg->variant ? 1 : 0, out);
}
static void route_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    int C = cc->period;
    int R = (ctx->cipher_len + C - 1) / C;
    char params[64];
    snprintf(params, sizeof(params), "%dx%d route=%d%s",
        R, C, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void route_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                         double score, int *decrypted) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    int C = cc->period;
    int R = (ctx->cipher_len + C - 1) / C;
    static const char *route_names[N_ROUTES] = {
        "rows-snake", "cols-snake", "spiral-cw", "spiral-ccw", "diag-snake", "diag" };
    printf("\nroute: %d x %d grid, route %d (%s)%s\n",
        R, C, cc->aux[0], route_names[cc->aux[0]],
        variant ? " (variant: read/write swapped)" : "");
    char params[64];
    snprintf(params, sizeof(params), "%dx%d route=%d%s",
        R, C, cc->aux[0], variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const CipherModel ROUTE_MODEL = {
    .name = "route", .shape = SHAPE_SHOTGUN, .needs_hist = false,
    .enumerate_configs = route_enumerate, .key_len = sweep_keylen,
    .seed = sweep_noop_seed, .perturb = NULL, .copy_state = sweep_noop_copy,
    .decrypt = route_decrypt, .report = route_report,
    .report_verbose = route_report_verbose,
};

void solve_route(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str; // ciphertext is carried as cipher_indices.

    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for a route solve.\n\n");
        return ;
    }

    // For cipher_len >= 4 the C=2 column count always yields an R x C grid with
    // R, C >= 2, so the enumeration is non-empty (the old "no grid" guard is moot).
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    run_solver(&ROUTE_MODEL, &ctx);
}


