#include "tile_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Sub-grid / tile transposition (TRANSTILE)
// =====================================================================
//
//  A uniform h x w tile cell permutation composed with a columnar column-order
//  global. The engine JOINTLY anneals two lanes: the column order (length W, stored
//  in key[0..W-1]) and the tile cell permutation (length m = h*w, stored in
//  key[TILE_PERM_OFF ..]). The column count W is swept over the complete-grid
//  divisors of len; the tile shape h x w is fixed by -tile (default 2x2). The
//  decrypt is decrypt_tile(). See ciphers/W168/tiles.py for the validated model.

// The tile permutation lives above the column-order lane in key[]; MAX_COLS bounds
// the column count, so there is no overlap.
#define TILE_PERM_OFF MAX_COLS
#define TILE_WORD_SEARCH 0.6
static const WordSet *tile_ws = NULL;

static int tile_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int len = ctx->cipher_len;
    int h = ctx->cfg->tile_h, w = ctx->cfg->tile_w;
    int lo = ctx->cfg->min_cols, hi = ctx->cfg->max_cols;
    if (lo < 2) lo = 2;
    if (hi > MAX_COLS) hi = MAX_COLS;
    int n = 0;
    for (int W = lo; W <= hi && n < cap; W++) {
        if (len % W != 0) continue;                  // complete grid only
        int R = len / W;
        if (R < 2 || W < w || R < h) continue;       // need at least one full tile
        out[n].period = W; out[n].aux[0] = h; out[n].aux[1] = w;
        out[n].j = 0; out[n].k = 0; n++;
    }
    return n;
}
static void tile_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    (void) ctx;
    int m = cc->aux[0] * cc->aux[1];
    perm_seed(st->key, cc->period);               // column order
    perm_seed(st->key + TILE_PERM_OFF, m);        // tile cell permutation
}
static void tile_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st, bool *fp) {
    (void) ctx; (void) fp;
    int m = cc->aux[0] * cc->aux[1];
    if (frand() < 0.65) perm_move(st->key, cc->period);      // mostly reorder columns
    else                perm_move(st->key + TILE_PERM_OFF, m); // sometimes shuffle the tile
}
static void tile_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    int m = cc->aux[0] * cc->aux[1];
    for (int i = 0; i < cc->period; i++) dst->key[i] = src->key[i];
    for (int i = 0; i < m; i++) dst->key[TILE_PERM_OFF + i] = src->key[TILE_PERM_OFF + i];
}
static void tile_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                         int *out, double *adj) {
    int len = ctx->cipher_len;
    decrypt_tile((int *) ctx->cipher, len, cc->period, st->key,
                 cc->aux[0], cc->aux[1], st->key + TILE_PERM_OFF, out);
    if (tile_ws && len > 0) {
        double w = (ctx->cfg->weight_word > 0.0) ? ctx->cfg->weight_word : TILE_WORD_SEARCH;
        *adj += w * word_coverage(out, len, tile_ws) / (double) len;
    }
}
static void tile_param_summary(const SolverCtx *ctx, const SolverConfig *cc, char *buf, size_t n) {
    int W = cc->period, R = ctx->cipher_len / W;
    snprintf(buf, n, "%dx%d tile=%dx%d", R, W, cc->aux[0], cc->aux[1]);
}
static void tile_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    char params[64]; tile_param_summary(ctx, cc, params, sizeof params);
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}
static void tile_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                        double score, int *decrypted) {
    char params[64]; tile_param_summary(ctx, cc, params, sizeof params);
    int W = cc->period, R = ctx->cipher_len / W, m = cc->aux[0] * cc->aux[1];
    printf("\ntranstile: %d x %d grid, %dx%d tiles, column order + tile cell permutation\n",
        R, W, cc->aux[0], cc->aux[1]);
    printf("column order:");
    for (int c = 0; c < W; c++) printf(" %d", st->key[c]);
    printf("\ntile perm:");
    for (int s = 0; s < m; s++) printf(" %d", st->key[TILE_PERM_OFF + s]);
    printf("\n");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}

static const CipherModel TILE_MODEL = {
    .name = "tile", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = tile_enumerate, .key_len = NULL,
    .seed = tile_seed, .perturb = tile_perturb, .copy_state = tile_copy,
    .decrypt = tile_decrypt, .report = tile_report, .report_verbose = tile_report_verbose,
};

void solve_tile(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for a transtile solve.\n\n");
        return;
    }
    tile_ws = trans_word_set(shared);
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    run_solver(&TILE_MODEL, &ctx);
}
