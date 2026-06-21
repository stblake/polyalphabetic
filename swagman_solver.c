#include "swagman_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Swagman solver (TYPE swagman) -- sweep N in [3,7] x read-off mode
// =====================================================================

static void swagman_seed(int *key, int key_len) {
    int N = exact_isqrt(key_len);
    int col[8];
    for (int j = 0; j < N; j++) {
        for (int r = 0; r < N; r++) col[r] = r;
        shuffle(col, N);
        for (int r = 0; r < N; r++) key[r * N + j] = col[r];     // each square column a permutation
    }
}
static void swagman_move(int *key, int key_len) {
    int N = exact_isqrt(key_len);
    int j = rand_int(0, N), r1 = rand_int(0, N), r2 = rand_int(0, N);
    int t = key[r1 * N + j]; key[r1 * N + j] = key[r2 * N + j]; key[r2 * N + j] = t;
}

// Sweep N in [3,7] (len % N == 0) x readmode; period = N*N is the key-square length.
static int swagman_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int n = 0;
    for (int N = 3; N <= 7; N++) {
        if (ctx->cipher_len % N != 0) continue;       // need N equal-length rows
        for (int readmode = 0; readmode <= 1 && n < cap; readmode++) {
            out[n].period = N * N; out[n].aux[0] = readmode; out[n].j = 0; out[n].k = 0;
            n++;
        }
    }
    if (n == 0)
        printf("\n\nERROR: no Swagman period in [3,7] divides length %d.\n\n", ctx->cipher_len);
    return n;
}
static void swagman_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                            int *out, double *adj) {
    (void) adj;
    int N = exact_isqrt(cc->period);
    decrypt_swagman(ctx->cipher, ctx->cipher_len, N, st->key,
        cc->aux[0] /* readmode */, ctx->cfg->variant ? 1 : 0, out);
}
static void swagman_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "N=%d read=%d%s",
        exact_isqrt(cc->period), cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void swagman_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                           double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int N = exact_isqrt(cc->period), readmode = cc->aux[0];
    printf("\nswagman: %dx%d key square, read %s%s\nsquare:",
        N, N, readmode ? "column-major" : "row-major",
        variant ? " (variant: read/write swapped)" : "");
    for (int r = 0; r < N; r++) { printf("\n  "); for (int j = 0; j < N; j++) printf("%d ", st->key[r * N + j]); }
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "N=%d read=%d%s", N, readmode, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps SWAGMAN_OPS = { swagman_seed, swagman_move };
static const CipherModel SWAGMAN_MODEL = {
    .name = "swagman", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = swagman_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = swagman_decrypt, .report = swagman_report,
    .report_verbose = swagman_report_verbose,
};

void solve_swagman(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    if (cipher_len < 9) { printf("\n\nERROR: ciphertext too short for a Swagman solve.\n\n"); return; }
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &SWAGMAN_OPS;
    run_solver(&SWAGMAN_MODEL, &ctx);
}


