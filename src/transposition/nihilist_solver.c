#include "nihilist_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Nihilist transposition solver (TYPE nihilist) -- N = sqrt(len)
// =====================================================================

// The climbed key packs the row permutation (first N) and column permutation
// (second N) of the N x N grid; readmode (row/column-major read-off) is swept.
static void nihilist_seed(int *key, int key_len) {   // two independent permutations
    int N = key_len / 2;
    for (int i = 0; i < N; i++) key[i] = i;
    shuffle(key, N);
    for (int i = 0; i < N; i++) key[N + i] = i;
    shuffle(key + N, N);
}
static void nihilist_move(int *key, int key_len) {   // perturb one of the two halves
    int N = key_len / 2;
    if (frand() < 0.5) perm_move(key, N);
    else perm_move(key + N, N);
}

// N = sqrt(len); period = 2N packs row + column permutations. aux[0] = readmode.
static int nihilist_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    (void) cap;
    int N = exact_isqrt(ctx->cipher_len);
    if (N < 2) {
        printf("\n\nERROR: Nihilist transposition needs a perfect-square length (got %d).\n\n", ctx->cipher_len);
        return 0;
    }
    for (int readmode = 0; readmode <= 1; readmode++) {
        out[readmode].period = 2 * N; out[readmode].aux[0] = readmode;
        out[readmode].j = 0; out[readmode].k = 0;
    }
    return 2;
}
static void nihilist_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                             int *out, double *adj) {
    (void) adj;
    int N = cc->period / 2;
    decrypt_nihilist(ctx->cipher, ctx->cipher_len, N, st->key, st->key + N,
        cc->aux[0] /* readmode */, ctx->cfg->variant ? 1 : 0, out);
}
static void nihilist_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "N=%d read=%d%s",
        cc->period / 2, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void nihilist_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                            double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int N = cc->period / 2, readmode = cc->aux[0];
    printf("\nnihilist: %d x %d grid, read %s%s\nrows:", N, N,
        readmode ? "column-major" : "row-major",
        variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < N; c++) printf(" %d", st->key[c]);
    printf("\ncols:");
    for (int c = 0; c < N; c++) printf(" %d", st->key[N + c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "N=%d read=%d%s", N, readmode, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps NIHILIST_OPS = { nihilist_seed, nihilist_move };
static const CipherModel NIHILIST_MODEL = {
    .name = "nihilist", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = nihilist_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = nihilist_decrypt, .report = nihilist_report,
    .report_verbose = nihilist_report_verbose,
};

void solve_nihilist(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &NIHILIST_OPS;
    run_solver(&NIHILIST_MODEL, &ctx);
}


