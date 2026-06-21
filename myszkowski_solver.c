#include "myszkowski_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Myszkowski solver (TYPE myszkowski)
// =====================================================================

// Rank-vector neighbour move: swap two ranks (reorder), copy one rank onto another
// (merge -> create a tie), or relabel one column (split). This explores both the
// column ordering and the tie structure that distinguishes Myszkowski from columnar.
static void mysz_move(int *key, int K) {
    if (K < 2) return;
    double r = frand();
    if (r < 0.60) {
        int a = rand_int(0, K), b = rand_int(0, K);
        int t = key[a]; key[a] = key[b]; key[b] = t;
    } else if (r < 0.80) {
        int a = rand_int(0, K), b = rand_int(0, K);
        key[a] = key[b];                      // merge a into b's rank group
    } else {
        int a = rand_int(0, K);
        key[a] = rand_int(0, K);              // relabel (may split a tie)
    }
}

// period = K (column count = rank-vector length). Seeds a random permutation
// (distinct ranks -> columnar); mysz_move then introduces ties.
static int mysz_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int lo = max(2, ctx->cfg->min_cols), hi = min(ctx->cfg->max_cols, ctx->cipher_len / 2);
    if (hi < lo) hi = lo;
    int n = 0;
    for (int K = lo; K <= hi && n < cap; K++) {
        out[n].period = K; out[n].j = 0; out[n].k = 0;
        n++;
    }
    return n;
}
static void mysz_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                         int *out, double *adj) {
    (void) adj;
    decrypt_myszkowski(ctx->cipher, ctx->cipher_len, cc->period, st->key,
        ctx->cfg->variant ? 1 : 0, out);
}
static void mysz_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "K=%d%s", cc->period, variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void mysz_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                        double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int K = cc->period;
    printf("\nmyszkowski: %d columns%s\nranks:", K,
        variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < K; c++) printf(" %d", st->key[c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "K=%d%s", K, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps MYSZ_OPS = { perm_seed, mysz_move };
static const CipherModel MYSZKOWSKI_MODEL = {
    .name = "myszkowski", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = mysz_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = mysz_decrypt, .report = mysz_report,
    .report_verbose = mysz_report_verbose,
};

void solve_myszkowski(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for a Myszkowski solve.\n\n");
        return ;
    }
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &MYSZ_OPS;
    run_solver(&MYSZKOWSKI_MODEL, &ctx);
}


