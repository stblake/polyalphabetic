#include "grille_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Turning-grille solver (TYPE grille) -- N = sqrt(len)
// =====================================================================

static void grille_seed(int *key, int key_len) {
    for (int i = 0; i < key_len; i++) key[i] = rand_int(0, 4);   // each orbit: which of 4 turns
}
static void grille_move(int *key, int key_len) {
    key[rand_int(0, key_len)] = rand_int(0, 4);
}

// Single config: N = sqrt(len); period = n_orbits (probed) is the key length;
// aux[0] = N (decrypt_grille needs the grid size).
static int grille_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    (void) cap;
    int N = exact_isqrt(ctx->cipher_len);
    if (N < 2) {
        printf("\n\nERROR: turning grille needs a perfect-square length (got %d).\n\n", ctx->cipher_len);
        return 0;
    }
    // Discover the orbit count (the climbed key length) for this N via a probe.
    int n_orbits = 0, tmp_key[MAX_TRANS_KEY] = {0}, tmp_out[MAX_CIPHER_LENGTH];
    decrypt_grille(ctx->cipher, ctx->cipher_len, N, tmp_key, 0, tmp_out, &n_orbits);
    if (n_orbits < 1 || n_orbits > MAX_TRANS_KEY) {
        printf("\n\nERROR: grille orbit count %d out of range for N=%d.\n\n", n_orbits, N);
        return 0;
    }
    out[0].period = n_orbits; out[0].aux[0] = N; out[0].j = 0; out[0].k = 0;
    return 1;
}
static void grille_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                           int *out, double *adj) {
    (void) adj;
    decrypt_grille(ctx->cipher, ctx->cipher_len, cc->aux[0] /* N */, st->key,
        ctx->cfg->variant ? 1 : 0, out, NULL);
}
static void grille_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "N=%d%s", cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void grille_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                          double score, int *decrypted) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    int N = cc->aux[0];
    printf("\ngrille: %d x %d, %d orbits%s\n", N, N, cc->period,
        variant ? " (variant: read/write swapped)" : "");
    char params[64];
    snprintf(params, sizeof(params), "N=%d%s", N, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps GRILLE_OPS = { grille_seed, grille_move };
static const CipherModel GRILLE_MODEL = {
    .name = "grille", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = grille_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = grille_decrypt, .report = grille_report,
    .report_verbose = grille_report_verbose,
};

void solve_grille(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &GRILLE_OPS;
    run_solver(&GRILLE_MODEL, &ctx);
}
