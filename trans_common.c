#include "trans_common.h"

// =====================================================================
//  Shared reporting for the dedicated transposition solvers
// =====================================================================
//
// Every transposition solver recovers a single best plaintext plus a short,
// type-specific parameter description; this helper prints the common
// human-readable block and the ">>> ..." one-line CSV summary so the output shape
// (and, crucially, the recovered plaintext as the final CSV field that the
// regression suite scrapes) is identical across types. `param_summary` is one
// already-formatted CSV field describing the recovered key (e.g. "rails=5 off=0").
void report_transposition(ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len, int best_decrypted[],
    double best_score, char *cribtext_str, int n_cribs,
    const char *param_summary) {

    int n_words_found = 0;

    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < cipher_len; i++) plaintext_string[i] = index_to_char(best_decrypted[i]);
    plaintext_string[cipher_len] = '\0';

    if (cfg->dictionary_present && shared->dict != NULL) {
        n_words_found = find_dictionary_words(plaintext_string, shared->dict,
            shared->n_dict_words, shared->max_dict_word_len);
    }

    printf("\nResult Score: %.2f | Words: %d | %s\n", best_score, n_words_found, param_summary);

    print_text(cipher_indices, cipher_len);
    printf("\n");
    print_text(best_decrypted, cipher_len);
    printf("\n");
    printf("%s\n", cribtext_str);

    if (PARTIAL_CRIB_MATCH && n_cribs > 0) {
        for (int i = 0; i < cipher_len; i++) {
            if (cribtext_str[i] == '_') {
                printf("_");
            } else {
                int diff = abs(best_decrypted[i] - (g_char_to_idx[toupper((unsigned char)cribtext_str[i]) & 127]));
                if (diff < 10) printf("%d", diff); else printf("*");
            }
        }
        printf("\n");
    }

    // One-liner summary: >>> score, [words,] type, <params>, file, CIPHER, PLAINTEXT
    if (cfg->dictionary_present) {
        printf(">>> %.2f, %d, %d, ", best_score, n_words_found, cfg->cipher_type);
    } else {
        printf(">>> %.2f, %d, ", best_score, cfg->cipher_type);
    }
    printf("%s, ", param_summary);
    printf("%s, ", cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    print_text(cipher_indices, cipher_len);
    printf(", ");
    print_text(best_decrypted, cipher_len);
    printf("\n");
}

// Live (-verbose) progress block for the optimization-based transposition models, in
// the same shape as permutation_report_verbose / columnar_model_report_verbose: timing
// and search counters, a type-specific param line, and the current best plaintext.
// best_decrypted is the just-accepted best decrypt the engine passes to report_verbose.
void report_transposition_verbose(const SolverCtx *ctx, double best_score,
    int best_decrypted[], const EngineStats *stats, const char *param_summary) {

    double elapsed = ((double) clock() - stats->start_time)/CLOCKS_PER_SEC;
    double n_iter_per_sec = (elapsed > 0.) ? ((double) stats->n_iterations)/elapsed : 0.;
    printf("\n%.2f\t[sec]\n", elapsed);
    printf("%.0fK\t[it/sec]\n", 1.e-3*n_iter_per_sec);
    printf("%d\t[restarts]\n", stats->n_restarts);
    printf("%d\t[backtracks]\n", stats->n_backtracks);
    printf("%d\t[slips]\n", stats->n_slips);
    printf("%.4f\t[entropy]\n", entropy(best_decrypted, ctx->cipher_len));
    printf("%.2f\t[score]\n", best_score);
    printf("%s\t[params]\n\n", param_summary);
    print_text(best_decrypted, ctx->cipher_len); printf("\n");
    fflush(stdout);
}


// =====================================================================
//  Shared key-anneal hooks for the permutation-style transposition models
// =====================================================================
//
// Amsco, Myszkowski, Redefence, Cadenus, Nihilist, Swagman and Grille all reduce
// to annealing a short integer key (st->key) through the generic engine. Only the
// key->plaintext decrypt, the neighbour move, the restart seed, the outer parameter
// sweep and the report differ per type. The move and seed are supplied through a
// TransKeyOps descriptor (placed in ctx->model_scratch by the solve_ entry point);
// the decrypt, enumerate and report are per-type hooks. cc->period carries the key
// length; cc->aux[0..1] carry the fixed per-config parameters (start / offset /
// readmode / N), with -variant read straight from cfg.


void tkey_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    ((const TransKeyOps *) ctx->model_scratch)->seed_cb(st->key, cc->period);
}
void tkey_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st, bool *fp) {
    (void) fp;
    ((const TransKeyOps *) ctx->model_scratch)->move_cb(st->key, cc->period);
}
void tkey_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    for (int i = 0; i < cc->period; i++) dst->key[i] = src->key[i];
}

// Neighbour move shared by the permutation-key types (swap dominant, with short
// reverses and block moves), preserving the permutation property.
void perm_move(int *key, int K) {
    if (K < 2) return;
    double r = frand();
    if (r < 0.70) {
        int a = rand_int(0, K), b = rand_int(0, K);
        int t = key[a]; key[a] = key[b]; key[b] = t;
    } else if (r < 0.85) {
        int max_blk = min(K, 8);
        int blk = rand_int(2, max_blk + 1);
        int s = rand_int(0, K - blk + 1);
        for (int a = s, b = s + blk - 1; a < b; a++, b--) {
            int t = key[a]; key[a] = key[b]; key[b] = t;
        }
    } else {
        int max_blk = min(K, 8);
        int blk = rand_int(1, max_blk + 1);
        int s = rand_int(0, K - blk + 1);
        int d = rand_int(0, K - blk + 1);
        if (d == s) return;
        int tmp[8];
        for (int a = 0; a < blk; a++) tmp[a] = key[s + a];
        if (d < s) { for (int a = s - 1; a >= d; a--) key[a + blk] = key[a]; }
        else       { for (int a = s + blk; a < d + blk; a++) key[a - blk] = key[a]; }
        for (int a = 0; a < blk; a++) key[d + a] = tmp[a];
    }
}

// Restart seed shared by the permutation-key types: a random permutation.
void perm_seed(int *key, int K) {
    for (int i = 0; i < K; i++) key[i] = i;
    shuffle(key, K);
}


int sweep_keylen(const SolverCtx *ctx, const SolverConfig *cc) { (void)ctx; (void)cc; return 0; }
void sweep_noop_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) { (void)ctx; (void)cc; (void)st; }
void sweep_noop_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) { (void)cc; (void)src; (void)dst; }
// Integer square root with exact-square test: returns N where N*N == x, else -1.
int exact_isqrt(int x) {
    if (x < 0) return -1;
    int n = (int)(sqrt((double)x) + 0.5);
    for (int d = -1; d <= 1; d++)
        if ((n + d) >= 0 && (n + d) * (n + d) == x) return n + d;
    return -1;
}


