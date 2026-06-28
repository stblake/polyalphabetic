#include "digrafid_solver.h"
#include "engine.h"
#include "scoring.h"
#include "trans_common.h"

// =====================================================================
//  Digrafid solver (TYPE digrafid)
// =====================================================================
//
// Digrafid is a digraphic fractionation cipher over TWO independently keyed 27-symbol
// alphabets (A..Z + '#'): a horizontal grid H (3x9) and a vertical grid V (9x3). Breaking
// it is two coupled problems: recover the period and recover both grids. The grid search
// is the same SA square break Playfair/Two-Square use -- the state is the pair of grids,
// two permutations of 0..26 packed back-to-back in st->key (H = key[0..26], V =
// key[27..53]) -- annealed with n-gram scoring, each move perturbing ONE grid (chosen
// uniformly) with a cell swap (dominant) plus row/column swaps and reflections honouring
// that grid's shape (3x9 vs 9x3). No anti-collapse penalty is needed (every grid is a
// bijection, so the whole digraph map is), so score_adjust stays 0 and it rides the
// generic state_score; like the other square types it effectively needs -logprob.
//
// The period is recovered by an index-of-coincidence test (digrafid_estimate_periods):
// the ciphertext is laid out in 2P lanes -- one per (digraph-position-in-group, first/
// second-letter role) -- and at the true period each lane is coordinate-constrained, so
// the mean per-lane IoC stands out (it also peaks at multiples, which decrypt to gibberish
// and lose on the n-gram score). We anneal the top-K periods (one engine config each) and
// the n-gram score picks the winner. -period pins a single period.

#define DIGRAFID_MAX_PERIODS 64

typedef struct {
    int grid_size;                       // cells per grid (== g_alpha == 27)
    int n_periods;                       // number of candidate periods
    int periods[DIGRAFID_MAX_PERIODS];   // the candidate periods (config order)
} DigrafidScratch;

// --- period estimation --------------------------------------------------------
//
// For each trial period P, average the Index of Coincidence over the 2P lanes formed by
// (digraph index mod P, first/second-letter role). At the true period every lane draws a
// coordinate-constrained sub-distribution, so the mean per-lane IoC peaks. Returns the top
// n_want periods (descending) into out[].
int digrafid_estimate_periods(int cipher[], int len, int min_p, int max_p,
                              int n_want, int out[], bool verbose) {
    static double ioc[MAX_CIPHER_LENGTH];   // ioc[p] for p in [min_p..max_p]
    int ndig = len / 2;
    if (max_p > ndig / 2) max_p = ndig / 2;
    if (max_p < min_p) max_p = min_p;
    if (n_want < 1) n_want = 1;
    if (n_want > DIGRAFID_MAX_PERIODS) n_want = DIGRAFID_MAX_PERIODS;

    for (int p = min_p; p <= max_p; p++) {
        double total = 0.0;
        int nlanes = 0;
        for (int lane = 0; lane < 2 * p; lane++) {
            int counts[MAX_ALPHABET_SIZE];
            for (int s = 0; s < g_alpha; s++) counts[s] = 0;
            int N = 0;
            int dpos = lane / 2, role = lane & 1;        // digraph-position-in-group, role
            for (int d = dpos; d < ndig; d += p) {
                int sym = cipher[2 * d + role];
                if (sym >= 0 && sym < g_alpha) { counts[sym]++; N++; }
            }
            if (N > 1) {
                long acc = 0;
                for (int s = 0; s < g_alpha; s++) acc += (long) counts[s] * (counts[s] - 1);
                total += (double) acc / ((double) N * (N - 1));
                nlanes++;
            }
        }
        ioc[p] = (nlanes > 0) ? total / nlanes : 0.0;
    }

    if (verbose) {
        printf("\nDigrafid period estimate (mean per-lane IoC):\n  period\tIoC\n");
        for (int p = min_p; p <= max_p; p++) printf("  %d\t%.4f\n", p, ioc[p]);
    }

    // Selection by repeated max (n_want is small); mark taken periods with -1.
    int n = 0;
    for (; n < n_want; n++) {
        int best_p = -1;
        double best_ioc = -1.0;
        for (int p = min_p; p <= max_p; p++)
            if (ioc[p] >= 0.0 && ioc[p] > best_ioc) { best_ioc = ioc[p]; best_p = p; }
        if (best_p < 0) break;
        out[n] = best_p;
        ioc[best_p] = -1.0;
    }
    if (verbose) {
        printf("  -> annealing periods:");
        for (int i = 0; i < n; i++) printf(" %d", out[i]);
        printf("\n");
    }
    return n;
}

// One config per candidate period; period carries the block size, key the two grids.
static int digrafid_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    const DigrafidScratch *d = (const DigrafidScratch *) ctx->model_scratch;
    int n = d->n_periods;
    if (n > cap) n = cap;
    for (int i = 0; i < n; i++) {
        out[i].period = d->periods[i];
        out[i].j = 0; out[i].k = 0; out[i].aux[0] = 0; out[i].aux[1] = 0;
    }
    return n;
}

// Seed: two independent uniformly-random grids (a Fisher-Yates shuffle per grid).
static void digrafid_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    (void) cc;
    const DigrafidScratch *d = (const DigrafidScratch *) ctx->model_scratch;
    int g = d->grid_size;
    for (int s = 0; s < 2; s++) {
        int *blk = st->key + s * g;
        for (int i = 0; i < g; i++) blk[i] = i;
        for (int i = g - 1; i > 0; i--) {
            int j = rand_int(0, i + 1);
            int t = blk[i]; blk[i] = blk[j]; blk[j] = t;
        }
    }
    st->key_len = 2 * g;
}

// Apply one Playfair-style move to a single rows x cols grid `blk` (n = rows*cols cells,
// cell = r*cols + c): 80% swap two cells; 8% swap two rows; 8% swap two columns; 2% reverse
// (rotate 180); 1% flip rows; 1% flip columns. The larger moves jump the basins a single
// cell swap cannot escape; the shape (3x9 vs 9x3) is honoured so row/col swaps stay valid.
static void digrafid_perturb_block(int *blk, int rows, int cols, int n) {
    double r = frand();
    if (r < 0.80) {                              // swap two cells
        int a = rand_int(0, n), b = rand_int(0, n);
        int t = blk[a]; blk[a] = blk[b]; blk[b] = t;
    } else if (r < 0.88) {                       // swap two rows
        int r1 = rand_int(0, rows), r2 = rand_int(0, rows);
        for (int c = 0; c < cols; c++) {
            int t = blk[r1 * cols + c]; blk[r1 * cols + c] = blk[r2 * cols + c]; blk[r2 * cols + c] = t;
        }
    } else if (r < 0.96) {                       // swap two columns
        int c1 = rand_int(0, cols), c2 = rand_int(0, cols);
        for (int rr = 0; rr < rows; rr++) {
            int t = blk[rr * cols + c1]; blk[rr * cols + c1] = blk[rr * cols + c2]; blk[rr * cols + c2] = t;
        }
    } else if (r < 0.98) {                       // reverse the whole grid (rotate 180)
        for (int i = 0, j = n - 1; i < j; i++, j--) {
            int t = blk[i]; blk[i] = blk[j]; blk[j] = t;
        }
    } else if (r < 0.99) {                       // flip rows top<->bottom
        for (int r1 = 0, r2 = rows - 1; r1 < r2; r1++, r2--)
            for (int c = 0; c < cols; c++) {
                int t = blk[r1 * cols + c]; blk[r1 * cols + c] = blk[r2 * cols + c]; blk[r2 * cols + c] = t;
            }
    } else {                                     // flip columns left<->right
        for (int c1 = 0, c2 = cols - 1; c1 < c2; c1++, c2--)
            for (int rr = 0; rr < rows; rr++) {
                int t = blk[rr * cols + c1]; blk[rr * cols + c1] = blk[rr * cols + c2]; blk[rr * cols + c2] = t;
            }
    }
}

// Neighbour move: perturb ONE of the two grids, chosen uniformly, honouring its shape.
static void digrafid_perturb(const SolverCtx *ctx, const SolverConfig *cc,
                             SolverState *st, bool *force_primary) {
    const DigrafidScratch *d = (const DigrafidScratch *) ctx->model_scratch;
    (void) cc; (void) force_primary;
    int g = d->grid_size;
    if (rand_int(0, 2) == 0)
        digrafid_perturb_block(st->key, DIGRAFID_HROWS, DIGRAFID_HCOLS, g);     // H: 3x9
    else
        digrafid_perturb_block(st->key + g, DIGRAFID_VROWS, DIGRAFID_VCOLS, g); // V: 9x3
}

static void digrafid_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    (void) cc;
    // Both grids (DIGRAFID_STATE cells); the period config does not carry the state length.
    for (int i = 0; i < DIGRAFID_STATE; i++) dst->key[i] = src->key[i];
}

static void digrafid_decrypt_hook(const SolverCtx *ctx, const SolverConfig *cc,
                                  SolverState *st, int *out, double *score_adjust) {
    const DigrafidScratch *d = (const DigrafidScratch *) ctx->model_scratch;
    digrafid_decrypt(ctx->cipher, ctx->cipher_len, st->key, st->key + d->grid_size,
                     cc->period, out);
    *score_adjust = 0.0;
}

// Render one rows x cols grid as an indented box of letters.
static void digrafid_print_grid(const int grid[], int rows, int cols) {
    for (int r = 0; r < rows; r++) {
        printf("    ");
        for (int c = 0; c < cols; c++) printf("%c ", index_to_char(grid[r * cols + c]));
        printf("\n");
    }
}

static void digrafid_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    const DigrafidScratch *d = (const DigrafidScratch *) ctx->model_scratch;
    printf("\n  period %d, horizontal grid (3x9):\n", cc->period);
    digrafid_print_grid(st->key, DIGRAFID_HROWS, DIGRAFID_HCOLS);
    printf("  vertical grid (9x3):\n");
    digrafid_print_grid(st->key + d->grid_size, DIGRAFID_VROWS, DIGRAFID_VCOLS);
    report_transposition_verbose(ctx, score, decrypted, stats, "digrafid");
}

static void digrafid_report(const SolverCtx *ctx, const SolverConfig *cc,
                            const SolverState *st, double score, int *decrypted) {
    ColossusConfig *cfg = ctx->cfg;
    const DigrafidScratch *d = (const DigrafidScratch *) ctx->model_scratch;
    int len = ctx->cipher_len, n = d->grid_size;

    int n_words_found = 0;
    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < len; i++) plaintext_string[i] = index_to_char(decrypted[i]);
    plaintext_string[len] = '\0';
    if (cfg->dictionary_present && ctx->shared->dict != NULL)
        n_words_found = find_dictionary_words(plaintext_string, ctx->shared->dict,
            ctx->shared->n_dict_words, ctx->shared->max_dict_word_len);

    // The two recovered grids, read row-major (H first, then V).
    char hstr[DIGRAFID_GRID + 1], vstr[DIGRAFID_GRID + 1];
    for (int i = 0; i < n; i++) { hstr[i] = index_to_char(st->key[i]); vstr[i] = index_to_char(st->key[n + i]); }
    hstr[n] = '\0'; vstr[n] = '\0';

    printf("\nResult Score: %.2f | Words: %d | period=%d | H=%s | V=%s\n",
        score, n_words_found, cc->period, hstr, vstr);

    print_cipher(ctx->cipher, len, NULL);
    printf("\n");
    print_text(decrypted, len);
    printf("\n");
    printf("%s\n", ctx->cribtext);

    printf("\nrecovered horizontal grid (3x9, row major):\n");
    digrafid_print_grid(st->key, DIGRAFID_HROWS, DIGRAFID_HCOLS);
    printf("recovered vertical grid (9x3, row major):\n");
    digrafid_print_grid(st->key + n, DIGRAFID_VROWS, DIGRAFID_VCOLS);

    if (ctx->result) {
        ctx->result->solved = true;
        ctx->result->cipher_type = cfg->cipher_type;
        ctx->result->score = score;
        ctx->result->n_words = n_words_found;
        ctx->result->cycleword_len = cc->period;   // report the recovered period here
        vec_copy(decrypted, ctx->result->decrypted, len);
        ctx->result->decrypted_len = len;
    }

    // One-liner summary: >>> score, [words,] type, period=, H=, V=, file, CIPHER, PLAINTEXT
    if (cfg->dictionary_present)
        printf(">>> %.2f, %d, %d, period=%d, H=%s, V=%s, ",
            score, n_words_found, cfg->cipher_type, cc->period, hstr, vstr);
    else
        printf(">>> %.2f, %d, period=%d, H=%s, V=%s, ",
            score, cfg->cipher_type, cc->period, hstr, vstr);
    printf("%s, ", cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    print_cipher(ctx->cipher, len, NULL);
    printf(", ");
    print_text(decrypted, len);
    printf("\n");
}

static const CipherModel DIGRAFID_MODEL = {
    .name = "digrafid", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = digrafid_enumerate, .key_len = NULL,
    .seed = digrafid_seed, .perturb = digrafid_perturb, .copy_state = digrafid_copy,
    .decrypt = digrafid_decrypt_hook, .report = digrafid_report,
    .report_verbose = digrafid_report_verbose,
};

void solve_digrafid(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result) {

    (void) ciphertext_str;

    // Digrafid needs the 27-symbol alphabet (A..Z + '#'); the binary's main forces it, but
    // guard in case solve_digrafid is driven directly.
    if (g_alpha != DIGRAFID_GRID) {
        printf("\n\nERROR: Digrafid needs the 27-symbol alphabet (A..Z + '%c'; got %d).\n\n",
               DIGRAFID_EXTRA_CHAR, g_alpha);
        return;
    }
    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for a Digrafid solve.\n\n");
        return;
    }
    if (cipher_len % 2 != 0)
        printf("\nWARNING: odd ciphertext length (%d); a Digrafid ciphertext is always "
               "even. The trailing letter is left undecrypted.\n", cipher_len);
    for (int i = 0; i < cipher_len; i++)
        if (cipher_indices[i] < 0 || cipher_indices[i] >= g_alpha) {
            printf("\n\nERROR: ciphertext has a non-alphabet symbol at position %d; "
                   "Digrafid ciphertext must be solid symbols (A..Z + '%c').\n\n",
                   i, DIGRAFID_EXTRA_CHAR);
            return;
        }

    DigrafidScratch scratch;
    scratch.grid_size = g_alpha;

    // Candidate periods: pinned, or the estimator's top-K over [2 .. max_period].
    if (cfg->period_present) {
        scratch.periods[0] = cfg->period;
        scratch.n_periods = 1;
        if (cfg->verbose) printf("\ndigrafid: period pinned to %d\n", cfg->period);
    } else {
        int max_p = (cfg->max_period > 0) ? cfg->max_period : 20;
        int ndig = cipher_len / 2;
        if (max_p > ndig) max_p = ndig;
        int n_want = cfg->n_periods;
        scratch.n_periods = digrafid_estimate_periods(cipher_indices, cipher_len, 2, max_p,
            n_want, scratch.periods, cfg->verbose);
        if (scratch.n_periods < 1) { scratch.periods[0] = 2; scratch.n_periods = 1; }
    }

    if (cfg->verbose)
        printf("\ndigrafid: %d positions (%d digraphs), %d-symbol alphabet %s, %d candidate period(s)\n",
            cipher_len, cipher_len / 2, g_alpha, g_idx_to_char_arr, scratch.n_periods);

    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = &scratch;
    ctx.result = result;          // digrafid_report fills it (may be NULL for CLI use)

    run_solver(&DIGRAFID_MODEL, &ctx);
}
