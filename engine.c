#include "engine.h"
#include "scoring.h"




// =====================================================================
//  Cipher-type-agnostic search engine
// =====================================================================
//
// run_solver() drives every cipher type through one skeleton; the per-type
// CipherModel (colossus.h) supplies the cipher specifics as hooks. See the header
// for the interface contract. The big SolverState buffers are file-static (the
// program is single-threaded -- rng_state is a global) so unifying them here does
// not grow the stack.

// Build the optimal-cycleword per-column ciphertext histogram for a given period
// into ctx->hist_by_col (laid out as hist_by_col[col*ALPHABET_SIZE + c]). Depends
// only on the fixed ciphertext and the period, so the engine builds it once per
// config rather than on every derive_optimal_cycleword call.
static void engine_build_hist(SolverCtx *ctx, int period) {
    if (ctx->hist_by_col == NULL || period <= 0) return;
    for (int i = 0; i < period * ALPHABET_SIZE; i++) ctx->hist_by_col[i] = 0;
    int col = 0;
    for (int i = 0; i < ctx->cipher_len; i++) {
        int c = ctx->cipher[i];
        if (c >= 0) ctx->hist_by_col[col * ALPHABET_SIZE + c]++;
        if (++col == period) col = 0;
    }
}

static double engine_score(const SolverCtx *ctx, int *decrypted, double adjust) {
    ColossusConfig *cfg = ctx->cfg;
    return state_score(decrypted, ctx->cipher_len,
        ctx->crib_indices, ctx->crib_positions, ctx->n_cribs,
        ctx->ngram_data, cfg->ngram_size,
        cfg->weight_ngram, cfg->weight_crib, cfg->weight_ioc, cfg->weight_entropy) + adjust;
}

// Incremental variant of run_one_config (same restart / annealing / backtrack /
// best-tracking skeleton) for models that supply the score_neighbor/commit/sync
// hooks. The current state's decryption (cur_dec) is kept live; each neighbour is
// scored as a delta and only committed into cur_dec + the model caches on accept,
// so the per-iteration cost is O(positions the move touched) rather than O(N).
static double run_one_config_incremental(const CipherModel *m, SolverCtx *ctx,
                                         const SolverConfig *cfg_c,
                                         SolverState *out_best, int *out_decrypted) {

    static SolverState cur, loc, best;
    static int cur_dec[MAX_CIPHER_LENGTH], best_dec[MAX_CIPHER_LENGTH];
    ColossusConfig *cfg = ctx->cfg;

    double best_score = 0.0, cur_score, loc_score, adjust;
    bool have_best = false;
    bool force_primary = true;

    SearchShape shape = m->shape;
    if (cfg->method == METHOD_SHOTGUN) shape = SHAPE_SHOTGUN;
    else if (cfg->method == METHOD_ANNEAL) shape = SHAPE_ANNEAL;
    bool done = false;

    EngineStats st;
    memset(&st, 0, sizeof st);
    st.start_time = clock();

    double temp_start = cfg->init_temp;
    double cooling;
    if (cfg->cooling_rate > 0.0) {
        cooling = cfg->cooling_rate;
    } else {
        cooling = 1.0;
        if (cfg->n_hill_climbs > 1)
            cooling = pow(cfg->min_temp / temp_start, 1.0 / (double)(cfg->n_hill_climbs - 1));
    }

    for (int rs = 0; rs < cfg->n_restarts && !done; rs++) {
        st.n_restarts = rs;

        if (have_best && frand() < cfg->backtracking_probability) {
            m->copy_state(cfg_c, &best, &cur);
            vec_copy(best_dec, cur_dec, ctx->cipher_len);
            cur_score = best_score;
            st.n_backtracks++;
        } else {
            m->seed(ctx, cfg_c, &cur);
            adjust = 0.0;
            m->decrypt(ctx, cfg_c, &cur, cur_dec, &adjust);
            cur_score = engine_score(ctx, cur_dec, adjust);
        }
        // (Re)build the model caches so they describe the current decryption.
        m->sync_caches(ctx, cfg_c, cur_dec);

        force_primary = true;

        double temp = temp_start;
        for (int it = 0; it < cfg->n_hill_climbs && !done; it++) {
            st.n_iterations++;

            m->copy_state(cfg_c, &cur, &loc);
            m->perturb(ctx, cfg_c, &loc, &force_primary);

            loc_score = m->score_neighbor(ctx, cfg_c, &cur, &loc, cur_dec, cur_score);

            bool accept;
            if (loc_score > cur_score) {
                accept = true;
            } else if (shape == SHAPE_ANNEAL) {
                accept = frand() < exp((loc_score - cur_score) / temp);
            } else {
                accept = frand() < cfg->slip_probability;
            }
            if (accept) {
                if (loc_score <= cur_score) st.n_slips++;
                m->commit_neighbor(ctx, cfg_c, cur_dec);   // advance cur_dec + caches
                m->copy_state(cfg_c, &loc, &cur);
                cur_score = loc_score;
            }
            temp *= cooling;

            if (!have_best || cur_score > best_score) {
                best_score = cur_score; have_best = true;
                m->copy_state(cfg_c, &cur, &best);
                vec_copy(cur_dec, best_dec, ctx->cipher_len);
                if (cfg->verbose && m->report_verbose)
                    m->report_verbose(ctx, cfg_c, &best, best_score, cur_dec, &st);
                if (shape == SHAPE_DETERMINISTIC) done = true;
            }
        }
    }

    m->copy_state(cfg_c, &best, out_best);
    vec_copy(best_dec, out_decrypted, ctx->cipher_len);
    return best_score;
}

// Hill-climb one outer config: shotgun restarts + per-iteration neighbour move,
// with SHOTGUN slip / ANNEAL Metropolis acceptance and best-state tracking. Writes
// the config's best state to *out_best and its decryption to out_decrypted, and
// returns the best score.
static double run_one_config(const CipherModel *m, SolverCtx *ctx,
                             const SolverConfig *cfg_c,
                             SolverState *out_best, int *out_decrypted) {

    // Models exposing the incremental hooks take the fast path; all others fall
    // through to the unchanged generic climber below.
    if (m->score_neighbor && m->commit_neighbor && m->sync_caches)
        return run_one_config_incremental(m, ctx, cfg_c, out_best, out_decrypted);

    static SolverState cur, loc, best;
    static int decrypted[MAX_CIPHER_LENGTH];
    ColossusConfig *cfg = ctx->cfg;

    double best_score = 0.0, cur_score, loc_score, adjust;
    bool have_best = false;
    bool force_primary = true;               // first iteration forces a primary (keyword) move

    // -method overrides the model's built-in shape on EVERY cipher type (the engine
    // is acceptance-strategy agnostic); METHOD_DEFAULT keeps the model's own shape.
    SearchShape shape = m->shape;
    if (cfg->method == METHOD_SHOTGUN) shape = SHAPE_SHOTGUN;
    else if (cfg->method == METHOD_ANNEAL) shape = SHAPE_ANNEAL;
    bool deterministic = (shape == SHAPE_DETERMINISTIC);
    bool done = false;

    EngineStats st;
    memset(&st, 0, sizeof st);
    st.start_time = clock();

    // Geometric Metropolis annealing schedule (used only by SHAPE_ANNEAL). The
    // start temperature and cooling come from cfg (-inittemp / -coolingrate); when
    // no cooling rate is given it is derived to cool init_temp -> min_temp over the
    // hill-climb. Defaults reproduce the previously hardcoded 0.10 -> 0.001 schedule.
    double temp_start = cfg->init_temp;
    double cooling;
    if (cfg->cooling_rate > 0.0) {
        cooling = cfg->cooling_rate;
    } else {
        cooling = 1.0;
        if (cfg->n_hill_climbs > 1)
            cooling = pow(cfg->min_temp / temp_start, 1.0 / (double)(cfg->n_hill_climbs - 1));
    }

    for (int rs = 0; rs < cfg->n_restarts && !done; rs++) {
        st.n_restarts = rs;

        if (have_best && frand() < cfg->backtracking_probability) {
            m->copy_state(cfg_c, &best, &cur);
            cur_score = best_score;
            st.n_backtracks++;
        } else {
            m->seed(ctx, cfg_c, &cur);
            adjust = 0.0;
            m->decrypt(ctx, cfg_c, &cur, decrypted, &adjust);
            cur_score = engine_score(ctx, decrypted, adjust);
        }

        // Best is recorded only inside the hill-climb loop below (matching every
        // original climber), so have_best transitions to true on the first
        // iteration -- the restart-0 backtrack check then draws no RNG, keeping
        // the draw sequence identical to the per-cipher climbers this replaces.

        // force_primary is the per-restart "must perturb the primary lane" flag
        // (polyalpha's perturbate_keyword_p); the model reads and updates it.
        force_primary = true;

        double temp = temp_start;
        for (int it = 0; it < cfg->n_hill_climbs && !done; it++) {
            st.n_iterations++;

            m->copy_state(cfg_c, &cur, &loc);

            m->perturb(ctx, cfg_c, &loc, &force_primary);

            adjust = 0.0;
            m->decrypt(ctx, cfg_c, &loc, decrypted, &adjust);
            loc_score = engine_score(ctx, decrypted, adjust);

            bool accept;
            if (loc_score > cur_score) {
                accept = true;
            } else if (shape == SHAPE_ANNEAL) {
                accept = frand() < exp((loc_score - cur_score) / temp);
            } else {
                accept = frand() < cfg->slip_probability;
            }
            if (accept) {
                if (loc_score <= cur_score) st.n_slips++;
                m->copy_state(cfg_c, &loc, &cur);
                cur_score = loc_score;
            }
            temp *= cooling;

            if (!have_best || cur_score > best_score) {
                best_score = cur_score; have_best = true;
                m->copy_state(cfg_c, &cur, &best);
                if (cfg->verbose && m->report_verbose)
                    m->report_verbose(ctx, cfg_c, &best, best_score, decrypted, &st);
                if (deterministic) done = true;
            }
        }
    }

    m->copy_state(cfg_c, &best, out_best);
    adjust = 0.0;
    m->decrypt(ctx, cfg_c, &best, out_decrypted, &adjust);
    return best_score;
}

double run_solver(const CipherModel *m, SolverCtx *ctx) {

    static SolverConfig configs[MAX_SOLVER_CONFIGS];
    static SolverState best_state, cand_state;
    static int best_decrypted[MAX_CIPHER_LENGTH], cand_decrypted[MAX_CIPHER_LENGTH];
    // Optimal-cycleword histogram scratch, owned by the engine (single-threaded).
    static int hist_by_col[MAX_CYCLEWORD_LEN * ALPHABET_SIZE];
    ctx->hist_by_col = hist_by_col;

    int nconf = m->enumerate_configs(ctx, configs, MAX_SOLVER_CONFIGS);
    if (nconf <= 0) return 0.0;

    double best_score = 0.0;
    bool have_best = false;
    SolverConfig best_cfg;

    for (int c = 0; c < nconf; c++) {
        SolverConfig *cc = &configs[c];

        if (m->needs_hist) engine_build_hist(ctx, cc->period);

        double sc;
        if (m->key_len && m->key_len(ctx, cc) == 0) {
            // SWEEP cell: the config itself is the candidate (one decrypt+score).
            double adjust = 0.0;
            m->seed(ctx, cc, &cand_state);
            m->decrypt(ctx, cc, &cand_state, cand_decrypted, &adjust);
            sc = engine_score(ctx, cand_decrypted, adjust);
        } else {
            sc = run_one_config(m, ctx, cc, &cand_state, cand_decrypted);
        }

        if (!have_best || sc > best_score) {
            best_score = sc; have_best = true;
            best_cfg = *cc;
            m->copy_state(cc, &cand_state, &best_state);
            vec_copy(cand_decrypted, best_decrypted, ctx->cipher_len);
        }
    }

    if (!have_best) return 0.0;

    m->report(ctx, &best_cfg, &best_state, best_score, best_decrypted);
    return best_score;
}

// Assemble the invariant SolverCtx the engine and every model hook read from.
// hist_by_col is left NULL here; run_solver() points it at its own scratch buffer.
SolverCtx make_solver_ctx(ColossusConfig *cfg, SharedData *shared, char *cribtext,
    int cipher[], int cipher_len, int crib_indices[], int crib_positions[], int n_cribs) {

    SolverCtx ctx;
    ctx.cfg = cfg;
    ctx.shared = shared;
    ctx.cipher = cipher;
    ctx.cipher_len = cipher_len;
    ctx.crib_indices = crib_indices;
    ctx.crib_positions = crib_positions;
    ctx.n_cribs = n_cribs;
    ctx.cribtext = cribtext;
    ctx.ngram_data = shared->ngram_data;
    ctx.hist_by_col = NULL;
    ctx.model_scratch = NULL;
    ctx.result = NULL;
    return ctx;
}


// Tuned per-cipher-type search schedules. See SearchDefaults (colossus.h). Only types
// whose ideal schedule differs materially from the init_config globals appear here;
// every other type is absent and so keeps the global defaults bit-for-bit.
//
//   Playfair: the score is a MEAN log-probability (so the natural temperature lives on
//   a much smaller scale than the polyalphabetic/transposition reward score), and the
//   digraph landscape is riddled with local optima. The profile below (single-letter-
//   swap-dominated anneal at inittemp 0.08, several backtracking restarts) reliably
//   recovers ~600+ character ciphers; below that Playfair is genuinely near the limit
//   of a quadgram attack (see tests/test_playfair_solver.c).
//   Bifid: the same square-anneal landscape as Playfair, but several candidate periods
//   are each annealed (run_solver keeps the global best by n-gram score), so the per-
//   period budget is smaller than Playfair's single-config budget to keep the whole
//   solve in the same ballpark. Same small-scale temperature (mean log-probability).
//   Trifid: the same fractionation-anneal as Bifid but over a 27-cell 3x3x3 cube (a
//   larger permutation space than Bifid's 25-cell square), so it gets a larger per-
//   period budget; otherwise identical small-scale temperature and per-period scheme.
//   Hill: the state is a k x k decryption matrix (every entry 0..25) hill-climbed /
//   annealed with the same mean-log-probability fitness, so it shares the small-scale
//   temperature. The matrices are small (k=2 is only 26^4 keys) and greedy climbs
//   converge fast on a rugged landscape, so -- unlike the fractionation types -- the
//   lever is RESTARTS, not iterations: the profile is many short restarts (250x8000),
//   run once per swept block size (k = 2..5).
static const SearchDefaults g_search_defaults[] = {
    { .cipher_type = PLAYFAIR, .default_shape = SHAPE_ANNEAL,
      .a_n_restarts = 6, .a_n_hill_climbs = 400000,
      .a_init_temp = 0.08, .a_min_temp = 0.001, .a_cooling_rate = 0.0,
      .a_backtracking_probability = 0.30,
      .s_n_restarts = 30, .s_n_hill_climbs = 300000,
      .s_slip_probability = 0.0005, .s_backtracking_probability = 0.20 },
    { .cipher_type = BIFID, .default_shape = SHAPE_ANNEAL,
      .a_n_restarts = 4, .a_n_hill_climbs = 200000,
      .a_init_temp = 0.08, .a_min_temp = 0.001, .a_cooling_rate = 0.0,
      .a_backtracking_probability = 0.30,
      .s_n_restarts = 20, .s_n_hill_climbs = 200000,
      .s_slip_probability = 0.0005, .s_backtracking_probability = 0.20 },
    { .cipher_type = TRIFID, .default_shape = SHAPE_ANNEAL,
      .a_n_restarts = 6, .a_n_hill_climbs = 300000,
      .a_init_temp = 0.08, .a_min_temp = 0.001, .a_cooling_rate = 0.0,
      .a_backtracking_probability = 0.30,
      .s_n_restarts = 24, .s_n_hill_climbs = 300000,
      .s_slip_probability = 0.0005, .s_backtracking_probability = 0.20 },
    { .cipher_type = HILL, .default_shape = SHAPE_ANNEAL,
      .a_n_restarts = 250, .a_n_hill_climbs = 8000,
      .a_init_temp = 0.10, .a_min_temp = 0.001, .a_cooling_rate = 0.0,
      .a_backtracking_probability = 0.25,
      .s_n_restarts = 250, .s_n_hill_climbs = 8000,
      .s_slip_probability = 0.0005, .s_backtracking_probability = 0.20 },
    // Phillips (and its column / row-column variants): the same 5x5-square anneal as
    // Playfair (one config, the base grid is the only unknown), so it shares Playfair's
    // small-scale temperature and backtracking. But Phillips is MONOGRAPHIC (every letter
    // is independently substituted, period 40), so it carries more signal per character
    // than digraphic Playfair and recovers reliably from ~200 characters at a leaner
    // budget -- 4x250000 lands a 760-char solve at ~100% in ~16s (see
    // tests/test_phillips_solver.c). Same profile for all three variants.
    { .cipher_type = PHILLIPS, .default_shape = SHAPE_ANNEAL,
      .a_n_restarts = 4, .a_n_hill_climbs = 250000,
      .a_init_temp = 0.08, .a_min_temp = 0.001, .a_cooling_rate = 0.0,
      .a_backtracking_probability = 0.30,
      .s_n_restarts = 20, .s_n_hill_climbs = 250000,
      .s_slip_probability = 0.0005, .s_backtracking_probability = 0.20 },
    { .cipher_type = PHILLIPS_C, .default_shape = SHAPE_ANNEAL,
      .a_n_restarts = 4, .a_n_hill_climbs = 250000,
      .a_init_temp = 0.08, .a_min_temp = 0.001, .a_cooling_rate = 0.0,
      .a_backtracking_probability = 0.30,
      .s_n_restarts = 20, .s_n_hill_climbs = 250000,
      .s_slip_probability = 0.0005, .s_backtracking_probability = 0.20 },
    { .cipher_type = PHILLIPS_RC, .default_shape = SHAPE_ANNEAL,
      .a_n_restarts = 4, .a_n_hill_climbs = 250000,
      .a_init_temp = 0.08, .a_min_temp = 0.001, .a_cooling_rate = 0.0,
      .a_backtracking_probability = 0.30,
      .s_n_restarts = 20, .s_n_hill_climbs = 250000,
      .s_slip_probability = 0.0005, .s_backtracking_probability = 0.20 },
};

bool apply_cipher_defaults(ColossusConfig *cfg, bool announce) {
    const SearchDefaults *d = NULL;
    for (size_t i = 0; i < sizeof(g_search_defaults) / sizeof(g_search_defaults[0]); i++)
        if (g_search_defaults[i].cipher_type == cfg->cipher_type) { d = &g_search_defaults[i]; break; }
    if (d == NULL) return false;

    // Effective shape: an explicit -method wins, else the type's own default shape.
    SearchShape shape = d->default_shape;
    if (cfg->method == METHOD_SHOTGUN) shape = SHAPE_SHOTGUN;
    else if (cfg->method == METHOD_ANNEAL) shape = SHAPE_ANNEAL;

    if (shape == SHAPE_SHOTGUN) {
        cfg->n_restarts = d->s_n_restarts;
        cfg->n_hill_climbs = d->s_n_hill_climbs;
        cfg->slip_probability = d->s_slip_probability;
        cfg->backtracking_probability = d->s_backtracking_probability;
        if (announce)
            printf("-type defaults: shotgun schedule %dx%d (slipprob %.4f, backtrack %.2f)\n",
                d->s_n_restarts, d->s_n_hill_climbs, d->s_slip_probability,
                d->s_backtracking_probability);
    } else {
        cfg->n_restarts = d->a_n_restarts;
        cfg->n_hill_climbs = d->a_n_hill_climbs;
        cfg->init_temp = d->a_init_temp;
        cfg->min_temp = d->a_min_temp;
        cfg->cooling_rate = d->a_cooling_rate;
        cfg->backtracking_probability = d->a_backtracking_probability;
        if (announce)
            printf("-type defaults: anneal schedule %dx%d (inittemp %.3f, backtrack %.2f)\n",
                d->a_n_restarts, d->a_n_hill_climbs, d->a_init_temp,
                d->a_backtracking_probability);
    }
    return true;
}



