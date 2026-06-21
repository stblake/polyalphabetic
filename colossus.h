#ifndef COLOSSUS_H
#define COLOSSUS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h> 
#include <string.h>
#include <math.h>
#include <time.h>
#include <strings.h>
#include <unistd.h>
#include <stdint.h>

#define KRYPTOS 0
#define CRIB_CHECK 0
#define PARTIAL_CRIB_MATCH 1

#define VIGENERE 0
#define QUAGMIRE_1 1
#define QUAGMIRE_2 2
#define QUAGMIRE_3 3
#define QUAGMIRE_4 4
#define BEAUFORT   5
#define PORTA      6
#define AUTOKEY_0  7 
#define AUTOKEY_1  8 
#define AUTOKEY_2  9 
#define AUTOKEY_3  10
#define AUTOKEY_4  11
#define AUTOKEY_BEAU 12
#define AUTOKEY_PORTA 13
#define TRANSMATRIX    14
#define TRANSPEROFFSET 15
#define TRANSPOSITION  16
#define TRANSCOL       17   // single columnar transposition (dedicated solver)
#define TRANSCOL2      18   // double (nested) columnar transposition
#define RAILFENCE      19   // rail fence + variant rail fence (phase-offset sweep)
#define ROUTE          20   // route transposition (snake / spiral over an R x C grid)
#define AMSCO          21   // Amsco (alternating 1/2-letter columnar)
#define MYSZKOWSKI     22   // Myszkowski (columnar with tied keyword ranks)
#define REDEFENCE      23   // Redefence (keyed rail fence)
#define CADENUS        24   // Cadenus (rotated-column transposition, 25 rows)
#define NIHILIST       25   // Nihilist transposition (single perm on rows + columns)
#define SWAGMAN        26   // Swagman (N x N Latin-square column transposition)
#define GRILLE         27   // Turning grille
#define INDEP_PERIODIC 28   // period-P substitution with P INDEPENDENT mixed alphabets
#define HOMOPHONIC     29   // homophonic substitution (ciphertext alphabet > plaintext)

#define ALPHABET_SIZE 26        // compile-time MAX alphabet size (sizes all arrays)
#define MAX_CIPHER_LENGTH 10000
#define MAX_SYMBOLS    512      // distinct ciphertext symbols a homophonic cipher may use
#define MAX_TOKEN_LEN  16       // longest surface form of one ciphertext symbol token
#define MAX_FILENAME_LEN 4096   // must hold absolute paths; main() strcpy's CLI args in unbounded
#define MAX_KEYWORD_LEN 26
#define MAX_CYCLEWORD_LEN 300
#define MAX_NGRAM_SIZE 8
#define MAX_DICT_WORD_LEN 30
#define MAX_COLS 100            // upper bound on columnar column count (sizes order arrays)
#define MAX_TRANS_KEY 1024      // upper bound on a climbed transposition key length
                                // (grille orbit map, packed Cadenus order+rotation, etc.)

// Columnar read direction (cfg->read_direction).
#define COL_READ_TB   0        // read each column top-to-bottom (canonical)
#define COL_READ_BT   1        // read each column bottom-to-top
#define COL_READ_BOTH 2        // search both directions

// Optimization method (cfg->method): which acceptance strategy the engine uses.
// METHOD_DEFAULT keeps each cipher model's built-in SearchShape; the others force
// one strategy on EVERY cipher type (cipher-agnostic), set via -method.
#define METHOD_DEFAULT 0       // per-model default (shotgun, or anneal for transposition)
#define METHOD_SHOTGUN 1       // accept-worse with slip_probability
#define METHOD_ANNEAL  2       // geometric-cooling Metropolis (simulated annealing)

#define FREQUENCY_WEIGHTED_SELECTION 1
#define DICTIONARY 1
#define INACTIVE -9999

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

// --- Tokenized ciphertext I/O ---
//
// A SymbolTable interns the distinct surface tokens of a ciphertext so that ciphers
// whose ciphertext alphabet is larger than (or disjoint from) A..Z -- homophonic
// substitution, in particular -- can be entered and displayed consistently. The
// ciphertext is decoded into a sequence of integer symbol ids (0..n-1) indexing this
// table. The single-character / 0..25 letter path (every other cipher type) does NOT
// build a table: decode_cipher reproduces ord() byte-for-byte when tab is unused.
typedef struct {
    int  n;                                    // distinct symbols interned so far
    char tokens[MAX_SYMBOLS][MAX_TOKEN_LEN];   // surface form of each symbol id
    int  freq[MAX_SYMBOLS];                    // occurrence count of each symbol id
    char delimiter;                            // 0 => per-character; else the field separator
} SymbolTable;

// --- Configuration Structs ---

typedef struct {
    int cipher_type;
    int ngram_size;
    int n_hill_climbs;
    int n_restarts;
    
    // Keyword/Cycleword constraints
    int plaintext_keyword_len;
    int ciphertext_keyword_len;
    int min_keyword_len;
    int plaintext_max_keyword_len;
    int ciphertext_max_keyword_len;
    int max_cycleword_len;
    int cycleword_len;
    
    // Input Flags for lengths
    bool plaintext_keyword_len_present;
    bool ciphertext_keyword_len_present;
    bool cycleword_len_present;

    // Explicit User Keywords (Strings)
    char user_plaintext_keyword[ALPHABET_SIZE + 1];
    char user_ciphertext_keyword[ALPHABET_SIZE + 1];
    bool user_plaintext_keyword_present;
    bool user_ciphertext_keyword_present;

    // Probabilities & Thresholds
    double n_sigma_threshold;
    double ioc_threshold;
    double backtracking_probability;
    double keyword_permutation_probability;
    double slip_probability;

    // Weights
    float weight_ngram;
    float weight_crib;
    float weight_ioc;
    float weight_entropy;
    float weight_structure; // general transposition: reward regular (columnar) key steps
    float weight_monogram;  // homophonic: penalise decrypted letter-frequency deviation
                            // from English (chi-squared) -- stops the map collapsing
                            // many symbols onto a few common letters

    // Files
    char ciphertext_file[MAX_FILENAME_LEN];
    char batch_file[MAX_FILENAME_LEN];
    char crib_file[MAX_FILENAME_LEN];
    char dictionary_file[MAX_FILENAME_LEN];
    char ngram_file[MAX_FILENAME_LEN];

    // Flags
    bool verbose;
    bool skip_spaces;   // strip spaces/punctuation from the ciphertext entirely
    bool cipher_present;
    bool batch_present;
    bool crib_present;
    bool dictionary_present;
    bool variant;
    bool beaufort;

    bool optimal_cycleword;
    bool same_key_cycle;

    int method;          // METHOD_DEFAULT / METHOD_SHOTGUN / METHOD_ANNEAL (-method)

    // Simulated-annealing schedule (SHAPE_ANNEAL only). Backtracking is shared with
    // the shotgun path via backtracking_probability above. cooling_rate <= 0 means
    // "derive a geometric init_temp -> min_temp schedule over n_hill_climbs steps".
    double init_temp;    // starting temperature (-inittemp), default 0.10
    double min_temp;     // floor temperature for the derived schedule (-mintemp), default 0.001
    double cooling_rate; // per-iteration multiplier (-coolingrate); <= 0 => derive, default 0

    // Transpositions.
    bool transperoffset_present;
    int trans_offset;
    int trans_period;

    bool transmatrix_present;
    int trans_w1;
    int trans_w2;
    int trans_clockwise; // 1 for clockwise, 0 for anti-clockwise

    // Columnar transposition (TRANSCOL / TRANSCOL2).
    int min_cols;        // smallest column count to search
    int max_cols;        // largest column count to search
    int read_direction;  // COL_READ_TB / COL_READ_BT / COL_READ_BOTH

    // Tokenized I/O. delimiter == 0 keeps the historical per-character / 0..25 letter
    // decode (bit-identical to ord()); a non-zero delimiter (default ',' for
    // HOMOPHONIC) splits the ciphertext into multi-character symbol tokens.
    char delimiter;
    bool delimiter_present;

} ColossusConfig;

typedef struct {
    float *ngram_data;
    char **dict;
    int n_dict_words;
    int max_dict_word_len;
} SharedData;

// Outcome of a polyalphabetic solve. solve_cipher fills this (when a non-NULL
// pointer is passed) so callers -- in particular the regression tests -- can
// inspect the recovered solution instead of scraping stdout. solved is false if
// no valid configuration was found, or for the transposition cipher types
// (which are dispatched to their own solvers and report separately).
typedef struct {
    bool solved;
    int cipher_type;
    double score;
    int n_words;
    int cycleword_len;
    int plaintext_keyword[ALPHABET_SIZE];
    int ciphertext_keyword[ALPHABET_SIZE];
    int cycleword[MAX_CYCLEWORD_LEN];
    int decrypted[MAX_CIPHER_LENGTH];
    int decrypted_len;
} SolveResult;

// =====================================================================
//  Cipher-type-agnostic search engine (run_solver) -- see CLAUDE.md.
// =====================================================================
//
// Every cipher is solved by the same skeleton: enumerate the outer search
// configurations, then for each either evaluate a single candidate (a pure
// parameter sweep) or shotgun-restart + hill-climb a candidate state, scoring
// each decrypt with the shared n-gram (+ crib) state_score and keeping the best.
// The skeleton lives in run_solver()/run_one_config(); each cipher type supplies
// a CipherModel (a vtable of hooks) describing how to seed/perturb/decrypt/report
// its own state. The engine owns the loops, acceptance, backtracking, best
// tracking, and the single state_score call site; the model owns the cipher math.

#define MAX_SOLVER_CONFIGS 65536   // cap on enumerated outer configs per solve

// Invariant problem instance + engine-owned scratch, passed to every hook.
typedef struct {
    ColossusConfig *cfg;
    SharedData     *shared;
    int            *cipher;          // cipher_indices[0..cipher_len-1]
    int             cipher_len;
    int            *crib_indices;
    int            *crib_positions;
    int             n_cribs;
    char           *cribtext;        // raw crib string ('_' = no crib) for the report hooks
    float          *ngram_data;      // == shared->ngram_data, hoisted for the hot path
    int            *hist_by_col;     // engine scratch: optimal-cycleword per-column histogram
                                     // (hist_by_col[col*ALPHABET_SIZE + c]); built when model->needs_hist
    void           *model_scratch;   // model-private per-config cache (e.g. indep_periodic seed)
    SolveResult    *result;          // polyalpha: report hook fills it (may be NULL)
} SolverCtx;

// One outer enumeration point. Field meanings are per-model: `period` is the
// cycleword length / column count K / rail count / permutation length; `j`,`k`
// are the polyalphabetic pt/ct keyword lengths; `aux` holds any remaining fixed
// parameters (amsco start, columnar read direction, route id, rail offset, ...).
typedef struct {
    int period;
    int j, k;
    int aux[2];
} SolverConfig;

// Superset candidate state; a model uses only the lane(s) it needs and its
// copy_state hook copies only those, so the per-iteration copy stays cheap.
typedef struct {
    int pt_keyword[ALPHABET_SIZE];   // polyalpha lane
    int ct_keyword[ALPHABET_SIZE];
    int cycleword[MAX_CYCLEWORD_LEN];
    int key[MAX_CIPHER_LENGTH];       // transposition lane (perm / order / rank / rot / square / turns)
    int key_len;
    int aux[8];                       // small per-state scratch (stage K's, dirs, carried period, ...)
} SolverState;

typedef enum {
    SHAPE_SHOTGUN,        // accept-worse with slip_probability (polyalpha, transmatrix)
    SHAPE_ANNEAL,         // geometric-cooling Metropolis acceptance (columnar, permutation)
    SHAPE_DETERMINISTIC   // shotgun + first-improvement break (Vig/Beau/Porta under -optimalcycle)
} SearchShape;

// Live engine counters, filled by the engine for the verbose-report hook.
typedef struct {
    int    n_iterations;
    int    n_restarts;
    int    n_backtracks;
    int    n_slips;
    int    n_contradictions;
    clock_t start_time;
} EngineStats;

// The per-cipher-type model. Optional hooks may be NULL.
typedef struct CipherModel {
    const char *name;
    SearchShape shape;
    bool        needs_hist;          // engine builds ctx->hist_by_col before each config

    // Fill out[] with up to cap outer configs; return the count (<= cap).
    int  (*enumerate_configs)(const SolverCtx *ctx, SolverConfig *out, int cap);

    // Return the climbed key length for this config; 0 => this config is a single
    // SWEEP candidate (seed+decrypt+score once, no restarts). NULL => always climb.
    int  (*key_len)(const SolverCtx *ctx, const SolverConfig *cfg_c);

    // Produce a fresh restart state (random, or deterministic for a SWEEP cell).
    void (*seed)(const SolverCtx *ctx, const SolverConfig *cfg_c, SolverState *st);

    // One neighbour move on `st` (already a copy of current). *force_primary is the
    // cross-iteration "must perturb the primary lane" flag (polyalpha's
    // perturbate_keyword_p): the engine sets it true at the start of each restart;
    // the model reads it and writes back the value for the next iteration. Models
    // with no primary/secondary distinction ignore it. Any deterministic refine
    // (optimal cycleword), crib constrain, and -samekey coupling that the original
    // per-cipher climber did around the move live inside this hook.
    void (*perturb)(const SolverCtx *ctx, const SolverConfig *cfg_c, SolverState *st,
                    bool *force_primary);

    // Copy only the live lane(s) of `src` into `dst`.
    void (*copy_state)(const SolverConfig *cfg_c, const SolverState *src, SolverState *dst);

    // Decrypt `st` into out[0..cipher_len-1]. *score_adjust (init 0 by the engine)
    // receives any additive score term the model wants folded into state_score
    // (e.g. the general-transposition structure score); st may be mutated to carry
    // state forward (e.g. the detected period). Most models leave *score_adjust 0.
    void (*decrypt)(const SolverCtx *ctx, const SolverConfig *cfg_c, SolverState *st,
                    int *out, double *score_adjust);

    // Final report (human block + ">>>" CSV) for the global-best state.
    void (*report)(const SolverCtx *ctx, const SolverConfig *cfg_c, const SolverState *st,
                   double score, int *decrypted);
    // Optional: live display on each best-improvement when -verbose.
    void (*report_verbose)(const SolverCtx *ctx, const SolverConfig *cfg_c, const SolverState *st,
                           double score, int *decrypted, const EngineStats *stats);
} CipherModel;

// Run `model` over `ctx`: enumerate configs, sweep/climb each, report the best.
// Returns the best score (0 if no configuration produced a candidate).
double run_solver(const CipherModel *model, SolverCtx *ctx);

// --- Statistics Data ---

static int n_english_word_length_frequency_letters = 25;
static double english_word_length_frequencies[] = {
	0.0316, 0.16975, 0.21192, 0.15678, 0.10852, 0.08524, 0.07724, 
	0.05623, 0.04032, 0.02766, 0.01582, 0.00917, 0.00483, 0.00262, 
	0.00099, 0.0005, 0.00027, 0.00022, 0.00011, 0.00006, 0.00005, 
	0.00002, 0.00001, 0.00001, 0.00001};

static double english_monograms[] = {
	0.085517, 0.016048, 0.031644, 0.038712, 0.120965, 0.021815, 
	0.020863, 0.049557, 0.073251, 0.002198, 0.008087, 0.042065, 
	0.025263, 0.071722, 0.074673, 0.020662, 0.001040, 0.063327, 
	0.067282, 0.089381, 0.026816, 0.010593, 0.018254, 0.001914, 
	0.017214, 0.001138
};

// Core Logic
void init_config(ColossusConfig *cfg);
// result may be NULL (CLI use); when supplied it receives the recovered solution.
void solve_cipher(char *ciphertext_str, char *cribtext_str, ColossusConfig *cfg,
    SharedData *shared, SolveResult *result);

// Prints the human-readable block and the ">>> ..." one-line CSV summary for a
// polyalphabetic solve, from the populated result.
void report_solution(ColossusConfig *cfg, char *cribtext_str,
    int cipher_indices[], SolveResult *res);

// Porta cipher
void porta_decrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len);
void porta_encrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len);

// Vigenere cipher
void vigenere_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len, bool variant);
void vigenere_encrypt(int encrypted[], int plaintext_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len, bool variant);

// Beaufort cipher
void beaufort_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len);
void beaufort_encrypt(int encrypted[], int plaintext_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len);

// Quagmire I - IV ciphers
void quagmire_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int cycleword_indices[], int cycleword_len, bool variant);
void quagmire_encrypt(int encrypted[], int plaintext_indices[], int cipher_len, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int cycleword_indices[], int cycleword_len, bool variant);

// Autokey
void autokey_encrypt(ColossusConfig *cfg, int ciphertext[], int plaintext_indices[],
    int plaintext_len, int plaintext_keyword[], int ciphertext_keyword[],
    int primer_indices[], int primer_len);
void autokey_decrypt(ColossusConfig *cfg, int decrypted[], int cipher_indices[],
    int cipher_len, int plaintext_keyword[], int ciphertext_keyword[],
    int key_indices[], int key_len);

// Transposition
void transperoffset(int plaintext[], int len, int d, int n);
void matrix_rotate(int text[], int len, int width, int clockwise);
void transmatrix(int text[], int len, int w1, int w2, int clockwise);

// Columnar transposition primitive (one stage). Inverts a columnar encryption:
// the ciphertext is `K` columns concatenated in read order `order[0..K-1]`, each
// column read top-to-bottom (dir == COL_READ_TB) or bottom-to-top (COL_READ_BT).
// Incomplete grids (len % K != 0) are handled via per-column heights. Writes the
// recovered row-major plaintext to out[0..len-1] (out must differ from cipher).
void decrypt_columnar(int cipher[], int len, int K, int order[], int dir, int out[]);

// Number of geometric routes recognised by route_cells()/decrypt_route().
#define N_ROUTES 6

// Rail fence (and variant rail fence) primitive: invert a zigzag over `rails`
// rows with starting phase `offset` in [0, 2*(rails-1)). `variant` swaps the read
// and write directions (the -variant convention). out[] must not alias cipher[].
void decrypt_railfence(int cipher[], int len, int rails, int offset, int variant, int out[]);

// Route transposition primitives. route_cells() fills cells[] with the row-major
// cell indices in reading order for route_id in [0, N_ROUTES), emitting only cells
// that exist (row-major index < len, so a ragged final row is handled), and returns
// the number of cells emitted. decrypt_route() inverts one route over an R x C grid
// (complete or ragged: (R-1)*C < len <= R*C); `variant` swaps read/write directions.
int route_cells(int R, int C, int len, int route_id, int cells[]);
void decrypt_route(int cipher[], int len, int R, int C, int route_id, int variant, int out[]);

// Amsco primitive: invert an alternating 1/2-letter columnar transposition over K
// columns read in `order`, with `start` (1 or 2) the size of the first cell.
// `variant` swaps read/write. out[] must not alias cipher[].
void decrypt_amsco(int cipher[], int len, int K, int order[], int start, int variant, int out[]);

// Myszkowski primitive: invert a columnar transposition over K columns whose
// keyword ranks `rank[0..K-1]` may tie; tied columns are read row-by-row together.
// `variant` swaps read/write. out[] must not alias cipher[].
void decrypt_myszkowski(int cipher[], int len, int K, int rank[], int variant, int out[]);

// Redefence primitive: rail fence over `rails` rows (phase `offset`) whose rails
// are read in keyed order `order[0..rails-1]`. `variant` swaps read/write.
void decrypt_redefence(int cipher[], int len, int rails, int offset, int order[], int variant, int out[]);

// Cadenus primitive: K = len/rows columns rotated vertically by rot[c] and reordered
// by order[p] (read col p -> original col order[p]), grid read row-major.
void decrypt_cadenus(int cipher[], int len, int K, int order[], int rot[], int variant, int out[]);

// Nihilist transposition primitive: independent rowperm/colperm on the N x N grid
// (N = sqrt(len)), read row-major (readmode 0) or column-major (readmode 1).
// `variant` swaps read/write.
void decrypt_nihilist(int cipher[], int len, int N, int rowperm[], int colperm[],
                      int readmode, int variant, int out[]);

// Swagman primitive: N x N key square (column j a permutation of 0..N-1) applied
// column-wise over an N x (len/N) grid; readmode selects row/column-major read-off.
void decrypt_swagman(int cipher[], int len, int N, int square[], int readmode, int variant, int out[]);

// Turning-grille primitive: key[orbit] in {0..3} chooses the turn that exposes each
// rotation orbit of the N x N grid (N = sqrt(len)). Writes the orbit count to
// *n_orbits (the climbed key length) when non-NULL. `variant` swaps read/write.
void decrypt_grille(int cipher[], int len, int N, int key[], int variant, int out[], int *n_orbits);

// Transposition solvers (optimization over the transform parameters)
void solve_transposition(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

// General transposition solver (AZDecrypt-style permutation-key hill climber)
void solve_general_transposition(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

// Dedicated columnar solver (single TRANSCOL and double TRANSCOL2). Optimizes the
// small per-stage column-order permutation directly, rather than the full
// N-length permutation key.
void solve_columnar(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

// Enumerate-and-score solvers for the small-key-space transposition types. Both
// exhaustively try every parameter setting (no hill climbing needed), score each
// with the shared n-gram (+ optional crib) state_score, and report the best:
//   solve_railfence : rails in [min_cols, max_cols] x starting phase offset
//   solve_route     : every R x C factorization of len x N_ROUTES routes
void solve_railfence(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_route(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

// Hill-climbing solvers for the small-permutation transposition types. Both sweep
// the column count K = [min_cols, max_cols] and, per K, anneal a short key via the
// cipher-agnostic engine (run_solver, SHAPE_ANNEAL):
//   solve_amsco      : climbs the column order x start-chunk in {1,2}
//   solve_myszkowski : climbs the per-column rank vector (ties allowed)
void solve_amsco(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_myszkowski(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

// Remaining transposition solvers (all anneal a short key via run_solver):
//   solve_redefence : sweeps rails x phase, climbs the rail read-order permutation
//   solve_cadenus   : K = len/25, climbs the packed column order + per-column rotation
//   solve_nihilist  : N = sqrt(len), climbs the single row+column permutation
//   solve_swagman   : sweeps N (3..7) x readmode, climbs the N x N key square
//   solve_grille    : N = sqrt(len), climbs the per-orbit turn assignment
void solve_redefence(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_cadenus(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_nihilist(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_swagman(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_grille(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_indep_periodic(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);

void solve_homophonic(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SymbolTable *tab);

// hist_by_col, when non-NULL, is a caller-supplied per-column ciphertext
// histogram laid out as hist_by_col[col*ALPHABET_SIZE + c] (counts of cipher
// char c in column col for this cycleword_len). It depends only on the (fixed)
// ciphertext and cycleword_len, so the caller computes it once per
// shotgun_hill_climber call instead of every derive. Pass NULL to have the
// routine build it locally (standalone/test use).
void derive_optimal_cycleword(
    ColossusConfig *cfg,
    int cipher_indices[], int cipher_len,
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[],
    int cycleword_state[], int cycleword_len, int *hist_by_col);

// Helpers
int map_crib_to_cipher_pos(ColossusConfig *cfg, int crib_pos, int cipher_len);
int get_matrix_rotate_old_idx(int target_idx, int len, int width, int clockwise);

bool cribs_satisfied_p(ColossusConfig *cfg, int cipher_indices[], int cipher_len, int crib_indices[], 
    int crib_positions[], int n_cribs, int cycleword_len, bool verbose);

bool constrain_cycleword(ColossusConfig *cfg, int cipher_indices[], int cipher_len, 
    int crib_indices[], int crib_positions[], int n_cribs, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int cycleword_indices[], int cycleword_len,
    bool variant, bool verbose);

void decrypt_state(ColossusConfig *cfg, int cipher_indices[], int cipher_len, 
                   int plaintext_keyword_state[], int ciphertext_keyword_state[], 
                   int cycleword_state[], int cycleword_len, 
                   int decrypted[]);

double state_score(int decrypted[], int cipher_len, 
            int crib_indices[], int crib_positions[], int n_cribs, 
            float *ngram_data, int ngram_size, 
            float weight_ngram, float weight_crib, 
            float weight_ioc, float weight_entropy);

void straight_alphabet(int keyword[], int len);
void make_keyed_alphabet(char *keyword_str, int *output_indices); // NEW
double ngram_score(int decrypted[], int cipher_len, float *ngram_data, int ngram_size);
double crib_score(int text[], int len, int crib_indices[], int crib_positions[], int n_cribs);
double entropy(int text[], int len);
double chi_squared(int plaintext[], int len);

// I/O & Data
void load_dictionary(char *filename, char ***dict, int *n_dict_words, int *max_dict_word_len, bool verbose);
void free_dictionary(char **dict, int n_dict_words);
int find_dictionary_words(char *plaintext, char **dict, int n_dict_words, int max_dict_word_len);

float* load_ngrams(char *ngram_file, int ngram_size, bool verbose);
int ngram_index_int(int *ngram, int ngram_size);
int ngram_index_str(char *ngram, int ngram_size);

// Randomization
void perturbate_keyword(int state[], int len, int keyword_len);
void random_keyword(int keyword[], int len, int keyword_len);
void random_cycleword(int cycleword[], int max, int keyword_len);
void perturbate_cycleword(int state[], int max, int len);
int rand_int_frequency_weighted(int state[], int min_index, int max_index);
void shuffle(int *array, size_t n);

// Stats
double mean_ioc(int text[], int len, int len_cycleword, int *caesar_column);
void estimate_cycleword_lengths(int text[], int len, int max_cycleword_len, 
	double n_sigma_threshold, double ioc_threshold, 
	int *n_cycleword_lengths, int cycleword_lengths[], bool verbose);
double vec_mean(double vec[], int len);
double vec_stddev(double vec[], int len);

// Utils
static inline uint32_t fast_rand(void);
static inline void seed_fast_rand(uint32_t seed);
static inline uint32_t fast_rand_bounded(uint32_t range);
int gcd(int a, int b);
int str_eq(const char *a, const char *b);
int parse_cipher_type(const char *arg);
int unique_len(char *str);
void vec_print(int vec[], int len);
void print_text(int indices[], int len);
void ord(char *text, int indices[]);

// Decode a raw ciphertext string into integer indices, returning the index count.
// LETTER mode (cfg->cipher_type != HOMOPHONIC and no -delimiter): byte-for-byte ord()
// -- one index per character, A..Z -> 0..g_alpha-1, everything else a negative
// sentinel; tab is left untouched (may be NULL). SYMBOL mode (HOMOPHONIC, or any type
// with -delimiter): split into tokens and intern them into tab, writing symbol ids.
int decode_cipher(const char *text, const ColossusConfig *cfg, int indices[], SymbolTable *tab);

// Echo a decoded ciphertext. tab == NULL reproduces print_text() exactly (letter
// mode); otherwise the symbol tokens are printed joined by tab->delimiter.
void print_cipher(const int indices[], int len, const SymbolTable *tab);

// Non-alphabetic bytes (spaces, punctuation) in a ciphertext are carried through
// the integer-index arrays as negative values that reversibly encode the original
// byte: index = -(unsigned char)c - 1, so 'A'..'Z' stay 0..25 and everything else
// is < 0. Scoring and frequency stats skip these positions; printing restores the
// original character. This lets pure-transposition solves permute the spaces along
// with the letters and reveal word boundaries in the recovered plaintext.
// Runtime alphabet. Defaults to the full 26-letter A..Z (g_alpha == 26,
// g_idx_to_char_arr == "ABC..Z", g_char_to_idx the identity) so the historical
// behaviour is bit-identical. -excludeletter / -alphabet shrink it (e.g. the
// 25-letter A..Z-minus-P, mod 25) for ciphers built on a reduced alphabet.
// Array sizes everywhere stay ALPHABET_SIZE (26, the max); only loop bounds,
// modular arithmetic, and the n-gram packing base use g_alpha.
extern bool g_ngram_logprob;      // n-gram scoring mode (see utils.c); false = legacy
extern int  g_alpha;              // runtime alphabet size (<= ALPHABET_SIZE)
extern int  g_char_to_idx[128];   // ASCII (upper) -> alphabet index, or -1 if absent
extern char g_idx_to_char_arr[ALPHABET_SIZE + 1];  // alphabet index -> char
extern double g_monograms[ALPHABET_SIZE];          // English monogram freqs, reindexed to runtime alphabet
void init_alphabet(const char *excluded);          // (re)build the maps; NULL => full A..Z

static inline int index_to_char(int idx) {
    return (idx >= 0) ? (unsigned char) g_idx_to_char_arr[idx] : (-(idx + 1));
}

float index_of_coincidence(int plaintext[], int len);
void tally(int plaintext[], int len, int frequencies[], int n_frequencies);
bool file_exists(const char * filename);
void vec_copy(int src[], int dest[], int len);
int int_pow(int base, int exp);

extern uint32_t rng_state;

// Fast inline Xorshift32 generator
static inline uint32_t fast_rand(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rng_state = x;
}

// Function to seed the PRNG
static inline void seed_rand(uint32_t seed) {
    if (seed == 0) seed = 1; // State cannot be 0
    rng_state = seed;
}

// Lemire's method to map the 32-bit random integer to a specific range [0, range)
static inline uint32_t rand_bounded(uint32_t range) {
    return (uint32_t)(((uint64_t)fast_rand() * range) >> 32);
}

static inline int rand_int(int min, int max) {
    if (min >= max) return min; 
    uint32_t range = (uint32_t)(max - min);
    return min + (int)rand_bounded(range);
}

static inline double frand(void) {
    // Divided by 2^32 to ensure the result is strictly < 1.0
    return (double)fast_rand() / 4294967296.0; 
}

#endif
