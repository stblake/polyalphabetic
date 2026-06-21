//
//  Colossus - a classical cipher solver
//

// A stochastic, slippery shotgun-restarted hill climber with backtracking for solving
// Vigenere, Beaufort, Porta, Quagmire I - IV, and Autokey ciphers with variants.

// One cipher-agnostic search engine -- run_solver() / run_one_config() -- drives EVERY
// cipher type. Each type supplies a CipherModel (colossus.h): a vtable of
// seed / perturb / decrypt / enumerate / report hooks plus a SearchShape (SHOTGUN slip,
// ANNEAL Metropolis, or DETERMINISTIC first-improvement). The engine owns the restart /
// hill-climb / accept / backtrack / best-tracking loop and the single state_score call;
// the model owns the cipher math. The polyalphabetic family (Vigenere/Quagmire/Beaufort/
// Porta/Autokey) is one model whose seed/perturb keep the explicit per-type
// switch(cipher_type) ladders. The transposition families are their own models:
//   - transmatrix / transperoffset : climb the transform's small parameter vector.
//   - transposition                : AZDecrypt-style full-permutation-key climb with a
//                                    periodic-redundancy structure term (key_structure_score,
//                                    weight -weightstructure) folded into the decrypt score.
//   - transcol / transcol2         : climb the per-stage column-order permutation(s).
//   - railfence / route            : exhaustive parameter sweeps (key_len 0 => no climb).
//   - amsco / myszkowski / redefence / cadenus / nihilist / swagman / grille : anneal a
//                                    short integer key, with a shared TransKeyOps seed/move.
// (indep_periodic keeps its own coordinate-ascent iterated-local-search climber, a search
// shape that does not fit the shotgun/anneal engine.)
//
// The -type values above are distinct from the -transmatrix / -transperoffset post-decrypt
// STAGE flags, which apply a fixed, user-supplied transposition after a polyalphabetic solve.

// Written by Sam Blake, started 14 July 2023.

/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.
*/

// Reference for n-gram data: http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/

/* Usage
    -----
    $ ./colossus [options]

    Parameters
    ----------
    Input/Output:
        -cipher <file> : str
            Path to the ciphertext file. The cipher should be on the first line.
        -batch <file> : str
            Path to a file containing multiple ciphers (one per line) for batch processing.
        -crib <file> : str
            Path to the crib file. Use "_" for unknown characters. Must match cipher length.
        -dictionary <file> : str, optional
            Path to a dictionary file (one word per line). Defaults to "OxfordEnglishWords.txt".
        -verbose : flag
            Enable detailed output during execution.
        -seed <int> : int, optional
            Fix the PRNG seed for reproducible runs. Defaults to the current
            Unix time. Used by the regression tests to make stochastic solves
            deterministic.

    Cipher Configuration:
        -type <int> : int
            The cipher algorithm to solve:
            vigenere, vig, 0  : Vigenere
            quagmire1, quag1, q1, 1  : Quagmire I
            quagmire2, quag2, q2, 2  : Quagmire II
            quagmire3, quag3, q3, 3  : Quagmire III
            quagmire4, quag4, q4, 4  : Quagmire IV
            beaufort, beau, 5        : Beaufort
            porta, 6                 : Porta
            auto, autokey, 7         : Autokey (Vigenere tableau)
            auto1, autokey1, 8       : Autokey (Quagmire I tableau)
            auto2, autokey2, 9       : Autokey (Quagmire II tableau)
            auto3, autokey3, 10      : Autokey (Quagmire III tableau)
            auto4, autokey4, 11      : Autokey (Quagmire IV tableau)
            auto5, autobeau          : Autokey (Beaufort tableau)
            auto6, autoporta         : Autokey (Porta tableau)
            transmatrix, tmatrix, 14 : Transposition - double grid rotation (K3-style),
                                       solved by optimizing (w1, w2, direction).
            transperoffset, tpo, 15  : Transposition - periodic decimation + rotation,
                                       solved by optimizing (period d, offset n).
            transposition, trans, 16 : General transposition (columnar / route) - hill
                                       climbs the full permutation key (AZDecrypt-style),
                                       guarded by a periodic-structure score
                                       (-weightstructure). Restarts seeded from columnar
                                       layouts; column-swap move reorders whole columns.
            transcol, 17             : Dedicated single columnar - hill climbs only the
                                       column-order permutation (length K) via
                                       decrypt_columnar(), sweeping K over
                                       -mincols..-maxcols. Read direction via -readdir.
            transcol2, 18            : Dedicated double columnar - randomises the two
                                       column counts (K1, K2) per restart and anneals
                                       both column-order permutations together.
        -transperiodoffset <int> <int> : int, int
            Applies a periodic decimation and rotation to the decrypted text.
            The first integer specifies the offset (rotation), and the second 
            integer specifies the period (decimation step). 
            Aliases: -transperoffset, -transperoff
        -transmatrix <int> <int> <str> : int, int, str
            Applies a double matrix transposition (like Kryptos K3).
            The first integer is the initial grid width (w1), the second is 
            the subsequent grid width (w2). The string specifies the rotation 
            direction: 'cw' (clockwise) or 'ccw' (anti-clockwise).
        -variant : flag
            Enable the Quagmire variant (which swaps decryption for encryption.)
        -samekey : flag
            Forces the cycleword (indicator word) to be the same as the plaintext / ciphertext 
            keyword.

    Optimization Strategy:
        -optimalcycle : flag (default true)
            Enables hybrid deterministic solving. The cycleword is mathematically derived 
            (using Chi-squared/Dot-product) for every keyword candidate, rather than being 
            perturbed stochastically. Highly recommended for ciphers without cribs.
        -stochasticcycle : flag (default false)
            Enables stochastic solving for cycleword (indicator word.) The cycle is not 
            derived using the Chi-squared/Dot-product algorithm, rather it is perturbed 
            stochastically. 
        -nhillclimbs <int> : int
            Number of iterations per restart in the hill climber.
        -nrestarts <int> : int
            Number of times to restart the hill climber from a random state.

    Constraints (Lengths & Fixed Keywords):
        -plaintextkeyword <str> : str
            Fixes the plaintext keyword to a specific string.
        -ciphertextkeyword <str> : str
            Fixes the ciphertext keyword to a specific string.
        -cyclewordlen <int> : int
            Fixes the cycleword (period) length.
        -maxcyclewordlen <int> : int
            Maximum allowable length for the cycleword (if not fixed).
        -plaintextkeywordlen <int> : int
            Fixed length for the plaintext keyword.
        -ciphertextkeywordlen <int> : int
            Fixed length for the ciphertext keyword.
        -maxkeywordlen <int> : int
            Sets both plaintext and ciphertext max keyword lengths.
        -keywordlen <int> : int
            Sets both plaintext and ciphertext fixed lengths.

    Statistics & Resources:
        -ngramfile <file> : str
            Path to the n-gram statistics file.
        -ngramsize <int> : int
            The size of the n-grams (e.g., 3 for trigrams, 4 for quadgrams).

    Tuning Probabilities & Thresholds:
        -backtrackprob <float> : float
            Probability (0.0 - 1.0) of backtracking to the best known solution 
            instead of a random state during a restart.
        -keywordpermprob <float> : float
            Probability (0.0 - 1.0) of permuting the keyword vs the cycleword 
            (Ignored if -optimalcycle is enabled).
        -slipprob <float> : float
            Probability (0.0 - 1.0) of accepting a worse score to escape local maxima.
        -nsigmathreshold <float> : float
            Sigma threshold for cycleword length estimation via IoC.
        -iocthreshold <float> : float
            Minimum IoC required to consider a cycleword length valid.

    Scoring Weights:
        -weightngram <float> : float
            Weight of the n-gram score component.
        -weightcrib <float> : float
            Weight of the crib match component.
        -weightioc <float> : float
            Weight of the Index of Coincidence component.
        -weightentropy <float> : float
            Weight of the entropy component.
        -weightstructure <float> : float
            (General transposition only.) Weight of the columnar-structure reward
            that biases the permutation key toward regular (periodic) layouts.

    Columnar transposition (transcol / transcol2):
        -mincols <int> / -maxcols <int> : int
            Column-count search range (default 2..30, clamped to len/2). Set
            -mincols == -maxcols to target a single, known column count.
        -readdir <tb|bt|both> :
            Column read direction: top-to-bottom (default), bottom-to-top, or
            search both. Variants are only tried when explicitly requested.

    Notes
    -----
    Cipher Types:
        Ciphers are as defined by the American Cryptogram Association. 
        https://www.cryptogram.org/resource-area/cipher-types/


*/

#include "colossus.h"

void init_config(ColossusConfig *cfg) {
    // Set Defaults
    cfg->cipher_type = -1;
    cfg->ngram_size = 0;
    cfg->n_hill_climbs = 1000;
    cfg->n_restarts = 1;

    cfg->ciphertext_keyword_len = 5;
    cfg->plaintext_keyword_len = 5;
    cfg->ciphertext_max_keyword_len = 12;
    cfg->min_keyword_len = 5;
    cfg->plaintext_max_keyword_len = 12;
    cfg->max_cycleword_len = 20;
    cfg->cycleword_len = 0; // 0 implies not set by user

    cfg->plaintext_keyword_len_present = false;
    cfg->ciphertext_keyword_len_present = false;
    cfg->cycleword_len_present = false;
    cfg->user_plaintext_keyword_present = false;
    cfg->user_ciphertext_keyword_present = false;

    cfg->cipher_present = false;
    cfg->batch_present = false;
    cfg->crib_present = false;
    cfg->dictionary_present = false;
    cfg->verbose = false;
    cfg->skip_spaces = false;
    cfg->multiline = false;
    cfg->variant = false;
    cfg->beaufort = false;

    cfg->n_sigma_threshold = 1.0;
    cfg->ioc_threshold = 0.047;
    cfg->backtracking_probability = 0.15;
    cfg->keyword_permutation_probability = 0.95;
    cfg->slip_probability = 0.001;

    cfg->weight_ngram = 12.0;
    cfg->weight_crib = 36.0;
    cfg->weight_ioc = 0.0;
    cfg->weight_entropy = 0.0;
    cfg->weight_structure = 4.0;
    cfg->weight_monogram = 1.0;   // homophonic anti-collapse penalty (chi-squared vs English)

    cfg->optimal_cycleword = true;
    cfg->same_key_cycle = false;

    cfg->method = METHOD_DEFAULT;
    cfg->init_temp = 0.10;     // matches the previously hardcoded annealing schedule
    cfg->min_temp = 0.001;
    cfg->cooling_rate = 0.0;   // 0 => derive the geometric schedule over n_hill_climbs

    cfg->transperoffset_present = false;
    cfg->trans_offset = 0;
    cfg->trans_period = 1;

    cfg->transmatrix_present = false;
    cfg->trans_w1 = 0;
    cfg->trans_w2 = 0;
    cfg->trans_clockwise = 1; // Default to clockwise

    cfg->min_cols = 2;
    cfg->max_cols = 30;
    cfg->read_direction = COL_READ_TB; // canonical only; bottom-to-top is opt-in

    cfg->delimiter = 0;                 // 0 => per-character / 0..25 letter decode (ord())
    cfg->delimiter_present = false;
}



// Guarded so the regression tests can link the whole solver (solve_cipher and
// its dependencies live in this file) while supplying their own main:
// compile this translation unit with -DCOLOSSUS_NO_MAIN.
#ifndef COLOSSUS_NO_MAIN
int main(int argc, char **argv) {
    ColossusConfig cfg;
    SharedData shared;
    int i;
    char single_ciphertext_buffer[MAX_CIPHER_LENGTH];
    char cribtext[MAX_CIPHER_LENGTH];

    printf("\n\nCOLOSSUS Cipher Solver\n\n");
    printf("Written by Sam Blake, started 14 July 2023.\n\n");

    // Seed the PRNG with the current Unix time (seconds since Epoch).
    // A -seed <uint> argument (parsed below) overrides this for reproducible runs.
    uint32_t rng_seed = (uint32_t)time(NULL);
    seed_rand(rng_seed);

    init_config(&cfg);

    // Default to the full 26-letter A..Z alphabet; -excludeletter (parsed below)
    // shrinks it (must happen before load_ngrams and any ord() call).
    init_alphabet(NULL);

    // Initialize shared data pointers.
    shared.ngram_data = NULL;
    shared.dict = NULL;
    shared.n_dict_words = 0;
    shared.max_dict_word_len = 0;

    // --- Argument Parsing ---
    for(i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-type") == 0) {
            char *type_arg = argv[++i];            
            cfg.cipher_type = parse_cipher_type(type_arg); 
            printf("-type %s\n", type_arg);      
        } else if (strcmp(argv[i], "-cipher") == 0) {
            cfg.cipher_present = true;
            strcpy(cfg.ciphertext_file, argv[++i]);
            printf("-cipher %s\n", cfg.ciphertext_file);
        } else if (strcmp(argv[i], "-batch") == 0) {
            cfg.batch_present = true;
            strcpy(cfg.batch_file, argv[++i]);
            printf("-batch %s\n", cfg.batch_file);
        } else if (strcmp(argv[i], "-crib") == 0 || strcmp(argv[i], "-cribs") == 0) {
            cfg.crib_present = true;
            strcpy(cfg.crib_file, argv[++i]);
            printf("-crib %s\n", cfg.crib_file);
        } else if (strcmp(argv[i], "-ngramsize") == 0) {
            cfg.ngram_size = atoi(argv[++i]);
            printf("-ngramsize %d\n", cfg.ngram_size);
        } else if (strcmp(argv[i], "-ngramfile") == 0) {
            strcpy(cfg.ngram_file, argv[++i]);
            printf("-ngramfile %s\n", cfg.ngram_file);
        } else if (strcmp(argv[i], "-excludeletter") == 0) {
            // Drop one (or more) letters from the alphabet, shrinking it to an
            // N<26 letter alphabet with mod-N arithmetic. E.g. -excludeletter P
            // gives the 25-letter A..Z-minus-P alphabet (mod 25). Must be set
            // before the ngram table is loaded and before any ciphertext is read.
            init_alphabet(argv[++i]);
            printf("-excludeletter %s  (alphabet size now %d: %s)\n",
                argv[i], g_alpha, g_idx_to_char_arr);
        } else if (strcmp(argv[i], "-maxkeywordlen") == 0) {
            cfg.plaintext_keyword_len = atoi(argv[++i]);
            cfg.ciphertext_keyword_len = cfg.plaintext_keyword_len;
            printf("-maxkeywordlen %d\n", cfg.plaintext_keyword_len);
        } else if (strcmp(argv[i], "-keywordlen") == 0) {
            cfg.plaintext_keyword_len_present = true;
            cfg.ciphertext_keyword_len_present = true;
            cfg.plaintext_keyword_len = atoi(argv[++i]);
            cfg.ciphertext_keyword_len = cfg.plaintext_keyword_len;
            cfg.plaintext_max_keyword_len = max(cfg.plaintext_max_keyword_len, 1 + cfg.plaintext_keyword_len);
            cfg.ciphertext_max_keyword_len = max(cfg.ciphertext_max_keyword_len, 1 + cfg.ciphertext_keyword_len);
            cfg.min_keyword_len = cfg.plaintext_keyword_len;
            printf("-keywordlen %d\n", cfg.plaintext_keyword_len);
        } else if (strcmp(argv[i], "-plaintextkeywordlen") == 0) {
            cfg.plaintext_keyword_len_present = true;
            cfg.plaintext_keyword_len = atoi(argv[++i]);
            cfg.plaintext_max_keyword_len = max(cfg.plaintext_max_keyword_len, 1 + cfg.plaintext_keyword_len);
            cfg.min_keyword_len = cfg.plaintext_keyword_len;
            printf("-plaintextkeywordlen %d\n", cfg.plaintext_keyword_len);
        } else if (strcmp(argv[i], "-ciphertextkeywordlen") == 0) {
            cfg.ciphertext_keyword_len_present = true;
            cfg.ciphertext_keyword_len = atoi(argv[++i]);
            cfg.ciphertext_max_keyword_len = max(cfg.ciphertext_max_keyword_len, 1 + cfg.ciphertext_keyword_len);
            cfg.min_keyword_len = cfg.ciphertext_keyword_len;
            printf("-ciphertextkeywordlen %d\n", cfg.ciphertext_keyword_len);
        } else if (strcmp(argv[i], "-plaintextkeyword") == 0) {
            // Explicit Plaintext Keyword
            cfg.user_plaintext_keyword_present = true;
            strcpy(cfg.user_plaintext_keyword, argv[++i]);
            int len = unique_len(cfg.user_plaintext_keyword);
            cfg.plaintext_keyword_len = len;
            cfg.plaintext_max_keyword_len = len + 1;
            cfg.plaintext_keyword_len_present = true;
            printf("-plaintextkeyword %s\n", cfg.user_plaintext_keyword);
        } else if (strcmp(argv[i], "-ciphertextkeyword") == 0) {
            // Explicit Ciphertext Keyword
            cfg.user_ciphertext_keyword_present = true;
            strcpy(cfg.user_ciphertext_keyword, argv[++i]);
            int len = unique_len(cfg.user_ciphertext_keyword);
            cfg.ciphertext_keyword_len = len;
            cfg.ciphertext_max_keyword_len = len + 1;
            cfg.ciphertext_keyword_len_present = true;
            printf("-ciphertextkeyword %s\n", cfg.user_ciphertext_keyword);
        } else if (strcmp(argv[i], "-maxcyclewordlen") == 0) {
            cfg.max_cycleword_len = atoi(argv[++i]);
            printf("-maxcyclewordlen %d\n", cfg.max_cycleword_len);
        } else if (strcmp(argv[i], "-cyclewordlen") == 0) {
            cfg.cycleword_len_present = true;
            cfg.cycleword_len = atoi(argv[++i]);
            cfg.max_cycleword_len = max(cfg.max_cycleword_len, 1 + cfg.cycleword_len);
            printf("-cyclewordlen %d\n", cfg.cycleword_len);
        } else if (strcmp(argv[i], "-nsigmathreshold") == 0) {
            cfg.n_sigma_threshold = atof(argv[++i]);
            printf("-nsigmathreshold %.4f\n", cfg.n_sigma_threshold);
        } else if (strcmp(argv[i], "-nhillclimbs") == 0) {
            cfg.n_hill_climbs = atoi(argv[++i]);
            printf("-nhillclimbs %d\n", cfg.n_hill_climbs);
        } else if (strcmp(argv[i], "-nrestarts") == 0) {
            cfg.n_restarts = atoi(argv[++i]);
            printf("-nrestarts %d\n", cfg.n_restarts);
        } else if (strcmp(argv[i], "-backtrackprob") == 0) {
            cfg.backtracking_probability = atof(argv[++i]);
            printf("-backtrackprob %.6f\n", cfg.backtracking_probability);
        } else if (strcmp(argv[i], "-keywordpermprob") == 0) {
            cfg.keyword_permutation_probability = atof(argv[++i]);
            printf("-keywordpermprob %.4f\n", cfg.keyword_permutation_probability);
        } else if (strcmp(argv[i], "-slipprob") == 0) {
            cfg.slip_probability = atof(argv[++i]);
            printf("-slipprob %.6f\n", cfg.slip_probability);
        } else if (strcmp(argv[i], "-method") == 0) {
            // Cipher-agnostic optimization strategy override.
            char *m = argv[++i];
            if (strcasecmp(m, "shotgun") == 0) {
                cfg.method = METHOD_SHOTGUN;
            } else if (strcasecmp(m, "sa") == 0 || strcasecmp(m, "anneal") == 0 ||
                       strcasecmp(m, "simanneal") == 0 || strcasecmp(m, "simulatedannealing") == 0) {
                cfg.method = METHOD_ANNEAL;
            } else {
                printf("Unknown -method '%s' (expected shotgun | sa | anneal | simanneal | simulatedannealing).\n", m);
                return 1;
            }
            printf("-method %s\n", cfg.method == METHOD_SHOTGUN ? "shotgun" : "simulated-annealing");
        } else if (strcmp(argv[i], "-inittemp") == 0 || strcmp(argv[i], "-initialtemp") == 0 ||
                   strcmp(argv[i], "-inittemperature") == 0 || strcmp(argv[i], "-initialtemperature") == 0) {
            cfg.init_temp = atof(argv[++i]);
            printf("-inittemp %.6f\n", cfg.init_temp);
        } else if (strcmp(argv[i], "-mintemp") == 0 || strcmp(argv[i], "-mintemperature") == 0) {
            cfg.min_temp = atof(argv[++i]);
            printf("-mintemp %.6f\n", cfg.min_temp);
        } else if (strcmp(argv[i], "-coolingrate") == 0 || strcmp(argv[i], "-cooling") == 0) {
            cfg.cooling_rate = atof(argv[++i]);
            printf("-coolingrate %.6f\n", cfg.cooling_rate);
        } else if (strcmp(argv[i], "-iocthreshold") == 0) {
            cfg.ioc_threshold = atof(argv[++i]);
            printf("-iocthreshold %.4f\n", cfg.ioc_threshold);
        } else if (strcmp(argv[i], "-dictionary") == 0 || strcmp(argv[i], "-dict") == 0) {
            cfg.dictionary_present = true;
            strcpy(cfg.dictionary_file, argv[++i]);
            printf("-dictionary %s\n", cfg.dictionary_file);
        } else if (strcmp(argv[i], "-weightngram") == 0) { 
            cfg.weight_ngram = atof(argv[++i]);
            printf("-weightngram %.4f\n", cfg.weight_ngram);
        } else if (strcmp(argv[i], "-weightcrib") == 0) { 
            cfg.weight_crib = atof(argv[++i]);
            printf("-weightcrib %.4f\n", cfg.weight_crib);
        } else if (strcmp(argv[i], "-weightioc") == 0) { 
            cfg.weight_ioc = atof(argv[++i]);
            printf("-weightioc %.4f\n", cfg.weight_ioc);
        } else if (strcmp(argv[i], "-weightentropy") == 0) {
            cfg.weight_entropy = atof(argv[++i]);
            printf("-weightentropy %.4f\n", cfg.weight_entropy);
        } else if (strcmp(argv[i], "-weightstructure") == 0) {
            cfg.weight_structure = atof(argv[++i]);
            printf("-weightstructure %.4f\n", cfg.weight_structure);
        } else if (strcmp(argv[i], "-variant") == 0) { 
            cfg.variant = true;
            printf("-variant\n");
        } else if (strcmp(argv[i], "-seed") == 0) {
            // Fix the PRNG seed for reproducible runs (regression tests, debugging).
            rng_seed = (uint32_t)strtoul(argv[++i], NULL, 10);
            seed_rand(rng_seed);
            printf("-seed %u\n", rng_seed);
        } else if (strcmp(argv[i], "-verbose") == 0) {
            cfg.verbose = true;
            printf("-verbose\n");
        } else if (strcmp(argv[i], "-skipspaces") == 0) {
            cfg.skip_spaces = true;
            printf("-skipspaces\n");
        } else if (strcmp(argv[i], "-multiline") == 0) {
            cfg.multiline = true;
            printf("-multiline\n");
        } else if (strcmp(argv[i], "-logprob") == 0 || strcmp(argv[i], "-azdecrypt") == 0) {
            g_ngram_logprob = true;
            printf("-logprob (AZDecrypt-style n-gram fitness: log-probabilities with an unseen-n-gram floor)\n");
        } else if (strcmp(argv[i], "-weightmono") == 0) {
            cfg.weight_monogram = atof(argv[++i]);
            printf("-weightmono %.3f\n", cfg.weight_monogram);
        } else if (strcmp(argv[i], "-delimiter") == 0) {
            // Field separator for tokenized input. The literal word "space" / "char"
            // (or an empty arg) selects per-character tokenization; otherwise the
            // first character of the argument is the delimiter (e.g. -delimiter ,).
            const char *d = argv[++i];
            if (str_eq(d, "space") || str_eq(d, "char") || str_eq(d, "none") || d[0] == '\0')
                cfg.delimiter = 0;
            else
                cfg.delimiter = d[0];
            cfg.delimiter_present = true;
            printf("-delimiter '%c' (code %d)\n", cfg.delimiter ? cfg.delimiter : ' ', cfg.delimiter);
        } else if (strcmp(argv[i], "-optimalcycle") == 0) {
            cfg.optimal_cycleword = true;
            printf("-optimalcycle\n");
        } else if (strcmp(argv[i], "-stochasticcycle") == 0) {
            cfg.optimal_cycleword = false;
            printf("-stochasticcycle\n");
        } else if (strcmp(argv[i], "-samekey") == 0) {
            cfg.same_key_cycle = true;
        } else if (strcmp(argv[i], "-transperiodoffset") == 0 || 
                strcmp(argv[i], "-transperoffset") == 0 || 
                strcmp(argv[i], "-transperoff") == 0) {
            cfg.trans_offset = atoi(argv[++i]);
            cfg.trans_period = atoi(argv[++i]);
            cfg.transperoffset_present = true;
            printf("-transperiodoffset %d %d\n", cfg.trans_offset, cfg.trans_period);
        } else if (strcmp(argv[i], "-transmatrix") == 0) {
            cfg.transmatrix_present = true;
            cfg.trans_w1 = atoi(argv[++i]);
            cfg.trans_w2 = atoi(argv[++i]);
            
            char *dir_arg = argv[++i];
            // Flexible parsing for clockwise vs anti-clockwise
            if (strcasecmp(dir_arg, "cw") == 0 || strcasecmp(dir_arg, "clockwise") == 0 || strcmp(dir_arg, "1") == 0) {
                cfg.trans_clockwise = 1;
            } else if (strcasecmp(dir_arg, "ccw") == 0 || strcasecmp(dir_arg, "anticlockwise") == 0 || strcmp(dir_arg, "0") == 0) {
                cfg.trans_clockwise = 0;
            } else {
                printf("\n\nERROR: Invalid direction '%s' for -transmatrix. Use 'cw' or 'ccw'.\n\n", dir_arg);
                return 0;
            }
            printf("-transmatrix %d %d %s\n", cfg.trans_w1, cfg.trans_w2, cfg.trans_clockwise ? "cw" : "ccw");
        } else if (strcmp(argv[i], "-mincols") == 0) {
            cfg.min_cols = atoi(argv[++i]);
            printf("-mincols %d\n", cfg.min_cols);
        } else if (strcmp(argv[i], "-maxcols") == 0) {
            cfg.max_cols = atoi(argv[++i]);
            printf("-maxcols %d\n", cfg.max_cols);
        } else if (strcmp(argv[i], "-readdir") == 0) {
            char *dir_arg = argv[++i];
            // Flexible parsing of the columnar read direction.
            if (strcasecmp(dir_arg, "tb") == 0 || strcasecmp(dir_arg, "topbottom") == 0 || strcmp(dir_arg, "0") == 0) {
                cfg.read_direction = COL_READ_TB;
            } else if (strcasecmp(dir_arg, "bt") == 0 || strcasecmp(dir_arg, "bottomtop") == 0 || strcmp(dir_arg, "1") == 0) {
                cfg.read_direction = COL_READ_BT;
            } else if (strcasecmp(dir_arg, "both") == 0 || strcmp(dir_arg, "2") == 0) {
                cfg.read_direction = COL_READ_BOTH;
            } else {
                printf("\n\nERROR: Invalid direction '%s' for -readdir. Use 'tb', 'bt' or 'both'.\n\n", dir_arg);
                return 0;
            }
            printf("-readdir %s\n", dir_arg);
        } else {
            printf("\n\nERROR: unknown command line arg: \'%s\'\n\n", argv[i]);
            return 0;
        }
    }

    printf("\n\n");

    if (cfg.cipher_type == VIGENERE) {
        printf("\nAttacking a Vigenere cipher.\n\n");
    } else if (cfg.cipher_type == QUAGMIRE_1) {
        printf("\nAttacking a Quagmire I cipher.\n\n");
    } else if (cfg.cipher_type == QUAGMIRE_2) {
        printf("\nAttacking a Quagmire II cipher.\n\n");
    } else if (cfg.cipher_type == QUAGMIRE_3) {
        printf("\nAttacking a Quagmire III cipher.\n\n");
    } else if (cfg.cipher_type == QUAGMIRE_4) {
        printf("\nAttacking a Quagmire IV cipher.\n\n");
    } else if (cfg.cipher_type == BEAUFORT) {
        printf("\nAttacking a Beaufort cipher.\n\n");
    } else if (cfg.cipher_type == PORTA) {
        printf("\nAttacking a Porta cipher.\n\n");
    } else if (cfg.cipher_type == AUTOKEY_0) {
        printf("\nAttacking a Autokey cipher (Vigenere tableau.)\n\n");
    } else if (cfg.cipher_type == AUTOKEY_1) {
        printf("\nAttacking a Autokey cipher (Quagmire I tableau.)\n\n");
    } else if (cfg.cipher_type == AUTOKEY_2) {
        printf("\nAttacking a Autokey cipher (Quagmire II tableau.)\n\n");
    } else if (cfg.cipher_type == AUTOKEY_3) {
        printf("\nAttacking a Autokey cipher (Quagmire III tableau.)\n\n");
    } else if (cfg.cipher_type == AUTOKEY_4) {
        printf("\nAttacking a Autokey cipher (Quagmire IV tableau.)\n\n");
    } else if (cfg.cipher_type == AUTOKEY_BEAU) {
        printf("\nAttacking a Autokey cipher (Beaufort tableau.)\n\n");
    } else if (cfg.cipher_type == AUTOKEY_PORTA) {
        printf("\nAttacking a Autokey cipher (Porta tableau.)\n\n");
    } else if (cfg.cipher_type == TRANSMATRIX) {
        printf("\nAttacking a transmatrix (double grid rotation) transposition cipher.\n\n");
    } else if (cfg.cipher_type == TRANSPEROFFSET) {
        printf("\nAttacking a transperoffset (periodic decimation + rotation) transposition cipher.\n\n");
    } else if (cfg.cipher_type == TRANSPOSITION) {
        printf("\nAttacking a general transposition cipher (permutation-key hill climber).\n\n");
    } else if (cfg.cipher_type == TRANSCOL) {
        printf("\nAttacking a columnar transposition cipher (column-order hill climber).\n\n");
    } else if (cfg.cipher_type == TRANSCOL2) {
        printf("\nAttacking a double columnar transposition cipher (column-order hill climber).\n\n");
    } else if (cfg.cipher_type == RAILFENCE) {
        printf("\nAttacking a rail fence transposition cipher (rail-count + phase enumeration).\n\n");
    } else if (cfg.cipher_type == ROUTE) {
        printf("\nAttacking a route transposition cipher (grid + route enumeration).\n\n");
    } else if (cfg.cipher_type == AMSCO) {
        printf("\nAttacking an Amsco transposition cipher (column-order hill climber).\n\n");
    } else if (cfg.cipher_type == MYSZKOWSKI) {
        printf("\nAttacking a Myszkowski transposition cipher (rank-vector hill climber).\n\n");
    } else if (cfg.cipher_type == REDEFENCE) {
        printf("\nAttacking a redefence (keyed rail fence) cipher (rail-order hill climber).\n\n");
    } else if (cfg.cipher_type == CADENUS) {
        printf("\nAttacking a Cadenus transposition cipher (order + rotation hill climber).\n\n");
    } else if (cfg.cipher_type == NIHILIST) {
        printf("\nAttacking a Nihilist transposition cipher (single-permutation hill climber).\n\n");
    } else if (cfg.cipher_type == SWAGMAN) {
        printf("\nAttacking a Swagman transposition cipher (key-square hill climber).\n\n");
    } else if (cfg.cipher_type == GRILLE) {
        printf("\nAttacking a turning grille transposition cipher (orbit-assignment hill climber).\n\n");
    } else if (cfg.cipher_type == INDEP_PERIODIC) {
        printf("\nAttacking an independent-periodic substitution (P independent mixed alphabets, joint hill climber).\n\n");
    } else if (cfg.cipher_type == HOMOPHONIC) {
        printf("\nAttacking a homophonic substitution (ciphertext alphabet larger than the plaintext alphabet).\n\n");
    } else {
        printf("\n\nERROR: Unknown cipher type %d.\n\n", cfg.cipher_type);
        return 0;
    }


    if (cfg.cipher_type == BEAUFORT) {
        cfg.beaufort = true;
    }

    // --- Validation ---
    if (cfg.cipher_type == -1) {
        printf("\n\nERROR: missing cipher type. Use -type /name or integer code/. \n\n");
        return 0;
    }

    if (!cfg.cipher_present && !cfg.batch_present) {
        printf("\n\nERROR: No cipher input specified. Use -cipher or -batch.\n\n");
        return 0;
    }

    if (cfg.ngram_size == 0) {
        printf("\n\nERROR: -ngramsize missing.\n\n");
        return 0;
    }
    if (!file_exists(cfg.ngram_file)) {
        printf("\nERROR: missing file '%s'\n", cfg.ngram_file);
        return 0;
    }

    // Default Dictionary Check
    char oxford_english_words[] = "OxfordEnglishWords.txt";
    if (!cfg.dictionary_present && file_exists(oxford_english_words)) {
        cfg.dictionary_present = true;
        strcpy(cfg.dictionary_file, oxford_english_words);
        if (cfg.verbose) printf("\nDefault dictionary = %s\n", cfg.dictionary_file);
    }

    // --- Resource Loading ---
    
    shared.ngram_data = load_ngrams(cfg.ngram_file, cfg.ngram_size, cfg.verbose);

    if (cfg.dictionary_present) {
        load_dictionary(cfg.dictionary_file, &shared.dict, &shared.n_dict_words, &shared.max_dict_word_len, cfg.verbose);
    }

    cribtext[0] = '\0';
    if (cfg.crib_present) {
        if (file_exists(cfg.crib_file)) {
            FILE *fp_crib = fopen(cfg.crib_file, "r");
            fscanf(fp_crib, "%s", cribtext);
            fclose(fp_crib);
            if (cfg.verbose) printf("cribtext = \n\'%s\'\n\n", cribtext);
        } else {
            printf("\nERROR: missing file '%s'\n", cfg.crib_file);
            return 0;
        }
    }


    // --- Execution Flow ---

    printf("\nRNG seed = %u (override with -seed)\n", rng_seed);

    if (cfg.batch_present) {
        if (!file_exists(cfg.batch_file)) {
             printf("\nERROR: missing batch file '%s'\n", cfg.batch_file);
             return 0;
        }

        FILE *fp_batch = fopen(cfg.batch_file, "r");
        char line_buffer[MAX_CIPHER_LENGTH];
        
        printf("\n--- Starting Batch Processing ---\n");

        int n_ciphers = 0;
        while (fgets(line_buffer, sizeof(line_buffer), fp_batch)) {
            // Strip newline
            line_buffer[strcspn(line_buffer, "\r\n")] = 0;
            
            // Skip empty lines
            if (strlen(line_buffer) < 5) continue; 

            n_ciphers ++;
            printf("\nProcessing %d: %s\n", n_ciphers, line_buffer);
            solve_cipher(line_buffer, cribtext, &cfg, &shared, NULL);
        }
        fclose(fp_batch);

    } else {
        // Single Cipher Mode
        if (!file_exists(cfg.ciphertext_file)) {
             printf("\nERROR: missing cipher file '%s'\n", cfg.ciphertext_file);
             return 0;
        }

        // Read the cipher file as the ciphertext, preserving any internal spaces and
        // punctuation (unlike fscanf("%s"), which stops at the first whitespace). By
        // default only the first line is read: stopping at the newline keeps the
        // historical behaviour of ignoring trailing lines (e.g. a "plaintext = ..."
        // annotation). With -multiline the whole file is read and newlines are dropped
        // (not turned into cipher positions), so a ciphertext laid out over several
        // lines -- e.g. a homophonic grid -- is concatenated into one symbol stream.
        // These non-alphabetic characters are kept as positions and carried through the
        // decryption; scoring skips them. Use -skipspaces to drop them entirely.
        FILE *fp_cipher = fopen(cfg.ciphertext_file, "r");
        int ci = 0, ch;
        while ((ch = fgetc(fp_cipher)) != EOF && (cfg.multiline || ch != '\n')
               && ci < MAX_CIPHER_LENGTH - 1) {
            if (ch == '\r' || ch == '\n') continue;
            single_ciphertext_buffer[ci++] = (char) ch;
        }
        single_ciphertext_buffer[ci] = '\0';
        // Trim trailing whitespace so a stray space at the end of the line does not
        // become an extra cipher position.
        while (ci > 0 && isspace((unsigned char) single_ciphertext_buffer[ci - 1]))
            single_ciphertext_buffer[--ci] = '\0';
        fclose(fp_cipher);

        if (cfg.verbose) printf("ciphertext = \n\'%s\'\n\n", single_ciphertext_buffer);

        solve_cipher(single_ciphertext_buffer, cribtext, &cfg, &shared, NULL);
    }

    // --- Cleanup ---
    free(shared.ngram_data);
    if (shared.dict != NULL) {
        free_dictionary(shared.dict, shared.n_dict_words);
    }

    return 1;
}
#endif // COLOSSUS_NO_MAIN



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

// Hill-climb one outer config: shotgun restarts + per-iteration neighbour move,
// with SHOTGUN slip / ANNEAL Metropolis acceptance and best-state tracking. Writes
// the config's best state to *out_best and its decryption to out_decrypted, and
// returns the best score.
static double run_one_config(const CipherModel *m, SolverCtx *ctx,
                             const SolverConfig *cfg_c,
                             SolverState *out_best, int *out_decrypted) {

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
static SolverCtx make_solver_ctx(ColossusConfig *cfg, SharedData *shared, char *cribtext,
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


// ====================================================================
//  Polyalphabetic model (Vigenere / Quagmire I-IV / Beaufort / Porta /
//  Autokey*; cipher-agnostic engine)
// ====================================================================
//
// All 14 polyalphabetic types share one model and one uniform state (a pt and ct
// keyed alphabet plus the periodic cycleword). The per-type differences -- which
// alphabet is straight vs keyed, which is perturbed, the optimal-cycleword refine,
// the crib constraint, and -samekey coupling -- stay as the explicit
// switch(cipher_type) ladders moved verbatim from the old shotgun_hill_climber
// into the seed and perturb hooks (per CLAUDE.md: don't genericise the dispatch).

static inline bool poly_is_autokey(int t) {
    return (t >= AUTOKEY_0 && t <= AUTOKEY_4) || t == AUTOKEY_BEAU || t == AUTOKEY_PORTA;
}

// The polyalphabetic model carries a single verbose-only contradiction counter
// through ctx->model_scratch (a long*); solve_cipher owns the storage on its stack.

// Outer configs: cycleword length(s) x (pt_keyword_len j, ct_keyword_len k), with
// the per-type validity pruning and crib gate. Reproduces solve_cipher's old
// period-estimation + keyword-bound + (j,k) loop, printing the same diagnostics.
static int polyalpha_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    ColossusConfig *cfg = ctx->cfg;
    int *cipher_indices = ctx->cipher;
    int cipher_len = ctx->cipher_len;
    int n_cribs = ctx->n_cribs;
    int *crib_indices = ctx->crib_indices, *crib_positions = ctx->crib_positions;

    int n_cycleword_lengths, cycleword_lengths[MAX_CIPHER_LENGTH];

    // --- cycleword / primer length setup ---
    if (cfg->cycleword_len_present) {
        n_cycleword_lengths = 1;
        cycleword_lengths[0] = cfg->cycleword_len;
    } else if ((cfg->cipher_type >= AUTOKEY_0 && cfg->cipher_type <= AUTOKEY_4) ||
        cfg->cipher_type == AUTOKEY_BEAU || cfg->cipher_type == AUTOKEY_PORTA ||
        cfg->transperoffset_present) {
        // Autokey (aperiodic) or polyalphabetic+transposition: IoC fails, brute-force.
        n_cycleword_lengths = 0;
        for (int len = 1; len <= cfg->max_cycleword_len; len++) {
            cycleword_lengths[n_cycleword_lengths++] = len;
        }
    } else {
        estimate_cycleword_lengths(cipher_indices, cipher_len, cfg->max_cycleword_len,
            cfg->n_sigma_threshold, cfg->ioc_threshold,
            &n_cycleword_lengths, cycleword_lengths, cfg->verbose);
        if (n_cycleword_lengths == 0) {
            if (cfg->verbose) printf("No periodicities found above threshold. Not running the hillclimber and exiting.\n");
            return 0;
        }
    }

    // --- keyword length bounds (cipher-type specific; mutates cfg as before) ---
    int min_kw = cfg->min_keyword_len;
    int pt_max = cfg->plaintext_max_keyword_len;
    int ct_max = cfg->ciphertext_max_keyword_len;

    if (cfg->cipher_type == VIGENERE || cfg->cipher_type == BEAUFORT ||
        cfg->cipher_type == PORTA ||
        (cfg->cipher_type >= AUTOKEY_0 && cfg->cipher_type <= AUTOKEY_2) ||
        cfg->cipher_type == QUAGMIRE_1 || cfg->cipher_type == QUAGMIRE_2 ||
        cfg->cipher_type == AUTOKEY_BEAU || cfg->cipher_type == AUTOKEY_PORTA) {
        min_kw = 1;
    }

    if (cfg->cipher_type == VIGENERE || cfg->cipher_type == AUTOKEY_0 ||
        cfg->cipher_type == AUTOKEY_BEAU || cfg->cipher_type == AUTOKEY_PORTA) {
        pt_max = 2; ct_max = 2;
        cfg->plaintext_keyword_len = 0;
        cfg->ciphertext_keyword_len = 0;
    } else if (cfg->cipher_type == BEAUFORT) {
        pt_max = 2;
        cfg->plaintext_keyword_len = 1;
    } else if (cfg->cipher_type == PORTA) {
        pt_max = 2; ct_max = 2;
        cfg->plaintext_keyword_len = 1;
        cfg->ciphertext_keyword_len = 1;
    } else if (cfg->cipher_type == QUAGMIRE_1 || cfg->cipher_type == AUTOKEY_1) {
        ct_max = 2;
        cfg->ciphertext_keyword_len = 1;
    } else if (cfg->cipher_type == QUAGMIRE_2 || cfg->cipher_type == AUTOKEY_2) {
        pt_max = 2;
        cfg->plaintext_keyword_len = 1;
    }

    // --- enumerate (cycleword_len, j, k) with per-type pruning + crib gate ---
    int n = 0;
    for (int i = 0; i < n_cycleword_lengths; i++) {
        if (cfg->verbose) printf("\ncycleword length = %d\n", cycleword_lengths[i]);
        for (int j = min(min_kw, cfg->plaintext_keyword_len); j < pt_max; j++) {
            for (int k = min(min_kw, cfg->ciphertext_keyword_len); k < ct_max; k++) {
                if (cfg->verbose) printf("\npt/ct keyword len = %d, %d\n", j, k);
                if (cfg->plaintext_keyword_len_present && j != cfg->plaintext_keyword_len) continue;
                if (cfg->ciphertext_keyword_len_present && k != cfg->ciphertext_keyword_len) continue;

                if (cfg->cipher_type == QUAGMIRE_3 && j != k) continue;
                if (cfg->cipher_type == BEAUFORT && ! (j == 1 && k == 1)) continue;
                if (cfg->cipher_type == VIGENERE && ! (j == 1 && k == 1)) continue;
                if (cfg->cipher_type == PORTA && ! (j == 1 && k == 1)) continue;
                if (cfg->cipher_type == AUTOKEY_0 && ! (j == 1 && k == 1)) continue;
                if (cfg->cipher_type == AUTOKEY_1 && k != 1) continue;
                if (cfg->cipher_type == AUTOKEY_2 && j != 1) continue;
                if (cfg->cipher_type == AUTOKEY_3 && j != k) continue;
                if (cfg->cipher_type == AUTOKEY_BEAU && ! (j == 1 && k == 1)) continue;
                if (cfg->cipher_type == AUTOKEY_PORTA && ! (j == 1 && k == 1)) continue;

                if (cfg->cipher_type != AUTOKEY_0 && cfg->cipher_type != AUTOKEY_1 &&
                    cfg->cipher_type != AUTOKEY_2 && cfg->cipher_type != AUTOKEY_3 &&
                    cfg->cipher_type != AUTOKEY_4 && cfg->cipher_type != AUTOKEY_BEAU &&
                    cfg->cipher_type != AUTOKEY_PORTA) {
                    if (!cribs_satisfied_p(cfg, cipher_indices, cipher_len, crib_indices,
                        crib_positions, n_cribs, cycleword_lengths[i], cfg->verbose)) {
                        #if CRIB_CHECK
                        continue;
                        #endif
                    }
                }

                if (n < cap) {
                    out[n].period = cycleword_lengths[i];
                    out[n].j = j; out[n].k = k;
                    out[n].aux[0] = 0; out[n].aux[1] = 0;
                    n++;
                }
            }
        }
    }

    if (n == 0) {
        printf("\n\nERROR: No valid configuration found. Check your length constraints.\n");
        printf("Debug: Type=%d, PT_Len=%d, CT_Len=%d\n",
               cfg->cipher_type, cfg->plaintext_keyword_len, cfg->ciphertext_keyword_len);
    }
    return n;
}

static void polyalpha_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    ColossusConfig *cfg = ctx->cfg;
    int *current_plaintext_keyword_state = st->pt_keyword;
    int *current_ciphertext_keyword_state = st->ct_keyword;
    int *current_cycleword_state = st->cycleword;
    int cycleword_len = cc->period;
    int plaintext_keyword_len = cc->j, ciphertext_keyword_len = cc->k;
    bool is_autokey = poly_is_autokey(cfg->cipher_type);
    int i;

    switch (cfg->cipher_type) {
        case VIGENERE:
            straight_alphabet(current_plaintext_keyword_state, g_alpha);
            straight_alphabet(current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break ;
        case QUAGMIRE_1:
            if (cfg->user_plaintext_keyword_present) {
                make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
            } else {
                random_keyword(current_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
            }
            straight_alphabet(current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break ;
        case QUAGMIRE_2:
            straight_alphabet(current_plaintext_keyword_state, g_alpha);
            if (cfg->user_ciphertext_keyword_present) {
                make_keyed_alphabet(cfg->user_ciphertext_keyword, current_ciphertext_keyword_state);
            } else {
                random_keyword(current_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
            }
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break ;
        case QUAGMIRE_3:
            if (cfg->user_plaintext_keyword_present) {
                make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
            } else if (cfg->user_ciphertext_keyword_present) {
                make_keyed_alphabet(cfg->user_ciphertext_keyword, current_plaintext_keyword_state);
            } else {
                random_keyword(current_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
            }
            vec_copy(current_plaintext_keyword_state, current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break ;
        case QUAGMIRE_4:
            if (cfg->user_plaintext_keyword_present) {
                make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
            } else {
                random_keyword(current_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
            }
            if (cfg->user_ciphertext_keyword_present) {
                make_keyed_alphabet(cfg->user_ciphertext_keyword, current_ciphertext_keyword_state);
            } else {
                random_keyword(current_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
            }
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break ;
        case BEAUFORT:
            plaintext_keyword_len = g_alpha;
            ciphertext_keyword_len = g_alpha;
            for (i = 0; i < g_alpha; i++) current_plaintext_keyword_state[i] = i;
            vec_copy(current_plaintext_keyword_state, current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break ;
        case PORTA:
            straight_alphabet(current_plaintext_keyword_state, g_alpha);
            straight_alphabet(current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break ;
        case AUTOKEY_0:
            straight_alphabet(current_plaintext_keyword_state, g_alpha);
            straight_alphabet(current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break;
        case AUTOKEY_1:
            if (cfg->user_plaintext_keyword_present) {
                make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
            } else {
                random_keyword(current_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
            }
            straight_alphabet(current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break;
        case AUTOKEY_2:
            straight_alphabet(current_plaintext_keyword_state, g_alpha);
            if (cfg->user_ciphertext_keyword_present) {
                make_keyed_alphabet(cfg->user_ciphertext_keyword, current_ciphertext_keyword_state);
            } else {
                random_keyword(current_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
            }
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break;
        case AUTOKEY_3:
            if (cfg->user_plaintext_keyword_present) {
                make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
            } else if (cfg->user_ciphertext_keyword_present) {
                make_keyed_alphabet(cfg->user_ciphertext_keyword, current_plaintext_keyword_state);
            } else {
                random_keyword(current_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
            }
            vec_copy(current_plaintext_keyword_state, current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break;
        case AUTOKEY_4:
            if (cfg->user_plaintext_keyword_present) {
                make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
            } else {
                random_keyword(current_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
            }
            if (cfg->user_ciphertext_keyword_present) {
                make_keyed_alphabet(cfg->user_ciphertext_keyword, current_ciphertext_keyword_state);
            } else {
                random_keyword(current_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
            }
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break;
        case AUTOKEY_BEAU:
        case AUTOKEY_PORTA:
            plaintext_keyword_len = g_alpha;
            ciphertext_keyword_len = g_alpha;
            straight_alphabet(current_plaintext_keyword_state, g_alpha);
            straight_alphabet(current_ciphertext_keyword_state, g_alpha);
            random_cycleword(current_cycleword_state, g_alpha, cycleword_len);
            break;
    }

    if (cfg->same_key_cycle) {
        vec_copy(current_plaintext_keyword_state, current_ciphertext_keyword_state, g_alpha);
        vec_copy(current_ciphertext_keyword_state, current_cycleword_state, g_alpha);
    }

    if (cfg->optimal_cycleword && ! is_autokey) {
        derive_optimal_cycleword(cfg, ctx->cipher, ctx->cipher_len,
            current_plaintext_keyword_state, current_ciphertext_keyword_state,
            current_cycleword_state, cycleword_len, ctx->hist_by_col);
    }
}

static void polyalpha_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                              bool *force_primary) {
    ColossusConfig *cfg = ctx->cfg;
    int *cipher_indices = ctx->cipher;
    int cipher_len = ctx->cipher_len;
    int *crib_indices = ctx->crib_indices, *crib_positions = ctx->crib_positions;
    int n_cribs = ctx->n_cribs;
    // st is the engine's `local` (already a copy of `current`); operate on it directly.
    int *local_plaintext_keyword_state = st->pt_keyword;
    int *local_ciphertext_keyword_state = st->ct_keyword;
    int *local_cycleword_state = st->cycleword;
    int cycleword_len = cc->period;
    int plaintext_keyword_len = cc->j, ciphertext_keyword_len = cc->k;
    bool is_autokey = poly_is_autokey(cfg->cipher_type);
    bool perturbate_keyword_p = *force_primary;
    bool did_perturb_keyword = false;
    bool contradiction;

    if (perturbate_keyword_p ||
            cfg->cipher_type == VIGENERE || is_autokey || frand() < cfg->keyword_permutation_probability) {
        switch (cfg->cipher_type) {
            case VIGENERE:
            case PORTA:
            case BEAUFORT:
            case AUTOKEY_0:
            case AUTOKEY_BEAU:
            case AUTOKEY_PORTA:
                did_perturb_keyword = false;
                break ;
            case QUAGMIRE_1:
                if (!cfg->user_plaintext_keyword_present) {
                    perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                    did_perturb_keyword = true;
                }
                break ;
            case QUAGMIRE_2:
                if (!cfg->user_ciphertext_keyword_present) {
                    perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                    did_perturb_keyword = true;
                }
                break ;
            case QUAGMIRE_3:
                if (!cfg->user_plaintext_keyword_present && !cfg->user_ciphertext_keyword_present) {
                    perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                    vec_copy(local_plaintext_keyword_state, local_ciphertext_keyword_state, g_alpha);
                    did_perturb_keyword = true;
                }
                break ;
            case QUAGMIRE_4:
                if (cfg->user_plaintext_keyword_present && cfg->user_ciphertext_keyword_present) {
                    did_perturb_keyword = false;
                } else if (cfg->user_plaintext_keyword_present) {
                    perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                    did_perturb_keyword = true;
                } else if (cfg->user_ciphertext_keyword_present) {
                    perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                    did_perturb_keyword = true;
                } else {
                    if (frand() < 0.5) {
                        perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                    } else {
                        perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                    }
                    did_perturb_keyword = true;
                }
                break ;
            case AUTOKEY_1:
                 if (!cfg->user_plaintext_keyword_present) {
                     perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                     did_perturb_keyword = true;
                 }
                 break;
            case AUTOKEY_2:
                 if (!cfg->user_ciphertext_keyword_present) {
                     perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                     did_perturb_keyword = true;
                 }
                 break;
            case AUTOKEY_3:
                 if (!cfg->user_plaintext_keyword_present && !cfg->user_ciphertext_keyword_present) {
                     perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                     vec_copy(local_plaintext_keyword_state, local_ciphertext_keyword_state, g_alpha);
                     did_perturb_keyword = true;
                 }
                 break;
            case AUTOKEY_4:
                 if (cfg->user_plaintext_keyword_present && cfg->user_ciphertext_keyword_present) {
                     did_perturb_keyword = false;
                 } else if (cfg->user_plaintext_keyword_present) {
                     perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                     did_perturb_keyword = true;
                 } else if (cfg->user_ciphertext_keyword_present) {
                     perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                     did_perturb_keyword = true;
                 } else {
                     if (frand() < 0.5) perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                     else perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                     did_perturb_keyword = true;
                 }
                 break;
        }
    } else {
        did_perturb_keyword = false;
    }

    if (cfg->optimal_cycleword && ! is_autokey) {
        if (!did_perturb_keyword && cfg->cipher_type != BEAUFORT && cfg->cipher_type != VIGENERE && cfg->cipher_type != PORTA) {
            if (cfg->cipher_type == QUAGMIRE_3 && !(cfg->user_plaintext_keyword_present || cfg->user_ciphertext_keyword_present)) {
                 perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                 vec_copy(local_plaintext_keyword_state, local_ciphertext_keyword_state, g_alpha);
                 did_perturb_keyword = true;
            }
            else if (cfg->cipher_type == QUAGMIRE_1 && !cfg->user_plaintext_keyword_present) {
                perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                did_perturb_keyword = true;
            }
            else if (cfg->cipher_type == QUAGMIRE_2 && !cfg->user_ciphertext_keyword_present) {
                perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                did_perturb_keyword = true;
            }
            else if (cfg->cipher_type == QUAGMIRE_4) {
                if (!cfg->user_plaintext_keyword_present && !cfg->user_ciphertext_keyword_present) {
                    if (frand() < 0.5) {
                        perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                    } else {
                        perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                    }
                    did_perturb_keyword = true;
                } else if (!cfg->user_plaintext_keyword_present) {
                     perturbate_keyword(local_plaintext_keyword_state, g_alpha, plaintext_keyword_len);
                     did_perturb_keyword = true;
                } else if (!cfg->user_ciphertext_keyword_present) {
                     perturbate_keyword(local_ciphertext_keyword_state, g_alpha, ciphertext_keyword_len);
                     did_perturb_keyword = true;
                }
            }
        }

        derive_optimal_cycleword(cfg, cipher_indices, cipher_len,
            local_plaintext_keyword_state, local_ciphertext_keyword_state,
            local_cycleword_state, cycleword_len, ctx->hist_by_col);

    } else {
        if (cfg->cipher_type == VIGENERE || cfg->cipher_type == PORTA || is_autokey) {
             perturbate_cycleword(local_cycleword_state, g_alpha, cycleword_len);
        }
        else if (!did_perturb_keyword) {
            perturbate_cycleword(local_cycleword_state, g_alpha, cycleword_len);
        }

        if (cfg->cipher_type != VIGENERE && cfg->cipher_type != BEAUFORT && cfg->cipher_type != PORTA && ! is_autokey) {
            perturbate_keyword_p = false;

            if (did_perturb_keyword) {
                contradiction = constrain_cycleword(cfg, cipher_indices, cipher_len, crib_indices,
                    crib_positions, n_cribs,
                    local_plaintext_keyword_state, local_ciphertext_keyword_state,
                    local_cycleword_state, cycleword_len, cfg->variant, cfg->verbose);

                if (contradiction) {
                    if (ctx->model_scratch) (*(long *) ctx->model_scratch) += 1;
                    perturbate_keyword_p = true;
                }
            }
        }
    }

    if (cfg->same_key_cycle) {
        vec_copy(local_plaintext_keyword_state, local_ciphertext_keyword_state, g_alpha);
        vec_copy(local_ciphertext_keyword_state, local_cycleword_state, g_alpha);
    }

    *force_primary = perturbate_keyword_p;
}

static void polyalpha_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    for (int i = 0; i < g_alpha; i++) {
        dst->pt_keyword[i] = src->pt_keyword[i];
        dst->ct_keyword[i] = src->ct_keyword[i];
    }
    for (int i = 0; i < cc->period; i++) dst->cycleword[i] = src->cycleword[i];
}

static void polyalpha_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                              int *out, double *score_adjust) {
    (void) score_adjust;
    decrypt_state(ctx->cfg, ctx->cipher, ctx->cipher_len,
        st->pt_keyword, st->ct_keyword, st->cycleword, cc->period, out);
}

static void polyalpha_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) decrypted;
    ColossusConfig *cfg = ctx->cfg;
    int cipher_len = ctx->cipher_len;
    int *cipher_indices = ctx->cipher;
    int cycleword_len = cc->period;
    bool is_autokey = poly_is_autokey(cfg->cipher_type);
    int buf[MAX_CIPHER_LENGTH];
    int j, k, indx, offset = 0;

    const int *best_plaintext_keyword_state = st->pt_keyword;
    const int *best_ciphertext_keyword_state = st->ct_keyword;
    const int *best_cycleword_state = st->cycleword;

    if (cfg->cipher_type == PORTA) {
        porta_decrypt(buf, cipher_indices, cipher_len, (int *) best_cycleword_state, cycleword_len);
    } else if (cfg->cipher_type == BEAUFORT) {
        beaufort_decrypt(buf, cipher_indices, cipher_len, (int *) best_cycleword_state, cycleword_len);
    } else if (is_autokey) {
        autokey_decrypt(cfg, buf, cipher_indices, cipher_len,
            (int *) best_plaintext_keyword_state, (int *) best_ciphertext_keyword_state,
            (int *) best_cycleword_state, cycleword_len);
    } else {
        quagmire_decrypt(buf, cipher_indices, cipher_len,
            (int *) best_plaintext_keyword_state, (int *) best_ciphertext_keyword_state,
            (int *) best_cycleword_state, cycleword_len, cfg->variant);
    }

    if (cfg->transperoffset_present)
        transperoffset(buf, cipher_len, cfg->trans_period, cfg->trans_offset);
    if (cfg->transmatrix_present)
        transmatrix(buf, cipher_len, cfg->trans_w1, cfg->trans_w2, cfg->trans_clockwise);

    double ioc = index_of_coincidence(buf, cipher_len);
    double chi = chi_squared(buf, cipher_len);
    double entropy_score = entropy(buf, cipher_len);
    double elapsed = ((double) clock() - stats->start_time)/CLOCKS_PER_SEC;
    double n_iter_per_sec = ((double) stats->n_iterations)/elapsed;

    printf("\n%.2f\t[sec]\n", elapsed);
    printf("%.0fK\t[it/sec]\n", 1.e-3*n_iter_per_sec);
    printf("%d\t[backtracks]\n", stats->n_backtracks);
    printf("%d\t[restarts]\n", stats->n_restarts);
    printf("%d\t[slips]\n", stats->n_slips);
    long n_contradictions = ctx->model_scratch ? *(long *) ctx->model_scratch : 0;
    printf("%.2f\t[contradiction pct]\n", ((double) n_contradictions)/stats->n_iterations);
    printf("%.4f\t[IOC]\n", ioc);
    printf("%.4f\t[entropy]\n", entropy_score);
    printf("%.2f\t[chi-squared]\n", chi);
    printf("%.2f\t[score]\n", score);

    if (cfg->cipher_type != PORTA) {
        print_text((int *) best_plaintext_keyword_state, g_alpha); printf("\n");
        print_text((int *) best_ciphertext_keyword_state, g_alpha); printf("\n");
    }
    print_text((int *) best_cycleword_state, cycleword_len); printf("\n");

    printf("\n");
    if (cfg->cipher_type != PORTA) {
        for (k = 0; k < cycleword_len; k++) {
            for (j = 0; j < g_alpha; j++) {
                if (best_ciphertext_keyword_state[j] == best_cycleword_state[k]) offset = j;
            }
            for (j = 0; j < g_alpha; j++) {
                indx = (j + offset) % g_alpha;
                printf("%c", index_to_char(best_ciphertext_keyword_state[indx]));
            }
            printf("\n");
        }
    }
    printf("\n");
    print_text(buf, cipher_len); printf("\n");
    fflush(stdout);
}

static void polyalpha_report(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted) {
    ColossusConfig *cfg = ctx->cfg;
    SharedData *shared = ctx->shared;
    int cipher_len = ctx->cipher_len;
    int n_words_found = 0;

    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < cipher_len; i++) plaintext_string[i] = index_to_char(decrypted[i]);
    plaintext_string[cipher_len] = '\0';

    if (cfg->dictionary_present && shared->dict != NULL) {
        n_words_found = find_dictionary_words(plaintext_string, shared->dict,
            shared->n_dict_words, shared->max_dict_word_len);
    }

    SolveResult local_res;
    SolveResult *res = ctx->result ? ctx->result : &local_res;
    res->solved = true;
    res->cipher_type = cfg->cipher_type;
    res->score = score;
    res->n_words = n_words_found;
    res->cycleword_len = cc->period;
    vec_copy((int *) st->pt_keyword, res->plaintext_keyword, g_alpha);
    vec_copy((int *) st->ct_keyword, res->ciphertext_keyword, g_alpha);
    vec_copy((int *) st->cycleword, res->cycleword, cc->period);
    vec_copy(decrypted, res->decrypted, cipher_len);
    res->decrypted_len = cipher_len;

    report_solution(cfg, ctx->cribtext, ctx->cipher, res);
}

static const CipherModel POLYALPHA_MODEL = {
    .name = "polyalphabetic",
    .shape = SHAPE_SHOTGUN,          // overridden per-solve (DETERMINISTIC for optimal Vig/Beau/Porta)
    .needs_hist = false,             // set per-solve (optimal && !autokey)
    .enumerate_configs = polyalpha_enumerate,
    .key_len = NULL,
    .seed = polyalpha_seed,
    .perturb = polyalpha_perturb,
    .copy_state = polyalpha_copy,
    .decrypt = polyalpha_decrypt,
    .report = polyalpha_report,
    .report_verbose = polyalpha_report_verbose,
};


// Core Solver

void solve_cipher(char *ciphertext_str, char *cribtext_str, ColossusConfig *cfg,
    SharedData *shared, SolveResult *result) {

    // Default to "not solved": every early return (transposition dispatch, no
    // periodicities found, no valid configuration) then leaves a correct result.
    if (result) result->solved = false;

    // Tokenized (symbol) input: HOMOPHONIC always, or any cipher run with -delimiter.
    // In this mode delimiters and symbol tokens are significant, so -skipspaces (which
    // would strip them) is suppressed and the ciphertext is decoded into symbol ids.
    bool symbol_mode = (cfg->cipher_type == HOMOPHONIC) || cfg->delimiter_present;

    // -skipspaces: drop spaces/punctuation from the ciphertext entirely, so they
    // are not even carried as transposition positions. Default (flag off) keeps
    // them -- ord() encodes them as negative sentinels that ride through the
    // decryption and are skipped only by scoring.
    if (cfg->skip_spaces && !symbol_mode) {
        int w = 0;
        for (int r = 0; ciphertext_str[r] != '\0'; r++) {
            if (isalpha((unsigned char) ciphertext_str[r]))
                ciphertext_str[w++] = ciphertext_str[r];
        }
        ciphertext_str[w] = '\0';
    }

    int cipher_indices[MAX_CIPHER_LENGTH];
    int n_cribs = 0;
    int crib_positions[MAX_CIPHER_LENGTH];
    int crib_indices[MAX_CIPHER_LENGTH];
    SymbolTable symtab;

    // Prepare indices. Letter ciphers get the historical 0..25/sentinel encoding
    // (decode_cipher reproduces ord() byte-for-byte); HOMOPHONIC fills symtab with the
    // distinct ciphertext symbols and emits one symbol id per position.
    int cipher_len = decode_cipher(ciphertext_str, cfg, cipher_indices, &symtab);

    // Process Cribs (Local to this cipher)
    if (strlen(cribtext_str) > 0) {
        if ((int)strlen(cribtext_str) != cipher_len) {
            if (cfg->verbose) printf("Crib length mismatch (Crib: %lu, Cipher: %d). Ignoring crib.\n", strlen(cribtext_str), cipher_len);
            n_cribs = 0;
        } else {
            for (int i = 0; i < cipher_len; i++) {
                if (cribtext_str[i] != '_') {
                    crib_positions[n_cribs] = i;
                    crib_indices[n_cribs] = g_char_to_idx[toupper((unsigned char)cribtext_str[i]) & 127];
                    n_cribs++;
                }
            }
        }
    }


    // --- TRANSPOSITION CIPHERS ---
    // These are pure transpositions solved by optimization over the transform
    // parameters, not via the keyword/cycleword/period machinery below.
    if (cfg->cipher_type == TRANSMATRIX || cfg->cipher_type == TRANSPEROFFSET) {
        solve_transposition(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == TRANSPOSITION) {
        solve_general_transposition(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == TRANSCOL || cfg->cipher_type == TRANSCOL2) {
        solve_columnar(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == RAILFENCE) {
        solve_railfence(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == ROUTE) {
        solve_route(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == AMSCO) {
        solve_amsco(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == MYSZKOWSKI) {
        solve_myszkowski(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == REDEFENCE) {
        solve_redefence(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == CADENUS) {
        solve_cadenus(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == NIHILIST) {
        solve_nihilist(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == SWAGMAN) {
        solve_swagman(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == GRILLE) {
        solve_grille(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == INDEP_PERIODIC) {
        solve_indep_periodic(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
        return ;
    }
    if (cfg->cipher_type == HOMOPHONIC) {
        solve_homophonic(ciphertext_str, cribtext_str, cfg, shared,
            cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs, &symtab);
        return ;
    }


    // --- POLYALPHABETIC CIPHERS ---
    // Vigenere / Quagmire I-IV / Beaufort / Porta / Autokey* all share one model;
    // the cipher-agnostic engine enumerates (cycleword_len, j, k) and shotgun /
    // hill-climbs each via the model's seed/perturb/decrypt hooks.
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.result = result;

    bool is_autokey = poly_is_autokey(cfg->cipher_type);
    long poly_contradictions = 0;            // verbose-only telemetry for the perturb hook
    ctx.model_scratch = &poly_contradictions;

    CipherModel model = POLYALPHA_MODEL;
    model.needs_hist = cfg->optimal_cycleword && !is_autokey;
    // Vigenere/Beaufort/Porta in optimal mode use fixed straight alphabets and a
    // deterministically-derived cycleword, so the climb is deterministic: stop at
    // the first recorded best. (-samekey breaks the determinism, so exclude it.)
    if (cfg->optimal_cycleword && !is_autokey && !cfg->same_key_cycle &&
        (cfg->cipher_type == VIGENERE || cfg->cipher_type == BEAUFORT ||
         cfg->cipher_type == PORTA)) {
        model.shape = SHAPE_DETERMINISTIC;
    }

    run_solver(&model, &ctx);
}



// Prints the human-readable result block and the ">>> ..." one-line CSV summary
// from a populated SolveResult. Output is byte-for-byte the same as the inline
// reporting it replaced, so batch grep/sort over the ">>>" lines is unaffected.
void report_solution(ColossusConfig *cfg, char *cribtext_str,
    int cipher_indices[], SolveResult *res) {

    int cipher_len = res->decrypted_len;
    int n_cribs = 0;
    for (int i = 0; cribtext_str[i] != '\0'; i++) if (cribtext_str[i] != '_') n_cribs++;

    if (cfg->transperoffset_present) {
        printf("\ntransperiodoffset: period = %d, offset = %d\n", cfg->trans_period, cfg->trans_offset);
    }

    if (cfg->transmatrix_present) {
        printf("\ntransmatrix: w1 = %d, w2 = %d, direction = %s\n", cfg->trans_w1, cfg->trans_w2, cfg->trans_clockwise ? "cw" : "ccw");
    }

    // Results Output
    printf("\nResult Score: %.2f | Words: %d\n", res->score, res->n_words);

    print_text(cipher_indices, cipher_len);
    printf("\n");

    if (cfg->cipher_type != PORTA) {
        print_text(res->plaintext_keyword, g_alpha);
        printf("\n");
        print_text(res->ciphertext_keyword, g_alpha);
        printf("\n");
    }

    print_text(res->cycleword, res->cycleword_len);
    printf("\n");
    print_text(res->decrypted, cipher_len);
    printf("\n");
    printf("%s\n", cribtext_str);

    if (PARTIAL_CRIB_MATCH && n_cribs > 0) {
        // Index the crib by cipher position via cribtext_str ('_' = no crib),
        // not the positionally-packed crib_indices array. 0 = exact match,
        // a small digit = near miss, '*' = far (>= 10) from the crib char.
        for (int i = 0; i < cipher_len; i++) {
            if (cribtext_str[i] == '_') {
                printf("_"); // No crib defined for this position.
            } else {
                int diff = abs(res->decrypted[i] - (g_char_to_idx[toupper((unsigned char)cribtext_str[i]) & 127]));
                if (diff < 10) {
                    printf("%d", diff);
                } else {
                    printf("*");
                }
            }
        }
    }
    printf("\n\n");

    // One-liner summary
    if (cfg->transperoffset_present) {
        if (cfg->dictionary_present) {
            printf(">>> %.2f, %d, %d, %d, %d, %s, ", res->score, res->n_words, cfg->cipher_type, cfg->trans_period, cfg->trans_offset, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        } else {
            printf(">>> %.2f, %d, %d, %d, %s, ", res->score, cfg->cipher_type, cfg->trans_period, cfg->trans_offset, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        }
    } else if (cfg->transmatrix_present) {
        if (cfg->dictionary_present) {
            printf(">>> %.2f, %d, %d, %d, %d, %d, %s, ", res->score, res->n_words, cfg->cipher_type, cfg->trans_w1, cfg->trans_w2, cfg->trans_clockwise, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        } else {
            printf(">>> %.2f, %d, %d, %d, %d, %s, ", res->score, cfg->cipher_type, cfg->trans_w1, cfg->trans_w2, cfg->trans_clockwise, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        }
    } else {
        if (cfg->dictionary_present) {
            printf(">>> %.2f, %d, %d, %s, ", res->score, res->n_words, cfg->cipher_type, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        } else {
            printf(">>> %.2f, %d, %s, ", res->score, cfg->cipher_type, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        }
    }

    print_text(cipher_indices, cipher_len);
    printf(", ");

    if (cfg->cipher_type != PORTA) {
        print_text(res->plaintext_keyword, g_alpha);
        printf(", ");
        print_text(res->ciphertext_keyword, g_alpha);
        printf(", ");
    }

    print_text(res->cycleword, res->cycleword_len);
    printf(", ");

    print_text(res->decrypted, cipher_len);
    printf("\n");
}



// Transposition cipher solvers
//
// Pure transposition ciphers (transmatrix, transperoffset) are cracked by
// optimizing the small parameter vector of the transform itself, rather than
// enumerating every configuration. The search reuses the same shotgun /
// slippery hill-climbing engine and n-gram scoring as the polyalphabetic path.
//   - TRANSMATRIX    : params (p1,p2,p3) = (w1, w2, clockwise)
//   - TRANSPEROFFSET : params (p1,p2)    = (period d, offset n)

// Apply a candidate transform to a fresh copy of the ciphertext.
static void apply_transposition(ColossusConfig *cfg, int cipher_indices[],
    int cipher_len, int p1, int p2, int p3, int decrypted[]) {

    vec_copy(cipher_indices, decrypted, cipher_len);
    if (cfg->cipher_type == TRANSMATRIX) {
        transmatrix(decrypted, cipher_len, p1, p2, p3); // p1=w1, p2=w2, p3=clockwise
    } else { // TRANSPEROFFSET
        transperoffset(decrypted, cipher_len, p1, p2);  // p1=period(d), p2=offset(n)
    }
}

// Pick a random valid parameter triple for the current transposition type.
static void random_transposition_params(ColossusConfig *cfg, int cipher_len,
    int *p1, int *p2, int *p3) {

    if (cfg->cipher_type == TRANSMATRIX) {
        // Valid grid widths are [2, len-1]; matrix_rotate is identity outside.
        *p1 = rand_int(2, cipher_len);
        *p2 = rand_int(2, cipher_len);
        *p3 = rand_int(0, 2);            // clockwise in {0,1}
    } else { // TRANSPEROFFSET
        // The decimation step d must be coprime to len for a bijection.
        do {
            *p1 = rand_int(1, cipher_len);
        } while (gcd(*p1, cipher_len) != 1);
        *p2 = rand_int(0, cipher_len);   // offset n in [0, len-1]
        *p3 = 0;                         // unused
    }
}

// Perturb a single parameter (one local neighbour move).
static void perturbate_transposition_params(ColossusConfig *cfg, int cipher_len,
    int *p1, int *p2, int *p3) {

    if (cfg->cipher_type == TRANSMATRIX) {
        int which = rand_int(0, 3);
        if (which == 2) {
            *p3 = 1 - *p3;               // flip direction
        } else {
            int *w = (which == 0) ? p1 : p2;
            if (cipher_len > 4 && frand() < 0.5) {
                // Local +/-1 step, clamped to [2, len-1].
                *w += (frand() < 0.5) ? -1 : 1;
                if (*w < 2) *w = 2;
                if (*w > cipher_len - 1) *w = cipher_len - 1;
            } else {
                *w = rand_int(2, cipher_len);
            }
        }
    } else { // TRANSPEROFFSET
        if (frand() < 0.5) {
            // Local rotation step: aligns the wrap boundary / any crib.
            *p2 += (frand() < 0.5) ? -1 : 1;
            *p2 = ((*p2 % cipher_len) + cipher_len) % cipher_len;
        } else {
            // d is non-smooth, so re-randomise among coprime values.
            do {
                *p1 = rand_int(1, cipher_len);
            } while (gcd(*p1, cipher_len) != 1);
        }
    }
}

// ---- transmatrix / transperoffset model (cipher-agnostic engine) ----------
// A pure parameter-vector search: the candidate state is the transform's own
// (p1,p2,p3) triple carried in st->aux[0..2]. SHAPE_SHOTGUN reproduces the
// slip-probability acceptance and RNG draw order of the original dedicated
// climber, so the search is bit-identical at a fixed seed.

static int transmat_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    (void) ctx; (void) cap;
    out[0].period = 0; out[0].j = 0; out[0].k = 0;
    out[0].aux[0] = 0; out[0].aux[1] = 0;
    return 1;     // a single config; the whole search is the inner climb
}

static void transmat_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    (void) cc;
    random_transposition_params(ctx->cfg, ctx->cipher_len, &st->aux[0], &st->aux[1], &st->aux[2]);
}

static void transmat_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                             bool *force_primary) {
    (void) cc; (void) force_primary;
    perturbate_transposition_params(ctx->cfg, ctx->cipher_len, &st->aux[0], &st->aux[1], &st->aux[2]);
}

static void transmat_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    (void) cc;
    dst->aux[0] = src->aux[0]; dst->aux[1] = src->aux[1]; dst->aux[2] = src->aux[2];
}

static void transmat_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                             int *out, double *score_adjust) {
    (void) cc; (void) score_adjust;
    apply_transposition(ctx->cfg, ctx->cipher, ctx->cipher_len,
        st->aux[0], st->aux[1], st->aux[2], out);
}

static void transmat_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) cc; (void) decrypted;
    ColossusConfig *cfg = ctx->cfg;
    int buf[MAX_CIPHER_LENGTH];
    apply_transposition(cfg, ctx->cipher, ctx->cipher_len, st->aux[0], st->aux[1], st->aux[2], buf);

    double elapsed = ((double) clock() - stats->start_time)/CLOCKS_PER_SEC;
    double n_iter_per_sec = (elapsed > 0.) ? ((double) stats->n_iterations)/elapsed : 0.;

    printf("\n%.2f\t[sec]\n", elapsed);
    printf("%.0fK\t[it/sec]\n", 1.e-3*n_iter_per_sec);
    printf("%d\t[restarts]\n", stats->n_restarts);
    printf("%d\t[backtracks]\n", stats->n_backtracks);
    printf("%d\t[slips]\n", stats->n_slips);
    printf("%.4f\t[entropy]\n", entropy(buf, ctx->cipher_len));
    printf("%.2f\t[score]\n", score);
    if (cfg->cipher_type == TRANSMATRIX) {
        printf("w1 = %d, w2 = %d, direction = %s\t[params]\n",
            st->aux[0], st->aux[1], st->aux[2] ? "cw" : "ccw");
    } else { // TRANSPEROFFSET
        printf("period = %d, offset = %d\t[params]\n", st->aux[0], st->aux[1]);
    }
    printf("\n");
    print_text(buf, ctx->cipher_len); printf("\n");
    fflush(stdout);
}

static void transmat_report(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted) {
    (void) cc;
    ColossusConfig *cfg = ctx->cfg;
    SharedData *shared = ctx->shared;
    int cipher_len = ctx->cipher_len;
    int *cipher_indices = ctx->cipher;
    char *cribtext_str = ctx->cribtext;
    int n_cribs = ctx->n_cribs;
    int best_p1 = st->aux[0], best_p2 = st->aux[1], best_p3 = st->aux[2];
    int n_words_found = 0;

    // Parameter report line.
    if (cfg->cipher_type == TRANSMATRIX) {
        printf("\ntransmatrix: w1 = %d, w2 = %d, direction = %s\n",
            best_p1, best_p2, best_p3 ? "cw" : "ccw");
    } else {
        printf("\ntransperiodoffset: period = %d, offset = %d\n", best_p1, best_p2);
    }

    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < cipher_len; i++) plaintext_string[i] = index_to_char(decrypted[i]);
    plaintext_string[cipher_len] = '\0';

    if (cfg->dictionary_present && shared->dict != NULL) {
        n_words_found = find_dictionary_words(plaintext_string, shared->dict,
            shared->n_dict_words, shared->max_dict_word_len);
    }

    // Results output.
    printf("\nResult Score: %.2f | Words: %d\n", score, n_words_found);

    print_text(cipher_indices, cipher_len);
    printf("\n");
    print_text(decrypted, cipher_len);
    printf("\n");
    printf("%s\n", cribtext_str);

    if (PARTIAL_CRIB_MATCH && n_cribs > 0) {
        // Indexed by cipher position via cribtext_str (same scheme as solve_cipher).
        for (int i = 0; i < cipher_len; i++) {
            if (cribtext_str[i] == '_') {
                printf("_");
            } else {
                int diff = abs(decrypted[i] - (g_char_to_idx[toupper((unsigned char)cribtext_str[i]) & 127]));
                if (diff < 10) printf("%d", diff); else printf("*");
            }
        }
    }
    printf("\n\n");

    // One-liner summary. Field order matches the existing transmatrix /
    // transperoffset summaries, minus the keyword/cycleword fields (a pure
    // transposition has none).
    if (cfg->cipher_type == TRANSMATRIX) {
        if (cfg->dictionary_present) {
            printf(">>> %.2f, %d, %d, %d, %d, %d, %s, ", score, n_words_found,
                cfg->cipher_type, best_p1, best_p2, best_p3,
                cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        } else {
            printf(">>> %.2f, %d, %d, %d, %d, %s, ", score,
                cfg->cipher_type, best_p1, best_p2, best_p3,
                cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        }
    } else {
        if (cfg->dictionary_present) {
            printf(">>> %.2f, %d, %d, %d, %d, %s, ", score, n_words_found,
                cfg->cipher_type, best_p1, best_p2,
                cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        } else {
            printf(">>> %.2f, %d, %d, %d, %s, ", score,
                cfg->cipher_type, best_p1, best_p2,
                cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
        }
    }

    print_text(cipher_indices, cipher_len);
    printf(", ");
    print_text(decrypted, cipher_len);
    printf("\n");
}

static const CipherModel TRANSMATRIX_MODEL = {
    .name = "transmatrix",
    .shape = SHAPE_SHOTGUN,
    .needs_hist = false,
    .enumerate_configs = transmat_enumerate,
    .key_len = NULL,
    .seed = transmat_seed,
    .perturb = transmat_perturb,
    .copy_state = transmat_copy,
    .decrypt = transmat_decrypt,
    .report = transmat_report,
    .report_verbose = transmat_report_verbose,
};

void solve_transposition(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str; // ciphertext is carried as cipher_indices.

    if (cipher_len < 3) {
        printf("\n\nERROR: ciphertext too short for a transposition solve.\n\n");
        return ;
    }

    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    run_solver(&TRANSMATRIX_MODEL, &ctx);
}



// General transposition solver (AZDecrypt-style)
//
// Solves an arbitrary columnar / route transposition by hill-climbing the full
// permutation key directly, rather than the fixed parameters of a specific
// transform family. The key is an array key[i] = source position, so the
// candidate plaintext is decrypted[i] = ciphertext[key[i]]. Neighbour moves
// (swap, segment reverse, block move) all preserve the permutation; scoring,
// slip, backtracking and restarts reuse the program's standard machinery.

// Apply a permutation key: decrypted[i] = cipher[key[i]].
static void apply_permutation(int cipher_indices[], int key[], int len, int decrypted[]) {
    for (int i = 0; i < len; i++) decrypted[i] = cipher_indices[key[i]];
}

// Structural regularity of a permutation key, in [0,1]. Columnar / route
// transpositions are periodic: for the period p (the column count), plaintext
// positions i and i+p sit in the same column one row apart, so their ciphertext
// positions differ by a constant stride. We scan candidate periods and, for
// each, histogram the strides key[i+p]-key[i]; the best (most concentrated)
// period gives the score = fraction of pairs in the single modal stride.
// English-looking but structurally random permutations score low; a true
// (keyed) columnar key scores high at its period. This is the n-gram-gaming
// guard that AZDecrypt gets from its periodic-redundancy rule.
static double key_structure_score(int key[], int len, int *out_period) {
    static int hist[2 * MAX_CIPHER_LENGTH];
    if (out_period) *out_period = 0;
    if (len < 2) return 0.0;

    int max_period = len / 3;
    if (max_period > 24) max_period = 24;   // bound cost; covers realistic column counts
    if (max_period < 1) max_period = 1;

    double best_frac = 0.0;
    for (int p = 1; p <= max_period; p++) {
        int npairs = len - p;
        if (npairs < 1) break;
        int modal = 0;
        for (int i = 0; i + p < len; i++) {
            int b = key[i + p] - key[i] + len;   // offset into [0, 2*len)
            int c = ++hist[b];
            if (c > modal) modal = c;
        }
        // Re-zero only the bins we touched (cheaper than a full memset per period).
        for (int i = 0; i + p < len; i++) hist[key[i + p] - key[i] + len] = 0;

        double frac = (double) modal / (double) npairs;
        if (frac > best_frac) { best_frac = frac; if (out_period) *out_period = p; }
    }
    return best_frac;
}

// Perturb a permutation key with one of several permutation-preserving moves.
// target_period is the column count currently detected in the key (0 if none);
// the column-swap move uses it so it reorders the actual columns rather than
// guessing a period at random.
static void perturbate_permutation(int key[], int len, int target_period) {
    int max_p = min(len / 2, 40);

    // Column swap: swap the two sets of key entries {.., r*p+c1, ..} and
    // {.., r*p+c2, ..}. With p = the detected column count this reorders whole
    // columns in one step without disturbing the within-column structure — the
    // move that lets a columnar-seeded key reach the exact column order. Once a
    // period is detected it is the dominant move; small position moves would
    // need ~one-column-height steps to do the same and erode the structure.
    bool do_colswap = (target_period >= 2 && target_period <= max_p && max_p >= 2 && frand() < 0.6);
    if (do_colswap) {
        int p = target_period;
        int c1 = rand_int(0, p), c2 = rand_int(0, p);
        if (c1 == c2) return;
        for (int r = 0; ; r++) {
            int i1 = r * p + c1, i2 = r * p + c2;
            if (i1 >= len || i2 >= len) break;   // only swap rows where both columns exist
            int t = key[i1]; key[i1] = key[i2]; key[i2] = t;
        }
        return;
    }

    int move = rand_int(0, 3);
    if (move == 0) {
        // Swap two positions.
        int i = rand_int(0, len), j = rand_int(0, len);
        int t = key[i]; key[i] = key[j]; key[j] = t;
    } else if (move == 1) {
        // Reverse a short segment.
        int max_blk = min(len, 14);
        int blk = rand_int(2, max_blk + 1);
        int s = rand_int(0, len - blk + 1);
        for (int a = s, b = s + blk - 1; a < b; a++, b--) {
            int t = key[a]; key[a] = key[b]; key[b] = t;
        }
    } else {
        // Cut a short block and re-insert it elsewhere (a range rotation).
        int max_blk = min(len, 14);
        int blk = rand_int(1, max_blk + 1);
        int s = rand_int(0, len - blk + 1);          // block start
        int d = rand_int(0, len - blk + 1);          // destination start
        if (d == s) return;
        int tmp[14];
        for (int a = 0; a < blk; a++) tmp[a] = key[s + a];
        if (d < s) {
            for (int a = s - 1; a >= d; a--) key[a + blk] = key[a];
        } else {
            for (int a = s + blk; a < d + blk; a++) key[a - blk] = key[a];
        }
        for (int a = 0; a < blk; a++) key[d + a] = tmp[a];
    }
}

// Seed a key with a columnar-transposition layout: the ciphertext is read as
// `p` columns (row-major fill, so the final row may be short) taken in column
// order `ord`. key[plaintext_pos] = ciphertext_pos. Seeding restarts from such
// structured keys turns the intractable free-permutation search into "find the
// right period and column order", which the climber refines easily.
static void build_columnar_seed(int key[], int len, int p, int ord[]) {
    int pos = 0;
    for (int k = 0; k < p; k++) {
        int c = ord[k];
        for (int r = 0; r * p + c < len; r++) key[r * p + c] = pos++;
    }
}

// ---- general transposition model (TYPE transposition; cipher-agnostic) -----
// SHAPE_ANNEAL over the full length-N permutation key (st->key, key_len = N). The
// AZDecrypt periodic-redundancy guard (key_structure_score) is folded in two
// ways: its value becomes the decrypt score_adjust, and the period it detects is
// carried in st->aux[0] so the next perturb's column-swap move can target it.
// The RNG draw order matches the original climber, so the search is bit-identical.

static int permutation_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    (void) ctx; (void) cap;
    out[0].period = 0; out[0].j = 0; out[0].k = 0;
    return 1;
}

static void permutation_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    (void) cc;
    int len = ctx->cipher_len;
    st->key_len = len;
    // Mostly a structured columnar seed (random period and column order),
    // occasionally a fully random permutation so route transpositions stay reachable.
    if (frand() < 0.85) {
        int max_p = min(len / 2, 40);
        if (max_p < 2) max_p = 2;
        int p = rand_int(2, max_p + 1);
        int ord[64];
        if (p > 64) p = 64;
        for (int c = 0; c < p; c++) ord[c] = c;
        shuffle(ord, p);
        build_columnar_seed(st->key, len, p, ord);
    } else {
        for (int i = 0; i < len; i++) st->key[i] = i;
        shuffle(st->key, len);
    }
    st->aux[0] = 0;     // detected period; decrypt() fills it from key_structure_score
}

static void permutation_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                                bool *force_primary) {
    (void) cc; (void) force_primary;
    perturbate_permutation(st->key, ctx->cipher_len, st->aux[0]);
}

static void permutation_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    (void) cc;
    int len = src->key_len;
    dst->key_len = len;
    dst->aux[0] = src->aux[0];
    for (int i = 0; i < len; i++) dst->key[i] = src->key[i];
}

static void permutation_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                                int *out, double *score_adjust) {
    (void) cc;
    apply_permutation(ctx->cipher, st->key, ctx->cipher_len, out);
    int period = 0;
    double s = key_structure_score(st->key, ctx->cipher_len, &period);
    st->aux[0] = period;                                     // carry period for the next perturb
    *score_adjust = ctx->cfg->weight_structure * s;
}

static void permutation_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) cc; (void) decrypted;
    int buf[MAX_CIPHER_LENGTH];
    apply_permutation(ctx->cipher, (int *) st->key, ctx->cipher_len, buf);
    double elapsed = ((double) clock() - stats->start_time)/CLOCKS_PER_SEC;
    double n_iter_per_sec = (elapsed > 0.) ? ((double) stats->n_iterations)/elapsed : 0.;
    printf("\n%.2f\t[sec]\n", elapsed);
    printf("%.0fK\t[it/sec]\n", 1.e-3*n_iter_per_sec);
    printf("%d\t[restarts]\n", stats->n_restarts);
    printf("%d\t[backtracks]\n", stats->n_backtracks);
    printf("%d\t[slips]\n", stats->n_slips);
    printf("%.4f\t[entropy]\n", entropy(buf, ctx->cipher_len));
    printf("%.2f\t[score]\n", score);
    printf("%d\t[period]\n", st->aux[0]);
    printf("\n");
    print_text(buf, ctx->cipher_len); printf("\n");
    fflush(stdout);
}

static void permutation_report(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted) {
    (void) cc;
    ColossusConfig *cfg = ctx->cfg;
    SharedData *shared = ctx->shared;
    int cipher_len = ctx->cipher_len;
    int *cipher_indices = ctx->cipher;
    char *cribtext_str = ctx->cribtext;
    int n_cribs = ctx->n_cribs;
    int n_words_found = 0;

    printf("\ntransposition: permutation key of length %d\n", cipher_len);

    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < cipher_len; i++) plaintext_string[i] = index_to_char(decrypted[i]);
    plaintext_string[cipher_len] = '\0';

    if (cfg->dictionary_present && shared->dict != NULL) {
        n_words_found = find_dictionary_words(plaintext_string, shared->dict,
            shared->n_dict_words, shared->max_dict_word_len);
    }

    printf("\nResult Score: %.2f | Words: %d\n", score, n_words_found);

    print_text(cipher_indices, cipher_len);
    printf("\n");
    print_text(decrypted, cipher_len);
    printf("\n");
    printf("%s\n", cribtext_str);

    if (PARTIAL_CRIB_MATCH && n_cribs > 0) {
        for (int i = 0; i < cipher_len; i++) {
            if (cribtext_str[i] == '_') {
                printf("_");
            } else {
                int diff = abs(decrypted[i] - (g_char_to_idx[toupper((unsigned char)cribtext_str[i]) & 127]));
                if (diff < 10) printf("%d", diff); else printf("*");
            }
        }
    }
    printf("\n");

    // Recovered key (source position for each output position), for reproduction.
    printf("key: ");
    for (int i = 0; i < cipher_len; i++) printf("%d%s", st->key[i], (i + 1 < cipher_len) ? " " : "");
    printf("\n\n");

    // One-liner summary.
    if (cfg->dictionary_present) {
        printf(">>> %.2f, %d, %d, %s, ", score, n_words_found, cfg->cipher_type,
            cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    } else {
        printf(">>> %.2f, %d, %s, ", score, cfg->cipher_type,
            cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    }
    print_text(cipher_indices, cipher_len);
    printf(", ");
    print_text(decrypted, cipher_len);
    printf("\n");
}

static const CipherModel PERMUTATION_MODEL = {
    .name = "transposition",
    .shape = SHAPE_ANNEAL,
    .needs_hist = false,
    .enumerate_configs = permutation_enumerate,
    .key_len = NULL,
    .seed = permutation_seed,
    .perturb = permutation_perturb,
    .copy_state = permutation_copy,
    .decrypt = permutation_decrypt,
    .report = permutation_report,
    .report_verbose = permutation_report_verbose,
};

void solve_general_transposition(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str; // ciphertext is carried as cipher_indices.

    if (cipher_len < 3) {
        printf("\n\nERROR: ciphertext too short for a transposition solve.\n\n");
        return ;
    }

    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    run_solver(&PERMUTATION_MODEL, &ctx);
}


// =====================================================================
//  Dedicated columnar transposition solver (TRANSCOL / TRANSCOL2)
//
//  Where solve_general_transposition hill-climbs the full N-length
//  permutation key and leans on a structure-score guard, this solver
//  optimizes only the small per-stage column-order permutation (length
//  K, the column count). The search space is K! (or K1!*K2! for double),
//  every candidate is a genuine columnar layout by construction, and a
//  column swap maps one-to-one onto the key -- the AZDecrypt approach.
// =====================================================================

// Decrypt one or two stacked columnar stages. cipher[] -> out[].
// Encryption applies stage 0 then stage 1, so we invert stage 1 then stage 0.
static void decrypt_columnar_stages(int cipher[], int len, int nstages,
    int K[2], int order[2][MAX_COLS], int dir[2], int out[]) {
    if (nstages == 1) {
        decrypt_columnar(cipher, len, K[0], order[0], dir[0], out);
    } else {
        int tmp[MAX_CIPHER_LENGTH];
        decrypt_columnar(cipher, len, K[1], order[1], dir[1], tmp);  // undo outer (2nd applied)
        decrypt_columnar(tmp,    len, K[0], order[0], dir[0], out);  // undo inner (1st applied)
    }
}

// Perturb a single stage's column order with one permutation-preserving move
// (swap dominant, plus short reverse and short block-move). The direction is
// only flipped when the user asked to search both (search_dir == COL_READ_BOTH);
// otherwise it stays pinned to the requested read direction.
static void perturbate_column_order(int order[], int K, int *dir, int search_dir) {
    if (search_dir == COL_READ_BOTH && frand() < 0.05) {
        *dir = 1 - *dir;
        return;
    }
    if (K < 2) return;

    double r = frand();
    if (r < 0.70) {
        // Swap two columns (the dominant move).
        int a = rand_int(0, K), b = rand_int(0, K);
        int t = order[a]; order[a] = order[b]; order[b] = t;
    } else if (r < 0.85) {
        // Reverse a short segment of the order.
        int max_blk = min(K, 8);
        int blk = rand_int(2, max_blk + 1);
        int s = rand_int(0, K - blk + 1);
        for (int a = s, b = s + blk - 1; a < b; a++, b--) {
            int t = order[a]; order[a] = order[b]; order[b] = t;
        }
    } else {
        // Cut a short block and re-insert it elsewhere (a range rotation).
        int max_blk = min(K, 8);
        int blk = rand_int(1, max_blk + 1);
        int s = rand_int(0, K - blk + 1);
        int d = rand_int(0, K - blk + 1);
        if (d == s) return;
        int tmp[8];
        for (int a = 0; a < blk; a++) tmp[a] = order[s + a];
        if (d < s) {
            for (int a = s - 1; a >= d; a--) order[a + blk] = order[a];
        } else {
            for (int a = s + blk; a < d + blk; a++) order[a - blk] = order[a];
        }
        for (int a = 0; a < blk; a++) order[d + a] = tmp[a];
    }
}

// Seed a fresh restart: random column order(s), direction(s) per read_direction.
static void columnar_seed(ColossusConfig *cfg, int nstages,
    int K[2], int order[2][MAX_COLS], int dir[2]) {
    for (int s = 0; s < nstages; s++) {
        for (int c = 0; c < K[s]; c++) order[s][c] = c;
        shuffle(order[s], K[s]);
        dir[s] = (cfg->read_direction == COL_READ_BOTH) ? rand_int(0, 2) : cfg->read_direction;
    }
}

// ---- columnar model (TRANSCOL / TRANSCOL2; cipher-agnostic engine) ---------
// SHAPE_ANNEAL over the per-stage column order. The state lives in SolverState:
//   aux[0] = nstages; aux[1..2] = K per stage; aux[3..4] = read direction per
//   stage; key[] reinterpreted as order[2][MAX_COLS] (stride MAX_COLS).
// Single columnar enumerates one config per column count K (the K-sweep); double
// columnar is a single config that randomises (K1,K2) per restart in seed().

// Column-count search range, clamped to [2, len/2] and the array bound.
static void columnar_krange(const SolverCtx *ctx, int *lo, int *hi) {
    int l = ctx->cfg->min_cols, h = ctx->cfg->max_cols;
    int cap = ctx->cipher_len / 2;
    if (cap < 2) cap = 2;
    if (cap > MAX_COLS) cap = MAX_COLS;
    if (l < 2) l = 2;
    if (h > cap) h = cap;
    if (l > h) l = h;
    *lo = l; *hi = h;
}

static int columnar_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    if (ctx->cfg->cipher_type == TRANSCOL2) {
        out[0].period = 0; out[0].j = 0; out[0].k = 0;
        return 1;                                   // (K1,K2) randomised per restart
    }
    int lo, hi;
    columnar_krange(ctx, &lo, &hi);
    int n = 0;
    for (int K = lo; K <= hi && n < cap; K++) {      // one config per column count
        out[n].period = K; out[n].j = 0; out[n].k = 0;
        n++;
    }
    return n;
}

static void columnar_model_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    int nstages = (ctx->cfg->cipher_type == TRANSCOL2) ? 2 : 1;
    int *K   = &st->aux[1];
    int *dir = &st->aux[3];
    int (*order)[MAX_COLS] = (int (*)[MAX_COLS]) st->key;
    st->aux[0] = nstages;
    if (nstages == 1) {
        K[0] = cc->period;
    } else {
        int lo, hi;
        columnar_krange(ctx, &lo, &hi);
        K[0] = rand_int(lo, hi + 1);
        K[1] = rand_int(lo, hi + 1);
    }
    columnar_seed(ctx->cfg, nstages, K, order, dir);
}

static void columnar_model_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                                   bool *force_primary) {
    (void) cc; (void) force_primary;
    int nstages = st->aux[0];
    int (*order)[MAX_COLS] = (int (*)[MAX_COLS]) st->key;
    int s = (nstages == 1) ? 0 : rand_int(0, 2);
    int dir = st->aux[3 + s];
    perturbate_column_order(order[s], st->aux[1 + s], &dir, ctx->cfg->read_direction);
    st->aux[3 + s] = dir;
}

static void columnar_model_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    (void) cc;
    int nstages = src->aux[0];
    const int (*sord)[MAX_COLS] = (const int (*)[MAX_COLS]) src->key;
    int (*dord)[MAX_COLS] = (int (*)[MAX_COLS]) dst->key;
    dst->aux[0] = nstages;
    for (int s = 0; s < nstages; s++) {
        dst->aux[1 + s] = src->aux[1 + s];          // K
        dst->aux[3 + s] = src->aux[3 + s];          // dir
        int K = src->aux[1 + s];
        for (int c = 0; c < K; c++) dord[s][c] = sord[s][c];
    }
}

static void columnar_model_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                                   int *out, double *score_adjust) {
    (void) cc; (void) score_adjust;
    int nstages = st->aux[0];
    int K[2]   = { st->aux[1], st->aux[2] };
    int dir[2] = { st->aux[3], st->aux[4] };
    int (*order)[MAX_COLS] = (int (*)[MAX_COLS]) st->key;
    decrypt_columnar_stages(ctx->cipher, ctx->cipher_len, nstages, K, order, dir, out);
}

static void columnar_model_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) cc; (void) decrypted;
    int nstages = st->aux[0];
    int K[2]   = { st->aux[1], st->aux[2] };
    int dir[2] = { st->aux[3], st->aux[4] };
    int (*order)[MAX_COLS] = (int (*)[MAX_COLS]) st->key;
    int buf[MAX_CIPHER_LENGTH];
    decrypt_columnar_stages(ctx->cipher, ctx->cipher_len, nstages, K, order, dir, buf);

    double elapsed = ((double) clock() - stats->start_time)/CLOCKS_PER_SEC;
    double n_iter_per_sec = (elapsed > 0.) ? ((double) stats->n_iterations)/elapsed : 0.;
    printf("\n%.2f\t[sec]\n", elapsed);
    printf("%.0fK\t[it/sec]\n", 1.e-3*n_iter_per_sec);
    printf("%d\t[restarts]\n", stats->n_restarts);
    printf("%d\t[backtracks]\n", stats->n_backtracks);
    printf("%d\t[slips]\n", stats->n_slips);
    printf("%.4f\t[entropy]\n", entropy(buf, ctx->cipher_len));
    printf("%.2f\t[score]\n", score);
    for (int s = 0; s < nstages; s++)
        printf("stage %d: K=%d dir=%s\t[params]\n", s + 1, K[s],
            dir[s] == COL_READ_BT ? "bt" : "tb");
    printf("\n");
    print_text(buf, ctx->cipher_len); printf("\n");
    fflush(stdout);
}

static void columnar_model_report(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted) {
    (void) cc;
    ColossusConfig *cfg = ctx->cfg;
    SharedData *shared = ctx->shared;
    int cipher_len = ctx->cipher_len;
    int *cipher_indices = ctx->cipher;
    char *cribtext_str = ctx->cribtext;
    int n_cribs = ctx->n_cribs;
    int nstages = st->aux[0];
    int best_K[2]   = { st->aux[1], st->aux[2] };
    int best_dir[2] = { st->aux[3], st->aux[4] };
    int (*best_order)[MAX_COLS] = (int (*)[MAX_COLS]) st->key;
    int n_words_found = 0;

    if (nstages == 1)
        printf("\ntranscol: single columnar, %d columns, read %s\n",
            best_K[0], best_dir[0] == COL_READ_BT ? "bottom-to-top" : "top-to-bottom");
    else
        printf("\ntranscol2: double columnar, %d x %d columns\n", best_K[0], best_K[1]);

    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < cipher_len; i++) plaintext_string[i] = index_to_char(decrypted[i]);
    plaintext_string[cipher_len] = '\0';

    if (cfg->dictionary_present && shared->dict != NULL) {
        n_words_found = find_dictionary_words(plaintext_string, shared->dict,
            shared->n_dict_words, shared->max_dict_word_len);
    }

    printf("\nResult Score: %.2f | Words: %d\n", score, n_words_found);

    print_text(cipher_indices, cipher_len);
    printf("\n");
    print_text(decrypted, cipher_len);
    printf("\n");
    printf("%s\n", cribtext_str);

    if (PARTIAL_CRIB_MATCH && n_cribs > 0) {
        for (int i = 0; i < cipher_len; i++) {
            if (cribtext_str[i] == '_') {
                printf("_");
            } else {
                int diff = abs(decrypted[i] - (g_char_to_idx[toupper((unsigned char)cribtext_str[i]) & 127]));
                if (diff < 10) printf("%d", diff); else printf("*");
            }
        }
    }
    printf("\n");

    // Recovered column order(s), for reproduction.
    for (int s = 0; s < nstages; s++) {
        printf("stage %d (K=%d, dir=%s) order:", s + 1, best_K[s],
            best_dir[s] == COL_READ_BT ? "bt" : "tb");
        for (int c = 0; c < best_K[s]; c++) printf(" %d", best_order[s][c]);
        printf("\n");
    }
    printf("\n");

    // One-liner summary.
    if (cfg->dictionary_present) {
        printf(">>> %.2f, %d, %d, ", score, n_words_found, cfg->cipher_type);
    } else {
        printf(">>> %.2f, %d, ", score, cfg->cipher_type);
    }
    if (nstages == 1) printf("%d, ", best_K[0]);
    else printf("%d, %d, ", best_K[0], best_K[1]);
    printf("%s, ", cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    print_text(cipher_indices, cipher_len);
    printf(", ");
    print_text(decrypted, cipher_len);
    printf("\n");
}

static const CipherModel COLUMNAR_MODEL = {
    .name = "columnar",
    .shape = SHAPE_ANNEAL,
    .needs_hist = false,
    .enumerate_configs = columnar_enumerate,
    .key_len = NULL,
    .seed = columnar_model_seed,
    .perturb = columnar_model_perturb,
    .copy_state = columnar_model_copy,
    .decrypt = columnar_model_decrypt,
    .report = columnar_model_report,
    .report_verbose = columnar_model_report_verbose,
};

void solve_columnar(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str; // ciphertext is carried as cipher_indices.

    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for a columnar solve.\n\n");
        return ;
    }

    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    run_solver(&COLUMNAR_MODEL, &ctx);
}



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
static void report_transposition(ColossusConfig *cfg, SharedData *shared,
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
static void report_transposition_verbose(const SolverCtx *ctx, double best_score,
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
//  Independent periodic substitution (TYPE indep_periodic)
// =====================================================================
//
// A period-P cipher in which each residue class i % P is enciphered with its OWN,
// INDEPENDENT mixed substitution alphabet (unlike Quagmire, whose columns are all
// shifts of one keyed alphabet). decrypted[i] = map[i % P][cipher[i]], where each
// map[] is a permutation of the runtime alphabet sending a cipher letter to its
// plaintext letter.
//
// The columns CANNOT be solved one at a time: column j read alone is every P-th
// letter of the message and carries no n-gram signal. The only constraint tying
// the P alphabets down is that CONSECUTIVE plaintext letters -- which come from
// DIFFERENT columns -- must form English n-grams. So all P alphabets are climbed
// JOINTLY against the reassembled text. With P alphabets x (alpha-1) d.o.f. this is
// a hard search, so we use simulated annealing + iterated local search (restarts
// that perturb the global best, not just fresh seeds) and frequency-seeded starts.

// Build the plaintext (as indices) from the P per-column maps. Sentinels (<0,
// carried-through spaces/punctuation) pass through unchanged.
static void indep_decrypt(int cipher_indices[], int cipher_len, int period,
    int maps[][ALPHABET_SIZE], int decrypted[]) {
    for (int i = 0; i < cipher_len; i++) {
        int c = cipher_indices[i];
        decrypted[i] = (c >= 0) ? maps[i % period][c] : c;
    }
}

// Frequency-seed each column's map: most-frequent cipher letter in the column ->
// most-frequent English letter, etc. Gives the annealer a sensible starting point.
static void indep_seed(int cipher_indices[], int cipher_len, int period,
    int maps[][ALPHABET_SIZE]) {

    // English letters (runtime alphabet indices) sorted by descending frequency.
    int eng_rank[ALPHABET_SIZE];
    for (int i = 0; i < g_alpha; i++) eng_rank[i] = i;
    for (int a = 0; a < g_alpha; a++)
        for (int b = a + 1; b < g_alpha; b++)
            if (g_monograms[eng_rank[b]] > g_monograms[eng_rank[a]]) {
                int t = eng_rank[a]; eng_rank[a] = eng_rank[b]; eng_rank[b] = t;
            }

    for (int j = 0; j < period; j++) {
        int hist[ALPHABET_SIZE];
        for (int c = 0; c < g_alpha; c++) hist[c] = 0;
        for (int i = j; i < cipher_len; i += period)
            if (cipher_indices[i] >= 0) hist[cipher_indices[i]]++;
        // cipher letters sorted by descending column frequency (stable on ties)
        int crank[ALPHABET_SIZE];
        for (int c = 0; c < g_alpha; c++) crank[c] = c;
        for (int a = 0; a < g_alpha; a++)
            for (int b = a + 1; b < g_alpha; b++)
                if (hist[crank[b]] > hist[crank[a]]) {
                    int t = crank[a]; crank[a] = crank[b]; crank[b] = t;
                }
        for (int r = 0; r < g_alpha; r++) maps[j][crank[r]] = eng_rank[r];
    }
}

// Coordinate ascent: fully local-optimize ONE column's alphabet (best-improving
// pairwise swaps to convergence) holding the other columns fixed. This is the move
// that breaks the coordination barrier -- single random swaps barely move the score
// while neighbouring columns are still wrong, but greedily perfecting one column
// against the (partially correct) others gives a real gradient. Returns the score.
static double indep_column_opt(ColossusConfig *cfg,
    int cipher_indices[], int cipher_len, int period, int j,
    int maps[][ALPHABET_SIZE], int crib_indices[], int crib_positions[], int n_cribs,
    float *ngram_data, int decrypted[], double cur_score) {

    bool improved = true;
    while (improved) {
        improved = false;
        for (int a = 0; a < g_alpha; a++) {
            for (int b = a + 1; b < g_alpha; b++) {
                int t = maps[j][a]; maps[j][a] = maps[j][b]; maps[j][b] = t;
                indep_decrypt(cipher_indices, cipher_len, period, maps, decrypted);
                double sc = state_score(decrypted, cipher_len,
                    crib_indices, crib_positions, n_cribs, ngram_data, cfg->ngram_size,
                    cfg->weight_ngram, cfg->weight_crib, cfg->weight_ioc, cfg->weight_entropy);
                if (sc > cur_score) { cur_score = sc; improved = true; }
                else { t = maps[j][a]; maps[j][a] = maps[j][b]; maps[j][b] = t; }
            }
        }
    }
    return cur_score;
}

static double shotgun_indep_climber(ColossusConfig *cfg,
    int cipher_indices[], int cipher_len, int period,
    int crib_indices[], int crib_positions[], int n_cribs,
    float *ngram_data, int best_decrypted[], int best_maps[][ALPHABET_SIZE]) {

    int cur[MAX_COLS][ALPHABET_SIZE], loc[MAX_COLS][ALPHABET_SIZE];
    int seed[MAX_COLS][ALPHABET_SIZE];
    int decrypted[MAX_CIPHER_LENGTH];
    double best_score = 0., current_score = 0.;
    bool have_best = false;
    size_t state_bytes = (size_t) period * ALPHABET_SIZE * sizeof(int);
    (void) loc;

    indep_seed(cipher_indices, cipher_len, period, seed);

    clock_t start_time = clock();
    long n_iterations = 0, n_slips = 0, n_backtracks = 0;
    double elapsed, n_iter_per_sec, entropy_score;

    for (long rs = 0; rs < cfg->n_restarts; rs++) {

        if (have_best && frand() < cfg->backtracking_probability) {
            // Iterated local search: perturb the global best (basin hopping).
            memcpy(cur, best_maps, state_bytes);
            int kicks = rand_int(3, 9);
            for (int k = 0; k < kicks; k++) {
                int j = rand_int(0, period), a = rand_int(0, g_alpha), b = rand_int(0, g_alpha);
                int t = cur[j][a]; cur[j][a] = cur[j][b]; cur[j][b] = t;
            }
            n_backtracks += 1;
        } else {
            // Fresh frequency-seeded start, lightly shuffled for diversity.
            memcpy(cur, seed, state_bytes);
            for (int k = 0; k < (int)(rs % 25); k++) {
                int j = rand_int(0, period), a = rand_int(0, g_alpha), b = rand_int(0, g_alpha);
                int t = cur[j][a]; cur[j][a] = cur[j][b]; cur[j][b] = t;
            }
        }
        (void) n_slips;
        indep_decrypt(cipher_indices, cipher_len, period, cur, decrypted);
        current_score = state_score(decrypted, cipher_len,
            crib_indices, crib_positions, n_cribs, ngram_data, cfg->ngram_size,
            cfg->weight_ngram, cfg->weight_crib, cfg->weight_ioc, cfg->weight_entropy);

        // Local search = coordinate-ascent sweeps over the columns: optimize each
        // column fully given the others, repeating until a whole sweep makes no
        // progress. Columns are visited in random order each sweep. n_hill_climbs
        // caps the number of sweeps.
        int order[MAX_COLS];
        for (int j = 0; j < period; j++) order[j] = j;
        int max_sweeps = cfg->n_hill_climbs > 0 ? cfg->n_hill_climbs : 1;
        if (max_sweeps > 200) max_sweeps = 200;   // coordinate ascent converges fast
        for (int sweep = 0; sweep < max_sweeps; sweep++) {
            for (int x = period - 1; x > 0; x--) {   // shuffle column order
                int y = rand_int(0, x + 1); int t = order[x]; order[x] = order[y]; order[y] = t;
            }
            double before = current_score;
            for (int jj = 0; jj < period; jj++) {
                n_iterations += 1;
                current_score = indep_column_opt(cfg, cipher_indices, cipher_len, period,
                    order[jj], cur, crib_indices, crib_positions, n_cribs,
                    ngram_data, decrypted, current_score);
            }
            if (current_score <= before + 1.e-9) break;   // converged
        }

        if (!have_best || current_score > best_score) {
            best_score = current_score;
            memcpy(best_maps, cur, state_bytes);
            have_best = true;
            if (cfg->verbose) {
                indep_decrypt(cipher_indices, cipher_len, period, best_maps, decrypted);
                entropy_score = entropy(decrypted, cipher_len);
                elapsed = ((double) clock() - start_time)/CLOCKS_PER_SEC;
                n_iter_per_sec = (elapsed > 0.) ? ((double) n_iterations)/elapsed : 0.;
                printf("\n%.2f\t[sec]\n%.0fK\t[col-opts/sec]\n%ld\t[restarts]\n%ld\t[backtracks]\n"
                       "%.4f\t[entropy]\nperiod %d\t[params]\n%.2f\t[score]\n",
                    elapsed, 1.e-3*n_iter_per_sec, rs, n_backtracks,
                    entropy_score, period, best_score);
                // The N independent alphabets (each row maps cipher A.. -> plaintext),
                // mirroring how the Quagmire climber prints its keyed alphabets.
                for (int j = 0; j < period; j++) {
                    printf("alphabet %d: ", j);
                    for (int c = 0; c < g_alpha; c++) printf("%c", index_to_char(best_maps[j][c]));
                    printf("\n");
                }
                printf("\n");
                print_text(decrypted, cipher_len); printf("\n"); fflush(stdout);
            }
        }
    }

    indep_decrypt(cipher_indices, cipher_len, period, best_maps, best_decrypted);
    return best_score;
}

void solve_indep_periodic(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;

    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for an independent-periodic solve.\n\n");
        return ;
    }

    // Candidate periods. With -cyclewordlen, use it; otherwise estimate them by
    // columnar-IoC the same way the periodic polyalphabetic ciphers do (each
    // residue class mod P is monoalphabetic, so the IoC peaks at the true P).
    int periods[MAX_CYCLEWORD_LEN];
    int n_periods = 0;
    if (cfg->cycleword_len_present) {
        periods[n_periods++] = cfg->cycleword_len;
    } else {
        estimate_cycleword_lengths(cipher_indices, cipher_len,
            cfg->max_cycleword_len, cfg->n_sigma_threshold, cfg->ioc_threshold,
            &n_periods, periods, cfg->verbose);
        if (n_periods == 0) {
            printf("\nNo periodicities found above threshold; nothing to attack.\n");
            return ;
        }
    }

    int best_decrypted[MAX_CIPHER_LENGTH], best_maps[MAX_COLS][ALPHABET_SIZE];
    int try_decrypted[MAX_CIPHER_LENGTH], try_maps[MAX_COLS][ALPHABET_SIZE];
    double best_score = -1.e18;
    int best_period = periods[0];

    for (int pi = 0; pi < n_periods; pi++) {
        int p = periods[pi];
        if (p < 1 || p > MAX_COLS || p > cipher_len / 2) continue;
        double sc = shotgun_indep_climber(cfg, cipher_indices, cipher_len, p,
            crib_indices, crib_positions, n_cribs,
            shared->ngram_data, try_decrypted, try_maps);
        if (cfg->verbose)
            printf("\nperiod %d: score %.2f\n", p, sc);
        if (sc > best_score) {
            best_score = sc;
            best_period = p;
            memcpy(best_decrypted, try_decrypted, (size_t) cipher_len * sizeof(int));
            memcpy(best_maps, try_maps, (size_t) p * ALPHABET_SIZE * sizeof(int));
        }
    }

    char param_summary[64];
    snprintf(param_summary, sizeof(param_summary), "period=%d", best_period);
    report_transposition(cfg, shared, cipher_indices, cipher_len, best_decrypted,
        best_score, cribtext_str, n_cribs, param_summary);

    // Recovered per-column alphabets (cipher A..Z -> plaintext), for reproduction.
    for (int j = 0; j < best_period; j++) {
        printf("col %d:", j);
        for (int c = 0; c < g_alpha; c++) printf("%c", index_to_char(best_maps[j][c]));
        printf("\n");
    }
}


// =====================================================================
//  Homophonic substitution solver (TYPE homophonic)
// =====================================================================
//
// A monoalphabetic-in-meaning substitution whose CIPHERTEXT alphabet is larger than
// the plaintext alphabet: each plaintext letter is enciphered by any of several
// distinct ciphertext symbols (its homophones), chosen to flatten the ciphertext
// frequency profile (Zodiac-408 style). The ciphertext is decoded (decode_cipher)
// into a sequence of symbol ids 0..N-1 indexing a SymbolTable; the key is the
// many-to-one map symbol_id -> plaintext letter, so decrypted[i] = key[cipher[i]].
//
// There is no period or transposition to recover -- positions are preserved -- so the
// solver just hill-climbs the N-entry map against the n-gram score, exactly like the
// other CipherModels. It plugs into the shared shotgun/anneal engine (run_solver):
// SHAPE_ANNEAL (Metropolis) acceptance, shotgun restarts, backtracking. Seeds are
// frequency-flattening (symbols drawn from the English monogram distribution, so
// common letters naturally receive more homophones); the move set reassigns one
// symbol's letter (dominant) or swaps two symbols' letters.

typedef struct {
    SymbolTable *tab;     // the interned ciphertext symbols (for display)
    int          n_symbols;
} HomophonicScratch;

// One config: the whole map is climbed at once. period carries the key length.
static int homophonic_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    const HomophonicScratch *h = (const HomophonicScratch *) ctx->model_scratch;
    if (cap < 1) return 0;
    out[0].period = h->n_symbols;
    out[0].j = 0; out[0].k = 0; out[0].aux[0] = 0; out[0].aux[1] = 0;
    return 1;
}

// Frequency-flattening seed: draw each symbol's plaintext letter from the English
// monogram distribution. Randomised (so shotgun restarts diversify) yet biased so the
// recovered ciphertext frequencies start out roughly English-shaped.
static void homophonic_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    (void) ctx;
    int n = cc->period;
    double cum[ALPHABET_SIZE], total = 0.;
    for (int c = 0; c < g_alpha; c++) { total += g_monograms[c]; cum[c] = total; }
    for (int s = 0; s < n; s++) {
        double r = frand() * total;
        int c = 0;
        while (c < g_alpha - 1 && r > cum[c]) c++;
        st->key[s] = c;
    }
    st->key_len = n;
}

// The anti-collapse penalty: chi-squared of the decrypted letter-frequency profile
// against English monograms. Unlike a 26->26 substitution (a bijection, which cannot
// pile multiple symbols onto one letter), a homophonic map is free to fold many symbols
// onto E/T/A... to tile high-frequency n-grams -- a fixed point that out-scores the
// true plaintext on raw n-grams alone. Penalising the resulting (wildly non-English)
// monogram distribution removes that fixed point. Returned as a positive quantity to be
// SUBTRACTED from the score.
static double homophonic_penalty(const SolverCtx *ctx, const int *dec) {
    if (ctx->cfg->weight_monogram <= 1.e-9) return 0.0;
    return ctx->cfg->weight_monogram * chi_squared((int *) dec, ctx->cipher_len);
}

// Score the map `key` by decrypting into `dec` and running the shared n-gram (+ crib)
// score minus the anti-collapse penalty. Used by the greedy move below to pick a
// symbol's best plaintext letter; must match the engine's score (decrypt's
// score_adjust applies the same penalty) so greedy and acceptance optimise the same
// objective.
static double homophonic_score(const SolverCtx *ctx, const int *key, int *dec) {
    ColossusConfig *cfg = ctx->cfg;
    for (int i = 0; i < ctx->cipher_len; i++) dec[i] = key[ctx->cipher[i]];
    return state_score(dec, ctx->cipher_len, ctx->crib_indices, ctx->crib_positions,
        ctx->n_cribs, ctx->ngram_data, cfg->ngram_size,
        cfg->weight_ngram, cfg->weight_crib, cfg->weight_ioc, cfg->weight_entropy)
        - homophonic_penalty(ctx, dec);
}

// Neighbour move. The dominant move is a GREEDY coordinate step -- pick one symbol and
// set it to the plaintext letter that maximises the score with every other symbol
// held fixed. Simple random reassignment alone collapses homophonic climbs into a
// high-n-gram-score but wrong fixed point (many symbols folded onto E/T/A...); the
// greedy step gives a real gradient on each symbol, the way the independent-periodic
// solver coordinate-optimises a whole column. Random reassignment and pair swaps are
// retained at low probability for exploration / to escape the greedy basin.
static void homophonic_perturb(const SolverCtx *ctx, const SolverConfig *cc,
                               SolverState *st, bool *force_primary) {
    (void) force_primary;
    static int dec[MAX_CIPHER_LENGTH];
    int n = cc->period;
    if (n < 1) return;
    double r = frand();
    if (r < 0.65) {
        // Greedy coordinate step: best plaintext letter for one symbol.
        int s = rand_int(0, n);
        int best_c = st->key[s];
        double best = -1.e18;
        for (int c = 0; c < g_alpha; c++) {
            st->key[s] = c;
            double sc = homophonic_score(ctx, st->key, dec);
            if (sc > best) { best = sc; best_c = c; }
        }
        st->key[s] = best_c;
    } else if (r < 0.85) {
        // Letter-class swap: exchange the WHOLE homophone classes of two plaintext
        // letters at once. Greedy single-symbol moves cannot cross a two-letter swap
        // (e.g. W<->M, near-identical monogram frequency), since flipping one symbol
        // first makes it worse; swapping both classes together crosses that barrier.
        int a = rand_int(0, g_alpha), b = rand_int(0, g_alpha);
        if (a != b)
            for (int s = 0; s < n; s++) {
                if (st->key[s] == a) st->key[s] = b;
                else if (st->key[s] == b) st->key[s] = a;
            }
    } else if (n >= 2 && r < 0.93) {
        // Swap two symbols' letters (fine-grained exploration).
        int a = rand_int(0, n), b = rand_int(0, n);
        int t = st->key[a]; st->key[a] = st->key[b]; st->key[b] = t;
    } else {
        // Random reassignment (escape).
        st->key[rand_int(0, n)] = rand_int(0, g_alpha);
    }
}

static void homophonic_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    for (int i = 0; i < cc->period; i++) dst->key[i] = src->key[i];
}

static void homophonic_decrypt(const SolverCtx *ctx, const SolverConfig *cc,
                               SolverState *st, int *out, double *score_adjust) {
    (void) cc;
    for (int i = 0; i < ctx->cipher_len; i++) out[i] = st->key[ctx->cipher[i]];
    *score_adjust = -homophonic_penalty(ctx, out);   // engine adds this to state_score
}

static void homophonic_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) cc; (void) st;
    const HomophonicScratch *h = (const HomophonicScratch *) ctx->model_scratch;
    char params[64];
    snprintf(params, sizeof(params), "symbols=%d", h->n_symbols);
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void homophonic_report(const SolverCtx *ctx, const SolverConfig *cc,
                              const SolverState *st, double score, int *decrypted) {
    (void) cc;
    ColossusConfig *cfg = ctx->cfg;
    const HomophonicScratch *h = (const HomophonicScratch *) ctx->model_scratch;
    SymbolTable *tab = h->tab;
    int n = h->n_symbols, len = ctx->cipher_len;

    int n_words_found = 0;
    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < len; i++) plaintext_string[i] = index_to_char(decrypted[i]);
    plaintext_string[len] = '\0';
    if (cfg->dictionary_present && ctx->shared->dict != NULL)
        n_words_found = find_dictionary_words(plaintext_string, ctx->shared->dict,
            ctx->shared->n_dict_words, ctx->shared->max_dict_word_len);

    printf("\nResult Score: %.2f | Words: %d | symbols=%d\n", score, n_words_found, n);

    print_cipher(ctx->cipher, len, tab);
    printf("\n");
    print_text(decrypted, len);
    printf("\n");
    printf("%s\n", ctx->cribtext);

    // Recovered homophone classes: each plaintext letter and the symbols decoding to it.
    printf("\nhomophone key (plaintext <- symbols):\n");
    for (int c = 0; c < g_alpha; c++) {
        int any = 0;
        for (int s = 0; s < n; s++) if (st->key[s] == c) {
            if (!any) { printf("  %c <-", index_to_char(c)); any = 1; }
            printf(" %s", tab->tokens[s]);
        }
        if (any) printf("\n");
    }

    // One-liner summary: >>> score, [words,] type, symbols=N, file, CIPHER, PLAINTEXT
    if (cfg->dictionary_present)
        printf(">>> %.2f, %d, %d, symbols=%d, ", score, n_words_found, cfg->cipher_type, n);
    else
        printf(">>> %.2f, %d, symbols=%d, ", score, cfg->cipher_type, n);
    printf("%s, ", cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    print_cipher(ctx->cipher, len, tab);
    printf(", ");
    print_text(decrypted, len);
    printf("\n");
}

static const CipherModel HOMOPHONIC_MODEL = {
    .name = "homophonic", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = homophonic_enumerate, .key_len = NULL,
    .seed = homophonic_seed, .perturb = homophonic_perturb, .copy_state = homophonic_copy,
    .decrypt = homophonic_decrypt, .report = homophonic_report,
    .report_verbose = homophonic_report_verbose,
};

void solve_homophonic(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SymbolTable *tab) {

    (void) ciphertext_str;
    if (cipher_len < 4 || tab == NULL || tab->n < 1) {
        printf("\n\nERROR: ciphertext too short for a homophonic solve.\n\n");
        return ;
    }
    if (cfg->verbose)
        printf("\nhomophonic: %d positions, %d distinct symbols\n", cipher_len, tab->n);

    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    HomophonicScratch scratch = { tab, tab->n };
    ctx.model_scratch = &scratch;
    run_solver(&HOMOPHONIC_MODEL, &ctx);
}


// =====================================================================
//  Rail fence solver (TYPE railfence) -- covers variant rail fence too
// =====================================================================
//
// The key space is tiny (rail count x starting phase), so we enumerate it
// exhaustively rather than hill-climb: for each rail count in [min_cols, max_cols]
// and every starting phase offset, invert the zigzag with decrypt_railfence and
// keep the highest-scoring plaintext. -variant swaps the read/write directions.
// SWEEP model: each (rails, offset) cell is one candidate (key_len 0 => no climb).
// period = rails, aux[0] = starting phase offset.
static int railfence_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int lo = max(2, ctx->cfg->min_cols);
    int hi = min(ctx->cfg->max_cols, ctx->cipher_len - 1);
    if (hi < lo) hi = lo;
    int n = 0;
    for (int rails = lo; rails <= hi; rails++) {
        int P = 2 * (rails - 1);                 // number of distinct phases
        for (int offset = 0; offset < P && n < cap; offset++) {
            out[n].period = rails; out[n].aux[0] = offset; out[n].j = 0; out[n].k = 0;
            n++;
        }
    }
    return n;
}
static int sweep_keylen(const SolverCtx *ctx, const SolverConfig *cc) { (void)ctx; (void)cc; return 0; }
static void sweep_noop_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) { (void)ctx; (void)cc; (void)st; }
static void sweep_noop_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) { (void)cc; (void)src; (void)dst; }

static void railfence_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                              int *out, double *adj) {
    (void) st; (void) adj;
    decrypt_railfence(ctx->cipher, ctx->cipher_len, cc->period, cc->aux[0],
        ctx->cfg->variant ? 1 : 0, out);
}
static void railfence_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void railfence_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                             double score, int *decrypted) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    printf("\nrailfence: %d rails, starting phase %d%s\n",
        cc->period, cc->aux[0], variant ? " (variant: read/write swapped)" : "");
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const CipherModel RAILFENCE_MODEL = {
    .name = "railfence", .shape = SHAPE_SHOTGUN, .needs_hist = false,
    .enumerate_configs = railfence_enumerate, .key_len = sweep_keylen,
    .seed = sweep_noop_seed, .perturb = NULL, .copy_state = sweep_noop_copy,
    .decrypt = railfence_decrypt, .report = railfence_report,
    .report_verbose = railfence_report_verbose,
};

void solve_railfence(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str; // ciphertext is carried as cipher_indices.

    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for a rail fence solve.\n\n");
        return ;
    }

    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    run_solver(&RAILFENCE_MODEL, &ctx);
}


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

typedef struct {
    void (*seed_cb)(int *key, int key_len);
    void (*move_cb)(int *key, int key_len);
} TransKeyOps;

static void tkey_seed(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st) {
    ((const TransKeyOps *) ctx->model_scratch)->seed_cb(st->key, cc->period);
}
static void tkey_perturb(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st, bool *fp) {
    (void) fp;
    ((const TransKeyOps *) ctx->model_scratch)->move_cb(st->key, cc->period);
}
static void tkey_copy(const SolverConfig *cc, const SolverState *src, SolverState *dst) {
    for (int i = 0; i < cc->period; i++) dst->key[i] = src->key[i];
}

// Neighbour move shared by the permutation-key types (swap dominant, with short
// reverses and block moves), preserving the permutation property.
static void perm_move(int *key, int K) {
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
static void perm_seed(int *key, int K) {
    for (int i = 0; i < K; i++) key[i] = i;
    shuffle(key, K);
}


// =====================================================================
//  Amsco solver (TYPE amsco)
// =====================================================================

// period = K (column count = key length); aux[0] = start-chunk (1 or 2).
static int amsco_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int lo = max(2, ctx->cfg->min_cols), hi = min(ctx->cfg->max_cols, ctx->cipher_len / 2);
    if (hi < lo) hi = lo;
    int n = 0;
    for (int K = lo; K <= hi; K++)
        for (int start = 1; start <= 2 && n < cap; start++) {
            out[n].period = K; out[n].aux[0] = start; out[n].j = 0; out[n].k = 0;
            n++;
        }
    return n;
}
static void amsco_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                          int *out, double *adj) {
    (void) adj;
    decrypt_amsco(ctx->cipher, ctx->cipher_len, cc->period, st->key,
        cc->aux[0] /* start */, ctx->cfg->variant ? 1 : 0, out);
}
static void amsco_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "K=%d start=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void amsco_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                         double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int K = cc->period, start = cc->aux[0];
    printf("\namsco: %d columns, start-chunk %d%s\norder:", K, start,
        variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < K; c++) printf(" %d", st->key[c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "K=%d start=%d%s", K, start, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps AMSCO_OPS = { perm_seed, perm_move };
static const CipherModel AMSCO_MODEL = {
    .name = "amsco", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = amsco_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = amsco_decrypt, .report = amsco_report,
    .report_verbose = amsco_report_verbose,
};

void solve_amsco(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    if (cipher_len < 4) {
        printf("\n\nERROR: ciphertext too short for an Amsco solve.\n\n");
        return ;
    }
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &AMSCO_OPS;
    run_solver(&AMSCO_MODEL, &ctx);
}


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


// Integer square root with exact-square test: returns N where N*N == x, else -1.
static int exact_isqrt(int x) {
    if (x < 0) return -1;
    int n = (int)(sqrt((double)x) + 0.5);
    for (int d = -1; d <= 1; d++)
        if ((n + d) >= 0 && (n + d) * (n + d) == x) return n + d;
    return -1;
}


// =====================================================================
//  Redefence solver (TYPE redefence)
// =====================================================================

// period = rails (rail read-order permutation length); aux[0] = starting phase.
static int redefence_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    int lo = max(2, ctx->cfg->min_cols), hi = min(ctx->cfg->max_cols, ctx->cipher_len - 1);
    if (hi < lo) hi = lo;
    int n = 0;
    for (int rails = lo; rails <= hi; rails++) {
        int P = 2 * (rails - 1);
        for (int offset = 0; offset < P && n < cap; offset++) {
            out[n].period = rails; out[n].aux[0] = offset; out[n].j = 0; out[n].k = 0;
            n++;
        }
    }
    return n;
}
static void redefence_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                              int *out, double *adj) {
    (void) adj;
    decrypt_redefence(ctx->cipher, ctx->cipher_len, cc->period /* rails */,
        cc->aux[0] /* offset */, st->key, ctx->cfg->variant ? 1 : 0, out);
}
static void redefence_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s",
        cc->period, cc->aux[0], variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void redefence_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                             double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int rails = cc->period, offset = cc->aux[0];
    printf("\nredefence: %d rails, phase %d%s\norder:", rails, offset,
        variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < rails; c++) printf(" %d", st->key[c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "rails=%d off=%d%s", rails, offset, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps REDEFENCE_OPS = { perm_seed, perm_move };
static const CipherModel REDEFENCE_MODEL = {
    .name = "redefence", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = redefence_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = redefence_decrypt, .report = redefence_report,
    .report_verbose = redefence_report_verbose,
};

void solve_redefence(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    if (cipher_len < 4) { printf("\n\nERROR: ciphertext too short for a redefence solve.\n\n"); return; }
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &REDEFENCE_OPS;
    run_solver(&REDEFENCE_MODEL, &ctx);
}


// =====================================================================
//  Cadenus solver (TYPE cadenus) -- 25 rows, K = len/25 columns
// =====================================================================
//
// The climbed key packs two halves: key[0..K-1] is the column read-order
// permutation, key[K..2K-1] is the per-column upward rotation in [0,25). Decoupling
// them lets the search subsume any keyword/alphabet convention.

static void cadenus_seed(int *key, int key_len) {
    int K = key_len / 2;
    for (int i = 0; i < K; i++) key[i] = i;
    shuffle(key, K);
    for (int i = 0; i < K; i++) key[K + i] = rand_int(0, 25);   // Cadenus has 25 rows
}
static void cadenus_move(int *key, int key_len) {
    int K = key_len / 2;
    if (frand() < 0.55) perm_move(key, K);                       // reorder columns
    else key[K + rand_int(0, K)] = rand_int(0, 25);              // re-rotate one column
}

// Single config: K = len/25 columns, period = 2K packs column order + rotations.
static int cadenus_enumerate(const SolverCtx *ctx, SolverConfig *out, int cap) {
    (void) cap;
    int len = ctx->cipher_len;
    if (len % 25 != 0) {
        printf("\n\nERROR: Cadenus needs a length that is a multiple of 25 (got %d).\n\n", len);
        return 0;
    }
    int K = len / 25;
    if (K < 2 || 2 * K > MAX_TRANS_KEY) {
        printf("\n\nERROR: Cadenus column count %d out of range.\n\n", K);
        return 0;
    }
    out[0].period = 2 * K; out[0].j = 0; out[0].k = 0;
    return 1;
}
static void cadenus_decrypt(const SolverCtx *ctx, const SolverConfig *cc, SolverState *st,
                            int *out, double *adj) {
    (void) adj;
    int K = cc->period / 2;
    decrypt_cadenus(ctx->cipher, ctx->cipher_len, K, st->key, st->key + K,
        ctx->cfg->variant ? 1 : 0, out);
}
static void cadenus_report_verbose(const SolverCtx *ctx, const SolverConfig *cc,
        const SolverState *st, double score, int *decrypted, const EngineStats *stats) {
    (void) st;
    int variant = ctx->cfg->variant ? 1 : 0;
    char params[64];
    snprintf(params, sizeof(params), "K=%d%s", cc->period / 2, variant ? " var" : "");
    report_transposition_verbose(ctx, score, decrypted, stats, params);
}

static void cadenus_report(const SolverCtx *ctx, const SolverConfig *cc, const SolverState *st,
                           double score, int *decrypted) {
    int variant = ctx->cfg->variant ? 1 : 0;
    int K = cc->period / 2;
    printf("\ncadenus: %d columns x 25 rows%s\norder:", K, variant ? " (variant: read/write swapped)" : "");
    for (int c = 0; c < K; c++) printf(" %d", st->key[c]);
    printf("\nrot:");
    for (int c = 0; c < K; c++) printf(" %d", st->key[K + c]);
    printf("\n");
    char params[64];
    snprintf(params, sizeof(params), "K=%d%s", K, variant ? " var" : "");
    report_transposition(ctx->cfg, ctx->shared, ctx->cipher, ctx->cipher_len, decrypted,
        score, ctx->cribtext, ctx->n_cribs, params);
}
static const TransKeyOps CADENUS_OPS = { cadenus_seed, cadenus_move };
static const CipherModel CADENUS_MODEL = {
    .name = "cadenus", .shape = SHAPE_ANNEAL, .needs_hist = false,
    .enumerate_configs = cadenus_enumerate, .key_len = NULL,
    .seed = tkey_seed, .perturb = tkey_perturb, .copy_state = tkey_copy,
    .decrypt = cadenus_decrypt, .report = cadenus_report,
    .report_verbose = cadenus_report_verbose,
};

void solve_cadenus(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs) {

    (void) ciphertext_str;
    SolverCtx ctx = make_solver_ctx(cfg, shared, cribtext_str,
        cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs);
    ctx.model_scratch = (void *) &CADENUS_OPS;
    run_solver(&CADENUS_MODEL, &ctx);
}


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




// derive_optimal_cycleword() lives in optimal_cycleword.c (prototype in the
// shared header). It deterministically solves each period column for the key
// character that best matches English monogram frequencies.


int get_matrix_rotate_old_idx(int target_idx, int len, int width, int clockwise) {
    if (width <= 1 || width >= len) return target_idx;
    
    int R = (len + width - 1) / width;
    int W = width;
    int current_idx = 0;

    if (clockwise) {
        // Trace left-to-right, bottom-to-top
        for (int c = 0; c < W; c++) {
            for (int r = R - 1; r >= 0; r--) {
                int old_idx = r * W + c;
                if (old_idx < len) {
                    if (current_idx == target_idx) return old_idx;
                    current_idx++;
                }
            }
        }
    } else {
        // Trace right-to-left, top-to-bottom
        for (int c = W - 1; c >= 0; c--) {
            for (int r = 0; r < R; r++) {
                int old_idx = r * W + c;
                if (old_idx < len) {
                    if (current_idx == target_idx) return old_idx;
                    current_idx++;
                }
            }
        }
    }
    return target_idx;
}

int map_crib_to_cipher_pos(ColossusConfig *cfg, int crib_pos, int cipher_len) {
    int pos = crib_pos;

    // Un-map transmatrix (in reverse order of decryption: w2, then w1)
    if (cfg->transmatrix_present) {
        pos = get_matrix_rotate_old_idx(pos, cipher_len, cfg->trans_w2, cfg->trans_clockwise);
        pos = get_matrix_rotate_old_idx(pos, cipher_len, cfg->trans_w1, cfg->trans_clockwise);
    }

    // Un-map transperoffset.
    if (cfg->transperoffset_present) {
        pos = (pos + cfg->trans_offset) % cipher_len;
        if (pos < 0) pos += cipher_len;
        pos = (cfg->trans_period * pos) % cipher_len;
    }

    return pos;
}



bool cribs_satisfied_p(ColossusConfig *cfg, int cipher_indices[], int cipher_len, int crib_indices[], 
    int crib_positions[], int n_cribs, int cycleword_len, bool verbose) {

    int i, j, k, ii, jj, total, column_length, ciphertext_column_indices[MAX_CIPHER_LENGTH], 
        ciphertext_column[MAX_CIPHER_LENGTH], crib_frequencies[ALPHABET_SIZE][ALPHABET_SIZE];
    int mapped_crib_positions[MAX_CIPHER_LENGTH];

    if (n_cribs == 0) return true;

    // Map crib positions to their original ciphertext positions
    for (i = 0; i < n_cribs; i++) {
        mapped_crib_positions[i] = map_crib_to_cipher_pos(cfg, crib_positions[i], cipher_len);
    }

    for (j = 0; j < cycleword_len; j++) {
        if (verbose) {
            printf("\nCOLUMN = %d \n", j);
        }

        k = 0;
        while (cycleword_len*k + j < cipher_len) {
            ciphertext_column_indices[k] = cycleword_len*k + j;
            ciphertext_column[k] = cipher_indices[ciphertext_column_indices[k]];
            k++;
        }
        column_length = k;

        for (i = 0; i < g_alpha; i++) {
            for (k = 0; k < g_alpha; k++) {
                crib_frequencies[i][k] = 0;
            }
        }

        for (i = 0; i < n_cribs; i++) {
            for (k = 0; k < column_length; k++) {
                // Use mapped_crib_positions here instead of crib_positions
                if (mapped_crib_positions[i] == ciphertext_column_indices[k]) {
                    if (verbose) {
                        printf("CT = %c, PT = %c\n", index_to_char(ciphertext_column[k]), index_to_char(crib_indices[i]));
                    }
                    
                    crib_frequencies[crib_indices[i]][ciphertext_column[k]] = 1;

                    for (ii = 0; ii < g_alpha; ii++) {
                        total = 0;
                        for (jj = 0; jj < g_alpha; jj++) {
                            total += crib_frequencies[ii][jj];
                            if (total > 1) {
                                if (verbose) {
                                    printf("\n\nContradiction at col %d, crib char %c\n\n", j, index_to_char(crib_indices[i]));
                                }
                                return false;
                            }
                        }
                    }

                    for (jj = 0; jj < g_alpha; jj++) {
                        total = 0;
                        for (ii = 0; ii < g_alpha; ii++) {
                            total += crib_frequencies[ii][jj];
                            if (total > 1) {
                                if (verbose) {
                                    printf("\n\nContradiction at col %d, crib char %c\n\n", j, index_to_char(crib_indices[i]));
                                }
                                return false;
                            }
                        }
                    }                   
                }
            }
        }
    }
    return true;
}



bool constrain_cycleword(ColossusConfig *cfg, int cipher_indices[], int cipher_len, 
    int crib_indices[], int crib_positions[], int n_cribs, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int cycleword_indices[], int cycleword_len, 
    bool variant, bool verbose) {

    int i, j, k, crib_char, ciphertext_char, posn_keyword, posn_cycleword, 
        indx, crib_cyclewords[MAX_CYCLEWORD_LEN], mapped_pos;

    if (n_cribs == 0) return false; 

    for (i = 0; i < cycleword_len; i++) crib_cyclewords[i] = INACTIVE; 

    for (i = 0; i < cycleword_len; i++) {
        for (j = 0; j < n_cribs; j++) {
            
            mapped_pos = map_crib_to_cipher_pos(cfg, crib_positions[j], cipher_len);
            
            // Check against the mapped ciphertext position
            if (mapped_pos % cycleword_len == i) {
                crib_char = crib_indices[j];
                ciphertext_char = cipher_indices[mapped_pos];
                
                for (k = 0; k < g_alpha; k++) {
                    if (ciphertext_keyword_indices[k] == ciphertext_char) {
                        posn_keyword = k; 
                        break ;
                    }
                }
                for (k = 0; k < g_alpha; k++) {
                    if (plaintext_keyword_indices[k] == crib_char) {
                        posn_cycleword = k; 
                        break ;
                    }
                }

                if (variant) {
                    indx = (posn_cycleword - posn_keyword) % g_alpha;
                } else {
                    indx = (posn_keyword - posn_cycleword) % g_alpha;
                }
                
                if (indx < 0) indx += g_alpha;                    

                if (crib_cyclewords[i] == INACTIVE) {
                    crib_cyclewords[i] = ciphertext_keyword_indices[indx];
                    cycleword_indices[i] = ciphertext_keyword_indices[indx]; 
                } else if (crib_cyclewords[i] != ciphertext_keyword_indices[indx]) { 
                    /*
                    if (verbose) {
                        printf("\n\nContradiction at crib %c, posn %d; rejecting keyword ", 
                            index_to_char(crib_indices[j]), crib_positions[j]);
                    } */
                    return true; 
                }
            }
        }
    }
    return false;
}



void decrypt_state(ColossusConfig *cfg, int cipher_indices[], int cipher_len, 
                   int plaintext_keyword_state[], int ciphertext_keyword_state[], 
                   int cycleword_state[], int cycleword_len, 
                   int decrypted[]) {
                   
    bool is_autokey = ((cfg->cipher_type >= AUTOKEY_0 && cfg->cipher_type <= AUTOKEY_4) || 
        cfg->cipher_type == AUTOKEY_BEAU || cfg->cipher_type == AUTOKEY_PORTA);

    if (cfg->cipher_type == PORTA) { 
        porta_decrypt(decrypted, cipher_indices, cipher_len, 
                     cycleword_state, cycleword_len);
    } else if (cfg->cipher_type == BEAUFORT) { 
        beaufort_decrypt(decrypted, cipher_indices, cipher_len, 
                     cycleword_state, cycleword_len);
    } else if (is_autokey) {
        autokey_decrypt(cfg, decrypted, cipher_indices, cipher_len, 
            plaintext_keyword_state, ciphertext_keyword_state,
            cycleword_state, cycleword_len);
    } else if (cfg->cipher_type == VIGENERE) { 
        vigenere_decrypt(decrypted, cipher_indices, cipher_len, 
                         cycleword_state, cycleword_len, cfg->variant);
    } else {
        // Quagmire I-IV
        quagmire_decrypt(decrypted, cipher_indices, cipher_len, 
            plaintext_keyword_state, ciphertext_keyword_state, 
            cycleword_state, cycleword_len, cfg->variant);
    }

    // Apply transposition. 
    if (cfg->transperoffset_present) {
        transperoffset(decrypted, cipher_len, cfg->trans_period, cfg->trans_offset);
    }

    if (cfg->transmatrix_present) {
        transmatrix(decrypted, cipher_len, cfg->trans_w1, cfg->trans_w2, cfg->trans_clockwise);
    }
}



double state_score(int decrypted[], int cipher_len, 
            int crib_indices[], int crib_positions[], int n_cribs, 
            float *ngram_data, int ngram_size, 
            float weight_ngram, float weight_crib, 
            float weight_ioc, float weight_entropy) {

    double score, decrypted_ngram_score = 0., decrypted_crib_score = 0.;

    if (weight_crib > 1.e-4) {
        decrypted_crib_score = crib_score(decrypted, cipher_len, crib_indices, crib_positions, n_cribs);
    }

    if (weight_ngram > 1.e-4) {
        decrypted_ngram_score = ngram_score(decrypted, cipher_len, ngram_data, ngram_size);
    }

    if (n_cribs > 0) {
        score = weight_ngram * decrypted_ngram_score + weight_crib * decrypted_crib_score;
        score /= weight_ngram + weight_crib;
    } else {
        score = decrypted_ngram_score;
    }

    return score;
}



double crib_score(int text[], int len, int crib_indices[], int crib_positions[], int n_cribs) {
    if (n_cribs == 0) return 0.;
#if PARTIAL_CRIB_MATCH
    int diff;
    double score = 0.;
    for (int i = 0; i < n_cribs; i++) {
        diff = abs(text[crib_positions[i]] - crib_indices[i]);
        if (diff == 0) {
            score += 1.;
        } else {
            score += 1./(1. + diff * diff);
        }
    }
    return score / ((double) n_cribs);
#else
    int n_matches = 0;
    for (int i = 0; i < n_cribs; i++) {
        if (text[crib_positions[i]] == crib_indices[i]) {
            n_matches += 1;
        }
    }
    return ((double) n_matches)/((double) n_cribs);
#endif
}

double ngram_score(int decrypted[], int cipher_len, float *ngram_data, int ngram_size) {
    int index, base;
    double score = 0.;

    // pow(g_alpha, ngram_size) is a positive constant for the whole run
    // (ngram_size never changes), yet was previously recomputed via a libm pow()
    // on EVERY score -- i.e. every hill-climber iteration. Memoize it. pow()
    // returns the identical double for identical args, so the cached value equals
    // the recomputed one bit-for-bit; the score is unchanged.
    static int cached_ngram_size = -1;
    static double scale = 0.;
    if (ngram_size != cached_ngram_size) {
        // Legacy table entries are ~1/n_ngrams, so the historical g_alpha^ngram_size
        // factor brings the mean back to O(1). The log-prob table already holds O(1)
        // log10 values, so it needs no rescaling (scale = 1) -- the score is then a
        // mean log-probability, the AZDecrypt fitness.
        scale = g_ngram_logprob ? 1.0 : pow(g_alpha, ngram_size);
        cached_ngram_size = ngram_size;
    }

    // Rolling base-26 index. The packed window index is little-endian
    //   idx_i = sum_{j=0..n-1} decrypted[i+j] * 26^j,
    // so advancing one position is exact integer arithmetic:
    //   idx_{i+1} = (idx_i - decrypted[i]) / 26 + decrypted[i+n] * 26^(n-1).
    // (idx_i - decrypted[i]) is divisible by 26 -- every surviving term carries a
    // factor of 26 -- so the integer division is exact and idx_{i+1} is the SAME
    // integer the old per-window inner loop produced. Identical index => identical
    // ngram_data[] element => identical sum in the same order: bit-for-bit unchanged.
    // This collapses the per-window O(ngram_size) multiply-add loop to O(1).
    // Windows containing a negative sentinel (a space or punctuation character
    // carried through from the ciphertext) are skipped -- only n-grams that lie
    // wholly inside a run of letters are scored. `bad` counts the sentinels in the
    // current window; a sentinel contributes 0 to the packed index so the rolling
    // base-26 arithmetic stays valid across it. When the text is all letters `bad`
    // is always 0 and every operation is bit-identical to the unguarded version.
    int n_windows = cipher_len - ngram_size + 1;
    if (n_windows > 0) {
        int top = 1;                    // 26^(ngram_size-1)
        for (int j = 0; j < ngram_size - 1; j++) top *= g_alpha;

        index = 0;
        base = 1;
        int bad = 0;
        for (int j = 0; j < ngram_size; j++) {
            int v = decrypted[j];
            if (v < 0) { bad++; v = 0; }
            index += v*base;
            base *= g_alpha;
        }
        if (bad == 0) score += ngram_data[index];

        for (int i = 1; i < n_windows; i++) {
            int out_v = decrypted[i - 1];
            int in_v  = decrypted[i + ngram_size - 1];
            if (out_v < 0) { bad--; out_v = 0; }
            int in_iv = in_v;
            if (in_v < 0) { bad++; in_iv = 0; }
            index = (index - out_v) / g_alpha + in_iv * top;
            if (bad == 0) score += ngram_data[index];
        }
    }
    score = scale*score/(cipher_len - ngram_size);
    return score;
}

void perturbate_cycleword(int state[], int max, int len) {
    int i = rand_int(0, len);
    state[i] = rand_int(0, max);
}

void perturbate_keyword(int state[], int len, int keyword_len) {
    int i, j, k, l, temp;

    if (frand() < 0.2) { 
        // Swap two letters of the key.
        i = rand_int(0, keyword_len);
        j = rand_int(0, keyword_len);
        temp = state[i];
        state[i] = state[j];
        state[j] = temp;
    } else {
        // Swap a letter from the key with an alphabet letter. 
#if FREQUENCY_WEIGHTED_SELECTION
        i = rand_int_frequency_weighted(state, 0, keyword_len);
        j = rand_int_frequency_weighted(state, keyword_len, len);
#else
        i = rand_int(0, keyword_len);
        j = rand_int(keyword_len, len);
#endif
        temp = state[i];
        state[i] = state[j];
        for (k = j + 1; k < len; k++) state[k - 1] = state[k];
        for (k = keyword_len; k < len; k++) {
            if (state[k] > temp || k == len - 1) {
                for (l = len - 1; l > k; l--) state[l] = state[l - 1];
                state[k] = temp;
                break ;
            }
        }
    }
}

void random_keyword(int keyword[], int len, int keyword_len) {
    int i, j, candidate, indx, n_chars;
    bool distinct, present;
    n_chars = 0;
    while (n_chars < keyword_len) {
        distinct = true;
        candidate = rand_int(0, g_alpha);
        for (i = 0; i < n_chars; i++) {
            if (keyword[i] == candidate) {
                distinct = false;
                break ;
            }
        }
        if (distinct) keyword[n_chars++] = candidate;
    }
    indx = keyword_len;
    for (i = 0; i < g_alpha; i++) {
        present = false;
        for (j = 0; j < keyword_len; j++) {
            if (keyword[j] == i) {
                present = true; 
                break ;
            }
        }
        if (! present) keyword[indx++] = i;
    }
}

void random_cycleword(int cycleword[], int max, int keyword_len) {
    for (int i = 0; i < keyword_len; i++) {
        cycleword[i] = rand_int(0, max);
    }
}

int rand_int_frequency_weighted(int state[], int min_index, int max_index) {
    double total = 0.0;
    double cumsum = 0.0;

    for (int i = min_index; i < max_index; i++) {
        total += english_monograms[state[i]];
    }

    if (total == 0.0) {
        return rand_int(min_index, max_index - 1); 
    }

    // Multiply the random float [0.0, 1.0) by the total weight.
    double target = frand() * total; 

    // Accumulate raw weights.
    for (int i = min_index; i < max_index; i++) {
        cumsum += english_monograms[state[i]];
        if (cumsum >= target) {
            return i;
        }
    }

    return max_index - 1;
}

float* load_ngrams(char *ngram_file, int ngram_size, bool verbose) {
    FILE *fp;
    int i, n_ngrams, freq, indx;
    char ngram[MAX_NGRAM_SIZE];
    float *ngram_data, total;

    if (verbose) printf("\nLoading ngrams...");
    n_ngrams = int_pow(g_alpha, ngram_size);
    ngram_data = malloc(n_ngrams*sizeof(float));
    for (i = 0; i < n_ngrams; i++) ngram_data[i] = 0.;

    fp = fopen(ngram_file, "r");
    // Loop on the parse succeeding (both fields read), not on feof: !feof is
    // still false after the last good line, so feof-looping re-reads the final
    // line and would mis-assign on any trailing/malformed line.
    while (fscanf(fp, "%s\t%d", ngram, &freq) == 2) {
        indx = ngram_index_str(ngram, ngram_size);
        if (indx < 0) continue;   // n-gram uses a letter not in the runtime alphabet
        ngram_data[indx] = freq;
    }
    fclose(fp);

    if (g_ngram_logprob) {
        // AZDecrypt / Practical-Cryptography fitness: each cell holds log10 P(n-gram),
        // and every UNSEEN n-gram is set to a floor probability so implausible n-grams
        // are penalised (the legacy table leaves them at 0, i.e. merely unrewarded).
        // The per-window sum of these log-probs is the standard n-gram fitness; ngram_score
        // keeps the scale at 1 in this mode so the result is a mean log-probability.
        double count_total = 0.;
        for (i = 0; i < n_ngrams; i++) count_total += ngram_data[i];   // raw counts
        if (count_total <= 0.) count_total = 1.;
        double floor = log10(0.01 / count_total);   // ~ a rare-but-not-impossible n-gram
        for (i = 0; i < n_ngrams; i++)
            ngram_data[i] = (ngram_data[i] > 0.) ? (float) log10(ngram_data[i] / count_total)
                                                 : (float) floor;
    } else {
        // Legacy reward-only scheme: normalized log(1 + count); unseen -> 0.
        total = 0.;
        for (i = 0; i < n_ngrams; i++) {
            ngram_data[i] = log(1. + ngram_data[i]);
            total += ngram_data[i];
        }
        for (i = 0; i < n_ngrams; i++) ngram_data[i] /= total;
    }
    if (verbose) printf("...finished.\n\n");
    return ngram_data;
}

int ngram_index_str(char *ngram, int ngram_size) {
    int c, index = 0, base = 1;
    for (int i = 0; i < ngram_size; i++) {
        c = g_char_to_idx[toupper((unsigned char) ngram[i]) & 127];
        // An n-gram containing a letter outside the runtime alphabet (e.g. 'P'
        // under -excludeletter P) cannot occur in the plaintext, so it has no
        // slot; signal the caller to skip it.
        if (c < 0) return -1;
        index += c*base;
        base *= g_alpha;
    }
    return index;
}

int ngram_index_int(int *ngram, int ngram_size) {
    int index = 0, base = 1;
    for (int i = 0; i < ngram_size; i++) {
        index += ngram[i]*base;
        base *= g_alpha;
    }
    return index;
}
