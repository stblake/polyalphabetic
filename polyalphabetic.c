//
//  Polyalphabetic cipher solver
//

// A stochastic, shotgun-restarted hill climber with backtracking for solving 
// Vigenere, Beaufort, and Quagmire I - IV with variants. 

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

// TODO:    - remove decryption from state_score. 

// Reference for n-gram data: http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/

/* Usage
    -----
    $ ./quagmire [options]

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

    Cipher Configuration:
        -type <int> : int
            The cipher algorithm to solve:
            0 : Vigenere
            1 : Quagmire I
            2 : Quagmire II
            3 : Quagmire III
            4 : Quagmire IV
            5 : Beaufort
            6 : Autokey
        -variant : flag
            Enable the Quagmire variant (which swaps decryption for encryption.)

    Optimization Strategy:
        -optimalcycle : flag
            Enables hybrid deterministic solving. The cycleword is mathematically derived 
            (using Chi-squared/Dot-product) for every keyword candidate, rather than being 
            perturbed stochastically. Highly recommended for short ciphers without cribs.
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

    Notes
    -----
    Cipher Types:
        Types 1-4 correspond to ACA standards:
        https://www.cryptogram.org/resource-area/cipher-types/
        Type 5 is the Beaufort cipher:
        https://www.cryptogram.org/downloads/aca.info/ciphers/Beaufort.pdf

*/

#include "polyalphabetic.h"

void init_config(QuagmireConfig *cfg) {
    // Set Defaults
    cfg->cipher_type = 3;
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
    cfg->variant = false;
    cfg->beaufort = false;

    cfg->n_sigma_threshold = 1.0;
    cfg->ioc_threshold = 0.047;
    cfg->backtracking_probability = 0.15;
    cfg->keyword_permutation_probability = 0.95;
    cfg->slip_probability = 0.01;

    cfg->weight_ngram = 12.0;
    cfg->weight_crib = 36.0;
    cfg->weight_ioc = 0.0;
    cfg->weight_entropy = 0.0;

    cfg->optimal_cycleword = true;
}

int main(int argc, char **argv) {
    QuagmireConfig cfg;
    SharedData shared;
    int i;
    char single_ciphertext_buffer[MAX_CIPHER_LENGTH];
    char cribtext[MAX_CIPHER_LENGTH];

    init_config(&cfg);
    
    // Initialize shared data pointers
    shared.ngram_data = NULL;
    shared.dict = NULL;
    shared.n_dict_words = 0;
    shared.max_dict_word_len = 0;

    // --- Argument Parsing ---
    for(i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-type") == 0) {
            cfg.cipher_type = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-cipher") == 0) {
            cfg.cipher_present = true;
            strcpy(cfg.ciphertext_file, argv[++i]);
        } else if (strcmp(argv[i], "-batch") == 0) {
            cfg.batch_present = true;
            strcpy(cfg.batch_file, argv[++i]);
        } else if (strcmp(argv[i], "-crib") == 0) {
            cfg.crib_present = true;
            strcpy(cfg.crib_file, argv[++i]);
        } else if (strcmp(argv[i], "-ngramsize") == 0) {
            cfg.ngram_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-ngramfile") == 0) {
            strcpy(cfg.ngram_file, argv[++i]);
        } else if (strcmp(argv[i], "-maxkeywordlen") == 0) {
            cfg.plaintext_keyword_len = atoi(argv[++i]);
            cfg.ciphertext_keyword_len = cfg.plaintext_keyword_len;
        } else if (strcmp(argv[i], "-keywordlen") == 0) {
            cfg.plaintext_keyword_len_present = true;
            cfg.ciphertext_keyword_len_present = true;
            cfg.plaintext_keyword_len = atoi(argv[++i]);
            cfg.ciphertext_keyword_len = cfg.plaintext_keyword_len;
            cfg.plaintext_max_keyword_len = max(cfg.plaintext_max_keyword_len, 1 + cfg.plaintext_keyword_len);
            cfg.ciphertext_max_keyword_len = max(cfg.ciphertext_max_keyword_len, 1 + cfg.ciphertext_keyword_len);
            cfg.min_keyword_len = cfg.plaintext_keyword_len;
        } else if (strcmp(argv[i], "-plaintextkeywordlen") == 0) {
            cfg.plaintext_keyword_len_present = true;
            cfg.plaintext_keyword_len = atoi(argv[++i]);
            cfg.plaintext_max_keyword_len = max(cfg.plaintext_max_keyword_len, 1 + cfg.plaintext_keyword_len);
            cfg.min_keyword_len = cfg.plaintext_keyword_len;
        } else if (strcmp(argv[i], "-ciphertextkeywordlen") == 0) {
            cfg.ciphertext_keyword_len_present = true;
            cfg.ciphertext_keyword_len = atoi(argv[++i]);
            cfg.ciphertext_max_keyword_len = max(cfg.ciphertext_max_keyword_len, 1 + cfg.ciphertext_keyword_len);
            cfg.min_keyword_len = cfg.ciphertext_keyword_len;
        } else if (strcmp(argv[i], "-plaintextkeyword") == 0) {
            // Explicit Plaintext Keyword
            cfg.user_plaintext_keyword_present = true;
            strcpy(cfg.user_plaintext_keyword, argv[++i]);
            
            int len = (int)strlen(cfg.user_plaintext_keyword);
            cfg.plaintext_keyword_len = len;
            cfg.plaintext_max_keyword_len = len + 1;
            cfg.plaintext_keyword_len_present = true;
            printf("\nFixed Plaintext Keyword: %s (Alphabet will be generated)", cfg.user_plaintext_keyword);

        } else if (strcmp(argv[i], "-ciphertextkeyword") == 0) {
            // Explicit Ciphertext Keyword
            cfg.user_ciphertext_keyword_present = true;
            strcpy(cfg.user_ciphertext_keyword, argv[++i]);

            int len = (int)strlen(cfg.user_ciphertext_keyword);
            cfg.ciphertext_keyword_len = len;
            cfg.ciphertext_max_keyword_len = len + 1;
            cfg.ciphertext_keyword_len_present = true;
            printf("\nFixed Ciphertext Keyword: %s (Alphabet will be generated)", cfg.user_ciphertext_keyword);

        } else if (strcmp(argv[i], "-maxcyclewordlen") == 0) {
            cfg.max_cycleword_len = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-cyclewordlen") == 0) {
            cfg.cycleword_len_present = true;
            cfg.cycleword_len = atoi(argv[++i]);
            cfg.max_cycleword_len = max(cfg.max_cycleword_len, 1 + cfg.cycleword_len);
        } else if (strcmp(argv[i], "-nsigmathreshold") == 0) {
            cfg.n_sigma_threshold = atof(argv[++i]);
        } else if (strcmp(argv[i], "-nhillclimbs") == 0) {
            cfg.n_hill_climbs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-nrestarts") == 0) {
            cfg.n_restarts = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-backtrackprob") == 0) {
            cfg.backtracking_probability = atof(argv[++i]);
        } else if (strcmp(argv[i], "-keywordpermprob") == 0) {
            cfg.keyword_permutation_probability = atof(argv[++i]);
        } else if (strcmp(argv[i], "-slipprob") == 0) {
            cfg.slip_probability = atof(argv[++i]);
        } else if (strcmp(argv[i], "-iocthreshold") == 0) {
            cfg.ioc_threshold = atof(argv[++i]);
        } else if (strcmp(argv[i], "-dictionary") == 0 || strcmp(argv[i], "-dict") == 0) {
            cfg.dictionary_present = true;
            strcpy(cfg.dictionary_file, argv[++i]);
        } else if (strcmp(argv[i], "-weightngram") == 0) { 
            cfg.weight_ngram = atof(argv[++i]);
        } else if (strcmp(argv[i], "-weightcrib") == 0) { 
            cfg.weight_crib = atof(argv[++i]);
        } else if (strcmp(argv[i], "-weightioc") == 0) { 
            cfg.weight_ioc = atof(argv[++i]);
        } else if (strcmp(argv[i], "-weightentropy") == 0) { 
            cfg.weight_entropy = atof(argv[++i]);
        } else if (strcmp(argv[i], "-variant") == 0) { 
            cfg.variant = true;
        } else if (strcmp(argv[i], "-verbose") == 0) {
            cfg.verbose = true;
        } else if (strcmp(argv[i], "-optimalcycle") == 0) {
            cfg.optimal_cycleword = true;
        }
    }

    printf("\n\n");

    if (cfg.cipher_type == BEAUFORT) {
        cfg.beaufort = true;
    }

    // --- Validation ---

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

    srand(time(NULL));

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
            solve_cipher(line_buffer, cribtext, &cfg, &shared);
        }
        fclose(fp_batch);

    } else {
        // Single Cipher Mode
        if (!file_exists(cfg.ciphertext_file)) {
             printf("\nERROR: missing cipher file '%s'\n", cfg.ciphertext_file);
             return 0;
        }

        FILE *fp_cipher = fopen(cfg.ciphertext_file, "r");
        fscanf(fp_cipher, "%s", single_ciphertext_buffer);
        fclose(fp_cipher);

        if (cfg.verbose) printf("ciphertext = \n\'%s\'\n\n", single_ciphertext_buffer);

        solve_cipher(single_ciphertext_buffer, cribtext, &cfg, &shared);
    }

    // --- Cleanup ---
    free(shared.ngram_data);
    if (shared.dict != NULL) {
        free_dictionary(shared.dict, shared.n_dict_words);
    }

    return 1;
}

// ============================================================================
// Core Solver Logic
// ============================================================================

void solve_cipher(char *ciphertext_str, char *cribtext_str, QuagmireConfig *cfg, SharedData *shared) {
    
    int cipher_len = (int)strlen(ciphertext_str);
    int cipher_indices[MAX_CIPHER_LENGTH];
    int n_cribs = 0;
    int crib_positions[MAX_CIPHER_LENGTH];
    int crib_indices[MAX_CIPHER_LENGTH];
    
    int n_cycleword_lengths, cycleword_lengths[MAX_CIPHER_LENGTH];
    int best_cycleword_length = 0;

    // Variables added to fix compilation error:
    int best_plaintext_keyword_length = 0;
    int best_ciphertext_keyword_length = 0;

    // Result buffers
    int decrypted[MAX_CIPHER_LENGTH];
    int best_decrypted[MAX_CIPHER_LENGTH];
    int plaintext_keyword[ALPHABET_SIZE]; 
    int ciphertext_keyword[ALPHABET_SIZE]; 
    int cycleword[ALPHABET_SIZE];
    int best_plaintext_keyword[ALPHABET_SIZE]; 
    int best_ciphertext_keyword[ALPHABET_SIZE]; 
    int best_cycleword[ALPHABET_SIZE];
    char best_key_str[MAX_CIPHER_LENGTH]; // For autokey

    double score, best_score = 0.0;
    int n_words_found = 0;
    
    // Prepare Indices
    ord(ciphertext_str, cipher_indices);

    // Process Cribs (Local to this cipher)
    if (strlen(cribtext_str) > 0) {
        if ((int)strlen(cribtext_str) != cipher_len) {
            if (cfg->verbose) printf("Crib length mismatch (Crib: %lu, Cipher: %d). Ignoring crib.\n", strlen(cribtext_str), cipher_len);
            n_cribs = 0;
        } else {
            for (int i = 0; i < cipher_len; i++) {
                if (cribtext_str[i] != '_') {
                    crib_positions[n_cribs] = i;
                    crib_indices[n_cribs] = cribtext_str[i] - 'A';
                    n_cribs++;
                }
            }
        }
    }

    // Attack Logic
    if (cfg->cipher_type == AUTOKEY) {

        if (!cfg->dictionary_present || shared->dict == NULL) {
            printf("ERROR: Autokey attack requires dictionary.\n");
            return;
        }

        best_score = autokey_dictionary_attack(
            cipher_indices, cipher_len,
            shared,
            cfg->ngram_size,
            crib_indices, crib_positions, n_cribs,
            cfg->weight_ngram, cfg->weight_crib, cfg->weight_ioc, cfg->weight_entropy,
            best_key_str, best_decrypted,
            cfg->verbose
        );

        // Normalize results for printing
        ord(best_key_str, best_plaintext_keyword);
        best_cycleword_length = 0;

    } else {
        // Quagmire / Hill Climber
        
        // Estimate Cycleword
        estimate_cycleword_lengths(
            cipher_indices, 
            cipher_len, 
            cfg->max_cycleword_len, 
            cfg->n_sigma_threshold,
            cfg->ioc_threshold, 
            &n_cycleword_lengths, 
            cycleword_lengths, 
            cfg->verbose);

        if (cfg->cycleword_len_present) {
            n_cycleword_lengths = 1;
            cycleword_lengths[0] = cfg->cycleword_len;
        }

        // Keyword constraints
        int min_kw = cfg->min_keyword_len;
        int pt_max = cfg->plaintext_max_keyword_len;
        int ct_max = cfg->ciphertext_max_keyword_len;

        if (cfg->cipher_type == VIGENERE) min_kw = 1;
        if (cfg->cipher_type == BEAUFORT) {
            min_kw = 1;
            pt_max = 2; 
        }

        // Shotgun Loop
        best_score = 0.;

        for (int i = 0; i < n_cycleword_lengths; i++) {
            for (int j = min(min_kw, cfg->plaintext_keyword_len); j < pt_max; j++) {
                for (int k = min(min_kw, cfg->ciphertext_keyword_len); k < ct_max; k++) {

                    // Skip invalid combos based on flags
                    if (cfg->plaintext_keyword_len_present && j != cfg->plaintext_keyword_len) continue;
                    if (cfg->ciphertext_keyword_len_present && k != cfg->ciphertext_keyword_len) continue;
                    
                    if ((cfg->cipher_type == VIGENERE || cfg->cipher_type == QUAGMIRE_3) && j != k) continue;
                    if (cfg->cipher_type == VIGENERE && ! (cycleword_lengths[i] == j && cycleword_lengths[i] == k)) continue;
                    if (cfg->cipher_type == BEAUFORT && ! (j == 1 && k == 1)) continue;

                    // Check Crib compatibility
                    if (!cribs_satisfied_p(cipher_indices, cipher_len, crib_indices, crib_positions, n_cribs, cycleword_lengths[i], cfg->verbose)) {
                        #if CRIB_CHECK
                        continue;
                        #endif
                    }

                    // Run Hill Climber
                    score = quagmire_shotgun_hill_climber(
                        cfg,
                        cipher_indices, cipher_len,
                        crib_indices, crib_positions, n_cribs,
                        cycleword_lengths[i], j, k,
                        shared->ngram_data,
                        decrypted, plaintext_keyword, ciphertext_keyword, cycleword
                    );

                    if (score > best_score) {
                        best_score = score;
                        best_cycleword_length = cycleword_lengths[i];
                        best_plaintext_keyword_length = j;
                        best_ciphertext_keyword_length = k;
                        vec_copy(decrypted, best_decrypted, cipher_len);
                        vec_copy(plaintext_keyword, best_plaintext_keyword, ALPHABET_SIZE);
                        vec_copy(ciphertext_keyword, best_ciphertext_keyword, ALPHABET_SIZE);
                        vec_copy(cycleword, best_cycleword, ALPHABET_SIZE);
                    }
                }
            }
        }
    }

    // Reporting

    char plaintext_string[MAX_CIPHER_LENGTH];
    for (int i = 0; i < cipher_len; i++) {
        plaintext_string[i] = best_decrypted[i] + 'A';
    }
    plaintext_string[cipher_len] = '\0';

    if (cfg->dictionary_present && shared->dict != NULL) {
        n_words_found = find_dictionary_words(plaintext_string, shared->dict, shared->n_dict_words, shared->max_dict_word_len);
    }

    // Results Output
    printf("\nResult Score: %.2f | Words: %d\n", best_score, n_words_found);
    
    print_text(cipher_indices, cipher_len);
    printf("\n");
    print_text(best_plaintext_keyword, ALPHABET_SIZE);
    printf("\n");
    
    if (cfg->cipher_type != AUTOKEY) {
        print_text(best_ciphertext_keyword, ALPHABET_SIZE);
        printf("\n");
        print_text(best_cycleword, best_cycleword_length);
        printf("\n");
    }
    print_text(best_decrypted, cipher_len);
    printf("\n");

    // One-liner summary
    if (cfg->dictionary_present) {
        printf(">>> %.2f, %d, %d, %s, ", best_score, n_words_found, cfg->cipher_type, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    } else {
        printf(">>> %.2f, %d, %s, ", best_score, cfg->cipher_type, cfg->batch_present ? "BATCH" : cfg->ciphertext_file);
    }
    
    print_text(cipher_indices, cipher_len);
    printf(", ");
    print_text(best_plaintext_keyword, ALPHABET_SIZE);
    printf(", ");
    if (cfg->cipher_type != AUTOKEY) {
        print_text(best_ciphertext_keyword, ALPHABET_SIZE);
        printf(", ");
        print_text(best_cycleword, best_cycleword_length);
        printf(", ");
    }
    print_text(best_decrypted, cipher_len);
    printf("\n");
}


// Hill Climber

double quagmire_shotgun_hill_climber(
    QuagmireConfig *cfg,
    int cipher_indices[], int cipher_len, 
    int crib_indices[], int crib_positions[], int n_cribs,
    int cycleword_len, int plaintext_keyword_len, int ciphertext_keyword_len, 
    float *ngram_data,
    int decrypted[MAX_CIPHER_LENGTH], int plaintext_keyword[ALPHABET_SIZE], 
    int ciphertext_keyword[ALPHABET_SIZE], int cycleword[ALPHABET_SIZE]) {

    int i, j, k, n, indx, offset, n_iterations, n_backtracks, n_explore, n_contradictions;
    int local_plaintext_keyword_state[ALPHABET_SIZE], current_plaintext_keyword_state[ALPHABET_SIZE]; 
    int local_ciphertext_keyword_state[ALPHABET_SIZE], current_ciphertext_keyword_state[ALPHABET_SIZE]; 
    int best_plaintext_keyword_state[ALPHABET_SIZE], best_ciphertext_keyword_state[ALPHABET_SIZE];
    int local_cycleword_state[MAX_CYCLEWORD_LEN], current_cycleword_state[MAX_CYCLEWORD_LEN]; 
    int best_cycleword_state[MAX_CYCLEWORD_LEN];

    double start_time, elapsed, n_iter_per_sec, best_score, local_score, current_score;
    double ioc, chi, entropy_score;
    bool perturbate_keyword_p, contradiction;

    if (cfg->cipher_type == VIGENERE) {
        cycleword_len = ALPHABET_SIZE;
    }

    n_iterations = 0;
    n_backtracks = 0;
    n_explore = 0;
    n_contradictions = 0;
    start_time = clock();

    best_score = 0.;

    for (n = 0; n < cfg->n_restarts; n++) {

        if (best_score > 0. && frand() < cfg->backtracking_probability) {
            // Backtrack to best state. 
            n_backtracks += 1;
            current_score = best_score;
            vec_copy(best_plaintext_keyword_state, current_plaintext_keyword_state, ALPHABET_SIZE);
            vec_copy(best_ciphertext_keyword_state, current_ciphertext_keyword_state, ALPHABET_SIZE);
            vec_copy(best_cycleword_state, current_cycleword_state, cycleword_len);
        } else {
            // Initialise random state.
            switch (cfg->cipher_type) {
                case VIGENERE:
                    // Vigenere uses the same keyword for PT/CT/Cycle (in this logic model)
                    random_keyword(current_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                    vec_copy(current_plaintext_keyword_state, current_ciphertext_keyword_state, ALPHABET_SIZE);
                    vec_copy(current_plaintext_keyword_state, current_cycleword_state, ALPHABET_SIZE);
                    break ;
                case QUAGMIRE_1:
                    // PT keyword is scrambled, CT is straight.
                    if (cfg->user_plaintext_keyword_present) {
                        make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
                    } else {
                        random_keyword(current_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                    }
                    straight_alphabet(current_ciphertext_keyword_state, ALPHABET_SIZE);
                    random_cycleword(current_cycleword_state, ALPHABET_SIZE, cycleword_len);
                    break ;
                case QUAGMIRE_2:
                    // PT straight, CT scrambled
                    straight_alphabet(current_plaintext_keyword_state, ALPHABET_SIZE);
                    if (cfg->user_ciphertext_keyword_present) {
                        make_keyed_alphabet(cfg->user_ciphertext_keyword, current_ciphertext_keyword_state);
                    } else {
                        random_keyword(current_ciphertext_keyword_state, ALPHABET_SIZE, ciphertext_keyword_len);
                    }
                    random_cycleword(current_cycleword_state, ALPHABET_SIZE, cycleword_len);
                    break ;
                case QUAGMIRE_3:
                    // PT and CT are the same scrambled alphabet
                    if (cfg->user_plaintext_keyword_present) {
                        make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
                    } else if (cfg->user_ciphertext_keyword_present) {
                        make_keyed_alphabet(cfg->user_ciphertext_keyword, current_plaintext_keyword_state);
                    } else {
                        random_keyword(current_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                    }
                    vec_copy(current_plaintext_keyword_state, current_ciphertext_keyword_state, ALPHABET_SIZE);
                    random_cycleword(current_cycleword_state, ALPHABET_SIZE, cycleword_len);
                    break ;
                case QUAGMIRE_4:
                    // PT and CT are different scrambled alphabets
                    if (cfg->user_plaintext_keyword_present) {
                        make_keyed_alphabet(cfg->user_plaintext_keyword, current_plaintext_keyword_state);
                    } else {
                        random_keyword(current_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                    }
                    
                    if (cfg->user_ciphertext_keyword_present) {
                        make_keyed_alphabet(cfg->user_ciphertext_keyword, current_ciphertext_keyword_state);
                    } else {
                        random_keyword(current_ciphertext_keyword_state, ALPHABET_SIZE, ciphertext_keyword_len);
                    }
                    random_cycleword(current_cycleword_state, ALPHABET_SIZE, cycleword_len);
                    break ;
                case BEAUFORT:
                    plaintext_keyword_len = ALPHABET_SIZE;
                    ciphertext_keyword_len = ALPHABET_SIZE;
                    for (i = 0; i < ALPHABET_SIZE; i++) current_plaintext_keyword_state[i] = i;
                    vec_copy(current_plaintext_keyword_state, current_ciphertext_keyword_state, ALPHABET_SIZE);
                    random_cycleword(current_cycleword_state, ALPHABET_SIZE, cycleword_len);
                    break ; 
            }

            // If in optimal mode, fix the cycleword immediately for the initial random state
            if (cfg->optimal_cycleword) {
                derive_optimal_cycleword(cipher_indices, cipher_len, 
                    current_plaintext_keyword_state, current_ciphertext_keyword_state, 
                    current_cycleword_state, cycleword_len, 
                    cfg->variant, cfg->beaufort);
            }

            current_score = state_score(cipher_indices, cipher_len, 
                crib_indices, crib_positions, n_cribs, 
                current_plaintext_keyword_state, current_ciphertext_keyword_state, 
                current_cycleword_state, cycleword_len, 
                cfg->variant, cfg->beaufort, 
                decrypted, ngram_data, cfg->ngram_size,
                cfg->weight_ngram, cfg->weight_crib, cfg->weight_ioc, cfg->weight_entropy);
        }

        perturbate_keyword_p = true;

        for (i = 0; i < cfg->n_hill_climbs; i++) {
                
            n_iterations += 1;

            // perturbate.
            vec_copy(current_plaintext_keyword_state, local_plaintext_keyword_state, ALPHABET_SIZE);
            vec_copy(current_ciphertext_keyword_state, local_ciphertext_keyword_state, ALPHABET_SIZE);
            vec_copy(current_cycleword_state, local_cycleword_state, cycleword_len);

            bool did_perturb_keyword = false; 

            if (cfg->cipher_type != BEAUFORT && (perturbate_keyword_p || cfg->cipher_type == VIGENERE || frand() < cfg->keyword_permutation_probability)) {
                
                // Logic: Only perturb keywords if they were NOT provided by the user.
                // If the user provided a keyword, it is treated as fixed for that component.

                switch (cfg->cipher_type) {
                    case VIGENERE:
                        // Vigenere isn't really compatible with these flags in the same way, standard perturbation
                        perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                        vec_copy(local_plaintext_keyword_state, local_ciphertext_keyword_state, ALPHABET_SIZE); 
                        vec_copy(local_plaintext_keyword_state, local_cycleword_state, ALPHABET_SIZE);
                        did_perturb_keyword = true;
                        break ; 
                    case QUAGMIRE_1:
                        if (!cfg->user_plaintext_keyword_present) {
                            perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                            did_perturb_keyword = true;
                        }
                        break ;
                    case QUAGMIRE_2:
                        if (!cfg->user_ciphertext_keyword_present) {
                            perturbate_keyword(local_ciphertext_keyword_state, ALPHABET_SIZE, ciphertext_keyword_len);
                            did_perturb_keyword = true;
                        }
                        break ;
                    case QUAGMIRE_3:
                        if (!cfg->user_plaintext_keyword_present && !cfg->user_ciphertext_keyword_present) {
                            perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                            vec_copy(local_plaintext_keyword_state, local_ciphertext_keyword_state, ALPHABET_SIZE);
                            did_perturb_keyword = true;
                        }
                        break ;
                    case QUAGMIRE_4:
                        // If both are present, we can't perturb keywords at all, fall through to cycleword.
                        // If one is present, only perturb the other.
                        
                        if (cfg->user_plaintext_keyword_present && cfg->user_ciphertext_keyword_present) {
                            did_perturb_keyword = false; // Force cycleword perturbation
                        } else if (cfg->user_plaintext_keyword_present) {
                            // Only perturb ciphertext
                            perturbate_keyword(local_ciphertext_keyword_state, ALPHABET_SIZE, ciphertext_keyword_len);
                            did_perturb_keyword = true;
                        } else if (cfg->user_ciphertext_keyword_present) {
                            // Only perturb plaintext
                            perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                            did_perturb_keyword = true;
                        } else {
                            // Standard Q4 stochastic choice
                            if (frand() < 0.5) {
                                perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                            } else {
                                perturbate_keyword(local_ciphertext_keyword_state, ALPHABET_SIZE, ciphertext_keyword_len);
                            }
                            did_perturb_keyword = true;
                        }
                        break ;
                }
            } else {
                did_perturb_keyword = false;
            }
            
            // ================================================================
            // NEW BRANCHING LOGIC
            // ================================================================
            
            if (cfg->optimal_cycleword) {
                // --- NEW METHOD: DETERMINISTIC ---
                // We NEVER perturb the cycleword randomly.
                // We always mathematically derive the best cycleword for the current keyword.
                
                // If we didn't touch the keyword this turn, and we're in optimal mode,
                // re-calculating the cycleword for the SAME keyword is useless.
                // We must force a keyword change to progress.
                if (!did_perturb_keyword && cfg->cipher_type != BEAUFORT) {
                    
                    // Force perturbation on valid alphabets
                    if (cfg->cipher_type == QUAGMIRE_3) {
                         perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                         vec_copy(local_plaintext_keyword_state, local_ciphertext_keyword_state, ALPHABET_SIZE);
                         did_perturb_keyword = true;
                    } 
                    else if (cfg->cipher_type == QUAGMIRE_1) {
                        perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                        did_perturb_keyword = true;
                    }
                    else if (cfg->cipher_type == QUAGMIRE_2) {
                        perturbate_keyword(local_ciphertext_keyword_state, ALPHABET_SIZE, ciphertext_keyword_len);
                        did_perturb_keyword = true;
                    }
                    else if (cfg->cipher_type == QUAGMIRE_4) {
                        // Random force
                        if (frand() < 0.5) {
                             perturbate_keyword(local_plaintext_keyword_state, ALPHABET_SIZE, plaintext_keyword_len);
                        } else {
                             perturbate_keyword(local_ciphertext_keyword_state, ALPHABET_SIZE, ciphertext_keyword_len);
                        }
                        did_perturb_keyword = true;
                    }
                }

                derive_optimal_cycleword(cipher_indices, cipher_len, 
                    local_plaintext_keyword_state, local_ciphertext_keyword_state, 
                    local_cycleword_state, cycleword_len, cfg->variant, cfg->beaufort);

            } else {
                // --- OLD METHOD: STOCHASTIC ---
                // If we decided NOT to perturb the keyword (because it was fixed by user, or stochastic choice),
                // we perturb the cycleword.
                if (!did_perturb_keyword) {
                    perturbate_cycleword(local_cycleword_state, ALPHABET_SIZE, cycleword_len);
                }

                if (cfg->cipher_type != VIGENERE && cfg->cipher_type != BEAUFORT) {
                    perturbate_keyword_p = false; 
                    
                    if (did_perturb_keyword) { 
                        contradiction = constrain_cycleword(cipher_indices, cipher_len, crib_indices, 
                            crib_positions, n_cribs, 
                            local_plaintext_keyword_state, local_ciphertext_keyword_state, 
                            local_cycleword_state, cycleword_len, cfg->variant, cfg->verbose);

                        if (contradiction) {
                            n_contradictions += 1; 
                            perturbate_keyword_p = true; 
                        }
                    }
                }
            }

            local_score = state_score(cipher_indices, cipher_len, 
                crib_indices, crib_positions, n_cribs, 
                local_plaintext_keyword_state, local_ciphertext_keyword_state, 
                local_cycleword_state, cycleword_len, 
                cfg->variant, cfg->beaufort, 
                decrypted, ngram_data, cfg->ngram_size,
                cfg->weight_ngram, cfg->weight_crib, cfg->weight_ioc, cfg->weight_entropy);

            if (local_score > current_score) {
                current_score = local_score;
                vec_copy(local_plaintext_keyword_state, current_plaintext_keyword_state, ALPHABET_SIZE);
                vec_copy(local_ciphertext_keyword_state, current_ciphertext_keyword_state, ALPHABET_SIZE);
                vec_copy(local_cycleword_state, current_cycleword_state, cycleword_len);
            } else if (frand() < cfg->slip_probability) {
                n_explore += 1;
                current_score = local_score;
                vec_copy(local_plaintext_keyword_state, current_plaintext_keyword_state, ALPHABET_SIZE);
                vec_copy(local_ciphertext_keyword_state, current_ciphertext_keyword_state, ALPHABET_SIZE);
                vec_copy(local_cycleword_state, current_cycleword_state, cycleword_len);
            }

            if (current_score > best_score) {
                best_score = current_score;
                vec_copy(current_plaintext_keyword_state, best_plaintext_keyword_state, ALPHABET_SIZE);
                vec_copy(current_ciphertext_keyword_state, best_ciphertext_keyword_state, ALPHABET_SIZE);
                vec_copy(current_cycleword_state, best_cycleword_state, cycleword_len);
                if (cfg->verbose) {

                    quagmire_decrypt(decrypted, cipher_indices, cipher_len, 
                        best_plaintext_keyword_state, best_ciphertext_keyword_state, 
                        best_cycleword_state, cycleword_len, cfg->variant, cfg->beaufort);

                    ioc = index_of_coincidence(decrypted, cipher_len);
                    chi = chi_squared(decrypted, cipher_len);
                    entropy_score = entropy(decrypted, cipher_len);

                    elapsed = ((double) clock() - start_time)/CLOCKS_PER_SEC;
                    n_iter_per_sec = ((double) n_iterations)/elapsed;

                    printf("\n%.2f\t[sec]\n", elapsed);
                    printf("%.0fK\t[it/sec]\n", 1.e-3*n_iter_per_sec);
                    printf("%d\t[backtracks]\n", n_backtracks);
                    printf("%d\t[restarts]\n", n);
                    printf("%d\t[slips]\n", n_explore);
                    printf("%.2f\t[contradiction pct]\n", ((double) n_contradictions)/n_iterations);
                    printf("%.4f\t[IOC]\n", ioc);
                    printf("%.4f\t[entropy]\n", entropy_score);
                    printf("%.2f\t[chi-squared]\n", chi);
                    printf("%.2f\t[score]\n", best_score);
                    
                    print_text(best_plaintext_keyword_state, ALPHABET_SIZE); printf("\n");
                    print_text(best_ciphertext_keyword_state, ALPHABET_SIZE); printf("\n");
                    print_text(best_cycleword_state, cycleword_len); printf("\n");
                    
                    // Detailed Tableau Display (Restored)
                    printf("\n");
                    for (k = 0; k < cycleword_len; k++) {
                        for (j = 0; j < ALPHABET_SIZE; j++) {
                            if (best_ciphertext_keyword_state[j] == best_cycleword_state[k]) {
                                offset = j;
                            }
                        }
                        for (j = 0; j < ALPHABET_SIZE; j++) {
                            indx = (j + offset) % ALPHABET_SIZE;
                            printf("%c", best_ciphertext_keyword_state[indx] + 'A');
                        }
                        printf("\n");
                    }
                    printf("\n");

                    print_text(decrypted, cipher_len); printf("\n");

                    fflush(stdout);
                }
            }
        }
    }

    vec_copy(best_plaintext_keyword_state, plaintext_keyword, ALPHABET_SIZE);
    vec_copy(best_ciphertext_keyword_state, ciphertext_keyword, ALPHABET_SIZE);
    vec_copy(best_cycleword_state, cycleword, cycleword_len);

    quagmire_decrypt(decrypted, cipher_indices, cipher_len, 
                    best_plaintext_keyword_state, best_ciphertext_keyword_state, 
                    best_cycleword_state, cycleword_len, cfg->variant, cfg->beaufort);

    return best_score;
}



// Solves the cycleword optimally for the given keywords using columnar dot product.

void derive_optimal_cycleword(
    int cipher_indices[], int cipher_len,
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[],
    int cycleword_state[], int cycleword_len,
    bool variant, bool beaufort) {

    int col, row, i, shift, best_shift_index;
    int ct_char, pt_char, pt_idx_calc;
    int posn_keyword, posn_cycleword;
    double best_score, current_score;
    int char_counts[ALPHABET_SIZE];
    int total_count;

    // 1. Pre-calculate lookup table for ciphertext keyword positions to speed up the loop
    int ct_key_lookup[ALPHABET_SIZE];
    for (i = 0; i < ALPHABET_SIZE; i++) ct_key_lookup[i] = -1;
    for (i = 0; i < ALPHABET_SIZE; i++) {
        // We map the CHAR (0-25) to its POSITION (0-25) in the CT keyword
        ct_key_lookup[ciphertext_keyword_indices[i]] = i;
    }

    // 2. Iterate over each column of the period
    for (col = 0; col < cycleword_len; col++) {
        best_score = -1.0;
        best_shift_index = 0; // This will be the index in the CT keyword

        // Try all 26 possible shifts (letters of the cycleword)
        for (shift = 0; shift < ALPHABET_SIZE; shift++) {
            
            // Reset counts
            for (i = 0; i < ALPHABET_SIZE; i++) char_counts[i] = 0;
            total_count = 0;

            // Decrypt this column using the current 'shift'
            row = 0;
            while ((row * cycleword_len + col) < cipher_len) {
                ct_char = cipher_indices[row * cycleword_len + col];
                
                // Look up position of CT char in CT keyword
                posn_keyword = ct_key_lookup[ct_char];
                
                // If the char isn't in the keyed alphabet (shouldn't happen if full alphabet), skip
                if (posn_keyword == -1) { row++; continue; }

                // The 'shift' variable acts as 'posn_cycleword'
                posn_cycleword = shift;
                if (beaufort) posn_cycleword = ALPHABET_SIZE - posn_cycleword - 1;

                // Quagmire Decryption Math
                if (variant) {
                    pt_idx_calc = (posn_keyword + posn_cycleword) % ALPHABET_SIZE;
                } else {
                    pt_idx_calc = (posn_keyword - posn_cycleword) % ALPHABET_SIZE;
                }
                if (pt_idx_calc < 0) pt_idx_calc += ALPHABET_SIZE;

                // Map index back to Plaintext Character
                pt_char = plaintext_keyword_indices[pt_idx_calc];
                if (beaufort) pt_char = ALPHABET_SIZE - pt_char - 1;

                char_counts[pt_char]++;
                total_count++;
                row++;
            }

            // Calculate Dot Product Score (Frequency * English Probability)
            current_score = 0.0;
            if (total_count > 0) {
                for (i = 0; i < ALPHABET_SIZE; i++) {
                    // english_monograms is defined in quagmire.h
                    current_score += ((double)char_counts[i]) * english_monograms[i];
                }
                // Normalize isn't strictly necessary for comparison, but good for debug
                current_score /= total_count; 
            }

            // Maximizing Dot Product finds the best fit
            if (current_score > best_score) {
                best_score = current_score;
                best_shift_index = shift;
            }
        }

        // Set the best cycleword character for this column
        // Note: The state stores the CHARACTER, not the index.
        cycleword_state[col] = ciphertext_keyword_indices[best_shift_index];
    }
}



// Performs a dictionary attack on an Autokey cipher.
double autokey_dictionary_attack(
    int cipher_indices[], int cipher_len,
    SharedData *shared,
    int ngram_size,
    int crib_indices[], int crib_positions[], int n_cribs,
    float weight_ngram, float weight_crib, float weight_ioc, float weight_entropy,
    char best_key[], int best_decrypted[],
    bool verbose) {

    double score, best_score = 0.; 
    int decrypted[MAX_CIPHER_LENGTH];

    if (verbose) {
        printf("Running attack using %d loaded dictionary words.\n", shared->n_dict_words);
    }

    for (int i = 0; i < shared->n_dict_words; i++) {
        char *current_key_str = shared->dict[i];
        int current_key_len = strlen(current_key_str);
        int current_key_indices[MAX_KEYWORD_LEN];
        if (current_key_len > MAX_KEYWORD_LEN) continue; 

        ord(current_key_str, current_key_indices);
        autokey_decrypt(decrypted, cipher_indices, cipher_len, current_key_indices, current_key_len);
        
        double decrypted_ngram_score = ngram_score(decrypted, cipher_len, shared->ngram_data, ngram_size);
        double decrypted_crib_score = crib_score(decrypted, cipher_len, crib_indices, crib_positions, n_cribs);
        
        if (n_cribs > 0) {
            score = weight_ngram * decrypted_ngram_score + 
                weight_crib * decrypted_crib_score;
            score /= weight_ngram + weight_crib; 
        } else {
            score = decrypted_ngram_score;
        }

        if (score > best_score) {
            best_score = score;
            strcpy(best_key, current_key_str);
            vec_copy(decrypted, best_decrypted, cipher_len);
            
            if (verbose) {
                printf("\nNew best score: %.4f with key: %s\n", best_score, best_key);
                print_text(best_decrypted, cipher_len);
                printf("\n");
            }
        }
    }
    
    return best_score;
}

void autokey_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int key_indices[], int key_len) {
    
    int key_stream[MAX_CIPHER_LENGTH + MAX_KEYWORD_LEN];
    int key_stream_len = key_len;
    int i;

    for (i = 0; i < key_len; i++) {
        key_stream[i] = key_indices[i];
    }

    for (i = 0; i < cipher_len; i++) {
        int c_val = cipher_indices[i];
        int k_val = key_stream[i];
        int p_val = (c_val - k_val + ALPHABET_SIZE) % ALPHABET_SIZE;
        decrypted[i] = p_val;
        key_stream[key_stream_len] = p_val;
        key_stream_len++;
    }
}

bool cribs_satisfied_p(int cipher_indices[], int cipher_len, int crib_indices[], 
    int crib_positions[], int n_cribs, int cycleword_len, bool verbose) {

    int i, j, k, ii, jj, total, column_length, ciphertext_column_indices[MAX_CIPHER_LENGTH], 
        ciphertext_column[MAX_CIPHER_LENGTH], crib_frequencies[ALPHABET_SIZE][ALPHABET_SIZE];

    if (n_cribs == 0) return true;

    for (j = 0; j < cycleword_len; j++) {
        if (verbose) printf("\nCOLUMN = %d \n", j);

        k = 0;
        while (cycleword_len*k + j < cipher_len) {
            ciphertext_column_indices[k] = cycleword_len*k + j;
            ciphertext_column[k] = cipher_indices[ciphertext_column_indices[k]];
            k++;
        }
        column_length = k;

        for (i = 0; i < ALPHABET_SIZE; i++) {
            for (k = 0; k < ALPHABET_SIZE; k++) {
                crib_frequencies[i][k] = 0;
            }
        }

        for (i = 0; i < n_cribs; i++) {
            for (k = 0; k < column_length; k++) {
                if (crib_positions[i] == ciphertext_column_indices[k]) {
                    if (verbose) printf("CT = %c, PT = %c\n", ciphertext_column[k] + 'A', crib_indices[i] + 'A');
                    
                    crib_frequencies[crib_indices[i]][ciphertext_column[k]] = 1;

                    for (ii = 0; ii < ALPHABET_SIZE; ii++) {
                        total = 0;
                        for (jj = 0; jj < ALPHABET_SIZE; jj++) {
                            total += crib_frequencies[ii][jj];
                            if (total > 1) {
                                printf("\n\nContradiction at col %d, crib char %c\n\n", j, crib_indices[i] + 'A');
                                return false;
                            }
                        }
                    }

                    for (jj = 0; jj < ALPHABET_SIZE; jj++) {
                        total = 0;
                        for (ii = 0; ii < ALPHABET_SIZE; ii++) {
                            total += crib_frequencies[ii][jj];
                            if (total > 1) {
                                printf("\n\nContradiction at col %d, crib char %c\n\n", j, crib_indices[i] + 'A');
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

bool constrain_cycleword(int cipher_indices[], int cipher_len, 
    int crib_indices[], int crib_positions[], int n_cribs, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int cycleword_indices[], int cycleword_len, 
    bool variant, bool verbose) {

    int i, j, k, crib_char, ciphertext_char, posn_keyword, posn_cycleword, 
        indx, crib_cyclewords[MAX_CYCLEWORD_LEN];

    if (n_cribs == 0) return false; 

    for (i = 0; i < cycleword_len; i++) crib_cyclewords[i] = INACTIVE; 

    for (i = 0; i < cycleword_len; i++) {
        for (j = 0; j < n_cribs; j++) {
            if (crib_positions[j]%cycleword_len == i) {
                crib_char = crib_indices[j];
                ciphertext_char = cipher_indices[crib_positions[j]];
                
                for (k = 0; k < ALPHABET_SIZE; k++) {
                    if (ciphertext_keyword_indices[k] == ciphertext_char) {
                        posn_keyword = k; 
                        break ;
                    }
                }
                for (k = 0; k < ALPHABET_SIZE; k++) {
                    if (plaintext_keyword_indices[k] == crib_char) {
                        posn_cycleword = k; 
                        break ;
                    }
                }

                if (variant) {
                    indx = (posn_cycleword - posn_keyword)%ALPHABET_SIZE;
                } else {
                    indx = (posn_keyword - posn_cycleword)%ALPHABET_SIZE;
                }
                
                if (indx < 0) indx += ALPHABET_SIZE;                    

                if (crib_cyclewords[i] == INACTIVE) {
                    if (false) printf("cycleword char %c at %d\n", ciphertext_keyword_indices[indx] + 'A', i);
                    crib_cyclewords[i] = ciphertext_keyword_indices[indx];
                    cycleword_indices[i] = ciphertext_keyword_indices[indx]; 
                } else if (crib_cyclewords[i] != ciphertext_keyword_indices[indx]) { 
                    if (false) {
                        printf("\n\nContradiction at crib %c, posn %d; rejecting keyword ", 
                            crib_indices[j] + 'A', crib_positions[j]);
                    }
                    return true; 
                }
            }
        }
    }
    return false;
}

double state_score(int cipher_indices[], int cipher_len, 
            int crib_indices[], int crib_positions[], int n_cribs, 
            int plaintext_keyword_state[], int ciphertext_keyword_state[], 
            int cycleword_state[], int cycleword_len, 
            bool variant, bool beaufort, 
            int decrypted[], 
            float *ngram_data, int ngram_size, 
            float weight_ngram, float weight_crib, float weight_ioc, float weight_entropy) {

    double score, decrypted_ngram_score, decrypted_crib_score;

    quagmire_decrypt(decrypted, cipher_indices, cipher_len, 
        plaintext_keyword_state, ciphertext_keyword_state, 
        cycleword_state, cycleword_len, variant, beaufort);

    decrypted_crib_score = crib_score(decrypted, cipher_len, crib_indices, crib_positions, n_cribs);
    // return decrypted_crib_score; 

    decrypted_ngram_score = ngram_score(decrypted, cipher_len, ngram_data, ngram_size);

    if (n_cribs > 0) {
        score = weight_ngram * decrypted_ngram_score + weight_crib * decrypted_crib_score;
        score /= weight_ngram + weight_crib;
        score /= 3.55; 
    } else {
        score = decrypted_ngram_score;
    }

    return score;
}

double entropy(int text[], int len) {
    int frequencies[ALPHABET_SIZE];
    double entropy = 0., freq;

    tally(text, len, frequencies, ALPHABET_SIZE);

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (frequencies[i] > 0) {
            freq = ((double) frequencies[i])/len;
            entropy -= freq*log(freq);
        }
    }
    return entropy;
}

double chi_squared(int plaintext[], int len) {
    int i, counts[ALPHABET_SIZE];
    double frequency, chi2 = 0.;
    tally(plaintext, len, counts, ALPHABET_SIZE);
    for (i = 0; i < ALPHABET_SIZE; i++) {
        frequency = ((double) counts[i])/len;
        chi2 += pow(frequency - english_monograms[i], 2)/english_monograms[i];
    }
    return chi2;
}

double crib_score(int text[], int len, int crib_indices[], int crib_positions[], int n_cribs) {
    if (n_cribs == 0) return 0.;
    int n_matches = 0;
    for (int i = 0; i < n_cribs; i++) {
        if (text[crib_positions[i]] == crib_indices[i]) {
            n_matches += 1;
        }
    }
    return ((double) n_matches)/((double) n_cribs);
}

double ngram_score(int decrypted[], int cipher_len, float *ngram_data, int ngram_size) {
    int index, base;
    double score = 0.;

    for (int i = 0; i < cipher_len - ngram_size + 1; i++) {
        index = 0;
        base = 1;
        for (int j = 0; j < ngram_size; j++) {
            index += decrypted[i + j]*base;
            base *= ALPHABET_SIZE;
        }
        score += ngram_data[index];
    }
    score = pow(ALPHABET_SIZE,ngram_size)*score/(cipher_len - ngram_size);
    return score;
}

void quagmire_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int cycleword_indices[], int cycleword_len, 
    bool variant, bool beaufort) {
    
    int i, j, posn_keyword, posn_cycleword, indx, ct_indx, cw_indx; 

    for (i = 0; i < cipher_len; i++) {
        // Find position of ciphertext char in ciphertext key. 
        for (j = 0; j < ALPHABET_SIZE; j++) {
            ct_indx = ciphertext_keyword_indices[j];
            if (cipher_indices[i] == ct_indx) {
                posn_keyword = j; 
                break ;
            }
        }
        // Find the position of cycleword char in keyword. 
        for (j = 0; j < ALPHABET_SIZE; j++) {
            cw_indx = cycleword_indices[i%cycleword_len];
            if (beaufort) cw_indx = ALPHABET_SIZE - cw_indx - 1; 
            if (cw_indx == ciphertext_keyword_indices[j]) {
                posn_cycleword = j; 
                break ;
            }
        }

        if (variant) {
            indx = (posn_keyword + posn_cycleword)%ALPHABET_SIZE;
        } else {
            indx = (posn_keyword - posn_cycleword)%ALPHABET_SIZE;
        }

        if (indx < 0) indx += ALPHABET_SIZE;
        decrypted[i] = plaintext_keyword_indices[indx];
        if (beaufort) decrypted[i] = ALPHABET_SIZE - decrypted[i] - 1; 
    }
}

void quagmire_encrypt(int encrypted[], int plaintext_indices[], int cipher_len, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int cycleword_indices[], int cycleword_len, 
    bool variant, bool beaufort) {
    
    int i, j, posn_keyword, posn_cycleword, indx, pt_indx, cw_indx;

    for (i = 0; i < cipher_len; i++) {
        for (j = 0; j < ALPHABET_SIZE; j++) {
            pt_indx = plaintext_indices[i];
            if (pt_indx == plaintext_keyword_indices[j]) {
                posn_keyword = j; 
                break ;
            }
        }
        for (j = 0; j < ALPHABET_SIZE; j++) {
            cw_indx = cycleword_indices[i%cycleword_len];
            if (beaufort) cw_indx = ALPHABET_SIZE - cw_indx - 1; 
            if (cw_indx == ciphertext_keyword_indices[j]) {
                posn_cycleword = j; 
                break ;
            }
        }
        if (variant) {
            indx = (posn_keyword - posn_cycleword)%ALPHABET_SIZE;
        } else {
            indx = (posn_keyword + posn_cycleword)%ALPHABET_SIZE;
        }
        if (indx < 0) indx += ALPHABET_SIZE;
        encrypted[i] = ciphertext_keyword_indices[indx];
        if (beaufort) encrypted[i] = ALPHABET_SIZE - encrypted[i] - 1; 
    }
}

void perturbate_cycleword(int state[], int max, int len) {
    int i = rand_int(0, len);
    state[i] = rand_int(0, max);
}

void perturbate_keyword(int state[], int len, int keyword_len) {
    int i, j, k, l, temp;

    if (frand() < 0.2) { 
#if KRYPTOS_PT_SCRAMBLE
        i = rand_int(7, keyword_len);
        j = rand_int(7, keyword_len);
#else
        i = rand_int(0, keyword_len);
        j = rand_int(0, keyword_len);
#endif
        temp = state[i];
        state[i] = state[j];
        state[j] = temp;
    } else {
#if KRYPTOS_PT_SCRAMBLE
        i = rand_int(7, len);   
        j = rand_int(7, len);   
#else
#if FREQUENCY_WEIGHTED_SELECTION
        i = rand_int_frequency_weighted(state, 0, keyword_len);
        j = rand_int_frequency_weighted(state, keyword_len, len);
#else
        i = rand_int(0, keyword_len);
        j = rand_int(keyword_len, len);
#endif
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
        candidate = rand_int(0, ALPHABET_SIZE);
        for (i = 0; i < n_chars; i++) {
            if (keyword[i] == candidate) {
                distinct = false;
                break ;
            }
        }
        if (distinct) keyword[n_chars++] = candidate;
    }
    indx = keyword_len;
    for (i = 0; i < ALPHABET_SIZE; i++) {
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

void make_keyed_alphabet(char *keyword_str, int *output_indices) {
    int i, char_idx;
    int seen[ALPHABET_SIZE];
    int current_pos = 0;
    int len = strlen(keyword_str);

    for(i = 0; i < ALPHABET_SIZE; i++) seen[i] = 0;

    // Process keyword string
    for(i = 0; i < len; i++) {
        char_idx = toupper(keyword_str[i]) - 'A';
        if(char_idx >= 0 && char_idx < ALPHABET_SIZE) {
            if(!seen[char_idx]) {
                output_indices[current_pos++] = char_idx;
                seen[char_idx] = 1;
            }
        }
    }

    // Fill remaining alphabet
    for(i = 0; i < ALPHABET_SIZE; i++) {
        if(!seen[i]) {
            output_indices[current_pos++] = i;
        }
    }
}

void random_cycleword(int cycleword[], int max, int keyword_len) {
    for (int i = 0; i < keyword_len; i++) {
        cycleword[i] = rand_int(0, max);
    }
}

int rand_int_frequency_weighted(int state[], int min_index, int max_index) {
    double total, rnd, cumsum;
    total = 0.;
    for (int i = min_index; i < max_index; i++) total += english_monograms[state[i]];
    rnd = frand();
    cumsum = 0.;
    for (int i = min_index; i < max_index; i++) {
        cumsum += english_monograms[state[i]]/total;
        if (cumsum > rnd) return i;
    }
    return max_index - 1;
}

float* load_ngrams(char *ngram_file, int ngram_size, bool verbose) {
    FILE *fp;
    int i, n_ngrams, freq, indx;
    char ngram[MAX_NGRAM_SIZE];
    float *ngram_data, total;

    if (verbose) printf("\nLoading ngrams...");
    n_ngrams = int_pow(ALPHABET_SIZE, ngram_size);
    ngram_data = malloc(n_ngrams*sizeof(float));
    for (i = 0; i < n_ngrams; i++) ngram_data[i] = 0.;

    fp = fopen(ngram_file, "r");
    while(!feof (fp)) {
        fscanf(fp, "%s\t%d", ngram, &freq);
        indx = ngram_index_str(ngram, ngram_size);
        ngram_data[indx] = freq;
    }
    fclose(fp);

    total = 0.;
    for (i = 0; i < n_ngrams; i++) {
        ngram_data[i] = log(1. + ngram_data[i]);
        total += ngram_data[i];
    }
    for (i = 0; i < n_ngrams; i++) ngram_data[i] /= total;  
    if (verbose) printf("...finished.\n\n");
    return ngram_data;
}

int ngram_index_str(char *ngram, int ngram_size) {
    int c, index = 0, base = 1;
    for (int i = 0; i < ngram_size; i++) {
        c = toupper(ngram[i]) - 'A';
        index += c*base;
        base *= ALPHABET_SIZE;
    }
    return index;
}

int ngram_index_int(int *ngram, int ngram_size) {
    int index = 0, base = 1;
    for (int i = 0; i < ngram_size; i++) {
        index += ngram[i]*base;
        base *= ALPHABET_SIZE;
    }
    return index;
}

void load_dictionary(char *filename, char ***dict, int *n_dict_words, int *max_dict_word_len, bool verbose) {
    FILE *fp;
    int i, n_words, max_word_len;
    char word[MAX_DICT_WORD_LEN];

    if (verbose) printf("\nLoading dictionary...\n\n");
    fp = fopen(filename, "r");
    n_words = 0;
    max_word_len = 0;
    while(!feof (fp)) {
        fscanf(fp, "%s\n", word);
        n_words++;
        if (strlen(word) > max_word_len) max_word_len = strlen(word);
    }
    *max_dict_word_len = max_word_len;
    *n_dict_words = n_words;
    fclose(fp);

    if (verbose) printf("%d words in dictionary, longest word has %d chars.\n", n_words, max_word_len);
    *dict = malloc(n_words*sizeof(char*));
    for (i = 0; i < n_words; i++) {
        (*dict)[i] = malloc((max_word_len + 1)*sizeof(char));
    }

    fp = fopen(filename, "r");
    i = 0; 
    while(!feof (fp)) {
        fscanf(fp, "%s\n", word);
        strcpy((*dict)[i], word);
        i++; 
    }
    fclose(fp);
    if (verbose) printf("\n...finished.\n");
}

void free_dictionary(char **dict, int n_dict_words) {
    for (int i = 0; i < n_dict_words; i++) free(dict[i]);
    free(dict);
}

int find_dictionary_words(char *plaintext, char **dict, int n_dict_words, int max_dict_word_len) {
    int n_matches = 0, plaintext_len, min_word_len;
    char fragment[MAX_DICT_WORD_LEN], *dict_word;
    plaintext_len = strlen(plaintext);
    min_word_len = 3;
    for (int i = 0; i < plaintext_len - min_word_len; i++) {
        for (int word_len = min_word_len; word_len < min(max_dict_word_len, plaintext_len - i); word_len++) {
            for (int j = 0; j < word_len; j++) fragment[j] = plaintext[i + j];
            fragment[word_len] = '\0'; 
            for (int k = 0; k < n_dict_words; k++) {
                dict_word = dict[k];
                if (strlen(dict_word) > word_len) continue ;
                else if (strlen(dict_word) < word_len) break ;
                else if (strcmp(dict_word, fragment) == 0 ) {
                    printf("%s\n", fragment);
                    n_matches++;
                    break ;
                }
            }
        }
    }
    return n_matches;
}

void estimate_cycleword_lengths(
    int text[], 
    int len, 
    int max_cycleword_len, 
    double n_sigma_threshold,
    double ioc_threshold,
    int *n_cycleword_lengths, 
    int cycleword_lengths[], 
    bool verbose) {

    int i, j, caesar_column[MAX_CIPHER_LENGTH]; 
    double mu, std, max_ioc, current_ioc, 
        mu_ioc[MAX_CYCLEWORD_LEN], mu_ioc_normalised[MAX_CYCLEWORD_LEN];
    bool threshold;

    for (i = 1; i <= max_cycleword_len; i++) mu_ioc[i - 1] = mean_ioc(text, len, i, caesar_column);

    mu = vec_mean(mu_ioc, max_cycleword_len);
    std = vec_stddev(mu_ioc, max_cycleword_len);

    if (verbose) printf("\ncycleword mu,std = %.3f, %.6f\n", mu, std);

    for (i = 0; i < max_cycleword_len; i++) mu_ioc_normalised[i] = (mu_ioc[i] - mu)/std;

    *n_cycleword_lengths = 0;
    current_ioc = 1.e6;
    for (i = 0; i < max_cycleword_len; i++) {
        threshold = false;
        max_ioc = 0.;
        for (j = 0; j < max_cycleword_len; j++) {
            if (mu_ioc_normalised[j] > n_sigma_threshold && mu_ioc[j] > ioc_threshold && mu_ioc_normalised[j] > max_ioc && mu_ioc_normalised[j] < current_ioc) {
                threshold = true;
                max_ioc = mu_ioc_normalised[j];
                cycleword_lengths[i] = j + 1;
            }
        }
        current_ioc = max_ioc;
        if (threshold) (*n_cycleword_lengths)++;
    }

    if (verbose) {
        printf("\nlen\tmean IOC\n");
        for (i = 0; i < max_cycleword_len; i++) printf("%d\t%.4f\n", i + 1, mu_ioc[i]);
        printf("\ncycleword_lengths =\t");
        for (i = 0; i < *n_cycleword_lengths; i++) printf("%d\t", cycleword_lengths[i]);
        printf("\n\n");
    }
}

double mean_ioc(int text[], int len, int len_cycleword, int *caesar_column) {
    int i, k;
    double weighted_ioc = 0.;
    for (k = 0; k < len_cycleword; k++) {
        i = 0;
        while (len_cycleword*i + k < len) {
            caesar_column[i] = text[len_cycleword*i + k];
            i++;
        }
        weighted_ioc += index_of_coincidence(caesar_column, i);
    }
    return weighted_ioc/len_cycleword;
}

double vec_mean(double vec[], int len) {
    int i;
    double total = 0.;
    for (i = 0; i < len; i++) total += vec[i];
    return total/len;
}

double vec_stddev(double vec[], int len) {
    int i;
    double mu, sumdev = 0.;
    mu = vec_mean(vec, len);
    for (i = 0; i < len; i++) sumdev += pow(vec[i] - mu, 2); 
    return sqrt(sumdev/len);
}

void vec_print(int vec[], int len) {
    for (int i = 0; i < len; i++) printf("%d ", vec[i]);
    printf("\n");
}

void print_text(int indices[], int len) {
    for (int i = 0; i < len; i++) printf("%c", indices[i] + 'A');
}

void ord(char *text, int indices[]) {
    for (int i = 0; i < strlen(text); i++) indices[i] = toupper(text[i]) - 'A';
}

void tally(int plaintext[], int len, int frequencies[], int n_frequencies) {
    int i;
    for (i = 0; i < n_frequencies; i++) frequencies[i] = 0;
    for (i = 0; i < len; i++) frequencies[plaintext[i]]++;
}

float index_of_coincidence(int plaintext[], int len) {
    int i, frequencies[ALPHABET_SIZE];
    double ioc = 0.;
    tally(plaintext, len, frequencies, ALPHABET_SIZE);
    for (i = 0; i < ALPHABET_SIZE; i++) ioc += frequencies[i]*(frequencies[i] - 1);
    ioc /= len*(len - 1);
    return ioc;
}

void straight_alphabet(int keyword[], int len) {
    for (int i = 0; i < len; i++) keyword[i] = i;
}

bool file_exists(const char *filename) {
    FILE *file;
    file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return true;
    }
    return false;
}

void shuffle(int *array, size_t n) {
    if (n > 1) {
        size_t i;
        for (i = 0; i < n - 1; i++) {
          size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
          int t = array[j];
          array[j] = array[i];
          array[i] = t;
        }
    }
}

void vec_copy(int src[], int dest[], int len) {
    for (int i = 0; i < len; i++) dest[i] = src[i]; 
}

int int_pow(int base, int exp) {
    int result = 1;
    while (exp) {
        if (exp % 2) result *= base;
        exp /= 2;
        base *= base;
    }
    return result;
}

int rand_int(int min, int max) {
   return min + rand() % (max - min);
}

double frand() {
  return ((double) rand())/((double) RAND_MAX);
}