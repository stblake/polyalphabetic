#include "scoring.h"

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
