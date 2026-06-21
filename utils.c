
// Cryptanalytic and general software utilities 


#include "colossus.h"

uint32_t rng_state = 123456789;

// --- Runtime alphabet (see colossus.h). Defaults to the full A..Z so the
// historical 26-letter behaviour is bit-identical until -excludeletter/-alphabet
// is given. ---
int  g_alpha = ALPHABET_SIZE;
int  g_char_to_idx[128];
char g_idx_to_char_arr[ALPHABET_SIZE + 1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
double g_monograms[ALPHABET_SIZE];

// Build the index<->char maps and the reindexed monogram table. `excluded` is a
// string of letters to drop from the standard A..Z ordering (NULL/"" => full A..Z).
void init_alphabet(const char *excluded) {
    for (int i = 0; i < 128; i++) g_char_to_idx[i] = -1;
    int pos = 0;
    for (char c = 'A'; c <= 'Z'; c++) {
        bool drop = false;
        if (excluded) {
            for (const char *e = excluded; *e; e++) {
                if (toupper((unsigned char) *e) == c) { drop = true; break; }
            }
        }
        if (drop) continue;
        g_idx_to_char_arr[pos] = c;
        g_char_to_idx[(int) c] = pos;
        g_monograms[pos] = english_monograms[c - 'A'];
        pos++;
    }
    g_idx_to_char_arr[pos] = '\0';
    g_alpha = pos;
}

int gcd(int a, int b) {
    while (b) { a %= b; int t = a; a = b; b = t; }
    return a;
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
    for (i = 0; i < g_alpha; i++) {
        frequency = ((double) counts[i])/len;
        chi2 += pow(frequency - g_monograms[i], 2)/g_monograms[i];
    }
    return chi2;
}



int unique_len(char *str) {
    int len = 0;
    int seen[ALPHABET_SIZE];
    int i, idx;

    // Initialise seen array.
    for (i = 0; i < ALPHABET_SIZE; i++) seen[i] = 0;

    for (i = 0; str[i] != '\0'; i++) {
        unsigned char ch = (unsigned char) toupper((unsigned char) str[i]);
        idx = (ch < 128) ? g_char_to_idx[ch] : -1;
        if (idx >= 0 && idx < ALPHABET_SIZE) {
            if (!seen[idx]) {
                seen[idx] = 1;
                len++;
            }
        }
    }
    return len;
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
    for (int i = 0; i < len; i++) printf("%c", index_to_char(indices[i]));
}



void ord(char *text, int indices[]) {
    for (int i = 0; i < strlen(text); i++) {
        unsigned char c = (unsigned char) text[i];
        int v = isalpha(c) ? g_char_to_idx[toupper(c)] : -1;
        // Letters outside the runtime alphabet (e.g. 'P' under -excludeletter P)
        // and all non-letters are carried as reversible negative sentinels.
        indices[i] = (v >= 0) ? v : (-(int) c - 1);
    }
}



void tally(int plaintext[], int len, int frequencies[], int n_frequencies) {
    int i;
    for (i = 0; i < n_frequencies; i++) frequencies[i] = 0;
    // Skip negative sentinels (non-alphabetic characters); they have no histogram
    // bin. For all-letter text this loop is identical to the unguarded version.
    for (i = 0; i < len; i++) {
        if (plaintext[i] >= 0 && plaintext[i] < n_frequencies) frequencies[plaintext[i]]++;
    }
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

// Build a keyed alphabet (as 0-25 indices) from a keyword string: the keyword's
// distinct letters in order, then the remaining letters in alphabetical order.
void make_keyed_alphabet(char *keyword_str, int *output_indices) {
    int i, char_idx;
    int seen[ALPHABET_SIZE];
    int current_pos = 0;
    int len = strlen(keyword_str);

    for(i = 0; i < ALPHABET_SIZE; i++) seen[i] = 0;

    // Process keyword string.
    for(i = 0; i < len; i++) {
        char_idx = g_char_to_idx[toupper((unsigned char) keyword_str[i]) & 127];
        if(char_idx >= 0 && char_idx < ALPHABET_SIZE) {
            if(!seen[char_idx]) {
                output_indices[current_pos++] = char_idx;
                seen[char_idx] = 1;
            }
        }
    }

    // Fill remaining alphabet.
    for(i = 0; i < g_alpha; i++) {
        if(!seen[i]) {
            output_indices[current_pos++] = i;
        }
    }
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
          // size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
          size_t range = n - i;
          size_t j = i + rand_bounded(range);
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
        if (exp) base *= base; // skip the final squaring (would overflow, e.g. 26^4 squared)
    }
    return result;
}
