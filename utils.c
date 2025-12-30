
// Cryptanalytic and general software utilities 


#include "polyalphabetic.h"


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



int unique_len(char *str) {
    int len = 0;
    int seen[ALPHABET_SIZE];
    int i, idx;

    // Initialise seen array.
    for (i = 0; i < ALPHABET_SIZE; i++) seen[i] = 0;

    for (i = 0; str[i] != '\0'; i++) {
        idx = toupper(str[i]) - 'A';
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

