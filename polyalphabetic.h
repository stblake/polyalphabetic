#ifndef POLYALPHABETIC_H
#define POLYALPHABETIC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h> 
#include <string.h>
#include <math.h>
#include <time.h>
#include <strings.h>

#define KRYPTOS 0
#define CRIB_CHECK 0

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

#define ALPHABET_SIZE 26
#define MAX_CIPHER_LENGTH 10000
#define MAX_FILENAME_LEN 100
#define MAX_KEYWORD_LEN 26
#define MAX_CYCLEWORD_LEN 300
#define MAX_NGRAM_SIZE 8
#define MAX_DICT_WORD_LEN 30

#define FREQUENCY_WEIGHTED_SELECTION 1
#define DICTIONARY 1
#define INACTIVE -9999

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

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

    // Files
    char ciphertext_file[MAX_FILENAME_LEN];
    char batch_file[MAX_FILENAME_LEN];
    char crib_file[MAX_FILENAME_LEN];
    char dictionary_file[MAX_FILENAME_LEN];
    char ngram_file[MAX_FILENAME_LEN];

    // Flags
    bool verbose;
    bool cipher_present;
    bool batch_present;
    bool crib_present;
    bool dictionary_present;
    bool variant;
    bool beaufort;

    bool optimal_cycleword;
    bool same_key_cycle;

} PolyalphabeticConfig;

typedef struct {
    float *ngram_data;
    char **dict;
    int n_dict_words;
    int max_dict_word_len;
} SharedData;

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
void solve_cipher(char *ciphertext_str, char *cribtext_str, PolyalphabeticConfig *cfg, SharedData *shared);

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
void autokey_decrypt(PolyalphabeticConfig *cfg, int decrypted[], int cipher_indices[], 
    int cipher_len, int plaintext_keyword[], int ciphertext_keyword[],
    int key_indices[], int key_len);

// Hill Climber
double shotgun_hill_climber(
    PolyalphabeticConfig *cfg,
	int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs,
	int cycleword_len, int plaintext_keyword_len, int ciphertext_keyword_len, 
	float *ngram_data,
	int decrypted[MAX_CIPHER_LENGTH], int plaintext_keyword[ALPHABET_SIZE], 
	int ciphertext_keyword[ALPHABET_SIZE], int cycleword[MAX_CYCLEWORD_LEN]);

void derive_optimal_cycleword(
    PolyalphabeticConfig *cfg, 
    int cipher_indices[], int cipher_len,
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[],
    int cycleword_state[], int cycleword_len);

// Helpers
bool cribs_satisfied_p(int cipher_indices[], int cipher_len, int crib_indices[], 
	int crib_positions[], int n_cribs, int cycleword_len, bool verbose);

bool constrain_cycleword(int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs, 
	int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
	int cycleword_indices[], int cycleword_len,
	bool variant, bool verbose);

double state_score(PolyalphabeticConfig *cfg, 
            int cipher_indices[], int cipher_len, 
			int crib_indices[], int crib_positions[], int n_cribs, 
			int plaintext_keyword_state[], int ciphertext_keyword_state[], 
			int cycleword_state[], int cycleword_len,
			int decrypted[], 
			float *ngram_data, int ngram_size,
			float weight_ngram, float weight_crib, float weight_ioc, float weight_entropy);

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
int rand_int(int min, int max);
int rand_int_frequency_weighted(int state[], int min_index, int max_index);
double frand();
void shuffle(int *array, size_t n);

// Stats
double mean_ioc(int text[], int len, int len_cycleword, int *caesar_column);
void estimate_cycleword_lengths(int text[], int len, int max_cycleword_len, 
	double n_sigma_threshold, double ioc_threshold, 
	int *n_cycleword_lengths, int cycleword_lengths[], bool verbose);
double vec_mean(double vec[], int len);
double vec_stddev(double vec[], int len);

// Utils
int parse_cipher_type(const char *arg);
int unique_len(char *str);
void vec_print(int vec[], int len);
void print_text(int indices[], int len);
void ord(char *text, int indices[]);
float index_of_coincidence(int plaintext[], int len);
void tally(int plaintext[], int len, int frequencies[], int n_frequencies);
bool file_exists(const char * filename);
void vec_copy(int src[], int dest[], int len);
int int_pow(int base, int exp);

#endif
