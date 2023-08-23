

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h> 
#include <string.h>
#include <math.h>
#include <time.h>

#define KRYPTOS_PT 0
#define KOMITET_PT 0

#define KRYPTOS_CT 0
#define KOMITET_CT 0

#define VIGENERE 0
#define QUAGMIRE_1 1
#define QUAGMIRE_2 2
#define QUAGMIRE_3 3
#define QUAGMIRE_4 4

#define ALPHABET_SIZE 26
#define MAX_CIPHER_LENGTH 10000
#define MAX_FILENAME_LEN 100
#define MAX_KEYWORD_LEN 30
#define MAX_CYCLEWORD_LEN 30
#define MAX_NGRAM_SIZE 8

#define FREQUENCY_WEIGHTED_SELECTION 1

#define INACTIVE -9999

#define min(a,b) (((a) < (b)) ? (a) : (b))

#define max(a,b) (((a) > (b)) ? (a) : (b))


// English word length frequencies. (Ref: https://math.wvu.edu/~hdiamond/Math222F17/Sigurd_et_al-2004-Studia_Linguistica.pdf)

int n_english_word_length_frequency_letters = 25;
double english_word_length_frequencies[] = {
	0.0316, 0.16975, 0.21192, 0.15678, 0.10852, 0.08524, 0.07724, 
	0.05623, 0.04032, 0.02766, 0.01582, 0.00917, 0.00483, 0.00262, 
	0.00099, 0.0005, 0.00027, 0.00022, 0.00011, 0.00006, 0.00005, 
	0.00002, 0.00001, 0.00001, 0.00001};



// Ref: http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
double english_monograms[] = {
	0.085517, // A
	0.016048, // B
	0.031644, // C
	0.038712, // D
	0.120965, // E
	0.021815, // F
	0.020863, // G
	0.049557, // H
	0.073251, // I
	0.002198, // J
	0.008087, // K
	0.042065, // L
	0.025263, // M
	0.071722, // N
	0.074673, // O
	0.020662, // P
	0.001040, // Q
	0.063327, // R
	0.067282, // S
	0.089381, // T
	0.026816, // U
	0.010593, // V
	0.018254, // W
	0.001914, // X
	0.017214, // Y
	0.001138  // Z
};



double quagmire_shotgun_hill_climber(
	int cipher_type, 
	int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs,
	int cycleword_len, int plaintext_keyword_len, int ciphertext_keyword_len, 
	int n_hill_climbs, int n_restarts,
	float *ngram_data, int ngram_size,
	int decrypted[MAX_CIPHER_LENGTH], int plaintext_keyword[ALPHABET_SIZE], 
	int ciphertext_keyword[ALPHABET_SIZE], int cycleword[ALPHABET_SIZE],
	double backtracking_probability, double keyword_permutation_probability, double slip_probability,
	bool verbose);

bool cribs_satisfied_p(int cipher_indices[], int cipher_len, int crib_indices[], 
	int crib_positions[], int n_cribs, int cycleword_len, bool verbose);

bool constrain_cycleword(int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs, 
	int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
	int cycleword_indices[], int cycleword_len, bool verbose);

void quagmire_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
	int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
	int cycleword_indices[], int cycleword_len);

double state_score(int cipher_indices[], int cipher_len, 
			int crib_indices[], int crib_positions[], int n_cribs, 
			int plaintext_keyword_state[], int ciphertext_keyword_state[], 
			int cycleword_state[], int cycleword_len,
			int decrypted[], 
			float *ngram_data, int ngram_size);

void straight_alphabet(int keyword[], int len);

double ngram_score(int decrypted[], int cipher_len, float *ngram_data, int ngram_size);

double crib_score(int text[], int len, int crib_indices[], int crib_positions[], int n_cribs);

double entropy(int text[], int len);
double chi_squared(int plaintext[], int len);

float* load_ngrams(char *ngram_file, int ngram_size, bool verbose);
int ngram_index_int(int *ngram, int ngram_size);
int ngram_index_str(char *ngram, int ngram_size);

void pertubate_keyword(int state[], int len, int keyword_len);
void random_keyword(int keyword[], int len, int keyword_len);

void random_cycleword(int cycleword[], int max, int keyword_len);
void pertubate_cycleword(int state[], int max, int len);

int rand_int(int min, int max);
int rand_int_frequency_weighted(int state[], int min_index, int max_index);

double mean_ioc(int text[], int len, int len_cycleword, int *caesar_column);
void estimate_cycleword_lengths(int text[], int len, int max_cycleword_len, double n_sigma_threshold,
	int *n_cycleword_lengths, int cycleword_lengths[], bool verbose);
double vec_mean(double vec[], int len);
double vec_stddev(double vec[], int len);
void vec_print(int vec[], int len);
void print_text(int indices[], int len);
void ord(char *text, int indices[]);
float index_of_coincidence(int plaintext[], int len);
void tally(int plaintext[], int len, int frequencies[], int n_frequencies);
bool file_exists(const char * filename);
void shuffle(int *array, size_t n);
void vec_copy(int src[], int dest[], int len);
int int_pow(int base, int exp);
double frand();
