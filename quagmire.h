

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h> 
#include <string.h>
#include <math.h>
#include <time.h>

#define KRYPTOS 0
#define KOMITET 0

#define ALPHABET_SIZE 26
#define MAX_CIPHER_LENGTH 10000
#define MAX_FILENAME_LEN 100
#define MAX_KEYWORD_LEN 30
#define MAX_CYCLEWORD_LEN 30
#define MAX_NGRAM_SIZE 8

#define INACTIVE -9999

#define min(a,b) (((a) < (b)) ? (a) : (b))

#define max(a,b) (((a) > (b)) ? (a) : (b))


double quagmire3_shotgun_hill_climber(
	int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs,
	int cycleword_len, int keyword_len,
	int n_hill_climbs, int n_restarts,
	float *ngram_data, int ngram_size, 
	int decrypted[MAX_CIPHER_LENGTH], int keyword[ALPHABET_SIZE], int cycleword[ALPHABET_SIZE],
	double backtracking_probability, double keyword_permutation_probability, double slip_probability,
	bool verbose);

bool cribs_satisfied_p(int cipher_indices[], int cipher_len, int crib_indices[], 
	int crib_positions[], int n_cribs, int cycleword_len, bool verbose);

bool constrain_cycleword(int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs, 
	int keyword_indices[], int cycleword_indices[], int cycleword_len, 
	bool verbose);

void quagmire3_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
	int keyword_indices[], int cycleword_indices[], int cycleword_len);

double state_score(int cipher_indices[], int cipher_len, 
			int crib_indices[], int crib_positions[], int n_cribs, 
			int keyword_state[], int cycleword_state[], int cycleword_len,
			int decrypted[], 
			float *ngram_data, int ngram_size);

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
