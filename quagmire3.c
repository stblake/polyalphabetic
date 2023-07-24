//
//	Quagmire III cipher solver
//

// Written by Sam Blake, started 14 July 2023


#include "quagmire3.h"


/* Program syntax:

	$ ./quagmire3 \
		-cipher /ciphertext file/ \
		-crib /crib file/ \
		-temperature /initial temperature/ \
		-coolrate /cooling rate/ \
		-ngramsize /n-gram size in n-gram statistics file/ \
		-ngramfile /n-gram statistics file/ \
		-maxkeywordlen /max length of the keyword/ \
		-maxcyclewordlen /max length of the cycleword/ \
		-nsigmathreshold /n sigma threshold for candidate keyword length/ \
		-nrestarts /number of restarts/ \
		-verbose


	Notes: 

	/ciphertext file/ -- may contain multiple ciphers, with one per line.

	/crib file/ -- uses "_" for unknown chars. Just a single line of the same length
	as the ciphers contained in the cipher file. For K4 it should contain

		_____________________EASTNORTHEAST_____________________________BERLINCLOCK_______________________
	
*/

#define ALPHABET_SIZE 26

#define MAX_CIPHER_LENGTH 1000
#define MAX_FILENAME_LEN 64



int main(int argc, char **argv) {

	int i, cipher_len, ngram_size = 0, max_keyword_len = 12, max_cycleword_len = 12, n_restarts = 1, n_cycleword_lengths, 
		n_cribs, cipher_indices[MAX_CIPHER_LENGTH], crib_positions[MAX_CIPHER_LENGTH], 
		crib_indices[MAX_CIPHER_LENGTH], cycleword_lengths[MAX_CIPHER_LENGTH]; 
	double n_sigma_threshold = 1., *ngram_table;
	char ciphertext_file[MAX_FILENAME_LEN], crib_file[MAX_FILENAME_LEN], 
		model_config_file[MAX_FILENAME_LEN], ngram_file[MAX_FILENAME_LEN],
		ciphertext[MAX_CIPHER_LENGTH], cribtext[MAX_CIPHER_LENGTH];
	bool verbose = false, cipher_present = false, crib_present = false;
	FILE *fp;


	// Read command line args. 
	for(i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-cipher") == 0) {
			cipher_present = true;
			strcpy(ciphertext_file, argv[++i]);
			printf("\n-cipher %s", ciphertext_file);
		} else if (strcmp(argv[i], "-crib") == 0) {
			crib_present = true;
			strcpy(crib_file, argv[++i]);
			printf("\n-crib %s", crib_file);
		} else if (strcmp(argv[i], "-ngramsize") == 0) {
			ngram_size = atoi(argv[++i]);
			printf("\n-ngram_size %d", ngram_size);
		} else if (strcmp(argv[i], "-ngramfile") == 0) {
			strcpy(ngram_file, argv[++i]);
			printf("\n-ngramfile %s", ngram_file);
		} else if (strcmp(argv[i], "-maxkeywordlen") == 0) {
			max_keyword_len = atoi(argv[++i]);
			printf("\n-maxkeywordlen %d", max_keyword_len);
		} else if (strcmp(argv[i], "-maxcyclewordlen") == 0) {
			max_cycleword_len = atoi(argv[++i]);
			printf("\n-maxcyclewordlen %d", max_cycleword_len);
		} else if (strcmp(argv[i], "-nsigmathreshold") == 0) {
			n_sigma_threshold = atof(argv[++i]);
			printf("\n-nsigmathreshold %.2f", n_sigma_threshold);
		} else if (strcmp(argv[i], "-nrestarts") == 0) {
			n_restarts = atoi(argv[++i]);
			printf("\n-nrestarts %d", n_restarts);
		} else if (strcmp(argv[i], "-verbose") == 0) {
			verbose = true;
			printf("\n-verbose ");
		} else {
			printf("\n\nERROR: unknown arg '%s'", argv[i]);
			return 0;
		}
	}
	printf("\n\n");

	// Check command line inputs. 
	if (!cipher_present) {
		printf("\n\nERROR: cipher file not present.\n\n");
		return 0;
	}

	if (ngram_size == 0) {
		printf("\n\nERROR: -ngramsize missing.\n\n");
		return 0;
	}

	if (! file_exists(ciphertext_file)) {
		printf("\nERROR: missing file '%s'\n", ciphertext_file);
  		return 0;
	}

	if (! file_exists(ngram_file)) {
		printf("\nERROR: missing file '%s'\n", ngram_file);
  		return 0;
	}

	if (crib_present && ! file_exists(crib_file)) {
		printf("\nERROR: missing file '%s'\n", crib_file);
  		return 0;
	}

	// Read ciphertext. 

	fp = fopen(ciphertext_file, "r");
	fscanf(fp, "%s", ciphertext);
	fclose(fp);

	if (verbose) {
		printf("ciphertext = \n\'%s\'\n\n", ciphertext);
	}

	cipher_len = (int) strlen(ciphertext);

	// Read crib. 

	fp = fopen(crib_file, "r");
	fscanf(fp, "%s", cribtext);
	fclose(fp);

	if (verbose) {
		printf("cribtext = \n\'%s\'\n\n", cribtext);
	}

	// Check ciphertext and cribtext are of the same length. 

	if (cipher_len != strlen(cribtext)) {
		printf("\n\nERROR: strlen(ciphertext) = %d, strlen(cribtext) = %lu.\n\n", 
			cipher_len, strlen(cribtext));
		return 0; 
	}

	// Extract crib positions and corresponding plaintext. 

	if (verbose) {
		printf("\ncrib indices = \n\n");
	}

	n_cribs = 0;
	for (i = 0; i < cipher_len; i++) {
		if (cribtext[i] != '_') {
			crib_positions[n_cribs] = i;
			crib_indices[n_cribs] = cribtext[i] - 'A';
			n_cribs++;
			if (verbose) {
				printf("%d, %c, %d\n", i, cribtext[i], cribtext[i] - 'A');
			}
		}
	}

	if (verbose) {
		printf("\n");
	}

	// Compute ciphertext indices. 

	ord(ciphertext, cipher_indices);

	// Estimate cycleword length. 

	estimate_cycleword_lengths(
			cipher_indices, 
			cipher_len, 
			max_cycleword_len, 
			n_sigma_threshold,
			&n_cycleword_lengths, 
			cycleword_lengths, 
			verbose);

	// Set random seed.

	srand(time(NULL));

	// For each cycleword length, run the 'shotgun' hill climber. 

	for (i = 0; i < n_cycleword_lengths; i++) {
		if (verbose) {
			printf("\ncycleword length = %d\n", cycleword_lengths[i]);
		}

		quagmire3_shotgun_hill_climber(
			cipher_indices, 
			cipher_len, 
			crib_indices, 
			crib_positions, 
			n_cribs,
			n_restarts, 
			verbose);
	}


#if 0
	// Read crib file. 


	// Read n-gram file. 
	read_ngram_file(ngram_size, ngram_file, ngram_table);

	fp = fopen(ciphertext_file, "r");

	while ( ! feof(fp) ) {

		// Read ciphertext from file. 
		fscanf(fp, "%s", ciphertext);
		printf("\n%s\n", ciphertext);

		cipher_len = strlen(ciphertext);


		// Estimate cycleword length. 

		// Check for collision against crib. 


		// Call the optimisation routine. 

		solve_quagmire3_simulated_annealing( // TODO: add n_restarts
				ciphertext, cribtext, 
				ngram_size, ngram_table, 
				init_temp, cooling_rate, verbose_level,
				&score, keyword, cycleword, plaintext);

		printf("%.2f\t%s\t%s\t%s\n", score, keyword, cycleword, plaintext);

	}

	fclose(fp);
#endif

	return 1;
}



// 'shotgun' hill climber for Quagmire 3 cipher

void quagmire3_shotgun_hill_climber(
	int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs,
	int n_restarts, bool verbose) {



}



// Estimate the cycleword length from the ciphertext. 

void estimate_cycleword_lengths(
	int text[], 
	int len, 
	int max_cycleword_len, 
	double n_sigma_threshold,
	int *n_cycleword_lengths, 
	int cycleword_lengths[], 
	bool verbose) {

	int i, j, *caesar_column; 
	double *mu_ioc, *mu_ioc_normalised, mu, std, max_ioc, current_ioc;
	bool threshold;

	// Compute the mean IOC for each candidate cycleword length. 
	mu_ioc = malloc((max_cycleword_len - 1)*sizeof(double));
	mu_ioc_normalised = malloc((max_cycleword_len - 1)*sizeof(double));
	caesar_column = malloc(len*sizeof(int));

	for (i = 1; i <= max_cycleword_len; i++) {
		mu_ioc[i - 1] = mean_ioc(text, len, i, caesar_column);
	}

	// Normalise.
	mu = vec_mean(mu_ioc, max_cycleword_len);
	std = vec_stddev(mu_ioc, max_cycleword_len);

	if (verbose) {
		printf("\ncycleword mu,std = %.3f, %.6f\n", mu, std);
	}

	for (i = 0; i < max_cycleword_len; i++) {
		mu_ioc_normalised[i] = (mu_ioc[i] - mu)/std;
	}

	// Select only those above n_sigma_threshold and sort by mean IOC. 

	// TODO: the sorting by max IOC makes this code is fucking ugly - rewrite! 

	*n_cycleword_lengths = 0;
	max_ioc = 1.e6;
	for (i = 0; i < max_cycleword_len; i++) {
		threshold = false;
		for (j = 0; j < max_cycleword_len; j++) {
			if (mu_ioc_normalised[j] > n_sigma_threshold && mu_ioc_normalised[j] < max_ioc) {
				threshold = true;
				current_ioc = mu_ioc_normalised[j];
				cycleword_lengths[i] = j + 1;
			}
		}
		max_ioc = current_ioc;
		if (threshold) {
			(*n_cycleword_lengths)++;
		}
	}

	if (verbose) {
		printf("\nlen\tmean IOC\tnormalised IOC\n");
		for (i = 0; i < max_cycleword_len; i++) {
			if (verbose) {
				printf("%d\t%.3f\t\t%.2f\n", i + 1, mu_ioc[i], mu_ioc_normalised[i]);
			}
		}
	}

	if (verbose) {
		printf("\ncycleword_lengths =\t");
		for (i = 0; i < *n_cycleword_lengths; i++) {
			printf("%d\t", cycleword_lengths[i]);
		}
		printf("\n\n");
	}


	free(mu_ioc);
	free(mu_ioc_normalised);
	free(caesar_column);
	
	return ;
}



// Given the cycleword length, compute the mean IOC. 

double mean_ioc(int text[], int len, int len_cycleword, int *caesar_column) {

	int i, k;
	double weighted_ioc = 0.;

	for (k = 0; k < len_cycleword; k++) {

		i = 0;
		while (len_cycleword*i + k < len) {
			caesar_column[i] = text[len_cycleword*i + k];
			i++;
		}

		weighted_ioc += i*index_of_coincidence(caesar_column, i);
	}

	return weighted_ioc/len;
}



// Mean and standard deviation of a 1D array. 

double vec_mean(double vec[], int len) {
	int i;
	double total = 0.;

	for (i = 0; i < len; i++) {
		total += vec[i];
	}
	return total/len;
}



double vec_stddev(double vec[], int len) {

	int i, count = 0;
	double mu, sumdev = 0.;

	mu = vec_mean(vec, len);

	for (i = 0; i < len; i++) {
		sumdev += pow(vec[i] - mu, 2); 
	}

    return sqrt(sumdev/len);
}



// Print plaintext from indices. 

void print_text(int indices[], int len) {

	for (int i = 0; i < len; i++) {
		printf("%c", indices[i] + 'A');
	}
	return ;
}



// Compute the index of each char. A -> 0, B -> 1, ..., Z -> 25

void ord(char *text, int indices[]) {

	for (int i = 0; i < strlen(text); i++) {
		indices[i] = toupper(text[i]) - 'A';
	}

	return ;
}



// Count the frequencies of char in plaintext. 

void tally(int plaintext[], int len, int frequencies[], int n_frequencies) {

	int i;

	// Initialise frequencies to zero. 
	for (i = 0; i < n_frequencies; i++) {
		frequencies[i] = 0;
	}

	// Tally. 
	for (i = 0; i < len; i++) {
		frequencies[plaintext[i]]++;
	}

	return ;
}

// Friedman's Index of Coincidence. 

float index_of_coincidence(int plaintext[], int len) {

	int i, frequencies[ALPHABET_SIZE];
	double ioc = 0.;

	// Compute plaintext char frequencies. 
	tally(plaintext, len, frequencies, ALPHABET_SIZE);

	for (i = 0; i < ALPHABET_SIZE; i++) {
        ioc += frequencies[i]*(frequencies[i] - 1);
    }

    ioc /= len*(len - 1);
    return ioc;
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




