//
//	Quagmire III cipher solver - stochastic shotgun-restarted hill climber 
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
		-nlocal /number of local searches to find an improved score/ \
		-nhillclimbs /number of hillclimbing steps/ \
		-backtrackprob /probability of backtracking to the best 
			solution instead of a random initial solution/ \
		-keywordpermprob /probability of permuting the keyword instead of the cycleword/
		-nrestarts /number of restarts/ \
		-verbose


	Notes: 

		/ciphertext file/ -- may contain multiple ciphers, with one per line.

		/crib file/ -- uses "_" for unknown chars. Just a single line of the same length
			as the ciphers contained in the cipher file. For Kryptos K4 cipher it should contain

		_____________________EASTNORTHEAST_____________________________BERLINCLOCK_______________________
	
*/

int main(int argc, char **argv) {

	int i, j, cipher_len, keyword_len, cycleword_len, ngram_size = 0, max_keyword_len = 12, max_cycleword_len = 12, n_restarts = 1, 
		n_local = 1, n_cycleword_lengths, n_hill_climbs = 1000, n_cribs, best_cycleword_length, best_keyword_length,
		cipher_indices[MAX_CIPHER_LENGTH], crib_positions[MAX_CIPHER_LENGTH], 
		crib_indices[MAX_CIPHER_LENGTH], cycleword_lengths[MAX_CIPHER_LENGTH],
		decrypted[MAX_CIPHER_LENGTH], best_decrypted[MAX_CIPHER_LENGTH],
		keyword[ALPHABET_SIZE], cycleword[ALPHABET_SIZE],
		best_keyword[ALPHABET_SIZE], best_cycleword[ALPHABET_SIZE]; 
	double n_sigma_threshold = 1., backtracking_probability = 0.01, keyword_permutation_probability = 0.01, 
		slip_probability = 0.01, score, best_score;
	char ciphertext_file[MAX_FILENAME_LEN], crib_file[MAX_FILENAME_LEN], 
		ngram_file[MAX_FILENAME_LEN], ciphertext[MAX_CIPHER_LENGTH], 
		cribtext[MAX_CIPHER_LENGTH];
	bool verbose = false, cipher_present = false, crib_present = false, keyword_len_present = false, 
		cycleword_len_present = false;
	FILE *fp;
	float *ngram_data;


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
		} else if (strcmp(argv[i], "-keywordlen") == 0) {
			keyword_len_present = true;
			keyword_len = atoi(argv[++i]);
			printf("\n-keywordlen %d", keyword_len);
		} else if (strcmp(argv[i], "-maxcyclewordlen") == 0) {
			max_cycleword_len = atoi(argv[++i]);
			printf("\n-maxcyclewordlen %d", max_cycleword_len);
		} else if (strcmp(argv[i], "-cyclewordlen") == 0) {
			cycleword_len_present = true;
			cycleword_len = atoi(argv[++i]);
			printf("\n-cyclewordlen %d", cycleword_len);
		} else if (strcmp(argv[i], "-nsigmathreshold") == 0) {
			n_sigma_threshold = atof(argv[++i]);
			printf("\n-nsigmathreshold %.2f", n_sigma_threshold);
		} else if (strcmp(argv[i], "-nlocal") == 0) {
			n_local = atoi(argv[++i]);
			printf("\n-nlocal %d", n_local);	
		} else if (strcmp(argv[i], "-nhillclimbs") == 0) {
			n_hill_climbs = atoi(argv[++i]);
			printf("\n-nhillclimbs %d", n_hill_climbs);			
		} else if (strcmp(argv[i], "-nrestarts") == 0) {
			n_restarts = atoi(argv[++i]);
			printf("\n-nrestarts %d", n_restarts);
		} else if (strcmp(argv[i], "-backtrackprob") == 0) {
			backtracking_probability = atof(argv[++i]);
			printf("\n-backtrackprob %.4f", backtracking_probability);
		} else if (strcmp(argv[i], "-keywordpermprob") == 0) {
			backtracking_probability = atof(argv[++i]);
			printf("\n-keywordpermprob %.4f", keyword_permutation_probability);
		} else if (strcmp(argv[i], "-slipprob") == 0) {
			slip_probability = atof(argv[++i]);
			printf("\n-slipprob %.4f", slip_probability);
		} else if (strcmp(argv[i], "-verbose") == 0) {
			verbose = true;
			printf("\n-verbose ");
		} else {
			printf("\n\nERROR: unknown arg '%s'\n\n", argv[i]);
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

	if (file_exists(crib_file)) {

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
	} else {
		// No cribs present. 
		n_cribs = 0;
	}

	// Load n-gram file. 

	ngram_data = load_ngrams(ngram_file, ngram_size, verbose);

	// Compute ciphertext indices. A -> 0, B -> 1, ..., Z -> 25 (Assuming ALPHABET_SIZE = 26)

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

	best_score = 0.;

	for (i = 0; i < n_cycleword_lengths; i++) {
		for (j = 3; j < max_keyword_len; j++) {

			if (keyword_len_present && j != keyword_len) continue;

			if (cycleword_len_present && cycleword_lengths[i] != cycleword_len) continue;

			if (verbose) {
				printf("\ncycleword/keyword length = %d, %d\n", cycleword_lengths[i], j);
			}

			score = quagmire3_shotgun_hill_climber(
				cipher_indices, 
				cipher_len, 
				crib_indices, 
				crib_positions, 
				n_cribs, 
				cycleword_lengths[i],
				j, 
				n_local, 
				n_hill_climbs, 
				n_restarts, 
				ngram_data, 
				ngram_size,
				decrypted, 
				keyword,
				cycleword, 
				backtracking_probability,
				keyword_permutation_probability,
				slip_probability, 
				verbose);

			if (score > best_score) {
				best_score = score;
				best_cycleword_length = cycleword_lengths[i];
				best_keyword_length = j;
				vec_copy(decrypted, best_decrypted, cipher_len);
				vec_copy(keyword, best_keyword, ALPHABET_SIZE);
				vec_copy(cycleword, best_cycleword, ALPHABET_SIZE);
			}
		}
	}

	printf("\n\n%.2f\n", best_score);
	print_text(cipher_indices, cipher_len);
	printf("\n");
	print_text(best_keyword, ALPHABET_SIZE);
	printf("\n");
	print_text(best_cycleword, best_cycleword_length);
	printf("\n");
	print_text(best_decrypted, cipher_len);
	printf("\n\n");

	free(ngram_data);

	return 1;
}





// slippery stochastic shotgun restarted hill climber for Quagmire 3 cipher

double quagmire3_shotgun_hill_climber(
	int cipher_indices[], int cipher_len, 
	int crib_indices[], int crib_positions[], int n_cribs,
	int cycleword_len, int keyword_len, 
	int n_local, int n_hill_climbs, int n_restarts,
	float *ngram_data, int ngram_size,
	int decrypted[MAX_CIPHER_LENGTH], int keyword[ALPHABET_SIZE], int cycleword[ALPHABET_SIZE],
	double backtracking_probability, double keyword_permutation_probability, double slip_probability,
	bool verbose) {

	int i, j, n, n_iterations, n_backtracks, n_explore, 
		local_keyword_state[ALPHABET_SIZE], current_keyword_state[ALPHABET_SIZE], 
		best_keyword_state[ALPHABET_SIZE],
		local_cycleword_state[MAX_CYCLEWORD_LEN], current_cycleword_state[MAX_CYCLEWORD_LEN], 
		best_cycleword_state[MAX_CYCLEWORD_LEN];
	double start_time, elapsed, n_iter_per_sec, best_score, local_score, current_score;

	n_iterations = 0;
	n_backtracks = 0;
	n_explore = 0;
	start_time = clock();

	// TODO: remove local search (does nothing in this context.)

	best_score = 0.;

	for (n = 0; n < n_restarts; n++) {

		if (best_score > 0. && frand() < backtracking_probability) {
			// Backtrack to best state. 
			n_backtracks += 1;
			current_score = best_score;
			vec_copy(best_keyword_state, current_keyword_state, ALPHABET_SIZE);
			vec_copy(best_cycleword_state, current_cycleword_state, cycleword_len);
		} else {
			// Initialise random state.
			random_keyword(current_keyword_state, ALPHABET_SIZE, keyword_len);
			random_cycleword(current_cycleword_state, ALPHABET_SIZE, cycleword_len);

			current_score = state_score(cipher_indices, cipher_len, 
				crib_indices, crib_positions, n_cribs, 
				current_keyword_state, current_cycleword_state, cycleword_len,
				decrypted, ngram_data, ngram_size);
		}

		for (i = 0; i < n_hill_climbs; i++) {

			// Local search for improved state. 
			for (j = 0; j < n_local; j++) {
				
				n_iterations += 1;

				// Pertubate.
				vec_copy(current_keyword_state, local_keyword_state, ALPHABET_SIZE);
				vec_copy(current_cycleword_state, local_cycleword_state, cycleword_len);

				if (frand() < keyword_permutation_probability) {
					pertubate_keyword(local_keyword_state, ALPHABET_SIZE, keyword_len);
				} else {
					pertubate_cycleword(local_cycleword_state, ALPHABET_SIZE, cycleword_len);
				}

				// Compute score. 
				local_score = state_score(cipher_indices, cipher_len, 
					crib_indices, crib_positions, n_cribs, 
					local_keyword_state, local_cycleword_state, cycleword_len,
					decrypted, ngram_data, ngram_size);

#if 0
				printf("\nlocal_score = %.4f\n", local_score);
				print_text(decrypted, cipher_len);
				printf("\n");
				print_text(local_keyword_state, ALPHABET_SIZE);
				printf("\n");
				print_text(local_cycleword_state, cycleword_len);
				printf("\n");
#endif

				if (local_score > current_score) {
					// printf("improvement\n");
					current_score = local_score;
					vec_copy(local_keyword_state, current_keyword_state, ALPHABET_SIZE);
					vec_copy(local_cycleword_state, current_cycleword_state, cycleword_len);
					break ;
				} else if (frand() < slip_probability) {
					// printf("exploring\n");
					n_explore += 1;
					current_score = local_score;
					vec_copy(local_keyword_state, current_keyword_state, ALPHABET_SIZE);
					vec_copy(local_cycleword_state, current_cycleword_state, cycleword_len);
					break ;
				}
			}

			if (current_score > best_score) {
				best_score = current_score;
				vec_copy(current_keyword_state, best_keyword_state, ALPHABET_SIZE);
				vec_copy(current_cycleword_state, best_cycleword_state, cycleword_len);
				if (verbose) {

					elapsed = ((double) clock() - start_time)/CLOCKS_PER_SEC;
					n_iter_per_sec = ((double) n_iterations)/elapsed;

					printf("\n%.2f\t[sec]\n", elapsed);
					printf("%.0fK\t[it/sec]\n", 1.e-3*n_iter_per_sec);
					printf("%d\t[backtracks]\n", n_backtracks);
					printf("%d\t[restarts]\n", n);
					printf("%d\t[iterations]\n", i);
					printf("%d\t[slips]\n", n_explore);
					printf("%.2f\t[score]\n", best_score);
					print_text(best_keyword_state, ALPHABET_SIZE);
					printf("\n");
					print_text(best_cycleword_state, cycleword_len);
					printf("\n");

					quagmire3_decrypt(decrypted, cipher_indices, cipher_len, 
						best_keyword_state, best_cycleword_state, cycleword_len);
					print_text(decrypted, cipher_len);
					printf("\n");
					fflush(stdout);
				}
			}

		}

	}

	vec_copy(best_keyword_state, keyword, ALPHABET_SIZE);
	vec_copy(best_cycleword_state, cycleword, cycleword_len);

	quagmire3_decrypt(decrypted, cipher_indices, cipher_len, 
						best_keyword_state, best_cycleword_state, cycleword_len);

	return best_score;
}



// Score candidate cipher solution. 

double state_score(int cipher_indices[], int cipher_len, 
			int crib_indices[], int crib_positions[], int n_cribs, 
			int keyword_state[], int cycleword_state[], int cycleword_len,
			int decrypted[], 
			float *ngram_data, int ngram_size) {

	double score = 0., decrypted_ngram_score, decrypted_crib_score, 
	weight_ngram, weight_crib; 

	// TODO: these should be command line args. 
	weight_ngram = 1.;
	weight_crib  = 3.;

	// Decrypt cipher using the candidate keyword and cycleword. 
	quagmire3_decrypt(decrypted, cipher_indices, cipher_len, 
		keyword_state, cycleword_state, cycleword_len);

	// n-gram score. 

	decrypted_ngram_score = ngram_score(decrypted, cipher_len, ngram_data, ngram_size);

	// crib score. 

	decrypted_crib_score = crib_score(decrypted, cipher_len, crib_indices, crib_positions, n_cribs);

	score = weight_ngram*decrypted_ngram_score + weight_crib*decrypted_crib_score;
	score /= weight_ngram + weight_crib;

	return score;
}



// Entropy. 

double entropy(int text[], int len) {

	int frequencies[ALPHABET_SIZE];
	double entropy = 0.;

	// Count frequencies of each plaintext letter. 
	tally(text, len, frequencies, ALPHABET_SIZE);

	return entropy; 
}


// Score for known plaintext. (Naive - not using symmetry of the vigenere encryption.)

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



// Score a plaintext based on ngram frequencies. 

double ngram_score(int decrypted[], int cipher_len, float *ngram_data, int ngram_size) {

	int indx, ngram[MAX_NGRAM_SIZE];
	double score = 0.;

	for (int i = 0; i < cipher_len - ngram_size; i++) {

		// Extract slice decrypted[i : i + ngram_size].
		for (int j = 0; j < ngram_size; j++) {
			ngram[j] = decrypted[i + j];
		}

		indx = ngram_index_int(ngram, ngram_size);
		score += ngram_data[indx];
	}

	return int_pow(ALPHABET_SIZE,ngram_size)*score/(cipher_len - ngram_size);
}


// Given a ciphertext, keyword and cycleword (all in index form), compute the 
// Quagmire 3 decryption.  

void quagmire3_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
	int keyword_indices[], int cycleword_indices[], int cycleword_len) {
	
	int i, j, posn_keyword, posn_cycleword, indx;

	for (i = 0; i < cipher_len; i++) {

		// Find position of ciphertext char in keyword. 
		for (j = 0; j < ALPHABET_SIZE; j++) {
			if (cipher_indices[i] == keyword_indices[j]) {
				posn_keyword = j;
				break ;
			}
		}

		// Find the position of cycleword char in keyword. 
		for (j = 0; j < ALPHABET_SIZE; j++) {
			if (cycleword_indices[i%cycleword_len] == keyword_indices[j]) {
				posn_cycleword = j; 
				break ;
			}
		}

		indx = (posn_keyword - posn_cycleword)%ALPHABET_SIZE;
		if (indx < 0) indx += ALPHABET_SIZE;
		decrypted[i] = keyword_indices[indx];
	}

	return ;
}



// Pertubate a cycleword. 

void pertubate_cycleword(int state[], int max, int len) {

	int i; 
	i = rand_int(0, len);
	state[i] = rand_int(0, max);
}



// Pertubate a key - Ref: http://www.mountainvistasoft.com/cryptoden/articles/Q3%20Keyspace.pdf

void pertubate_keyword(int state[], int len, int keyword_len) {

	int i, j, k, l, temp;

	if (frand() < 0.2) {
		// Once in 5, swap two letters within the keyspace.  
		i = rand_int(0, keyword_len);
		j = rand_int(0, keyword_len);
		temp = state[i];
		state[i] = state[j];
		state[j] = temp;
	} else {
		// Four times in 5, swap a letter in the keyspace with 
		// a letter outside and remake the letters following the 
		// keyspace in normal order.

		i = rand_int(0, keyword_len);
		j = rand_int(keyword_len, len);

		// printf("\ni,j = %d,%d\n", i, j);

		temp = state[i];
		state[i] = state[j];

		// Re-order - delete state[j]. 

		for (k = j + 1; k < len; k++) {
			state[k - 1] = state[k];
		}
		
		// Re-order - insert state[i]. 
		for (k = keyword_len; k < len; k++) {
			// Find insertion point. 
			if (state[k] > temp || k == len - 1) {
				// Shunt along. 
				for (l = len - 1; l > k; l--) {
					state[l] = state[l - 1];
				}
				// Insert. 
				state[k] = temp;
				break ;
			}
		}

	}

	return ;
}



// Random keyword initialisation routine. 

void random_keyword(int keyword[], int len, int keyword_len) {

	int i, j, candidate, indx, n_chars;
	bool distinct, present;

	// Get keyword_len distinct letters in [0 - ALPHABET_SIZE). 

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

		if (distinct) {
			keyword[n_chars++] = candidate;
		}
	}

	// Pad out the rest of the chars. Eg. if we have "KRYPTOS", then here we 
	// generate "ABCDEFGHIJLMNQUVWXZ" (in index form). 

	indx = keyword_len;
	for (i = 0; i < ALPHABET_SIZE; i++) {

		present = false;
		for (j = 0; j < keyword_len; j++) {
			if (keyword[j] == i) {
				present = true; 
				break ;
			}
		}

		if (! present) {
			keyword[indx++] = i;
		}
	}

	return ;
}



void random_cycleword(int cycleword[], int max, int keyword_len) {

	for (int i = 0; i < keyword_len; i++) {
		cycleword[i] = rand_int(0, max);
	}

	return ;
}


// Load n-gram data from file. 

float* load_ngrams(char *ngram_file, int ngram_size, bool verbose) {

	FILE *fp;
	int i, n_ngrams, freq, indx;
	char ngram[MAX_NGRAM_SIZE];
	float *ngram_data, total;

	if (verbose) {
		printf("\nLoading ngrams...");
	}

	// Allocate memory for the ngram data.

	n_ngrams = int_pow(ALPHABET_SIZE, ngram_size);
	ngram_data = malloc(n_ngrams*sizeof(float));

	// Initialise. 

	for (i = 0; i < n_ngrams; i++) {
		ngram_data[i] = 0.;
	}

	// Read raw data from file. 

	fp = fopen(ngram_file, "r");

	while(!feof (fp)) {
		fscanf(fp, "%s\t%d", ngram, &freq);
		indx = ngram_index_str(ngram, ngram_size);
		ngram_data[indx] = freq;
	}

	fclose(fp);

	// Log-scale.

	total = 0.;
	for (i = 0; i < n_ngrams; i++) {
		ngram_data[i] = log(1. + ngram_data[i]);
		total += ngram_data[i];
	}

	// Normalise.

	for (i = 0; i < n_ngrams; i++) {
		ngram_data[i] /= total;
	}	

	if (verbose) {
		printf("...finished.\n\n");
	}

	return ngram_data;
}



// Returns the index of an n-gram. For example, the index of 'TH' would be 
// 19 + 7*26 = 201, as 'T' and 'H' and the 19th and 7th letters of the alphabet 
// respectively. 
 
int ngram_index_str(char *ngram, int ngram_size) {

	int c, index = 0;

	for (int i = 0; i < ngram_size; i++) {
		c = toupper(ngram[i]) - 'A';
		index += c*int_pow(ALPHABET_SIZE, i);
	}

	return index;
}

int ngram_index_int(int *ngram, int ngram_size) {

	int index = 0;

	for (int i = 0; i < ngram_size; i++) {
		index += ngram[i]*int_pow(ALPHABET_SIZE, i);
	}

	return index;
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

	// TODO: the sorting by max IOC makes this code fucking ugly - rewrite! 

	*n_cycleword_lengths = 0;
	current_ioc = 1.e6;
	for (i = 0; i < max_cycleword_len; i++) {
		threshold = false;
		max_ioc = 0.;
		for (j = 0; j < max_cycleword_len; j++) {
			if (mu_ioc_normalised[j] > n_sigma_threshold && mu_ioc_normalised[j] > max_ioc && mu_ioc_normalised[j] < current_ioc) {
				threshold = true;
				max_ioc = mu_ioc_normalised[j];
				cycleword_lengths[i] = j + 1;
			}
		}
		current_ioc = max_ioc;
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

		weighted_ioc += 26.*index_of_coincidence(caesar_column, i);
	}

	return weighted_ioc/len_cycleword;
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

	int i;
	double mu, sumdev = 0.;

	mu = vec_mean(vec, len);

	for (i = 0; i < len; i++) {
		sumdev += pow(vec[i] - mu, 2); 
	}

    return sqrt(sumdev/len);
}


void vec_print(int vec[], int len) {
	for (int i = 0; i < len; i++) {
		printf("%d, ", vec[i]);
	}
	printf("\n");
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



// Shuffle array -- ref: https://stackoverflow.com/questions/6127503/shuffle-array-in-c

void shuffle(int *array, size_t n) 
{
    if (n > 1) 
    {
        size_t i;
        for (i = 0; i < n - 1; i++) 
        {
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



int int_pow(int base, int exp)
{
    int result = 1;
    while (exp)
    {
        if (exp % 2)
           result *= base;
        exp /= 2;
        base *= base;
    }
    return result;
}



// Returns a random int in [min, max). 

int rand_int(int min, int max) {
   return min + rand() % (max - min); // result in [min, max)
}


double frand() {
  return ((double) rand())/((double) RAND_MAX); // result in [0, 1]
}


