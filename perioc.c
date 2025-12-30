
// Periodic index of coincidence

#include "polyalphabetic.h"

/*
   estimate_cycleword_lengths

   Estimates the most probable cycleword lengths (periods) by analyzing the 
   Index of Coincidence (IoC) of the ciphertext columns for various trial lengths.

   ## Mathematical Model

   The routine tests trial periods $L$ from $1$ to $L_{max}$. For a given $L$, 
   the ciphertext $C$ is treated as $L$ interleaved Caesar ciphers (columns).

   ### Columnar Index of Coincidence
   
   For a specific trial period $L$, we calculate the average IoC across all 
   $L$ columns. Let $IC_k$ be the Index of Coincidence for the $k$-th column 
   ($0 \le k < L$). The metric for period $L$ is:

   $$ \overline{IC}_L = \frac{1}{L} \sum_{k=0}^{L-1} IC_k $$

   where the standard definition of IoC for a column of length $N$ with character 
   counts $f_i$ is:
   
   $$ IC = \frac{\sum_{i=A}^{Z} f_i (f_i - 1)}{N(N-1)} $$

   ### Statistical Normalization (Z-Score)
   
   To identify statistically significant periods, we normalize the $\overline{IC}_L$ 
   values against the population of all trial lengths.
   
   First, calculate the population mean ($\mu$) and standard deviation ($\sigma$) 
   of the calculated IoCs:
   
   $$ \mu = \frac{1}{L_{max}} \sum_{L=1}^{L_{max}} \overline{IC}_L $$
   $$ \sigma = \sqrt{ \frac{1}{L_{max}} \sum_{L=1}^{L_{max}} (\overline{IC}_L - \mu)^2 } $$

   Then, compute the Z-score (Standard Score) for each period $L$:
   
   $$ Z_L = \frac{\overline{IC}_L - \mu}{\sigma} $$

   ### Selection Criteria
   
   A candidate period $L$ is accepted if it satisfies two conditions:
   
   1.  **Significance**: The Z-score exceeds the user-defined sigma threshold ($\tau_\sigma$).
       $$ Z_L > \tau_\sigma $$
       
   2.  **Magnitude**: The raw IoC exceeds the minimum IoC threshold ($\tau_{ioc}$), typically 
       set near the random text threshold ($\approx 0.038$) or English threshold ($\approx 0.066$).
       $$ \overline{IC}_L > \tau_{ioc} $$
       
   The resulting list of valid lengths is sorted by score (or processed to find local maxima) 
   and returned to the solver.
*/

typedef struct {
    int len;
    double ioc;
    double z_score;
} PeriodCandidate;

int compare_candidates(const void *a, const void *b) {
    PeriodCandidate *cA = (PeriodCandidate *)a;
    PeriodCandidate *cB = (PeriodCandidate *)b;
    // Sort descending by IoC
    if (cA->ioc < cB->ioc) return 1;
    if (cA->ioc > cB->ioc) return -1;
    return 0;
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

    int i, length_candidate;
    int caesar_column[MAX_CIPHER_LENGTH]; 
    double raw_iocs[MAX_CYCLEWORD_LEN];
    double z_scores[MAX_CYCLEWORD_LEN];
    
    // Statistics variables.
    double sum = 0.0, sum_sq = 0.0;
    double mean, std_dev;

    // Calculate raw IoCs for all periods.
    for (length_candidate = 1; length_candidate <= max_cycleword_len; length_candidate++) {
        // Calculate IoC for this period length.
        raw_iocs[length_candidate - 1] = mean_ioc(text, len, length_candidate, caesar_column);
        
        sum += raw_iocs[length_candidate - 1];
        sum_sq += raw_iocs[length_candidate - 1] * raw_iocs[length_candidate - 1];
    }

    // Calculate statistics.
    mean = sum / max_cycleword_len;
    double variance = (sum_sq / max_cycleword_len) - (mean * mean);
    std_dev = sqrt(variance > 0 ? variance : 0);

    // Calculate Z-Scores for all periods. 
    for (i = 0; i < max_cycleword_len; i++) {
        z_scores[i] = (std_dev > 0) ? (raw_iocs[i] - mean) / std_dev : 0.0;
    }

    // Display all periods. 
    if (verbose) {
        printf("\nCycleword Stats: Mean IoC = %.4f, StdDev = %.6f\n", mean, std_dev);
        printf("len\tIOC\tZ-Score\n");
        for (i = 0; i < max_cycleword_len; i++) {
            printf("%d\t%.4f\t%.2f\n", i + 1, raw_iocs[i], z_scores[i]);
        }
    }

    if (verbose) {
        printf("\nCycleword Stats: Mean IoC = %.4f, StdDev = %.6f\n", mean, std_dev);
    }

    // Filter candidates.
    PeriodCandidate candidates[MAX_CYCLEWORD_LEN];
    int count = 0;

    for (i = 0; i < max_cycleword_len; i++) {
        length_candidate = i + 1;
        double current_ioc = raw_iocs[i];
        double z_score = (std_dev > 0) ? (current_ioc - mean) / std_dev : 0.0;

        // Condition: Must meet Sigma Threshold AND Absolute IoC Threshold
        if (z_score >= n_sigma_threshold && current_ioc >= ioc_threshold) {
            candidates[count].len = length_candidate;
            candidates[count].ioc = current_ioc;
            candidates[count].z_score = z_score;
            count++;
        }
    }

    // Sort candidates (Highest IoC first.)
    qsort(candidates, count, sizeof(PeriodCandidate), compare_candidates);

    // Output results.
    *n_cycleword_lengths = count;
    
    if (verbose) printf("\nlen\tIOC\tZ-Score\n");
    
    for (i = 0; i < count; i++) {
        cycleword_lengths[i] = candidates[i].len;
        if (verbose) {
            printf("%d\t%.4f\t%.2f\n", candidates[i].len, candidates[i].ioc, candidates[i].z_score);
        }
    }
    
    if (verbose) {
        printf("\nSelected %d candidate lengths.\n\n", count);
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
