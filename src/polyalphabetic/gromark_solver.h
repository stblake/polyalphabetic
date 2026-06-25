#ifndef GROMARK_SOLVER_H
#define GROMARK_SOLVER_H
#include "colossus.h"

// Gromark / Periodic Gromark solver. See gromark_solver.c for the attack (a primer
// pre-pass that ranks the finite primer space by a fast assignment-based frequency
// attack, then anneals the keyed alphabet for the top-K primers).

// Basic-Gromark primer pre-pass. Sweeps the full 10^P primer space (P == fixed_period, default
// GROMARK_PRIMER_LEN), ranks each by an assignment-based frequency fit (a 26x26 Hungarian that
// recovers a provisional keyed alphabet given the running key, scored by n-grams), and returns
// the best K. Fills out_periods[k], out_primers[k*GROMARK_MAX_PRIMER..] and the provisional
// alphabet (+zero offsets) out_warm[k*(ALPHABET_SIZE+GROMARK_MAX_PRIMER)..]; returns the count.
// (variant/minP/maxP are accepted for symmetry but ignored: Periodic Gromark is NOT solved by a
// primer pre-pass -- its whole key is one keyword, which solve_gromark anneals directly.)
int gromark_rank_primers(const int cipher[], int n, int variant,
                         int fixed_period, int minP, int maxP,
                         const float *ngram, int ngram_size, int K,
                         int out_periods[], int out_primers[], int out_warm[],
                         bool verbose);

void solve_gromark(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
