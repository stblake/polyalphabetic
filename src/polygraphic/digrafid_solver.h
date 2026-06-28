#ifndef DIGRAFID_SOLVER_H
#define DIGRAFID_SOLVER_H
#include "colossus.h"

void solve_digrafid(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

// Rank trial periods in [min_p .. max_p] by the mean per-lane Index of Coincidence over
// the ciphertext digraphs (each (digraph-position mod P, first/second role) is one lane)
// and return the top n_want (descending) in out[]; returns the count written. Exposed for
// the solver tests.
int digrafid_estimate_periods(int cipher[], int len, int min_p, int max_p,
                              int n_want, int out[], bool verbose);
#endif
