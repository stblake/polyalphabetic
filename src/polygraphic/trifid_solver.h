#ifndef TRIFID_SOLVER_H
#define TRIFID_SOLVER_H
#include "colossus.h"

void solve_trifid(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

// Rank trial periods in [min_p .. max_p] by columnar IoC and return the top n_want
// (descending) in out[]; returns the count written. Exposed for the solver tests.
int trifid_estimate_periods(int cipher[], int len, int min_p, int max_p,
                            int n_want, int out[], bool verbose);
#endif
