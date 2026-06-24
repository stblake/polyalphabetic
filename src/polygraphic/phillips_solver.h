#ifndef PHILLIPS_SOLVER_H
#define PHILLIPS_SOLVER_H
#include "colossus.h"

// Solve a Phillips cipher (cfg->cipher_type one of PHILLIPS / PHILLIPS_C / PHILLIPS_RC,
// selecting the square-generation variant). Hill-climbs / anneals the base 5x5 keyed
// square with n-gram scoring through the shared run_solver() engine.
void solve_phillips(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
