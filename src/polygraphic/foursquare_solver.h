#ifndef FOURSQUARE_SOLVER_H
#define FOURSQUARE_SOLVER_H
#include "colossus.h"

void solve_foursquare(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);
#endif
