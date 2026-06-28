#ifndef SERIATED_PLAYFAIR_SOLVER_H
#define SERIATED_PLAYFAIR_SOLVER_H

#include "colossus.h"

// Seriated Playfair solver (TYPE seriated-playfair). Digraphic Playfair over the vertical
// pairs of a two-row seriated layout; one global 5x5 keyed square, with the seriation
// period swept (one engine config per period, the n-gram score picks the true one).
void solve_seriated_playfair(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
