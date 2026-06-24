#ifndef CADENUS_SOLVER_H
#define CADENUS_SOLVER_H
#include "colossus.h"

void solve_cadenus(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);
#endif
