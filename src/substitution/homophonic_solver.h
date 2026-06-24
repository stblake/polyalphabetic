#ifndef HOMOPHONIC_SOLVER_H
#define HOMOPHONIC_SOLVER_H
#include "colossus.h"

void solve_homophonic(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SymbolTable *tab);
#endif
