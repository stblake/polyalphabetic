#ifndef COLUMNAR_TRACK_SOLVER_H
#define COLUMNAR_TRACK_SOLVER_H
#include "colossus.h"

// TRANSCOL_L: columnar transposition that additionally recovers a uniform
// within-column row permutation L (the "track order"). The engine anneals the
// column order; for every candidate column order the BEST L is recovered exactly
// by the Held-Karp seam decomposition (trans_common.c) and the candidate is scored
// at that best-L reading. Sweeps the column count K and (optionally) the column /
// row read directions. See ciphers/W168 (gridlib.py) for the validated model.
void solve_columnar_track(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);
#endif
