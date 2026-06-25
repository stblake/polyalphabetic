#ifndef TILE_SOLVER_H
#define TILE_SOLVER_H
#include "colossus.h"

// TRANSTILE: sub-grid / tile transposition. The plaintext grid is partitioned into
// h x w tiles, every tile permuted by the SAME cell permutation, composed with a
// columnar column-order global. The solver JOINTLY anneals the column order and the
// tile cell permutation, sweeping the (complete-grid) column count. The tile shape
// is set with -tile h w (default 2 2). See ciphers/W168/tiles.py.
void solve_tile(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);
#endif
