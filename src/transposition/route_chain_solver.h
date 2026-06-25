#ifndef ROUTE_CHAIN_SOLVER_H
#define ROUTE_CHAIN_SOLVER_H
#include "colossus.h"

// TRANSROUTECOL: a two-stage transposition CHAIN. The cipher was produced by
// writing the plaintext into an R x C grid along a fixed geometric read-route
// (route_cells), permuting the C columns by a key, then reading rows. The solver
// sweeps the complete-grid shapes (R*C == len) and all routes, anneals the column
// key, and reads each candidate with the exact Held-Karp seam best row order. A
// generalization (off the 6x28/2x2-local model) of ciphers/W168/chains.py.
void solve_route_chain(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs);
#endif
