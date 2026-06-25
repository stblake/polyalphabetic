#ifndef ADFGVX_SOLVER_H
#define ADFGVX_SOLVER_H

#include "colossus.h"

// ADFGX / ADFGVX solver (adfgvx_solver.c). Plugs ADFGVX_MODEL into the shared
// run_solver() engine: a coupled simulated-annealing search over a keyed Polybius
// square AND a keyed columnar column order, swept over the column count K, with a
// structural IoC reward that decouples the column-order search from the square. The
// ciphertext is mapped from label characters to coordinates up front. cipher_len is
// the ciphertext (coordinate) length 2N; the recovered plaintext has length N.
void solve_adfgvx(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
