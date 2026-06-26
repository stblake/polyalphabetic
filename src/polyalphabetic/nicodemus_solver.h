#ifndef NICODEMUS_SOLVER_H
#define NICODEMUS_SOLVER_H
#include "colossus.h"

// Nicodemus solver. The attack anneals only the per-block COLUMN ORDER (a permutation
// of length P) and derives the P per-column substitution shifts deterministically for
// each candidate order by a monogram frequency fit -- the decoupling that makes the
// substitution+transposition composite tractable (the analog of the default
// -optimalcycle path). One engine config per (period P, block height H) pair.

void solve_nicodemus(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
