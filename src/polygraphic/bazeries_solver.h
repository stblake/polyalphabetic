#ifndef BAZERIES_SOLVER_H
#define BAZERIES_SOLVER_H
#include "colossus.h"

// Bazeries solver (TYPE bazeries). Rides the cipher-agnostic engine: the climbed state is
// the key NUMBER's decimal digits (one engine config per digit count D in [1..6]); the
// spelled-out number derives the keyed ciphertext square and the digits drive the
// digit-grouped reversal transposition. A square-quality monogram reward folded into
// score_adjust gives the digit climb a gradient (the inverse-substitution's monogram fit is
// transposition-independent) so the rugged < 10^6 keyspace is navigable rather than a
// needle-in-a-haystack. See bazeries_solver.c.
void solve_bazeries(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
