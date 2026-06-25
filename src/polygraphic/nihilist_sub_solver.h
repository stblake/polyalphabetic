#ifndef NIHILIST_SUB_SOLVER_H
#define NIHILIST_SUB_SOLVER_H

#include "colossus.h"

// Nihilist Substitution solver (nihilist_sub_solver.c). Plugs NIHILIST_SUB_MODEL into the
// shared run_solver() engine: a coupled simulated-annealing search over a keyed Polybius
// square AND a periodic additive key, swept over the key period, with a square-independent
// "validity" reward (folded into score_adjust) that decouples the additive-key search from
// the square -- the climb locks the additive by validity, then the n-gram score recovers the
// square. The ciphertext is a stream of decimal NUMBERS parsed from ciphertext_str; cipher_len
// passed in is the (per-character) decode length and is IGNORED. cfg->cipher_type selects the
// addition convention (NIHILIST_SUB / _NC / _M100). One engine config per candidate period.
void solve_nihilist_sub(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

// Rank trial periods in [min_p .. max_p] by columnar IoC over the ciphertext NUMBERS and
// return the top n_want (descending) in out[]; returns the count. Exposed for the tests.
int nihilist_sub_estimate_periods(const int values[], int n, int min_p, int max_p,
                                  int n_want, int out[], bool verbose);

#endif
