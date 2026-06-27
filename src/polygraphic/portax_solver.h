#ifndef PORTAX_SOLVER_H
#define PORTAX_SOLVER_H
#include "colossus.h"

// Portax solver (TYPE portax). Rides the cipher-agnostic engine: the climbed state is the
// periodic key -- P Porta SHIFTS (0..12), one per column, carried in the cycleword lane -- with
// one engine config per period P in the sweep (IoC estimation is useless through the digraphic
// vertical pairing). Each vertical pair is enciphered entirely by its column key, so a column's
// pairs decrypt from that column's shift ALONE: the per-column monogram-fit shift (the analog of
// derive_optimal_cycleword) warm-starts the seed, and the n-gram score -- cross-column digraphs
// only form at the true shifts -- corrects any column the monogram fit got wrong. Cribs are
// supported (the cipher is positional: decrypted[i] is plaintext[i]). See portax_solver.c.
void solve_portax(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
