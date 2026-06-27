#ifndef SLIDEFAIR_SOLVER_H
#define SLIDEFAIR_SOLVER_H
#include "colossus.h"

// Slidefair solver (TYPES slidefair / slidefair-var / slidefair-beau). Rides the cipher-agnostic
// engine: the climbed state is the periodic key -- P key letters (0..25), one per column, carried
// in the cycleword lane -- with one engine config per period P in the sweep (IoC estimation is
// useless through the digraphic pairing). Each digraph is enciphered entirely by its column key,
// so a column's digraphs decrypt from that column's key ALONE: the per-column monogram-fit key
// (the analog of derive_optimal_cycleword) warm-starts the seed, and the n-gram score -- cross-
// column digraphs only form at the true keys -- corrects any column the monogram fit got wrong.
// One primitive + one solver serve all three variants (branched on cfg->cipher_type); Vigenere and
// Variant are not separately identifiable (a free per-column key absorbs the sign), so either cracks
// a shift-Slidefair, only Beaufort is distinct. Cribs are supported (the cipher is positional:
// decrypted[i] is plaintext[i]). See slidefair_solver.c.
void solve_slidefair(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
