#ifndef PROGKEY_SOLVER_H
#define PROGKEY_SOLVER_H
#include "colossus.h"

// Progressive Key solver (TYPE progkey / progkey-var / progkey-beau). Rides the cipher-
// agnostic engine. The whole key is a P-letter keyword (per-column base shifts 0..25, in the
// cycleword lane) PLUS a per-group progression index (0..25). IoC period estimation is useless
// (each column spans multiple groups with different drifted shifts -> not monoalphabetic), so
// the PERIOD is brute-forced and the PROGRESSION enumerated 0..25: one engine config per
// (P, prog) pair (aux[0] = prog). For a fixed prog, DE-PROGRESSING the ciphertext (undoing only
// the drift pass) leaves a pure periodic base cipher whose columns are independent -- so the
// per-column monogram-fit shift (the analog of derive_optimal_cycleword) warm-starts the seed,
// and the n-gram score, across all (P, prog) configs, picks the true period, progression, and
// keyword (cross-column digraphs only form at the true shifts). Cribs are supported (positional:
// decrypted[i] is plaintext[i]). The three base types (Vigenere / Variant / Beaufort) share the
// solver, branched on cfg->cipher_type. See progkey_solver.c.
void solve_progkey(char *ciphertext_str, char *cribtext_str,
    ColossusConfig *cfg, SharedData *shared,
    int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

#endif
