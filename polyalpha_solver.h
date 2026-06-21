#ifndef POLYALPHA_SOLVER_H
#define POLYALPHA_SOLVER_H
#include "colossus.h"

// Polyalphabetic solver (Vigenere / Quagmire I-IV / Beaufort / Porta / Autokey*).
// POLYALPHA_MODEL and the per-type seed/perturb ladders are private to the .c.
void solve_polyalpha(char *ciphertext_str, char *cribtext_str, ColossusConfig *cfg,
    SharedData *shared, int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs, SolveResult *result);

// Prints the human-readable block and the ">>> ..." CSV summary for a polyalphabetic
// solve, from the populated result.
void report_solution(ColossusConfig *cfg, char *cribtext_str,
    int cipher_indices[], SolveResult *res);

// Crib / cycleword helpers used by the polyalphabetic model hooks.
int map_crib_to_cipher_pos(ColossusConfig *cfg, int crib_pos, int cipher_len);
int get_matrix_rotate_old_idx(int target_idx, int len, int width, int clockwise);
bool cribs_satisfied_p(ColossusConfig *cfg, int cipher_indices[], int cipher_len, int crib_indices[],
    int crib_positions[], int n_cribs, int cycleword_len, bool verbose);
bool constrain_cycleword(ColossusConfig *cfg, int cipher_indices[], int cipher_len,
    int crib_indices[], int crib_positions[], int n_cribs,
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[],
    int cycleword_indices[], int cycleword_len,
    bool variant, bool verbose);
void decrypt_state(ColossusConfig *cfg, int cipher_indices[], int cipher_len,
                   int plaintext_keyword_state[], int ciphertext_keyword_state[],
                   int cycleword_state[], int cycleword_len,
                   int decrypted[]);
#endif
