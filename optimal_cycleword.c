//
// Optimal cycleword derivation
//

#include "polyalphabetic.h"

/*
   derive_optimal_cycleword
   ========================

   Determines the statistically most likely cycleword (key) for a given set of
   plaintext and ciphertext alphabets. Instead of perturbing the cycleword
   stochastically, this routine deterministically solves for the optimal key
   character for each column of the period.

   ## Mathematical Model

   Let L be the period (cycleword length) and C the ciphertext of length N.
   Partition C into L columns, the k-th column being all C_i with i = k (mod L).
   For each column we pick the key character that maximizes the correlation
   between the decrypted column's letter frequencies and English monograms E.

   For a candidate shift s, the column score is the dot product of the decrypted
   frequencies with E:

       S_s = sum_i f^(s)_i * E_i

   ## Implementation (column histogram * shift-weight correlation)

   The decryption D(c, s) of a ciphertext char c under shift s does not depend on
   which column c sits in, so the per-shift, per-char monogram weight

       weight[s][c] = E[ D(c, s) ]

   is built ONCE per call (a 26x26 table). Each column is then scored by
   histogramming its raw ciphertext characters once and forming

       S_s = sum_c hist[c] * weight[s][c].

   This replaces the previous "re-decrypt the whole column for each of the 26
   shifts" inner loop: per-column work drops from O(26 * column_length) to
   O(column_length + 26*26). derive_optimal_cycleword is the dominant cost of the
   default -optimalcycle hill climb, so this is the hot path.

   ## Decryption functions D(c, s)

   * Vigenere : D = (c - s) mod 26          (variant: (s - c) mod 26)
   * Beaufort : D = (s - c) mod 26
   * Porta    : S = floor(s/2); c in [0,12] -> (c + S) mod 13 + 13,
                                 c in [13,25] -> (c - 13 - S) mod 13
   * Quagmire : p = position of c in the CT keyed alphabet;
                D = A_pt[(p - s) mod 26]     (variant: A_pt[(p + s) mod 26])
*/

void derive_optimal_cycleword(
    PolyalphabeticConfig *cfg,
    int cipher_indices[], int cipher_len,
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[],
    int cycleword_state[], int cycleword_len, int *hist_by_col) {

    int i, c, s, col, row;

    // Position of each ciphertext character within the CT keyed alphabet
    // (ciphertext_keyword_indices is always a permutation of 0..25).
    int ct_key_lookup[ALPHABET_SIZE];
    for (i = 0; i < ALPHABET_SIZE; i++) ct_key_lookup[ciphertext_keyword_indices[i]] = i;

    // The 26x26 monogram-weight table depends only on (cipher_type, variant, and
    // the two keyed alphabets). For fixed-keyword ciphers (Vigenere/Beaufort/
    // Porta) the keywords never change, so it is built once for the whole run;
    // for Quagmire it is rebuilt only on calls where a keyword actually changed.
    // We detect change by comparing the inputs against the cached ones (52 int
    // compares + a couple of scalars -- far cheaper than recomputing 676 entries
    // with per-cell branches and mods). The rebuilt values are identical to the
    // old code's, so derived cyclewords are bit-for-bit unchanged.
    static double weight[ALPHABET_SIZE][ALPHABET_SIZE];
    static int w_valid = 0, w_type = -1, w_variant = -1;
    static int w_pt[ALPHABET_SIZE], w_ct[ALPHABET_SIZE];

    int rebuild = !w_valid || w_type != cfg->cipher_type || w_variant != (int)cfg->variant;
    if (!rebuild) {
        for (i = 0; i < ALPHABET_SIZE; i++) {
            if (w_pt[i] != plaintext_keyword_indices[i] ||
                w_ct[i] != ciphertext_keyword_indices[i]) { rebuild = 1; break; }
        }
    }
    if (rebuild) {
        for (s = 0; s < ALPHABET_SIZE; s++) {
            for (c = 0; c < ALPHABET_SIZE; c++) {
                int pt_char;
                if (cfg->cipher_type == PORTA) {
                    int porta_shift = s / 2;
                    if (c < 13) pt_char = (c + porta_shift) % 13 + 13;
                    else        pt_char = (c - 13 - porta_shift + ALPHABET_SIZE) % 13;
                } else if (cfg->cipher_type == BEAUFORT) {
                    pt_char = (s - c + ALPHABET_SIZE) % ALPHABET_SIZE;
                } else if (cfg->cipher_type == VIGENERE) {
                    // Must match vigenere_decrypt: standard P = (C - K), variant
                    // P = (C + K) mod 26.
                    if (cfg->variant) pt_char = (c + s) % ALPHABET_SIZE;
                    else              pt_char = (c - s + ALPHABET_SIZE) % ALPHABET_SIZE;
                } else {
                    // Quagmire I-IV.
                    int posn_keyword = ct_key_lookup[c];
                    int pt_idx;
                    if (cfg->variant) pt_idx = (posn_keyword + s) % ALPHABET_SIZE;
                    else              pt_idx = (posn_keyword - s) % ALPHABET_SIZE;
                    if (pt_idx < 0) pt_idx += ALPHABET_SIZE;
                    pt_char = plaintext_keyword_indices[pt_idx];
                }
                weight[s][c] = english_monograms[pt_char];
            }
        }
        w_valid = 1; w_type = cfg->cipher_type; w_variant = (int)cfg->variant;
        for (i = 0; i < ALPHABET_SIZE; i++) {
            w_pt[i] = plaintext_keyword_indices[i];
            w_ct[i] = ciphertext_keyword_indices[i];
        }
    }

    // Solve each column independently for the shift best matching English. The
    // dropped per-column normalization (1/column_length) is constant across
    // shifts, so it does not affect the argmax; ties go to the lowest shift, as
    // before.
    int local_hist[ALPHABET_SIZE];
    for (col = 0; col < cycleword_len; col++) {
        int *hist;
        if (hist_by_col) {
            hist = hist_by_col + col * ALPHABET_SIZE;
        } else {
            // Standalone path: histogram this column's ciphertext chars locally.
            for (c = 0; c < ALPHABET_SIZE; c++) local_hist[c] = 0;
            for (row = 0; row * cycleword_len + col < cipher_len; row++)
                local_hist[cipher_indices[row * cycleword_len + col]]++;
            hist = local_hist;
        }

        // Compact the column's nonzero histogram entries once (in increasing c
        // order). Columns hold only ~cipher_len/cycleword_len characters, so most
        // of the 26 counts are zero. Skipping the zero terms is exact -- adding
        // hist[c]*weight == 0.0 is a no-op in IEEE arithmetic -- so the per-shift
        // scores, and hence the argmax, are bit-for-bit unchanged. This turns the
        // inner dot product from 26 multiply-adds into (#distinct chars) of them,
        // and derive_optimal_cycleword is the dominant cost of the optimal climb.
        int nz_c[ALPHABET_SIZE], nz_n[ALPHABET_SIZE], n_nz = 0;
        for (c = 0; c < ALPHABET_SIZE; c++) {
            if (hist[c]) { nz_c[n_nz] = c; nz_n[n_nz] = hist[c]; n_nz++; }
        }

        double best_score = -1.0;
        int best_shift = 0;
        for (s = 0; s < ALPHABET_SIZE; s++) {
            double score = 0.0;
            const double *ws = weight[s];
            for (int k = 0; k < n_nz; k++) score += nz_n[k] * ws[nz_c[k]];
            if (score > best_score) { best_score = score; best_shift = s; }
        }

        // State stores the cycleword CHARACTER (from the CT keyed alphabet).
        cycleword_state[col] = ciphertext_keyword_indices[best_shift];
    }
}
