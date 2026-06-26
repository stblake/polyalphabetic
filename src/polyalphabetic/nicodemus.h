#ifndef NICODEMUS_H
#define NICODEMUS_H
#include "colossus.h"

// Nicodemus cipher primitives (substitution + transposition composite).
//
// A single keyword of length P drives two stages over blocks of `block_h` rows x P
// columns (the final block may be ragged):
//   1. Substitution: each grid column c is enciphered by the keyword letter at that
//      column -- shift[c]. Three ACA-recognised conventions (selected by `variant`):
//        NICO_VIG     : C = (P + k) mod 26   /  P = (C - k) mod 26   (standard Vigenere)
//        NICO_VARIANT : C = (P - k) mod 26   /  P = (C + k) mod 26   (Variant)
//        NICO_BEAU    : C = (k - P) mod 26   /  P = (k - C) mod 26   (Beaufort, reciprocal)
//   2. Transposition: within each block the columns are read off top-to-bottom in the
//      column read order `order` (for the ACA cipher, the alphabetical rank order of the
//      keyword letters), and the blocks are concatenated.
//
// The primitives are general in (order, shifts) so the generator and the solver share one
// code path; nicodemus_key_from_keyword() derives the ACA-consistent (order, shifts) pair
// from a keyword. Full 26-letter alphabet (no J-merge). out[] must not alias the input.

#define NICO_VIG      0
#define NICO_VARIANT  1
#define NICO_BEAU     2

// One plaintext->cipher letter under column shift k (and its inverse). Shared by the
// primitive and the solver's per-column monogram shift derivation. Mod ALPHABET_SIZE (26).
static inline int nicodemus_sub(int p, int k, int variant) {
    switch (variant) {
        case NICO_VARIANT: return ((p - k) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE;
        case NICO_BEAU:    return ((k - p) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE;
        default:           return (p + k) % ALPHABET_SIZE;            // NICO_VIG
    }
}
static inline int nicodemus_inv_sub(int c, int k, int variant) {
    switch (variant) {
        case NICO_VARIANT: return (c + k) % ALPHABET_SIZE;
        case NICO_BEAU:    return ((k - c) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE;
        default:           return ((c - k) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE;  // NICO_VIG
    }
}

// ACA key derivation: shifts[c] = kw[c]; order = stable argsort of the keyword letters
// (ascending, ties broken by column index). kw[], order[], shifts[] are length P.
void nicodemus_key_from_keyword(const int kw[], int P, int order[], int shifts[]);

// Encrypt / decrypt under an explicit column order and per-column shifts.
void nicodemus_encrypt(const int plain[], int len, int P, int block_h,
                       const int order[], const int shifts[], int variant, int out[]);
void nicodemus_decrypt(const int cipher[], int len, int P, int block_h,
                       const int order[], const int shifts[], int variant, int out[]);

// Stage-1 inverse only: undo the per-block columnar transposition (incomplete-grid rule per
// H*P block), leaving the still-enciphered text in grid row-major order (grid column of out[i]
// is i % P). The solver uses this to derive the per-column shifts before inverse-substituting.
void nicodemus_detranspose(const int cipher[], int len, int P, int block_h,
                           const int order[], int out[]);

// Apply the per-column inverse substitution to detransposed text desub[] (column = i % P).
void nicodemus_inv_substitute(const int desub[], int len, int P,
                              const int shifts[], int variant, int out[]);

#endif
