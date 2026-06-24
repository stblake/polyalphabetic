//
//  Two-Square cipher primitives (digraphic substitution over two keyed 5x5 squares).
//
//  Each square is a permutation of the active n = side*side letter alphabet: the binary
//  forces g_alpha == 25 for -type twosquare (J merged into I, ACA convention), so a square
//  is a 5x5 grid of 0..24 indices. sq[p] is the letter at cell p (row p/side, col p%side)
//  and the inverse pos[l] is the cell of letter l. The two squares are independent.
//
//  Encryption splits the plaintext into digraphs; the first letter is located in square 1,
//  the second in square 2, and the cipher pair is the OTHER two corners of the rectangle
//  they span. The `variant` is the arrangement:
//
//    TWO_SQ_HORIZONTAL (the ACA standard, squares side by side -- verified cell-for-cell
//      against the ACA worked example): for a in sq1 at (r1,c1) and b in sq2 at (r2,c2),
//        cipher = (sq2[r1][c2], sq1[r2][c1]).
//      When r1 == r2 (same row) this collapses to the reversed pair (b, a) -- the "same-row
//      transparency" the ACA notes. Decryption is the mirror (the first cipher letter is
//      found in sq2, the second in sq1).
//
//    TWO_SQ_VERTICAL (the Wikipedia arrangement, squares stacked -- verified against the
//      Wikipedia worked example): for a in sq1 at (r1,c1) and b in sq2 at (r2,c2),
//        cipher = (sq1[r1][c2], sq2[r2][c1]).
//      This keeps each output letter in its own square, so the map is SELF-INVERSE
//      (decryption == encryption); a same-column digraph (c1 == c2) maps to itself.
//
//  Both squares are bijections, so the whole digraph map is a bijection -- decryption is
//  exact and needs no length padding (an odd trailing letter passes through, mirroring
//  playfair_decrypt). The solver needs only twosquare_decrypt(); encrypt + the shared
//  playfair_grid_from_keyword serve the test-data generator and the unit tests.
//

#include "colossus.h"

// Build pos[] (letter -> cell) from sq[] (cell -> letter) for one side x side square.
static void twosquare_build_inverse(const int sq[], int pos[], int n) {
    for (int p = 0; p < n; p++) pos[sq[p]] = p;
}

// Encipher one digraph (a in sq1, b in sq2) into (*oa, *ob) using the rectangle rule for
// the given arrangement. pos1/pos2 are the inverse maps of sq1/sq2.
static inline void twosquare_pair_enc(const int sq1[], const int pos1[],
                                      const int sq2[], const int pos2[],
                                      int side, int variant, int a, int b, int *oa, int *ob) {
    int p1 = pos1[a], p2 = pos2[b];
    int r1 = p1 / side, c1 = p1 % side;
    int r2 = p2 / side, c2 = p2 % side;
    if (variant == TWO_SQ_VERTICAL) {            // stacked: each output stays in its square
        *oa = sq1[r1 * side + c2];
        *ob = sq2[r2 * side + c1];
    } else {                                     // horizontal (ACA): outputs cross squares
        *oa = sq2[r1 * side + c2];
        *ob = sq1[r2 * side + c1];
    }
}

// Decipher one cipher digraph back to its plaintext (a, b). For the vertical arrangement
// the cipher is self-inverse, so this is exactly twosquare_pair_enc; for the horizontal
// arrangement the first cipher letter lives in sq2 and the second in sq1 (the mirror).
static inline void twosquare_pair_dec(const int sq1[], const int pos1[],
                                      const int sq2[], const int pos2[],
                                      int side, int variant, int a, int b, int *oa, int *ob) {
    if (variant == TWO_SQ_VERTICAL) {
        twosquare_pair_enc(sq1, pos1, sq2, pos2, side, variant, a, b, oa, ob);
        return;
    }
    int p1 = pos2[a], p2 = pos1[b];              // first cipher letter in sq2, second in sq1
    int r1 = p1 / side, c2 = p1 % side;
    int r2 = p2 / side, c1 = p2 % side;
    *oa = sq1[r1 * side + c1];
    *ob = sq2[r2 * side + c2];
}

// Encipher plaintext (any length) into out[] under the two squares. An odd trailing letter
// passes through unchanged.
void twosquare_encrypt(const int plain[], int len, const int sq1[], const int sq2[],
                       int side, int variant, int out[]) {
    int n = side * side;
    int pos1[SQUARE_MAX_GRID], pos2[SQUARE_MAX_GRID];
    twosquare_build_inverse(sq1, pos1, n);
    twosquare_build_inverse(sq2, pos2, n);
    int i = 0;
    for (; i + 1 < len; i += 2)
        twosquare_pair_enc(sq1, pos1, sq2, pos2, side, variant,
                           plain[i], plain[i + 1], &out[i], &out[i + 1]);
    if (i < len) out[i] = plain[i];
}

// Decipher ciphertext (any length) into out[]. Inverse of twosquare_encrypt.
void twosquare_decrypt(const int cipher[], int len, const int sq1[], const int sq2[],
                       int side, int variant, int out[]) {
    int n = side * side;
    int pos1[SQUARE_MAX_GRID], pos2[SQUARE_MAX_GRID];
    twosquare_build_inverse(sq1, pos1, n);
    twosquare_build_inverse(sq2, pos2, n);
    int i = 0;
    for (; i + 1 < len; i += 2)
        twosquare_pair_dec(sq1, pos1, sq2, pos2, side, variant,
                           cipher[i], cipher[i + 1], &out[i], &out[i + 1]);
    if (i < len) out[i] = cipher[i];
}
