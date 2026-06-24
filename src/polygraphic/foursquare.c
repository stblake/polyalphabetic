//
//  Four-Square cipher primitives (digraphic substitution over four 5x5 squares).
//
//  The four squares are arranged in a 2x2 layout:
//
//        UL  UR
//        LL  LR
//
//  UL (upper-left) and LR (lower-right) are the FIXED standard square -- cell p simply
//  holds letter p (a straight A..Z over the active 25-letter, J->I alphabet). UR (upper-
//  right) and LL (lower-left) are the two KEYED squares, each a permutation of the active
//  n = side*side letter alphabet in 0..n-1 indices (sq[p] = letter at cell p, row p/side
//  col p%side). These two keyed squares are the only unknowns the solver recovers.
//
//  Encryption splits the plaintext into digraphs. For (p1, p2): p1 is located in the
//  standard UL at (r1,c1) -- because UL is the identity square, that cell IS p1, so
//  (r1,c1) = (p1/side, p1%side) -- and p2 in the standard LR at (r2,c2) = (p2/side,
//  p2%side). The cipher pair is the other two corners of the rectangle:
//        cipher = (ur[r1][c2], ll[r2][c1]).
//  Decryption is the inverse: locate c1 in UR at (r1,c2) and c2 in LL at (r2,c1), then
//  read the standard corners UL[r1][c1] = r1*side+c1 and LR[r2][c2] = r2*side+c2.
//
//  Every square is a bijection, so the digraph map is a bijection -- decryption is exact
//  and needs no padding (an odd trailing letter passes through, mirroring playfair_decrypt).
//  Verified against the Wikipedia worked example (keywords EXAMPLE / KEYWORD, HE -> FY).
//  The solver needs only foursquare_decrypt(); encrypt + standard_square serve the test-
//  data generator and the unit tests.
//

#include "colossus.h"

// The fixed plaintext square: the identity permutation (cell p holds letter p).
void foursquare_standard_square(int sq[], int n) {
    for (int p = 0; p < n; p++) sq[p] = p;
}

// Encipher plaintext (any length) into out[] under the two keyed squares ur (upper-right)
// and ll (lower-left). The plaintext squares are the identity, so a plaintext letter's
// row/col is read straight from its value. An odd trailing letter passes through.
void foursquare_encrypt(const int plain[], int len, const int ur[], const int ll[],
                        int side, int out[]) {
    int i = 0;
    for (; i + 1 < len; i += 2) {
        int p1 = plain[i], p2 = plain[i + 1];    // UL, LR identity: cell == letter
        int r1 = p1 / side, c1 = p1 % side;
        int r2 = p2 / side, c2 = p2 % side;
        out[i]     = ur[r1 * side + c2];
        out[i + 1] = ll[r2 * side + c1];
    }
    if (i < len) out[i] = plain[i];
}

// Decipher ciphertext (any length) into out[]. Inverse of foursquare_encrypt.
void foursquare_decrypt(const int cipher[], int len, const int ur[], const int ll[],
                        int side, int out[]) {
    int n = side * side;
    int pos_ur[SQUARE_MAX_GRID], pos_ll[SQUARE_MAX_GRID];
    for (int p = 0; p < n; p++) { pos_ur[ur[p]] = p; pos_ll[ll[p]] = p; }
    int i = 0;
    for (; i + 1 < len; i += 2) {
        int c1 = cipher[i], c2 = cipher[i + 1];
        int u = pos_ur[c1], r1 = u / side, cc2 = u % side;   // c1 in UR -> (r1, c2)
        int l = pos_ll[c2], r2 = l / side, cc1 = l % side;   // c2 in LL -> (r2, c1)
        out[i]     = r1 * side + cc1;            // UL standard corner
        out[i + 1] = r2 * side + cc2;            // LR standard corner
    }
    if (i < len) out[i] = cipher[i];
}
