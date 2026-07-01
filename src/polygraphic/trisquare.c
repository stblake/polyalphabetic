//
//  Tri-Square cipher primitives (digraphic substitution over THREE keyed 5x5 squares).
//
//  Three independent keyed squares sq1, sq2, sq3 (each a permutation of the active
//  n = side*side letter alphabet; the binary forces g_alpha == 25 for -type trisquare, J
//  merged into I). Plaintext is taken in pairs. A plaintext digraph (p1, p2) -- p1 located
//  in sq1 at (r1,c1), p2 in sq2 at (r2,c2) -- enciphers to a ciphertext TRIGRAPH (a 3:2
//  length expansion):
//
//    c0 = any letter in the SAME COLUMN as p1 in sq1    (decodes to p1's column c1)
//    c1 = sq3[r1][c2]                                    (the deterministic middle letter)
//    c2 = any letter in the SAME ROW    as p2 in sq2    (decodes to p2's row r2)
//
//  The first and third letters are POLYPHONIC on encode (the ACA lets the clerk pick any of
//  the 5 column/row members); DECRYPTION is exact regardless of the choice, because a square
//  maps any column member back to its column (and any row member back to its row):
//
//    col1       = pos1[c0] % side          row1, col2 = pos3[c1] / side, % side
//    row2       = pos2[c2] / side
//    p1 = sq1[row1*side + col1]            p2 = sq2[row2*side + col2]
//
//  trisquare_encrypt picks a RANDOM representative for the two polyphonic letters (a real
//  Tri-Square is polyphonic -- the ACA example's cipher letters are varied, not a fixed
//  5-set), so it consumes the global RNG and is only reproducible under a fixed seed (the
//  generator seeds it; the solver never encrypts). A deterministic canonical choice would
//  concentrate c0/c2 into a size-5 subset -- unfaithful, and it starves the solver's gradient.
//  The polyphonic freedom is exercised by the unit tests (which enumerate all alternatives and
//  assert decrypt-invariance), and the ACA worked example is pinned as a decrypt-only
//  known-answer vector. Every square is a bijection, so decryption is exact; a lone trailing
//  plaintext/cipher letter passes through (the generator pads an odd plaintext with X). The
//  solver needs only trisquare_decrypt();
//  encrypt + the shared playfair_grid_from_keyword serve the generator and the unit tests.
//  Side-generic (side / n = side*side); reuses bifid_build_inverse.
//

#include "colossus.h"

// Encipher plaintext (any length) into out[] under the three squares. out holds one TRIGRAPH
// (3 letters) per plaintext digraph, so out has length 3*(len/2) [+ 1 if len is odd]. A RANDOM
// representative (consuming the global RNG) is chosen for the two polyphonic cipher letters:
// c0 = a random letter in p1's column of sq1, c2 = a random letter in p2's row of sq2. A lone
// trailing letter passes through. Returns the ciphertext length written.
int trisquare_encrypt(const int plain[], int len, const int sq1[], const int sq2[],
                      const int sq3[], int side, int out[]) {
    int n = side * side;
    int pos1[SQUARE_MAX_GRID], pos2[SQUARE_MAX_GRID];
    bifid_build_inverse(sq1, pos1, n);
    bifid_build_inverse(sq2, pos2, n);
    int i = 0, o = 0;
    for (; i + 1 < len; i += 2) {
        int a = pos1[plain[i]],     r1 = a / side, c1 = a % side;   // p1 in sq1
        int b = pos2[plain[i + 1]], r2 = b / side, c2 = b % side;   // p2 in sq2
        out[o++] = sq1[rand_int(0, side) * side + c1];  // c0: any letter in p1's column of sq1
        out[o++] = sq3[r1 * side + c2];                 // c1: sq3[row(p1)][col(p2)] (deterministic)
        out[o++] = sq2[r2 * side + rand_int(0, side)];  // c2: any letter in p2's row of sq2
    }
    if (i < len) out[o++] = plain[i];       // lone trailing letter passes through
    return o;
}

// Decipher a Tri-Square ciphertext (a stream of trigraphs) into out[]. Two plaintext letters
// per trigraph; a lone trailing letter (len3 % 3 == 1) passes through. Returns the plaintext
// length written (2*(len3/3) [+ len3%3]). Inverse of trisquare_encrypt for any clerk choices.
int trisquare_decrypt(const int cipher[], int len3, const int sq1[], const int sq2[],
                      const int sq3[], int side, int out[]) {
    int n = side * side;
    int pos1[SQUARE_MAX_GRID], pos2[SQUARE_MAX_GRID], pos3[SQUARE_MAX_GRID];
    bifid_build_inverse(sq1, pos1, n);
    bifid_build_inverse(sq2, pos2, n);
    bifid_build_inverse(sq3, pos3, n);
    int i = 0, o = 0;
    for (; i + 2 < len3; i += 3) {
        int c0 = cipher[i], c1 = cipher[i + 1], c2 = cipher[i + 2];
        int col1 = pos1[c0] % side;                          // column of c0 in sq1 == p1's col
        int m = pos3[c1], row1 = m / side, col2 = m % side;  // cell of c1 in sq3
        int row2 = pos2[c2] / side;                          // row of c2 in sq2 == p2's row
        out[o++] = sq1[row1 * side + col1];
        out[o++] = sq2[row2 * side + col2];
    }
    while (i < len3) out[o++] = cipher[i++];                 // lone trailing letter(s) pass through
    return o;
}
