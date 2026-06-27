//
// Slidefair Cipher (ACA "periodic digraphic Vigenere/Variant/Beaufort")
//

/*
   Slidefair: definition and the verified arithmetic.

   A two-row slide for key letter k (0..25). The TOP row is the standard alphabet; the BOTTOM
   row is one of the classic shift alphabets:

       top[col]                = col
       bottom[col] (Vigenere)  = (col + k) mod 26
       bottom[col] (Variant)   = (col - k) mod 26
       bottom[col] (Beaufort)  = (k - col) mod 26

   so the column holding a given BOTTOM value v inverts as:

       bottom_col(v) (Vigenere) = (v - k) mod 26
       bottom_col(v) (Variant)  = (v + k) mod 26
       bottom_col(v) (Beaufort) = (k - v) mod 26    (Beaufort is its own inverse)

   A plaintext digraph (p1 = top, p2 = bottom) sits at diagonal corners of a 2-row rectangle:
   p1 in column col1 = p1, p2 in column col2 = bottom_col(p2). The substitutes are the OTHER two
   corners, the TOP one first:

       col1 != col2 :  c1 = top[col2] = col2,     c2 = bottom[col1]
       col1 == col2 :  vertical pair -> the pair one column to the RIGHT:
                       c1 = top[(col1+1)%26],     c2 = bottom[(col1+1)%26]

   Decryption is the SAME rectangle operation (self-reciprocal), except the vertical case takes
   the pair one column to the LEFT, inverting the encrypt step. A rectangle cipher pair is never
   itself vertical (its two letters lie in distinct columns col2 and col1), so decrypt detects
   the vertical case unambiguously.

   Hand-verified against every worked example in the ACA Slidefair description.
*/

#include "colossus.h"
#include "slidefair.h"

#define SF_N ALPHABET_SIZE   // 26

// Value at (bottom row, column col) for the given variant.
static inline int sf_bottom_val(int col, int k, int type) {
    if (type == SLIDEFAIR_BEAU) return (k - col + SF_N) % SF_N;
    if (type == SLIDEFAIR_VAR)  return (col - k + SF_N) % SF_N;
    return (col + k) % SF_N;                                   // SLIDEFAIR (Vigenere)
}

// Column whose bottom-row value equals v (the inverse of sf_bottom_val in col).
static inline int sf_bottom_col(int v, int k, int type) {
    if (type == SLIDEFAIR_BEAU) return (k - v + SF_N) % SF_N;  // Beaufort is self-inverse
    if (type == SLIDEFAIR_VAR)  return (v + k) % SF_N;
    return (v - k + SF_N) % SF_N;                              // SLIDEFAIR (Vigenere)
}

void slidefair_pair_enc(int p1, int p2, int k, int type, int *c1, int *c2) {
    int col1 = p1;                                             // p1 in the standard top row
    int col2 = sf_bottom_col(p2, k, type);                    // p2 in the slid bottom row
    if (col1 != col2) {
        *c1 = col2;                                            // top[col2]
        *c2 = sf_bottom_val(col1, k, type);
    } else {
        int cc = (col1 + 1) % SF_N;                           // vertical pair: one column right
        *c1 = cc;
        *c2 = sf_bottom_val(cc, k, type);
    }
}

void slidefair_pair_dec(int c1, int c2, int k, int type, int *p1, int *p2) {
    int a = c1;                                                // c1 read off the top row
    int b = sf_bottom_col(c2, k, type);                       // c2 read off the bottom row
    if (a != b) {
        *p1 = b;                                               // top[b]
        *p2 = sf_bottom_val(a, k, type);
    } else {
        int cc = (a - 1 + SF_N) % SF_N;                       // vertical pair: one column left
        *p1 = cc;
        *p2 = sf_bottom_val(cc, k, type);
    }
}

void slidefair_encrypt(int out[], const int in[], int len, const int key[], int P, int type) {
    int ndg = len / 2;
    for (int i = 0; i < ndg; i++) {
        int x, y;
        slidefair_pair_enc(in[2 * i], in[2 * i + 1], key[i % P], type, &x, &y);
        out[2 * i] = x;
        out[2 * i + 1] = y;
    }
    if (len & 1) out[len - 1] = in[len - 1];                  // lone final letter passes through
}

void slidefair_decrypt(int out[], const int in[], int len, const int key[], int P, int type) {
    int ndg = len / 2;
    for (int i = 0; i < ndg; i++) {
        int x, y;
        slidefair_pair_dec(in[2 * i], in[2 * i + 1], key[i % P], type, &x, &y);
        out[2 * i] = x;
        out[2 * i + 1] = y;
    }
    if (len & 1) out[len - 1] = in[len - 1];                  // lone final letter passes through
}
