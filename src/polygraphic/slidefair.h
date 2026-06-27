#ifndef SLIDEFAIR_H
#define SLIDEFAIR_H
#include "colossus.h"

// Slidefair cipher primitives (ACA "periodic digraphic Vigenere/Variant/Beaufort").
//
// Slidefair enciphers the plaintext in consecutive DIGRAPHS over a two-row slide. A keyword
// fixes the period P (= keyword length); DIGRAPH i (cipher letters 2i, 2i+1) is keyed by
// keyword letter key[i mod P] (so writing P digraphs per row puts one key letter per column).
// The slide for key letter k (0..25) is two rows: the TOP row is the standard alphabet
// (top[col] = col); the BOTTOM row depends on the variant:
//     SLIDEFAIR       (Vigenere) :  bottom[col] = (col + k) mod 26
//     SLIDEFAIR_VAR   (Variant)  :  bottom[col] = (col - k) mod 26
//     SLIDEFAIR_BEAU  (Beaufort) :  bottom[col] = (k - col) mod 26
//
// A plaintext digraph (p1, p2): p1 is found in the TOP row (column p1), p2 in the BOTTOM row
// (the column where bottom[col] == p2). They are diagonally opposite corners of a rectangle;
// the substitutes are the OTHER two corners, the one from the TOP row taken first:
//     c1 = top[col_of_p2] = col_of_p2,   c2 = bottom[col_of_p1].
// If p1 and p2 fall in the same column (a vertical pair), the cipher equivalent is the vertical
// pair "just to the right": c1 = top[col+1], c2 = bottom[col+1] (mod 26).
//
// Decryption is the SAME rectangle operation (the cipher is self-reciprocal) EXCEPT the vertical
// special case takes the pair just to the LEFT, inverting the encrypt "right" step. Rectangle
// cipher pairs are never themselves vertical, so the case is detected unambiguously.
//
// Verified cell-for-cell against the ACA worked examples (key B: ca -> ZD/BB/BZ, de -> EF/FC/XY
// for Vig/Var/Beau; keyword DIGRAPH, "the slidefair can be used..." -> EWKMCRNUAFCXTJ...).
//
// `type` is one of the cipher-type codes SLIDEFAIR / SLIDEFAIR_VAR / SLIDEFAIR_BEAU.
// Full 26-letter alphabet (NO J->I merge). out[] must not alias the input. A lone final letter
// (odd length) has no partner and passes through unchanged.

// Encipher one digraph (p1 = top, p2 = bottom) under key letter k for the given variant.
void slidefair_pair_enc(int p1, int p2, int k, int type, int *c1, int *c2);

// Decipher one digraph (c1 = top, c2 = bottom) under key letter k for the given variant.
void slidefair_pair_dec(int c1, int c2, int k, int type, int *p1, int *p2);

// Apply Slidefair to in[0..len-1] with per-column key letters key[0..P-1] (each 0..25).
// out[] must not alias in[].
void slidefair_encrypt(int out[], const int in[], int len, const int key[], int P, int type);
void slidefair_decrypt(int out[], const int in[], int len, const int key[], int P, int type);

#endif
