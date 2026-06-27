#ifndef PORTAX_H
#define PORTAX_H
#include "colossus.h"

// Portax cipher primitives (ACA "periodic digraphic Porta").
//
// Portax enciphers the plaintext in VERTICAL PAIRS over a Porta slide. The message is written
// row-major into a block of width P (= keyword length); rows are taken in PAIRS (rows 2g and
// 2g+1), and the vertical pair in column c -- (top = pt[2g*P + c], bottom = pt[2g*P + P + c]) --
// is enciphered as a unit by the column key letter keyword[c]. Only the Porta SHIFT s = key/2
// (0..12) matters (key letters U and V are identical), exactly as for the plain Porta cipher.
//
// The slide has four rows:
//     A1/1 (fixed, A..M)         the top letter is found here if it is in A..M (0..12)
//     A1/2 (sliding, N..Z...)    or here if it is in N..Z (13..25)
//     A2 top (sliding, even letters A C E ...)   the bottom letter is found in one of these two
//     A2 bot (sliding, odd  letters B D F ...)   A2 rows
// The two plaintext letters are diagonally opposite corners of a rectangle; the substitutes are
// the OTHER two corners (top taken first). When both letters fall in the same vertical line, the
// substitutes are the other two letters of that line (top over bottom). The cipher is SELF-
// RECIPROCAL: the same operation enciphers and deciphers (decrypt == encrypt).
//
// Verified cell-for-cell against the ACA worked examples (key U/V: IN->JL, NO->UA, NA->DB;
// key E: TA->NM, BG->QH; keyword EASY, "the early bird gets the worm" -> NIJAMPBGQCWKHQJEUIKYMPAT).
//
// Full 26-letter alphabet (NO J->I merge). out[] must not alias the input.

#define PORTAX_HALF 13   // half-alphabet size; Porta shifts live in 0..PORTAX_HALF-1 (0..12)

// Encipher/decipher one vertical pair (a = top, b = bottom) under Porta shift s (0..12), an
// involution. Writes the substitute pair to *x (top) and *y (bottom).
void portax_pair(int a, int b, int s, int *x, int *y);

// Apply Portax to in[0..len-1] with per-column Porta SHIFTS shifts[0..period-1] (each 0..12).
// Self-inverse (same routine encrypts and decrypts). A ragged final block whose bottom row is
// missing leaves the lone top letters unchanged. out[] must not alias in[].
void portax_apply(const int in[], int len, const int shifts[], int period, int out[]);

// Key-letter convenience matching the porta_*/cycleword interface: cycleword_indices are key
// LETTERS 0..25 (shift = key/2 per column), cycleword_len is the period. Both call portax_apply.
void portax_encrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len);
void portax_decrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len);

#endif
