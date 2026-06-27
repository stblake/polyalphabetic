#ifndef BAZERIES_H
#define BAZERIES_H
#include "colossus.h"

// Bazeries cipher primitives ("simple substitution plus transposition", ACA).
//
// The whole key is one number N < 1,000,000 (e.g. 3752). That single number drives BOTH
// stages over the 25-letter J->I alphabet (a 5x5 Polybius geometry):
//
//   1. Transposition: split the plaintext into groups whose sizes cycle through the
//      DECIMAL DIGITS of N (3,7,5,2,3,7,5,2,...) and REVERSE each group. A 0 digit is a
//      zero-length group (skipped); the leading digit is >= 1 so the walk always advances.
//      Reversal is an involution, so the same routine undoes it.
//   2. Substitution: a fixed monoalphabetic map between two 5x5 squares. The PLAINTEXT
//      square is the alphabet entered COLUMN-major (cell (r,c) holds alphabet index c*5+r);
//      the CIPHERTEXT square is N spelled out ("three thousand seven hundred fifty two")
//      used as the keyword of a keyed square entered ROW-major (== bifid_grid_from_keyword).
//      Each transposed letter is found in the pt square and replaced by the letter at the
//      same (row,col) in the ct square.
//
// Encryption = transpose then substitute; decryption = inverse-substitute then un-transpose.
// out[] must not alias the input. The active alphabet must be the 25-letter J->I set
// (init_alphabet("J")), so g_char_to_idx maps the spelled letters into 0..24.

#define BAZERIES_SIDE 5
#define BAZERIES_GRID 25            // BAZERIES_SIDE * BAZERIES_SIDE
#define BAZERIES_MAX_DIGITS 6       // a key number < 1,000,000 has at most 6 decimal digits
#define BAZERIES_MAX_KEY 999999L    // largest key number ("less than a million")
#define BAZERIES_MAX_SPELL 64       // headroom for the letters of the longest spelled number

// Spell key number n (1..999999, no "and") and emit its letters as J->I alphabet indices
// (via g_char_to_idx over the active 25-letter alphabet). Returns the count written to kw[]
// (kw[] must hold BAZERIES_MAX_SPELL entries). Letters that do not map are skipped.
int  bazeries_spell(long n, int kw[]);

// Build the keyed ciphertext square (row-major, BAZERIES_GRID cells) from the spelled number:
// bazeries_spell -> bifid_grid_from_keyword.
void bazeries_build_square(long key, int square[]);

// Forward substitution table fsub[L] (plaintext letter L -> ciphertext letter): the pt
// square is the fixed column-major alphabet, so L sits at (r=L%5, c=L/5) and maps to the
// ct-square cell r*side+c. 25 entries.
void bazeries_build_sub(const int square[], int fsub[]);

// Inverse substitution table invsub[X] (ciphertext letter X -> plaintext letter): X sits at
// ct-square cell p, and the pt square's column-major letter at (r=p/5,c=p%5) is c*5+r. 25 entries.
void bazeries_build_invsub(const int square[], int invsub[]);

// Decimal digits of key (MSB first); writes *ndigits in [1..BAZERIES_MAX_DIGITS].
void bazeries_digits(long key, int digits[], int *ndigits);

// Reverse each cycling digit-sized group of in[0..n-1] into out[] (an involution; a 0
// digit is a zero-length group, skipped). out[] must not alias in[].
void bazeries_transpose(const int in[], int n, const int digits[], int ndigits, int out[]);

// Encrypt / decrypt n symbols under the key number. out[] must not alias the input.
void bazeries_encrypt(const int plain[], int n, long key, int out[]);
void bazeries_decrypt(const int cipher[], int n, long key, int out[]);

#endif
