//
// Portax Cipher (ACA "periodic digraphic Porta")
//

/*
   Portax: definition and the verified arithmetic.

   The slide is the Porta tableau split into a fixed upper half and a sliding lower half.
   With the slide set for a key whose Porta shift is s (= key/2, in 0..12):

     UPPER band, two rows:
       FIXED  A1/1 :  letter m (A..M, 0..12) sits at column m              (s-independent)
       SLIDE  A1/2 :  letter 13+j (N..Z) sits at column (j - s) mod 13
     LOWER band A2, two rows (one alphabet split into even/odd letters):
       TOP (even) :  letter 2j   sits at column (j - s) mod 13
       BOT (odd)  :  letter 2j+1 sits at column (j - s) mod 13

   A vertical plaintext pair (a = top, b = bottom): a is located in the UPPER band (FIXED if
   a < 13, else SLIDE), b in the LOWER band A2 (TOP row if b even, BOT row if b odd). They are
   diagonally opposite corners of a rectangle whose other two corners are the substitutes (the
   one in a's row taken first):

       colA != colB :  x = upper(rowA, colB, s)        # a's row, b's column
                       y = a2  (rowB, colA, s)         # b's row, a's column
       colA == colB :  x = upper(OTHER(rowA), colA, s) # the other upper cell of that line
                       y = a2  (OTHER(rowB), colA, s)  # the other lower cell of that line

   where, inverting the column formulas above (j = (col + s) mod 13):
       upper(FIXED, col, s) = col
       upper(SLIDE, col, s) = 13 + ((col + s) mod 13)
       a2  (TOP,   col, s)  = 2 * ((col + s) mod 13)
       a2  (BOT,   col, s)  = 2 * ((col + s) mod 13) + 1

   The map is self-reciprocal (decrypt == encrypt): each pair operation is an involution.
   Hand-verified against every worked example in the ACA Portax description.
*/

#include "colossus.h"
#include "portax.h"

void portax_pair(int a, int b, int s, int *x, int *y) {
    int a_slide = (a >= 13);
    int colA = a_slide ? (a - 13 - s + 2 * ALPHABET_SIZE) % PORTAX_HALF : a;
    int rb   = b & 1;                                  // 0 = A2 TOP (even), 1 = A2 BOT (odd)
    int colB = (b / 2 - s + 2 * ALPHABET_SIZE) % PORTAX_HALF;

    if (colA != colB) {
        // Rectangle: substitute in a's row at b's column, and in b's row at a's column.
        *x = a_slide ? 13 + (colB + s) % PORTAX_HALF : colB;
        *y = 2 * ((colA + s) % PORTAX_HALF) + rb;
    } else {
        // Same vertical line: the OTHER upper cell and the OTHER lower cell, top over bottom.
        *x = a_slide ? colA : 13 + (colA + s) % PORTAX_HALF;   // OTHER(rowA): SLIDE<->FIXED
        *y = 2 * ((colA + s) % PORTAX_HALF) + (1 - rb);        // OTHER(rowB): TOP<->BOT
    }
}

void portax_apply(const int in[], int len, const int shifts[], int period, int out[]) {
    int block = 2 * period;
    for (int b = 0; b < len; b += block) {
        for (int c = 0; c < period; c++) {
            int it = b + c;                 // top-row cell of this column
            int ib = b + period + c;        // bottom-row partner
            if (it >= len) break;           // past the end of the (top) row
            if (ib < len) {
                int x, y;
                portax_pair(in[it], in[ib], shifts[c], &x, &y);
                out[it] = x;
                out[ib] = y;
            } else {
                out[it] = in[it];           // ragged: lone top letter, no partner -> passthrough
            }
        }
    }
}

// --- key-letter convenience (cycleword = key letters 0..25; shift = key/2) -----------------

static void portax_key_apply(int output[], int input[], int len,
                             int cycleword_indices[], int cycleword_len) {
    int shifts[MAX_CYCLEWORD_LEN];
    for (int c = 0; c < cycleword_len; c++) shifts[c] = cycleword_indices[c] / 2;
    portax_apply(input, len, shifts, cycleword_len, output);
}

void portax_encrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len) {
    portax_key_apply(output, input, len, cycleword_indices, cycleword_len);
}

void portax_decrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len) {
    portax_key_apply(output, input, len, cycleword_indices, cycleword_len);   // reciprocal
}
