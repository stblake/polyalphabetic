//
//  Seriated Playfair cipher primitives (ACA "Seriated Playfair"; see PLAYFAIR).
//
//  Plain Playfair over a 5x5 keyed square, but the digraphs are formed from VERTICAL
//  PAIRS of a two-row seriated layout of period P instead of consecutive horizontal
//  pairs. Lay the plaintext into blocks of 2P letters: the first P are the top row, the
//  next P the bottom row. Within a block, vertical pair j couples block-letter j (top)
//  with block-letter j+P (bottom), for j = 0..P-1; each pair is enciphered by the three
//  standard Playfair rules (same row -> shift right; same column -> shift down;
//  rectangle -> swap columns) and the two cipher letters are written BACK to positions
//  j and j+P. The cipher stream is the blocks serialized left-to-right (top row then
//  bottom row) -- the "taken off horizontally" readout. So the whole cipher is exactly:
//
//      for each block of 2P letters, for j in 0..P-1:
//          (out[j], out[j+P]) = playfair_pair(in[j], in[j+P], dir)   // +1 enc, -1 dec
//
//  The same 0..24 alphabet-index representation and 5x5 grid (a permutation of the
//  active 25-letter alphabet) as playfair.c; the grid/inverse builder and the keyword
//  grid build are reused from there (playfair_build_inverse, playfair_grid_from_keyword).
//  The 3-rule pair is a small static-inline copy here so playfair.c stays byte-identical
//  (its hot loop keeps its own inlined copy) and this module's hot loop is inlined too;
//  both copies are pinned by the round-trip + known-answer unit tests.
//
//  The solver only needs seriated_playfair_decrypt(); encrypt + prepare exist for the
//  test-data generator and the round-trip / ACA known-answer unit tests. Nulls are
//  transparent on decrypt (extra plaintext letters, like Playfair's X), so the solver
//  never touches the prepare step; a ragged final block passes lone top letters through.
//

#include "colossus.h"

// Apply the three Playfair rules to the digraph (a, b) with the inverse map pos[].
// dir = +1 enciphers (shift right / down), dir = -1 deciphers (shift left / up); the
// rectangle rule (column swap) is self-inverse, so the same branch serves both. (A copy
// of playfair.c's static-inline playfair_pair -- see the file header.)
static inline void sp_pair(const int grid[], const int pos[],
                           int a, int b, int dir, int *oa, int *ob) {
    int s = PLAYFAIR_SIDE;
    int pa = pos[a], pb = pos[b];
    int ra = pa / s, ca = pa % s;
    int rb = pb / s, cb = pb % s;
    if (ra == rb) {                              // same row: shift column by dir (cyclic)
        *oa = grid[ra * s + (ca + dir + s) % s];
        *ob = grid[rb * s + (cb + dir + s) % s];
    } else if (ca == cb) {                       // same column: shift row by dir (cyclic)
        *oa = grid[((ra + dir + s) % s) * s + ca];
        *ob = grid[((rb + dir + s) % s) * s + cb];
    } else {                                     // rectangle: swap columns (self-inverse)
        *oa = grid[ra * s + cb];
        *ob = grid[rb * s + ca];
    }
}

// Encipher (dir=+1) or decipher (dir=-1) `len` letters of `in` into `out` over the
// seriated layout of period `period` and the 5x5 grid. Vertical pair j (j=0..P-1) of
// each 2P block couples in[j] with in[j+P]; outputs go back to the same positions. A
// ragged final block (no bottom partner) passes the lone top letter through unchanged.
static void seriated_playfair_apply(const int in[], int len, const int grid[],
                                    int period, int dir, int out[]) {
    int pos[PLAYFAIR_GRID];
    playfair_build_inverse(grid, pos);
    int P = period, B = 2 * P;
    for (int b = 0; b < len; b += B) {
        for (int j = 0; j < P; j++) {
            int it = b + j, ib = b + P + j;
            if (it >= len) break;                // no more top letters in this block
            if (ib >= len) { out[it] = in[it]; continue; }   // lone top letter: pass through
            sp_pair(grid, pos, in[it], in[ib], dir, &out[it], &out[ib]);
        }
    }
}

// Encipher a prepared plaintext into out[]. (prepared = no doubled vertical pairs; see
// seriated_playfair_prepare.)
void seriated_playfair_encrypt(const int plain[], int len, const int grid[],
                               int period, int out[]) {
    seriated_playfair_apply(plain, len, grid, period, +1, out);
}

// Decipher ciphertext into out[]. Inverse of seriated_playfair_encrypt. The only routine
// the solver needs.
void seriated_playfair_decrypt(const int cipher[], int len, const int grid[],
                               int period, int out[]) {
    seriated_playfair_apply(cipher, len, grid, period, -1, out);
}

// Lay raw plaintext (alphabet indices) into the seriated period-P layout and break
// doubled vertical pairs: when a complete block's vertical pair (j, j+P) is two equal
// letters, insert a null at the BOTTOM cell (filler, or `alt` if the letter IS the
// filler) and reflow the tail -- exactly the ACA rule. The final partial block is then
// padded with the filler to a full 2P width. Returns the prepared length (bounded by
// out_cap). (At P=1 this reduces to playfair_prepare's consecutive-pair handling.)
int seriated_playfair_prepare(const int raw[], int len, int period,
                              int filler, int alt, int out[], int out_cap) {
    int P = period, B = 2 * P;
    int n = 0;
    for (int i = 0; i < len && n < out_cap; i++) out[n++] = raw[i];

    // Null-insertion pass over COMPLETE blocks (re-reading n, which grows on insert: a
    // pushed letter just forms part of a later block). Pad-only tails are handled after.
    for (int b = 0; b + B <= n; b += B) {
        for (int j = 0; j < P; j++) {
            int it = b + j, ib = b + P + j;
            if (out[it] != out[ib]) continue;            // not a doubled vertical pair
            if (n + 1 > out_cap) return n;               // no room for the null
            int nullv = (out[it] == filler) ? alt : filler;
            for (int k = n; k > ib; k--) out[k] = out[k - 1];   // reflow the tail right
            out[ib] = nullv;
            n++;
        }
    }

    // Pad the final partial block to a full 2P width with the filler (pad-vs-pad doubles
    // are harmless: they round-trip, and a human ignores trailing fillers).
    if (n % B != 0)
        while (n % B != 0 && n < out_cap) out[n++] = filler;
    return n;
}
