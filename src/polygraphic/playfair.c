//
//  Playfair cipher primitives (digraphic substitution over a 5x5 keyed grid).
//
//  The grid is a permutation of the active 25-letter alphabet: the binary forces
//  g_alpha == 25 for -type playfair by excluding one letter (J, merged into I, by
//  default). Letters are carried as 0..24 alphabet indices, so grid[p] is the letter
//  at grid position p (row p / 5, col p % 5) and the inverse pos[l] is the grid
//  position of letter l. Every routine here assumes that representation and a
//  PLAYFAIR_SIDE x PLAYFAIR_SIDE grid.
//
//  Encryption maps each plaintext digraph by the three standard rules (same row ->
//  shift right; same column -> shift down; rectangle -> swap columns); decryption is
//  the inverse (left / up / swap columns). The solver only needs playfair_decrypt();
//  encrypt + prepare + grid_from_keyword exist for the test-data generator and the
//  round-trip / known-answer unit tests, which cross-check the convention.
//

#include "colossus.h"

// Build pos[] (letter -> grid position) from grid[] (position -> letter).
void playfair_build_inverse(const int grid[], int pos[]) {
    for (int p = 0; p < PLAYFAIR_GRID; p++) pos[grid[p]] = p;
}

// Apply the three Playfair rules to the digraph (a, b) with the inverse map pos[].
// dir = +1 enciphers (shift right / down), dir = -1 deciphers (shift left / up); the
// rectangle rule (column swap) is self-inverse, so the same branch serves both.
static inline void playfair_pair(const int grid[], const int pos[],
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

// Encipher a prepared plaintext (even length, no equal-letter pairs) into out[].
void playfair_encrypt(const int plain[], int len, const int grid[], int out[]) {
    int pos[PLAYFAIR_GRID];
    playfair_build_inverse(grid, pos);
    int i = 0;
    for (; i + 1 < len; i += 2)
        playfair_pair(grid, pos, plain[i], plain[i + 1], +1, &out[i], &out[i + 1]);
    if (i < len) out[i] = plain[i];              // stray unpaired letter: pass through
}

// Decipher ciphertext (even length) into out[]. Inverse of playfair_encrypt.
void playfair_decrypt(const int cipher[], int len, const int grid[], int out[]) {
    int pos[PLAYFAIR_GRID];
    playfair_build_inverse(grid, pos);
    int i = 0;
    for (; i + 1 < len; i += 2)
        playfair_pair(grid, pos, cipher[i], cipher[i + 1], -1, &out[i], &out[i + 1]);
    if (i < len) out[i] = cipher[i];
}

// A filler distinct from `a`, so a doubled letter never produces the pair (a, a).
static inline int playfair_filler_for(int a, int filler, int alt) {
    return (a == filler) ? alt : filler;
}

// Split raw plaintext (alphabet indices, no excluded letter) into Playfair digraphs:
// insert `filler` between the two equal letters of a pair, and pad a final lone letter
// with `filler`. `alt` is a backup filler used when the doubled letter IS the filler.
// Returns the prepared length (always even, bounded by out_cap).
int playfair_prepare(const int raw[], int len, int filler, int alt, int out[], int out_cap) {
    int n = 0, i = 0;
    while (i < len && n + 2 <= out_cap) {
        int a = raw[i], b;
        if (i + 1 < len) {
            if (raw[i + 1] == a) { b = playfair_filler_for(a, filler, alt); i += 1; }
            else                 { b = raw[i + 1];                          i += 2; }
        } else                   { b = playfair_filler_for(a, filler, alt); i += 1; }
        out[n++] = a;
        out[n++] = b;
    }
    return n;
}

// Build a grid from a keyword (alphabet indices): the keyword letters in order with
// duplicates removed, then the remaining alphabet letters in ascending order.
void playfair_grid_from_keyword(const int keyword[], int kwlen, int grid[]) {
    char used[PLAYFAIR_GRID];
    for (int l = 0; l < PLAYFAIR_GRID; l++) used[l] = 0;
    int n = 0;
    for (int i = 0; i < kwlen && n < PLAYFAIR_GRID; i++) {
        int l = keyword[i];
        if (l < 0 || l >= PLAYFAIR_GRID || used[l]) continue;
        used[l] = 1;
        grid[n++] = l;
    }
    for (int l = 0; l < PLAYFAIR_GRID && n < PLAYFAIR_GRID; l++)
        if (!used[l]) { used[l] = 1; grid[n++] = l; }
}
