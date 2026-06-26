//
// Nicodemus cipher (substitution + transposition composite)
// =========================================================
//
// See nicodemus.h for the convention. The cipher processes the text in blocks of
// `block_h` rows x P columns (row-major fill); each block is enciphered independently:
// every grid column is Vigenere/Variant/Beaufort-enciphered by its own keyword letter,
// then the columns are read off top-to-bottom in `order` (a per-block columnar
// transposition). The columnar take-off and its inverse use the standard incomplete-grid
// rule (the leftmost L % P columns one cell taller) directly per block -- the same math as
// transpositions.c's decrypt_columnar, but applied to each H*P block (decrypt_columnar's
// K > len identity guard would misfire on a final block narrower than P columns).
//
// All arithmetic is mod ALPHABET_SIZE (26): Nicodemus runs on the full 26-letter
// alphabet, like Vigenere/Gromark.

#include "colossus.h"
#include "nicodemus.h"

void nicodemus_key_from_keyword(const int kw[], int P, int order[], int shifts[]) {
    for (int c = 0; c < P; c++) shifts[c] = kw[c];
    // order[rank(g)] = g, where rank is the stable ascending rank of keyword letter g:
    // letters strictly smaller, plus equal letters at an earlier index.
    for (int g = 0; g < P; g++) {
        int rank = 0;
        for (int h = 0; h < P; h++) {
            if (kw[h] < kw[g]) rank++;
            else if (kw[h] == kw[g] && h < g) rank++;
        }
        order[rank] = g;
    }
}

void nicodemus_encrypt(const int plain[], int len, int P, int block_h,
                       const int order[], const int shifts[], int variant, int out[]) {
    int blk = block_h * P;
    int tmp[MAX_CIPHER_LENGTH];
    int opos = 0;
    for (int base = 0; base < len; base += blk) {
        int L = (len - base < blk) ? (len - base) : blk;
        // Substitute in place (grid column of position i within the block is i % P).
        for (int i = 0; i < L; i++)
            tmp[i] = nicodemus_sub(plain[base + i], shifts[i % P], variant);
        // Read columns off top-to-bottom in `order`. The grid has R rows (ceil), the
        // leftmost (L % P) columns one cell taller -- the inverse of decrypt_columnar.
        int R = (L + P - 1) / P;
        int rem = L % P;
        for (int j = 0; j < P; j++) {
            int c = order[j];
            int h = (rem == 0 || c < rem) ? R : R - 1;
            for (int r = 0; r < h; r++) out[opos++] = tmp[r * P + c];
        }
    }
}

void nicodemus_detranspose(const int cipher[], int len, int P, int block_h,
                           const int order[], int out[]) {
    int blk = block_h * P;
    int grid[MAX_CIPHER_LENGTH + MAX_COLS];
    for (int base = 0; base < len; base += blk) {
        int L = (len - base < blk) ? (len - base) : blk;
        // Per-block columnar inverse: refill the P columns in read order, then read the grid
        // row-major. The leftmost (L % P) columns are one cell taller -- the exact inverse of
        // the take-off in nicodemus_encrypt (and of decrypt_columnar, but without its K > len
        // identity guard, which would misfire on a final block narrower than P columns).
        int R = (L + P - 1) / P;
        int rem = L % P;
        int pos = 0;
        for (int j = 0; j < P; j++) {
            int c = order[j];
            int h = (rem == 0 || c < rem) ? R : R - 1;
            for (int r = 0; r < h; r++) grid[r * P + c] = cipher[base + pos++];
        }
        int o = 0;
        for (int r = 0; r < R; r++)
            for (int c = 0; c < P; c++) {
                int h = (rem == 0 || c < rem) ? R : R - 1;
                if (r < h) out[base + o++] = grid[r * P + c];
            }
    }
}

void nicodemus_inv_substitute(const int desub[], int len, int P,
                              const int shifts[], int variant, int out[]) {
    // Grid column of detransposed position i is i % P (block bases are multiples of P,
    // since a full block is block_h * P letters), so a single i % P suffices globally.
    for (int i = 0; i < len; i++)
        out[i] = nicodemus_inv_sub(desub[i], shifts[i % P], variant);
}

void nicodemus_decrypt(const int cipher[], int len, int P, int block_h,
                       const int order[], const int shifts[], int variant, int out[]) {
    int desub[MAX_CIPHER_LENGTH];
    nicodemus_detranspose(cipher, len, P, block_h, order, desub);
    nicodemus_inv_substitute(desub, len, P, shifts, variant, out);
}
