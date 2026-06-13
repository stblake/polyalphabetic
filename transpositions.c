
// Transpositions

#include "polyalphabetic.h"

void transperoffset(int plaintext[], int len, int d, int n) {

    if (d == 1 && n == 0) return; // Identity transformation.

    int indx, temp[MAX_CIPHER_LENGTH];
    
    // Periodic decimation.
    for (int i = 0; i < len; i++) {
        temp[i] = plaintext[(d * i) % len];
    }

    // Rotation (Offset.)
    for (int i = 0; i < len; i++) {
    	indx = (i + n) % len;
    	if (indx < 0) {
    		indx += len;
    	}
        plaintext[i] = temp[indx];
    }
    return ;
}



void matrix_rotate(int text[], int len, int width, int clockwise) {
    if (width <= 1 || width >= len) return; // Identity or 1D matrix

    int R = (len + width - 1) / width; // Ceiling division for rows
    int W = width;
    int temp[MAX_CIPHER_LENGTH];
    int idx = 0;

    if (clockwise) {
        // Read columns left-to-right, but from bottom row to top row
        for (int c = 0; c < W; c++) {
            for (int r = R - 1; r >= 0; r--) {
                int old_idx = r * W + c;
                // Only read if the cell is valid (handles incomplete final rows)
                if (old_idx < len) {
                    temp[idx++] = text[old_idx];
                }
            }
        }
    } else {
        // Anti-clockwise: Read columns right-to-left, top to bottom
        for (int c = W - 1; c >= 0; c--) {
            for (int r = 0; r < R; r++) {
                int old_idx = r * W + c;
                if (old_idx < len) {
                    temp[idx++] = text[old_idx];
                }
            }
        }
    }

    // Copy back to original array
    for (int i = 0; i < len; i++) {
        text[i] = temp[i];
    }
}

void transmatrix(int text[], int len, int w1, int w2, int clockwise) {
    // Perform a K3-like double rotation.
    matrix_rotate(text, len, w1, clockwise);
    matrix_rotate(text, len, w2, clockwise);
}


// Invert one columnar transposition stage.
//
// Encryption writes the plaintext into a grid of K columns, row by row
// left-to-right, then reads the columns off in order `order[0..K-1]` (each column
// top-to-bottom for COL_READ_TB, bottom-to-top for COL_READ_BT). The grid's last
// row is short when len % K != 0: the leftmost (len % K) columns are one cell
// taller than the rest, so each column's height is known up front.
//
// To decrypt we slice the ciphertext back into those columns in read order,
// refill the grid, and read it row-major. out[] must not alias cipher[].
void decrypt_columnar(int cipher[], int len, int K, int order[], int dir, int out[]) {

    if (K <= 1 || K > len) {            // degenerate: a single column is the identity
        for (int i = 0; i < len; i++) out[i] = cipher[i];
        return;
    }

    int grid[MAX_CIPHER_LENGTH];
    int R = (len + K - 1) / K;          // number of rows (ceiling)
    int rem = len % K;                  // tall columns are 0..rem-1 (all K if rem==0)

    // Refill the grid one column at a time, consuming the ciphertext in read order.
    int pos = 0;
    for (int j = 0; j < K; j++) {
        int c = order[j];
        int h = (rem == 0 || c < rem) ? R : R - 1;   // height of grid column c
        if (dir == COL_READ_BT) {
            for (int r = h - 1; r >= 0; r--) grid[r * K + c] = cipher[pos++];
        } else { // COL_READ_TB
            for (int r = 0; r < h; r++) grid[r * K + c] = cipher[pos++];
        }
    }

    // Read the grid row-major to recover the plaintext (skip missing short-row cells).
    int o = 0;
    for (int r = 0; r < R; r++) {
        for (int c = 0; c < K; c++) {
            int h = (rem == 0 || c < rem) ? R : R - 1;
            if (r < h) out[o++] = grid[r * K + c];
        }
    }
}

