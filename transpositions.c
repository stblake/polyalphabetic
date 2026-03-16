
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

