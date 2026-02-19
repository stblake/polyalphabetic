
// Transpositions

#include "polyalphabetic.h"

void transperoffset(int plaintext[], int len, int d, int n) {

    if (d == 1 && n == 0) return; // Identity transformation.

    int temp[MAX_CIPHER_LENGTH];
    
    // Periodic decimation.
    for (int i = 0; i < len; i++) {
        temp[i] = plaintext[(d * i) % len];
    }

    // Rotation (Offset.)
    for (int i = 0; i < len; i++) {
        plaintext[i] = temp[(i + n) % len];
    }
    return ;
}


