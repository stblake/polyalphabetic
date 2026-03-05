
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


