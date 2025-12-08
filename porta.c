// 
// Porta Cipher Logic 
//

// Started 8 December, 2025. 

/*
   Porta Cipher Logic (ACA Standard)
  
   The Porta cipher is a reciprocal polyalphabetic substitution cipher,
   meaning the same process is used for both encryption and decryption.
   It uses a periodic keyword to determine the shifts.
   The alphabet is divided into two halves: A-M (0-12) and N-Z (13-25).
   A key character 'K' (at index 0-25) provides a fixed shift value, S,
   calculated as S = floor(K / 2). This means that every two key letters
   (e.g., A/B, C/D, E/F, etc.) use the same substitution pattern.
   The substitution is always reciprocal and defined by the following formulas,
   where I is the input index (0-25) and S is the key shift (0-12):
   1. If Input I is in A-M (0-12):
   Output O is in N-Z (13-25). Formula: O = (I + S) mod 13 + 13
   2. If Input I is in N-Z (13-25):
   Output O is in A-M (0-12). Formula: O = (I - 13 - S) mod 13
   * This implementation adheres to the existing index-based (0-25) solver framework
   and is mathematically consistent across decryption and scoring routines.
 */


#include "polyalphabetic.h"

void porta_core(int output[], int input[], int len, int cycleword_indices[], int cycleword_len) {
    int i, input_val, key_val, shift;

    for (i = 0; i < len; i++) {
        input_val = input[i]; // Input index (0-25)
        key_val = cycleword_indices[i % cycleword_len]; // Key index (0-25)

        // The Porta shift value (0-12)
        shift = key_val / 2;
        
        // This is the core reciprocal transformation (ACA definition)
        if (input_val < 13) { // Input char is in A-M (0-12)
            // Output char is in N-Z (13-25). Formula: O = (I + S) mod 13 + 13
            output[i] = (input_val + shift) % 13 + 13;
        } else { // Input char is in N-Z (13-25)
            // Output char is in A-M (0-12). Formula: O = (I - 13 - S) mod 13
            // We ensure positive result before modulus 13.
            // ALPHABET_SIZE (26) is used here as a sufficient large constant.
            output[i] = (input_val - 13 - shift + ALPHABET_SIZE) % 13; 
        }
    }
}

void porta_decrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len) {
    porta_core(output, input, len, cycleword_indices, cycleword_len);
}

void porta_encrypt(int output[], int input[], int len, int cycleword_indices[], int cycleword_len) {
    porta_core(output, input, len, cycleword_indices, cycleword_len);
}

