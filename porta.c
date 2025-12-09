// 
// Porta Cipher 
//

/*
   Porta Cipher: Definition and Logic (ACA Standard)
  
   The Porta cipher is a **reciprocal polyalphabetic substitution cipher**, 
   meaning the encryption and decryption processes use the exact same steps.
   It relies on a periodic keyword (cycleword) to determine the shift for 
   each letter.
   
   ## Key Shift Determination
   
   The full alphabet (A-Z, indices 0-25) is divided into two halves:
   1. **First Half**: A-M (indices 0-12)
   2. **Second Half**: N-Z (indices 13-25)
   
   A key character K (index $K_{idx} \in [0, 25]$) generates a fixed shift value S 
   (where $S \in [0, 12]$) using the following rule:
   
   $$S = \lfloor \frac{K_{idx}}{2} \rfloor$$
   
   This ensures that every pair of key letters (A/B, C/D, E/F, etc.) applies 
   the same substitution pattern.

   ## Reciprocal Substitution Formulas
   
   The substitution is reciprocal (I = Input Index, O = Output Index):
   
   **1. If Input I is in the First Half (A-M, $I \in [0, 12]$):**
      The Output O will be in the Second Half (N-Z).
      
      $$O = (I + S) \pmod{13} + 13$$
      
   **2. If Input I is in the Second Half (N-Z, $I \in [13, 25]$):**
      The Output O will be in the First Half (A-M).
      
      $$O = (I - 13 - S) \pmod{13}$$

   Since $E=D$, these formulas are applied identically for both encryption and decryption.
*/


#include "polyalphabetic.h"

void porta_core(int output[], int input[], int len, int cycleword_indices[], int cycleword_len);


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

