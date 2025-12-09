//
// Beaufort Cipher
//

#include "polyalphabetic.h"

/*
   Beaufort Cipher (ACA Standard)
  
   The Beaufort cipher is a reciprocal substitution cipher, meaning the 
   same process is used for both encryption and decryption. 
   It uses a Vigenere square (Tabula Recta) but employs a subtraction 
   formula.

   The fundamental formula for both encryption (E) and decryption (D) is:
   Output = Key - Input (mod 26)

   Where:
   P = Plaintext index (0-25)
   C = Ciphertext index (0-25)
   K = Key character index (0-25)
   
   Encryption: C = K - P (mod 26)
   Decryption: P = K - C (mod 26)
   
   Since the formula is symmetrical, E = D, confirming its reciprocal nature.
*/
void beaufort_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len) {
    
    int i, c_val, k_val, p_val;

    for (i = 0; i < cipher_len; i++) {
        c_val = cipher_indices[i]; // Cipher index (C)
        k_val = cycleword_indices[i % cycleword_len]; // Key index (K)

        // Beaufort Decryption: P = K - C (mod 26)
        p_val = (k_val - c_val + ALPHABET_SIZE) % ALPHABET_SIZE;
        decrypted[i] = p_val;
    }
}

void beaufort_encrypt(int encrypted[], int plaintext_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len) {
    
    // Identical to decryption
    beaufort_decrypt(encrypted, plaintext_indices, cipher_len, 
        cycleword_indices, cycleword_len);
}