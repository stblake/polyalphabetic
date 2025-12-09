//
// Vigenere Cipher
//

#include "polyalphabetic.h"

/*
   Vigenère Cipher Logic
  
   The Vigenère cipher is a polyalphabetic substitution cipher that uses a 
   keyword (cycleword) to determine a sequence of different Caesar cipher shifts. 
   It uses a standard (straight) alphabet for both plaintext and ciphertext. 
   
   The core operation is modular addition for encryption and subtraction for 
   decryption, all modulo 26 (the alphabet size).
   
   Let P be the plaintext character index (0-25), 
   C be the ciphertext character index (0-25),
   and K be the key character index (0-25).
   
   The key stream is determined by repeating the cycleword.

   Encryption (Standard, non-variant):
   C = (P + K) mod 26
   
   Decryption (Standard, non-variant):
   P = (C - K) mod 26
   
   Variant/Reciprocal Vigenère (sometimes called Vigenère Autokey or just "Variant"):
   P = (K - C) mod 26
   
   The Vigenère cipher uses straight A-Z alphabets for the plaintext and 
   ciphertext substitutions, making it a simple case of the Quagmire I-IV family.
*/

void vigenere_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len, bool variant) {
    
    int straight_alphabet_indices[ALPHABET_SIZE];
    straight_alphabet(straight_alphabet_indices, ALPHABET_SIZE);
    
    // Vigenere: variant=false, beaufort=false, straight keywords
    quagmire_decrypt(decrypted, cipher_indices, cipher_len, 
        straight_alphabet_indices, straight_alphabet_indices, 
        cycleword_indices, cycleword_len, 
        variant);
}



void vigenere_encrypt(int encrypted[], int plaintext_indices[], int cipher_len, 
    int cycleword_indices[], int cycleword_len, bool variant) {
    
    int straight_alphabet_indices[ALPHABET_SIZE];
    straight_alphabet(straight_alphabet_indices, ALPHABET_SIZE);

    // Vigenere: variant=false, beaufort=false, straight keywords
    quagmire_encrypt(encrypted, plaintext_indices, cipher_len, 
        straight_alphabet_indices, straight_alphabet_indices, 
        cycleword_indices, cycleword_len, 
        variant);
}