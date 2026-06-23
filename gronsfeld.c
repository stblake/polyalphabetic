//
// Gronsfeld Cipher
//

#include "colossus.h"

/*
   Gronsfeld Cipher Logic

   The Gronsfeld cipher is the polyalphabetic substitution cipher you get by
   running a Vigenère cipher with a *numeric* key: instead of a letter keyword,
   the key is a sequence of digits 0..9, and digit d shifts a column by d. It uses
   straight A-Z alphabets for both plaintext and ciphertext, so it is exactly the
   Vigenère cipher restricted to the 10 smallest shifts.

   Let P be the plaintext character index (0-25),
   C be the ciphertext character index (0-25),
   and K be the key digit (0-9) for the column, drawn from the repeating key.

   Encryption:   C = (P + K) mod 26
   Decryption:   P = (C - K) mod 26

   The primitives operate directly on the integer-index text arrays and the
   integer key-digit array (no straight-alphabet build / Quagmire indirection),
   which keeps them tight for the solver hot loop. The solver carries the per-
   column shifts in the cycleword lane, so the key digits ARE the cycleword.
*/

void gronsfeld_decrypt(int decrypted[], int cipher_indices[], int cipher_len,
    int key_digits[], int key_len) {

    for (int i = 0; i < cipher_len; i++) {
        int k = key_digits[i % key_len];
        decrypted[i] = (cipher_indices[i] - k + ALPHABET_SIZE) % ALPHABET_SIZE;
    }
}


void gronsfeld_encrypt(int encrypted[], int plaintext_indices[], int plaintext_len,
    int key_digits[], int key_len) {

    for (int i = 0; i < plaintext_len; i++) {
        int k = key_digits[i % key_len];
        encrypted[i] = (plaintext_indices[i] + k) % ALPHABET_SIZE;
    }
}
