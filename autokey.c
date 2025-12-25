//
// Autokey Cipher
//

#include "polyalphabetic.h"

void autokey_decrypt(int decrypted[], int cipher_indices[], int cipher_len, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int primer_indices[], int primer_len) {
    
    // Buffer for the running key (starts with primer, then appends plaintext)
    int key_stream[MAX_CIPHER_LENGTH + MAX_KEYWORD_LEN];
    int key_stream_len = primer_len;
    int i, j;
    
    // Initialize key stream with the primer
    for (i = 0; i < primer_len; i++) {
        key_stream[i] = primer_indices[i];
    }

    int posn_keyword, posn_key_char, indx, ct_indx, k_char;

    for (i = 0; i < cipher_len; i++) {
        // Find position of Ciphertext char (C) in Ciphertext Keyword
        // (Same as Quagmire logic)
        posn_keyword = -1;
        for (j = 0; j < ALPHABET_SIZE; j++) {
            ct_indx = ciphertext_keyword_indices[j];
            if (cipher_indices[i] == ct_indx) {
                posn_keyword = j; 
                break;
            }
        }

        // Get the current Key Character (K) from the stream
        k_char = key_stream[i];

        // Find position of Key Character (K) in Ciphertext Keyword
        // (Consistent with Quagmire decrypt logic provided)
        posn_key_char = -1;
        for (j = 0; j < ALPHABET_SIZE; j++) {
            if (k_char == ciphertext_keyword_indices[j]) {
                posn_key_char = j; 
                break;
            }
        }

        // Safety check for incomplete alphabets
        if (posn_keyword == -1 || posn_key_char == -1) {
             decrypted[i] = 0; // Fallback
             continue;
        }

        // Perform Quagmire Decryption Math
        // P_index = (Pos_C - Pos_K) mod 26
        indx = (posn_keyword - posn_key_char) % ALPHABET_SIZE;
        if (indx < 0) indx += ALPHABET_SIZE;

        // Map index back to Plaintext Character
        int p_val = plaintext_keyword_indices[indx];
        decrypted[i] = p_val;

        // Append Plaintext to Key Stream (Autokey behavior)
        key_stream[key_stream_len++] = p_val;
    }
}

