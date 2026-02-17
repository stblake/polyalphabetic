//
// Autokey Cipher
//

#include "polyalphabetic.h"


void autokey_decrypt(PolyalphabeticConfig *cfg, int decrypted[], int cipher_indices[], int cipher_len, 
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int primer_indices[], int primer_len) {
    
    int key_stream[MAX_CIPHER_LENGTH + MAX_KEYWORD_LEN];
    int key_stream_len = primer_len;
    int i, j;
    
    // Initialise key stream with the primer.
    for (i = 0; i < primer_len; i++) {
        key_stream[i] = primer_indices[i];
    }

    for (i = 0; i < cipher_len; i++) {
        int ct_char = cipher_indices[i];
        int k_char = key_stream[i];
        int p_val;

        if (cfg->cipher_type == AUTOKEY_BEAU) { 
            // Beaufort Autokey: P = K - C (mod 26)
            p_val = (k_char - ct_char + ALPHABET_SIZE) % ALPHABET_SIZE;
        } 
        else if (cfg->cipher_type == AUTOKEY_PORTA) { 
            // Porta Autokey (Reciprocal)
            int shift = k_char / 2;
            if (ct_char < 13) {
                p_val = (ct_char + shift) % 13 + 13;
            } else {
                p_val = (ct_char - 13 - shift + ALPHABET_SIZE) % 13;
            }
        } 
        else {
            // Quagmire/Vigenere Autokey.
            int posn_keyword = -1;
            for (j = 0; j < ALPHABET_SIZE; j++) {
                if (ct_char == ciphertext_keyword_indices[j]) {
                    posn_keyword = j; 
                    break;
                }
            }

            int posn_key_char = -1;
            for (j = 0; j < ALPHABET_SIZE; j++) {
                if (k_char == ciphertext_keyword_indices[j]) {
                    posn_key_char = j; 
                    break;
                }
            }

            int indx = (posn_keyword - posn_key_char) % ALPHABET_SIZE;
            if (indx < 0) indx += ALPHABET_SIZE;
            p_val = plaintext_keyword_indices[indx];
        }

        decrypted[i] = p_val;
        key_stream[key_stream_len++] = p_val; // Extend stream with plaintext
    }
}

