//
// Autokey Cipher
//

#include "colossus.h"

// Plaintext autokey encryption -- the exact inverse of autokey_decrypt below.
// The key stream is the primer followed by the plaintext itself; character i is
// enciphered against key_stream[i]. Tableau conventions (and therefore the
// standard/variant sign) mirror autokey_decrypt one-for-one, so
// autokey_decrypt(autokey_encrypt(P)) == P for every supported type.
void autokey_encrypt(ColossusConfig *cfg, int ciphertext[], int plaintext_indices[], int plaintext_len,
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[],
    int primer_indices[], int primer_len) {

    int key_stream[MAX_CIPHER_LENGTH + MAX_KEYWORD_LEN];
    int i;

    // Invert both keyed alphabets once: the message char comes from the PT
    // alphabet, the key char from the CT alphabet. Replaces two per-character
    // linear 26-scans with O(1) lookups.
    int pt_inverse[ALPHABET_SIZE], ct_inverse[ALPHABET_SIZE];
    for (i = 0; i < ALPHABET_SIZE; i++) {
        pt_inverse[plaintext_keyword_indices[i]] = i;
        ct_inverse[ciphertext_keyword_indices[i]] = i;
    }

    // Key stream = primer, then the plaintext (autokey feedback).
    for (i = 0; i < primer_len; i++) key_stream[i] = primer_indices[i];
    for (i = 0; i < plaintext_len; i++) key_stream[primer_len + i] = plaintext_indices[i];

    for (i = 0; i < plaintext_len; i++) {
        int p_char = plaintext_indices[i];
        int k_char = key_stream[i];
        int c_val;

        if (cfg->cipher_type == AUTOKEY_BEAU) {
            // Beaufort Autokey (Reciprocal): C = K - P (mod 26)
            c_val = (k_char - p_char + ALPHABET_SIZE) % ALPHABET_SIZE;
        }
        else if (cfg->cipher_type == AUTOKEY_PORTA) {
            // Porta Autokey (Reciprocal)
            int shift = k_char / 2;
            if (p_char < 13) {
                c_val = (p_char + shift) % 13 + 13;
            } else {
                c_val = (p_char - 13 - shift + ALPHABET_SIZE) % 13;
            }
        }
        else {
            // Quagmire/Vigenere Autokey.
            int p_idx = pt_inverse[p_char];
            int k_idx = ct_inverse[k_char];

            int indx;
            if (cfg->variant) {
                // Variant: C = P - K (mod 26)
                indx = (p_idx - k_idx + ALPHABET_SIZE) % ALPHABET_SIZE;
            } else {
                // Standard: C = P + K (mod 26)
                indx = (p_idx + k_idx) % ALPHABET_SIZE;
            }

            c_val = ciphertext_keyword_indices[indx];
        }

        ciphertext[i] = c_val;
    }
}

void autokey_decrypt(ColossusConfig *cfg, int decrypted[], int cipher_indices[], int cipher_len,
    int plaintext_keyword_indices[], int ciphertext_keyword_indices[], 
    int primer_indices[], int primer_len) {
    
    int key_stream[MAX_CIPHER_LENGTH + MAX_KEYWORD_LEN];
    int key_stream_len = primer_len;
    int i;

    // Invert the CT keyed alphabet once: ct_inverse[char] = its position. Both the
    // ciphertext char and the key char are looked up in the CT alphabet, so this
    // replaces the two per-character linear 26-scans with O(1) lookups. (Mirrors
    // the optimization already in quagmire_decrypt; this is the autokey hot path.)
    int ct_inverse[ALPHABET_SIZE];
    for (i = 0; i < ALPHABET_SIZE; i++) ct_inverse[ciphertext_keyword_indices[i]] = i;

    // Initialise key stream with the primer.
    for (i = 0; i < primer_len; i++) {
        key_stream[i] = primer_indices[i];
    }

    for (i = 0; i < cipher_len; i++) {
        int ct_char = cipher_indices[i];
        int k_char = key_stream[i];
        int p_val;

        if (cfg->cipher_type == AUTOKEY_BEAU) { 
            // Beaufort Autokey (Reciprocal): P = K - C (mod 26)
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
            int posn_keyword = ct_inverse[ct_char];
            int posn_key_char = ct_inverse[k_char];

            int indx;
            if (cfg->variant) {
                // Variant: P = C + K (mod 26)
                indx = (posn_keyword + posn_key_char) % ALPHABET_SIZE;
            } else {
                // Standard: P = C - K (mod 26)
                indx = (posn_keyword - posn_key_char) % ALPHABET_SIZE;
            }
            
            if (indx < 0) indx += ALPHABET_SIZE;
            p_val = plaintext_keyword_indices[indx];
        }

        decrypted[i] = p_val;
        key_stream[key_stream_len++] = p_val; // Extend stream with plaintext
    }
}