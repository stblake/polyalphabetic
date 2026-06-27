//
// Progressive Key Cipher
//

#include "colossus.h"

/*
   Progressive Key Cipher Logic
   ============================

   The ACA Progressive Key cipher is a PERIODIC polyalphabetic cipher whose key
   DRIFTS by a constant amount every period. The plaintext is written in groups of
   P letters (P = keyword length). Two encipherments of the SAME base type T are
   applied:

     1. PRIMARY  : an ordinary periodic encipherment under the keyword,
                       C1[i] = E_T(pt[i], keyword[i mod P]).
     2. PROGRESS : a second encipherment, constant per group g = i / P, using the
                   progressive key letter Kp[g] = (g * prog) mod 26,
                       C[i]  = E_T(C1[i], (g * prog) mod 26).

   `prog` is the progression index (1 -> A,B,C,...; 2 -> A,C,E,...; 0 = no drift,
   a plain periodic cipher for the Vigenere/Variant bases -- but note the Beaufort
   group-0 pass E(c1, 0) = -c1 is a reflection, not identity). E_T / D_T is one of
   three base types:

     * Vigenere (PROGKEY)      E(p,k) = (p + k),  D(c,k) = (c - k)
     * Variant  (PROGKEY_VAR)  E(p,k) = (p - k),  D(c,k) = (c + k)
     * Beaufort (PROGKEY_BEAU) E(p,k) = (k - p),  D(c,k) = (k - c)   (self-reciprocal)

   all mod 26 (progkey_base_encrypt / progkey_base_decrypt in colossus.h).

   Hand-verified against the ACA worked example (Vigenere, key GRAPEFRUIT, P=10,
   prog=1): "thiscipher..." -> "ZYIHGNGBMK JSORJAKZMQ QMJRTFHBDC ..." -- group 0
   adds A(0), group 1 adds B(1), group 2 adds C(2) on top of the primary Vigenere.

   Decryption undoes the progressive pass then the primary:
       C1[i] = D_T(C[i], (g * prog) mod 26)
       pt[i] = D_T(C1[i], keyword[i mod P]).

   The solver attacks the cipher by DE-PROGRESSING (undoing only the progressive
   pass, progkey_deprogress) for a candidate `prog`, which leaves a pure periodic
   base cipher C1 whose per-column shift is keyword[col] alone -- so each column is
   recovered independently by a monogram fit (see progkey_solver.c).

   The primitives operate directly on the integer-index text arrays; the keyword
   shifts (0..25) live in the cycleword lane for the solver, so the keyword IS the
   recovered per-column shift sequence.
*/

void progkey_encrypt(int encrypted[], int plaintext_indices[], int plaintext_len,
    int keyword[], int P, int prog, int base) {

    for (int i = 0; i < plaintext_len; i++) {
        int g = i / P;                                  // group index
        int kp = (g * prog) % ALPHABET_SIZE;            // progressive key letter for this group
        int c1 = progkey_base_encrypt(plaintext_indices[i], keyword[i % P], base);
        encrypted[i] = progkey_base_encrypt(c1, kp, base);
    }
}

void progkey_decrypt(int decrypted[], int cipher_indices[], int cipher_len,
    int keyword[], int P, int prog, int base) {

    for (int i = 0; i < cipher_len; i++) {
        int g = i / P;
        int kp = (g * prog) % ALPHABET_SIZE;
        int c1 = progkey_base_decrypt(cipher_indices[i], kp, base);   // undo progressive pass
        decrypted[i] = progkey_base_decrypt(c1, keyword[i % P], base); // undo primary pass
    }
}

// Undo only the progressive (drift) pass, leaving the primary base ciphertext C1
// (a pure periodic Vig/Var/Beau cipher under the keyword). Used by the solver to
// decouple the keyword search from the progression index for a candidate `prog`.
void progkey_deprogress(int out[], int cipher_indices[], int cipher_len,
    int P, int prog, int base) {

    for (int i = 0; i < cipher_len; i++) {
        int g = i / P;
        int kp = (g * prog) % ALPHABET_SIZE;
        out[i] = progkey_base_decrypt(cipher_indices[i], kp, base);
    }
}
