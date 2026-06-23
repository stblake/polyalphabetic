//
//  Hill cipher primitives (polygraphic substitution by a k x k matrix multiply mod 26).
//
//  A block of k plaintext letters (a column vector p) is enciphered c = K p mod 26 with
//  the k x k key matrix K (row-major in mat[]); deciphering is p = K^-1 c mod 26, which
//  exists iff gcd(det K, 26) == 1 (i.e. det K is coprime to both 2 and 13). The mod base
//  is ALPHABET_SIZE (26): Hill needs the full 26-letter alphabet, so -type hill leaves
//  g_alpha at the 26-letter default rather than forcing a reduced alphabet.
//
//  The solver hill-climbs the DECRYPTION matrix directly (it applies the state matrix
//  straight to the ciphertext), so the one hot-path primitive is hill_mat_mul_blocks();
//  hill_encrypt / hill_decrypt, the determinant / modular-inverse / matrix-inverse and
//  the keyword build serve the test-data generator, the unit tests, and the solver's
//  report hook (which inverts the recovered decryption matrix to show the encryption
//  key). A trailing partial block (len % k letters) is copied through unchanged -- real
//  Hill ciphertext is a whole number of k-blocks, but the solver may try a k that does
//  not divide the ciphertext length, and that tail must not corrupt the rest.
//

#include "colossus.h"

// out[block] = mat (k x k, row-major) * in[block] (length-k column vector) mod 26, for
// every complete block; a short final block (len % k) is copied through unchanged.
void hill_mat_mul_blocks(const int mat[], int k, const int in[], int len, int out[]) {
    int nblocks = len / k;
    for (int b = 0; b < nblocks; b++) {
        const int *v = in + b * k;
        int *o = out + b * k;
        for (int r = 0; r < k; r++) {
            const int *row = mat + r * k;
            int acc = 0;
            for (int c = 0; c < k; c++) acc += row[c] * v[c];
            o[r] = ((acc % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
        }
    }
    for (int i = nblocks * k; i < len; i++) out[i] = in[i];
}

// Encipher plaintext (any length) under the k x k key matrix, block by block.
void hill_encrypt(const int plain[], int len, const int key[], int k, int out[]) {
    hill_mat_mul_blocks(key, k, plain, len, out);
}

// Decipher ciphertext under the k x k key by applying its inverse mod 26. If the key is
// singular mod 26 it cannot be a real Hill key; the ciphertext is copied through (callers
// -- the generator and the round-trip tests -- only ever pass invertible keys).
void hill_decrypt(const int cipher[], int len, const int key[], int k, int out[]) {
    int inv[HILL_MAX_KEY];
    if (!hill_mat_inverse(key, k, inv)) {
        for (int i = 0; i < len; i++) out[i] = cipher[i];
        return;
    }
    hill_mat_mul_blocks(inv, k, cipher, len, out);
}

// Modular inverse of a mod m via the extended Euclidean algorithm. Returns the inverse in
// [1, m-1], or 0 if gcd(a, m) != 1 (no inverse). Mod 26 the 12 units are
// 1,3,5,7,9,11,15,17,19,21,23,25.
int hill_mod_inverse(int a, int m) {
    a = ((a % m) + m) % m;
    int old_r = a, r = m;
    int old_s = 1, s = 0;
    while (r != 0) {
        int q = old_r / r;
        int t = old_r - q * r; old_r = r; r = t;
        t = old_s - q * s; old_s = s; s = t;
    }
    if (old_r != 1) return 0;                 // gcd(a, m) != 1 -> not invertible
    return ((old_s % m) + m) % m;
}

// Determinant of a k x k matrix (row-major) reduced mod 26, in [0, 25]. Cofactor
// expansion along the first row; k <= HILL_MAX_K so the O(k!) cost is negligible. Each
// recursive sub-determinant is already reduced, so intermediate values stay small.
int hill_det_mod(const int mat[], int k) {
    if (k == 1) return ((mat[0] % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
    if (k == 2) {
        int d = mat[0] * mat[3] - mat[1] * mat[2];
        return ((d % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
    }
    int det = 0;
    int minor[HILL_MAX_KEY];                  // own buffer per recursion frame
    for (int col = 0; col < k; col++) {
        int mi = 0;                           // minor: drop row 0 and column `col`
        for (int rr = 1; rr < k; rr++)
            for (int c = 0; c < k; c++)
                if (c != col) minor[mi++] = mat[rr * k + c];
        int sub = hill_det_mod(minor, k - 1);
        int term = mat[col] * sub;
        if (col & 1) term = -term;
        det += term;
    }
    return ((det % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
}

// Inverse of a k x k matrix mod 26: out = det^-1 * adj(mat) mod 26, where the adjugate is
// the transpose of the cofactor matrix. Returns 1 and fills out[] when invertible
// (gcd(det, 26) == 1), else 0 (and leaves out[] untouched).
int hill_mat_inverse(const int mat[], int k, int out[]) {
    int det = hill_det_mod(mat, k);
    int dinv = hill_mod_inverse(det, ALPHABET_SIZE);
    if (dinv == 0) return 0;                  // singular mod 26
    if (k == 1) { out[0] = dinv % ALPHABET_SIZE; return 1; }
    int minor[HILL_MAX_KEY];
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++) {
            int mi = 0;                       // minor: drop row i and column j
            for (int rr = 0; rr < k; rr++) {
                if (rr == i) continue;
                for (int c = 0; c < k; c++) {
                    if (c == j) continue;
                    minor[mi++] = mat[rr * k + c];
                }
            }
            int cof = hill_det_mod(minor, k - 1);
            if ((i + j) & 1) cof = (ALPHABET_SIZE - cof) % ALPHABET_SIZE;
            // adjugate transposes the cofactor matrix: out[j][i] = det^-1 * C_ij
            out[j * k + i] = (cof * dinv) % ALPHABET_SIZE;
        }
    }
    return 1;
}

// Fill a k x k matrix (row-major) from keyword letter indices, cycling the keyword if it
// is shorter than k*k. No invertibility guarantee -- the generator retries with a
// deterministic tweak until hill_mat_inverse confirms the key is invertible mod 26.
void hill_matrix_from_keyword(const int keyword[], int kwlen, int mat[], int k) {
    int n = k * k;
    if (kwlen <= 0) { for (int i = 0; i < n; i++) mat[i] = 0; return; }
    for (int i = 0; i < n; i++) mat[i] = ((keyword[i % kwlen] % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
}
