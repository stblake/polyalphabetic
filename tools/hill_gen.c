// Hill cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, builds a k x k key
// matrix from a keyword (retrying a deterministic tweak until the matrix is invertible
// mod 26), pads the plaintext up to a multiple of k with X, and enciphers. It links the
// REAL cipher code (hill.c + utils.c), so the generator and the solver can never drift.
//
//   make hill_gen
//   ./hill_gen plaintext.txt KEYWORD 3 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword> <k>
// stdout: the Hill ciphertext (one line, bare A..Z over the 26-letter alphabet)
// stderr: the padded plaintext (the solution: bare A..Z, what the solver recovers
//         character-for-character)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> <k>\n", argv[0]);
        return 1;
    }
    const char *keyword = argv[2];
    int k = atoi(argv[3]);
    if (k < 1 || k > HILL_MAX_K) {
        fprintf(stderr, "k must be in [1..%d]\n", HILL_MAX_K);
        return 1;
    }

    init_alphabet(NULL);                          // full 26-letter alphabet
    if (g_alpha != ALPHABET_SIZE) {
        fprintf(stderr, "alphabet is %d letters, need 26\n", g_alpha);
        return 1;
    }

    // Read the plaintext (first line of the file, or stdin), to alphabet indices.
    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static int raw[MAXLEN];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        int c = toupper(ch);
        if (c >= 'A' && c <= 'Z' && n < MAXLEN) raw[n++] = g_char_to_idx[c];
    }
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }

    // Pad up to a whole number of k-blocks with X (Hill enciphers complete blocks).
    int xidx = g_char_to_idx['X'];
    while (n % k != 0 && n < MAXLEN) raw[n++] = xidx;

    // Keyword to indices (non-letters dropped).
    static int kw[256];
    int kwn = 0;
    for (int i = 0; keyword[i] && kwn < 256; i++) {
        int c = toupper((unsigned char) keyword[i]);
        if (c >= 'A' && c <= 'Z') kw[kwn++] = g_char_to_idx[c];
    }
    if (kwn == 0) { fprintf(stderr, "keyword has no letters\n"); return 1; }

    // Derive an invertible-mod-26 key from the keyword: build the base matrix, then offset
    // its entries by a base-26 odometer indexed by `attempt` until hill_mat_inverse
    // confirms invertibility. attempt 0 is the untweaked keyword matrix (an already-
    // invertible keyword is used verbatim); successive attempts walk distinct matrices, so
    // an invertible one is reached in a handful of steps (~1/3 of matrices are invertible).
    int km = k * k;
    int mat[HILL_MAX_KEY], inv[HILL_MAX_KEY];
    int found = 0;
    for (int attempt = 0; attempt < 1000000 && !found; attempt++) {
        hill_matrix_from_keyword(kw, kwn, mat, k);
        for (int a = attempt, i = 0; a > 0 && i < km; a /= ALPHABET_SIZE, i++)
            mat[i] = (mat[i] + a % ALPHABET_SIZE) % ALPHABET_SIZE;
        found = hill_mat_inverse(mat, k, inv);
    }
    if (!found) { fprintf(stderr, "could not derive an invertible key for k=%d\n", k); return 1; }

    static int cipher[MAXLEN];
    hill_encrypt(raw, n, mat, k, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
