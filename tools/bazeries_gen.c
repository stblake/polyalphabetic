// Bazeries cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z (folding J->I), and
// enciphers it with a Bazeries cipher under a key number N < 1,000,000. It links the REAL
// cipher code (bazeries.c + bifid.c + utils.c), so the generator and the solver can never
// drift in convention.
//
//   make bazeries_gen
//   ./bazeries_gen plaintext.txt 3752     >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <number>
//   The number is spelled out to key the ciphertext square and its digits drive the
//   digit-grouped reversal transposition.
// stdout: the ciphertext (one line, bare A..Z over the 25-letter J->I alphabet).
// stderr: the plaintext solution (bare A..Z, J->I, what the solver recovers).

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"
#include "bazeries.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <plaintext|-> <number>\n", argv[0]);
        return 1;
    }
    long key = atol(argv[2]);
    if (key < 1 || key > BAZERIES_MAX_KEY) {
        fprintf(stderr, "number must be in 1..%ld\n", BAZERIES_MAX_KEY);
        return 1;
    }

    init_alphabet("J");                           // 25-letter J->I alphabet (as the binary forces)
    if (g_alpha != BAZERIES_GRID) {
        fprintf(stderr, "alphabet is %d letters, need %d\n", g_alpha, BAZERIES_GRID);
        return 1;
    }

    // Read the plaintext (first line of the file, or stdin) to alphabet indices, folding J->I.
    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static int raw[MAXLEN];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        int c = toupper(ch);
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z' && n < MAXLEN) {
            int idx = g_char_to_idx[c];
            if (idx >= 0) raw[n++] = idx;
        }
    }
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }

    static int cipher[MAXLEN];
    bazeries_encrypt(raw, n, key, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');
    fprintf(stderr, "[bazeries: number=%ld]\n", key);
    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
