// Gronsfeld cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, and enciphers it
// with a numeric Gronsfeld key (a string of digits 0..9). It links the REAL cipher
// code (gronsfeld.c + utils.c), so the generator and the solver can never drift.
//
//   make gronsfeld_gen
//   ./gronsfeld_gen plaintext.txt 31415 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <numeric-key>
// stdout: the Gronsfeld ciphertext (one line, bare A..Z over the 26-letter alphabet)
// stderr: the plaintext (the solution: bare A..Z, what the solver recovers
//         character-for-character)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "../colossus.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <plaintext|-> <numeric-key e.g. 31415>\n", argv[0]);
        return 1;
    }
    const char *keystr = argv[2];

    init_alphabet(NULL);                          // full 26-letter alphabet
    if (g_alpha != ALPHABET_SIZE) {
        fprintf(stderr, "alphabet is %d letters, need 26\n", g_alpha);
        return 1;
    }

    // Parse the numeric key into per-column shift digits 0..9.
    static int key[256];
    int keylen = 0;
    for (int i = 0; keystr[i] && keylen < 256; i++) {
        if (keystr[i] >= '0' && keystr[i] <= '9') key[keylen++] = keystr[i] - '0';
    }
    if (keylen == 0) { fprintf(stderr, "key has no digits\n"); return 1; }

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

    static int cipher[MAXLEN];
    gronsfeld_encrypt(cipher, raw, n, key, keylen);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
