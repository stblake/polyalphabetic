// Bifid cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, merges J into I
// (the ACA 25-letter convention), builds the 5x5 square from a keyword, and enciphers
// with the given period. It links the REAL cipher code (bifid.c + utils.c), so the
// generator and the solver can never drift in convention.
//
//   make bifid_gen
//   ./bifid_gen plaintext.txt KEYWORD 7 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword> <period> [omit-letter=J]
// stdout: the Bifid ciphertext (one line, bare A..Z over the 25-letter alphabet)
// stderr: the cleaned plaintext (the solution: bare A..Z, J->I, what the solver
//         recovers character-for-character)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

// Map an uppercase letter to its alphabet index, merging the omitted letter (J by
// default, -> I). Returns -1 for anything not in the active 25-letter alphabet.
static int letter_to_index(int c, char omit) {
    c = toupper(c);
    if (c == toupper((unsigned char) omit)) c = (toupper((unsigned char) omit) == 'J') ? 'I' : 0;
    if (c < 'A' || c > 'Z') return -1;
    return g_char_to_idx[c];
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> <period> [omit=J]\n", argv[0]);
        return 1;
    }
    const char *keyword = argv[2];
    int period = atoi(argv[3]);
    char omit = (argc > 4 && argv[4][0]) ? (char) toupper((unsigned char) argv[4][0]) : 'J';
    if (period < 1) { fprintf(stderr, "period must be >= 1\n"); return 1; }

    char omit_str[2] = { omit, '\0' };
    init_alphabet(omit_str);                     // 25-letter alphabet, base-25 indices
    if (g_alpha != PLAYFAIR_GRID) {
        fprintf(stderr, "alphabet is %d letters, need %d (one excluded)\n", g_alpha, PLAYFAIR_GRID);
        return 1;
    }
    int side = 5;

    // Read the plaintext (first line of the file, or stdin), to alphabet indices.
    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static int raw[MAXLEN];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        int idx = letter_to_index(ch, omit);
        if (idx >= 0 && n < MAXLEN) raw[n++] = idx;
    }
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }

    // Keyword to indices (non-letters dropped).
    static int kw[256];
    int kwn = 0;
    for (int i = 0; keyword[i] && kwn < 256; i++) {
        int idx = letter_to_index((unsigned char) keyword[i], omit);
        if (idx >= 0) kw[kwn++] = idx;
    }

    int grid[PLAYFAIR_GRID];
    bifid_grid_from_keyword(kw, kwn, grid, g_alpha);

    static int cipher[MAXLEN];
    bifid_encrypt(raw, n, grid, side, period, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
