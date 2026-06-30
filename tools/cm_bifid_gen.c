// CM Bifid (Conjugated Matrix Bifid) cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, merges J into I
// (the ACA 25-letter convention), builds TWO 5x5 squares from two keywords, and enciphers
// with the given period -- fractionate with square 1, recombine the coordinate pairs
// through square 2. It links the REAL cipher code (cm_bifid.c + bifid.c + utils.c), so the
// generator and the solver can never drift in convention.
//
//   make cm_bifid_gen
//   ./cm_bifid_gen plaintext.txt KEYWORD1 KEYWORD2 7 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword1> <keyword2> <period> [omit-letter=J]
// stdout: the CM Bifid ciphertext (one line, bare A..Z over the 25-letter alphabet)
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

// Build a keyed square (alphabet indices) from a keyword string, dropping non-letters.
static void square_from_keyword(const char *keyword, char omit, int grid[]) {
    int kw[256];
    int kwn = 0;
    for (int i = 0; keyword[i] && kwn < 256; i++) {
        int idx = letter_to_index((unsigned char) keyword[i], omit);
        if (idx >= 0) kw[kwn++] = idx;
    }
    bifid_grid_from_keyword(kw, kwn, grid, g_alpha);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword1> <keyword2> <period> [omit=J]\n", argv[0]);
        return 1;
    }
    const char *keyword1 = argv[2];
    const char *keyword2 = argv[3];
    int period = atoi(argv[4]);
    char omit = (argc > 5 && argv[5][0]) ? (char) toupper((unsigned char) argv[5][0]) : 'J';
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

    int sq1[PLAYFAIR_GRID], sq2[PLAYFAIR_GRID];
    square_from_keyword(keyword1, omit, sq1);
    square_from_keyword(keyword2, omit, sq2);

    static int cipher[MAXLEN];
    cm_bifid_encrypt(raw, n, sq1, sq2, side, period, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
