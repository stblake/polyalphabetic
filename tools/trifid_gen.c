// Trifid cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, builds the 3x3x3,
// 27-symbol cube (A..Z + '+') from a keyword, and enciphers with the given period. It
// links the REAL cipher code (trifid.c + utils.c), so the generator and the solver can
// never drift in convention.
//
//   make trifid_gen
//   ./trifid_gen plaintext.txt KEYWORD 7 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword> <period>
// stdout: the Trifid ciphertext (one line, over the 27-symbol alphabet, may contain '+')
// stderr: the cleaned plaintext (the solution: bare A..Z, what the solver recovers
//         character-for-character)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> <period>\n", argv[0]);
        return 1;
    }
    const char *keyword = argv[2];
    int period = atoi(argv[3]);
    if (period < 1) { fprintf(stderr, "period must be >= 1\n"); return 1; }

    init_alphabet_trifid();                      // 27-symbol alphabet (A..Z + '+')
    if (g_alpha != TRIFID_CELLS) {
        fprintf(stderr, "alphabet is %d symbols, need %d\n", g_alpha, TRIFID_CELLS);
        return 1;
    }
    int side = TRIFID_SIDE;

    // Read the plaintext (first line of the file, or stdin), to alphabet indices. Only
    // A..Z letters are kept (the cube's '+' is a cipher symbol, not used in plaintext).
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

    // Keyword to indices (A..Z and the '+' symbol kept; everything else dropped).
    static int kw[256];
    int kwn = 0;
    for (int i = 0; keyword[i] && kwn < 256; i++) {
        int c = toupper((unsigned char) keyword[i]);
        int idx = (c < 128) ? g_char_to_idx[c] : -1;
        if (idx >= 0) kw[kwn++] = idx;
    }

    int cube[TRIFID_CELLS];
    trifid_cube_from_keyword(kw, kwn, cube, g_alpha);

    static int cipher[MAXLEN];
    trifid_encrypt(raw, n, cube, side, period, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
