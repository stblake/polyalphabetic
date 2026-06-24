// Two-Square cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, merges J into I (the
// ACA 25-letter convention), pads a final lone letter with X so the length is even, builds
// the two 5x5 squares from two keywords, and enciphers. It links the REAL cipher code
// (twosquare.c + playfair.c's keyword build + utils.c), so the generator and the solver
// can never drift in convention.
//
//   make twosquare_gen
//   ./twosquare_gen plaintext.txt KEYONE KEYTWO >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword1> <keyword2> [variant=h|v] [omit=J]
//   variant: h (horizontal, ACA -- default) or v (vertical, self-inverse)
// stdout: the Two-Square ciphertext (one line, bare A..Z over the 25-letter alphabet)
// stderr: the (padded) plaintext (the solution the solver recovers char-for-char)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

static int letter_to_index(int c, char omit) {
    c = toupper(c);
    if (c == toupper((unsigned char) omit)) c = (toupper((unsigned char) omit) == 'J') ? 'I' : 0;
    if (c < 'A' || c > 'Z') return -1;
    return g_char_to_idx[c];
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword1> <keyword2> [variant=h|v] [omit=J]\n", argv[0]);
        return 1;
    }
    const char *kw1s = argv[2], *kw2s = argv[3];
    int variant = (argc > 4 && (argv[4][0] == 'v' || argv[4][0] == 'V'))
                  ? TWO_SQ_VERTICAL : TWO_SQ_HORIZONTAL;
    char omit = (argc > 5 && argv[5][0]) ? (char) toupper((unsigned char) argv[5][0]) : 'J';

    char omit_str[2] = { omit, '\0' };
    init_alphabet(omit_str);                     // 25-letter alphabet, base-25 indices
    if (g_alpha != SQUARE_GRID) {
        fprintf(stderr, "alphabet is %d letters, need %d (one excluded)\n", g_alpha, SQUARE_GRID);
        return 1;
    }

    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static int raw[MAXLEN + 1];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        int idx = letter_to_index(ch, omit);
        if (idx >= 0 && n < MAXLEN) raw[n++] = idx;
    }
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }
    if (n % 2 != 0) raw[n++] = letter_to_index('X', omit);   // pad to an even length

    int kw[256], kwn;
    int sq1[SQUARE_GRID], sq2[SQUARE_GRID];
    kwn = 0;
    for (int i = 0; kw1s[i] && kwn < 256; i++) { int x = letter_to_index((unsigned char) kw1s[i], omit); if (x >= 0) kw[kwn++] = x; }
    playfair_grid_from_keyword(kw, kwn, sq1);
    kwn = 0;
    for (int i = 0; kw2s[i] && kwn < 256; i++) { int x = letter_to_index((unsigned char) kw2s[i], omit); if (x >= 0) kw[kwn++] = x; }
    playfair_grid_from_keyword(kw, kwn, sq2);

    static int cipher[MAXLEN + 1];
    twosquare_encrypt(raw, n, sq1, sq2, SQUARE_SIDE, variant, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');
    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
