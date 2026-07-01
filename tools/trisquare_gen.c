// Tri-Square cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, merges J into I (the
// 25-letter convention), pads a final lone letter with X so the length is even, builds the
// three keyed squares from three keywords, and enciphers -- each plaintext digraph becomes a
// ciphertext TRIGRAPH (the two polyphonic letters chosen at random under a FIXED RNG seed, so a
// given invocation is reproducible), so the ciphertext is 3/2 the plaintext length. It links
// the REAL cipher code (trisquare.c + bifid.c's build-inverse + playfair.c's
// keyword build + utils.c), so the generator and the solver can never drift.
//
//   make trisquare_gen
//   ./trisquare_gen plaintext.txt KEYONE KEYTWO KEYTHREE >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword1> <keyword2> <keyword3> [omit=J]
// stdout: the Tri-Square ciphertext (one line, bare A..Z over the 25-letter alphabet)
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
    if (argc < 5) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword1> <keyword2> <keyword3> [omit=J]\n", argv[0]);
        return 1;
    }
    const char *k1s = argv[2], *k2s = argv[3], *k3s = argv[4];
    char omit = (argc > 5 && argv[5][0]) ? (char) toupper((unsigned char) argv[5][0]) : 'J';

    seed_rand(1u);                               // fixed seed -> reproducible polyphonic choices

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
    int sq1[SQUARE_GRID], sq2[SQUARE_GRID], sq3[SQUARE_GRID];
    kwn = 0;
    for (int i = 0; k1s[i] && kwn < 256; i++) { int x = letter_to_index((unsigned char) k1s[i], omit); if (x >= 0) kw[kwn++] = x; }
    playfair_grid_from_keyword(kw, kwn, sq1);
    kwn = 0;
    for (int i = 0; k2s[i] && kwn < 256; i++) { int x = letter_to_index((unsigned char) k2s[i], omit); if (x >= 0) kw[kwn++] = x; }
    playfair_grid_from_keyword(kw, kwn, sq2);
    kwn = 0;
    for (int i = 0; k3s[i] && kwn < 256; i++) { int x = letter_to_index((unsigned char) k3s[i], omit); if (x >= 0) kw[kwn++] = x; }
    playfair_grid_from_keyword(kw, kwn, sq3);

    static int cipher[MAXLEN + 1];
    int clen = trisquare_encrypt(raw, n, sq1, sq2, sq3, SQUARE_SIDE, cipher);

    for (int i = 0; i < clen; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');
    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
