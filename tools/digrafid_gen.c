// Digrafid cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, builds the two keyed
// 27-symbol grids (A..Z + '#') -- the horizontal 3x9 from keyword_H (row-major) and the
// vertical 9x3 from keyword_V (column-major) -- pads an odd length with a trailing 'X',
// and enciphers with the given period. It links the REAL cipher code (digrafid.c + bifid.c
// for build-inverse + utils.c), so the generator and the solver can never drift.
//
//   make digrafid_gen
//   ./digrafid_gen plaintext.txt KEYWORD VERTICAL 7 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword_H> <keyword_V> <period>
// stdout: the Digrafid ciphertext (one line, over the 27-symbol alphabet, may contain '#')
// stderr: the cleaned plaintext (the solution: bare A..Z, padded to even with 'X', what
//         the solver recovers character-for-character)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

// Keyword string -> alphabet indices (A..Z and '#' kept; everything else dropped).
static int keyword_to_idx(const char *s, int out[], int cap) {
    int n = 0;
    for (int i = 0; s[i] && n < cap; i++) {
        int c = toupper((unsigned char) s[i]);
        int idx = (c == '#') ? g_char_to_idx['#'] : ((c >= 'A' && c <= 'Z') ? g_char_to_idx[c] : -1);
        if (idx >= 0) out[n++] = idx;
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword_H> <keyword_V> <period>\n", argv[0]);
        return 1;
    }
    int period = atoi(argv[4]);
    if (period < 1) { fprintf(stderr, "period must be >= 1\n"); return 1; }

    init_alphabet_digrafid();                    // 27-symbol alphabet (A..Z + '#')
    if (g_alpha != DIGRAFID_GRID) {
        fprintf(stderr, "alphabet is %d symbols, need %d\n", g_alpha, DIGRAFID_GRID);
        return 1;
    }

    // Read the plaintext (first line of the file, or stdin), to alphabet indices. Only
    // A..Z letters are kept ('#' is a cipher symbol, not used in plaintext).
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
    if (n & 1) raw[n++] = g_char_to_idx['X'];    // pad odd length to a whole digraph

    int kw[256];
    int gridH[DIGRAFID_GRID], gridV[DIGRAFID_GRID];
    digrafid_grid_from_keyword(kw, keyword_to_idx(argv[2], kw, 256), gridH,
                               DIGRAFID_HROWS, DIGRAFID_HCOLS, 0);
    digrafid_grid_from_keyword(kw, keyword_to_idx(argv[3], kw, 256), gridV,
                               DIGRAFID_VROWS, DIGRAFID_VCOLS, 1);

    static int cipher[MAXLEN];
    digrafid_encrypt(raw, n, gridH, gridV, period, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
