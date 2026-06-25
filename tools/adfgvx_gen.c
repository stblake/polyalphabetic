// ADFGVX / ADFGX cipher generator (test-data tool, not part of the solver).
//
// Builds a keyed Polybius square from a SQUARE keyword, fractionates the plaintext into
// coordinate labels, then columnar-transposes the coordinate stream under a TRANSPOSITION
// keyword (the columns read in the keyword's alphabetical order). Links the REAL cipher
// code (adfgvx.c + bifid.c keyed-square build/inverse + transpositions.c + utils.c) so the
// generator and the solver can never drift in convention.
//
//   make adfgvx_gen
//   ./adfgvx_gen plaintext.txt SQUAREKEY TRANSKEY adfgx  >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <square-keyword> <transposition-keyword> [variant=adfgx|adfgvx]
// stdout: the ciphertext (one line, over the label alphabet -- ADFGX or ADFGVX)
// stderr: the cleaned plaintext (the solution the solver recovers, bare symbols)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

// Map an uppercase character to its alphabet index in the active alphabet (ADFGX: 25
// letters, J->I; ADFGVX: 36 symbols A..Z + 0..9). Returns -1 for anything not present.
static int sym_to_index(int c, int side) {
    c = toupper(c);
    if (side == ADFGX_SIDE && c == 'J') c = 'I';          // 25-letter convention
    if (c >= 'A' && c <= 'Z') return g_char_to_idx[c];
    if (side == ADFGVX_SIDE && c >= '0' && c <= '9') return g_char_to_idx[c];
    return -1;
}

// Build the columnar read order from a transposition keyword: order[j] is the column read
// at position j, columns taken in the keyword's alphabetical order (ties broken left to
// right, the stable columnar convention). Returns the column count K.
static int build_order(const char *kw, int side, int order[]) {
    int idx[MAX_COLS], K = 0;
    for (int i = 0; kw[i] && K < MAX_COLS; i++) {
        int v = sym_to_index((unsigned char) kw[i], side);
        if (v >= 0) idx[K++] = v;
    }
    // Selection sort of column indices by (key letter, original position) -> read order.
    char used[MAX_COLS];
    for (int c = 0; c < K; c++) used[c] = 0;
    for (int j = 0; j < K; j++) {
        int best = -1;
        for (int c = 0; c < K; c++) {
            if (used[c]) continue;
            if (best < 0 || idx[c] < idx[best]) best = c;   // smaller letter first; ties keep earliest
        }
        used[best] = 1;
        order[j] = best;
    }
    return K;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <square-keyword> <transposition-keyword> [adfgx|adfgvx]\n", argv[0]);
        return 1;
    }
    const char *square_kw = argv[2];
    const char *trans_kw  = argv[3];
    int side = ADFGX_SIDE;
    if (argc > 4 && (strcasecmp(argv[4], "adfgvx") == 0 || strcmp(argv[4], "6") == 0)) side = ADFGVX_SIDE;

    if (side == ADFGVX_SIDE) init_alphabet_adfgvx();          // 36 symbols
    else                     init_alphabet("J");              // 25 letters
    if (g_alpha != side * side) {
        fprintf(stderr, "alphabet is %d symbols, need %d\n", g_alpha, side * side);
        return 1;
    }

    // Read the plaintext (first line of the file, or stdin) to alphabet indices.
    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static int raw[MAXLEN];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        int idx = sym_to_index(ch, side);
        if (idx >= 0 && n < MAXLEN) raw[n++] = idx;
    }
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }

    // Square keyword -> keyed square; transposition keyword -> column read order.
    static int kw[256];
    int kwn = 0;
    for (int i = 0; square_kw[i] && kwn < 256; i++) {
        int idx = sym_to_index((unsigned char) square_kw[i], side);
        if (idx >= 0) kw[kwn++] = idx;
    }
    int square[SQUARE_MAX_GRID];
    bifid_grid_from_keyword(kw, kwn, square, g_alpha);

    int order[MAX_COLS];
    int K = build_order(trans_kw, side, order);
    if (K < 2) { fprintf(stderr, "transposition keyword must have >= 2 distinct columns\n"); return 1; }

    static int cipher[2 * MAXLEN];
    adfgvx_encrypt(raw, n, square, side, K, order, COL_READ_TB, cipher);

    const char *labels = adfgvx_labels(side);
    for (int i = 0; i < 2 * n; i++) putchar(labels[cipher[i]]);
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
