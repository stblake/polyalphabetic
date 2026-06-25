// Nihilist Substitution cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, merges J into I (the ACA
// 25-letter convention), builds the 5x5 square from a keyword, derives the periodic additive
// key from a second keyword (its letters' coordinates), and enciphers under one of the three
// addition conventions. Optional keyed row/column labels exercise the keyed-label variant. It
// links the REAL cipher code (nihilist_sub.c + bifid.c + utils.c), so the generator and the
// solver can never drift in convention.
//
//   make nihilist_sub_gen
//   ./tools/nihilist_sub_gen plaintext.txt KRYPTOS BERLIN carry >cipher.txt 2>solution.txt
//   ./tools/nihilist_sub_gen - KRYPTOS BERLIN nc -labels 31452 25134 >c.txt 2>sol.txt
//
// argv: <plaintext|-> <square-keyword> <additive-keyword> [carry|nc|m100] [-labels <row> <col>]
// stdout: the ciphertext (one line, space-separated decimal numbers)
// stderr: the cleaned plaintext (the solution: bare A..Z, J->I -- what the solver recovers)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

// Map an uppercase letter to its 25-letter (J->I) alphabet index; -1 otherwise.
static int letter_to_index(int c) {
    c = toupper(c);
    if (c == 'J') c = 'I';
    if (c < 'A' || c > 'Z') return -1;
    return g_char_to_idx[c];
}

// Parse a digit string (e.g. "31452") into a label array of `side` digits (a permutation of
// 1..side). Returns 1 on success.
static int parse_labels(const char *s, int side, int lbl[]) {
    int n = 0;
    for (int i = 0; s[i] && n < side; i++)
        if (s[i] >= '1' && s[i] <= '0' + side) lbl[n++] = s[i] - '0';
    if (n != side) return 0;
    int seen[16] = {0};
    for (int i = 0; i < side; i++) { if (seen[lbl[i]]) return 0; seen[lbl[i]] = 1; }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <square-keyword> <additive-keyword> "
                        "[carry|nc|m100] [-labels <row> <col>]\n", argv[0]);
        return 1;
    }
    const char *square_kw = argv[2];
    const char *add_kw     = argv[3];
    int conv = NIH_ADD_CARRY;
    int rowlbl[NIHILIST_SUB_SIDE], collbl[NIHILIST_SUB_SIDE];
    int side = NIHILIST_SUB_SIDE;
    nihilist_sub_fixed_labels(rowlbl, collbl, side);

    for (int i = 4; i < argc; i++) {
        if (strcasecmp(argv[i], "carry") == 0)      conv = NIH_ADD_CARRY;
        else if (strcasecmp(argv[i], "nc") == 0)    conv = NIH_ADD_NOCARRY;
        else if (strcasecmp(argv[i], "m100") == 0)  conv = NIH_ADD_MOD100;
        else if (strcmp(argv[i], "-labels") == 0 && i + 2 < argc) {
            if (!parse_labels(argv[i + 1], side, rowlbl) ||
                !parse_labels(argv[i + 2], side, collbl)) {
                fprintf(stderr, "labels must each be a permutation of 1..%d\n", side);
                return 1;
            }
            i += 2;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    init_alphabet("J");
    if (g_alpha != NIHILIST_SUB_GRID) {
        fprintf(stderr, "alphabet is %d letters, need %d\n", g_alpha, NIHILIST_SUB_GRID);
        return 1;
    }

    // Read the plaintext (first line of the file, or stdin), to alphabet indices.
    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static int raw[MAXLEN];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        int idx = letter_to_index(ch);
        if (idx >= 0 && n < MAXLEN) raw[n++] = idx;
    }
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }

    // Square keyword -> keyed square; additive keyword -> its cells (period = keyword length).
    int kw[256], kwn = 0;
    for (int i = 0; square_kw[i] && kwn < 256; i++) {
        int idx = letter_to_index((unsigned char) square_kw[i]);
        if (idx >= 0) kw[kwn++] = idx;
    }
    int grid[NIHILIST_SUB_GRID];
    bifid_grid_from_keyword(kw, kwn, grid, g_alpha);

    int pos[NIHILIST_SUB_GRID];
    bifid_build_inverse(grid, pos, g_alpha);          // letter -> cell

    int key_cells[256], period = 0;
    for (int i = 0; add_kw[i] && period < 256; i++) {
        int idx = letter_to_index((unsigned char) add_kw[i]);
        if (idx >= 0) key_cells[period++] = pos[idx];  // the additive's coordinate cells
    }
    if (period < 1) { fprintf(stderr, "additive keyword must have >= 1 letter\n"); return 1; }

    static int cipher[MAXLEN];
    nihilist_sub_encrypt(raw, n, grid, rowlbl, collbl, side, key_cells, period, conv, cipher);

    for (int i = 0; i < n; i++) printf("%s%d", i ? " " : "", cipher[i]);
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
