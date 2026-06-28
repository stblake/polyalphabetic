// Seriated Playfair cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, merges J into I (the
// ACA 25-letter convention), lays it into the two-row seriated layout of the given
// period (inserting a null on a doubled vertical pair and padding the final block),
// builds the 5x5 grid from a keyword, and enciphers each vertical pair by the Playfair
// rules. It links the REAL cipher code (seriated_playfair.c + playfair.c + utils.c), so
// the generator and the solver can never drift in convention.
//
//   make seriated_playfair_gen
//   ./tools/seriated_playfair_gen plaintext.txt LOGARITHM 6 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword> <period> [omit-letter=J] [filler=X]
// stdout: the ciphertext (one line, bare A..Z over the 25-letter alphabet; the seriated
//         layout taken off block by block, top row then bottom row)
// stderr: the prepared plaintext (the solution: bare A..Z, with fillers, what the solver
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
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> <period> [omit=J] [filler=X]\n", argv[0]);
        return 1;
    }
    const char *keyword = argv[2];
    int period = atoi(argv[3]);
    char omit   = (argc > 4 && argv[4][0]) ? (char) toupper((unsigned char) argv[4][0]) : 'J';
    char filler = (argc > 5 && argv[5][0]) ? (char) toupper((unsigned char) argv[5][0]) : 'X';
    if (period < 1) { fprintf(stderr, "period must be >= 1\n"); return 1; }

    char omit_str[2] = { omit, '\0' };
    init_alphabet(omit_str);                     // 25-letter alphabet, base-25 indices
    if (g_alpha != PLAYFAIR_GRID) {
        fprintf(stderr, "alphabet is %d letters, need %d (one excluded)\n", g_alpha, PLAYFAIR_GRID);
        return 1;
    }

    int filler_idx = letter_to_index(filler, omit);
    int alt_idx    = letter_to_index((filler == 'X') ? 'Q' : 'X', omit);
    if (filler_idx < 0 || alt_idx < 0) { fprintf(stderr, "bad filler letter\n"); return 1; }

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
    playfair_grid_from_keyword(kw, kwn, grid);

    static int prepared[MAXLEN + 4], cipher[MAXLEN + 4];
    int plen = seriated_playfair_prepare(raw, n, period, filler_idx, alt_idx, prepared, MAXLEN + 4);
    seriated_playfair_encrypt(prepared, plen, grid, period, cipher);

    for (int i = 0; i < plen; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    fprintf(stderr, "[seriated-playfair: keyword=%s, period=%d, %d letters]\n", keyword, period, plen);
    for (int i = 0; i < plen; i++) fputc(index_to_char(prepared[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
