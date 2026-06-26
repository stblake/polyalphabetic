// Nicodemus cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, and enciphers it with a
// Nicodemus cipher. It links the REAL cipher code (nicodemus.c + transpositions.c + utils.c),
// so the generator and the solver can never drift in convention.
//
//   make nicodemus_gen
//   ./nicodemus_gen plaintext.txt SECRET vig          >cipher.txt 2>solution.txt
//   ./nicodemus_gen plaintext.txt GENERAL beau 5      >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword> <vig|variant|beau> [block-height]
//   The keyword's letters give the per-column shifts; their alphabetical rank order gives the
//   per-block columnar read order. block-height (rows per block) defaults to 5 (ACA standard).
// stdout: the ciphertext (one line, bare A..Z).
// stderr: the plaintext solution (bare A..Z, what the solver recovers).

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"
#include "nicodemus.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> <vig|variant|beau> [block-height]\n", argv[0]);
        return 1;
    }
    const char *keyword = argv[2];
    const char *vname = argv[3];
    int block_h = (argc >= 5) ? atoi(argv[4]) : 5;
    if (block_h < 1) block_h = 5;

    int variant = NICO_VIG;
    if (strcasecmp(vname, "variant") == 0 || strcasecmp(vname, "v") == 0) variant = NICO_VARIANT;
    else if (strcasecmp(vname, "beaufort") == 0 || strcasecmp(vname, "beau") == 0 ||
             strcasecmp(vname, "b") == 0) variant = NICO_BEAU;
    else if (strcasecmp(vname, "vigenere") == 0 || strcasecmp(vname, "vig") == 0) variant = NICO_VIG;
    else { fprintf(stderr, "variant must be vig | variant | beau\n"); return 1; }

    init_alphabet(NULL);                          // full 26-letter alphabet
    if (g_alpha != ALPHABET_SIZE) {
        fprintf(stderr, "alphabet is %d letters, need 26\n", g_alpha);
        return 1;
    }

    // Keyword letters -> indices.
    int kw[MAX_COLS], P = 0;
    for (int i = 0; keyword[i] && P < MAX_COLS; i++) {
        int c = toupper((unsigned char) keyword[i]);
        if (c >= 'A' && c <= 'Z') kw[P++] = g_char_to_idx[c];
    }
    if (P < 1) { fprintf(stderr, "keyword has no letters\n"); return 1; }

    int order[MAX_COLS], shifts[MAX_COLS];
    nicodemus_key_from_keyword(kw, P, order, shifts);

    // Read the plaintext (first line of the file, or stdin) to alphabet indices.
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
    nicodemus_encrypt(raw, n, P, block_h, order, shifts, variant, cipher);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');
    fprintf(stderr, "[nicodemus: keyword=%s P=%d block_h=%d sub=%s]\n", keyword, P, block_h, vname);
    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
