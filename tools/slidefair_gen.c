// Slidefair cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, pads with X to an even length
// (Slidefair enciphers in digraphs), and enciphers it with a Slidefair cipher under a keyword and
// one of the three variants. It links the REAL cipher code (slidefair.c + utils.c), so the
// generator and the solver can never drift in convention.
//
//   make slidefair_gen
//   ./slidefair_gen plaintext.txt DIGRAPH vig    >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword> [vig|var|beau]
//   The keyword's length is the period P; each letter keys one column. The variant defaults to vig.
// stdout: the ciphertext (one line, bare A..Z).
// stderr: the plaintext solution (bare A..Z, padded -- what the solver recovers).

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"
#include "slidefair.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> [vig|var|beau]\n", argv[0]);
        return 1;
    }

    init_alphabet(NULL);                          // full 26-letter alphabet (no J->I merge)

    // Variant selector (default Vigenere).
    int type = SLIDEFAIR;
    const char *vname = "vig";
    if (argc >= 4) {
        if (strcmp(argv[3], "var") == 0)  { type = SLIDEFAIR_VAR;  vname = "var"; }
        else if (strcmp(argv[3], "beau") == 0) { type = SLIDEFAIR_BEAU; vname = "beau"; }
        else if (strcmp(argv[3], "vig") == 0)  { type = SLIDEFAIR; vname = "vig"; }
        else { fprintf(stderr, "variant must be vig|var|beau\n"); return 1; }
    }

    // Keyword -> per-column key letters (indices 0..25). Period P = keyword length.
    int key[MAX_KEYWORD_LEN];
    int P = 0;
    for (const char *k = argv[2]; *k && P < MAX_KEYWORD_LEN; k++) {
        int c = toupper((unsigned char) *k);
        if (c >= 'A' && c <= 'Z') key[P++] = c - 'A';
    }
    if (P == 0) { fprintf(stderr, "empty keyword\n"); return 1; }

    // Read the plaintext (first line of the file, or stdin) to alphabet indices.
    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static int raw[MAXLEN];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        int c = toupper(ch);
        if (c >= 'A' && c <= 'Z' && n < MAXLEN) raw[n++] = c - 'A';
    }
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }

    // Pad with X to an even length (a whole number of digraphs).
    if (n % 2 != 0 && n < MAXLEN) raw[n++] = 'X' - 'A';

    static int cipher[MAXLEN];
    slidefair_encrypt(cipher, raw, n, key, P, type);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');
    fprintf(stderr, "[slidefair: keyword=%s, variant=%s, P=%d, %d letters]\n", argv[2], vname, P, n);
    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
