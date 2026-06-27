// Progressive Key cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, and enciphers it with a
// Progressive Key cipher: a periodic base cipher (Vigenere / Variant / Beaufort) under a letter
// keyword, composed with a per-group constant key drift (the progression index). It links the
// REAL cipher code (progkey.c + utils.c), so the generator and the solver can never drift.
//
//   make progkey_gen
//   ./progkey_gen plaintext.txt GRAPEFRUIT 1 vig >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> <keyword> <progression-index> [vig|var|beau]
// stdout: the Progressive Key ciphertext (one line, bare A..Z over the 26-letter alphabet)
// stderr: the plaintext (the solution: bare A..Z, what the solver recovers char-for-char)

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> <progression-index> [vig|var|beau]\n",
            argv[0]);
        return 1;
    }
    const char *keyword_str = argv[2];
    int prog = atoi(argv[3]);
    const char *base_str = (argc >= 5) ? argv[4] : "vig";

    int base = PROGKEY_BASE_VIG;
    if (strcmp(base_str, "var") == 0 || strcmp(base_str, "variant") == 0) base = PROGKEY_BASE_VAR;
    else if (strcmp(base_str, "beau") == 0 || strcmp(base_str, "beaufort") == 0) base = PROGKEY_BASE_BEAU;
    else if (strcmp(base_str, "vig") != 0 && strcmp(base_str, "vigenere") != 0) {
        fprintf(stderr, "unknown base '%s' (use vig|var|beau)\n", base_str);
        return 1;
    }

    init_alphabet(NULL);                          // full 26-letter alphabet
    if (g_alpha != ALPHABET_SIZE) {
        fprintf(stderr, "alphabet is %d letters, need 26\n", g_alpha);
        return 1;
    }

    // Parse the keyword into per-column base shifts 0..25 (each key letter is its own shift).
    static int keyword[MAX_CYCLEWORD_LEN];
    int P = 0;
    for (int i = 0; keyword_str[i] && P < MAX_CYCLEWORD_LEN; i++) {
        int c = toupper(keyword_str[i]);
        if (c >= 'A' && c <= 'Z') keyword[P++] = g_char_to_idx[c];
    }
    if (P == 0) { fprintf(stderr, "keyword has no letters\n"); return 1; }

    // Read the plaintext (first line of the file, or stdin), to alphabet indices.
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
    progkey_encrypt(cipher, raw, n, keyword, P, prog, base);

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');

    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
