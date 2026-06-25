// Gromark / Periodic Gromark cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps A..Z, and enciphers it with a
// Gromark cipher. It links the REAL cipher code (gromark.c + utils.c), so the generator and
// the solver can never drift in convention.
//
//   make gromark_gen
//   ./gromark_gen plaintext.txt ENIGMA 23452          >cipher.txt 2>solution.txt   # basic
//   ./gromark_gen plaintext.txt ENIGMA periodic       >cipher.txt 2>solution.txt   # periodic
//
// argv: <plaintext-file|-> <keyword> <primer-digits | "periodic">
//   basic    : the mixed alphabet is the K2M of <keyword>; the primer is <primer-digits>.
//   periodic : everything derives from <keyword> -- the K2M alphabet, the primer (the
//              alphabetical ranks of the distinct keyword letters), the period (the number
//              of distinct keyword letters), and the per-group offsets (the keyword letters'
//              positions in the alphabet).
// stdout: the ciphertext (one line, bare A..Z).
// stderr: the plaintext solution (bare A..Z, what the solver recovers).

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "colossus.h"

#define MAXLEN (1 << 20)

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <plaintext|-> <keyword> <primer-digits | periodic>\n", argv[0]);
        return 1;
    }
    const char *keyword = argv[2];
    const char *mode = argv[3];
    int periodic = (strcasecmp(mode, "periodic") == 0);

    init_alphabet(NULL);                          // full 26-letter alphabet
    if (g_alpha != ALPHABET_SIZE) {
        fprintf(stderr, "alphabet is %d letters, need 26\n", g_alpha);
        return 1;
    }

    // The K2M mixed cipher alphabet, from the keyword.
    int sigma[ALPHABET_SIZE];
    gromark_mixed_alphabet(keyword, sigma);

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

    if (periodic) {
        // Derive the period (number of distinct keyword letters), the primer (their
        // alphabetical ranks 1..P), and the per-group offsets (their positions in sigma).
        int keyed[ALPHABET_SIZE];
        make_keyed_alphabet((char *) keyword, keyed);
        int seen[ALPHABET_SIZE] = {0}, P = 0;
        for (int i = 0; keyword[i]; i++) {
            int idx = g_char_to_idx[toupper((unsigned char) keyword[i]) & 127];
            if (idx >= 0 && idx < ALPHABET_SIZE && !seen[idx]) { seen[idx] = 1; P++; }
        }
        if (P < 1) { fprintf(stderr, "keyword has no letters\n"); return 1; }

        int sinv[ALPHABET_SIZE];
        for (int i = 0; i < ALPHABET_SIZE; i++) sinv[sigma[i]] = i;

        int primer[ALPHABET_SIZE], offsets[ALPHABET_SIZE];
        for (int g = 0; g < P; g++) {
            // rank of keyed[g] among the P distinct keyword letters (1-based, alphabetical).
            int rank = 1;
            for (int h = 0; h < P; h++) if (keyed[h] < keyed[g]) rank++;
            primer[g] = rank;
            offsets[g] = sinv[keyed[g]];
        }
        gromark_periodic_encrypt(raw, n, sigma, primer, P, offsets, cipher);
        fprintf(stderr, "[periodic gromark: keyword=%s period=%d primer=", keyword, P);
        for (int g = 0; g < P; g++) fprintf(stderr, "%d", primer[g]);
        fprintf(stderr, "]\n");
    } else {
        int primer[ALPHABET_SIZE], P = 0;
        for (int i = 0; mode[i] && P < ALPHABET_SIZE; i++)
            if (mode[i] >= '0' && mode[i] <= '9') primer[P++] = mode[i] - '0';
        if (P == 0) { fprintf(stderr, "primer has no digits (or use \"periodic\")\n"); return 1; }
        gromark_encrypt(raw, n, sigma, primer, P, cipher);
    }

    for (int i = 0; i < n; i++) putchar(index_to_char(cipher[i]));
    putchar('\n');
    for (int i = 0; i < n; i++) fputc(index_to_char(raw[i]), stderr);
    fputc('\n', stderr);
    return 0;
}
