// Homophonic substitution cipher generator (test-data tool, not part of the solver).
//
// Reads a plaintext (first line of a file, or stdin), keeps only A..Z, assigns each
// plaintext letter a number of homophone symbols proportional to its English frequency
// (totalling ~ <nsymbols>), and enciphers each letter as one of its homophones chosen
// uniformly at random. Symbols are emitted as zero-padded integers joined by commas --
// the canonical homophonic format the solver auto-detects.
//
//   cc -O2 -o homophonic_gen tools/homophonic_gen.c
//   ./homophonic_gen plaintext.txt 60 12 >cipher.txt 2>solution.txt
//
// argv: <plaintext-file|-> [nsymbols=60] [seed=1]
// stdout: the comma-separated homophonic ciphertext (one line)
// stderr: the cleaned A..Z plaintext (the solution), one line

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

// Relative English letter frequencies A..Z (percent); only the ratios matter here.
static const double freq[26] = {
    8.17,1.49,2.78,4.25,12.70,2.23,2.02,6.09,6.97,0.15,0.77,4.03,2.41,
    6.75,7.51,1.93,0.10,5.99,6.33,9.06,2.76,0.98,2.36,0.15,1.97,0.07
};

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <plaintext|-> [nsymbols] [seed]\n", argv[0]); return 1; }
    int nsymbols = (argc > 2) ? atoi(argv[2]) : 60;
    unsigned seed = (argc > 3) ? (unsigned) atoi(argv[3]) : 1u;
    srand(seed);

    // Read plaintext: first line of the file (or stdin), keep A..Z, uppercase.
    FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "r");
    if (!fp) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    static char pt[1 << 20];
    int n = 0, ch;
    while ((ch = fgetc(fp)) != EOF && ch != '\n')
        if (isalpha(ch) && n < (int) sizeof(pt) - 1) pt[n++] = (char) toupper(ch);
    pt[n] = '\0';
    if (fp != stdin) fclose(fp);
    if (n == 0) { fprintf(stderr, "empty plaintext\n"); return 1; }

    // Homophones per letter, proportional to frequency, at least 1 each.
    double total = 0.; for (int c = 0; c < 26; c++) total += freq[c];
    int nh[26], assigned = 0;
    for (int c = 0; c < 26; c++) {
        nh[c] = (int) (freq[c] / total * nsymbols + 0.5);
        if (nh[c] < 1) nh[c] = 1;
        assigned += nh[c];
    }

    // Lay the homophone symbol ids out contiguously: letter c owns base[c]..base[c]+nh[c]-1.
    int base[26];
    for (int c = 0, b = 0; c < 26; c++) { base[c] = b; b += nh[c]; }

    // Encipher: each plaintext letter -> a random one of its homophones. Zero-pad the
    // symbol numbers to a fixed width so the surface forms are uniform.
    int width = 1; for (int v = assigned - 1; v >= 10; v /= 10) width++;
    for (int i = 0; i < n; i++) {
        int c = pt[i] - 'A';
        int sym = base[c] + rand() % nh[c];
        if (i) putchar(',');
        printf("%0*d", width, sym);
    }
    putchar('\n');

    fprintf(stderr, "%s\n", pt);
    return 0;
}
