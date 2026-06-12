// Standalone demonstration of the load_ngrams() feof bug fix.
// Replicates the project's loader two ways (old = while(!feof), new =
// while(fscanf==2)) and shows how each handles a malformed final line.
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define MAX_NGRAM_SIZE 8

static int int_pow(int b, int e) { int r = 1; while (e-- > 0) r *= b; return r; }

static int ngram_index_str(char *ngram, int n) {
    int c, index = 0, base = 1;
    for (int i = 0; i < n; i++) { c = toupper(ngram[i]) - 'A'; index += c*base; base *= ALPHABET_SIZE; }
    return index;
}

// OLD: loops on !feof -> re-reads / mis-assigns on a trailing/malformed line.
static float* load_old(char *file, int sz, double *total_out) {
    FILE *fp; int i, n, freq, indx; char ng[MAX_NGRAM_SIZE]; float *d; double total = 0.;
    n = int_pow(ALPHABET_SIZE, sz); d = malloc(n*sizeof(float));
    for (i = 0; i < n; i++) d[i] = 0.;
    fp = fopen(file, "r");
    while (!feof(fp)) { fscanf(fp, "%s\t%d", ng, &freq); indx = ngram_index_str(ng, sz); d[indx] = freq; }
    fclose(fp);
    for (i = 0; i < n; i++) { d[i] = log(1. + d[i]); total += d[i]; }
    for (i = 0; i < n; i++) d[i] /= total;
    *total_out = total; return d;
}

// NEW: loops on a successful 2-field parse -> stops cleanly, ignores bad lines.
static float* load_new(char *file, int sz, double *total_out) {
    FILE *fp; int i, n, freq, indx; char ng[MAX_NGRAM_SIZE]; float *d; double total = 0.;
    n = int_pow(ALPHABET_SIZE, sz); d = malloc(n*sizeof(float));
    for (i = 0; i < n; i++) d[i] = 0.;
    fp = fopen(file, "r");
    while (fscanf(fp, "%s\t%d", ng, &freq) == 2) { indx = ngram_index_str(ng, sz); d[indx] = freq; }
    fclose(fp);
    for (i = 0; i < n; i++) { d[i] = log(1. + d[i]); total += d[i]; }
    for (i = 0; i < n; i++) d[i] /= total;
    *total_out = total; return d;
}

int main(int argc, char **argv) {
    char *file = argv[1];
    char *spurious = argv[2];   // quadgram that should NOT exist (malformed trailing token)
    int idx = ngram_index_str(spurious, 4);
    double t_old, t_new;
    float *o = load_old(file, 4, &t_old);
    float *n = load_new(file, 4, &t_new);
    printf("                         OLD (feof)     NEW (fscanf==2)\n");
    printf("normalization total:   %12.6f   %12.6f\n", t_old, t_new);
    printf("prob['%s']:           %12.8f   %12.8f\n", spurious, o[idx], n[idx]);
    printf("  -> OLD injected a spurious '%s' entry: %s\n", spurious, o[idx] > 0 ? "YES (bug)" : "no");
    printf("  -> NEW left '%s' at zero:             %s\n", spurious, n[idx] == 0 ? "YES (fixed)" : "no");
    free(o); free(n);
    return 0;
}
