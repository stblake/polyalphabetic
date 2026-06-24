//
//  Unit tests for derive_optimal_cycleword (optimal_cycleword.c).
//
//  Framework-free: build with `make test`. Exits non-zero if any check fails.
//
//  Strategy (planted-key recovery): generate English-distributed plaintext,
//  encrypt it under a known cycleword, then assert derive_optimal_cycleword
//  recovers exactly that cycleword. The derivation maximizes correlation with
//  English monograms, so it only recovers the true key when the plaintext is
//  genuinely English-like and long enough -- which is the regime it runs in.
//  This guards the histogram*shift-weight rewrite against a convention or
//  argmax regression.
//

#include "colossus.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

// Sample one letter from the English monogram distribution.
static int sample_english_letter(void) {
    double target = frand();   // english_monograms sums to ~1.0
    double cum = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        cum += english_monograms[i];
        if (target <= cum) return i;
    }
    return ALPHABET_SIZE - 1;
}

static void random_alphabet(int a[]) {
    for (int i = 0; i < ALPHABET_SIZE; i++) a[i] = i;
    shuffle(a, ALPHABET_SIZE);
}

static int arrays_equal(int a[], int b[], int len) {
    for (int i = 0; i < len; i++) if (a[i] != b[i]) return 0;
    return 1;
}

// Recover a planted cycleword for a given cipher type. pt/ct are the keyed
// alphabets (straight for Vigenere/Beaufort/Porta), variant the tableau flag.
// rows_per_col controls how much English text backs each period column.
static void check_recovery(const char *name, int cipher_type, int variant,
    int pt[], int ct[], int cwlen, int rows_per_col) {

    int len = cwlen * rows_per_col;
    int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH];
    int planted_cw[MAX_CYCLEWORD_LEN], recovered_cw[MAX_CYCLEWORD_LEN];

    // English-distributed plaintext.
    for (int i = 0; i < len; i++) P[i] = sample_english_letter();

    // Planted cycleword: random characters drawn from the CT keyed alphabet,
    // matching how derive_optimal_cycleword reports the key (as CT-keyword chars).
    for (int i = 0; i < cwlen; i++) planted_cw[i] = ct[rand_int(0, ALPHABET_SIZE)];

    // Encrypt with the matching primitive.
    ColossusConfig cfg;
    cfg.cipher_type = cipher_type;
    cfg.variant = variant;

    if (cipher_type == VIGENERE) {
        vigenere_encrypt(C, P, len, planted_cw, cwlen, variant);
    } else if (cipher_type == BEAUFORT) {
        beaufort_encrypt(C, P, len, planted_cw, cwlen);
    } else if (cipher_type == PORTA) {
        porta_encrypt(C, P, len, planted_cw, cwlen);
    } else { // Quagmire
        quagmire_encrypt(C, P, len, pt, ct, planted_cw, cwlen, variant);
    }

    derive_optimal_cycleword(&cfg, C, len, pt, ct, recovered_cw, cwlen, NULL);

    CHECK(arrays_equal(recovered_cw, planted_cw, cwlen),
        "%s: recovered cycleword != planted (cwlen=%d, len=%d)", name, cwlen, len);
}

int main(void) {
    seed_rand(424242u);

    // Build the runtime alphabet (g_monograms etc.); derive_optimal_cycleword scores
    // each column against the English monogram frequencies, which init_alphabet fills.
    init_alphabet(NULL);

    int straight[ALPHABET_SIZE];
    for (int i = 0; i < ALPHABET_SIZE; i++) straight[i] = i;

    // Long columns so the correct shift wins decisively (deterministic seed).
    int rows = 600;

    // Vigenere (standard + variant).
    check_recovery("vigenere", VIGENERE, 0, straight, straight, 5, rows);
    check_recovery("vigenere-variant", VIGENERE, 1, straight, straight, 4, rows);

    // Beaufort.
    check_recovery("beaufort", BEAUFORT, 0, straight, straight, 6, rows);

    // Porta: the key char only determines floor(s/2), so A/B, C/D, ... are
    // indistinguishable. Plant only even key chars so recovery is well-defined.
    {
        int cipher_type = PORTA, cwlen = 5, len = cwlen * rows;
        int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH];
        int planted[MAX_CYCLEWORD_LEN], recovered[MAX_CYCLEWORD_LEN];
        for (int i = 0; i < len; i++) P[i] = sample_english_letter();
        for (int i = 0; i < cwlen; i++) planted[i] = 2 * rand_int(0, 13); // even chars
        porta_encrypt(C, P, len, planted, cwlen);
        ColossusConfig cfg; cfg.cipher_type = cipher_type; cfg.variant = 0;
        derive_optimal_cycleword(&cfg, C, len, straight, straight, recovered, cwlen, NULL);
        int ok = 1;
        for (int i = 0; i < cwlen; i++) if (recovered[i] / 2 != planted[i] / 2) ok = 0;
        CHECK(ok, "porta: recovered shift (floor key/2) != planted");
    }

    // Quagmire I-IV: random keyed alphabets, standard + variant.
    int pt[ALPHABET_SIZE], ct[ALPHABET_SIZE];
    random_alphabet(pt);
    random_alphabet(ct);
    check_recovery("quagmire4", QUAGMIRE_4, 0, pt, ct, 5, rows);
    check_recovery("quagmire4-variant", QUAGMIRE_4, 1, pt, ct, 4, rows);
    check_recovery("quagmire3", QUAGMIRE_3, 0, pt, pt, 6, rows); // PT == CT

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
