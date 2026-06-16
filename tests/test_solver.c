//
//  In-process regression tests for the polyalphabetic optimizer (solve_cipher).
//
//  Framework-free: build with `make test`. This links the whole solver but
//  compiles polyalphabetic.c with -DPOLY_NO_MAIN and supplies its own main, so
//  solve_cipher can be driven directly and its SolveResult inspected -- no
//  stdout scraping. A fixed -seed makes each stochastic solve deterministic.
//
//  Strategy (planted-cipher recovery): encrypt a known English plaintext under a
//  known key, run solve_cipher with a fixed seed and a bounded budget, and
//  assert it recovers the plaintext exactly. This is the end-to-end guard against
//  optimizer regressions (scoring, cycleword derivation, the hill climber).
//
//  Run from the source directory (as `make test` does) so the n-gram table is
//  found in the cwd.
//

#include "../polyalphabetic.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

#define NGRAM_FILE "english_quadgrams.txt"
#define NGRAM_SIZE 4

// A chunk of natural English (Declaration of Independence), letters only.
static const char *PLAINTEXT =
    "WHENINTHECOURSEOFHUMANEVENTSITBECOMESNECESSARYFORONEPEOPLETODISSOLVE"
    "THEPOLITICALBANDSWHICHHAVECONNECTEDTHEMWITHANOTHERANDTOASSUMEAMONGTHE"
    "POWERSOFTHEEARTHTHESEPARATEANDEQUALSTATIONTOWHICHTHELAWSOFNATURE";

// Base config shared by the cases: optimal-cycle, no dictionary, fixed period.
static void base_config(PolyalphabeticConfig *cfg, int cipher_type, int cwlen) {
    init_config(cfg);
    cfg->cipher_type = cipher_type;
    cfg->ngram_size = NGRAM_SIZE;
    cfg->n_restarts = 60;
    cfg->n_hill_climbs = 1500;
    cfg->cycleword_len_present = true;   // pin the period (bypass IoC estimation)
    cfg->cycleword_len = cwlen;
    cfg->max_cycleword_len = cwlen + 1;
    cfg->dictionary_present = false;
    strcpy(cfg->ciphertext_file, "in-process-test");
    if (cipher_type == BEAUFORT) cfg->beaufort = true;
}

// Solve a planted cipher and require exact plaintext recovery.
static void check_solve(const char *name, int cipher_type,
    int key[], int cwlen, uint32_t seed, SharedData *shared) {

    int len = (int)strlen(PLAINTEXT);
    int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH];
    char cipher_str[MAX_CIPHER_LENGTH];

    ord((char *)PLAINTEXT, P);

    if (cipher_type == VIGENERE)      vigenere_encrypt(C, P, len, key, cwlen, false);
    else if (cipher_type == BEAUFORT) beaufort_encrypt(C, P, len, key, cwlen);
    else { CHECK(0, "%s: unsupported cipher type in harness", name); return; }

    for (int i = 0; i < len; i++) cipher_str[i] = C[i] + 'A';
    cipher_str[len] = '\0';

    PolyalphabeticConfig cfg;
    base_config(&cfg, cipher_type, cwlen);

    SolveResult res;
    seed_rand(seed);
    solve_cipher(cipher_str, "", &cfg, shared, &res);

    CHECK(res.solved, "%s: solver reported no solution", name);
    if (!res.solved) return;
    CHECK(res.decrypted_len == len, "%s: decrypted_len %d != %d", name, res.decrypted_len, len);

    int exact = 1;
    for (int i = 0; i < len; i++) if (res.decrypted[i] != P[i]) { exact = 0; break; }
    CHECK(exact, "%s: did not recover plaintext (score %.2f)", name, res.score);
}

int main(void) {
    SharedData shared = { NULL, NULL, 0, 0 };
    shared.ngram_data = load_ngrams(NGRAM_FILE, NGRAM_SIZE, false);
    if (!shared.ngram_data) {
        printf("FAIL: could not load %s (run from the source directory)\n", NGRAM_FILE);
        return 1;
    }

    // KRYPTOS as the key (period 7).
    int key[] = {10, 17, 24, 15, 19, 14, 18};

    check_solve("vigenere", VIGENERE, key, 7, 12345u, &shared);
    check_solve("beaufort", BEAUFORT, key, 7, 12345u, &shared);

    // A different seed must still recover (robustness, not seed-luck).
    check_solve("vigenere-seed2", VIGENERE, key, 7, 99999u, &shared);

    free(shared.ngram_data);

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
