//
//  Unit tests for the Bifid primitives (square build / encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against bifid.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Strategy: a hand-computed known-answer vector (the Wikipedia "Bifid cipher" worked
//  example -- square BGWKZQPNDSIOAXEFCLUMTHYVR, plaintext FLEEATONCE, period = full
//  length 10, ciphertext UAEOLWRINS) pins the actual convention: the row/column
//  fractionation, the row-then-column stream order, and the consecutive re-pairing. A
//  sign flip or a row/column mix-up is caught, not just a self-consistent round-trip.
//  Then decrypt(encrypt(P)) == P over random squares, lengths and periods (including
//  incomplete final blocks and period > len) covers the general case, and a 6x6 (36-
//  cell) round-trip exercises the side-generic path that the 5x5 default does not.
//

#include "../colossus.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

static int arrays_equal(const int a[], const int b[], int len) {
    for (int i = 0; i < len; i++) if (a[i] != b[i]) return 0;
    return 1;
}

// A..Z string -> alphabet indices, merging J into I (the 25-letter convention).
static int str_to_idx(const char *s, int out[]) {
    int n = 0;
    for (int i = 0; s[i]; i++) {
        int c = toupper((unsigned char) s[i]);
        if (c == 'J') c = 'I';
        if (c < 'A' || c > 'Z') continue;
        out[n++] = g_char_to_idx[c];
    }
    return n;
}

static void idx_to_str(const int a[], int len, char out[]) {
    for (int i = 0; i < len; i++) out[i] = index_to_char(a[i]);
    out[len] = '\0';
}

// --- Known-answer vector (Wikipedia "Bifid cipher" worked example) -------------

static void test_bifid_known_answer(void) {
    // The square is given directly (a scrambled 25-letter permutation, no J):
    //   B G W K Z / Q P N D S / I O A X E / F C L U M / T H Y V R
    int grid[PLAYFAIR_GRID];
    int gn = str_to_idx("BGWKZQPNDSIOAXEFCLUMTHYVR", grid);
    CHECK(gn == PLAYFAIR_GRID, "KAT square is not 25 letters (%d)", gn);

    int plain[64];
    int plen = str_to_idx("FLEEATONCE", plain);

    // Wikipedia reads the whole message as one block (period == length 10).
    int cipher[64];
    bifid_encrypt(plain, plen, grid, 5, plen, cipher);
    char cbuf[65]; idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "UAEOLWRINS") == 0,
        "bifid encrypt KAT mismatch: got '%s', want 'UAEOLWRINS'", cbuf);

    int back[64];
    bifid_decrypt(cipher, plen, grid, 5, plen, back);
    CHECK(arrays_equal(back, plain, plen), "bifid decrypt KAT round-trip mismatch");
}

// --- keyword square build -----------------------------------------------------

static void test_bifid_grid_build(void) {
    // Keyword PLAYFAIREXAMPLE over the 25-letter alphabet -> the same row-major square
    // Playfair builds (the keyed-square construction is shared): PLAYF IREXM BCDGH ...
    int kw[64], grid[PLAYFAIR_GRID];
    int kwn = str_to_idx("PLAYFAIREXAMPLE", kw);
    bifid_grid_from_keyword(kw, kwn, grid, PLAYFAIR_GRID);
    int expect[PLAYFAIR_GRID];
    str_to_idx("PLAYFIREXMBCDGHKNOQSTUVWZ", expect);
    CHECK(arrays_equal(grid, expect, PLAYFAIR_GRID), "bifid grid build mismatch");
}

// --- round-trip over random squares, lengths and periods ----------------------

static void test_bifid_roundtrip(void) {
    for (int t = 0; t < 5000; t++) {
        int grid[PLAYFAIR_GRID];
        for (int i = 0; i < PLAYFAIR_GRID; i++) grid[i] = i;
        shuffle(grid, PLAYFAIR_GRID);

        int len = 1 + rand_int(0, 600);
        int period = 1 + rand_int(0, 40);          // includes period > len and period 1
        int plain[640], cipher[640], back[640];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, PLAYFAIR_GRID);

        bifid_encrypt(plain, len, grid, 5, period, cipher);
        bifid_decrypt(cipher, len, grid, 5, period, back);
        CHECK(arrays_equal(back, plain, len),
            "bifid round-trip mismatch (len=%d period=%d)", len, period);
    }
}

// Period 1 is the identity transform (block of one letter -> stream (r,c) -> same cell).
static void test_bifid_period_one_identity(void) {
    int grid[PLAYFAIR_GRID];
    for (int i = 0; i < PLAYFAIR_GRID; i++) grid[i] = i;
    shuffle(grid, PLAYFAIR_GRID);
    int len = 50, plain[64], cipher[64];
    for (int i = 0; i < len; i++) plain[i] = rand_int(0, PLAYFAIR_GRID);
    bifid_encrypt(plain, len, grid, 5, 1, cipher);
    CHECK(arrays_equal(cipher, plain, len), "bifid period-1 is not the identity");
}

// --- 6x6 (36-cell) side-generic round-trip ------------------------------------

static void test_bifid_6x6_roundtrip(void) {
    for (int t = 0; t < 2000; t++) {
        int grid[BIFID_MAX_GRID];
        for (int i = 0; i < BIFID_MAX_GRID; i++) grid[i] = i;
        shuffle(grid, BIFID_MAX_GRID);

        int len = 1 + rand_int(0, 400);
        int period = 1 + rand_int(0, 30);
        int plain[420], cipher[420], back[420];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, BIFID_MAX_GRID);

        bifid_encrypt(plain, len, grid, 6, period, cipher);
        bifid_decrypt(cipher, len, grid, 6, period, back);
        CHECK(arrays_equal(back, plain, len),
            "bifid 6x6 round-trip mismatch (len=%d period=%d)", len, period);
    }
}

int main(void) {
    seed_rand(20240620u);
    init_alphabet("J");                  // 25-letter alphabet (J merged into I)
    CHECK(g_alpha == PLAYFAIR_GRID, "alphabet size %d, expected %d", g_alpha, PLAYFAIR_GRID);

    test_bifid_known_answer();
    test_bifid_grid_build();
    test_bifid_roundtrip();
    test_bifid_period_one_identity();
    test_bifid_6x6_roundtrip();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
