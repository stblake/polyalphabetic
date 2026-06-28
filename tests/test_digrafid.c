//
//  Unit tests for the Digrafid primitives (grid build / encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against digrafid.c + bifid.c
//  (for bifid_build_inverse) + utils.c. Exits non-zero if any check fails.
//
//  Strategy: the ACA "Digrafid" PDF worked example pins the whole convention end to end --
//  horizontal alphabet from keyword KEYWORD (3x9, row-major), vertical from VERTICAL (9x3,
//  column-major), plaintext THISISTHEFORESTPRI, and BOTH printed ciphertexts: period 3 ->
//  HJMXWSWJADWGFCSPYI and period 4 -> HJTKVHYUFFWDSQYPRI (the period-4 case exercises a
//  ragged final group of one digraph). The two grids are also asserted cell-for-cell. A
//  sign flip or a row/column / H<->V mix-up is caught, not just a self-consistent round
//  trip. Then decrypt(encrypt(P)) == P over random independent grids, even lengths and
//  periods (incl. ragged final blocks and period > length) covers the general case, an
//  odd-length lone-trailing-letter passthrough is checked, and period 1 is asserted to be
//  the identity.
//

#include "colossus.h"

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

// A..Z + '#' string -> alphabet indices over the 27-symbol Digrafid alphabet (no J->I).
static int str_to_idx(const char *s, int out[]) {
    int n = 0;
    for (int i = 0; s[i]; i++) {
        int c = toupper((unsigned char) s[i]);
        if (c == '#') { out[n++] = g_char_to_idx['#']; continue; }
        if (c < 'A' || c > 'Z') continue;
        out[n++] = g_char_to_idx[c];
    }
    return n;
}

static void idx_to_str(const int a[], int len, char out[]) {
    for (int i = 0; i < len; i++) out[i] = index_to_char(a[i]);
    out[len] = '\0';
}

// --- known-answer vectors (ACA "Digrafid" PDF worked example) ------------------

static void test_digrafid_known_answer(void) {
    int kw[32];
    int gridH[DIGRAFID_GRID], gridV[DIGRAFID_GRID];
    digrafid_grid_from_keyword(kw, str_to_idx("KEYWORD", kw), gridH, DIGRAFID_HROWS, DIGRAFID_HCOLS, 0);
    digrafid_grid_from_keyword(kw, str_to_idx("VERTICAL", kw), gridV, DIGRAFID_VROWS, DIGRAFID_VCOLS, 1);

    // The grids printed in the PDF, read row-major (H is 3x9, V is 9x3).
    char hbuf[DIGRAFID_GRID + 1], vbuf[DIGRAFID_GRID + 1];
    idx_to_str(gridH, DIGRAFID_GRID, hbuf);
    idx_to_str(gridV, DIGRAFID_GRID, vbuf);
    CHECK(strcmp(hbuf, "KEYWORDABCFGHIJLMNPQSTUVXZ#") == 0,
        "digrafid H grid mismatch: got '%s'", hbuf);
    CHECK(strcmp(vbuf, "VDPEFQRGSTHUIJWCKXAMYLNZBO#") == 0,
        "digrafid V grid mismatch: got '%s'", vbuf);

    int plain[64];
    int plen = str_to_idx("THISISTHEFORESTPRI", plain);
    CHECK(plen == 18, "KAT plaintext length %d, expected 18", plen);

    int cipher[64]; char cbuf[65];

    digrafid_encrypt(plain, plen, gridH, gridV, 3, cipher);
    idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "HJMXWSWJADWGFCSPYI") == 0,
        "digrafid period-3 KAT mismatch: got '%s', want 'HJMXWSWJADWGFCSPYI'", cbuf);
    int back[64];
    digrafid_decrypt(cipher, plen, gridH, gridV, 3, back);
    CHECK(arrays_equal(back, plain, plen), "digrafid period-3 decrypt round-trip mismatch");

    digrafid_encrypt(plain, plen, gridH, gridV, 4, cipher);
    idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "HJTKVHYUFFWDSQYPRI") == 0,
        "digrafid period-4 KAT mismatch: got '%s', want 'HJTKVHYUFFWDSQYPRI'", cbuf);
    digrafid_decrypt(cipher, plen, gridH, gridV, 4, back);
    CHECK(arrays_equal(back, plain, plen), "digrafid period-4 decrypt round-trip mismatch");
}

// --- round-trip over random independent grids, lengths and periods -------------

static void test_digrafid_roundtrip(void) {
    for (int t = 0; t < 5000; t++) {
        int gridH[DIGRAFID_GRID], gridV[DIGRAFID_GRID];
        for (int i = 0; i < DIGRAFID_GRID; i++) gridH[i] = i;
        for (int i = 0; i < DIGRAFID_GRID; i++) gridV[i] = i;
        shuffle(gridH, DIGRAFID_GRID);
        shuffle(gridV, DIGRAFID_GRID);

        int len = 2 * (1 + rand_int(0, 300));       // even length, 2..600
        int period = 1 + rand_int(0, 40);           // includes period > digraph count and 1
        int plain[640], cipher[640], back[640];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, DIGRAFID_GRID);

        digrafid_encrypt(plain, len, gridH, gridV, period, cipher);
        digrafid_decrypt(cipher, len, gridH, gridV, period, back);
        CHECK(arrays_equal(back, plain, len),
            "digrafid round-trip mismatch (len=%d period=%d)", len, period);
    }
}

// Odd length: the lone trailing letter passes through unchanged, the rest round-trips.
static void test_digrafid_odd_length(void) {
    int gridH[DIGRAFID_GRID], gridV[DIGRAFID_GRID];
    for (int i = 0; i < DIGRAFID_GRID; i++) { gridH[i] = i; gridV[i] = i; }
    shuffle(gridH, DIGRAFID_GRID);
    shuffle(gridV, DIGRAFID_GRID);
    int len = 51, period = 5, plain[64], cipher[64], back[64];
    for (int i = 0; i < len; i++) plain[i] = rand_int(0, DIGRAFID_GRID);
    digrafid_encrypt(plain, len, gridH, gridV, period, cipher);
    CHECK(cipher[len - 1] == plain[len - 1], "digrafid odd-length trailing letter not passed through");
    digrafid_decrypt(cipher, len, gridH, gridV, period, back);
    CHECK(arrays_equal(back, plain, len), "digrafid odd-length round-trip mismatch");
}

// Period 1 is the identity (each digraph is its own block; the reshape is a no-op and a
// digraph -> triple -> the same digraph).
static void test_digrafid_period_one_identity(void) {
    int gridH[DIGRAFID_GRID], gridV[DIGRAFID_GRID];
    for (int i = 0; i < DIGRAFID_GRID; i++) { gridH[i] = i; gridV[i] = i; }
    shuffle(gridH, DIGRAFID_GRID);
    shuffle(gridV, DIGRAFID_GRID);
    int len = 50, plain[64], cipher[64];
    for (int i = 0; i < len; i++) plain[i] = rand_int(0, DIGRAFID_GRID);
    digrafid_encrypt(plain, len, gridH, gridV, 1, cipher);
    CHECK(arrays_equal(cipher, plain, len), "digrafid period-1 is not the identity");
}

int main(void) {
    seed_rand(20240620u);
    init_alphabet_digrafid();            // 27-symbol alphabet (A..Z + '#')
    CHECK(g_alpha == DIGRAFID_GRID, "alphabet size %d, expected %d", g_alpha, DIGRAFID_GRID);

    test_digrafid_known_answer();
    test_digrafid_roundtrip();
    test_digrafid_odd_length();
    test_digrafid_period_one_identity();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
