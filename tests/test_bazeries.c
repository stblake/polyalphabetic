//
//  Unit tests for the Bazeries cipher primitives (bazeries.c).
//
//  Framework-free: build with `make test`, which links this against bazeries.c + bifid.c +
//  utils.c. Exits non-zero if any check fails.
//
//  Bazeries ("simple substitution plus transposition", ACA) is keyed by one number N < 10^6
//  that drives BOTH a digit-grouped reversal transposition and a fixed monoalphabetic map
//  between a column-major plaintext square and a keyed (N spelled out) row-major ciphertext
//  square. The 25-letter J->I alphabet, so strings are mapped through g_char_to_idx, NOT
//  s[i]-'A'. Core invariants pinned here, all against the ACA worked example (N=3752):
//    - the spelled-out keyword builds the PDF square THREOUSANDVFIYW BCGKLMPQXZ; digits 3,7,5,2;
//    - the RV transposition string mis/sbuselp/... and the full end-to-end ciphertext ACYYU...;
//    - encrypt/decrypt round-trips over random N x lengths (incl. the 150-250 ACA band);
//    - the transposition is an involution; the column-major pt vs row-major ct convention;
//    - edge cases: a 0 digit (3052), a 1-digit identity-ish key, ragged final group, short text.
//

#include "colossus.h"
#include "bazeries.h"

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

// Map an A..Z string (J folded to I) to J->I alphabet indices via g_char_to_idx.
static void str_to_idx(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) {
        int c = toupper((unsigned char) s[i]);
        if (c == 'J') c = 'I';
        out[i] = g_char_to_idx[c];
    }
}
static int idx_match_str(const int a[], const char *s) {
    int t[BAZERIES_MAX_SPELL > 256 ? BAZERIES_MAX_SPELL : 256];
    str_to_idx(s, t);
    for (int i = 0; s[i]; i++) if (a[i] != t[i]) return 0;
    return 1;
}
static int strlen_i(const char *s) { int n = 0; while (s[n]) n++; return n; }

// --- spelled keyword / square build / digits (ACA example N=3752) ----------

static void test_square_and_digits(void) {
    long key = 3752;

    int square[BAZERIES_GRID];
    bazeries_build_square(key, square);
    // PDF ciphertext square, row-major: THREO USAND VFIYW BCGKL MPQXZ.
    CHECK(idx_match_str(square, "THREOUSANDVFIYWBCGKLMPQXZ"),
        "N=3752 keyed square != PDF (THREOUSANDVFIYWBCGKLMPQXZ)");

    int digits[BAZERIES_MAX_DIGITS], nd;
    bazeries_digits(key, digits, &nd);
    CHECK(nd == 4 && digits[0] == 3 && digits[1] == 7 && digits[2] == 5 && digits[3] == 2,
        "N=3752 digits != {3,7,5,2} (got nd=%d)", nd);

    // Internal-zero and single-digit decompositions.
    int d2[BAZERIES_MAX_DIGITS], nd2;
    bazeries_digits(3052, d2, &nd2);
    CHECK(nd2 == 4 && d2[0] == 3 && d2[1] == 0 && d2[2] == 5 && d2[3] == 2,
        "N=3052 digits != {3,0,5,2}");
    bazeries_digits(7, d2, &nd2);
    CHECK(nd2 == 1 && d2[0] == 7, "N=7 digits != {7}");
    bazeries_digits(999999, d2, &nd2);
    CHECK(nd2 == 6, "N=999999 should have 6 digits (got %d)", nd2);
}

// --- transposition: the PDF RV string, and the involution -------------------

static void test_transpose(void) {
    const char *pt_str = "simplesubstitutionplustransposition";
    const char *rv_str = "missbuselptutitoilpnsnartsutisopoin";   // PDF "Reversed Groups"
    int n = strlen_i(pt_str);
    CHECK(n == strlen_i(rv_str), "pt/rv length mismatch (%d vs %d)", n, strlen_i(rv_str));

    int pt[64], rv[64];
    str_to_idx(pt_str, pt);
    int digits[BAZERIES_MAX_DIGITS], nd;
    bazeries_digits(3752, digits, &nd);
    bazeries_transpose(pt, n, digits, nd, rv);
    CHECK(idx_match_str(rv, rv_str), "N=3752 RV transposition != PDF (missbuselp...)");

    // Involution: reversing the same digit-groups twice is the identity.
    int back[64];
    bazeries_transpose(rv, n, digits, nd, back);
    CHECK(arrays_equal(back, pt, n), "transpose is not an involution");

    // Over random digit patterns and lengths.
    for (int trial = 0; trial < 200; trial++) {
        int len = rand_int(1, 260);
        int x[300], t1[300], t2[300];
        for (int i = 0; i < len; i++) x[i] = rand_int(0, BAZERIES_GRID);
        int dg[BAZERIES_MAX_DIGITS], ndg = rand_int(1, BAZERIES_MAX_DIGITS + 1);
        dg[0] = rand_int(1, 10);                                  // leading digit >= 1
        for (int i = 1; i < ndg; i++) dg[i] = rand_int(0, 10);
        bazeries_transpose(x, len, dg, ndg, t1);
        bazeries_transpose(t1, len, dg, ndg, t2);
        CHECK(arrays_equal(t2, x, len), "random involution len=%d ndg=%d", len, ndg);
    }
}

// --- substitution convention (column-major pt square, row-major ct square) --

static void test_substitution(void) {
    // With an identity ct square (row-major 0..24), encrypting plaintext letter L lands on
    // the ct cell (L%5)*5 + L/5 -- i.e. the row<->col transpose of L. Pins the convention.
    int square[BAZERIES_GRID];
    for (int i = 0; i < BAZERIES_GRID; i++) square[i] = i;
    int fsub[BAZERIES_GRID], invsub[BAZERIES_GRID];
    bazeries_build_sub(square, fsub);
    bazeries_build_invsub(square, invsub);
    for (int L = 0; L < BAZERIES_GRID; L++) {
        int expect = (L % BAZERIES_SIDE) * BAZERIES_SIDE + L / BAZERIES_SIDE;
        CHECK(fsub[L] == expect, "identity-square fsub[%d] = %d != %d", L, fsub[L], expect);
        CHECK(invsub[fsub[L]] == L, "invsub not inverse of fsub at %d", L);
    }

    // fsub and invsub are mutual inverses for a real keyed square too.
    bazeries_build_square(81257, square);
    bazeries_build_sub(square, fsub);
    bazeries_build_invsub(square, invsub);
    for (int L = 0; L < BAZERIES_GRID; L++)
        CHECK(invsub[fsub[L]] == L, "keyed-square invsub not inverse of fsub at %d", L);
}

// --- end-to-end known-answer vector (ACA example) --------------------------

static void test_known_answer(void) {
    const char *pt_str = "simplesubstitutionplustransposition";
    const char *ct_str = "ACYYUXYMRQKXKCKGCRQIYITNKYXKCYGQGCI";   // PDF ciphertext (5-grouped, joined)
    int n = strlen_i(pt_str);
    CHECK(n == strlen_i(ct_str), "pt/ct length mismatch (%d vs %d)", n, strlen_i(ct_str));

    int pt[64], ct[64], back[64];
    str_to_idx(pt_str, pt);
    bazeries_encrypt(pt, n, 3752, ct);
    CHECK(idx_match_str(ct, ct_str), "N=3752 encrypt != PDF ciphertext (ACYYU...)");

    int ctv[64];
    str_to_idx(ct_str, ctv);
    bazeries_decrypt(ctv, n, 3752, back);
    CHECK(arrays_equal(back, pt, n), "N=3752 decrypt(PDF ciphertext) != plaintext");
}

// --- round-trips over random keys x lengths --------------------------------

static void test_roundtrip(void) {
    int lens[] = { 1, 2, 7, 35, 97, 150, 200, 250, 511 };
    for (int li = 0; li < (int) (sizeof lens / sizeof lens[0]); li++) {
        int len = lens[li];
        for (int trial = 0; trial < 12; trial++) {
            long key = (long) rand_int(1, 1000000);              // 1..999999
            int pt[MAX_CIPHER_LENGTH], ct[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
            for (int i = 0; i < len; i++) pt[i] = rand_int(0, BAZERIES_GRID);
            bazeries_encrypt(pt, len, key, ct);
            bazeries_decrypt(ct, len, key, back);
            CHECK(arrays_equal(back, pt, len), "round-trip key=%ld len=%d", key, len);
        }
    }
}

// --- edge cases ------------------------------------------------------------

static void test_edges(void) {
    int pt[64], ct[64], back[64];
    for (int i = 0; i < 40; i++) pt[i] = rand_int(0, BAZERIES_GRID);

    long keys[] = { 1, 9, 10, 100, 1000, 3052, 200003, 999999 };
    for (int k = 0; k < (int) (sizeof keys / sizeof keys[0]); k++) {
        for (int len = 1; len <= 40; len += 13) {               // incl. ragged final groups
            bazeries_encrypt(pt, len, keys[k], ct);
            bazeries_decrypt(ct, len, keys[k], back);
            CHECK(arrays_equal(back, pt, len), "edge round-trip key=%ld len=%d", keys[k], len);
        }
    }
}

int main(void) {
    seed_rand(20260627u);
    init_alphabet("J");             // 25-letter J->I alphabet, as the binary forces for bazeries

    test_square_and_digits();
    test_transpose();
    test_substitution();
    test_known_answer();
    test_roundtrip();
    test_edges();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) { printf("TESTS FAILED\n"); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
