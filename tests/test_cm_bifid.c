//
//  Unit tests for the CM Bifid (Conjugated Matrix Bifid) primitives.
//
//  Framework-free: build with `make test`, which links this against cm_bifid.c + bifid.c
//  + utils.c. Exits non-zero if any check fails.
//
//  CM Bifid is plain Bifid except the coordinate-pair -> letter recombination uses a
//  SECOND square. Strategy:
//    * a known-answer vector taken cell-for-cell from the ACA CM Bifid worked example
//      (two explicit 5x5 squares, plaintext ODDPERIODSAREPOPULAR, period 7, ciphertext
//      FANXZEXFENUKKRBYNKAK) pins the whole convention -- which square fractionates, which
//      recombines, the row-then-column stream order, and the consecutive re-pairing;
//    * the sq1 == sq2 case must reduce EXACTLY to Bifid (cm_bifid == bifid), checked over
//      random squares/lengths/periods -- this anchors the new primitive to the proven one;
//    * decrypt(encrypt(P)) == P over random INDEPENDENT square pairs, lengths and periods
//      (incl. incomplete final blocks and period > len) covers the general two-square case;
//    * a period-1 check pins the degenerate monoalphabetic map (letter -> sq2[pos1(letter)]);
//    * a 6x6 (36-cell) round-trip exercises the side-generic path.
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

// --- Known-answer vector (ACA "CM Bifid" worked example) -----------------------

static void test_cm_bifid_known_answer(void) {
    // Square 1 (pt, fractionation):  E X T R A / K L M P O / H W Z Q D / G V U S I / F C B Y N
    // Square 2 (CT, recombination):  N C D R S / O B F Q U / V A G P W / E Y H M X / L T I K Z
    int sq1[PLAYFAIR_GRID], sq2[PLAYFAIR_GRID];
    int n1 = str_to_idx("EXTRAKLMPOHWZQDGVUSIFCBYN", sq1);
    int n2 = str_to_idx("NCDRSOBFQUVAGPWEYHMXLTIKZ", sq2);
    CHECK(n1 == PLAYFAIR_GRID, "KAT square 1 is not 25 letters (%d)", n1);
    CHECK(n2 == PLAYFAIR_GRID, "KAT square 2 is not 25 letters (%d)", n2);

    int plain[64];
    int plen = str_to_idx("ODDPERIODSAREPOPULAR", plain);   // 20 letters, period 7

    int cipher[64];
    cm_bifid_encrypt(plain, plen, sq1, sq2, 5, 7, cipher);
    char cbuf[65]; idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "FANXZEXFENUKKRBYNKAK") == 0,
        "cm-bifid encrypt KAT mismatch: got '%s', want 'FANXZEXFENUKKRBYNKAK'", cbuf);

    int back[64];
    cm_bifid_decrypt(cipher, plen, sq1, sq2, 5, 7, back);
    CHECK(arrays_equal(back, plain, plen), "cm-bifid decrypt KAT round-trip mismatch");
}

// --- sq1 == sq2 must reduce EXACTLY to plain Bifid ----------------------------

static void test_cm_bifid_reduces_to_bifid(void) {
    for (int t = 0; t < 3000; t++) {
        int grid[PLAYFAIR_GRID];
        for (int i = 0; i < PLAYFAIR_GRID; i++) grid[i] = i;
        shuffle(grid, PLAYFAIR_GRID);

        int len = 1 + rand_int(0, 400);
        int period = 1 + rand_int(0, 30);
        int plain[420], ref[420], got[420];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, PLAYFAIR_GRID);

        bifid_encrypt(plain, len, grid, 5, period, ref);
        cm_bifid_encrypt(plain, len, grid, grid, 5, period, got);
        CHECK(arrays_equal(ref, got, len),
            "cm-bifid(sq,sq) encrypt != bifid (len=%d period=%d)", len, period);

        bifid_decrypt(ref, len, grid, 5, period, plain);   // reuse plain as scratch
        cm_bifid_decrypt(got, len, grid, grid, 5, period, got);
        CHECK(arrays_equal(plain, got, len),
            "cm-bifid(sq,sq) decrypt != bifid (len=%d period=%d)", len, period);
    }
}

// --- round-trip over random INDEPENDENT square pairs, lengths and periods ------

static void test_cm_bifid_roundtrip(void) {
    for (int t = 0; t < 5000; t++) {
        int sq1[PLAYFAIR_GRID], sq2[PLAYFAIR_GRID];
        for (int i = 0; i < PLAYFAIR_GRID; i++) { sq1[i] = i; sq2[i] = i; }
        shuffle(sq1, PLAYFAIR_GRID);
        shuffle(sq2, PLAYFAIR_GRID);

        int len = 1 + rand_int(0, 600);
        int period = 1 + rand_int(0, 40);          // includes period > len and period 1
        int plain[640], cipher[640], back[640];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, PLAYFAIR_GRID);

        cm_bifid_encrypt(plain, len, sq1, sq2, 5, period, cipher);
        cm_bifid_decrypt(cipher, len, sq1, sq2, 5, period, back);
        CHECK(arrays_equal(back, plain, len),
            "cm-bifid round-trip mismatch (len=%d period=%d)", len, period);
    }
}

// Period 1: a block of one letter -> its (r,c) in sq1 -> sq2[r*side+c], i.e. the
// monoalphabetic map  letter -> sq2[pos1(letter)]. With sq1 == sq2 this is the identity.
static void test_cm_bifid_period_one(void) {
    int sq1[PLAYFAIR_GRID], sq2[PLAYFAIR_GRID], pos1[PLAYFAIR_GRID];
    for (int i = 0; i < PLAYFAIR_GRID; i++) { sq1[i] = i; sq2[i] = i; }
    shuffle(sq1, PLAYFAIR_GRID);
    shuffle(sq2, PLAYFAIR_GRID);
    bifid_build_inverse(sq1, pos1, PLAYFAIR_GRID);

    int len = 50, plain[64], cipher[64];
    for (int i = 0; i < len; i++) plain[i] = rand_int(0, PLAYFAIR_GRID);

    cm_bifid_encrypt(plain, len, sq1, sq2, 5, 1, cipher);
    int ok = 1;
    for (int i = 0; i < len; i++) if (cipher[i] != sq2[pos1[plain[i]]]) ok = 0;
    CHECK(ok, "cm-bifid period-1 is not the expected monoalphabetic map sq2[pos1(x)]");

    // sq1 == sq2 -> period-1 identity.
    cm_bifid_encrypt(plain, len, sq1, sq1, 5, 1, cipher);
    CHECK(arrays_equal(cipher, plain, len), "cm-bifid period-1 (sq,sq) is not the identity");
}

// --- 6x6 (36-cell) side-generic round-trip ------------------------------------

static void test_cm_bifid_6x6_roundtrip(void) {
    for (int t = 0; t < 2000; t++) {
        int sq1[BIFID_MAX_GRID], sq2[BIFID_MAX_GRID];
        for (int i = 0; i < BIFID_MAX_GRID; i++) { sq1[i] = i; sq2[i] = i; }
        shuffle(sq1, BIFID_MAX_GRID);
        shuffle(sq2, BIFID_MAX_GRID);

        int len = 1 + rand_int(0, 400);
        int period = 1 + rand_int(0, 30);
        int plain[420], cipher[420], back[420];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, BIFID_MAX_GRID);

        cm_bifid_encrypt(plain, len, sq1, sq2, 6, period, cipher);
        cm_bifid_decrypt(cipher, len, sq1, sq2, 6, period, back);
        CHECK(arrays_equal(back, plain, len),
            "cm-bifid 6x6 round-trip mismatch (len=%d period=%d)", len, period);
    }
}

int main(void) {
    seed_rand(20240620u);
    init_alphabet("J");                  // 25-letter alphabet (J merged into I)
    CHECK(g_alpha == PLAYFAIR_GRID, "alphabet size %d, expected %d", g_alpha, PLAYFAIR_GRID);

    test_cm_bifid_known_answer();
    test_cm_bifid_reduces_to_bifid();
    test_cm_bifid_roundtrip();
    test_cm_bifid_period_one();
    test_cm_bifid_6x6_roundtrip();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
