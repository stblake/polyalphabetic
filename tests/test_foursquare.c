//
//  Unit tests for the Four-Square primitives (encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against foursquare.c +
//  utils.c. Exits non-zero if any check fails.
//
//  Strategy: the Wikipedia "Four-square cipher" worked example pins the convention -- the
//  two keyed squares EXAMPLE / KEYWORD (omit Q), the fixed standard plaintext squares, and
//  the rectangle rule (HE -> FY, ...) -- so a row/column mix-up or a square-role swap is
//  caught, not just a self-consistent round-trip. Then decrypt(encrypt(P)) == P over random
//  keyed squares and random lengths (incl. odd, and a side-generic 6x6) covers the general
//  case, and a degenerate check (both keyed squares the identity) pins the exact coordinate
//  algebra.
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

// Explicit A..Z string -> alphabet indices via the CURRENT alphabet map (no J->I merge).
// The string must not contain the excluded letter (the KAT squares/texts never do).
static int to_idx(const char *s, int out[]) {
    int n = 0;
    for (int i = 0; s[i]; i++) {
        int c = toupper((unsigned char) s[i]);
        if (c < 'A' || c > 'Z') continue;
        out[n++] = g_char_to_idx[c];
    }
    return n;
}

static void idx_to_str(const int a[], int len, char out[]) {
    for (int i = 0; i < len; i++) out[i] = index_to_char(a[i]);
    out[len] = '\0';
}

// --- known-answer vector (Wikipedia "Four-square cipher" worked example) ----------
//
//   UR (EXAMPLE)        LL (KEYWORD)       -- both omit Q; UL/LR are the standard square
//   pt HELPMEOBIWANKENOBI -> ct FYGMKYHOBXMFKKKIMD

static void test_foursquare_kat(void) {
    init_alphabet("Q");                          // 25 letters, Q excluded (Wikipedia convention)
    int ur[SQUARE_GRID], ll[SQUARE_GRID];
    to_idx("EXAMPLBCDFGHIJKNORSTUVWYZ", ur);
    to_idx("KEYWORDABCFGHIJLMNPSTUVXZ", ll);

    int pt[64];
    int n = to_idx("HELPMEOBIWANKENOBI", pt);
    int ct[64];
    foursquare_encrypt(pt, n, ur, ll, SQUARE_SIDE, ct);
    char cb[65]; idx_to_str(ct, n, cb);
    CHECK(strcmp(cb, "FYGMKYHOBXMFKKKIMD") == 0,
        "foursquare KAT mismatch: got '%s'", cb);

    int back[64];
    foursquare_decrypt(ct, n, ur, ll, SQUARE_SIDE, back);
    CHECK(arrays_equal(back, pt, n), "foursquare decrypt round-trip mismatch");
}

// --- round-trip over random keyed squares + random lengths (incl. 6x6) ------------

static void random_square(int sq[], int n) {
    for (int i = 0; i < n; i++) sq[i] = i;
    shuffle(sq, n);
}

static void test_foursquare_roundtrip(void) {
    for (int t = 0; t < 4000; t++) {
        int ur[SQUARE_GRID], ll[SQUARE_GRID];
        random_square(ur, SQUARE_GRID);
        random_square(ll, SQUARE_GRID);

        int len = 1 + rand_int(0, 400);          // include odd lengths (lone trailing letter)
        int pt[512], ct[512], back[512];
        for (int i = 0; i < len; i++) pt[i] = rand_int(0, SQUARE_GRID);
        foursquare_encrypt(pt, len, ur, ll, SQUARE_SIDE, ct);
        foursquare_decrypt(ct, len, ur, ll, SQUARE_SIDE, back);
        CHECK(arrays_equal(back, pt, len), "foursquare round-trip mismatch (len=%d)", len);
    }
    // Side-generic 6x6 (36-cell keyed squares).
    for (int t = 0; t < 2000; t++) {
        int ur[36], ll[36];
        random_square(ur, 36);
        random_square(ll, 36);
        int len = 1 + rand_int(0, 300);
        int pt[512], ct[512], back[512];
        for (int i = 0; i < len; i++) pt[i] = rand_int(0, 36);
        foursquare_encrypt(pt, len, ur, ll, 6, ct);
        foursquare_decrypt(ct, len, ur, ll, 6, back);
        CHECK(arrays_equal(back, pt, len), "foursquare 6x6 round-trip mismatch (len=%d)", len);
    }
}

// --- degenerate identity squares --------------------------------------------------
//
// With both keyed squares the identity (cell p holds letter p, same as the plaintext
// squares), the rule reduces to pure coordinate algebra: a digraph (p1, p2) at coords
// (r1,c1),(r2,c2) enciphers to (r1*side+c2, r2*side+c1) -- i.e. the two letters keep their
// rows but exchange columns. Pins the exact index math independent of the KAT.

static void test_foursquare_identity(void) {
    int s = SQUARE_SIDE, n = SQUARE_GRID;
    int id[SQUARE_GRID];
    foursquare_standard_square(id, n);
    for (int i = 0; i < n; i++) CHECK(id[i] == i, "standard_square not identity at %d", i);

    for (int t = 0; t < 500; t++) {
        int p1 = rand_int(0, n), p2 = rand_int(0, n);
        int r1 = p1 / s, c1 = p1 % s, r2 = p2 / s, c2 = p2 % s;
        int pt[2] = { p1, p2 }, ct[2];
        foursquare_encrypt(pt, 2, id, id, s, ct);
        CHECK(ct[0] == r1 * s + c2 && ct[1] == r2 * s + c1,
            "foursquare identity-square algebra wrong");
    }
}

int main(void) {
    seed_rand(20240624u);

    test_foursquare_kat();

    init_alphabet("J");                          // back to a 25-letter alphabet for the rest
    test_foursquare_roundtrip();
    test_foursquare_identity();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
