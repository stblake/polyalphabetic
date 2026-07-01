//
//  Unit tests for the Tri-Square primitives (encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against trisquare.c + bifid.c
//  (for bifid_build_inverse) + utils.c. Exits non-zero if any check fails.
//
//  Strategy: the ACA "Tri-Square" worked example pins the convention as a DECRYPT-only
//  known-answer vector -- the three printed squares and CT RHLQXR... -> THREEKEYSQUARESUSEDX
//  -- so a row/column or square-role mix-up is caught (the ACA CT used arbitrary polyphonic
//  clerk choices we do not reproduce, but decryption is deterministic). Then decrypt(encrypt(P))
//  == P over random squares and random lengths (incl. odd, and a side-generic 6x6) covers the
//  general case, and a POLYPHONIC-INVARIANCE check enumerates all 25 (c0,c2) alternatives for a
//  digraph and asserts every one decrypts identically -- the Tri-Square analogue of the
//  Two-Square transparency / Four-Square identity-algebra structural test.
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

// --- known-answer vector (ACA "Tri-Square" worked example, decrypt-only) -----------
//
//   sq1 NSFMUOAGPWVBHQXECIRYLDKTZ   sq2 READINGBCFHKLMOPQSTUVWXYZ
//   sq3 PASTINOQRMLYZUEKXWVBHGFDC
//   ct RHLQXRLXOEVZBATXSERXDDIUAAABFZ -> pt THREEKEYSQUARESUSEDX

static void test_trisquare_kat(void) {
    init_alphabet("J");                          // 25 letters, J merged into I
    int sq1[SQUARE_GRID], sq2[SQUARE_GRID], sq3[SQUARE_GRID];
    to_idx("NSFMUOAGPWVBHQXECIRYLDKTZ", sq1);
    to_idx("READINGBCFHKLMOPQSTUVWXYZ", sq2);
    to_idx("PASTINOQRMLYZUEKXWVBHGFDC", sq3);

    int ct[64];
    int clen = to_idx("RHLQXRLXOEVZBATXSERXDDIUAAABFZ", ct);
    int back[64];
    int plen = trisquare_decrypt(ct, clen, sq1, sq2, sq3, SQUARE_SIDE, back);

    int expect[64];
    int elen = to_idx("THREEKEYSQUARESUSEDX", expect);
    CHECK(plen == elen, "trisquare KAT length %d, expected %d", plen, elen);
    CHECK(arrays_equal(back, expect, elen), "trisquare KAT decrypt mismatch");
}

// --- round-trip over random keyed squares + random lengths (incl. 6x6) ------------

static void random_square(int sq[], int n) {
    for (int i = 0; i < n; i++) sq[i] = i;
    shuffle(sq, n);
}

static void test_trisquare_roundtrip(void) {
    for (int t = 0; t < 4000; t++) {
        int sq1[SQUARE_GRID], sq2[SQUARE_GRID], sq3[SQUARE_GRID];
        random_square(sq1, SQUARE_GRID);
        random_square(sq2, SQUARE_GRID);
        random_square(sq3, SQUARE_GRID);

        int len = 1 + rand_int(0, 400);          // include odd lengths (lone trailing letter)
        int pt[512], ct[1024], back[512];
        for (int i = 0; i < len; i++) pt[i] = rand_int(0, SQUARE_GRID);
        int clen = trisquare_encrypt(pt, len, sq1, sq2, sq3, SQUARE_SIDE, ct);
        CHECK(clen == 3 * (len / 2) + (len % 2), "trisquare cipher length %d wrong (len=%d)", clen, len);
        int plen = trisquare_decrypt(ct, clen, sq1, sq2, sq3, SQUARE_SIDE, back);
        CHECK(plen == len && arrays_equal(back, pt, len),
            "trisquare round-trip mismatch (len=%d)", len);
    }
    // Side-generic 6x6 (36-cell keyed squares).
    for (int t = 0; t < 2000; t++) {
        int sq1[36], sq2[36], sq3[36];
        random_square(sq1, 36);
        random_square(sq2, 36);
        random_square(sq3, 36);
        int len = 1 + rand_int(0, 300);
        int pt[512], ct[1024], back[512];
        for (int i = 0; i < len; i++) pt[i] = rand_int(0, 36);
        int clen = trisquare_encrypt(pt, len, sq1, sq2, sq3, 6, ct);
        int plen = trisquare_decrypt(ct, clen, sq1, sq2, sq3, 6, back);
        CHECK(plen == len && arrays_equal(back, pt, len),
            "trisquare 6x6 round-trip mismatch (len=%d)", len);
    }
}

// --- polyphonic-invariance --------------------------------------------------------
//
// The first and third cipher letters are POLYPHONIC on encode: c0 may be any of the 5 letters
// in p1's column of sq1, c2 any of the 5 in p2's row of sq2 (the middle letter is fixed). A
// square maps any column member back to its column and any row member back to its row, so
// decryption must recover the SAME digraph for all 25 (c0, c2) alternatives. This pins that
// invariance directly (independent of which representative trisquare_encrypt happens to pick).

static void test_trisquare_polyphonic(void) {
    int s = SQUARE_SIDE, n = SQUARE_GRID;
    for (int t = 0; t < 500; t++) {
        int sq1[SQUARE_GRID], sq2[SQUARE_GRID], sq3[SQUARE_GRID];
        random_square(sq1, n);
        random_square(sq2, n);
        random_square(sq3, n);
        int pos1[SQUARE_GRID], pos2[SQUARE_GRID];
        bifid_build_inverse(sq1, pos1, n);
        bifid_build_inverse(sq2, pos2, n);

        int p1 = rand_int(0, n), p2 = rand_int(0, n);
        int a = pos1[p1], r1 = a / s, c1 = a % s;    // p1 in sq1 (column c1)
        int b = pos2[p2], r2 = b / s, c2 = b % s;    // p2 in sq2 (row r2)
        int mid = sq3[r1 * s + c2];                   // the fixed middle letter

        for (int cr = 0; cr < s; cr++)                // any row of p1's column ...
            for (int cc = 0; cc < s; cc++) {          // ... any column of p2's row
                int ct[3] = { sq1[cr * s + c1], mid, sq2[r2 * s + cc] };
                int back[2];
                trisquare_decrypt(ct, 3, sq1, sq2, sq3, s, back);
                CHECK(back[0] == p1 && back[1] == p2,
                    "trisquare polyphonic decrypt changed the digraph (cr=%d cc=%d)", cr, cc);
            }
    }
}

int main(void) {
    seed_rand(20240624u);

    test_trisquare_kat();                        // sets init_alphabet("J")
    test_trisquare_roundtrip();
    test_trisquare_polyphonic();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
