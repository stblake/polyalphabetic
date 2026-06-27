//
//  Unit tests for the Slidefair cipher primitives (slidefair.c).
//
//  Framework-free: build with `make test`, which links this against slidefair.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Slidefair (ACA "periodic digraphic Vigenere/Variant/Beaufort") enciphers consecutive DIGRAPHS
//  over a two-row slide: the TOP row is the standard alphabet, the BOTTOM row a shift alphabet keyed
//  by the column key letter (Vig: col+k, Var: col-k, Beau: k-col). The plaintext pair forms diagonal
//  corners of a 2-row rectangle; the substitutes are the other two corners (TOP first); a vertical
//  pair maps to the pair one column to the right (decrypt: to the left). Full 26-letter alphabet (no
//  J->I merge), so strings map via s[i]-'A'. Pinned here:
//    - the ACA mini examples for all three variants: key B, ca -> ZD/BB/BZ, de -> EF/FC/XY
//      (de is the vertical/same-column case);
//    - the full ACA Vigenere example: keyword DIGRAPH, "the slidefair can be used with vigenere
//      variant or beaufort" -> EWKMCRNUAFCXTJYQMMYYFUTIGWZPKHJMPKBSAIECKVCFMIILCI, and decrypt back;
//    - decrypt(encrypt(.)) == identity over random keys x lengths x all three variants (incl. odd
//      length -> lone final letter passes through);
//    - per-column independence (a key change touches only that column's digraphs);
//    - edge cases: P=1, P>ndigraphs, a single digraph, odd length.
//

#include "colossus.h"
#include "slidefair.h"

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
static void str_to_idx(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) out[i] = (toupper((unsigned char) s[i]) - 'A');
}
static int idx_eq_str(const int a[], const char *s) {
    for (int i = 0; s[i]; i++) if (a[i] != (toupper((unsigned char) s[i]) - 'A')) return 0;
    return 1;
}
static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

// --- known-answer pairs (the ACA mini examples, key letter B) ---------------

static void test_pair_kats(void) {
    int c1, c2;
    int B = 'B' - 'A';
    int ca[2] = { 'C'-'A', 'A'-'A' }, de[2] = { 'D'-'A', 'E'-'A' };

    // ca (rectangle) and de (vertical / same column) for each variant.
    slidefair_pair_enc(ca[0], ca[1], B, SLIDEFAIR, &c1, &c2);
    CHECK(c1 == 'Z'-'A' && c2 == 'D'-'A', "Vig ca -> ZD, got %c%c", c1+'A', c2+'A');
    slidefair_pair_enc(de[0], de[1], B, SLIDEFAIR, &c1, &c2);
    CHECK(c1 == 'E'-'A' && c2 == 'F'-'A', "Vig de -> EF, got %c%c", c1+'A', c2+'A');

    slidefair_pair_enc(ca[0], ca[1], B, SLIDEFAIR_VAR, &c1, &c2);
    CHECK(c1 == 'B'-'A' && c2 == 'B'-'A', "Var ca -> BB, got %c%c", c1+'A', c2+'A');
    slidefair_pair_enc(de[0], de[1], B, SLIDEFAIR_VAR, &c1, &c2);
    CHECK(c1 == 'F'-'A' && c2 == 'C'-'A', "Var de -> FC, got %c%c", c1+'A', c2+'A');

    slidefair_pair_enc(ca[0], ca[1], B, SLIDEFAIR_BEAU, &c1, &c2);
    CHECK(c1 == 'B'-'A' && c2 == 'Z'-'A', "Beau ca -> BZ, got %c%c", c1+'A', c2+'A');
    slidefair_pair_enc(de[0], de[1], B, SLIDEFAIR_BEAU, &c1, &c2);
    CHECK(c1 == 'X'-'A' && c2 == 'Y'-'A', "Beau de -> XY, got %c%c", c1+'A', c2+'A');

    // Each encrypt pair must invert under decrypt, over every key x variant x pair.
    int types[3] = { SLIDEFAIR, SLIDEFAIR_VAR, SLIDEFAIR_BEAU };
    for (int t = 0; t < 3; t++)
        for (int k = 0; k < 26; k++)
            for (int p1 = 0; p1 < 26; p1++)
                for (int p2 = 0; p2 < 26; p2++) {
                    int x, y, a, b;
                    slidefair_pair_enc(p1, p2, k, types[t], &x, &y);
                    slidefair_pair_dec(x, y, k, types[t], &a, &b);
                    CHECK(a == p1 && b == p2,
                        "pair not invertible: t=%d k=%d (%d,%d)->(%d,%d)->(%d,%d)",
                        t, k, p1, p2, x, y, a, b);
                }
}

// --- full ACA worked example (keyword DIGRAPH, Vigenere) --------------------

static void test_full_example(void) {
    const char *pt_s = "THESLIDEFAIRCANBEUSEDWITHVIGENEREVARIANTORBEAUFORT";  // 50 letters, even
    const char *ct_s = "EWKMCRNUAFCXTJYQMMYYFUTIGWZPKHJMPKBSAIECKVCFMIILCI";
    int n = slen(pt_s);
    int pt[64], ct[64], out[64];
    str_to_idx(pt_s, pt);
    int key[7]; str_to_idx("DIGRAPH", key);

    slidefair_encrypt(ct, pt, n, key, 7, SLIDEFAIR);
    CHECK(idx_eq_str(ct, ct_s), "DIGRAPH end-to-end ciphertext mismatch");

    slidefair_decrypt(out, ct, n, key, 7, SLIDEFAIR);
    CHECK(arrays_equal(out, pt, n), "DIGRAPH decrypt(ct) != plaintext");
}

// --- round-trip over random keys x lengths x variants -----------------------

static unsigned long rng = 0x9e3779b97f4a7c15UL;
static int rnd(int m) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (int)(rng % m); }

static void test_roundtrip_random(void) {
    int types[3] = { SLIDEFAIR, SLIDEFAIR_VAR, SLIDEFAIR_BEAU };
    int pt[2048], ct[2048], back[2048];
    for (int trial = 0; trial < 6000; trial++) {
        int type = types[trial % 3];
        int P = 1 + rnd(14);
        int n = 1 + rnd(600);                              // includes odd lengths
        int key[16];
        for (int c = 0; c < P; c++) key[c] = rnd(26);
        for (int i = 0; i < n; i++) pt[i] = rnd(26);

        slidefair_encrypt(ct, pt, n, key, P, type);
        slidefair_decrypt(back, ct, n, key, P, type);
        CHECK(arrays_equal(back, pt, n),
            "round-trip failed: type=%d P=%d n=%d trial=%d", type, P, n, trial);

        // A lone final letter (odd n) has no partner -> passes through unchanged.
        if (n & 1) CHECK(ct[n-1] == pt[n-1], "odd length: lone final letter not passed through");
    }
}

// --- per-column independence -------------------------------------------------

static void test_column_independence(void) {
    int P = 7, ndg = 9 * P, n = 2 * ndg;                   // 9 full rows of P digraphs
    int pt[400], a[400], b[400];
    int key[7], key2[7];
    for (int c = 0; c < P; c++) key[c] = key2[c] = rnd(26);
    for (int i = 0; i < n; i++) pt[i] = rnd(26);
    int col = 3;
    key2[col] = (key[col] + 1 + rnd(25)) % 26;             // change exactly one column

    slidefair_encrypt(a, pt, n, key, P, SLIDEFAIR);
    slidefair_encrypt(b, pt, n, key2, P, SLIDEFAIR);
    for (int i = 0; i < ndg; i++) {
        int in_col = (i % P) == col;
        if (!in_col)
            CHECK(a[2*i] == b[2*i] && a[2*i+1] == b[2*i+1],
                "column %d key change leaked to digraph %d", col, i);
    }
}

// --- edge cases --------------------------------------------------------------

static void test_edges(void) {
    int key[8];
    for (int c = 0; c < 8; c++) key[c] = rnd(26);

    // P=1: every digraph under the same key; round-trip.
    int pt[10], ct[10], back[10];
    for (int i = 0; i < 10; i++) pt[i] = rnd(26);
    slidefair_encrypt(ct, pt, 10, key, 1, SLIDEFAIR_BEAU);
    slidefair_decrypt(back, ct, 10, key, 1, SLIDEFAIR_BEAU);
    CHECK(arrays_equal(back, pt, 10), "P=1 round-trip failed");

    // P > number of digraphs: only key[0..ndg-1] used; still a clean round-trip.
    slidefair_encrypt(ct, pt, 6, key, 8, SLIDEFAIR);       // 3 digraphs, P=8
    slidefair_decrypt(back, ct, 6, key, 8, SLIDEFAIR);
    CHECK(arrays_equal(back, pt, 6), "P>ndigraphs round-trip failed");

    // Odd length: lone final letter passes through.
    slidefair_encrypt(ct, pt, 5, key, 2, SLIDEFAIR_VAR);
    CHECK(ct[4] == pt[4], "odd length: final letter not passed through");
    slidefair_decrypt(back, ct, 5, key, 2, SLIDEFAIR_VAR);
    CHECK(arrays_equal(back, pt, 5), "odd length round-trip failed");

    // A single digraph: de (vig key B) -> EF.
    int de[2] = { 'D'-'A', 'E'-'A' }, one_ct[2];
    int kb[1] = { 'B'-'A' };
    slidefair_encrypt(one_ct, de, 2, kb, 1, SLIDEFAIR);
    CHECK(one_ct[0] == 'E'-'A' && one_ct[1] == 'F'-'A', "single digraph de (vig B) -> EF");
}

int main(void) {
    init_alphabet(NULL);                       // full 26-letter alphabet

    test_pair_kats();
    test_full_example();
    test_roundtrip_random();
    test_column_independence();
    test_edges();

    printf("test_slidefair: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
