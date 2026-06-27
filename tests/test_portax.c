//
//  Unit tests for the Portax cipher primitives (portax.c).
//
//  Framework-free: build with `make test`, which links this against portax.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Portax (ACA "periodic digraphic Porta") enciphers VERTICAL PAIRS over a Porta slide: the
//  plaintext is written row-major at width P, rows are paired (2g, 2g+1), and the pair in
//  column c is enciphered as a unit by the column key letter (only its Porta shift key/2
//  matters). Full 26-letter alphabet (no J->I merge), so strings map via s[i]-'A'. The map is
//  self-reciprocal (decrypt == encrypt). Pinned here:
//    - the ACA worked examples: key U/V (IN->JL, NO->UA, NA->DB same-column);
//      key E (TA->NM, BG->QH same-column); keyword EASY end-to-end -> NIJAMPBGQCWKHQJEUIKYMPAT;
//    - the involution (apply twice == identity) and decrypt == encrypt over random keys x lengths;
//    - per-column independence (a shift change touches only that column's cells);
//    - ragged final block (missing bottom row -> lone top letters pass through);
//    - edge cases: P=1, P>len, a single pair.
//

#include "colossus.h"
#include "portax.h"

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

// --- known-answer pairs (the ACA mini examples) -----------------------------

static void test_pair_kats(void) {
    int x, y;
    // Key U or V -> Porta shift 10.
    portax_pair('I'-'A', 'N'-'A', 10, &x, &y);
    CHECK(x == 'J'-'A' && y == 'L'-'A', "IN (s=10) -> JL, got %c%c", x+'A', y+'A');
    portax_pair('N'-'A', 'O'-'A', 10, &x, &y);
    CHECK(x == 'U'-'A' && y == 'A'-'A', "NO (s=10) -> UA, got %c%c", x+'A', y+'A');
    portax_pair('N'-'A', 'A'-'A', 10, &x, &y);   // same vertical line
    CHECK(x == 'D'-'A' && y == 'B'-'A', "NA (s=10) -> DB, got %c%c", x+'A', y+'A');
    // Key E -> Porta shift 2.
    portax_pair('T'-'A', 'A'-'A', 2, &x, &y);
    CHECK(x == 'N'-'A' && y == 'M'-'A', "TA (s=2) -> NM, got %c%c", x+'A', y+'A');
    portax_pair('B'-'A', 'G'-'A', 2, &x, &y);    // same vertical line
    CHECK(x == 'Q'-'A' && y == 'H'-'A', "BG (s=2) -> QH, got %c%c", x+'A', y+'A');

    // Every pair operation is an involution: applying it to its own output returns the input.
    for (int s = 0; s < 13; s++)
        for (int a = 0; a < 26; a++)
            for (int b = 0; b < 26; b++) {
                portax_pair(a, b, s, &x, &y);
                int a2, b2; portax_pair(x, y, s, &a2, &b2);
                CHECK(a2 == a && b2 == b,
                    "pair not involution: s=%d (%d,%d)->(%d,%d)->(%d,%d)", s, a, b, x, y, a2, b2);
            }
}

// --- full ACA worked example (keyword EASY) ---------------------------------

static void test_full_example(void) {
    // "the early bird gets the worm", written width 4, padded one X to fill 6 rows (24 letters):
    //   THEE / ARLY / BIRD / GETS / THEW / ORMX  ->  row-major THEEARLYBIRDGETSTHEWORMX
    const char *pt_s = "THEEARLYBIRDGETSTHEWORMX";
    const char *ct_s = "NIJAMPBGQCWKHQJEUIKYMPAT";
    int n = slen(pt_s);
    int pt[64], ct[64], out[64];
    str_to_idx(pt_s, pt);
    int key[4] = { 'E'-'A', 'A'-'A', 'S'-'A', 'Y'-'A' };   // keyword EASY (key letters 0..25)

    portax_encrypt(ct, pt, n, key, 4);
    CHECK(idx_eq_str(ct, ct_s), "EASY end-to-end ciphertext mismatch");

    // Self-reciprocal: deciphering the ciphertext returns the plaintext.
    portax_decrypt(out, ct, n, key, 4);
    CHECK(arrays_equal(out, pt, n), "EASY decrypt(ct) != plaintext");
}

// --- involution / round-trip over random keys x lengths ---------------------

static unsigned long rng = 0x9e3779b97f4a7c15UL;
static int rnd(int m) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (int)(rng % m); }

static void test_roundtrip_random(void) {
    int pt[2048], ct[2048], back[2048];
    for (int trial = 0; trial < 4000; trial++) {
        int P = 1 + rnd(14);
        int n = 1 + rnd(600);
        int shifts[16];
        for (int c = 0; c < P; c++) shifts[c] = rnd(13);
        for (int i = 0; i < n; i++) pt[i] = rnd(26);

        portax_apply(pt, n, shifts, P, ct);
        portax_apply(ct, n, shifts, P, back);              // self-inverse
        CHECK(arrays_equal(back, pt, n),
            "portax_apply not involution: P=%d n=%d trial=%d", P, n, trial);

        // key-letter wrapper agrees with shift form (key letter 2s and 2s+1 both -> shift s).
        int key[16];
        for (int c = 0; c < P; c++) key[c] = 2 * shifts[c] + (rnd(2));
        portax_encrypt(back, pt, n, key, P);
        CHECK(arrays_equal(back, ct, n),
            "key-letter wrapper != shift form: P=%d n=%d", P, n);
    }
}

// --- per-column independence -------------------------------------------------

static void test_column_independence(void) {
    int pt[400], a[400], b[400];
    int P = 7, n = 7 * 2 * 9;                  // 9 full row-pairs
    int shifts[7], shifts2[7];
    for (int c = 0; c < P; c++) shifts[c] = shifts2[c] = rnd(13);
    for (int i = 0; i < n; i++) pt[i] = rnd(26);
    int col = 3;
    shifts2[col] = (shifts[col] + 1 + rnd(12)) % 13;        // change exactly one column

    portax_apply(pt, n, shifts, P, a);
    portax_apply(pt, n, shifts2, P, b);
    for (int i = 0; i < n; i++) {
        int off = i % (2 * P);
        int in_col = (off == col) || (off == col + P);      // top or bottom cell of `col`
        if (!in_col) CHECK(a[i] == b[i],
            "column %d shift change leaked to position %d (off=%d)", col, i, off);
    }
}

// --- ragged final block ------------------------------------------------------

static void test_ragged(void) {
    // P=4, length 4*2 + 4 + 2 = 14: a full block, then a top row of 4 and a bottom row of 2,
    // so columns 2,3 of the second block have lone top letters (no partner) -> passthrough.
    int P = 4, n = 14;
    int shifts[4] = { 1, 5, 9, 12 };
    int pt[14], ct[14], back[14];
    for (int i = 0; i < n; i++) pt[i] = rnd(26);
    portax_apply(pt, n, shifts, P, ct);
    // positions 12,13 are the lone top letters of columns 2,3 (block start 8, top row 8..11,
    // bottom row would be 12..15 but only 12,13 exist -> those pair with 8,9; 10,11 are lone).
    CHECK(ct[10] == pt[10] && ct[11] == pt[11], "ragged: lone top letters not passed through");
    portax_apply(ct, n, shifts, P, back);
    CHECK(arrays_equal(back, pt, n), "ragged: round-trip failed");
}

// --- edge cases --------------------------------------------------------------

static void test_edges(void) {
    int shifts[8];
    for (int c = 0; c < 8; c++) shifts[c] = rnd(13);

    // P=1: a single column, pairs are (row0,row1),(row2,row3),...
    int pt[10], ct[10], back[10];
    for (int i = 0; i < 10; i++) pt[i] = rnd(26);
    portax_apply(pt, 10, shifts, 1, ct);
    portax_apply(ct, 10, shifts, 1, back);
    CHECK(arrays_equal(back, pt, 10), "P=1 round-trip failed");

    // P > len: block bigger than the whole text -> all top cells, no partners -> identity.
    portax_apply(pt, 3, shifts, 8, ct);
    CHECK(arrays_equal(ct, pt, 3), "P>len should be identity (all lone tops)");

    // A single pair (n == 2P with one row-pair, P=1).
    int two_pt[2] = { 'B'-'A', 'G'-'A' }, two_ct[2];
    int s2[1] = { 2 };
    portax_apply(two_pt, 2, s2, 1, two_ct);
    CHECK(two_ct[0] == 'Q'-'A' && two_ct[1] == 'H'-'A', "single pair BG (s=2) -> QH");
}

int main(void) {
    init_alphabet(NULL);                       // full 26-letter alphabet

    test_pair_kats();
    test_full_example();
    test_roundtrip_random();
    test_column_independence();
    test_ragged();
    test_edges();

    printf("test_portax: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
