//
//  Unit + stress tests for the Nihilist Substitution primitives (encrypt / decrypt over the
//  three addition conventions, side-generic, label-aware).
//
//  Framework-free: build with `make test`, which links this against nihilist_sub.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Strategy:
//   - A hand-computed known-answer vector pins ALL THREE conventions at once on the SAME
//     plaintext/key/square: the carry-triggering positions make carry/no-carry/mod-100 produce
//     DIFFERENT ciphertext, so a cross-convention mix-up is caught (decrypting a carry cipher
//     under no-carry fails). The convention is exercised once per sub-type.
//   - Stress round-trips (>=5000 per convention) over random squares x random additive keys x
//     random lengths x random periods (incl. p=1, p>len, incomplete final period) assert exact
//     decrypt==plaintext AND that every legal-plaintext position decrypts as legal (n_valid==n).
//   - Keyed-label stress (>=2000 per convention) asserts the round-trip under random 1..5 label
//     permutations AND that a keyed-label cipher equals the SAME cipher under fixed labels with
//     the square relabelled (the "labels fold into the square" fact the solver relies on).
//   - A side-generic 6x6 round-trip per convention, and the validity predicate asserted vs V.
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

// Build pos[] (letter -> cell) from grid[] (cell -> letter).
static void build_inverse(const int grid[], int pos[], int n) {
    for (int p = 0; p < n; p++) pos[grid[p]] = p;
}

static const char *conv_name(int conv) {
    return conv == NIH_ADD_CARRY ? "carry" : conv == NIH_ADD_NOCARRY ? "nc" : "m100";
}

// --- Known-answer vector (hand-computed) --------------------------------------
//
// Identity 5x5 square over the 25-letter J-merged alphabet (ABCDE FGHIK LMNOP QRSTU VWXYZ),
// fixed labels 1..5, plaintext "ZAEZ", additive key "ZK" (period 2). Coordinate numbers
// (row+1)(col+1):  A=11  E=15  K=25  Z=55. Key Z=55, K=25.
//   pos0 Z+Z: carry 110, nc 00,  m100 10   <- distinguishes ALL THREE
//   pos1 A+K: carry 36,  nc 36,  m100 36
//   pos2 E+Z: carry 70,  nc 60,  m100 70   <- distinguishes no-carry
//   pos3 Z+K: carry 80,  nc 70,  m100 80
static void test_known_answer(void) {
    int grid[NIHILIST_SUB_GRID];
    int gn = str_to_idx("ABCDEFGHIKLMNOPQRSTUVWXYZ", grid);   // identity 0..24
    CHECK(gn == NIHILIST_SUB_GRID, "KAT alphabet is not 25 letters (%d)", gn);

    int rowlbl[NIHILIST_SUB_SIDE], collbl[NIHILIST_SUB_SIDE];
    nihilist_sub_fixed_labels(rowlbl, collbl, NIHILIST_SUB_SIDE);

    int pos[NIHILIST_SUB_GRID];
    build_inverse(grid, pos, NIHILIST_SUB_GRID);

    int plain[4];   str_to_idx("ZAEZ", plain);
    int keylt[2];   str_to_idx("ZK", keylt);
    int key_cells[2] = { pos[keylt[0]], pos[keylt[1]] };   // cells of Z, K -> 55, 25

    const int want_carry[4] = { 110, 36, 70, 80 };
    const int want_nc[4]    = {   0, 36, 60, 70 };
    const int want_m100[4]  = {  10, 36, 70, 80 };
    const int *want[3] = { want_carry, want_nc, want_m100 };
    const int convs[3] = { NIH_ADD_CARRY, NIH_ADD_NOCARRY, NIH_ADD_MOD100 };

    for (int v = 0; v < 3; v++) {
        int out[4];
        nihilist_sub_encrypt(plain, 4, grid, rowlbl, collbl, NIHILIST_SUB_SIDE,
            key_cells, 2, convs[v], out);
        CHECK(arrays_equal(out, want[v], 4),
            "KAT encrypt mismatch (%s): got {%d %d %d %d}", conv_name(convs[v]),
            out[0], out[1], out[2], out[3]);

        int back[4];
        int nv = nihilist_sub_decrypt(out, 4, grid, rowlbl, collbl, NIHILIST_SUB_SIDE,
            key_cells, 2, convs[v], back);
        CHECK(arrays_equal(back, plain, 4) && nv == 4,
            "KAT round-trip mismatch (%s) nv=%d", conv_name(convs[v]), nv);
    }

    // The three ciphertexts are pairwise distinct (the conventions are genuinely different
    // functions) -- here position 0 alone separates all three (110 / 0 / 10).
    CHECK(!arrays_equal(want_carry, want_nc, 4), "carry and no-carry ciphertext coincide");
    CHECK(!arrays_equal(want_nc, want_m100, 4),  "no-carry and mod-100 ciphertext coincide");
    CHECK(!arrays_equal(want_carry, want_m100, 4), "carry and mod-100 ciphertext coincide");

    // Cross-convention: the wrapped (no-carry / mod-100) ciphertexts -- whose position 0 is
    // 0 / 10 -- do NOT decrypt back to the plaintext under the CARRY rule (0-55 and 10-55 are
    // out of range, so the position is illegal). (The reverse direction can coincide when the
    // carry value never needed reducing, so only this robust direction is asserted.)
    for (int v = 1; v < 3; v++) {
        int back[4];
        nihilist_sub_decrypt(want[v], 4, grid, rowlbl, collbl, NIHILIST_SUB_SIDE,
            key_cells, 2, NIH_ADD_CARRY, back);
        CHECK(!arrays_equal(back, plain, 4),
            "%s cipher wrongly decrypts under carry", conv_name(convs[v]));
    }
}

// --- validity predicate vs the legal set V ------------------------------------
static void test_validity(void) {
    int n_legal = 0;
    for (int num = 0; num <= 99; num++) {
        int dr = num / 10, dc = num % 10;
        int legal = (dr >= 1 && dr <= 5 && dc >= 1 && dc <= 5);
        CHECK(nihilist_sub_num_valid(num, 5) == legal, "validity(%d) wrong", num);
        if (legal) n_legal++;
    }
    CHECK(n_legal == 25, "expected 25 legal coordinates, got %d", n_legal);
    // Out-of-2-digit numbers (carry can produce 100..110) are not legal at side 5.
    for (int num = 100; num <= 110; num++)
        CHECK(!nihilist_sub_num_valid(num, 5), "validity(%d) should be illegal at side 5", num);
}

// --- random permutation of 1..side into lbl[] ---------------------------------
static void random_labels(int lbl[], int side) {
    for (int i = 0; i < side; i++) lbl[i] = i + 1;
    for (int i = side - 1; i > 0; i--) { int j = rand_int(0, i + 1); int t = lbl[i]; lbl[i] = lbl[j]; lbl[j] = t; }
}

// --- stress round-trips (per convention, fixed labels) ------------------------
static void test_roundtrip(int conv) {
    int rowlbl[NIHILIST_SUB_SIDE], collbl[NIHILIST_SUB_SIDE];
    nihilist_sub_fixed_labels(rowlbl, collbl, NIHILIST_SUB_SIDE);
    int side = NIHILIST_SUB_SIDE, ncell = side * side;

    for (int t = 0; t < 5000; t++) {
        int grid[NIHILIST_SUB_GRID];
        for (int i = 0; i < ncell; i++) grid[i] = i;
        shuffle(grid, ncell);

        int len = 1 + rand_int(0, 600);
        int period = 1 + rand_int(0, 40);              // includes p>len and p==1
        int plain[640], key_cells[64], cipher[640], back[640];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, ncell);
        for (int j = 0; j < period && j < 64; j++) key_cells[j] = rand_int(0, ncell);
        if (period > 64) period = 64;

        nihilist_sub_encrypt(plain, len, grid, rowlbl, collbl, side, key_cells, period, conv, cipher);
        int nv = nihilist_sub_decrypt(cipher, len, grid, rowlbl, collbl, side, key_cells, period, conv, back);
        CHECK(arrays_equal(back, plain, len) && nv == len,
            "%s round-trip mismatch (len=%d period=%d nv=%d)", conv_name(conv), len, period, nv);
    }
}

// --- keyed-label stress + "labels fold into the square" -----------------------
static void test_keyed_labels(int conv) {
    int side = NIHILIST_SUB_SIDE, ncell = side * side;
    int fixrow[NIHILIST_SUB_SIDE], fixcol[NIHILIST_SUB_SIDE];
    nihilist_sub_fixed_labels(fixrow, fixcol, side);

    for (int t = 0; t < 2000; t++) {
        int grid[NIHILIST_SUB_GRID];
        for (int i = 0; i < ncell; i++) grid[i] = i;
        shuffle(grid, ncell);
        int rowlbl[NIHILIST_SUB_SIDE], collbl[NIHILIST_SUB_SIDE];
        random_labels(rowlbl, side);
        random_labels(collbl, side);

        int len = 1 + rand_int(0, 300);
        int period = 1 + rand_int(0, 12);
        int plain[320], key_cells[16], cipher[320], back[320];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, ncell);
        for (int j = 0; j < period; j++) key_cells[j] = rand_int(0, ncell);

        // Round-trip under the keyed labels.
        nihilist_sub_encrypt(plain, len, grid, rowlbl, collbl, side, key_cells, period, conv, cipher);
        int nv = nihilist_sub_decrypt(cipher, len, grid, rowlbl, collbl, side, key_cells, period, conv, back);
        CHECK(arrays_equal(back, plain, len) && nv == len,
            "%s keyed-label round-trip mismatch (len=%d period=%d)", conv_name(conv), len, period);

        // The label permutation folds into the square: relabel via phi(c) = the FIXED cell with
        // the same coordinate number as cell c under the keyed labels. Then the keyed-label
        // cipher equals the fixed-label cipher over the relabelled square + relabelled key.
        int gprime[NIHILIST_SUB_GRID], kprime[16];
        for (int c = 0; c < ncell; c++) {
            int phi = (rowlbl[c / side] - 1) * side + (collbl[c % side] - 1);
            gprime[phi] = grid[c];
        }
        for (int j = 0; j < period; j++) {
            int c = key_cells[j];
            kprime[j] = (rowlbl[c / side] - 1) * side + (collbl[c % side] - 1);
        }
        int cipher2[320];
        nihilist_sub_encrypt(plain, len, gprime, fixrow, fixcol, side, kprime, period, conv, cipher2);
        CHECK(arrays_equal(cipher2, cipher, len),
            "%s keyed-label cipher != relabelled fixed-label cipher (len=%d)", conv_name(conv), len);
    }
}

// --- side-generic 6x6 round-trip ----------------------------------------------
static void test_6x6_roundtrip(int conv) {
    int side = 6, ncell = side * side;
    int rowlbl[NIHILIST_SUB_MAX_SIDE], collbl[NIHILIST_SUB_MAX_SIDE];
    nihilist_sub_fixed_labels(rowlbl, collbl, side);

    for (int t = 0; t < 2000; t++) {
        int grid[NIHILIST_SUB_MAX_GRID];
        for (int i = 0; i < ncell; i++) grid[i] = i;
        shuffle(grid, ncell);

        int len = 1 + rand_int(0, 300);
        int period = 1 + rand_int(0, 20);
        int plain[320], key_cells[24], cipher[320], back[320];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, ncell);
        for (int j = 0; j < period; j++) key_cells[j] = rand_int(0, ncell);

        nihilist_sub_encrypt(plain, len, grid, rowlbl, collbl, side, key_cells, period, conv, cipher);
        int nv = nihilist_sub_decrypt(cipher, len, grid, rowlbl, collbl, side, key_cells, period, conv, back);
        CHECK(arrays_equal(back, plain, len) && nv == len,
            "%s 6x6 round-trip mismatch (len=%d period=%d)", conv_name(conv), len, period);
    }
}

int main(void) {
    seed_rand(20240620u);
    init_alphabet("J");
    CHECK(g_alpha == NIHILIST_SUB_GRID, "alphabet size %d, expected %d", g_alpha, NIHILIST_SUB_GRID);

    test_known_answer();
    test_validity();

    const int convs[3] = { NIH_ADD_CARRY, NIH_ADD_NOCARRY, NIH_ADD_MOD100 };
    for (int v = 0; v < 3; v++) {
        test_roundtrip(convs[v]);
        test_keyed_labels(convs[v]);
        test_6x6_roundtrip(convs[v]);
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) { printf("TESTS FAILED\n"); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
