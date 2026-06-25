//
//  Unit tests for the ADFGVX / ADFGX primitives (fractionation + columnar transposition).
//
//  Framework-free: build with `make test`, which links this against adfgvx.c + bifid.c
//  (keyed-square build/inverse) + transpositions.c (decrypt_columnar) + utils.c. Exits
//  non-zero if any check fails.
//
//  Strategy: a HAND-COMPUTED known-answer vector pins the actual convention end to end
//  (the fractionation, the row-then-column label order, and the columnar read order), so
//  a sign flip or a row/column or column-order mix-up is caught, not just a self-
//  consistent round-trip. The KAT (worked by hand in the comment below) is:
//
//    square = the IDENTITY 5x5 over the 25-letter J->I alphabet (cell p holds letter p):
//        A B C D E / F G H I K / L M N O P / Q R S T U / V W X Y Z
//    plaintext "ATTACK" -> indices [0,18,18,0,2,9]
//    fractionate (cell = letter index; row=cell/5, col=cell%5), labels {A,D,F,G,X}=0..4:
//        A(0)->(0,0)=AA  T(18)->(3,3)=GG  T->GG  A->AA  C(2)->(0,2)=AF  K(9)->(1,4)=DX
//      coordinate stream (length 12): 0 0 3 3 3 3 0 0 0 2 1 4
//    columnar, keyword "KEY" -> read columns in order [1,0,2] (E<K<Y), K=3, dir TB:
//        grid (row-major, 4x3):  [0 0 3 / 3 3 3 / 0 0 0 / 2 1 4]
//        read col1: 0 3 0 1 ; col0: 0 3 0 2 ; col2: 3 3 0 4
//      ciphertext coords: 0 3 0 1 0 3 0 2 3 3 0 4  -> labels  A G A D A G A F G G A X
//    => "AGADAGAFGGAX"
//
//  Then decrypt(encrypt(P)) == P over random squares, lengths, column counts and read
//  directions (including ragged grids, 2N % K != 0) covers the general case for both the
//  5x5 (ADFGX) and the side-generic 6x6 (ADFGVX, 36 cells) squares.
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

// --- Known-answer vector (hand-computed above) --------------------------------

static void test_adfgvx_known_answer(void) {
    int square[25];
    for (int i = 0; i < 25; i++) square[i] = i;          // identity 5x5

    int plain[16];
    int n = str_to_idx("ATTACK", plain);
    CHECK(n == 6, "KAT plaintext length %d, expected 6", n);

    int order[3] = { 1, 0, 2 };                          // keyword "KEY" read order
    int cipher[32];
    adfgvx_encrypt(plain, n, square, 5, 3, order, COL_READ_TB, cipher);

    // Map the coordinate output to label characters and compare to the KAT string.
    const char *labels = adfgvx_labels(5);                // "ADFGX"
    char cbuf[33];
    for (int i = 0; i < 2 * n; i++) cbuf[i] = labels[cipher[i]];
    cbuf[2 * n] = '\0';
    CHECK(strcmp(cbuf, "AGADAGAFGGAX") == 0,
        "ADFGX encrypt KAT mismatch: got '%s', want 'AGADAGAFGGAX'", cbuf);

    int back[16];
    adfgvx_decrypt(cipher, 2 * n, square, 5, 3, order, COL_READ_TB, back);
    CHECK(arrays_equal(back, plain, n), "ADFGX decrypt KAT round-trip mismatch");
}

// --- label tables -------------------------------------------------------------

static void test_adfgvx_labels(void) {
    CHECK(strcmp(adfgvx_labels(5), "ADFGX") == 0, "side-5 labels wrong: '%s'", adfgvx_labels(5));
    CHECK(strcmp(adfgvx_labels(6), "ADFGVX") == 0, "side-6 labels wrong: '%s'", adfgvx_labels(6));
}

// --- round-trip over random squares, lengths, column counts and directions ----

static void roundtrip_for_side(int side, int trials, int maxlen, int maxK) {
    int gs = side * side;
    for (int t = 0; t < trials; t++) {
        int square[36];
        for (int i = 0; i < gs; i++) square[i] = i;
        shuffle(square, gs);

        int n = 1 + rand_int(0, maxlen);
        int len2 = 2 * n;
        int K = 2 + rand_int(0, maxK - 1);               // [2, maxK]
        if (K > len2) K = len2;
        int dir = rand_int(0, 2);                        // TB or BT

        int order[64];
        for (int c = 0; c < K; c++) order[c] = c;
        shuffle(order, K);

        static int plain[2050], cipher[4100], back[2050];
        for (int i = 0; i < n; i++) plain[i] = rand_int(0, gs);

        adfgvx_encrypt(plain, n, square, side, K, order, dir, cipher);
        adfgvx_decrypt(cipher, len2, square, side, K, order, dir, back);
        CHECK(arrays_equal(back, plain, n),
            "ADFG%sX round-trip mismatch (n=%d K=%d dir=%d ragged=%d)",
            side == 6 ? "V" : "", n, K, dir, (len2 % K) != 0);
    }
}

// K = 1 is the identity columnar, so the whole cipher is plain fractionation (still a
// faithful round-trip).
static void test_adfgvx_k1_identity(void) {
    int square[25];
    for (int i = 0; i < 25; i++) square[i] = i;
    shuffle(square, 25);
    int order[1] = { 0 };
    int n = 40;
    int plain[40], cipher[80], back[40];
    for (int i = 0; i < n; i++) plain[i] = rand_int(0, 25);
    adfgvx_encrypt(plain, n, square, 5, 1, order, COL_READ_TB, cipher);
    adfgvx_decrypt(cipher, 2 * n, square, 5, 1, order, COL_READ_TB, back);
    CHECK(arrays_equal(back, plain, n), "ADFGX K=1 (identity columnar) round-trip mismatch");
}

int main(void) {
    seed_rand(20240625u);
    init_alphabet("J");                  // 25-letter alphabet (J merged into I) for the KAT
    CHECK(g_alpha == 25, "alphabet size %d, expected 25", g_alpha);

    test_adfgvx_known_answer();
    test_adfgvx_labels();
    test_adfgvx_k1_identity();
    roundtrip_for_side(5, 6000, 1000, 30);   // ADFGX (25-cell square)
    roundtrip_for_side(6, 4000, 1000, 30);   // ADFGVX (36-cell square, side-generic path)

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
