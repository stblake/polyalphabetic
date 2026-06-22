//
//  Unit tests for the Trifid primitives (cube build / encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against trifid.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Strategy: a hand-verified known-answer vector (the Wikipedia "Trifid cipher" worked
//  example -- 27-symbol cube "FELIXMARDSTBCGHJKNOPQUVWYZ+", period 5) pins the actual
//  convention: the (layer, row, column) fractionation, the layer-then-row-then-column
//  stream order, and the consecutive triple re-grouping. Two independent groups are
//  checked (AIDET -> FMJFV, OILEC -> OISSU), so a coordinate-axis mix-up or a stream-
//  order error is caught, not just a self-consistent round-trip. Then decrypt(encrypt(P))
//  == P over random cubes, lengths and periods (including incomplete final blocks and
//  period > len) covers the general case, and 2x2x2 (8-cell) and 4x4x4 (64-cell) round-
//  trips exercise the side-generic path that the 3x3x3 default does not.
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

// 27-symbol string (A..Z + '+') -> alphabet indices.
static int str_to_idx(const char *s, int out[]) {
    int n = 0;
    for (int i = 0; s[i]; i++) {
        int c = toupper((unsigned char) s[i]);
        int idx = (c < 128) ? g_char_to_idx[c] : -1;
        if (idx < 0) continue;
        out[n++] = idx;
    }
    return n;
}

static void idx_to_str(const int a[], int len, char out[]) {
    for (int i = 0; i < len; i++) out[i] = index_to_char(a[i]);
    out[len] = '\0';
}

// --- Known-answer vector (Wikipedia "Trifid cipher" worked example) -------------

static void encrypt_group_check(const int cube[], const char *plain_s, const char *want) {
    int plain[16];
    int plen = str_to_idx(plain_s, plain);
    int cipher[16];
    trifid_encrypt(plain, plen, cube, 3, plen, cipher);   // one block (period == length)
    char cbuf[17]; idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, want) == 0,
        "trifid encrypt KAT '%s': got '%s', want '%s'", plain_s, cbuf, want);
    int back[16];
    trifid_decrypt(cipher, plen, cube, 3, plen, back);
    CHECK(arrays_equal(back, plain, plen), "trifid decrypt KAT round-trip '%s'", plain_s);
}

static void test_trifid_known_answer(void) {
    // The cube is given directly as the 27-symbol permutation laid out cell-major
    // (layer 1: F E L / I X M / A R D, layer 2: S T B / C G H / J K N, layer 3:
    // O P Q / U V W / Y Z +). A = (layer1,row3,col1) = trigram 131, etc.
    int cube[TRIFID_CELLS];
    int cn = str_to_idx("FELIXMARDSTBCGHJKNOPQUVWYZ+", cube);
    CHECK(cn == TRIFID_CELLS, "KAT cube is not 27 symbols (%d)", cn);

    encrypt_group_check(cube, "AIDET", "FMJFV");   // first group of the worked example
    encrypt_group_check(cube, "OILEC", "OISSU");   // second group (independent check)
}

// --- keyword cube build -------------------------------------------------------

static void test_trifid_cube_build(void) {
    // Keyword FELIX over the 27-symbol alphabet -> the keyword letters (deduped) first,
    // then the remaining alphabet symbols (A..Z then '+') in ascending index order.
    int kw[64], cube[TRIFID_CELLS];
    int kwn = str_to_idx("FELIX", kw);
    trifid_cube_from_keyword(kw, kwn, cube, TRIFID_CELLS);
    int expect[TRIFID_CELLS];
    str_to_idx("FELIXABCDGHJKMNOPQRSTUVWYZ+", expect);
    CHECK(arrays_equal(cube, expect, TRIFID_CELLS), "trifid cube build mismatch");
}

// --- round-trip over random cubes, lengths and periods ------------------------

static void test_trifid_roundtrip(void) {
    for (int t = 0; t < 5000; t++) {
        int cube[TRIFID_CELLS];
        for (int i = 0; i < TRIFID_CELLS; i++) cube[i] = i;
        shuffle(cube, TRIFID_CELLS);

        int len = 1 + rand_int(0, 600);
        int period = 1 + rand_int(0, 40);          // includes period > len and period 1
        int plain[640], cipher[640], back[640];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, TRIFID_CELLS);

        trifid_encrypt(plain, len, cube, 3, period, cipher);
        trifid_decrypt(cipher, len, cube, 3, period, back);
        CHECK(arrays_equal(back, plain, len),
            "trifid round-trip mismatch (len=%d period=%d)", len, period);
    }
}

// Period 1 is the identity transform (block of one letter -> stream (c0,c1,c2) -> same cell).
static void test_trifid_period_one_identity(void) {
    int cube[TRIFID_CELLS];
    for (int i = 0; i < TRIFID_CELLS; i++) cube[i] = i;
    shuffle(cube, TRIFID_CELLS);
    int len = 50, plain[64], cipher[64];
    for (int i = 0; i < len; i++) plain[i] = rand_int(0, TRIFID_CELLS);
    trifid_encrypt(plain, len, cube, 3, 1, cipher);
    CHECK(arrays_equal(cipher, plain, len), "trifid period-1 is not the identity");
}

// --- side-generic round-trips (2x2x2 = 8 cells, 4x4x4 = 64 cells) -------------

static void test_trifid_sidegeneric_roundtrip(void) {
    int sides[] = {2, 4};
    for (int si = 0; si < 2; si++) {
        int side = sides[si], n = side * side * side;
        for (int t = 0; t < 2000; t++) {
            int cube[TRIFID_MAX_CELLS];
            for (int i = 0; i < n; i++) cube[i] = i;
            shuffle(cube, n);

            int len = 1 + rand_int(0, 400);
            int period = 1 + rand_int(0, 30);
            int plain[420], cipher[420], back[420];
            for (int i = 0; i < len; i++) plain[i] = rand_int(0, n);

            trifid_encrypt(plain, len, cube, side, period, cipher);
            trifid_decrypt(cipher, len, cube, side, period, back);
            CHECK(arrays_equal(back, plain, len),
                "trifid %dx%dx%d round-trip mismatch (len=%d period=%d)", side, side, side, len, period);
        }
    }
}

int main(void) {
    seed_rand(20240620u);
    init_alphabet_trifid();              // 27-symbol alphabet (A..Z + '+')
    CHECK(g_alpha == TRIFID_CELLS, "alphabet size %d, expected %d", g_alpha, TRIFID_CELLS);

    test_trifid_known_answer();
    test_trifid_cube_build();
    test_trifid_roundtrip();
    test_trifid_period_one_identity();
    test_trifid_sidegeneric_roundtrip();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
