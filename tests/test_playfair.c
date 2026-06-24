//
//  Unit tests for the Playfair primitives (grid build / prepare / encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against playfair.c +
//  utils.c. Exits non-zero if any check fails.
//
//  Strategy: a hand-computed known-answer vector (the Wikipedia worked example) pins
//  the actual convention -- grid layout, the three rules, and the X-insertion of the
//  prepare step -- so a sign flip or a row/column mix-up is caught, not just a
//  self-consistent round-trip. Then decrypt(encrypt(P)) == P over random grids and
//  random prepared plaintexts covers the general case, and a dedicated check confirms
//  the documented key-square equivalence (cyclic row/column rotation re-enciphers
//  identically) that the solver's grid recovery is unique only up to.
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

// --- Known-answer vector (Wikipedia "Playfair cipher" worked example) ---------

static void test_playfair_known_answer(void) {
    int kw[64], grid[PLAYFAIR_GRID];
    int kwn = str_to_idx("PLAYFAIREXAMPLE", kw);
    playfair_grid_from_keyword(kw, kwn, grid);

    // The reference grid, row by row: PLAYF / IREXM / BCDGH / KNOQS / TUVWZ.
    int expect_grid[PLAYFAIR_GRID];
    str_to_idx("PLAYFIREXMBCDGHKNOQSTUVWZ", expect_grid);
    CHECK(arrays_equal(grid, expect_grid, PLAYFAIR_GRID), "playfair grid build mismatch");

    // prepare: HIDETHEGOLDINTHETREESTUMP -> HIDETHEGOLDINTHETREXESTUMP (X splits EE).
    int raw[64], prepared[128];
    int rawn = str_to_idx("HIDETHEGOLDINTHETREESTUMP", raw);
    int filler = g_char_to_idx['X'], alt = g_char_to_idx['Q'];
    int plen = playfair_prepare(raw, rawn, filler, alt, prepared, 128);
    char pbuf[129]; idx_to_str(prepared, plen, pbuf);
    CHECK(plen == 26 && strcmp(pbuf, "HIDETHEGOLDINTHETREXESTUMP") == 0,
        "playfair prepare mismatch: got '%s' (len %d)", pbuf, plen);

    // encrypt: -> BMODZBXDNABEKUDMUIXMMOUVIF.
    int cipher[128];
    playfair_encrypt(prepared, plen, grid, cipher);
    char cbuf[129]; idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "BMODZBXDNABEKUDMUIXMMOUVIF") == 0,
        "playfair encrypt KAT mismatch: got '%s'", cbuf);

    // decrypt: -> back to the prepared plaintext.
    int back[128];
    playfair_decrypt(cipher, plen, grid, back);
    CHECK(arrays_equal(back, prepared, plen), "playfair decrypt KAT round-trip mismatch");
}

// --- prepare invariants -------------------------------------------------------

static void test_playfair_prepare_rules(void) {
    int filler = g_char_to_idx['X'], alt = g_char_to_idx['Q'];

    // Doubled letters get a filler between them: BALLOON -> BA LX LO ON.
    int raw[64], out[128];
    int n = str_to_idx("BALLOON", raw);             // B A L L O O N
    int plen = playfair_prepare(raw, n, filler, alt, out, 128);
    char buf[129]; idx_to_str(out, plen, buf);
    CHECK(strcmp(buf, "BALXLOON") == 0, "playfair prepare BALLOON -> '%s'", buf);

    // An odd-length text is padded with the filler: TREE -> TR EX E? -> TREXEX.
    int raw2[64], out2[128];
    int n2 = str_to_idx("TREE", raw2);              // T R E E
    int plen2 = playfair_prepare(raw2, n2, filler, alt, out2, 128);
    char buf2[129]; idx_to_str(out2, plen2, buf2);
    CHECK(strcmp(buf2, "TREXEX") == 0, "playfair prepare TREE -> '%s'", buf2);

    // General invariants over a batch of random texts: even length, never an equal
    // pair, and a doubled filler is itself split (never produces (filler, filler)).
    for (int t = 0; t < 2000; t++) {
        int len = 1 + rand_int(0, 40), r[64], o[160];
        for (int i = 0; i < len; i++) r[i] = rand_int(0, PLAYFAIR_GRID);
        int pl = playfair_prepare(r, len, filler, alt, o, 160);
        CHECK(pl % 2 == 0, "prepared length not even (%d)", pl);
        int bad = 0;
        for (int i = 0; i + 1 < pl; i += 2) if (o[i] == o[i + 1]) bad = 1;
        CHECK(!bad, "prepared digraph has equal letters");
    }
}

// --- round-trip over random grids + random prepared plaintexts ----------------

static void random_grid(int grid[]) {
    for (int i = 0; i < PLAYFAIR_GRID; i++) grid[i] = i;
    shuffle(grid, PLAYFAIR_GRID);
}

static void test_playfair_roundtrip(void) {
    int filler = g_char_to_idx['X'], alt = g_char_to_idx['Q'];
    for (int t = 0; t < 3000; t++) {
        int grid[PLAYFAIR_GRID];
        random_grid(grid);

        int len = 2 + rand_int(0, 400);
        int raw[512], prepared[640], cipher[640], back[640];
        for (int i = 0; i < len; i++) raw[i] = rand_int(0, PLAYFAIR_GRID);
        int plen = playfair_prepare(raw, len, filler, alt, prepared, 640);

        playfair_encrypt(prepared, plen, grid, cipher);
        playfair_decrypt(cipher, plen, grid, back);
        CHECK(arrays_equal(back, prepared, plen),
            "playfair round-trip mismatch (len=%d)", plen);
    }
}

// --- key-square equivalence ---------------------------------------------------
//
// Cyclically rotating every row (or every column) of the grid leaves the cipher
// unchanged -- the same-row right-neighbour, same-column down-neighbour and rectangle
// rules are all invariant under a uniform shift. This is exactly why the solver can
// only recover the grid up to such a rotation; the recovered PLAINTEXT is unaffected.

static void rotate_rows_down(const int in[], int out[]) {     // each column shifts down 1
    int s = PLAYFAIR_SIDE;
    for (int r = 0; r < s; r++)
        for (int c = 0; c < s; c++)
            out[((r + 1) % s) * s + c] = in[r * s + c];
}

static void rotate_cols_right(const int in[], int out[]) {    // each row shifts right 1
    int s = PLAYFAIR_SIDE;
    for (int r = 0; r < s; r++)
        for (int c = 0; c < s; c++)
            out[r * s + (c + 1) % s] = in[r * s + c];
}

static void test_playfair_equivalence(void) {
    int filler = g_char_to_idx['X'], alt = g_char_to_idx['Q'];
    for (int t = 0; t < 500; t++) {
        int grid[PLAYFAIR_GRID], g2[PLAYFAIR_GRID];
        random_grid(grid);

        int len = 2 + rand_int(0, 200), raw[256], prepared[320];
        for (int i = 0; i < len; i++) raw[i] = rand_int(0, PLAYFAIR_GRID);
        int plen = playfair_prepare(raw, len, filler, alt, prepared, 320);

        int c0[320], c1[320];
        playfair_encrypt(prepared, plen, grid, c0);

        rotate_rows_down(grid, g2);
        playfair_encrypt(prepared, plen, g2, c1);
        CHECK(arrays_equal(c0, c1, plen), "row-rotation changed the ciphertext");

        rotate_cols_right(grid, g2);
        playfair_encrypt(prepared, plen, g2, c1);
        CHECK(arrays_equal(c0, c1, plen), "column-rotation changed the ciphertext");
    }
}

int main(void) {
    seed_rand(20240620u);
    init_alphabet("J");                  // 25-letter Playfair alphabet (J merged into I)
    CHECK(g_alpha == PLAYFAIR_GRID, "alphabet size %d, expected %d", g_alpha, PLAYFAIR_GRID);

    test_playfair_known_answer();
    test_playfair_prepare_rules();
    test_playfair_roundtrip();
    test_playfair_equivalence();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
