//
//  Unit tests for the Seriated Playfair primitives (prepare / encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against seriated_playfair.c
//  + playfair.c (grid build / inverse) + utils.c. Exits non-zero if any check fails.
//
//  Strategy: the ACA worked-example known-answer vector pins the whole convention end to
//  end -- the 2P-block vertical pairing, the three Playfair rules, the null insertion, and
//  the block-serialized readout -- cell for cell. Then: a targeted null-insertion check
//  (the filler and the X->Q alt rule); a P=1 equivalence (seriated == plain Playfair on
//  consecutive pairs) pinning the convention against the existing primitive; and
//  encrypt/decrypt round-trips over random grids x plaintexts x periods, including ragged
//  buffers (lone top letters pass through) and P > length.
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

// --- ACA worked-example known-answer vector -----------------------------------
//
// Square LOGAR/ITHMB/CDEFK/NPQSU/VWXYZ, period 6. Plaintext
// "comequicklyweneedhelpimmediatelytom" -> prepared (one null splits the e/e vertical
// pair) "COMEQUICKLYWENEEDHXELPIMMEDIATELYTOM" -> cipher (blocks taken off top-then-bottom)
// "NLBCSPCDFGXZQQCDCMGCGQTBHCFTRHFGWHGB".

static void test_seriated_known_answer(void) {
    int grid[PLAYFAIR_GRID];
    int gn = str_to_idx("LOGARITHMBCDEFKNPQSUVWXYZ", grid);
    CHECK(gn == PLAYFAIR_GRID, "KAT square is not 25 distinct letters (%d)", gn);

    int raw[64], prepared[128];
    int rawn = str_to_idx("comequicklyweneedhelpimmediatelytom", raw);
    int filler = g_char_to_idx['X'], alt = g_char_to_idx['Q'];
    int plen = seriated_playfair_prepare(raw, rawn, 6, filler, alt, prepared, 128);
    char pbuf[129]; idx_to_str(prepared, plen, pbuf);
    CHECK(plen == 36 && strcmp(pbuf, "COMEQUICKLYWENEEDHXELPIMMEDIATELYTOM") == 0,
        "seriated prepare KAT mismatch: got '%s' (len %d)", pbuf, plen);

    int cipher[128];
    seriated_playfair_encrypt(prepared, plen, grid, 6, cipher);
    char cbuf[129]; idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "NLBCSPCDFGXZQQCDCMGCGQTBHCFTRHFGWHGB") == 0,
        "seriated encrypt KAT mismatch: got '%s'", cbuf);

    int back[128];
    seriated_playfair_decrypt(cipher, plen, grid, 6, back);
    CHECK(arrays_equal(back, prepared, plen), "seriated decrypt KAT round-trip mismatch");
}

// --- targeted null insertion (filler + the X->Q alt rule) ---------------------

static void test_seriated_null_insertion(void) {
    int filler = g_char_to_idx['X'], alt = g_char_to_idx['Q'];

    // period 3, raw ABCAYZ: column 0 is the vertical pair (A, A) -> a null X is inserted at
    // the bottom cell, so the prepared stream opens ABC X AYZ...
    int raw[16], out[64];
    int n = str_to_idx("ABCAYZ", raw);
    int plen = seriated_playfair_prepare(raw, n, 3, filler, alt, out, 64);
    CHECK(plen >= 7, "null-insertion prepared too short (%d)", plen);
    CHECK(out[0] == g_char_to_idx['A'] && out[1] == g_char_to_idx['B'] && out[2] == g_char_to_idx['C'],
        "null-insertion top row corrupted");
    CHECK(out[3] == filler, "null not inserted at the doubled vertical pair");
    CHECK(out[4] == g_char_to_idx['A'] && out[5] == g_char_to_idx['Y'] && out[6] == g_char_to_idx['Z'],
        "null insertion did not reflow the tail");

    // When the doubled letter IS the filler (X over X), the alt (Q) is used: XBC X YZ -> X
    // at col 0 over X -> insert Q.
    int raw2[16], out2[64];
    int n2 = str_to_idx("XBCXYZ", raw2);
    int plen2 = seriated_playfair_prepare(raw2, n2, 3, filler, alt, out2, 64);
    CHECK(plen2 >= 7 && out2[3] == alt, "alt filler not used when the double is the filler");
}

// --- P=1 equivalence: seriated == plain Playfair on consecutive pairs ----------

static void random_grid(int grid[]) {
    for (int i = 0; i < PLAYFAIR_GRID; i++) grid[i] = i;
    shuffle(grid, PLAYFAIR_GRID);
}

static void test_seriated_p1_equivalence(void) {
    for (int t = 0; t < 1000; t++) {
        int grid[PLAYFAIR_GRID];
        random_grid(grid);
        int len = 2 + rand_int(0, 200);          // include odd lengths (lone trailing letter)
        int cipher[256], a[256], b[256];
        for (int i = 0; i < len; i++) cipher[i] = rand_int(0, PLAYFAIR_GRID);
        seriated_playfair_decrypt(cipher, len, grid, 1, a);
        playfair_decrypt(cipher, len, grid, b);
        CHECK(arrays_equal(a, b, len), "seriated(P=1) != playfair_decrypt (len=%d)", len);
    }
}

// --- round-trips --------------------------------------------------------------

// (a) prepared round-trip: prepare -> encrypt -> decrypt == prepared, over random grids,
//     plaintexts and periods (prepare pads to whole 2P blocks).
static void test_seriated_prepared_roundtrip(void) {
    int filler = g_char_to_idx['X'], alt = g_char_to_idx['Q'];
    for (int t = 0; t < 3000; t++) {
        int grid[PLAYFAIR_GRID];
        random_grid(grid);
        int P = 1 + rand_int(0, 9);
        int len = 1 + rand_int(0, 300);
        int raw[512], prepared[700], cipher[700], back[700];
        for (int i = 0; i < len; i++) raw[i] = rand_int(0, PLAYFAIR_GRID);
        int plen = seriated_playfair_prepare(raw, len, P, filler, alt, prepared, 700);
        CHECK(plen % (2 * P) == 0, "prepared length %d not a multiple of 2P=%d", plen, 2 * P);
        seriated_playfair_encrypt(prepared, plen, grid, P, cipher);
        seriated_playfair_decrypt(cipher, plen, grid, P, back);
        CHECK(arrays_equal(back, prepared, plen),
            "seriated prepared round-trip mismatch (P=%d len=%d)", P, plen);
    }
}

// (b) raw involution: decrypt(encrypt(raw)) == raw for ARBITRARY (unprepared, possibly
//     ragged) buffers and any period, incl. P > length -- exercises the lone-top-letter
//     pass-through and the pair's invertibility directly.
static void test_seriated_raw_involution(void) {
    for (int t = 0; t < 3000; t++) {
        int grid[PLAYFAIR_GRID];
        random_grid(grid);
        int P = 1 + rand_int(0, 12);
        int len = 1 + rand_int(0, 120);          // often not a multiple of 2P; P can exceed len
        int raw[256], cipher[256], back[256];
        for (int i = 0; i < len; i++) raw[i] = rand_int(0, PLAYFAIR_GRID);
        seriated_playfair_encrypt(raw, len, grid, P, cipher);
        seriated_playfair_decrypt(cipher, len, grid, P, back);
        CHECK(arrays_equal(back, raw, len),
            "seriated raw involution mismatch (P=%d len=%d)", P, len);
    }
}

int main(void) {
    seed_rand(20240620u);
    init_alphabet("J");                  // 25-letter Playfair alphabet (J merged into I)
    CHECK(g_alpha == PLAYFAIR_GRID, "alphabet size %d, expected %d", g_alpha, PLAYFAIR_GRID);

    test_seriated_known_answer();
    test_seriated_null_insertion();
    test_seriated_p1_equivalence();
    test_seriated_prepared_roundtrip();
    test_seriated_raw_involution();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
