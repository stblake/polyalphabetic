//
//  Unit tests for the Two-Square primitives (encrypt / decrypt, both arrangements).
//
//  Framework-free: build with `make test`, which links this against twosquare.c +
//  playfair.c + utils.c. Exits non-zero if any check fails.
//
//  Strategy: hand-checked known-answer vectors pin the actual convention for BOTH
//  arrangements -- the ACA "Two-Square" worked example for the horizontal type (the two
//  printed squares, pt "an ot he ..." -> ct "IR RT EH ..."), and the Wikipedia worked
//  example for the vertical type (EXAMPLE / KEYWORD squares, omit Q) -- so a row/column
//  mix-up or a square-role swap is caught, not just a self-consistent round-trip. Then
//  decrypt(encrypt(P)) == P over random squares and random lengths (incl. odd, and a
//  side-generic 6x6) covers the general case, the vertical type is checked SELF-INVERSE,
//  and the documented transparencies (horizontal same-row -> reversed pair; vertical
//  same-column -> unchanged pair) are asserted directly.
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

// Explicit A..Z string -> alphabet indices via the CURRENT alphabet map (no J->I merge,
// so it works under any single-letter-excluded alphabet). The string must not contain the
// excluded letter (the KAT squares/texts never do).
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

// --- horizontal known-answer vector (ACA "Two-Square" worked example) ---------
//
//   Square 1            Square 2
//   D I A L O           B I O G R
//   G U E B C           A P H Y C
//   F H K M N           D E F K L
//   P Q R S T           M N Q S T
//   V W X Y Z           U V W X Z
//   pt: an ot he rd ig ra ph ic se tu px
//   CT: IR RT EH MK GI ME QG RU NM MZ SV

static void test_twosquare_horizontal_kat(void) {
    init_alphabet("J");                          // 25 letters, J merged into I (no J in the squares)
    int sq1[SQUARE_GRID], sq2[SQUARE_GRID];
    to_idx("DIALOGUEBCFHKMNPQRSTVWXYZ", sq1);
    to_idx("BIOGRAPHYCDEFKLMNQSTUVWXZ", sq2);

    int pt[64];
    int n = to_idx("ANOTHERDIGRAPHICSETUPX", pt);
    int ct[64];
    twosquare_encrypt(pt, n, sq1, sq2, SQUARE_SIDE, TWO_SQ_HORIZONTAL, ct);
    char cb[65]; idx_to_str(ct, n, cb);
    CHECK(strcmp(cb, "IRRTEHMKGIMEQGRUNMMZSV") == 0,
        "twosquare horizontal KAT mismatch: got '%s'", cb);

    int back[64];
    twosquare_decrypt(ct, n, sq1, sq2, SQUARE_SIDE, TWO_SQ_HORIZONTAL, back);
    CHECK(arrays_equal(back, pt, n), "twosquare horizontal decrypt round-trip mismatch");
}

// --- vertical known-answer vector (Wikipedia "Two-square cipher" worked example) ---
//
//   Top (EXAMPLE)       Bottom (KEYWORD)   -- both omit Q
//   pt HELPMEOBIWANKENOBI -> ct HEDLXWSDJYANHOTKDG
//   (HE and AN are transparencies: same column -> unchanged.)

static void test_twosquare_vertical_kat(void) {
    init_alphabet("Q");                          // 25 letters, Q excluded (Wikipedia convention)
    int top[SQUARE_GRID], bot[SQUARE_GRID];
    to_idx("EXAMPLBCDFGHIJKNORSTUVWYZ", top);
    to_idx("KEYWORDABCFGHIJLMNPSTUVXZ", bot);

    int pt[64];
    int n = to_idx("HELPMEOBIWANKENOBI", pt);
    int ct[64];
    twosquare_encrypt(pt, n, top, bot, SQUARE_SIDE, TWO_SQ_VERTICAL, ct);
    char cb[65]; idx_to_str(ct, n, cb);
    CHECK(strcmp(cb, "HEDLXWSDJYANHOTKDG") == 0,
        "twosquare vertical KAT mismatch: got '%s'", cb);

    // The vertical arrangement is self-inverse: decrypt == encrypt.
    int back[64];
    twosquare_decrypt(ct, n, top, bot, SQUARE_SIDE, TWO_SQ_VERTICAL, back);
    CHECK(arrays_equal(back, pt, n), "twosquare vertical decrypt round-trip mismatch");
    int twice[64];
    twosquare_encrypt(ct, n, top, bot, SQUARE_SIDE, TWO_SQ_VERTICAL, twice);
    CHECK(arrays_equal(twice, pt, n), "twosquare vertical encrypt is not self-inverse");
}

// --- round-trip over random squares + random lengths (both variants, incl. 6x6) ----

static void random_square(int sq[], int n) {
    for (int i = 0; i < n; i++) sq[i] = i;
    shuffle(sq, n);
}

static void test_twosquare_roundtrip(void) {
    for (int variant = 0; variant <= 1; variant++) {
        for (int t = 0; t < 3000; t++) {
            int sq1[SQUARE_GRID], sq2[SQUARE_GRID];
            random_square(sq1, SQUARE_GRID);
            random_square(sq2, SQUARE_GRID);

            int len = 1 + rand_int(0, 400);      // include odd lengths (lone trailing letter)
            int pt[512], ct[512], back[512];
            for (int i = 0; i < len; i++) pt[i] = rand_int(0, SQUARE_GRID);
            twosquare_encrypt(pt, len, sq1, sq2, SQUARE_SIDE, variant, ct);
            twosquare_decrypt(ct, len, sq1, sq2, SQUARE_SIDE, variant, back);
            CHECK(arrays_equal(back, pt, len),
                "twosquare round-trip mismatch (variant=%d len=%d)", variant, len);
        }
    }
    // Side-generic 6x6 (36-cell squares) exercises the path the 5x5 default does not.
    for (int variant = 0; variant <= 1; variant++) {
        for (int t = 0; t < 1500; t++) {
            int sq1[36], sq2[36];
            random_square(sq1, 36);
            random_square(sq2, 36);
            int len = 1 + rand_int(0, 300);
            int pt[512], ct[512], back[512];
            for (int i = 0; i < len; i++) pt[i] = rand_int(0, 36);
            twosquare_encrypt(pt, len, sq1, sq2, 6, variant, ct);
            twosquare_decrypt(ct, len, sq1, sq2, 6, variant, back);
            CHECK(arrays_equal(back, pt, len),
                "twosquare 6x6 round-trip mismatch (variant=%d len=%d)", variant, len);
        }
    }
}

// --- transparencies ----------------------------------------------------------------
//
// Horizontal: a same-ROW digraph (a in sq1 row r, b in sq2 row r) enciphers to the
// reversed pair (b, a). Vertical: a same-COLUMN digraph (a in sq1 col c, b in sq2 col c)
// enciphers to itself (a, b). Both fall straight out of the rectangle rule and are the
// documented ~20%-of-digraphs weakness.

static void test_twosquare_transparencies(void) {
    int s = SQUARE_SIDE;
    for (int t = 0; t < 500; t++) {
        int sq1[SQUARE_GRID], sq2[SQUARE_GRID];
        random_square(sq1, SQUARE_GRID);
        random_square(sq2, SQUARE_GRID);

        // Horizontal same-row -> reversed pair.
        int r = rand_int(0, s), ca = rand_int(0, s), cb = rand_int(0, s);
        int ph[2] = { sq1[r * s + ca], sq2[r * s + cb] }, ch[2];
        twosquare_encrypt(ph, 2, sq1, sq2, s, TWO_SQ_HORIZONTAL, ch);
        CHECK(ch[0] == ph[1] && ch[1] == ph[0],
            "twosquare horizontal same-row not reversed");

        // Vertical same-column -> unchanged pair.
        int col = rand_int(0, s), ra = rand_int(0, s), rb = rand_int(0, s);
        int pv[2] = { sq1[ra * s + col], sq2[rb * s + col] }, cv[2];
        twosquare_encrypt(pv, 2, sq1, sq2, s, TWO_SQ_VERTICAL, cv);
        CHECK(cv[0] == pv[0] && cv[1] == pv[1],
            "twosquare vertical same-column not unchanged");
    }
}

int main(void) {
    seed_rand(20240624u);

    test_twosquare_horizontal_kat();
    test_twosquare_vertical_kat();

    init_alphabet("J");                          // back to a 25-letter alphabet for the rest
    test_twosquare_roundtrip();
    test_twosquare_transparencies();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
