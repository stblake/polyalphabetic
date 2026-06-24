//
//  Unit tests for the Phillips primitives (square generation / encrypt / decrypt).
//
//  Framework-free: build with `make test`, which links this against phillips.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Strategy: a hand-checked known-answer vector (the ACA "Phillips" worked example -- base
//  square DIAGOCBSLNEFHKMUTRQPVWXYZ, the 81-letter plaintext "squares one ... is forty",
//  ciphertext KZWLY...GREYXO) pins the whole convention end-to-end: the 8-square row
//  reinsertion table, the block-of-5 / square cycling, and the down-right (with wrap)
//  encipherment. A separate assertion pins phillips_build_squares' Row table cell-for-cell
//  against the ACA's printed squares #1-#8. Then decrypt(encrypt(P)) == P over random base
//  squares, lengths and periods (incl. blocks shorter than the side and len < side) for ALL
//  THREE variants, plus a 6x6 (side-generic, 10-square) round-trip, covers the general case.
//  Finally the documented structural facts are checked: the cyclic column-rotation symmetry
//  (Row) and its row-rotation dual (Column), the two cyclically-equivalent square pairs
//  (#1==#5, #2==#8 encipher identically), and that the 8 derived squares are distinct grids.
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

// --- Known-answer vector (ACA "Phillips" worked example, key DIAGONALS) ---------

static void test_phillips_known_answer(void) {
    // The base square (#1) exactly as the ACA example prints it, row-major:
    //   D I A G O / C B S L N / E F H K M / U T R Q P / V W X Y Z
    int base[PHILLIPS_GRID];
    int gn = str_to_idx("DIAGOCBSLNEFHKMUTRQPVWXYZ", base);
    CHECK(gn == PHILLIPS_GRID, "KAT base square is not 25 letters (%d)", gn);

    const char *pt = "SQUARESONEANDFIVEAREACTUALLYTHESAMEASARESQUARESTWOANDEIGHTTHEOVERALLPERIODISFORTY";
    const char *want = "KZWLYTGEDTQETARBTYGTLFXWLPPOXLTYKUTKGKYTKZWLYTGXSEQETIRZQAAQTCITYKPPVBLHEFHGREYXO";
    int plain[128], cipher[128], back[128];
    int plen = str_to_idx(pt, plain);
    CHECK(plen == 81, "KAT plaintext length %d, expected 81", plen);

    phillips_encrypt(plain, plen, base, PHILLIPS_SIDE, PHILLIPS_ROW, cipher);
    char cbuf[129]; idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, want) == 0, "phillips encrypt KAT mismatch:\n got  '%s'\n want '%s'", cbuf, want);

    phillips_decrypt(cipher, plen, base, PHILLIPS_SIDE, PHILLIPS_ROW, back);
    CHECK(arrays_equal(back, plain, plen), "phillips decrypt KAT round-trip mismatch");
}

// --- Row square-generation table pinned to the ACA's printed squares #1-#8 ------

static void test_phillips_square_table(void) {
    int base[PHILLIPS_GRID];
    for (int i = 0; i < PHILLIPS_GRID; i++) base[i] = i;       // base = identity grid
    int squares[PHILLIPS_MAX_SQUARES * PHILLIPS_GRID];
    phillips_build_squares(base, PHILLIPS_SIDE, PHILLIPS_ROW, squares);

    // The ACA Phillips row-reinsertion order (0-indexed original rows) for squares #1-#8.
    static const int order[8][5] = {
        {0,1,2,3,4}, {1,0,2,3,4}, {1,2,0,3,4}, {1,2,3,0,4},
        {1,2,3,4,0}, {2,1,3,4,0}, {2,3,1,4,0}, {2,3,4,1,0},
    };
    for (int s = 0; s < 8; s++) {
        int expect[PHILLIPS_GRID];
        for (int r = 0; r < 5; r++)
            for (int c = 0; c < 5; c++)
                expect[r * 5 + c] = base[order[s][r] * 5 + c];
        CHECK(arrays_equal(squares + s * PHILLIPS_GRID, expect, PHILLIPS_GRID),
            "phillips Row square #%d mismatch vs ACA table", s + 1);
    }
}

// --- keyword square build -----------------------------------------------------

static void test_phillips_grid_build(void) {
    // Same keyed-square construction as Playfair/Bifid (keyword then remaining alphabet,
    // duplicates dropped): PLAYFAIREXAMPLE -> PLAYFIREXMBCDGHKNOQSTUVWZ.
    int kw[64], grid[PHILLIPS_GRID], expect[PHILLIPS_GRID];
    int kwn = str_to_idx("PLAYFAIREXAMPLE", kw);
    phillips_grid_from_keyword(kw, kwn, grid, PHILLIPS_GRID);
    str_to_idx("PLAYFIREXMBCDGHKNOQSTUVWZ", expect);
    CHECK(arrays_equal(grid, expect, PHILLIPS_GRID), "phillips grid build mismatch");
}

// --- round-trip over random squares, lengths, all three variants --------------

static void test_phillips_roundtrip(void) {
    const int variants[3] = { PHILLIPS_ROW, PHILLIPS_COL, PHILLIPS_ROWCOL };
    for (int t = 0; t < 6000; t++) {
        int grid[PHILLIPS_GRID];
        for (int i = 0; i < PHILLIPS_GRID; i++) grid[i] = i;
        shuffle(grid, PHILLIPS_GRID);

        int variant = variants[rand_int(0, 3)];
        int len = 1 + rand_int(0, 600);            // includes len < side and non-multiples of 5
        int plain[640], cipher[640], back[640];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, PHILLIPS_GRID);

        phillips_encrypt(plain, len, grid, PHILLIPS_SIDE, variant, cipher);
        phillips_decrypt(cipher, len, grid, PHILLIPS_SIDE, variant, back);
        CHECK(arrays_equal(back, plain, len),
            "phillips round-trip mismatch (variant=%d len=%d)", variant, len);
    }
}

// --- 6x6 (side-generic, 10-square) round-trip ---------------------------------

static void test_phillips_6x6_roundtrip(void) {
    const int variants[3] = { PHILLIPS_ROW, PHILLIPS_COL, PHILLIPS_ROWCOL };
    for (int t = 0; t < 3000; t++) {
        int grid[PHILLIPS_MAX_GRID];
        for (int i = 0; i < PHILLIPS_MAX_GRID; i++) grid[i] = i;
        shuffle(grid, PHILLIPS_MAX_GRID);

        int variant = variants[rand_int(0, 3)];
        int len = 1 + rand_int(0, 400);
        int plain[420], cipher[420], back[420];
        for (int i = 0; i < len; i++) plain[i] = rand_int(0, PHILLIPS_MAX_GRID);

        phillips_encrypt(plain, len, grid, 6, variant, cipher);
        phillips_decrypt(cipher, len, grid, 6, variant, back);
        CHECK(arrays_equal(back, plain, len),
            "phillips 6x6 round-trip mismatch (variant=%d len=%d)", variant, len);
    }
}

// --- structural / symmetry facts ----------------------------------------------

static void test_phillips_symmetries(void) {
    int base[PHILLIPS_GRID], rot[PHILLIPS_GRID];
    for (int i = 0; i < PHILLIPS_GRID; i++) base[i] = i;
    shuffle(base, PHILLIPS_GRID);

    int n = 160, plain[200], c1[200], c2[200];
    for (int i = 0; i < n; i++) plain[i] = rand_int(0, PHILLIPS_GRID);

    // Row variant: a cyclic COLUMN rotation of the base re-enciphers identically (so the
    // recovered square is unique only up to that rotation).
    for (int r = 0; r < 5; r++)
        for (int c = 0; c < 5; c++) rot[r * 5 + (c + 1) % 5] = base[r * 5 + c];
    phillips_encrypt(plain, n, base, PHILLIPS_SIDE, PHILLIPS_ROW, c1);
    phillips_encrypt(plain, n, rot,  PHILLIPS_SIDE, PHILLIPS_ROW, c2);
    CHECK(arrays_equal(c1, c2, n), "phillips Row column-rotation is not a symmetry");

    // Column variant: the dual -- a cyclic ROW rotation re-enciphers identically.
    for (int r = 0; r < 5; r++)
        for (int c = 0; c < 5; c++) rot[((r + 1) % 5) * 5 + c] = base[r * 5 + c];
    phillips_encrypt(plain, n, base, PHILLIPS_SIDE, PHILLIPS_COL, c1);
    phillips_encrypt(plain, n, rot,  PHILLIPS_SIDE, PHILLIPS_COL, c2);
    CHECK(arrays_equal(c1, c2, n), "phillips Column row-rotation is not a symmetry");

    // The 8 derived squares are distinct grids, but squares #1==#5 and #2==#8 encipher
    // identically (each is a cyclic row rotation of the other -> same down-right map).
    int sq[PHILLIPS_MAX_SQUARES * PHILLIPS_GRID];
    phillips_build_squares(base, PHILLIPS_SIDE, PHILLIPS_ROW, sq);
    int distinct = 1;
    for (int a = 0; a < 8; a++)
        for (int b = a + 1; b < 8; b++)
            if (arrays_equal(sq + a * PHILLIPS_GRID, sq + b * PHILLIPS_GRID, PHILLIPS_GRID)) distinct = 0;
    CHECK(distinct, "phillips derived squares are not all distinct grids");

    int dr[8][PHILLIPS_GRID];
    for (int s = 0; s < 8; s++) {
        int pos[PHILLIPS_GRID];
        for (int p = 0; p < PHILLIPS_GRID; p++) pos[sq[s * PHILLIPS_GRID + p]] = p;
        for (int L = 0; L < PHILLIPS_GRID; L++) {
            int cell = pos[L], r = cell / 5, c = cell % 5;
            dr[s][L] = sq[s * PHILLIPS_GRID + ((r + 1) % 5) * 5 + (c + 1) % 5];
        }
    }
    CHECK(arrays_equal(dr[0], dr[4], PHILLIPS_GRID), "phillips square #1 != #5 encipherment");
    CHECK(arrays_equal(dr[1], dr[7], PHILLIPS_GRID), "phillips square #2 != #8 encipherment");
}

int main(void) {
    seed_rand(20240623u);
    init_alphabet("J");                  // 25-letter alphabet (J merged into I)
    CHECK(g_alpha == PHILLIPS_GRID, "alphabet size %d, expected %d", g_alpha, PHILLIPS_GRID);

    test_phillips_known_answer();
    test_phillips_square_table();
    test_phillips_grid_build();
    test_phillips_roundtrip();
    test_phillips_6x6_roundtrip();
    test_phillips_symmetries();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
