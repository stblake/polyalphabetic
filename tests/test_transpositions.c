//
//  Unit tests for the transposition primitives (transpositions.c).
//
//  Framework-free: build with `make test`, which links this against
//  transpositions.c + utils.c. Exits non-zero if any check fails.
//
//  Strategy: each transform is a fixed permutation of positions. We recover that
//  permutation by running the transform on the identity index array, assert it is
//  a genuine bijection, then build a ciphertext whose transform reproduces a known
//  random plaintext and assert an exact round-trip (incl. incomplete final rows
//  and non-coprime decimation rejection).
//

#include "../polyalphabetic.h"

// rng_state and the transform/gcd/vec_copy symbols come from utils.c +
// transpositions.c at link time (see the `test` target in the makefile).

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

// Is a[] a permutation of {0, ..., len-1}?
static int is_permutation(int a[], int len) {
    int seen[MAX_CIPHER_LENGTH];
    for (int i = 0; i < len; i++) seen[i] = 0;
    for (int i = 0; i < len; i++) {
        if (a[i] < 0 || a[i] >= len || seen[a[i]]) return 0;
        seen[a[i]] = 1;
    }
    return 1;
}

// Fill P[] with a deterministic pseudo-random plaintext in [0,26).
static void random_text(int P[], int len) {
    for (int i = 0; i < len; i++) P[i] = rand_int(0, ALPHABET_SIZE);
}

// --- transperoffset -------------------------------------------------------

static void test_transperoffset(void) {
    int lens[] = {17, 100, 177, 336};
    int ds[]   = {1, 7, 25, 13, 6};   // 6 is NOT coprime to 100/336 -> must skip
    int ns[]   = {0, 11, 50, 200};

    for (int li = 0; li < 4; li++) {
        int len = lens[li];
        for (int di = 0; di < 5; di++) {
            int d = ds[di];
            if (d >= len) continue;
            int coprime = (gcd(d, len) == 1);
            for (int ni = 0; ni < 4; ni++) {
                int n = ns[ni] % len;

                int perm[MAX_CIPHER_LENGTH];
                for (int i = 0; i < len; i++) perm[i] = i;
                transperoffset(perm, len, d, n);

                if (!coprime) {
                    // Non-coprime decimation is not a bijection: confirm the
                    // solver is right to restrict its search to coprime d.
                    CHECK(!is_permutation(perm, len),
                        "transperoffset len=%d d=%d (non-coprime) unexpectedly bijective", len, d);
                    continue;
                }

                CHECK(is_permutation(perm, len),
                    "transperoffset len=%d d=%d n=%d perm not a bijection", len, d, n);

                // Build C such that transperoffset(C) == P, then round-trip.
                int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
                random_text(P, len);
                for (int i = 0; i < len; i++) C[perm[i]] = P[i];
                vec_copy(C, out, len);
                transperoffset(out, len, d, n);

                int ok = 1;
                for (int i = 0; i < len; i++) if (out[i] != P[i]) { ok = 0; break; }
                CHECK(ok, "transperoffset len=%d d=%d n=%d round-trip mismatch", len, d, n);
            }
        }
    }
}

// --- matrix_rotate / transmatrix -----------------------------------------

static void test_matrix_rotate(void) {
    // Mix of widths that divide the length and that leave an incomplete row.
    int lens[]   = {12, 100, 177, 336};
    int widths[] = {2, 3, 7, 9, 11};

    for (int li = 0; li < 4; li++) {
        int len = lens[li];
        for (int wi = 0; wi < 5; wi++) {
            int w = widths[wi];
            if (w >= len) continue;
            for (int dir = 0; dir <= 1; dir++) {
                int perm[MAX_CIPHER_LENGTH];
                for (int i = 0; i < len; i++) perm[i] = i;
                matrix_rotate(perm, len, w, dir);
                CHECK(is_permutation(perm, len),
                    "matrix_rotate len=%d w=%d dir=%d not a bijection", len, w, dir);

                int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
                random_text(P, len);
                for (int i = 0; i < len; i++) C[perm[i]] = P[i];
                vec_copy(C, out, len);
                matrix_rotate(out, len, w, dir);
                int ok = 1;
                for (int i = 0; i < len; i++) if (out[i] != P[i]) { ok = 0; break; }
                CHECK(ok, "matrix_rotate len=%d w=%d dir=%d round-trip mismatch", len, w, dir);
            }
        }
    }
}

static void test_transmatrix(void) {
    int len = 177;
    int pairs[][3] = { {9, 11, 1}, {7, 13, 0}, {2, 3, 1}, {21, 21, 0} };

    for (int p = 0; p < 4; p++) {
        int w1 = pairs[p][0], w2 = pairs[p][1], dir = pairs[p][2];

        int perm[MAX_CIPHER_LENGTH];
        for (int i = 0; i < len; i++) perm[i] = i;
        transmatrix(perm, len, w1, w2, dir);
        CHECK(is_permutation(perm, len),
            "transmatrix w1=%d w2=%d dir=%d not a bijection", w1, w2, dir);

        int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
        random_text(P, len);
        for (int i = 0; i < len; i++) C[perm[i]] = P[i];
        vec_copy(C, out, len);
        transmatrix(out, len, w1, w2, dir);
        int ok = 1;
        for (int i = 0; i < len; i++) if (out[i] != P[i]) { ok = 0; break; }
        CHECK(ok, "transmatrix w1=%d w2=%d dir=%d round-trip mismatch", w1, w2, dir);
    }
}

// --- columnar transposition (decrypt_columnar) ---------------------------
//
// Independent reference encryption: write the plaintext row-major into a grid of
// K columns (leftmost `len % K` columns one cell taller), then read the columns
// off in `order` (each top-to-bottom for COL_READ_TB, bottom-to-top otherwise).
// Coded separately from decrypt_columnar so a round-trip exercises both halves.
static void ref_columnar_encrypt(int P[], int len, int K, int order[], int dir, int ct[]) {
    int grid[MAX_CIPHER_LENGTH];
    int R = (len + K - 1) / K;
    int rem = len % K;

    // Write plaintext row-major (skipping the missing short-row cells).
    int pos = 0;
    for (int r = 0; r < R; r++)
        for (int c = 0; c < K; c++) {
            int h = (rem == 0 || c < rem) ? R : R - 1;
            if (r < h) grid[r * K + c] = P[pos++];
        }

    // Read columns in key order.
    int o = 0;
    for (int j = 0; j < K; j++) {
        int c = order[j];
        int h = (rem == 0 || c < rem) ? R : R - 1;
        if (dir == COL_READ_BT) { for (int r = h - 1; r >= 0; r--) ct[o++] = grid[r * K + c]; }
        else                    { for (int r = 0; r < h; r++)     ct[o++] = grid[r * K + c]; }
    }
}

static int arrays_equal(int a[], int b[], int len) {
    for (int i = 0; i < len; i++) if (a[i] != b[i]) return 0;
    return 1;
}

// Hand-computed known-answer tests: len=7, K=3 -> heights {3,2,2}, order {2,0,1}.
// These pin the exact grid/height/direction semantics independent of the
// reference encrypter above.
static void test_columnar_known_answer(void) {
    int identity[7] = {0,1,2,3,4,5,6};
    int order[3] = {2,0,1};
    int out[7];

    int ct_tb[7] = {2,5,0,3,6,1,4};   // worked example, top-to-bottom
    decrypt_columnar(ct_tb, 7, 3, order, COL_READ_TB, out);
    CHECK(arrays_equal(out, identity, 7), "columnar KAT (tb) mismatch");

    int ct_bt[7] = {5,2,6,3,0,4,1};   // same grid, columns read bottom-to-top
    decrypt_columnar(ct_bt, 7, 3, order, COL_READ_BT, out);
    CHECK(arrays_equal(out, identity, 7), "columnar KAT (bt) mismatch");
}

// Round-trip every sub-type: both read directions, complete and incomplete grids,
// across a range of lengths and column counts.
static void test_columnar_roundtrip(void) {
    int lens[]   = {12, 17, 49, 100, 177, 336};
    int Ks[]     = {2, 3, 5, 7, 9, 11, 13};
    int n_complete = 0, n_incomplete = 0;

    for (int li = 0; li < 6; li++) {
        int len = lens[li];
        for (int ki = 0; ki < 7; ki++) {
            int K = Ks[ki];
            if (K >= len) continue;
            for (int dir = 0; dir <= 1; dir++) {

                // Random column order.
                int order[MAX_COLS];
                for (int c = 0; c < K; c++) order[c] = c;
                shuffle(order, K);

                if (len % K == 0) n_complete++; else n_incomplete++;

                // The recovered position map must be a genuine bijection.
                int ident[MAX_CIPHER_LENGTH], src[MAX_CIPHER_LENGTH];
                for (int i = 0; i < len; i++) ident[i] = i;
                decrypt_columnar(ident, len, K, order, dir, src);
                CHECK(is_permutation(src, len),
                    "columnar len=%d K=%d dir=%d not a bijection", len, K, dir);

                // Encrypt a known plaintext, then decrypt and require exact recovery.
                int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
                random_text(P, len);
                ref_columnar_encrypt(P, len, K, order, dir, C);
                decrypt_columnar(C, len, K, order, dir, out);
                CHECK(arrays_equal(out, P, len),
                    "columnar len=%d K=%d dir=%d round-trip mismatch", len, K, dir);

                // The ciphertext must be a rearrangement of the plaintext multiset.
                int fp[ALPHABET_SIZE] = {0}, fc[ALPHABET_SIZE] = {0};
                for (int i = 0; i < len; i++) { fp[P[i]]++; fc[C[i]]++; }
                int multiset_ok = 1;
                for (int a = 0; a < ALPHABET_SIZE; a++) if (fp[a] != fc[a]) multiset_ok = 0;
                CHECK(multiset_ok, "columnar len=%d K=%d dir=%d ciphertext not a permutation of plaintext",
                    len, K, dir);
            }
        }
    }
    // Make sure the suite actually exercised both grid shapes.
    CHECK(n_complete  > 0, "columnar round-trip never tested a complete grid");
    CHECK(n_incomplete > 0, "columnar round-trip never tested an incomplete grid");
}

// Degenerate column counts collapse to the identity.
static void test_columnar_degenerate(void) {
    int len = 50;
    int P[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
    random_text(P, len);

    int order1[1] = {0};
    decrypt_columnar(P, len, 1, order1, COL_READ_TB, out);
    CHECK(arrays_equal(out, P, len), "columnar K=1 not identity");

    int order_big[MAX_COLS];
    for (int c = 0; c < MAX_COLS; c++) order_big[c] = c;
    decrypt_columnar(P, len, len + 5, order_big, COL_READ_TB, out);
    CHECK(arrays_equal(out, P, len), "columnar K>len not identity");
}

// Double columnar: encrypt with two stacked stages (stage0 then stage1), then
// invert stage1 then stage0 -- the composition the TRANSCOL2 solver decrypts.
static void test_columnar_double(void) {
    int cfgs[][5] = {
        // len, K1, dir1, K2, dir2
        {100, 7,  COL_READ_TB, 9,  COL_READ_TB},
        {177, 11, COL_READ_BT, 5,  COL_READ_TB},
        {336, 13, COL_READ_TB, 8,  COL_READ_BT},
        {97,  6,  COL_READ_BT, 7,  COL_READ_BT},
    };

    for (int t = 0; t < 4; t++) {
        int len = cfgs[t][0], K1 = cfgs[t][1], d1 = cfgs[t][2], K2 = cfgs[t][3], d2 = cfgs[t][4];

        int order1[MAX_COLS], order2[MAX_COLS];
        for (int c = 0; c < K1; c++) order1[c] = c;
        for (int c = 0; c < K2; c++) order2[c] = c;
        shuffle(order1, K1);
        shuffle(order2, K2);

        int P[MAX_CIPHER_LENGTH], s1[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH];
        int t1[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
        random_text(P, len);

        ref_columnar_encrypt(P,  len, K1, order1, d1, s1);   // stage 0 (inner)
        ref_columnar_encrypt(s1, len, K2, order2, d2, C);    // stage 1 (outer)

        decrypt_columnar(C,  len, K2, order2, d2, t1);       // undo outer
        decrypt_columnar(t1, len, K1, order1, d1, out);      // undo inner

        CHECK(arrays_equal(out, P, len),
            "double columnar len=%d K1=%d K2=%d round-trip mismatch", len, K1, K2);
    }
}

static void test_gcd(void) {
    CHECK(gcd(7, 177) == 1, "gcd(7,177)");
    CHECK(gcd(6, 100) == 2, "gcd(6,100)");
    CHECK(gcd(12, 8) == 4, "gcd(12,8)");
    CHECK(gcd(5, 0) == 5, "gcd(5,0)");
    CHECK(gcd(0, 9) == 9, "gcd(0,9)");
}

int main(void) {
    seed_rand(987654321u);

    test_gcd();
    test_transperoffset();
    test_matrix_rotate();
    test_transmatrix();
    test_columnar_known_answer();
    test_columnar_roundtrip();
    test_columnar_degenerate();
    test_columnar_double();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
