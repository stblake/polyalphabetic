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

#include "colossus.h"

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

// --- rail fence (decrypt_railfence) --------------------------------------
//
// Independent reference encryption: read the plaintext off rail by rail (the
// inverse of what decrypt_railfence does for variant==0). Two invariants tie the
// standard and variant directions together without trusting either alone:
//   C = encrypt(P);  decrypt(C, variant=0) == P   (standard recovery)
//                    decrypt(P, variant=1) == C   (variant applies the forward map)
static void ref_railfence_encrypt(int P[], int len, int rails, int offset, int ct[]) {
    int Pp = 2 * (rails - 1);
    int pos = 0;
    for (int r = 0; r < rails; r++)
        for (int i = 0; i < len; i++) {
            int ph = (i + offset) % Pp;
            int rail = (ph < rails) ? ph : Pp - ph;
            if (rail == r) ct[pos++] = P[i];
        }
}

static void test_railfence(void) {
    int lens[]  = {40, 47, 61, 100, 177};
    int railv[] = {2, 3, 4, 7, 9};

    for (int li = 0; li < 5; li++) {
        int len = lens[li];
        for (int ri = 0; ri < 5; ri++) {
            int rails = railv[ri];
            if (rails >= len) continue;
            int P = 2 * (rails - 1);
            for (int offset = 0; offset < P; offset++) {

                // Position map is a genuine bijection (both directions).
                int ident[MAX_CIPHER_LENGTH], map0[MAX_CIPHER_LENGTH], map1[MAX_CIPHER_LENGTH];
                for (int i = 0; i < len; i++) ident[i] = i;
                decrypt_railfence(ident, len, rails, offset, 0, map0);
                decrypt_railfence(ident, len, rails, offset, 1, map1);
                CHECK(is_permutation(map0, len),
                    "railfence len=%d rails=%d off=%d (std) not a bijection", len, rails, offset);
                CHECK(is_permutation(map1, len),
                    "railfence len=%d rails=%d off=%d (var) not a bijection", len, rails, offset);

                int Pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
                random_text(Pt, len);
                ref_railfence_encrypt(Pt, len, rails, offset, C);

                decrypt_railfence(C, len, rails, offset, 0, out);
                CHECK(arrays_equal(out, Pt, len),
                    "railfence len=%d rails=%d off=%d standard round-trip mismatch", len, rails, offset);

                decrypt_railfence(Pt, len, rails, offset, 1, out);
                CHECK(arrays_equal(out, C, len),
                    "railfence len=%d rails=%d off=%d variant round-trip mismatch", len, rails, offset);
            }
        }
    }
}

// --- route transposition (decrypt_route) ---------------------------------

static void ref_route_encrypt(int P[], int len, int R, int C, int route_id, int ct[]) {
    int cells[MAX_CIPHER_LENGTH];
    route_cells(R, C, len, route_id, cells);
    for (int k = 0; k < len; k++) ct[k] = P[cells[k]];
}

// Known-answer: 2x3 rows-snake reads (0,1,2) then (5,4,3).
static void test_route_known_answer(void) {
    int P[6] = {0,1,2,3,4,5}, ct[6], out[6];
    int expect_ct[6] = {0,1,2,5,4,3};
    ref_route_encrypt(P, 6, 2, 3, 0, ct);
    CHECK(arrays_equal(ct, expect_ct, 6), "route KAT (2x3 rows-snake) encrypt mismatch");
    decrypt_route(ct, 6, 2, 3, 0, 0, out);
    CHECK(arrays_equal(out, P, 6), "route KAT (2x3 rows-snake) decrypt mismatch");
}

static void test_route(void) {
    // (R,C) pairs spanning square and rectangular grids.
    int pairs[][2] = { {2,3}, {3,4}, {5,5}, {7,9}, {4,25}, {10,10} };

    for (int p = 0; p < 6; p++) {
        int R = pairs[p][0], C = pairs[p][1], len = R * C;
        for (int route_id = 0; route_id < N_ROUTES; route_id++) {

            int cells[MAX_CIPHER_LENGTH];
            route_cells(R, C, len, route_id, cells);
            CHECK(is_permutation(cells, len),
                "route %dx%d id=%d cell order not a bijection", R, C, route_id);

            int Pt[MAX_CIPHER_LENGTH], ct[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
            random_text(Pt, len);
            ref_route_encrypt(Pt, len, R, C, route_id, ct);

            decrypt_route(ct, len, R, C, route_id, 0, out);
            CHECK(arrays_equal(out, Pt, len),
                "route %dx%d id=%d standard round-trip mismatch", R, C, route_id);

            decrypt_route(Pt, len, R, C, route_id, 1, out);
            CHECK(arrays_equal(out, ct, len),
                "route %dx%d id=%d variant round-trip mismatch", R, C, route_id);
        }
    }
}

// Ragged grids (short final row, len not a multiple of C): every route must still
// be a bijection over the surviving cells and round-trip cleanly in both directions.
static void test_route_ragged(void) {
    // (R,C,len) with (R-1)*C < len < R*C, so the last row is partial.
    int cases[][3] = { {2,3,5}, {3,4,10}, {4,5,18}, {6,7,38}, {5,8,33}, {9,9,73} };

    for (int p = 0; p < 6; p++) {
        int R = cases[p][0], C = cases[p][1], len = cases[p][2];
        for (int route_id = 0; route_id < N_ROUTES; route_id++) {

            int cells[MAX_CIPHER_LENGTH];
            int n = route_cells(R, C, len, route_id, cells);
            CHECK(n == len, "ragged route %dx%d len=%d id=%d emitted %d cells",
                R, C, len, route_id, n);
            CHECK(is_permutation(cells, len),
                "ragged route %dx%d len=%d id=%d cell order not a bijection",
                R, C, len, route_id);

            int Pt[MAX_CIPHER_LENGTH], ct[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
            random_text(Pt, len);
            ref_route_encrypt(Pt, len, R, C, route_id, ct);

            decrypt_route(ct, len, R, C, route_id, 0, out);
            CHECK(arrays_equal(out, Pt, len),
                "ragged route %dx%d len=%d id=%d standard round-trip mismatch",
                R, C, len, route_id);

            decrypt_route(Pt, len, R, C, route_id, 1, out);
            CHECK(arrays_equal(out, ct, len),
                "ragged route %dx%d len=%d id=%d variant round-trip mismatch",
                R, C, len, route_id);
        }
    }
}

// --- Amsco (decrypt_amsco) -----------------------------------------------
//
// Independent reference encryption: rebuild the alternating-chunk grid, then read
// the columns off in key order. Coded separately from decrypt_amsco so a round-trip
// exercises both halves, plus the same C=encrypt(P)/decrypt(C)==P,
// decrypt(P,variant)==C invariants used elsewhere.
static void ref_amsco_encrypt(int P[], int len, int K, int order[], int start, int ct[]) {
    int cell_size[MAX_CIPHER_LENGTH], cell_off[MAX_CIPHER_LENGTH];
    int sz_even = start, sz_odd = (start == 1) ? 2 : 1;
    int n_cells = 0, placed = 0;
    while (placed < len) {
        int nominal = ((n_cells & 1) == 0) ? sz_even : sz_odd;
        int sz = (len - placed < nominal) ? (len - placed) : nominal;
        cell_off[n_cells] = placed; cell_size[n_cells] = sz;
        placed += sz; n_cells++;
    }
    int o = 0;
    for (int j = 0; j < K; j++) {
        int c = order[j];
        for (int m = c; m < n_cells; m += K)
            for (int i = 0; i < cell_size[m]; i++) ct[o++] = P[cell_off[m] + i];
    }
}

static void test_amsco(void) {
    int lens[] = {69, 84, 96, 100, 113};
    int Ks[]   = {3, 4, 5, 7, 8};

    for (int li = 0; li < 5; li++) {
        int len = lens[li];
        for (int ki = 0; ki < 5; ki++) {
            int K = Ks[ki];
            if (K >= len) continue;
            for (int start = 1; start <= 2; start++) {
                int order[MAX_COLS];
                for (int c = 0; c < K; c++) order[c] = c;
                shuffle(order, K);

                // Position map is a genuine bijection.
                int ident[MAX_CIPHER_LENGTH], map[MAX_CIPHER_LENGTH];
                for (int i = 0; i < len; i++) ident[i] = i;
                decrypt_amsco(ident, len, K, order, start, 0, map);
                CHECK(is_permutation(map, len),
                    "amsco len=%d K=%d start=%d not a bijection", len, K, start);

                int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
                random_text(P, len);
                ref_amsco_encrypt(P, len, K, order, start, C);

                decrypt_amsco(C, len, K, order, start, 0, out);
                CHECK(arrays_equal(out, P, len),
                    "amsco len=%d K=%d start=%d standard round-trip mismatch", len, K, start);

                decrypt_amsco(P, len, K, order, start, 1, out);
                CHECK(arrays_equal(out, C, len),
                    "amsco len=%d K=%d start=%d variant round-trip mismatch", len, K, start);
            }
        }
    }
}

// --- Myszkowski (decrypt_myszkowski) -------------------------------------
//
// Reference encryption honouring tied ranks (tied columns read row-by-row
// together). The rank vectors deliberately include ties so the row-by-row path is
// exercised, not just the all-distinct (plain columnar) degenerate case.
static void ref_mysz_encrypt(int P[], int len, int K, int rank[], int ct[]) {
    int R = (len + K - 1) / K;
    int o = 0;
    int done[MAX_COLS]; for (int c = 0; c < K; c++) done[c] = 0;
    int processed = 0;
    while (processed < K) {
        int v = 0, have_v = 0;
        for (int c = 0; c < K; c++)
            if (!done[c] && (!have_v || rank[c] < v)) { v = rank[c]; have_v = 1; }
        int group[MAX_COLS], g = 0;
        for (int c = 0; c < K; c++) if (!done[c] && rank[c] == v) { group[g++] = c; done[c] = 1; }
        processed += g;
        if (g == 1) {
            for (int r = 0; r < R; r++) { int pos = r * K + group[0]; if (pos < len) ct[o++] = P[pos]; }
        } else {
            for (int r = 0; r < R; r++)
                for (int gi = 0; gi < g; gi++) { int pos = r * K + group[gi]; if (pos < len) ct[o++] = P[pos]; }
        }
    }
}

static void test_myszkowski(void) {
    // Rank vectors with intentional ties (and one all-distinct = plain columnar).
    int len = 110;
    int ranks[][8] = {
        {2, 0, 1, 0, 2, 1, 0, 0},   // many ties
        {0, 1, 2, 3, 4, 5, 6, 7},   // all distinct (columnar)
        {1, 1, 0, 2, 2, 0, 1, 0},   // mixed
        {0, 0, 0, 1, 1, 1, 2, 2},   // block ties
    };
    for (int t = 0; t < 4; t++) {
        int K = 8;
        int *rank = ranks[t];

        int ident[MAX_CIPHER_LENGTH], map[MAX_CIPHER_LENGTH];
        for (int i = 0; i < len; i++) ident[i] = i;
        decrypt_myszkowski(ident, len, K, rank, 0, map);
        CHECK(is_permutation(map, len), "myszkowski case %d not a bijection", t);

        int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
        random_text(P, len);
        ref_mysz_encrypt(P, len, K, rank, C);

        decrypt_myszkowski(C, len, K, rank, 0, out);
        CHECK(arrays_equal(out, P, len), "myszkowski case %d standard round-trip mismatch", t);

        decrypt_myszkowski(P, len, K, rank, 1, out);
        CHECK(arrays_equal(out, C, len), "myszkowski case %d variant round-trip mismatch", t);
    }
}

// --- redefence (decrypt_redefence) ---------------------------------------
static void ref_redefence_encrypt(int P[], int len, int rails, int offset, int order[], int ct[]) {
    int Pp = 2 * (rails - 1), o = 0;
    for (int j = 0; j < rails; j++)
        for (int i = 0; i < len; i++) {
            int ph = (i + offset) % Pp, rail = (ph < rails) ? ph : Pp - ph;
            if (rail == order[j]) ct[o++] = P[i];
        }
}
static void test_redefence(void) {
    int lens[] = {50, 54, 63, 100}, railv[] = {3, 4, 5, 7};
    for (int li = 0; li < 4; li++) for (int ri = 0; ri < 4; ri++) {
        int len = lens[li], rails = railv[ri];
        if (rails >= len) continue;
        int P = 2 * (rails - 1);
        for (int offset = 0; offset < P; offset++) {
            int order[MAX_COLS];
            for (int c = 0; c < rails; c++) order[c] = c;
            shuffle(order, rails);
            int ident[MAX_CIPHER_LENGTH], map[MAX_CIPHER_LENGTH];
            for (int i = 0; i < len; i++) ident[i] = i;
            decrypt_redefence(ident, len, rails, offset, order, 0, map);
            CHECK(is_permutation(map, len), "redefence len=%d rails=%d off=%d not a bijection", len, rails, offset);
            int Pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
            random_text(Pt, len);
            ref_redefence_encrypt(Pt, len, rails, offset, order, C);
            decrypt_redefence(C, len, rails, offset, order, 0, out);
            CHECK(arrays_equal(out, Pt, len), "redefence len=%d rails=%d off=%d round-trip mismatch", len, rails, offset);
            decrypt_redefence(Pt, len, rails, offset, order, 1, out);
            CHECK(arrays_equal(out, C, len), "redefence len=%d rails=%d off=%d variant mismatch", len, rails, offset);
        }
    }
}

// --- Cadenus (decrypt_cadenus) -------------------------------------------
static void ref_cadenus_encrypt(int P[], int len, int K, int order[], int rot[], int ct[]) {
    int rows = len / K;
    for (int r = 0; r < rows; r++)
        for (int p = 0; p < K; p++) {
            int c = order[p];
            ct[r * K + p] = P[((r + rot[c]) % rows) * K + c];
        }
}
static void test_cadenus(void) {
    int lens[] = {100, 125, 150, 250};   // multiples of 25
    for (int li = 0; li < 4; li++) {
        int len = lens[li], K = len / 25, rows = 25;
        int order[MAX_COLS], rot[MAX_COLS];
        for (int c = 0; c < K; c++) order[c] = c;
        shuffle(order, K);
        for (int c = 0; c < K; c++) rot[c] = rand_int(0, rows);
        int ident[MAX_CIPHER_LENGTH], map[MAX_CIPHER_LENGTH];
        for (int i = 0; i < len; i++) ident[i] = i;
        decrypt_cadenus(ident, len, K, order, rot, 0, map);
        CHECK(is_permutation(map, len), "cadenus len=%d not a bijection", len);
        int Pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
        random_text(Pt, len);
        ref_cadenus_encrypt(Pt, len, K, order, rot, C);
        decrypt_cadenus(C, len, K, order, rot, 0, out);
        CHECK(arrays_equal(out, Pt, len), "cadenus len=%d round-trip mismatch", len);
        decrypt_cadenus(Pt, len, K, order, rot, 1, out);
        CHECK(arrays_equal(out, C, len), "cadenus len=%d variant mismatch", len);
    }
}

// --- Nihilist transposition (decrypt_nihilist) ---------------------------
static void ref_nihilist_encrypt(int P[], int N, int rowperm[], int colperm[], int readmode, int ct[]) {
    for (int r = 0; r < N; r++)
        for (int c = 0; c < N; c++) {
            int k = (readmode == 1) ? (c * N + r) : (r * N + c);
            ct[k] = P[rowperm[r] * N + colperm[c]];
        }
}
static void test_nihilist(void) {
    int Ns[] = {6, 8, 9, 10};
    for (int ni = 0; ni < 4; ni++) {
        int N = Ns[ni], len = N * N;
        int rowperm[MAX_COLS], colperm[MAX_COLS];
        for (int c = 0; c < N; c++) { rowperm[c] = c; colperm[c] = c; }
        shuffle(rowperm, N); shuffle(colperm, N);
        for (int readmode = 0; readmode <= 1; readmode++) {
            int ident[MAX_CIPHER_LENGTH], map[MAX_CIPHER_LENGTH];
            for (int i = 0; i < len; i++) ident[i] = i;
            decrypt_nihilist(ident, len, N, rowperm, colperm, readmode, 0, map);
            CHECK(is_permutation(map, len), "nihilist N=%d read=%d not a bijection", N, readmode);
            int Pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
            random_text(Pt, len);
            ref_nihilist_encrypt(Pt, N, rowperm, colperm, readmode, C);
            decrypt_nihilist(C, len, N, rowperm, colperm, readmode, 0, out);
            CHECK(arrays_equal(out, Pt, len), "nihilist N=%d read=%d round-trip mismatch", N, readmode);
            decrypt_nihilist(Pt, len, N, rowperm, colperm, readmode, 1, out);
            CHECK(arrays_equal(out, C, len), "nihilist N=%d read=%d variant mismatch", N, readmode);
        }
    }
}

// --- Swagman (decrypt_swagman) -------------------------------------------
static void ref_swagman_encrypt(int P[], int len, int N, int square[], int readmode, int ct[]) {
    int W = len / N, pod[7][7];
    for (int j = 0; j < N; j++) for (int r = 0; r < N; r++) pod[j][square[r * N + j]] = r;
    for (int i = 0; i < N; i++)
        for (int jj = 0; jj < W; jj++) {
            int pt = pod[jj % N][i] * W + jj;
            int k = (readmode == 1) ? (jj * N + i) : (i * W + jj);
            ct[k] = P[pt];
        }
}
static void test_swagman(void) {
    int cfgs[][2] = { {3, 96}, {4, 100}, {5, 95}, {7, 147} };  // {N, len} with len % N == 0
    for (int t = 0; t < 4; t++) {
        int N = cfgs[t][0], len = cfgs[t][1];
        int square[49], col[8];
        for (int j = 0; j < N; j++) {                          // each square column a permutation
            for (int r = 0; r < N; r++) col[r] = r;
            shuffle(col, N);
            for (int r = 0; r < N; r++) square[r * N + j] = col[r];
        }
        for (int readmode = 0; readmode <= 1; readmode++) {
            int ident[MAX_CIPHER_LENGTH], map[MAX_CIPHER_LENGTH];
            for (int i = 0; i < len; i++) ident[i] = i;
            decrypt_swagman(ident, len, N, square, readmode, 0, map);
            CHECK(is_permutation(map, len), "swagman N=%d read=%d not a bijection", N, readmode);
            int Pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
            random_text(Pt, len);
            ref_swagman_encrypt(Pt, len, N, square, readmode, C);
            decrypt_swagman(C, len, N, square, readmode, 0, out);
            CHECK(arrays_equal(out, Pt, len), "swagman N=%d read=%d round-trip mismatch", N, readmode);
            decrypt_swagman(Pt, len, N, square, readmode, 1, out);
            CHECK(arrays_equal(out, C, len), "swagman N=%d read=%d variant mismatch", N, readmode);
        }
    }
}

// --- turning grille (decrypt_grille) -------------------------------------
// Reference encryption: replay the four turns to map plaintext write-order to
// cells, then read the grid row-major. Independent of decrypt_grille's internals
// except the shared orbit numbering, which we recompute identically here.
static void test_grille(void) {
    int Ns[] = {4, 6, 8, 9, 10};   // include odd N=9 (centre orbit of size 1)
    for (int ni = 0; ni < 5; ni++) {
        int N = Ns[ni], len = N * N;

        // Build a random key of the right length by probing the orbit count.
        int probe = 0, zero[MAX_TRANS_KEY] = {0}, ztmp[MAX_CIPHER_LENGTH];
        decrypt_grille(zero, len, N, zero, 0, ztmp, &probe);
        CHECK(probe > 0, "grille N=%d zero orbit count", N);
        int key[MAX_TRANS_KEY];
        for (int i = 0; i < probe; i++) key[i] = rand_int(0, 4);

        int norb = 0;
        int ident[MAX_CIPHER_LENGTH], ptmap[MAX_CIPHER_LENGTH];
        for (int i = 0; i < len; i++) ident[i] = i;
        // variant=1 on the identity returns pt_of_ct directly (out[k] = pt_of_ct[k]):
        // ptmap[cell] = plaintext index written into that cell.
        decrypt_grille(ident, len, N, key, 1, ptmap, &norb);
        CHECK(is_permutation(ptmap, len), "grille N=%d not a bijection", N);

        int Pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], out[MAX_CIPHER_LENGTH];
        random_text(Pt, len);
        for (int k = 0; k < len; k++) C[k] = Pt[ptmap[k]];   // grid row-major = ciphertext
        decrypt_grille(C, len, N, key, 0, out, NULL);
        CHECK(arrays_equal(out, Pt, len), "grille N=%d round-trip mismatch", N);
        decrypt_grille(Pt, len, N, key, 1, out, NULL);
        CHECK(arrays_equal(out, C, len), "grille N=%d variant mismatch", N);
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
    test_railfence();
    test_route_known_answer();
    test_route();
    test_route_ragged();
    test_amsco();
    test_myszkowski();
    test_redefence();
    test_cadenus();
    test_nihilist();
    test_swagman();
    test_grille();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
