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

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
