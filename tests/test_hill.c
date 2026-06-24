//
//  Unit tests for the Hill primitives (matrix multiply / encrypt / decrypt / mod- and
//  matrix-inverse / keyword build).
//
//  Framework-free: build with `make test`, which links this against hill.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Strategy: a hand-computed known-answer vector (the Wikipedia "Hill cipher" worked
//  example -- encryption key GYBNQKURP, i.e. rows [6 24 1][13 16 10][20 17 15],
//  plaintext ACT -> POH and CAT -> FIN) pins the actual convention: row-major matrix
//  layout, column-vector blocks, and mod-26 arithmetic. A transpose or an index mix-up is
//  caught, not just a self-consistent round-trip. Then the modular inverse is checked over
//  all residues mod 26 (12 units, 14 non-units), the matrix inverse is checked by
//  M*inv == I and inv(inv) == M over random invertible matrices and rejected for known
//  singular ones, and decrypt(encrypt(P)) == P over random invertible keys, block sizes
//  k = 2..5 and lengths (including non-multiples of k, exercising the partial-block
//  pass-through) covers the general case.
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

// A..Z string -> 0..25 alphabet indices (full 26-letter alphabet, no J merge).
static int str_to_idx(const char *s, int out[]) {
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

// out = a * b (both k x k, row-major) mod 26.
static void matmul_mod(const int a[], const int b[], int k, int out[]) {
    for (int i = 0; i < k; i++)
        for (int j = 0; j < k; j++) {
            int s = 0;
            for (int t = 0; t < k; t++) s += a[i * k + t] * b[t * k + j];
            out[i * k + j] = ((s % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
        }
}

static int is_identity(const int m[], int k) {
    for (int i = 0; i < k; i++)
        for (int j = 0; j < k; j++)
            if (m[i * k + j] != (i == j ? 1 : 0)) return 0;
    return 1;
}

static void rand_invertible(int mat[], int k) {
    int inv[HILL_MAX_KEY];
    do {
        for (int i = 0; i < k * k; i++) mat[i] = rand_int(0, ALPHABET_SIZE);
    } while (!hill_mat_inverse(mat, k, inv));
}

// --- Known-answer vector (Wikipedia "Hill cipher" worked example) ---------------

static void test_hill_known_answer(void) {
    // Encryption key GYBNQKURP = [6 24 1 / 13 16 10 / 20 17 15].
    int key[HILL_MAX_KEY];
    int kn = str_to_idx("GYBNQKURP", key);
    CHECK(kn == 9, "KAT key is not 9 letters (%d)", kn);

    int plain[8], cipher[8], back[8];
    char cbuf[9];

    int plen = str_to_idx("ACT", plain);
    hill_encrypt(plain, plen, key, 3, cipher);
    idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "POH") == 0, "hill encrypt KAT ACT: got '%s', want 'POH'", cbuf);
    hill_decrypt(cipher, plen, key, 3, back);
    CHECK(arrays_equal(back, plain, plen), "hill decrypt KAT ACT round-trip mismatch");

    plen = str_to_idx("CAT", plain);
    hill_encrypt(plain, plen, key, 3, cipher);
    idx_to_str(cipher, plen, cbuf);
    CHECK(strcmp(cbuf, "FIN") == 0, "hill encrypt KAT CAT: got '%s', want 'FIN'", cbuf);
    hill_decrypt(cipher, plen, key, 3, back);
    CHECK(arrays_equal(back, plain, plen), "hill decrypt KAT CAT round-trip mismatch");

    // det(GYBNQKURP) = 441 = 25 (mod 26), a unit -> invertible.
    CHECK(hill_det_mod(key, 3) == 25, "hill det KAT: got %d, want 25", hill_det_mod(key, 3));
}

// --- modular inverse over all residues mod 26 ---------------------------------

static void test_mod_inverse(void) {
    int units[] = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
    char is_unit[26] = {0};
    for (int i = 0; i < 12; i++) {
        int a = units[i];
        is_unit[a] = 1;
        int inv = hill_mod_inverse(a, ALPHABET_SIZE);
        CHECK(inv != 0, "hill_mod_inverse(%d,26) reported non-invertible", a);
        CHECK((a * inv) % ALPHABET_SIZE == 1,
            "hill_mod_inverse(%d,26)=%d but product is %d", a, inv, (a * inv) % 26);
    }
    for (int a = 0; a < 26; a++)
        if (!is_unit[a])
            CHECK(hill_mod_inverse(a, ALPHABET_SIZE) == 0,
                "hill_mod_inverse(%d,26) should be 0 (not coprime to 26)", a);
}

// --- matrix inverse: round-trips and singular rejection -----------------------

static void test_mat_inverse(void) {
    // M * inv(M) == I and inv(inv(M)) == M over random invertible matrices, k = 2..5.
    for (int k = 2; k <= HILL_MAX_K; k++) {
        for (int t = 0; t < 2000; t++) {
            int M[HILL_MAX_KEY], inv[HILL_MAX_KEY], inv2[HILL_MAX_KEY], prod[HILL_MAX_KEY];
            rand_invertible(M, k);
            CHECK(hill_mat_inverse(M, k, inv), "k=%d random matrix not invertible after reject-sample", k);
            matmul_mod(M, inv, k, prod);
            CHECK(is_identity(prod, k), "k=%d M*inv(M) != I", k);
            CHECK(hill_mat_inverse(inv, k, inv2), "k=%d inv(M) not invertible", k);
            CHECK(arrays_equal(inv2, M, k * k), "k=%d inv(inv(M)) != M", k);
        }
    }
    // Singular: a matrix with two equal rows has det 0 (divisible by 2 and 13).
    int s2[] = {3, 7, 3, 7};
    CHECK(hill_mat_inverse(s2, 2, (int[HILL_MAX_KEY]){0}) == 0, "2x2 equal-rows should be singular");
    // det divisible by 13 only (so gcd(det,26)=13): [[13,0],[0,1]] -> det 13.
    int s13[] = {13, 0, 0, 1};
    CHECK(hill_det_mod(s13, 2) == 13, "det [[13,0],[0,1]] should be 13");
    CHECK(hill_mat_inverse(s13, 2, (int[HILL_MAX_KEY]){0}) == 0, "det==13 should be singular mod 26");
    // det divisible by 2 only: [[2,0],[0,1]] -> det 2, gcd(2,26)=2.
    int s2b[] = {2, 0, 0, 1};
    CHECK(hill_mat_inverse(s2b, 2, (int[HILL_MAX_KEY]){0}) == 0, "det==2 should be singular mod 26");
}

// --- determinant spot checks --------------------------------------------------

static void test_det(void) {
    int m2[] = {1, 2, 3, 4};                  // det = 1*4 - 2*3 = -2 = 24 (mod 26)
    CHECK(hill_det_mod(m2, 2) == 24, "det [[1,2],[3,4]] mod 26: got %d, want 24", hill_det_mod(m2, 2));
    int id3[] = {1, 0, 0, 0, 1, 0, 0, 0, 1};  // identity -> det 1
    CHECK(hill_det_mod(id3, 3) == 1, "det I3: got %d, want 1", hill_det_mod(id3, 3));
}

// --- round-trip over random invertible keys, block sizes and lengths ----------

static void test_hill_roundtrip(void) {
    for (int k = 2; k <= HILL_MAX_K; k++) {
        for (int t = 0; t < 3000; t++) {
            int key[HILL_MAX_KEY];
            rand_invertible(key, k);
            int len = 1 + rand_int(0, 600);   // includes lengths not a multiple of k
            int plain[640], cipher[640], back[640];
            for (int i = 0; i < len; i++) plain[i] = rand_int(0, ALPHABET_SIZE);
            hill_encrypt(plain, len, key, k, cipher);
            hill_decrypt(cipher, len, key, k, back);
            CHECK(arrays_equal(back, plain, len),
                "hill round-trip mismatch (k=%d len=%d)", k, len);
        }
    }
}

// --- k = 1 edge cases ---------------------------------------------------------

static void test_hill_k1(void) {
    // [1] is the identity; a general invertible [a] is a multiplicative cipher.
    int id[] = {1};
    int len = 40, plain[64], cipher[64], back[64];
    for (int i = 0; i < len; i++) plain[i] = rand_int(0, ALPHABET_SIZE);
    hill_encrypt(plain, len, id, 1, cipher);
    CHECK(arrays_equal(cipher, plain, len), "hill k=1 [1] is not the identity");

    int key[] = {7};                          // 7 is a unit mod 26
    hill_encrypt(plain, len, key, 1, cipher);
    hill_decrypt(cipher, len, key, 1, back);
    CHECK(arrays_equal(back, plain, len), "hill k=1 multiplicative round-trip mismatch");
}

// --- keyword build ------------------------------------------------------------

static void test_hill_keyword(void) {
    // "HILL" = H I L L = 7 8 11 11; cycled into a 3x3 (9 entries):
    //   7 8 11 / 11 7 8 / 11 11 7
    int kw[8], mat[HILL_MAX_KEY];
    int kwn = str_to_idx("HILL", kw);
    hill_matrix_from_keyword(kw, kwn, mat, 3);
    int expect[] = {7, 8, 11, 11, 7, 8, 11, 11, 7};
    CHECK(arrays_equal(mat, expect, 9), "hill keyword build (cycled) mismatch");
}

int main(void) {
    seed_rand(20240714u);
    init_alphabet(NULL);                       // full 26-letter alphabet
    CHECK(g_alpha == ALPHABET_SIZE, "alphabet size %d, expected 26", g_alpha);

    test_hill_known_answer();
    test_mod_inverse();
    test_mat_inverse();
    test_det();
    test_hill_roundtrip();
    test_hill_k1();
    test_hill_keyword();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
