//
//  Unit tests for the Gronsfeld cipher primitives (gronsfeld.c).
//
//  Framework-free: build with `make test`, which links this against gronsfeld.c +
//  vigenere.c + quagmire.c + utils.c. Exits non-zero if any check fails.
//
//  The Gronsfeld cipher is a Vigenere cipher with a NUMERIC key: each key digit
//  0..9 shifts a column by that amount (C = P + d, P = C - d, mod 26). So the core
//  invariants are: a hand-computed known-answer vector pinning the convention (sign
//  of the shift, key cycling, the zero-shift identity column, and the mod-26 wrap),
//  the encrypt/decrypt round-trip over many lengths and key lengths, and exact
//  agreement with the Vigenere primitive fed the same digits as its cycleword
//  (which is precisely the claim that Gronsfeld == digit-restricted Vigenere).
//

#include "../colossus.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

static int arrays_equal(int a[], int b[], int len) {
    for (int i = 0; i < len; i++) if (a[i] != b[i]) return 0;
    return 1;
}

// Deterministic pseudo-random plaintext in [0,26).
static void random_text(int P[], int len) {
    for (int i = 0; i < len; i++) P[i] = rand_int(0, ALPHABET_SIZE);
}

// A random Gronsfeld key: digits in [0,10).
static void random_key(int key[], int len) {
    for (int i = 0; i < len; i++) key[i] = rand_int(0, GRONSFELD_DIGITS);
}

// Convert an A-Z string to its 0-25 index array.
static void str_to_indices(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) out[i] = s[i] - 'A';
}

// Convert a digit string to its 0-9 key array.
static void digits_to_key(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) out[i] = s[i] - '0';
}

// --- Known-answer vector --------------------------------------------------

static void test_gronsfeld_known_answer(void) {
    // HELLOWORLD + key 12345 (cycled) -> IGOPTXQUPI  (C = P + d mod 26).
    int P[10], C[10], expected[10], key[5], back[10];
    str_to_indices("HELLOWORLD", P);
    str_to_indices("IGOPTXQUPI", expected);
    digits_to_key("12345", key);

    gronsfeld_encrypt(C, P, 10, key, 5);
    CHECK(arrays_equal(C, expected, 10), "gronsfeld KAT encrypt mismatch");

    gronsfeld_decrypt(back, C, 10, key, 5);
    CHECK(arrays_equal(back, P, 10), "gronsfeld KAT decrypt mismatch");

    // Zero-shift columns are the identity: key 00000 leaves the plaintext untouched.
    int zero[5] = {0, 0, 0, 0, 0}, Cz[10];
    gronsfeld_encrypt(Cz, P, 10, zero, 5);
    CHECK(arrays_equal(Cz, P, 10), "gronsfeld zero key is not identity");

    // Mod-26 wrap: Z (25) + 9 = 34 mod 26 = 8 = I; and the inverse wraps back.
    int z = 25, k9 = 9, cz, pz;
    gronsfeld_encrypt(&cz, &z, 1, &k9, 1);
    CHECK(cz == 8, "gronsfeld wrap encrypt: Z+9 should be I (8), got %d", cz);
    gronsfeld_decrypt(&pz, &cz, 1, &k9, 1);
    CHECK(pz == 25, "gronsfeld wrap decrypt did not return Z");
}

// --- Round-trip stress ----------------------------------------------------

static void test_gronsfeld_roundtrip(void) {
    int lens[]   = {1, 25, 97, 336, 600};
    int keylens[] = {1, 3, 5, 7, 11};
    for (int li = 0; li < 5; li++) {
        int len = lens[li];
        for (int ki = 0; ki < 5; ki++) {
            int keylen = keylens[ki];
            int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
            int key[MAX_CYCLEWORD_LEN];
            random_text(P, len);
            random_key(key, keylen);
            gronsfeld_encrypt(C, P, len, key, keylen);
            gronsfeld_decrypt(back, C, len, key, keylen);
            CHECK(arrays_equal(back, P, len),
                "gronsfeld round-trip len=%d keylen=%d", len, keylen);
        }
    }
}

// --- Equivalence with Vigenere -------------------------------------------
//
// Gronsfeld is exactly Vigenere restricted to the 10 smallest shifts: feeding the
// digit key to vigenere_*(variant=false) as its cycleword must reproduce the
// gronsfeld_* output bit-for-bit. This guards the solver's reuse of the polyalpha
// pipeline (which derives Vigenere-tableau shifts and decrypts via gronsfeld_decrypt).

static void test_gronsfeld_matches_vigenere(void) {
    int lens[]   = {26, 97, 300};
    int keylens[] = {1, 5, 9};
    for (int li = 0; li < 3; li++) {
        int len = lens[li];
        for (int ki = 0; ki < 3; ki++) {
            int keylen = keylens[ki];
            int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], vg[MAX_CIPHER_LENGTH];
            int gd[MAX_CIPHER_LENGTH], vd[MAX_CIPHER_LENGTH];
            int key[MAX_CYCLEWORD_LEN];
            random_text(P, len);
            random_key(key, keylen);

            // Encrypt agreement.
            gronsfeld_encrypt(C, P, len, key, keylen);
            vigenere_encrypt(vg, P, len, key, keylen, false);
            CHECK(arrays_equal(C, vg, len),
                "gronsfeld vs vigenere encrypt disagree len=%d keylen=%d", len, keylen);

            // Decrypt agreement (decrypt a random ciphertext both ways).
            gronsfeld_decrypt(gd, P, len, key, keylen);
            vigenere_decrypt(vd, P, len, key, keylen, false);
            CHECK(arrays_equal(gd, vd, len),
                "gronsfeld vs vigenere decrypt disagree len=%d keylen=%d", len, keylen);
        }
    }
}

// --- Edge cases -----------------------------------------------------------

static void test_gronsfeld_edge(void) {
    // key length 1 is a single Caesar shift applied to every position.
    int len = 50, P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
    random_text(P, len);
    for (int d = 0; d < GRONSFELD_DIGITS; d++) {
        int key = d;
        gronsfeld_encrypt(C, P, len, &key, 1);
        for (int i = 0; i < len; i++)
            CHECK(C[i] == (P[i] + d) % ALPHABET_SIZE, "gronsfeld keylen=1 d=%d pos=%d", d, i);
        gronsfeld_decrypt(back, C, len, &key, 1);
        CHECK(arrays_equal(back, P, len), "gronsfeld keylen=1 d=%d round-trip", d);
    }

    // A key longer than the plaintext: only the leading digits are ever used.
    int P2[3] = {0, 1, 2}, key[6] = {5, 4, 3, 2, 1, 0}, C2[3], b2[3];
    gronsfeld_encrypt(C2, P2, 3, key, 6);
    CHECK(C2[0] == 5 && C2[1] == 5 && C2[2] == 5, "gronsfeld long-key prefix");
    gronsfeld_decrypt(b2, C2, 3, key, 6);
    CHECK(arrays_equal(b2, P2, 3), "gronsfeld long-key round-trip");
}

int main(void) {
    seed_rand(20240617u);
    init_alphabet(NULL);            // full 26-letter alphabet, as the real binary does

    test_gronsfeld_known_answer();
    test_gronsfeld_roundtrip();
    test_gronsfeld_matches_vigenere();
    test_gronsfeld_edge();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
