//
//  Unit tests for the Progressive Key cipher primitives (progkey.c).
//
//  Framework-free: build with `make test`, which links this against progkey.c +
//  vigenere.c + beaufort.c + quagmire.c + utils.c. Exits non-zero if any check fails.
//
//  The Progressive Key cipher is a periodic base cipher (Vigenere / Variant / Beaufort)
//  under a letter keyword, composed with a SECOND base encipherment whose key drifts by a
//  constant (g*prog) every group g (= i / P). The invariants tested:
//
//    1. The ACA worked-example known-answer vector (Vigenere, key GRAPEFRUIT, P=10, prog=1)
//       pinning the whole convention -- the per-group drift A,B,C,... on top of the primary
//       Vigenere.
//    2. Encrypt/decrypt round-trips over random keyword x prog x length x period for all three
//       bases, incl. ragged final group, P=1, and an over-long key.
//    3. Agreement of progkey_encrypt with an INDEPENDENT two-pass reference built from the
//       canonical vigenere_*/beaufort_* primitives (keyword pass then a full-length drift-key
//       pass) -- for all three bases.
//    4. The prog=0 degeneration: for the Vigenere/Variant bases (no drift) progkey == the plain
//       periodic base cipher; for Beaufort the group-0 pass is a reflection (documented), so we
//       only assert the round-trip there.
//    5. progkey_deprogress inverts the drift pass exactly (leaving the primary base ciphertext).
//

#include "colossus.h"

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

static void random_text(int P[], int len) {
    for (int i = 0; i < len; i++) P[i] = rand_int(0, ALPHABET_SIZE);
}

// A random keyword: per-column base shifts 0..25.
static void random_keyword(int kw[], int len) {
    for (int i = 0; i < len; i++) kw[i] = rand_int(0, ALPHABET_SIZE);
}

static void str_to_indices(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) out[i] = s[i] - 'A';
}

static const int BASES[3] = { PROGKEY_BASE_VIG, PROGKEY_BASE_VAR, PROGKEY_BASE_BEAU };
static const char *BASE_NAME[3] = { "vig", "var", "beau" };
static int base_index(int base) { return base == PROGKEY_BASE_VAR ? 1 : base == PROGKEY_BASE_BEAU ? 2 : 0; }

// One base encipherment pass over a (periodic) key, using the CANONICAL primitives -- an
// independent reference for the composition in progkey_encrypt.
static void base_pass_encrypt(int out[], int in[], int len, int key[], int keylen, int base) {
    if (base == PROGKEY_BASE_BEAU) beaufort_encrypt(out, in, len, key, keylen);
    else vigenere_encrypt(out, in, len, key, keylen, base == PROGKEY_BASE_VAR);
}

// Reference Progressive Key encryption: keyword pass, then a full-length drift-key pass with
// key[i] = (i/P * prog) mod 26. Must match progkey_encrypt bit-for-bit. NOTE: the drift-key
// pass uses a length-`len` cycleword, so callers must keep len < MAX_CYCLEWORD_LEN (the
// canonical vigenere_*/beaufort_* cycleword scratch cap); progkey_* itself has no such limit.
static void progkey_ref_encrypt(int out[], int in[], int len, int kw[], int P, int prog, int base) {
    int drift[MAX_CIPHER_LENGTH], c1[MAX_CIPHER_LENGTH];
    for (int i = 0; i < len; i++) drift[i] = ((i / P) * prog) % ALPHABET_SIZE;
    base_pass_encrypt(c1, in, len, kw, P, base);
    base_pass_encrypt(out, c1, len, drift, len, base);
}

// --- Known-answer vector (ACA worked example) -----------------------------

static void test_progkey_known_answer(void) {
    // Vigenere base, key GRAPEFRUIT (P=10), prog=1: group g adds the letter (g) -- A,B,C,...
    //   pt "THISCIPHERCANBEUSEDWITHANYOFTH" -> "ZYIHGNGBMKJSORJAKZMQQMJRTFHBDC".
    int pt[30], expected[30], kw[10], C[30], back[30];
    str_to_indices("THISCIPHERCANBEUSEDWITHANYOFTH", pt);
    str_to_indices("ZYIHGNGBMKJSORJAKZMQQMJRTFHBDC", expected);
    str_to_indices("GRAPEFRUIT", kw);

    progkey_encrypt(C, pt, 30, kw, 10, 1, PROGKEY_BASE_VIG);
    CHECK(arrays_equal(C, expected, 30), "progkey ACA KAT encrypt mismatch");

    progkey_decrypt(back, C, 30, kw, 10, 1, PROGKEY_BASE_VIG);
    CHECK(arrays_equal(back, pt, 30), "progkey ACA KAT decrypt mismatch");

    // Group 0 is the primary Vigenere unchanged (Kp=A=0): first 10 chars == plain Vigenere.
    int vig[10];
    vigenere_encrypt(vig, pt, 10, kw, 10, false);
    CHECK(arrays_equal(C, vig, 10), "progkey group-0 should equal plain Vigenere");
}

// --- Round-trip stress (all bases) ----------------------------------------

static void test_progkey_roundtrip(void) {
    int lens[]    = {1, 2, 17, 50, 97, 336, 600};
    int periods[] = {1, 3, 5, 7, 10};
    for (int bi = 0; bi < 3; bi++) {
        int base = BASES[bi];
        for (int li = 0; li < 7; li++) {
            int len = lens[li];
            for (int pi = 0; pi < 5; pi++) {
                int P = periods[pi];
                for (int prog = 0; prog <= 25; prog += 5) {
                    int pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
                    int kw[MAX_CYCLEWORD_LEN];
                    random_text(pt, len);
                    random_keyword(kw, P);
                    progkey_encrypt(C, pt, len, kw, P, prog, base);
                    progkey_decrypt(back, C, len, kw, P, prog, base);
                    CHECK(arrays_equal(back, pt, len),
                        "progkey round-trip base=%s len=%d P=%d prog=%d",
                        BASE_NAME[bi], len, P, prog);
                }
            }
        }
    }
}

// --- Agreement with the independent two-pass reference (all bases) ---------

static void test_progkey_matches_reference(void) {
    int lens[]    = {30, 97, 150, 290};   // < MAX_CYCLEWORD_LEN (reference drift-key pass cap)
    int periods[] = {4, 7, 11};
    for (int bi = 0; bi < 3; bi++) {
        int base = BASES[bi];
        for (int li = 0; li < 4; li++) {
            int len = lens[li];
            for (int pi = 0; pi < 3; pi++) {
                int P = periods[pi];
                for (int prog = 0; prog <= 25; prog += 3) {
                    int pt[MAX_CIPHER_LENGTH], a[MAX_CIPHER_LENGTH], b[MAX_CIPHER_LENGTH];
                    int kw[MAX_CYCLEWORD_LEN];
                    random_text(pt, len);
                    random_keyword(kw, P);
                    progkey_encrypt(a, pt, len, kw, P, prog, base);
                    progkey_ref_encrypt(b, pt, len, kw, P, prog, base);
                    CHECK(arrays_equal(a, b, len),
                        "progkey vs two-pass reference base=%s len=%d P=%d prog=%d",
                        BASE_NAME[bi], len, P, prog);
                }
            }
        }
    }
}

// --- prog=0 degeneration (Vigenere / Variant) -----------------------------

static void test_progkey_prog0(void) {
    int len = 200, P = 8;
    int pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], ref[MAX_CIPHER_LENGTH];
    int kw[MAX_CYCLEWORD_LEN];
    random_text(pt, len);
    random_keyword(kw, P);

    // Vigenere base, prog=0 -> the plain periodic Vigenere over the keyword.
    progkey_encrypt(C, pt, len, kw, P, 0, PROGKEY_BASE_VIG);
    vigenere_encrypt(ref, pt, len, kw, P, false);
    CHECK(arrays_equal(C, ref, len), "progkey VIG prog=0 != plain Vigenere");

    // Variant base, prog=0 -> the plain periodic Variant cipher.
    progkey_encrypt(C, pt, len, kw, P, 0, PROGKEY_BASE_VAR);
    vigenere_encrypt(ref, pt, len, kw, P, true);
    CHECK(arrays_equal(C, ref, len), "progkey VAR prog=0 != plain Variant");
}

// --- progkey_deprogress inverts the drift pass ----------------------------

static void test_progkey_deprogress(void) {
    int len = 250, P = 9, prog = 7;
    for (int bi = 0; bi < 3; bi++) {
        int base = BASES[bi];
        int pt[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], C1[MAX_CIPHER_LENGTH], C1ref[MAX_CIPHER_LENGTH];
        int kw[MAX_CYCLEWORD_LEN];
        random_text(pt, len);
        random_keyword(kw, P);
        progkey_encrypt(C, pt, len, kw, P, prog, base);

        // De-progressing the ciphertext must recover the primary base ciphertext C1
        // (the keyword pass alone), which the solver then attacks per column.
        progkey_deprogress(C1, C, len, P, prog, base);
        base_pass_encrypt(C1ref, pt, len, kw, P, base);
        CHECK(arrays_equal(C1, C1ref, len),
            "progkey_deprogress base=%s did not recover the primary ciphertext", BASE_NAME[bi]);
    }
    (void) base_index;
}

int main(void) {
    seed_rand(20240617u);
    init_alphabet(NULL);            // full 26-letter alphabet, as the real binary does

    test_progkey_known_answer();
    test_progkey_roundtrip();
    test_progkey_matches_reference();
    test_progkey_prog0();
    test_progkey_deprogress();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
