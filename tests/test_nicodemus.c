//
//  Unit tests for the Nicodemus cipher primitives (nicodemus.c).
//
//  Framework-free: build with `make test`, which links this against nicodemus.c +
//  transpositions.c + utils.c (+ vigenere/beaufort for the agreement check). Exits non-zero
//  if any check fails.
//
//  Nicodemus composes a periodic per-column substitution (Vigenere / Variant / Beaufort, keyed
//  by the keyword letters) with a per-block columnar transposition (block height H rows x P
//  columns, columns read off in the keyword's alphabetical rank order). The core invariants:
//  a HAND-COMPUTED known-answer vector pinning all three substitution conventions on the same
//  plaintext/keyword (ATTACKATDAWN, keyword KEY, H=2); nicodemus_key_from_keyword (shifts +
//  stable-argsort order, including repeated keyword letters); encrypt/decrypt round-trips over
//  random orders/shifts x lengths x P x block heights (incl. ragged final blocks, H=1, and the
//  single-block degenerate) for all three variants; and agreement of the per-column substitution
//  with vigenere/beaufort fed the same shift as a length-1 cycleword.
//

#include "colossus.h"
#include "nicodemus.h"

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

static int indices_match_str(const int a[], const char *s) {
    for (int i = 0; s[i]; i++) if (a[i] != s[i] - 'A') return 0;
    return 1;
}

static void str_to_indices(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) out[i] = s[i] - 'A';
}

// --- hand-computed known-answer vector -------------------------------------
//
// plaintext ATTACKATDAWN, keyword KEY (shifts K=10,E=4,Y=24; order [1,0,2]), H=2, two blocks:
//   VIG     -> XGKKRIXAKKBL
//   VARIANT -> PYQQVMPSQQFP
//   BEAU    -> LCKKFOLIKKVL
// (derived by hand: substitute each column by its shift, read columns in rank order top-to-bottom.)

static void test_known_answer(void) {
    int kw[3]; str_to_indices("KEY", kw);
    int order[3], shifts[3];
    nicodemus_key_from_keyword(kw, 3, order, shifts);

    int pt[12]; str_to_indices("ATTACKATDAWN", pt);
    int ct[12], back[12];

    struct { int variant; const char *expect; } cases[] = {
        { NICO_VIG,     "XGKKRIXAKKBL" },
        { NICO_VARIANT, "PYQQVMPSQQFP" },
        { NICO_BEAU,    "LCKKFOLIKKVL" },
    };
    for (int c = 0; c < 3; c++) {
        nicodemus_encrypt(pt, 12, 3, 2, order, shifts, cases[c].variant, ct);
        CHECK(indices_match_str(ct, cases[c].expect),
            "nicodemus KAT encrypt variant=%d mismatch", cases[c].variant);
        int exp[12]; str_to_indices(cases[c].expect, exp);
        nicodemus_decrypt(exp, 12, 3, 2, order, shifts, cases[c].variant, back);
        CHECK(arrays_equal(back, pt, 12), "nicodemus KAT decrypt variant=%d mismatch", cases[c].variant);
    }
}

// --- key derivation (shifts + stable-argsort order) ------------------------

static void test_key_from_keyword(void) {
    int kw[8], order[8], shifts[8];

    str_to_indices("KEY", kw);
    nicodemus_key_from_keyword(kw, 3, order, shifts);
    int exp_o1[3] = {1, 0, 2}, exp_s1[3] = {10, 4, 24};
    CHECK(arrays_equal(order, exp_o1, 3), "key_from_keyword(KEY) order");
    CHECK(arrays_equal(shifts, exp_s1, 3), "key_from_keyword(KEY) shifts");

    // Repeated letters: ANNA -> shifts [0,13,13,0]; stable ascending order [0,3,1,2]
    // (the two A's keep input order, then the two N's keep input order).
    str_to_indices("ANNA", kw);
    nicodemus_key_from_keyword(kw, 4, order, shifts);
    int exp_o2[4] = {0, 3, 1, 2}, exp_s2[4] = {0, 13, 13, 0};
    CHECK(arrays_equal(order, exp_o2, 4), "key_from_keyword(ANNA) order");
    CHECK(arrays_equal(shifts, exp_s2, 4), "key_from_keyword(ANNA) shifts");

    // order is always a permutation of 0..P-1.
    str_to_indices("GENERAL", kw);
    nicodemus_key_from_keyword(kw, 7, order, shifts);
    int seen[7] = {0}; for (int i = 0; i < 7; i++) if (order[i] >= 0 && order[i] < 7) seen[order[i]]++;
    int ok = 1; for (int i = 0; i < 7; i++) if (seen[i] != 1) ok = 0;
    CHECK(ok, "key_from_keyword(GENERAL) order is not a permutation");
}

// --- round-trips over random (order, shifts) -------------------------------

static void random_perm(int a[], int n) {
    for (int i = 0; i < n; i++) a[i] = i;
    shuffle(a, n);
}

static void test_roundtrip(void) {
    int variants[] = { NICO_VIG, NICO_VARIANT, NICO_BEAU };
    int lens[] = { 1, 12, 28, 97, 200, 511 };
    for (int vi = 0; vi < 3; vi++) {
        int variant = variants[vi];
        for (int li = 0; li < 6; li++) {
            int len = lens[li];
            for (int trial = 0; trial < 8; trial++) {
                int P = rand_int(2, 13);          // 2..12 columns
                int H = rand_int(1, 9);           // 1..8 rows per block (incl. H=1)
                if (P > len) P = len < 2 ? 2 : len;
                int order[MAX_COLS], shifts[MAX_COLS];
                random_perm(order, P);
                for (int c = 0; c < P; c++) shifts[c] = rand_int(0, 26);
                int pt[MAX_CIPHER_LENGTH], ct[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
                for (int i = 0; i < len; i++) pt[i] = rand_int(0, 26);
                nicodemus_encrypt(pt, len, P, H, order, shifts, variant, ct);
                nicodemus_decrypt(ct, len, P, H, order, shifts, variant, back);
                CHECK(arrays_equal(back, pt, len),
                    "round-trip variant=%d len=%d P=%d H=%d", variant, len, P, H);
            }
        }
    }
}

static void test_single_block(void) {
    // H * P >= len => the whole message is one (ragged) block: a plain columnar after
    // the per-column substitution. Round-trip must still hold.
    int order[10], shifts[10];
    random_perm(order, 7);
    for (int c = 0; c < 7; c++) shifts[c] = rand_int(0, 26);
    int len = 30, pt[64], ct[64], back[64];
    for (int i = 0; i < len; i++) pt[i] = rand_int(0, 26);
    nicodemus_encrypt(pt, len, 7, 20, order, shifts, NICO_BEAU, ct);   // 7*20=140 >= 30
    nicodemus_decrypt(ct, len, 7, 20, order, shifts, NICO_BEAU, back);
    CHECK(arrays_equal(back, pt, len), "single-block round-trip");
}

static void test_detranspose_compose(void) {
    // nicodemus_decrypt == detranspose then inv_substitute (the solver's split path).
    int order[8], shifts[8];
    random_perm(order, 5);
    for (int c = 0; c < 5; c++) shifts[c] = rand_int(0, 26);
    int len = 123, pt[256], ct[256], back[256], desub[256], comp[256];
    for (int i = 0; i < len; i++) pt[i] = rand_int(0, 26);
    nicodemus_encrypt(pt, len, 5, 4, order, shifts, NICO_VARIANT, ct);
    nicodemus_decrypt(ct, len, 5, 4, order, shifts, NICO_VARIANT, back);
    nicodemus_detranspose(ct, len, 5, 4, order, desub);
    nicodemus_inv_substitute(desub, len, 5, shifts, NICO_VARIANT, comp);
    CHECK(arrays_equal(back, comp, len), "detranspose+inv_substitute != decrypt");
    CHECK(arrays_equal(comp, pt, len), "detranspose+inv_substitute != plaintext");
}

// --- agreement with the engine's Vigenere / Beaufort conventions -----------

static void test_substitution_agreement(void) {
    // The per-column substitution must match vigenere/beaufort fed the same shift as a
    // length-1 cycleword, so a recovered Nicodemus shift means the same as a Vigenere key.
    int len = 64, cipher[64], vg[64], nico[64];
    for (int i = 0; i < len; i++) cipher[i] = rand_int(0, 26);
    for (int shift = 0; shift < 26; shift++) {
        int cw[1] = { shift };

        vigenere_decrypt(vg, cipher, len, cw, 1, false);          // standard Vigenere
        for (int i = 0; i < len; i++) nico[i] = nicodemus_inv_sub(cipher[i], shift, NICO_VIG);
        CHECK(arrays_equal(vg, nico, len), "NICO_VIG != vigenere_decrypt shift=%d", shift);

        vigenere_decrypt(vg, cipher, len, cw, 1, true);           // Variant Vigenere
        for (int i = 0; i < len; i++) nico[i] = nicodemus_inv_sub(cipher[i], shift, NICO_VARIANT);
        CHECK(arrays_equal(vg, nico, len), "NICO_VARIANT != vigenere variant shift=%d", shift);

        beaufort_decrypt(vg, cipher, len, cw, 1);                 // Beaufort (reciprocal)
        for (int i = 0; i < len; i++) nico[i] = nicodemus_inv_sub(cipher[i], shift, NICO_BEAU);
        CHECK(arrays_equal(vg, nico, len), "NICO_BEAU != beaufort_decrypt shift=%d", shift);
    }
}

int main(void) {
    seed_rand(20240617u);
    init_alphabet(NULL);            // full 26-letter alphabet, as the real binary does

    test_known_answer();
    test_key_from_keyword();
    test_roundtrip();
    test_single_block();
    test_detranspose_compose();
    test_substitution_agreement();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) { printf("TESTS FAILED\n"); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
