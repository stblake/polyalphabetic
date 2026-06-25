//
//  Unit tests for the Gromark / Periodic Gromark cipher primitives (gromark.c).
//
//  Framework-free: build with `make test`, which links this against gromark.c + utils.c.
//  Exits non-zero if any check fails.
//
//  Gromark composes a keyed 26-letter substitution sigma with a chain-addition running key
//  (C = sigma[(p + d) mod 26]); Periodic Gromark adds a per-group offset. The core invariants:
//  the two ACA worked examples pinned cell-for-cell (keyword ENIGMA), the K2M mixed-alphabet
//  builder, the chain-addition rule for P=5 and P=6, encrypt/decrypt round-trips over random
//  alphabets/primers/lengths for both variants, the identity-alphabet reduction to a pure
//  chain-shift, and the periodic-with-zero-offsets == basic equivalence.
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

static void str_to_indices(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) out[i] = s[i] - 'A';
}

static int indices_match_str(const int a[], const char *s) {
    for (int i = 0; s[i]; i++) if (a[i] != s[i] - 'A') return 0;
    return 1;
}

// --- K2M mixed-alphabet builder -------------------------------------------

static void test_mixed_alphabet(void) {
    int sigma[26];
    gromark_mixed_alphabet("ENIGMA", sigma);
    CHECK(indices_match_str(sigma, "AJRXEBKSYGFPVIDOUMHQWNCLTZ"),
        "gromark K2M(ENIGMA) mismatch");

    // It is a permutation of 0..25.
    int seen[26] = {0};
    for (int i = 0; i < 26; i++) seen[sigma[i]]++;
    int ok = 1; for (int i = 0; i < 26; i++) if (seen[i] != 1) ok = 0;
    CHECK(ok, "gromark K2M(ENIGMA) is not a permutation");

    // A keyword with a repeat: REPEATED -> REPATD (6 distinct), per the ACA note.
    int s2[26];
    gromark_mixed_alphabet("REPEATED", s2);
    int seen2[26] = {0};
    for (int i = 0; i < 26; i++) seen2[s2[i]]++;
    ok = 1; for (int i = 0; i < 26; i++) if (seen2[i] != 1) ok = 0;
    CHECK(ok, "gromark K2M(REPEATED) is not a permutation");
}

// --- chain-addition running key -------------------------------------------

static void test_chain_key(void) {
    // P=5 primer 23452 -> 2 3 4 5 2 5 7 9 7 7 2 6 6 4 ...  (d[i] = (d[i-5]+d[i-4]) mod 10)
    int primer5[5] = {2, 3, 4, 5, 2};
    int d[14], exp5[14] = {2, 3, 4, 5, 2, 5, 7, 9, 7, 7, 2, 6, 6, 4};
    gromark_chain_key(primer5, 5, 14, d);
    CHECK(arrays_equal(d, exp5, 14), "gromark chain key P=5 mismatch");

    // P=6 primer 264351 -> 2 6 4 3 5 1 8 0 7 8 6 9 ...
    int primer6[6] = {2, 6, 4, 3, 5, 1};
    int d6[12], exp6[12] = {2, 6, 4, 3, 5, 1, 8, 0, 7, 8, 6, 9};
    gromark_chain_key(primer6, 6, 12, d6);
    CHECK(arrays_equal(d6, exp6, 12), "gromark chain key P=6 mismatch");
}

// --- ACA known-answer vectors ---------------------------------------------

static void test_known_answer_basic(void) {
    // ACA Gromark: keyword ENIGMA, primer 23452,
    //   pt thereareuptotensubstitutesperletter -> ct NFYCKBTIJCNWZYCACJNAYNLQPWWSTWPJQFL
    int sigma[26];
    gromark_mixed_alphabet("ENIGMA", sigma);
    int primer[5] = {2, 3, 4, 5, 2};
    int pt[64], ct[64], back[64];
    const char *PT = "THEREAREUPTOTENSUBSTITUTESPERLETTER";
    const char *CT = "NFYCKBTIJCNWZYCACJNAYNLQPWWSTWPJQFL";
    int len = (int) strlen(PT);
    str_to_indices(PT, pt);

    gromark_encrypt(pt, len, sigma, primer, 5, ct);
    CHECK(indices_match_str(ct, CT), "gromark basic KAT encrypt mismatch");

    int ctv[64]; str_to_indices(CT, ctv);
    gromark_decrypt(ctv, len, sigma, primer, 5, back);
    CHECK(arrays_equal(back, pt, len), "gromark basic KAT decrypt mismatch");
}

// Derive the Periodic Gromark primer (alphabetical ranks) and offsets (positions in sigma)
// from the keyword, exactly as the generator does.
static int periodic_params(const char *keyword, const int sigma[], int primer[], int offsets[]) {
    int keyed[26];
    make_keyed_alphabet((char *) keyword, keyed);
    int seen[26] = {0}, P = 0;
    for (int i = 0; keyword[i]; i++) {
        int idx = keyword[i] - 'A';
        if (idx >= 0 && idx < 26 && !seen[idx]) { seen[idx] = 1; P++; }
    }
    int sinv[26];
    for (int i = 0; i < 26; i++) sinv[sigma[i]] = i;
    for (int g = 0; g < P; g++) {
        int rank = 1;
        for (int h = 0; h < P; h++) if (keyed[h] < keyed[g]) rank++;
        primer[g] = rank;
        offsets[g] = sinv[keyed[g]];
    }
    return P;
}

static void test_known_answer_periodic(void) {
    // ACA Periodic Gromark: keyword ENIGMA (period 6, primer 264351, offsets E4 N21 I13 G9 M17 A0),
    //   pt wintryshowers... -> ct RHNAAXNRUZBN...
    int sigma[26];
    gromark_mixed_alphabet("ENIGMA", sigma);
    int primer[26], offsets[26];
    int P = periodic_params("ENIGMA", sigma, primer, offsets);
    CHECK(P == 6, "periodic ENIGMA period should be 6, got %d", P);
    int exp_primer[6] = {2, 6, 4, 3, 5, 1};
    int exp_offset[6] = {4, 21, 13, 9, 17, 0};
    CHECK(arrays_equal(primer, exp_primer, 6), "periodic ENIGMA primer (ranks) mismatch");
    CHECK(arrays_equal(offsets, exp_offset, 6), "periodic ENIGMA offsets mismatch");

    const char *PT = "WINTRYSHOWERSWILLCONTINUEFORTHENEXTFEWDAYSACCORDINGTOTHEFORECAST";
    const char *CT = "RHNAAXNRUZBNIUARXCRTPATBRLIGDSVCIRCVOYPVRAAZZMUSREQYEVMMURGWTLUD";
    int len = (int) strlen(PT);
    int pt[128], ct[128], back[128];
    str_to_indices(PT, pt);

    gromark_periodic_encrypt(pt, len, sigma, primer, P, offsets, ct);
    CHECK(indices_match_str(ct, CT), "gromark periodic KAT encrypt mismatch");

    int ctv[128]; str_to_indices(CT, ctv);
    gromark_periodic_decrypt(ctv, len, sigma, primer, P, offsets, back);
    CHECK(arrays_equal(back, pt, len), "gromark periodic KAT decrypt mismatch");
}

// --- round-trip stress ----------------------------------------------------

static void random_sigma(int sigma[]) {
    for (int i = 0; i < 26; i++) sigma[i] = i;
    shuffle(sigma, 26);
}

static void test_roundtrip_basic(void) {
    int lens[] = {1, 5, 26, 97, 333, 600};
    int Ps[] = {1, 2, 3, 5, 7};
    for (int li = 0; li < 6; li++) {
        int len = lens[li];
        for (int pi = 0; pi < 5; pi++) {
            int P = Ps[pi];
            int sigma[26], primer[26];
            int pt[MAX_CIPHER_LENGTH], ct[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
            random_sigma(sigma);
            for (int i = 0; i < P; i++) primer[i] = rand_int(0, 10);
            for (int i = 0; i < len; i++) pt[i] = rand_int(0, 26);
            gromark_encrypt(pt, len, sigma, primer, P, ct);
            gromark_decrypt(ct, len, sigma, primer, P, back);
            CHECK(arrays_equal(back, pt, len), "gromark basic round-trip len=%d P=%d", len, P);
        }
    }
}

static void test_roundtrip_periodic(void) {
    int lens[] = {6, 40, 97, 250, 600};
    int Ps[] = {2, 3, 5, 6, 8};
    for (int li = 0; li < 5; li++) {
        int len = lens[li];
        for (int pi = 0; pi < 5; pi++) {
            int P = Ps[pi];
            int sigma[26], primer[26], offsets[26];
            int pt[MAX_CIPHER_LENGTH], ct[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
            random_sigma(sigma);
            for (int i = 0; i < P; i++) { primer[i] = rand_int(0, 10); offsets[i] = rand_int(0, 26); }
            for (int i = 0; i < len; i++) pt[i] = rand_int(0, 26);
            gromark_periodic_encrypt(pt, len, sigma, primer, P, offsets, ct);
            gromark_periodic_decrypt(ct, len, sigma, primer, P, offsets, back);
            CHECK(arrays_equal(back, pt, len), "gromark periodic round-trip len=%d P=%d", len, P);
        }
    }
}

// --- structural equivalences ----------------------------------------------

static void test_identity_alphabet(void) {
    // With sigma = identity, basic Gromark is a pure chain-key shift: C[i] = (p[i] + d[i]) mod 26.
    int sigma[26]; for (int i = 0; i < 26; i++) sigma[i] = i;
    int primer[5] = {3, 1, 4, 1, 5};
    int len = 200, pt[256], ct[256], d[256];
    for (int i = 0; i < len; i++) pt[i] = rand_int(0, 26);
    gromark_encrypt(pt, len, sigma, primer, 5, ct);
    gromark_chain_key(primer, 5, len, d);
    for (int i = 0; i < len; i++)
        CHECK(ct[i] == (pt[i] + d[i]) % 26, "gromark identity-alphabet shift pos=%d", i);
}

static void test_zero_offsets_equals_basic(void) {
    // Periodic Gromark with all-zero offsets == basic Gromark (same primer/period).
    int sigma[26]; random_sigma(sigma);
    int primer[5] = {2, 3, 4, 5, 2}, offsets[5] = {0, 0, 0, 0, 0};
    int len = 300, pt[512], cb[512], cp[512];
    for (int i = 0; i < len; i++) pt[i] = rand_int(0, 26);
    gromark_encrypt(pt, len, sigma, primer, 5, cb);
    gromark_periodic_encrypt(pt, len, sigma, primer, 5, offsets, cp);
    CHECK(arrays_equal(cb, cp, len), "periodic zero-offsets != basic");
}

int main(void) {
    seed_rand(20240617u);
    init_alphabet(NULL);            // full 26-letter alphabet, as the real binary does

    test_mixed_alphabet();
    test_chain_key();
    test_known_answer_basic();
    test_known_answer_periodic();
    test_roundtrip_basic();
    test_roundtrip_periodic();
    test_identity_alphabet();
    test_zero_offsets_equals_basic();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) { printf("TESTS FAILED\n"); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
