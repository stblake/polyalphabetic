//
//  Unit tests for the cipher primitives (vigenere / beaufort / porta / quagmire).
//
//  Framework-free: build with `make test`, which links this against the cipher
//  sources + utils.c. Exits non-zero if any check fails.
//
//  Strategy: every cipher exposes an encrypt/decrypt pair, so the core invariant
//  is decrypt(encrypt(P, key), key) == P for random plaintext and random keyed
//  alphabets / cyclewords, across both the standard and variant tableaus. A few
//  hand-computed known-answer vectors pin the actual convention (so a sign flip
//  in the modular arithmetic is caught, not just a self-consistent round-trip).
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

// Deterministic pseudo-random plaintext in [0,26).
static void random_text(int P[], int len) {
    for (int i = 0; i < len; i++) P[i] = rand_int(0, ALPHABET_SIZE);
}

// A random keyed alphabet: a permutation of {0,...,25}.
static void random_alphabet(int a[]) {
    for (int i = 0; i < ALPHABET_SIZE; i++) a[i] = i;
    shuffle(a, ALPHABET_SIZE);
}

// Convert an A-Z string to its 0-25 index array.
static void str_to_indices(const char *s, int out[]) {
    for (int i = 0; s[i]; i++) out[i] = s[i] - 'A';
}

// --- Vigenere -------------------------------------------------------------

static void test_vigenere_known_answer(void) {
    // Classic vector: ATTACKATDAWN + key LEMON -> LXFOPVEFRNHR (standard, C = P + K).
    int P[12], C[12], expected[12], cw[5];
    str_to_indices("ATTACKATDAWN", P);
    str_to_indices("LXFOPVEFRNHR", expected);
    str_to_indices("LEMON", cw);

    vigenere_encrypt(C, P, 12, cw, 5, false);
    CHECK(arrays_equal(C, expected, 12), "vigenere KAT encrypt mismatch");

    int back[12];
    vigenere_decrypt(back, C, 12, cw, 5, false);
    CHECK(arrays_equal(back, P, 12), "vigenere KAT decrypt mismatch");
}

static void test_vigenere_roundtrip(void) {
    int lens[] = {1, 25, 97, 336};
    int cwlens[] = {1, 3, 7, 11};
    for (int li = 0; li < 4; li++) {
        int len = lens[li];
        for (int ci = 0; ci < 4; ci++) {
            int cwlen = cwlens[ci];
            for (int variant = 0; variant <= 1; variant++) {
                int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
                int cw[MAX_CYCLEWORD_LEN];
                random_text(P, len);
                for (int i = 0; i < cwlen; i++) cw[i] = rand_int(0, ALPHABET_SIZE);
                vigenere_encrypt(C, P, len, cw, cwlen, variant);
                vigenere_decrypt(back, C, len, cw, cwlen, variant);
                CHECK(arrays_equal(back, P, len),
                    "vigenere round-trip len=%d cwlen=%d variant=%d", len, cwlen, variant);
            }
        }
    }
}

// --- Beaufort (reciprocal) ------------------------------------------------

static void test_beaufort(void) {
    // Reciprocal: encrypt == decrypt, and a double application is the identity.
    int len = 200, cwlen = 9;
    int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
    int cw[MAX_CYCLEWORD_LEN];
    random_text(P, len);
    for (int i = 0; i < cwlen; i++) cw[i] = rand_int(0, ALPHABET_SIZE);

    beaufort_encrypt(C, P, len, cw, cwlen);
    beaufort_decrypt(back, C, len, cw, cwlen);
    CHECK(arrays_equal(back, P, len), "beaufort round-trip mismatch");

    int C2[MAX_CIPHER_LENGTH];
    beaufort_encrypt(C2, C, len, cw, cwlen);   // applying twice returns the plaintext
    CHECK(arrays_equal(C2, P, len), "beaufort not reciprocal");
}

// --- Porta (reciprocal) ---------------------------------------------------

static void test_porta(void) {
    int len = 200, cwlen = 6;
    int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];
    int cw[MAX_CYCLEWORD_LEN];
    random_text(P, len);
    for (int i = 0; i < cwlen; i++) cw[i] = rand_int(0, ALPHABET_SIZE);

    porta_encrypt(C, P, len, cw, cwlen);
    porta_decrypt(back, C, len, cw, cwlen);
    CHECK(arrays_equal(back, P, len), "porta round-trip mismatch");

    // Porta maps A-M <-> N-Z: every output must be in the opposite half.
    int half_ok = 1;
    for (int i = 0; i < len; i++)
        if ((P[i] < 13) == (C[i] < 13)) half_ok = 0;
    CHECK(half_ok, "porta did not swap alphabet halves");
}

// --- Quagmire I-IV --------------------------------------------------------
//
// Round-trip works for ANY pair of keyed alphabets; the Quagmire "type" only
// constrains which alphabet is straight. So random PT/CT permutations cover the
// general case (Q4), straight PT or CT covers Q1/Q2, and PT==CT covers Q3.

static void test_quagmire_roundtrip(void) {
    int lens[] = {26, 97, 336};
    int cwlens[] = {1, 5, 13};
    for (int li = 0; li < 3; li++) {
        int len = lens[li];
        for (int ci = 0; ci < 3; ci++) {
            int cwlen = cwlens[ci];
            for (int variant = 0; variant <= 1; variant++) {
                int pt[ALPHABET_SIZE], ct[ALPHABET_SIZE], cw[MAX_CYCLEWORD_LEN];
                int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];

                random_alphabet(pt);
                random_alphabet(ct);
                random_text(P, len);
                for (int i = 0; i < cwlen; i++) cw[i] = rand_int(0, ALPHABET_SIZE);

                quagmire_encrypt(C, P, len, pt, ct, cw, cwlen, variant);
                quagmire_decrypt(back, C, len, pt, ct, cw, cwlen, variant);
                CHECK(arrays_equal(back, P, len),
                    "quagmire(Q4) round-trip len=%d cwlen=%d variant=%d", len, cwlen, variant);

                // Q3: PT and CT are the same keyed alphabet.
                quagmire_encrypt(C, P, len, pt, pt, cw, cwlen, variant);
                quagmire_decrypt(back, C, len, pt, pt, cw, cwlen, variant);
                CHECK(arrays_equal(back, P, len),
                    "quagmire(Q3) round-trip len=%d cwlen=%d variant=%d", len, cwlen, variant);
            }
        }
    }
}

// Vigenere is exactly Quagmire with straight PT/CT alphabets: the dedicated
// vigenere_decrypt must agree with quagmire_decrypt on straight alphabets. This
// guards the inverse-table rewrite of quagmire_decrypt against a convention drift.
static void test_quagmire_matches_vigenere(void) {
    int len = 300, cwlen = 7;
    int straight[ALPHABET_SIZE];
    for (int i = 0; i < ALPHABET_SIZE; i++) straight[i] = i;

    int C[MAX_CIPHER_LENGTH], a[MAX_CIPHER_LENGTH], b[MAX_CIPHER_LENGTH];
    int cw[MAX_CYCLEWORD_LEN];
    random_text(C, len);
    for (int i = 0; i < cwlen; i++) cw[i] = rand_int(0, ALPHABET_SIZE);

    for (int variant = 0; variant <= 1; variant++) {
        vigenere_decrypt(a, C, len, cw, cwlen, variant);
        quagmire_decrypt(b, C, len, straight, straight, cw, cwlen, variant);
        CHECK(arrays_equal(a, b, len),
            "vigenere vs quagmire(straight) disagree, variant=%d", variant);
    }
}

// --- Autokey (Vigenere / Quagmire / Beaufort / Porta tableaus) ------------
//
// Plaintext autokey: the key stream is the primer followed by the plaintext.
// autokey_encrypt is the inverse of autokey_decrypt, so the round-trip invariant
// holds; the known-answer vectors below are taken verbatim from the reference
// implementation in autokey.ipynb and pin the actual convention per tableau.

// cfg carries only cipher_type + variant for the autokey primitives.
static void autokey_cfg(ColossusConfig *cfg, int cipher_type, int variant) {
    memset(cfg, 0, sizeof *cfg);
    cfg->cipher_type = cipher_type;
    cfg->variant = variant;
}

static void autokey_kat(const char *name, int cipher_type, int variant,
    const char *pt_kw, const char *ct_kw, const char *primer,
    const char *pt, const char *expected) {

    ColossusConfig cfg;
    autokey_cfg(&cfg, cipher_type, variant);

    int len = (int) strlen(pt);
    int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH], exp[MAX_CIPHER_LENGTH];
    int ptkw[ALPHABET_SIZE], ctkw[ALPHABET_SIZE], pr[MAX_CYCLEWORD_LEN];

    str_to_indices(pt, P);
    str_to_indices(expected, exp);
    if (pt_kw) make_keyed_alphabet((char *) pt_kw, ptkw); else straight_alphabet(ptkw, ALPHABET_SIZE);
    if (ct_kw) make_keyed_alphabet((char *) ct_kw, ctkw); else straight_alphabet(ctkw, ALPHABET_SIZE);
    str_to_indices(primer, pr);
    int prlen = (int) strlen(primer);

    autokey_encrypt(&cfg, C, P, len, ptkw, ctkw, pr, prlen);
    CHECK(arrays_equal(C, exp, len), "%s encrypt KAT mismatch", name);

    autokey_decrypt(&cfg, back, C, len, ptkw, ctkw, pr, prlen);
    CHECK(arrays_equal(back, P, len), "%s decrypt round-trip mismatch", name);
}

static void test_autokey_known_answer(void) {
    const char *cia =
        "CIAMARKERONTHEGROUNDEASTNORTHEASTOFKRYPTOSDECODEUSINGSETTHEORY"
        "BERLINCLOCKANDFOLLOWMARKERDIRECTION";

    // Auto0 (Vigenere tableau), standard and variant.
    autokey_kat("auto0-std", AUTOKEY_0, 0, NULL, NULL, "PRIMER",
        "DOYOULIKETHESUMMARY", "SFGAYCLYCHBPAEQFHVQ");
    autokey_kat("auto0-var", AUTOKEY_0, 1, NULL, NULL, "PRIMER",
        "DOYOULIKETHESUMMARY", "OXQCQUFWGFNTKKITTNG");

    // Auto1 (Quagmire I: keyed PT, straight CT), variant.
    autokey_kat("auto1-var", AUTOKEY_1, 1, "KRYPTOS", NULL, "GIRASOL", cia,
        "DHQSPNPJTFHEXBJKRIADHBPQZSYAOTOTQOTTXCLLRBAULQRXDDLRZDHKMGYZJY"
        "PSUNBCLQBSPZGIBRPHFKPCNPANODBUZAYCL");

    // Auto3 (Quagmire III: same keyed PT & CT), standard.
    autokey_kat("auto3-std", AUTOKEY_3, 0, "KRYPTOS", "KRYPTOS", "GIRASOL", cia,
        "VTBZGSLQJFEEIEXYDHWXVQACHXEIULEZCSJHFCCBDMDFEBHJRJKYMJVZDPTMAG"
        "FIIYQQEZJDLVFNPDKLFJYNSLYSAABFCIJIB");

    // Autokey Beaufort and Porta tableaus.
    autokey_kat("autobeau", AUTOKEY_BEAU, 0, NULL, NULL, "GIRASOL", cia,
        "EAROSXBYRMZHKGYAATGEAGZVHZMLTOTVVDOXNCDAANHNWBQKYLWPILABZBJSBG"
        "SPQTGEWQQPBIAZGARZMRRFXBHXTEJNILJPV");
    autokey_kat("autoporta", AUTOKEY_PORTA, 0, NULL, NULL, "GIRASOL", cia,
        "SZVZWKPSABHGPWVJHBETTQKMDIDEUNWMMGONCLGKHDVZOHZYLEXMNETJKYXLIJ"
        "XNBNPFOYMXPRHRXHZQBDNPKPWKOOEZUEQAJ");
}

// Round-trip across all autokey tableaus, primer lengths and (where meaningful)
// the variant flag. The quag-family math is identical for auto0-4 -- the type
// only fixes which alphabet is straight -- so random PT/CT alphabets under
// AUTOKEY_4 cover that whole family; AUTOKEY_BEAU/PORTA exercise the reciprocal
// tableaus (which ignore the keywords and variant).
static void test_autokey_roundtrip(void) {
    int types[] = {AUTOKEY_4, AUTOKEY_BEAU, AUTOKEY_PORTA};
    int lens[] = {1, 26, 97, 336};
    int prlens[] = {1, 4, 7};

    for (int ti = 0; ti < 3; ti++) {
        for (int li = 0; li < 4; li++) {
            int len = lens[li];
            for (int pi = 0; pi < 3; pi++) {
                int prlen = prlens[pi];
                for (int variant = 0; variant <= 1; variant++) {
                    ColossusConfig cfg;
                    autokey_cfg(&cfg, types[ti], variant);

                    int pt[ALPHABET_SIZE], ct[ALPHABET_SIZE], pr[MAX_CYCLEWORD_LEN];
                    int P[MAX_CIPHER_LENGTH], C[MAX_CIPHER_LENGTH], back[MAX_CIPHER_LENGTH];

                    random_alphabet(pt);
                    random_alphabet(ct);
                    random_text(P, len);
                    for (int i = 0; i < prlen; i++) pr[i] = rand_int(0, ALPHABET_SIZE);

                    autokey_encrypt(&cfg, C, P, len, pt, ct, pr, prlen);
                    autokey_decrypt(&cfg, back, C, len, pt, ct, pr, prlen);
                    CHECK(arrays_equal(back, P, len),
                        "autokey round-trip type=%d len=%d prlen=%d variant=%d",
                        types[ti], len, prlen, variant);
                }
            }
        }
    }
}

int main(void) {
    seed_rand(20240617u);

    // make_keyed_alphabet() maps keyword letters through g_char_to_idx, so the
    // runtime alphabet must be built first (exactly as the real binary's main does).
    // Without this the keyed-alphabet KATs (auto1/auto3) silently encrypt against a
    // straight alphabet -- round-trips still pass, but the fixed vectors mismatch.
    init_alphabet(NULL);

    test_vigenere_known_answer();
    test_vigenere_roundtrip();
    test_beaufort();
    test_porta();
    test_quagmire_roundtrip();
    test_quagmire_matches_vigenere();
    test_autokey_known_answer();
    test_autokey_roundtrip();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
