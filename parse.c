
// Parser for cipher types


#include "colossus.h"


// Helper for case-insensitive comparison
int str_eq(const char *a, const char *b) {
    return strcasecmp(a, b) == 0;
}



int parse_cipher_type(const char *arg) {
    // Check if the argument is a pure integer.
    char *endptr;
    long val = strtol(arg, &endptr, 10);
    
    // If endptr points to the null terminator, the whole string was a number.
    if (*arg != '\0' && *endptr == '\0') {
        return (int)val;
    }

    // Check string aliases (case insensitive.)
    
    // Vigenere
    if (str_eq(arg, "vig") || str_eq(arg, "vigenere")) return VIGENERE;

    // Quagmire I
    if (str_eq(arg, "q1") || str_eq(arg, "quag1") || str_eq(arg, "quagmire1")) return QUAGMIRE_1;

    // Quagmire II
    if (str_eq(arg, "q2") || str_eq(arg, "quag2") || str_eq(arg, "quagmire2")) return QUAGMIRE_2;

    // Quagmire III
    if (str_eq(arg, "q3") || str_eq(arg, "quag3") || str_eq(arg, "quagmire3")) return QUAGMIRE_3;

    // Quagmire IV
    if (str_eq(arg, "q4") || str_eq(arg, "quag4") || str_eq(arg, "quagmire4")) return QUAGMIRE_4;

    // Beaufort
    if (str_eq(arg, "beau") || str_eq(arg, "beaufort")) return BEAUFORT;

    // Porta
    if (str_eq(arg, "porta")) return PORTA;

    // Autokey (Vigenere Tableau)
    if (str_eq(arg, "auto") || str_eq(arg, "autokey") || str_eq(arg, "auto0") || str_eq(arg, "autovig")) return AUTOKEY_0;

    // Autokey Variants
    if (str_eq(arg, "auto1") || str_eq(arg, "autokey1") || str_eq(arg, "autoquag1")) return AUTOKEY_1;
    if (str_eq(arg, "auto2") || str_eq(arg, "autokey2") || str_eq(arg, "autoquag2")) return AUTOKEY_2;
    if (str_eq(arg, "auto3") || str_eq(arg, "autokey3") || str_eq(arg, "autoquag3")) return AUTOKEY_3;
    if (str_eq(arg, "auto4") || str_eq(arg, "autokey4") || str_eq(arg, "autoquag4")) return AUTOKEY_4;

    // Autokey with Beaufort and Porta tableau
	if (str_eq(arg, "auto5") || str_eq(arg, "abeau") || str_eq(arg, "autobeau") || str_eq(arg, "autobeaufort")) return AUTOKEY_BEAU;
	if (str_eq(arg, "auto6") || str_eq(arg, "aporta") || str_eq(arg, "autoporta")) return AUTOKEY_PORTA;

    // Transposition ciphers (solved by optimization over the transform parameters)
    if (str_eq(arg, "transmatrix") || str_eq(arg, "tmatrix") || str_eq(arg, "matrix")) return TRANSMATRIX;
    if (str_eq(arg, "transperoffset") || str_eq(arg, "transperiodoffset") ||
        str_eq(arg, "transperoff") || str_eq(arg, "tpo")) return TRANSPEROFFSET;
    if (str_eq(arg, "trans") || str_eq(arg, "transpo") || str_eq(arg, "transposition")) return TRANSPOSITION;

    // Columnar transposition (dedicated solver over the column-order permutation)
    if (str_eq(arg, "transcol") || str_eq(arg, "transpocolumnar") ||
        str_eq(arg, "columnar") || str_eq(arg, "col")) return TRANSCOL;
    if (str_eq(arg, "transcol2") || str_eq(arg, "doublecolumnar") ||
        str_eq(arg, "doublecol") || str_eq(arg, "dcol")) return TRANSCOL2;

    // Rail fence (covers the variant rail fence via the phase-offset sweep)
    if (str_eq(arg, "railfence") || str_eq(arg, "rail") || str_eq(arg, "rails") ||
        str_eq(arg, "varrailfence")) return RAILFENCE;

    // Route transposition (snake / spiral over an R x C grid)
    if (str_eq(arg, "route") || str_eq(arg, "routetransposition") ||
        str_eq(arg, "routetramp")) return ROUTE;

    // Amsco (alternating 1/2-letter columnar)
    if (str_eq(arg, "amsco")) return AMSCO;

    // Myszkowski (columnar with tied keyword ranks)
    if (str_eq(arg, "myszkowski") || str_eq(arg, "mysz")) return MYSZKOWSKI;

    // Redefence (keyed rail fence)
    if (str_eq(arg, "redefence") || str_eq(arg, "rede")) return REDEFENCE;

    // Cadenus (rotated-column transposition, 25 rows)
    if (str_eq(arg, "cadenus")) return CADENUS;

    // Nihilist transposition (single permutation on rows + columns)
    if (str_eq(arg, "nihilist") || str_eq(arg, "nihilisttransposition") ||
        str_eq(arg, "nihilisttramp")) return NIHILIST;

    // Swagman (N x N Latin-square column transposition)
    if (str_eq(arg, "swagman")) return SWAGMAN;

    // Turning grille
    if (str_eq(arg, "grille") || str_eq(arg, "turninggrille")) return GRILLE;

    // Independent periodic substitution (P independent mixed alphabets)
    if (str_eq(arg, "indep") || str_eq(arg, "indperiodic") || str_eq(arg, "periodicsub")
        || str_eq(arg, "indepperiodic")) return INDEP_PERIODIC;

    // Homophonic substitution (ciphertext alphabet larger than the plaintext alphabet)
    if (str_eq(arg, "homophonic") || str_eq(arg, "homophone") || str_eq(arg, "homo"))
        return HOMOPHONIC;

    // Playfair (digraphic substitution over a 5x5 keyed grid)
    if (str_eq(arg, "playfair") || str_eq(arg, "pf")) return PLAYFAIR;

    // Bifid (Delastelle fractionation over a keyed Polybius square)
    if (str_eq(arg, "bifid") || str_eq(arg, "bf")) return BIFID;

    // Trifid (Delastelle fractionation over a 3x3x3 keyed cube)
    if (str_eq(arg, "trifid") || str_eq(arg, "tf") || str_eq(arg, "tri")) return TRIFID;

    // Hill (polygraphic substitution by a k x k matrix mod 26)
    if (str_eq(arg, "hill")) return HILL;

    // Gronsfeld (Vigenere with a numeric key: per-column shifts 0..9)
    if (str_eq(arg, "gronsfeld") || str_eq(arg, "gron")) return GRONSFELD;

    // Phillips (8-square keyed-Polybius substitution) and its column / row-column variants.
    // Test the variants before the bare "phillips" so the longer aliases win.
    if (str_eq(arg, "phillips-c") || str_eq(arg, "phillipsc") || str_eq(arg, "phillips_c") ||
        str_eq(arg, "phillipscolumn")) return PHILLIPS_C;
    if (str_eq(arg, "phillips-rc") || str_eq(arg, "phillipsrc") || str_eq(arg, "phillips_rc") ||
        str_eq(arg, "phillipsrowcolumn")) return PHILLIPS_RC;
    if (str_eq(arg, "phillips") || str_eq(arg, "phil")) return PHILLIPS;

    // Return -1 to indicate invalid/unknown type.
    return -1;
}




