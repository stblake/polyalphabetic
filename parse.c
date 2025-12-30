
// Parser for cipher types


#include "polyalphabetic.h"


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
    if (str_eq(arg, "auto") || str_eq(arg, "autokey") || str_eq(arg, "auto0")) return AUTOKEY_0;

    // Autokey Variants
    if (str_eq(arg, "auto1") || str_eq(arg, "autokey1")) return AUTOKEY_1;
    if (str_eq(arg, "auto2") || str_eq(arg, "autokey2")) return AUTOKEY_2;
    if (str_eq(arg, "auto3") || str_eq(arg, "autokey3")) return AUTOKEY_3;
    if (str_eq(arg, "auto4") || str_eq(arg, "autokey4")) return AUTOKEY_4;

    // Return -1 to indicate invalid/unknown type.
    return -1;
}
