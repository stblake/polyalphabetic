//
//  Nihilist Substitution cipher primitives (periodic additive over a keyed Polybius square).
//
//  The square is a permutation of the active n = side*side letter alphabet (the binary forces
//  g_alpha == 25 for the default -type nihilist-sub: a 5x5 grid of 0..24, J merged into I).
//  grid[p] is the letter at cell p (row p/side, col p%side); the inverse pos[l] is the cell of
//  letter l. Each cell maps to a 2-digit coordinate NUMBER via the row/column labels:
//      num(cell) = rowlbl[row]*10 + collbl[col]
//  With the standard fixed labels (1..side) that is (row+1)*10 + (col+1), so for the 5x5 the
//  legal numbers are V = {11..15, 21..25, 31..35, 41..45, 51..55}. The labels may be a
//  permutation of 1..side (the "keyed-label" variant) -- but since that only permutes WHICH
//  cell gets WHICH number, the legal-number set V is unchanged, so validity (both digits in
//  1..side) is label-independent.
//
//  Encryption of position i (key has period p):
//      pt_num  = num(cell of plaintext[i])
//      key_num = num(key_cells[i % p])
//      cipher_num[i] = pt_num (+) key_num            -- (+) per the NIH_ADD_* convention
//  The three conventions:
//      NIH_ADD_CARRY   integer add with carry (ACA standard); cipher 22..110
//      NIH_ADD_NOCARRY each coordinate digit added mod 10, no carry; cipher 00..99
//      NIH_ADD_MOD100  the two 2-digit numbers added mod 100; cipher 00..99
//  Decryption inverts the add (pt_num = cipher_num (-) key_num) and looks the resulting
//  coordinate back up in the square. A position whose pt_num is not a legal coordinate
//  (digits outside 1..side -- only possible under a WRONG key) decrypts to the sentinel
//  letter 0; nihilist_sub_decrypt returns the count of LEGAL positions, the square-independent
//  signal the solver rewards to lock the additive key.
//
//  The additive key is carried as cell indices (0..n-1), exactly the plaintext space: a key
//  letter's number is num(its cell). The solver searches these cells directly (the recovered
//  key is reported both as numbers and, via the recovered square, as a keyword).
//

#include "colossus.h"

// Fill rowlbl[0..side-1] = collbl[0..side-1] = 1..side (the standard fixed coordinate labels).
void nihilist_sub_fixed_labels(int rowlbl[], int collbl[], int side) {
    for (int i = 0; i < side; i++) { rowlbl[i] = i + 1; collbl[i] = i + 1; }
}

// Are both digits of a 2-digit coordinate number in [1..side]? The legal-number set is
// label-permutation invariant, so this is the validity test regardless of keyed labels.
int nihilist_sub_num_valid(int num, int side) {
    int dr = num / 10, dc = num % 10;
    return (dr >= 1 && dr <= side && dc >= 1 && dc <= side);
}

// Build a digit -> index inverse for a label array (labels are 1..side, distinct).
static void nih_label_inverse(const int lbl[], int side, int inv[10]) {
    for (int d = 0; d < 10; d++) inv[d] = -1;
    for (int i = 0; i < side; i++) inv[lbl[i]] = i;
}

// Coordinate cell -> its 2-digit label number.
static int nih_cell_to_num(int cell, int side, const int rowlbl[], const int collbl[]) {
    return rowlbl[cell / side] * 10 + collbl[cell % side];
}

// Apply the additive convention: cipher_num = pt_num (+) key_num.
static int nih_add(int pt_num, int key_num, int conv) {
    if (conv == NIH_ADD_NOCARRY) {
        int dr = ((pt_num / 10) + (key_num / 10)) % 10;
        int dc = ((pt_num % 10) + (key_num % 10)) % 10;
        return dr * 10 + dc;
    }
    if (conv == NIH_ADD_MOD100)
        return (pt_num + key_num) % 100;
    return pt_num + key_num;                       // NIH_ADD_CARRY
}

// Invert the additive convention: pt_num = cipher_num (-) key_num.
static int nih_sub(int cipher_num, int key_num, int conv) {
    if (conv == NIH_ADD_NOCARRY) {
        int dr = (((cipher_num / 10) - (key_num / 10)) % 10 + 10) % 10;
        int dc = (((cipher_num % 10) - (key_num % 10)) % 10 + 10) % 10;
        return dr * 10 + dc;
    }
    if (conv == NIH_ADD_MOD100)
        return ((cipher_num - key_num) % 100 + 100) % 100;
    return cipher_num - key_num;                   // NIH_ADD_CARRY (may be negative / >99)
}

// Encipher n plaintext letters into n coordinate numbers out_nums[].
void nihilist_sub_encrypt(const int plain[], int n, const int grid[],
        const int rowlbl[], const int collbl[], int side,
        const int key_cells[], int period, int conv, int out_nums[]) {
    int ncell = side * side;
    int pos[NIHILIST_SUB_MAX_GRID];
    for (int p = 0; p < ncell; p++) pos[grid[p]] = p;       // letter -> cell
    for (int i = 0; i < n; i++) {
        int pt_num  = nih_cell_to_num(pos[plain[i]], side, rowlbl, collbl);
        int key_num = nih_cell_to_num(key_cells[i % period], side, rowlbl, collbl);
        out_nums[i] = nih_add(pt_num, key_num, conv);
    }
}

// Decipher n coordinate numbers into n plaintext letters out_letters[]; returns the number of
// positions that decrypted to a LEGAL coordinate (the rest get the sentinel letter 0).
int nihilist_sub_decrypt(const int nums[], int n, const int grid[],
        const int rowlbl[], const int collbl[], int side,
        const int key_cells[], int period, int conv, int out_letters[]) {
    int rinv[10], cinv[10];
    nih_label_inverse(rowlbl, side, rinv);
    nih_label_inverse(collbl, side, cinv);
    int n_valid = 0;
    for (int i = 0; i < n; i++) {
        int key_num = nih_cell_to_num(key_cells[i % period], side, rowlbl, collbl);
        int pt_num  = nih_sub(nums[i], key_num, conv);
        int dr = pt_num / 10, dc = pt_num % 10;
        // Range-check dr,dc BEFORE indexing the inverse (pt_num may be <0 or >99 under a
        // wrong CARRY key); the && short-circuits so the inverse is only read in-range.
        if (dr >= 1 && dr <= side && dc >= 1 && dc <= side && rinv[dr] >= 0 && cinv[dc] >= 0) {
            out_letters[i] = grid[rinv[dr] * side + cinv[dc]];
            n_valid++;
        } else {
            out_letters[i] = 0;                    // sentinel: scores as gibberish
        }
    }
    return n_valid;
}
