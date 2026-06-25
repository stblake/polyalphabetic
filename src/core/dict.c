
// Dictionary utilities

#include "colossus.h"

void load_dictionary(char *filename, char ***dict, int *n_dict_words, int *max_dict_word_len, bool verbose) {
    FILE *fp;
    int i, n_words, max_word_len;
    char word[MAX_DICT_WORD_LEN];

    if (verbose) printf("\nLoading dictionary...\n\n");
    fp = fopen(filename, "r");
    n_words = 0;
    max_word_len = 0;
    while(!feof (fp)) {
        fscanf(fp, "%s\n", word);
        n_words++;
        if (strlen(word) > max_word_len) max_word_len = strlen(word);
    }
    *max_dict_word_len = max_word_len;
    *n_dict_words = n_words;
    fclose(fp);

    if (verbose) printf("%d words in dictionary, longest word has %d chars.\n", n_words, max_word_len);
    *dict = malloc(n_words*sizeof(char*));
    for (i = 0; i < n_words; i++) {
        (*dict)[i] = malloc((max_word_len + 1)*sizeof(char));
    }

    fp = fopen(filename, "r");
    i = 0; 
    while(!feof (fp)) {
        fscanf(fp, "%s\n", word);
        strcpy((*dict)[i], word);
        i++; 
    }
    fclose(fp);
    if (verbose) printf("\n...finished.\n");
}



void free_dictionary(char **dict, int n_dict_words) {
    for (int i = 0; i < n_dict_words; i++) free(dict[i]);
    free(dict);
}



// =====================================================================
//  Word set (fast hash lookup) + word-coverage objective  (Rec 2)
// =====================================================================
//
// A hash set of the dictionary words for O(1) membership tests, used by the
// space-preserving transposition solvers (the seam best-L objective and the
// optional -weightword reward). Open addressing, linear probing, power-of-two
// capacity. Built only when a solver asks for it, so default solves are unaffected.

struct WordSet {
    char **slot;     // slot[i] = interned word or NULL
    int    cap;      // power of two
    int    count;
};

static unsigned long ws_hash(const char *s) {
    unsigned long h = 1469598103934665603UL;        // FNV-1a
    for (; *s; s++) { h ^= (unsigned char) *s; h *= 1099511628211UL; }
    return h;
}

static void ws_insert(WordSet *ws, const char *word) {
    int mask = ws->cap - 1;
    int i = (int)(ws_hash(word) & mask);
    while (ws->slot[i]) {
        if (strcmp(ws->slot[i], word) == 0) return;  // already present
        i = (i + 1) & mask;
    }
    ws->slot[i] = strdup(word);
    ws->count++;
}

WordSet *word_set_build(char **dict, int n_words) {
    WordSet *ws = malloc(sizeof(WordSet));
    int cap = 16;
    while (cap < n_words * 2) cap <<= 1;             // load factor < 0.5
    ws->cap = cap; ws->count = 0;
    ws->slot = calloc(cap, sizeof(char *));
    char buf[MAX_DICT_WORD_LEN + 1];
    for (int k = 0; k < n_words; k++) {
        const char *w = dict[k];
        int len = (int) strlen(w);
        if (len < 1 || len > MAX_DICT_WORD_LEN) continue;
        int ok = 1;
        for (int j = 0; j < len; j++) {
            unsigned char c = (unsigned char) w[j];
            if (!isalpha(c)) { ok = 0; break; }
            buf[j] = toupper(c);
        }
        if (!ok) continue;
        buf[len] = '\0';
        ws_insert(ws, buf);
    }
    return ws;
}

void word_set_free(WordSet *ws) {
    if (!ws) return;
    for (int i = 0; i < ws->cap; i++) free(ws->slot[i]);
    free(ws->slot);
    free(ws);
}

int word_set_contains(const WordSet *ws, const char *upper_word) {
    int mask = ws->cap - 1;
    int i = (int)(ws_hash(upper_word) & mask);
    while (ws->slot[i]) {
        if (strcmp(ws->slot[i], upper_word) == 0) return 1;
        i = (i + 1) & mask;
    }
    return 0;
}

// Length-weighted dictionary coverage of `text`: split on negative sentinels
// (spaces / punctuation carried through the cipher) into tokens, and sum the
// lengths of the tokens that are dictionary words. Additive across concatenation
// (a join can only form new boundary tokens), so it slots into the seam best-L
// decomposition exactly like the n-gram sum. Letters use the runtime alphabet map.
double word_coverage(const int *text, int len, const WordSet *ws) {
    if (!ws) return 0.0;
    double cov = 0.0;
    char tok[MAX_DICT_WORD_LEN + 1];
    int t = 0;
    for (int i = 0; i <= len; i++) {
        int v = (i < len) ? text[i] : -1;            // force a flush at the end
        if (v >= 0) {
            if (t <= MAX_DICT_WORD_LEN) {
                if (t < MAX_DICT_WORD_LEN) tok[t] = (char) toupper((unsigned char) g_idx_to_char_arr[v]);
                t++;
            }
        } else {
            if (t >= 1 && t <= MAX_DICT_WORD_LEN) {
                tok[t] = '\0';
                if (word_set_contains(ws, tok)) cov += t;
            }
            t = 0;
        }
    }
    return cov;
}

int find_dictionary_words(char *plaintext, char **dict, int n_dict_words, int max_dict_word_len) {
    int n_matches = 0, plaintext_len, min_word_len;
    char fragment[MAX_DICT_WORD_LEN], *dict_word;
    plaintext_len = strlen(plaintext);
    min_word_len = 3;
    for (int i = 0; i < plaintext_len - min_word_len; i++) {
        for (int word_len = min_word_len; word_len < min(max_dict_word_len, plaintext_len - i); word_len++) {
            for (int j = 0; j < word_len; j++) fragment[j] = plaintext[i + j];
            fragment[word_len] = '\0'; 
            for (int k = 0; k < n_dict_words; k++) {
                dict_word = dict[k];
                if (strlen(dict_word) > word_len) continue ;
                else if (strlen(dict_word) < word_len) break ;
                else if (strcmp(dict_word, fragment) == 0 ) {
                    printf("%s\n", fragment);
                    n_matches++;
                    break ;
                }
            }
        }
    }
    return n_matches;
}

