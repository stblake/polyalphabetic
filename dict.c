
// Dictionary utilities

#include "polyalphabetic.h"

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

