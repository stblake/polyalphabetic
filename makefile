#
#   makefile
#

CC=gcc -Wall -O3 

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) utils.c parse.c dict.c transpositions.c perioc.c quagmire.c vigenere.c porta.c beaufort.c autokey.c polyalphabetic.c -o polyalphabetic
	cp polyalphabetic ..
	cp polyalphabetic ../quagmire

# Unit tests for the transposition primitives. Add -lm on Linux.
test:
	$(CC) tests/test_transpositions.c utils.c transpositions.c -o tests/test_transpositions
	./tests/test_transpositions

clean:
	rm -f polyalphabetic tests/test_transpositions

