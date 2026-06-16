#
#   makefile
#

CC=gcc -Wall -O3 

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) utils.c parse.c dict.c transpositions.c perioc.c quagmire.c vigenere.c porta.c beaufort.c autokey.c optimal_cycleword.c polyalphabetic.c -o polyalphabetic
	cp polyalphabetic ..
	cp polyalphabetic ../quagmire

# Fast unit tests of the primitives (sub-second). Add -lm on Linux.
#   test_transpositions   : the transposition primitives (transpositions.c)
#   test_ciphers          : the cipher primitives (vigenere/beaufort/porta/quagmire/autokey)
#   test_optimal_cycleword : deterministic optimal-cycleword recovery
test:
	$(CC) tests/test_transpositions.c utils.c transpositions.c -o tests/test_transpositions
	./tests/test_transpositions
	$(CC) tests/test_ciphers.c utils.c quagmire.c vigenere.c porta.c beaufort.c autokey.c -o tests/test_ciphers
	./tests/test_ciphers
	$(CC) tests/test_optimal_cycleword.c utils.c quagmire.c vigenere.c porta.c beaufort.c optimal_cycleword.c -o tests/test_optimal_cycleword
	./tests/test_optimal_cycleword

# Slow optimizer regression suite (~30s): planted-cipher recovery through the
# full solve_cipher hill climber at fixed seeds and budgets. Kept separate from
# `make test` so the fast primitive checks stay in the quick edit/build loop.
testopt:
	$(CC) -DPOLY_NO_MAIN tests/test_solver.c utils.c parse.c dict.c transpositions.c perioc.c quagmire.c vigenere.c porta.c beaufort.c autokey.c optimal_cycleword.c polyalphabetic.c -o tests/test_solver
	./tests/test_solver

# Everything.
testall: test testopt

clean:
	rm -f polyalphabetic tests/test_transpositions tests/test_ciphers tests/test_optimal_cycleword tests/test_solver

