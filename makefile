#
#   makefile
#

CC=gcc -Wall -O3 -funroll-loops

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) utils.c parse.c dict.c transpositions.c perioc.c quagmire.c vigenere.c porta.c beaufort.c autokey.c optimal_cycleword.c playfair.c colossus.c -o colossus
	cp colossus ..
	cp colossus ../quagmire

# Fast unit tests of the primitives (sub-second). Add -lm on Linux.
#   test_transpositions   : the transposition primitives (transpositions.c)
#   test_ciphers          : the cipher primitives (vigenere/beaufort/porta/quagmire/autokey)
#   test_optimal_cycleword : deterministic optimal-cycleword recovery
#   test_playfair         : the Playfair primitives (grid build / encrypt / decrypt / prepare)
test:
	$(CC) tests/test_transpositions.c utils.c transpositions.c -o tests/test_transpositions
	./tests/test_transpositions
	$(CC) tests/test_ciphers.c utils.c quagmire.c vigenere.c porta.c beaufort.c autokey.c -o tests/test_ciphers
	./tests/test_ciphers
	$(CC) tests/test_optimal_cycleword.c utils.c quagmire.c vigenere.c porta.c beaufort.c optimal_cycleword.c -o tests/test_optimal_cycleword
	./tests/test_optimal_cycleword
	$(CC) tests/test_playfair.c utils.c playfair.c -o tests/test_playfair
	./tests/test_playfair

# Slow optimizer regression suite (~30s): planted-cipher recovery through the
# full solve_cipher hill climber at fixed seeds and budgets. Kept separate from
# `make test` so the fast primitive checks stay in the quick edit/build loop.
testopt:
	$(CC) -DCOLOSSUS_NO_MAIN tests/test_solver.c utils.c parse.c dict.c transpositions.c perioc.c quagmire.c vigenere.c porta.c beaufort.c autokey.c optimal_cycleword.c playfair.c colossus.c -o tests/test_solver
	./tests/test_solver
	$(CC) -DCOLOSSUS_NO_MAIN tests/test_playfair_solver.c utils.c parse.c dict.c transpositions.c perioc.c quagmire.c vigenere.c porta.c beaufort.c autokey.c optimal_cycleword.c playfair.c colossus.c -o tests/test_playfair_solver
	./tests/test_playfair_solver

# Everything.
testall: test testopt

# Standalone test-data generator for homophonic ciphers (not part of the solver
# build). Emits a comma-separated homophonic ciphertext + its plaintext solution;
# used to mint ciphers/tests/homophonic_test.*.
homophonic_gen:
	$(CC) tools/homophonic_gen.c -o tools/homophonic_gen

# Standalone test-data generator for Playfair ciphers. Reuses the real cipher code
# (playfair.c + utils.c) so the generator and solver can never drift in convention.
playfair_gen:
	$(CC) tools/playfair_gen.c playfair.c utils.c -o tools/playfair_gen

clean:
	rm -f colossus tests/test_transpositions tests/test_ciphers tests/test_optimal_cycleword tests/test_solver tests/test_playfair tests/test_playfair_solver tools/homophonic_gen tools/playfair_gen

