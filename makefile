#
#   makefile
#

CC=gcc -Wall -O3 -funroll-loops

# CC=gcc -Wall -lm -g -O0

# Sources live under src/<cipher-class>/. All local #includes are flat
# (#include "foo.h"), so the compiler finds every header via these -I paths
# regardless of which subdirectory it lives in.
SRC=src
INCLUDES=-I$(SRC)/core -I$(SRC)/polyalphabetic -I$(SRC)/transposition -I$(SRC)/polygraphic -I$(SRC)/substitution

CORE=$(SRC)/core
POLY=$(SRC)/polyalphabetic
TRANS=$(SRC)/transposition
GRAPH=$(SRC)/polygraphic
SUBST=$(SRC)/substitution

# Cipher primitives (decrypt math, shared by the solvers and the unit tests).
PRIMITIVES=$(CORE)/utils.c $(CORE)/parse.c $(CORE)/dict.c $(TRANS)/transpositions.c $(CORE)/perioc.c $(POLY)/quagmire.c $(POLY)/vigenere.c $(POLY)/gronsfeld.c $(POLY)/porta.c $(POLY)/beaufort.c $(POLY)/autokey.c $(CORE)/optimal_cycleword.c $(GRAPH)/playfair.c $(GRAPH)/bifid.c $(GRAPH)/trifid.c $(GRAPH)/hill.c $(GRAPH)/phillips.c

# Cipher-agnostic core + per-cipher-type solver modules (split out of colossus.c).
SOLVERS=$(CORE)/engine.c $(CORE)/scoring.c $(TRANS)/trans_common.c $(POLY)/polyalpha_solver.c $(TRANS)/transmatrix_solver.c $(TRANS)/permutation_solver.c $(TRANS)/columnar_solver.c $(TRANS)/railfence_solver.c $(TRANS)/route_solver.c $(TRANS)/amsco_solver.c $(TRANS)/myszkowski_solver.c $(TRANS)/redefence_solver.c $(TRANS)/cadenus_solver.c $(TRANS)/nihilist_solver.c $(TRANS)/swagman_solver.c $(TRANS)/grille_solver.c $(SUBST)/indep_solver.c $(SUBST)/homophonic_solver.c $(GRAPH)/playfair_solver.c $(GRAPH)/bifid_solver.c $(GRAPH)/trifid_solver.c $(GRAPH)/hill_solver.c $(GRAPH)/phillips_solver.c

# The full solver translation-unit set (everything but the test harnesses).
SOLVER_SRC=$(PRIMITIVES) $(SOLVERS) $(CORE)/colossus.c

all:
	$(CC) $(INCLUDES) $(SOLVER_SRC) -o colossus
	cp colossus ..
	cp colossus ../quagmire

# Fast unit tests of the primitives (sub-second). Add -lm on Linux.
#   test_transpositions   : the transposition primitives (transpositions.c)
#   test_ciphers          : the cipher primitives (vigenere/beaufort/porta/quagmire/autokey)
#   test_optimal_cycleword : deterministic optimal-cycleword recovery
#   test_playfair         : the Playfair primitives (grid build / encrypt / decrypt / prepare)
test:
	$(CC) $(INCLUDES) tests/test_transpositions.c $(CORE)/utils.c $(TRANS)/transpositions.c -o tests/test_transpositions
	./tests/test_transpositions
	$(CC) $(INCLUDES) tests/test_ciphers.c $(CORE)/utils.c $(POLY)/quagmire.c $(POLY)/vigenere.c $(POLY)/porta.c $(POLY)/beaufort.c $(POLY)/autokey.c -o tests/test_ciphers
	./tests/test_ciphers
	$(CC) $(INCLUDES) tests/test_gronsfeld.c $(CORE)/utils.c $(POLY)/gronsfeld.c $(POLY)/vigenere.c $(POLY)/quagmire.c -o tests/test_gronsfeld
	./tests/test_gronsfeld
	$(CC) $(INCLUDES) tests/test_optimal_cycleword.c $(CORE)/utils.c $(POLY)/quagmire.c $(POLY)/vigenere.c $(POLY)/porta.c $(POLY)/beaufort.c $(CORE)/optimal_cycleword.c -o tests/test_optimal_cycleword
	./tests/test_optimal_cycleword
	$(CC) $(INCLUDES) tests/test_playfair.c $(CORE)/utils.c $(GRAPH)/playfair.c -o tests/test_playfair
	./tests/test_playfair
	$(CC) $(INCLUDES) tests/test_bifid.c $(CORE)/utils.c $(GRAPH)/bifid.c -o tests/test_bifid
	./tests/test_bifid
	$(CC) $(INCLUDES) tests/test_trifid.c $(CORE)/utils.c $(GRAPH)/trifid.c -o tests/test_trifid
	./tests/test_trifid
	$(CC) $(INCLUDES) tests/test_hill.c $(CORE)/utils.c $(GRAPH)/hill.c -o tests/test_hill
	./tests/test_hill
	$(CC) $(INCLUDES) tests/test_phillips.c $(CORE)/utils.c $(GRAPH)/phillips.c -o tests/test_phillips
	./tests/test_phillips

# Slow optimizer regression suite (~30s): planted-cipher recovery through the
# full solve_cipher hill climber at fixed seeds and budgets. Kept separate from
# `make test` so the fast primitive checks stay in the quick edit/build loop.
testopt:
	$(CC) $(INCLUDES) -DCOLOSSUS_NO_MAIN tests/test_solver.c $(SOLVER_SRC) -o tests/test_solver
	./tests/test_solver
	$(CC) $(INCLUDES) -DCOLOSSUS_NO_MAIN tests/test_gronsfeld_solver.c $(SOLVER_SRC) -o tests/test_gronsfeld_solver
	./tests/test_gronsfeld_solver
	$(CC) $(INCLUDES) -DCOLOSSUS_NO_MAIN tests/test_playfair_solver.c $(SOLVER_SRC) -o tests/test_playfair_solver
	./tests/test_playfair_solver
	$(CC) $(INCLUDES) -DCOLOSSUS_NO_MAIN tests/test_bifid_solver.c $(SOLVER_SRC) -o tests/test_bifid_solver
	./tests/test_bifid_solver
	$(CC) $(INCLUDES) -DCOLOSSUS_NO_MAIN tests/test_trifid_solver.c $(SOLVER_SRC) -o tests/test_trifid_solver
	./tests/test_trifid_solver
	$(CC) $(INCLUDES) -DCOLOSSUS_NO_MAIN tests/test_hill_solver.c $(SOLVER_SRC) -o tests/test_hill_solver
	./tests/test_hill_solver
	$(CC) $(INCLUDES) -DCOLOSSUS_NO_MAIN tests/test_phillips_solver.c $(SOLVER_SRC) -o tests/test_phillips_solver
	./tests/test_phillips_solver

# Everything.
testall: test testopt

# Standalone test-data generator for homophonic ciphers (not part of the solver
# build). Emits a comma-separated homophonic ciphertext + its plaintext solution;
# used to mint ciphers/tests/homophonic_test.*.
homophonic_gen:
	$(CC) $(INCLUDES) tools/homophonic_gen.c -o tools/homophonic_gen

# Standalone test-data generator for Playfair ciphers. Reuses the real cipher code
# (playfair.c + utils.c) so the generator and solver can never drift in convention.
playfair_gen:
	$(CC) $(INCLUDES) tools/playfair_gen.c $(GRAPH)/playfair.c $(CORE)/utils.c -o tools/playfair_gen

# Standalone test-data generator for Bifid ciphers. Reuses the real cipher code
# (bifid.c + utils.c) so the generator and solver can never drift in convention.
bifid_gen:
	$(CC) $(INCLUDES) tools/bifid_gen.c $(GRAPH)/bifid.c $(CORE)/utils.c -o tools/bifid_gen

# Standalone test-data generator for Trifid ciphers. Reuses the real cipher code
# (trifid.c + utils.c) so the generator and solver can never drift in convention.
trifid_gen:
	$(CC) $(INCLUDES) tools/trifid_gen.c $(GRAPH)/trifid.c $(CORE)/utils.c -o tools/trifid_gen

# Standalone test-data generator for Hill ciphers. Reuses the real cipher code
# (hill.c + utils.c) so the generator and solver can never drift in convention.
hill_gen:
	$(CC) $(INCLUDES) tools/hill_gen.c $(GRAPH)/hill.c $(CORE)/utils.c -o tools/hill_gen

# Standalone test-data generator for Gronsfeld ciphers. Reuses the real cipher code
# (gronsfeld.c + utils.c) so the generator and solver can never drift in convention.
gronsfeld_gen:
	$(CC) $(INCLUDES) tools/gronsfeld_gen.c $(POLY)/gronsfeld.c $(CORE)/utils.c -o tools/gronsfeld_gen

# Standalone test-data generator for Phillips ciphers. Reuses the real cipher code
# (phillips.c + utils.c) so the generator and solver can never drift in convention.
phillips_gen:
	$(CC) $(INCLUDES) tools/phillips_gen.c $(GRAPH)/phillips.c $(CORE)/utils.c -o tools/phillips_gen

clean:
	rm -f colossus tests/test_transpositions tests/test_ciphers tests/test_optimal_cycleword tests/test_solver tests/test_playfair tests/test_playfair_solver tests/test_bifid tests/test_bifid_solver tests/test_trifid tests/test_trifid_solver tests/test_hill tests/test_hill_solver tests/test_gronsfeld tests/test_gronsfeld_solver tests/test_phillips tests/test_phillips_solver tools/homophonic_gen tools/playfair_gen tools/bifid_gen tools/trifid_gen tools/hill_gen tools/gronsfeld_gen tools/phillips_gen
