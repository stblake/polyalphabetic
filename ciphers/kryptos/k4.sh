#!/bin/bash

./polyalphabetic -type vig -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type beaufort -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type porta -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag1 -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag2 -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag3 -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag4 -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

# variants

./polyalphabetic -type vig -variant -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type beaufort -variant -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type porta -variant -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag1 -variant -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag2 -variant -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag3 -variant -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose

./polyalphabetic -type quag4 -variant -cipher k4.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 10000 -backtrackprob 0.15 -verbose


# autokey





