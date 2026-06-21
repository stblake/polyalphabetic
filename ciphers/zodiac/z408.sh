#!/bin/bash

# Z408 is short (408 symbols) and contains the Zodiac's own misspellings, so the
# homophonic climb needs many backtracking restarts to escape partial basins. With
# the incremental scorer each iteration is cheap, so ~40M iterations (~50s) reliably
# lands the full plaintext; fewer can stall in a near-miss basin (try another -seed).
../../colossus -type homophonic -multiline \
    -cipher z408.txt \
    -ngramsize 5 -ngramfile ../../english_quintgrams.txt -logprob  \
    -nrestarts 400 -nhillclimbs 100000 \
    -backtrackprob 0.15 -seed 1 -verbose

