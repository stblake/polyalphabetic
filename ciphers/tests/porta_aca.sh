#!/bin/bash

./polyalphabetic -type 7 -cipher porta_aca.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 250 -nrestarts 100 -backtrackprob 0.15 -slipprob 0.05 -cyclewordlen 11 -stochasticcycle -verbose
