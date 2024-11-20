#!/bin/bash

./quagmire -cipher cipher.txt -crib crib.txt -ngramsize 4 -ngramfile english_quadgrams.txt -keywordlen 7 -cyclewordlen 7 -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.15 -verbose

