#!/bin/bash

../quagmire -type 2 -cipher q2_p125_1.txt -ngramsize 5 -ngramfile ../english_quintgrams.txt -nsigmathreshold 1. -nhillclimbs 2500 -nrestarts 10000 -backtrackprob 0.15 -slipprob 0.0005 -plaintextkeywordlen 5 -ciphertextkeywordlen 5 -verbose
