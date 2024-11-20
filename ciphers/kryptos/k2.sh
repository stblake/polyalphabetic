#!/bin/bash

./quagmire -cipher k2.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nhillclimbs 500 -nrestarts 100000 -backtrackprob 0.15 -verbose


