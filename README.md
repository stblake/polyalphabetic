# Quagmire Cipher Solver
stochastic shotgun-restarted hill climber for Quagmire-type ciphers.

Here is a simple example where we solve the following length 97, Quagmire III cipher

```MFABBMNNQEYEZIAIABLJJEFXNWJOTNPVDIBHQNNSIMRJPZIXOEJXROJVTNPFILBBJNSNTGLDRISJZWQCSDVIFKNNMVOIXTQOP```

with the following cribs

```_____________________EASTNORTHEAST_____________________________BERLINCLOCK_______________________```

We use a dataset of 5-grams English letter frequencies and fix the keyword length to 7:

```$ ./quagmire -type 3 -cipher cipher.txt -crib crib.txt -ngramsize 5 -ngramfile english_quintgrams.txt -plaintextkeywordlen 7 -nsigmathreshold 1. -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 -verbose```

After about 2 seconds we arrive at the following decryption: 

```
2.15	[sec]
268K	[it/sec]
33	[backtracks]
231	[restarts]
740	[iterations]
281	[slips]
1.00	[contradiction pct]
3.51	[score]
KRYPTOSABCDEFGHIJLMNQUVWXZ
KOMITET
MAINTAININGAHEADINGOFEASTNORTHEASTTHIRTYTHREEDEGREESFROMTHEWESTBERLINCLOCKYOUWILLSEEFURTHERINFORM
```

So the keyword was `KRYPTOS` and the cycleword was `KOMITET`. 
