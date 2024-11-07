# Quagmire Cipher Solver
A prototype stochastic shotgun-restarted hill climber for Vigenere, Beaufort, Quagmire I, II, III, IV ciphers (including variants.) 

This program is inspired by various explanations of Jim Gillogly's cipher solving program: 

https://groups.google.com/g/sci.crypt/c/hOCNN6L13CM/m/s85aEvsmrl0J

## Vigenere

## Beaufort

## Quagmire I
The Quagmire I cipher uses plaintext keyword, a straight ciphertext alphabet (`ABCDEFGHIJKLMNOPQRSTUVWXYZ`), and a cycleword (indicator word.) 

Here is an example where we solve a length 370 Quagmire I cipher (which we store in `cipher_quagmire_1_longer.txt`) with a length 5 plaintext keyword, and a length 7 cycleword.

```$ ./quagmire -type 1 -cipher cipher_quagmire_1_longer.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 500 -backtrackprob 0.25 -slipprob 0.0005 -plaintextkeywordlen 5 -cyclewordlen 7 -verbose```

We quickly obtain the following decryption: 

```
0.74	[sec]
66K	[it/sec]
30	[backtracks]
97	[restarts]
73	[iterations]
21	[slips]
0.00	[contradiction pct]
0.0656	[IOC]
2.8699	[entropy]
0.24	[chi-squared]
0.75	[score]
WILAMBCDEFGHJKNOPQRSTUVXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
WEBSTER
ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO
```

So the plaintext keyword was `WIL[LI]AM`, the cycleword was `WEBSTER`, and the plaintext was the text from K2. 

## Quagmire II
The Quagmire II cipher uses a straight plaintext alphabet, a ciphertext keyword, and a cycleword (indicator word). 

Similarly to the previous cipher, we can solve a Quagmire II cipher as follows:

```$ ./quagmire -type 2 -cipher cipher_quagmire_2_longer.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.25 -slipprob 0.0005 -verbose -ciphertextkeywordlen 6 -cyclewordlen 7```

```
8.27	[sec]
85K	[it/sec]
69	[backtracks]
279	[restarts]
1690	[iterations]
362	[slips]
0.00	[contradiction pct]
0.0656	[IOC]
2.8699	[entropy]
0.24	[chi-squared]
0.75	[score]
ABCDEFGHIJKLMNOPQRSTUVWXYZ
ZENIGMABCDFHJKLOPQRSTUVWXY
WEBSTER
ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO
```

In this case the ciphertext keywords was `ENIGMA` and the cycleword was `WEBSTER`. 

## Quagmire III
The Quagmire III cipher uses the same plaintext and ciphertext keywords, and a distinct cycleword. 

Here is a simple example where we solve the following length 97, Quagmire III cipher (which we store in `cipher.txt`)

```MFABBMNNQEYEZIAIABLJJEFXNWJOTNPVDIBHQNNSIMRJPZIXOEJXROJVTNPFILBBJNSNTGLDRISJZWQCSDVIFKNNMVOIXTQOP```

with the following cribs (which we store in `cribs.txt`)

```_____________________EASTNORTHEAST_____________________________BERLINCLOCK_______________________```

We use a dataset of 5-grams English letter frequencies (`english_quintgrams.txt`) and fix the (plaintext and ciphertext) keyword lengths to 7:

```$ ./quagmire -type 3 -cipher cipher.txt -crib crib.txt -ngramsize 5 -ngramfile english_quintgrams.txt -plaintextkeywordlen 7 -nsigmathreshold 1. -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 -plaintextkeywordlen 7 -cyclewordlen 7 -verbose```

After about 2 seconds we arrive at the following decryption: 

```
2.15	[sec]
358K	[it/sec]
44	[backtracks]
308	[restarts]
32	[iterations]
406	[slips]
1.00	[contradiction pct]
0.0642	[IOC]
2.7714	[entropy]
0.12	[chi-squared]
2.73	[score]
KRYPTOSABCDEFGHIJLMNQUVWXZ
KRYPTOSABCDEFGHIJLMNQUVWXZ
KOMITET
MAINTAININGAHEADINGOFEASTNORTHEASTTHIRTYTHREEDEGREESFROMTHEWESTBERLINCLOCKYOUWILLSEEFURTHERINFORM
```

So the (plaintext and ciphertext) keywords were `KRYPTOS` and the cycleword (indicator) was `KOMITET`. 

## Quagmire IV

