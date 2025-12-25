# Polyalphabetic Cipher Solver
A prototype slippery stochastic shotgun-restarted hill climber with backtracking for Vigenere, Beaufort, Porta, Quagmire I, II, III, IV ciphers (including variants.) 

This program is inspired by various explanations of Jim Gillogly's cipher solving program (that he used for solving the first three ciphers on Kryptos): 

https://groups.google.com/g/sci.crypt/c/hOCNN6L13CM/m/s85aEvsmrl0J

The effort to make this program as efficient as possible was inspired by the homophonic solver in [AZDecrypt](https://github.com/doranchak/azdecrypt). 

## Algorithmic Description of the Polyalphabetic Solver

### Stochastic Shotgun Hill Climbing Architecture
The core engine of this program is a **Shotgun Hill Climber**, a heuristic search algorithm designed to navigate the rugged energy landscapes typical of polyalphabetic substitution ciphers. Unlike brute-force methods, which are computationally infeasible for (poly-)alphabetic permutations, this approach relies on iterative improvement.

The "Shotgun" aspect refers to the initialization strategy: the solver performs $N$ distinct **Restarts**, each initializing the state with a completely random permutation of keywords and cyclewords. This prevents the solver from becoming permanently trapped in a local maximum—a common pitfall where a solution scores well relative to its neighbors but is not the true plaintext.

During each restart, the algorithm executes a specified number of **Hill Climbing Steps**. In each step, the current state (the arrangement of the alphabets and the cycleword) is mutated slightly. If the mutation results in a higher fitness score, the new state is adopted. To further mitigate local maxima, the algorithm implements **Simulated Annealing-like mechanics**, including:
* **Slipping:** A defined probability of accepting a state with a lower score to traverse "valleys" in the fitness landscape.
* **Backtracking:** A probability of reverting the current state to the absolute best state found so far, ensuring that aggressive exploration does not lose a promising solution.

### State Representation and Cipher Modeling
The program models Quagmire I–IV, Beaufort, and Vigenère ciphers by managing three distinct state components:
1.  **Plaintext Alphabet ($P_k$):** The keyed alphabet mapping plaintext letters.
2.  **Ciphertext Alphabet ($C_k$):** The keyed alphabet mapping ciphertext letters.
3.  **Cycleword (Indicator):** The vector of offsets determining the shift for each period position.

Depending on the specific `cipher_type` selected, the mutator functions constrain these alphabets. For example, in a **Quagmire III**, the program ensures $P_k$ and $C_k$ remain identical but scrambled; in **Quagmire II**, $P_k$ is fixed to the standard alphabet while $C_k$ is scrambled.

### Hybrid Deterministic Optimization (The "Optimal Cycleword" Method)
A key innovation in this implementation is the **Profile-Based Cycleword Derivation** (activated via `-optimalcycle`). Standard hill climbers attempt to stochastically guess both the alphabet structure *and* the cycleword simultaneously. This creates a search space of magnitude $26! \times 26^N$.

The hybrid approach reduces the dimensionality of the problem to just $26!$. It operates hierarchically:
1.  **Stochastic Layer:** The hill climber perturbs the **Alphabet Keywords** only.
2.  **Deterministic Layer:** For every candidate alphabet, the program performs a columnar frequency analysis. It decomposes the ciphertext into $N$ cosets (where $N$ is the period length).
3.  **Cost Minimization:** For each coset, the algorithm calculates the **Dot Product** (or Chi-squared statistic) of the decrypted column against standard English monogram frequencies for all 26 possible shifts.
4.  **State Injection:** The shift producing the highest correlation is mathematically selected as the cycleword character for that column.

This ensures that every candidate alphabet is evaluated against its *theoretical best* cycleword, smoothing the scoring gradient and preventing correct alphabets from being discarded due to cycleword misalignment.

### Scoring Function (Fitness Metric)
The fitness of a candidate state is evaluated using a weighted sum of four metrics:
1.  **N-gram Statistics (Log-Likelihood):** The primary driver of the solve. The program sums the log-probabilities of decrypted $N$-grams (typically trigrams or quadgrams) based on a corpus of English text. This penalizes unpronounceable or statistically improbable sequences.
2.  **Crib Matching:** If a known plaintext string (crib) is provided, the function checks for consistency. In strict mode, a mismatch forces a score of zero; in weighted mode, partial matches contribute to the score.
3.  **Index of Coincidence (IoC):** Used primarily for period estimation, this measures the unevenness of letter distributions (the "roughness" of the text).
4.  **Entropy:** A measure of information density, ensuring the decrypted text resembles the low-entropy characteristics of natural language rather than random noise.

## Vigenère
The Vigenère cipher is a method of encrypting alphabetic text by using a keyword to shift each letter of the plaintext. Each letter in the keyword determines the shift for the corresponding letter in the plaintext, resulting in a polyalphabetic substitution cipher that is more resistant to frequency analysis than monoalphabetic ciphers.

Here we solve a simple Vigenère cipher:

```$ ./polyalphabetic -type 0 -cipher cipher_vigenere.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 100 -backtrackprob 0.15 -slipprob 0.0005 -verbose```

```
0.00	[sec]
8K	[it/sec]
0	[backtracks]
0	[restarts]
0	[slips]
0.00	[contradiction pct]
0.0643	[IOC]
2.8469	[entropy]
0.09	[chi-squared]
11.32	[score]
ABCDEFGHIJKLMNOPQRSTUVWXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
POLYALPHABETIC

ITISATRUTHUNIVERSALLYACKNOWLEDGEDTHATASINGLEMANINPOSSESSIONOFAGOODFORTUNEMUSTBEINWANTOFAWIFEHOWEVERLITTLEKNOWNTHEFEELINGSORVIEWSOFSUCHAMANMAYBEONHISFIRSTENTERINGANEIGHBOURHOODTHISTRUTHISSOWELLFIXEDINTHEMINDSOFTHESURROUNDINGFAMILIESTHATHEISCONSIDEREDTHERIGHTFULPROPERTYOFSOMEONEOROTHEROFTHEIRDAUGHTERS
```

So the cycleword (indicator) is `POLYALPHABETIC`. 

## Beaufort
The Beaufort cipher is a polyalphabetic substitution cipher that encrypts text by pairing each letter of the plaintext with a key and performing modular subtraction. It’s similar to the Vigenère cipher but uses subtraction instead of addition, making it its own reciprocal—encryption and decryption are performed with the same process.

For example, we solve a beaufort cipher which contains the famous opening line from _Pride and Prejudice_ by Jane Austen.

```$ ./quagmire -type 5 -cipher cipher_beaufort.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 100 -backtrackprob 0.15 -slipprob 0.0005 -cyclewordlen 7 -verbose```

```
0.01	[sec]
68K	[it/sec]
0	[backtracks]
0	[restarts]
389	[iterations]
0	[slips]
0.00	[contradiction pct]
0.0643	[IOC]
2.8469	[entropy]
0.09	[chi-squared]
0.81	[score]
ABCDEFGHIJKLMNOPQRSTUVWXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
REGXYLV
ITISATRUTHUNIVERSALLYACKNOWLEDGEDTHATASINGLEMANINPOSSESSIONOFAGOODFORTUNEMUSTBEINWANTOFAWIFEHOWEVERLITTLEKNOWNTHEFEELINGSORVIEWSOFSUCHAMANMAYBEONHISFIRSTENTERINGANEIGHBOURHOODTHISTRUTHISSOWELLFIXEDINTHEMINDSOFTHESURROUNDINGFAMILIESTHATHEISCONSIDEREDTHERIGHTFULPROPERTYOFSOMEONEOROTHEROFTHEIRDAUGHTERS
```

Note, there is a small bug here where the cycleword is messed-up, but we successfully extract the plaintext nonetheless.  

## Porta

The Porta cipher is a reciprocal polyalphabetic substitution cipher. We implement the Porta cipher as defined by the ACA (https://www.cryptogram.org/downloads/aca.info/ciphers/Porta.pdf)

```
./polyalphabetic -type 6 -cipher porta_aca.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 250 -nrestarts 100 -backtrackprob 0.15 -slipprob 0.05 -cyclewordlen 11 -stochasticcycle -verbose
```

We quickly obtain the decryption:

```
0.02	[sec]
1166K	[it/sec]
12	[backtracks]
91	[restarts]
977	[slips]
0.00	[contradiction pct]
0.0650	[IOC]
2.6692	[entropy]
0.52	[chi-squared]
10.55	[score]
OPQSBCJPGEQ

BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION
```

Note that many equivalent cyclewords are possible for Porta ciphers. 

## Autokey 

Below we solve an autokey cipher (using a straight alphabet, or Vigenere tableau.) 

```
$ ./polyalphabetic -type 7 -cipher autokey_len97_wl21.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 1000 -backtrackprob 0.15 -slipprob 0.0005 -cyclewordlen 21 -verbose
```

And we obtain the solution: 

```
1.46	[sec]
545K	[it/sec]
138	[backtracks]
794	[restarts]
392	[slips]
0.00	[contradiction pct]
0.0612	[IOC]
2.8111	[entropy]
0.24	[chi-squared]
10.55	[score]
ABCDEFGHIJKLMNOPQRSTUVWXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
JAMESHERBERTSANBORNJR

CIAMARKERONTHEGROUNDSEASTNORTHEASTOFKRYPTOSDECODEUSINGSETTHEORYBERLINCLOCKTHENFOLLOWMARKERDIRECTION
```

So the primer (or indicator) is `JAMESHERBERTSANBORNJR`. 

## Quagmire I
The Quagmire I cipher uses plaintext keyword, a straight ciphertext alphabet (`ABCDEFGHIJKLMNOPQRSTUVWXYZ`), and a cycleword (indicator word.) 

For example, we solve a length 370 Quagmire I cipher (which we store in `cipher_quagmire_1_longer.txt`) with a length 5 plaintext keyword, and a length 7 cycleword.

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

In the following example we solve K2: 

```
3.86	[sec]
19K	[it/sec]
6	[backtracks]
29	[restarts]
37	[slips]
0.00	[contradiction pct]
0.0656	[IOC]
2.8699	[entropy]
0.24	[chi-squared]
10.48	[score]
KRYPTOSABCDEFGHIJLMNQUVWXZ
KRYPTOSABCDEFGHIJLMNQUVWXZ
ABSCISSA

ABCDEFGHIJLMNQUVWXZKRYPTOS
BCDEFGHIJLMNQUVWXZKRYPTOSA
SABCDEFGHIJLMNQUVWXZKRYPTO
CDEFGHIJLMNQUVWXZKRYPTOSAB
IJLMNQUVWXZKRYPTOSABCDEFGH
SABCDEFGHIJLMNQUVWXZKRYPTO
SABCDEFGHIJLMNQUVWXZKRYPTO
ABCDEFGHIJLMNQUVWXZKRYPTOS

ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO
```

## Quagmire IV

Quagmire IV ciphers use a plaintext keyword, a ciphertext keyword, and a cycleword. They are, at least for this program, significantly harder to solve than other Quagmire ciphers (especially in the absence of any cribs.)

Here we solve a relatively easy Quagmire IV cipher, with a plaintext keyword of length 7, a ciphertext keyword of length 3, and a cycleword of length 3. 

```$ ./quagmire -type 4 -cipher cipher_quagmire_4_easier.txt -crib crib.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.25 -slipprob 0.0005 -verbose -plaintextkeywordlen 7 -ciphertextkeywordlen 3 -cyclewordlen 3```

```
15.81	[sec]
408K	[it/sec]
663	[backtracks]
2578	[restarts]
1194	[iterations]
3185	[slips]
1.00	[contradiction pct]
0.0642	[IOC]
2.7714	[entropy]
0.27	[chi-squared]
0.90	[score]
LRYPTOSABCDEFGHIJKMNQUVWXZ
ZCIABDEFGHJKLMNOPQRSTUVWXY
USA
MAINTAININGAHEADINGOFEASTNORTHEASTTHIRTYTHREEDEGREESFROMTHEWESTBERKINCKOCLYOUWIKKSEEFURTHERINFORM
```

The keywords are `KRYPTOS`, `CIA`, and `USA`. 

The following cipher is significantly harder for this program to solve: 

```$ ./quagmire -type 4 -cipher cipher_quagmire_4_longer.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 5000 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 -maxcyclewordlen 12 -plaintextkeywordlen 5 -ciphertextkeywordlen 6 -cyclewordlen 6 -verbose```

After around 5 minutes we get the following partial solution (keywords should be `WIL[L]IAM`, `WEBST[E]R`, and `ENIGMA`): 

```
261.06	[sec]
81K	[it/sec]
597	[backtracks]
4195	[restarts]
679	[iterations]
10555	[slips]
0.00	[contradiction pct]
0.0632	[IOC]
2.9092	[entropy]
1.45	[chi-squared]
0.52	[score]

ILAMBCDEFGHJKNOPQRSTUVWXYZ
WECSTRABDFGHIJKLMNOPQUVXYZ
COJHNB

CSTRABDFGHIJKLMNOPQUVXYZWE
KLMNOPQUVXYZWECSTRABDFGHIJ
FGHIJKLMNOPQUVXYZWECSTRABD
BDFGHIJKLMNOPQUVXYZWECSTRA
JKLMNOPQUVXYZWECSTRABDFGHI
ECSTRABDFGHIJKLMNOPQUVXYZW

CTZASTOTALLXCNVISVBLEHOZSTHATPOSSIBLETHEXUSEDTHEEARTHSMAGNETCCFIELDWTHEVNFOWMATIONZASGATHEREDANDTRANSMCTTEDUNDEWGRUUNDTOANPNKNOZNLOCATIONWDOESLANGLEXKNOZABOUTTHISTPEXSHOULDITSBPWIEDOPTTHERESOMEZHEREWZHOKNOZSTHEEWACTLOCATIONONLXZZTHISZASHISLASTMESSAGEWTHIRTXECGHTDEGREESFCFTXSEVENMINUTESSVWHOINTFIVESEIONDSNORTHSEVENTXSEVENDEGREESECGHTMVNUTESFORTXFOURSECONDSZESTWLAXERTZO
```

Re-running `quagmire` on this cipher highlighted the stochastic nature of this program, and we obtained a much better solution is half the compute time: 

```
197.75	[sec]
71K	[it/sec]
406	[backtracks]
2798	[restarts]
1856	[iterations]
6872	[slips]
0.00	[contradiction pct]
0.0656	[IOC]
2.8699	[entropy]
0.24	[chi-squared]
0.75	[score]
WILAMBCDEFGHJKNOPQRSTUVXYZ
WEBSTRACDFGHIJKLMNOPQUVXYZ
ENIGMA

TRACDFGHIJKLMNOPQUVXYZWEBS
JKLMNOPQUVXYZWEBSTRACDFGHI
DFGHIJKLMNOPQUVXYZWEBSTRAC
ACDFGHIJKLMNOPQUVXYZWEBSTR
IJKLMNOPQUVXYZWEBSTRACDFGH
WEBSTRACDFGHIJKLMNOPQUVXYZ

ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO
```


## Variants
We can solve Quagmire-type variant ciphers (where the encryption and decryption steps are swapped.) For example, we use the `-variant` flag to solve a variant Quagmire-3 cipher: 

```$ ./quagmire -type 3 -variant -cipher cipher_variant.txt -crib crib.txt -ngramsize 5 -ngramfile english_quintgrams.txt -keywordlen 7 -cyclewordlen 7 -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 -verbose```

```
19.34	[sec]
368K	[it/sec]
453	[backtracks]
2837	[restarts]
998	[iterations]
3531	[slips]
1.00	[contradiction pct]
0.0642	[IOC]
2.7714	[entropy]
0.12	[chi-squared]
1.00	[score]
KRYPTOSABCDEFGHIJLMNQUVWXZ
KRYPTOSABCDEFGHIJLMNQUVWXZ
KOMITET
MAINTAININGAHEADINGOFEASTNORTHEASTTHIRTYTHREEDEGREESFROMTHEWESTBERLINCLOCKYOUWILLSEEFURTHERINFORM
```

## Indicator keys
We can solve Quagmire-type ciphers when the indicator key is not under the first letter of the plaintext keyword. In the following example, the cycleword is `FLOWER`. You need to do your own search for the cycleword, as we do not use a dictionary search for any of the keywords. 

```$ ./quagmire -type 1 -cipher cipher_quagmire_1_indicator.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 2500 -nrestarts 10000 -backtrackprob 0.15 -slipprob 0.0005 -plaintextkeywordlen 6 -cyclewordlen 6 -verbose```

```
8.89	[sec]
72K	[it/sec]
34	[backtracks]
247	[restarts]
2024	[iterations]
321	[slips]
0.00	[contradiction pct]
0.0656	[IOC]
2.8699	[entropy]
0.26	[chi-squared]
0.73	[score]
SQRINGABCDEFHJKLMOPTUVWXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
YEHPXK

ABCDEFGHIJKLMNOPQRSTUVWXYZ
GHIJKLMNOPQRSTUVWXYZABCDEF
JKLMNOPQRSTUVWXYZABCDEFGHI
RSTUVWXYZABCDEFGHIJKLMNOPQ
ZABCDEFGHIJKLMNOPQRSTUVWXY
MNOPQRSTUVWXYZABCDEFGHIJKL

ITWASTOTALLYINVISIBLEHOWSTHATQOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXQOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO
```

## Known and unknown key lengths
If you know the key lengths for the ciphertext keyword, the plaintext keyword, or the cycleword (indicator) keyword, then you can set them manually via:

- `-plaintextkeywordlen /positive integer/`
- `-plaintextkeywordlen /positive integer/`
- `-cyclewordlen /positive integer/` 

Otherwise, for any unspecified keyword length, `quagmire` will search through keyword lengths up to `-maxkeywordlen` and it will estimate which cycleword lengths to test based on periodic index of coincidence statistics. (TODO: explain this in more detail with examples.)
