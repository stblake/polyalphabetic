# Colossus — a Classical Cipher Solver
A prototype slippery stochastic shotgun-restarted hill climber with backtracking for a wide range of classical ciphers. It attacks the **polyalphabetic** family — Vigenère, Gronsfeld, Beaufort, Porta, Quagmire I, II, III, IV, and Autokey (including variants and the Beaufort/Porta autokey tableaus) — together with **monographic and polygraphic substitution** ciphers (homophonic substitution, Playfair, Bifid, Trifid, Hill, and Phillips) and a portfolio of **pure transposition** ciphers (matrix/route/columnar/rail-fence/AMSCO/Myszkowski/Redefence/Cadenus/Nihilist/Swagman/turning-grille), optionally composed with a transposition stage.

Cipher conventions follow the [American Cryptogram Association](https://www.cryptogram.org/resource-area/cipher-types/). The solver exists to crack the Kryptos sculpture's K1–K4.

This program is inspired by various explanations of Jim Gillogly's cipher solving program (that he used for solving the first three ciphers on Kryptos): 

https://groups.google.com/g/sci.crypt/c/hOCNN6L13CM/m/s85aEvsmrl0J

The effort to make this program as efficient as possible was inspired by the homophonic solver in [AZDecrypt](https://github.com/doranchak/azdecrypt). 

## Algorithmic Description of the Colossus Solver

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

```$ ./colossus -type vig -cipher cipher_vigenere.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 100 -backtrackprob 0.15 -slipprob 0.0005 -verbose```

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

```$ ./colossus -type beaufort -cipher cipher_beaufort.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 100 -backtrackprob 0.15 -slipprob 0.0005 -cyclewordlen 7 -verbose```

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
./colossus -type porta -cipher porta_aca.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 250 -nrestarts 100 -backtrackprob 0.15 -slipprob 0.05 -cyclewordlen 11 -stochasticcycle -verbose
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

## Gronsfeld

The Gronsfeld cipher is a Vigenère cipher with a **numeric key**: each column shift is a digit `0–9` (`C = P + d`, `P = C − d`, mod 26), so it is exactly Vigenère restricted to the ten smallest shifts. Colossus solves it through the same polyalphabetic pipeline as Vigenère (IoC period estimation + the deterministic optimal-cycleword frequency attack), but with the cycleword/shift domain **bounded to `0–9`**. That digit bound is a strong prior, so recovery is faster and reliable from shorter text than an unconstrained Vigenère solve, and the default reward-only quadgram table suffices (no `-logprob` needed).

```bash
$ ./colossus -type gron -cipher cipher_gronsfeld.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nrestarts 200 -nhillclimbs 500 -verbose
```

```
0.00	[sec]
...
ABCDEFGHIJKLMNOPQRSTUVWXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
DBEBFJCG
...
key (numeric): 31415926
ITISATRUTHUNIVERSALLYACKNOWLEDGEDTHATASINGLEMANINPOSSESSIONOFAGOODFORTUNEMUSTBEINWANTOFAWIFEHOWEVER...
```

The report prints the recovered key both as a keyed-alphabet row (`DBEBFJCG`) and as digits (`31415926`). Test ciphers can be minted with the standalone generator (`make gronsfeld_gen`, then `./tools/gronsfeld_gen plaintext.txt 31415926 > cipher.txt`).

## Autokey 

Below we solve an autokey cipher (using a straight alphabet, or Vigenere tableau.) 

```
$ ./colossus -type autokey -cipher autokey_len97_wl21.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 1000 -backtrackprob 0.15 -slipprob 0.0005 -cyclewordlen 21 -verbose
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

We can also solve Autokey ciphers that use a Beaufort tableau (with `-type autobeau`): 

```
./colossus -type autobeau -cipher cipher_autokey_beaufort.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 --cyclewordlen 7 -verbose
```

And almost instantly we get the following solution:

```
0.01	[sec]
415K	[it/sec]
0	[backtracks]
4	[restarts]
2	[slips]
0.00	[contradiction pct]
0.0599	[IOC]
2.8191	[entropy]
0.25	[chi-squared]
10.58	[score]
ABCDEFGHIJKLMNOPQRSTUVWXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
GIRASOL

CIAMARKERONTHEGROUNDEASTNORTHEASTOFKRYPTOSDECODEUSINGSETTHEORYBERLINCLOCKANDFOLLOWMARKERDIRECTION
```

Similarly, we can solve an autokey cipher that uses a Porta tableau (with `-type autoporta`)

```
0.00	[sec]
399K	[it/sec]
0	[backtracks]
1	[restarts]
1	[slips]
0.00	[contradiction pct]
0.0601	[IOC]
2.8170	[entropy]
0.25	[chi-squared]
10.60	[score]
ABCDEFGHIJKLMNOPQRSTUVWXYZ
ABCDEFGHIJKLMNOPQRSTUVWXYZ
EIRATOL

DIAMARKERONTHEGROUNDEASTNORTHEASTOFKRYPTOSDECODEUSINGSETTHEORYBERLINCLOCKANDFOLLOWMARKERDIRECTION
```

We get out the solution, and the primer word is close to the correct primer `GIRASOL`. 

Solving autokey ciphers that use a Quagmire I-IV tableau are much harder to solve as the multidimensional search space is rugged. If we can guess the key for the keyed alphabet, then we can solve these ciphers as quickly as we did previously for the Vigenere, Beaufort, and Porta tableau - encrypted autokey ciphers. For example, the following is an autokey cipher that uses a Quagmire III tableau. We have guessed the key for the keyed alphabet is KRYPTOS. 

```
./colossus -type auto3 -cipher cipher_autokey_quag3.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 1000 -backtrackprob 0.15 -slipprob 0.0005 -verbose -cyclewordlen 7 -plaintextkeyword KRYPTOS
```

```
0.01	[sec]
353K	[it/sec]
0	[backtracks]
3	[restarts]
0	[slips]
0.00	[contradiction pct]
0.0599	[IOC]
2.8191	[entropy]
0.25	[chi-squared]
10.58	[score]
KRYPTOSABCDEFGHIJLMNQUVWXZ
KRYPTOSABCDEFGHIJLMNQUVWXZ
GIRASOL

CIAMARKERONTHEGROUNDEASTNORTHEASTOFKRYPTOSDECODEUSINGSETTHEORYBERLINCLOCKANDFOLLOWMARKERDIRECTION
```

## Quagmire I
The Quagmire I cipher uses plaintext keyword, a straight ciphertext alphabet (`ABCDEFGHIJKLMNOPQRSTUVWXYZ`), and a cycleword (indicator word.) 

For example, we solve a length 370 Quagmire I cipher (which we store in `cipher_quagmire_1_longer.txt`) with a length 5 plaintext keyword, and a length 7 cycleword.

```$ ./colossus -type quag1 -cipher cipher_quagmire_1_longer.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 500 -nrestarts 500 -backtrackprob 0.25 -slipprob 0.0005 -plaintextkeywordlen 5 -cyclewordlen 7 -verbose```

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

```$ ./colossus -type quag2 -cipher cipher_quagmire_2_longer.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.25 -slipprob 0.0005 -verbose -ciphertextkeywordlen 6 -cyclewordlen 7```

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

```$ ./colossus -type quag3 -cipher cipher.txt -crib crib.txt -ngramsize 5 -ngramfile english_quintgrams.txt -plaintextkeywordlen 7 -nsigmathreshold 1. -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 -plaintextkeywordlen 7 -cyclewordlen 7 -verbose```

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

```$ ./colossus -type quag4 -cipher cipher_quagmire_4_easier.txt -crib crib.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.25 -slipprob 0.0005 -verbose -plaintextkeywordlen 7 -ciphertextkeywordlen 3 -cyclewordlen 3```

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

```$ ./colossus -type quag4 -cipher cipher_quagmire_4_longer.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 5000 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 -maxcyclewordlen 12 -plaintextkeywordlen 5 -ciphertextkeywordlen 6 -cyclewordlen 6 -verbose```

After around a minutes we get the following solution (keywords should be `WIL[L]IAM`, `WEBST[E]R`, and `ENIGMA`): 

```
43.57	[sec]
19K	[it/sec]
30	[backtracks]
169	[restarts]
414	[slips]
0.00	[contradiction pct]
0.0656	[IOC]
2.8699	[entropy]
0.24	[chi-squared]
10.48	[score]
WILAMBCDEFGHJKNOPQRSTUVXYZ
WEBSTRACDFGHIJKLMNOPQUVXYZ
ENIGMA

EBSTRACDFGHIJKLMNOPQUVXYZW
NOPQUVXYZWEBSTRACDFGHIJKLM
IJKLMNOPQUVXYZWEBSTRACDFGH
GHIJKLMNOPQUVXYZWEBSTRACDF
MNOPQUVXYZWEBSTRACDFGHIJKL
ACDFGHIJKLMNOPQUVXYZWEBSTR

ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO
```

## Variants
We can solve Quagmire-type variant ciphers (where the encryption and decryption steps are swapped.) For example, we use the `-variant` flag to solve a variant Quagmire-3 cipher: 

```$ ./colossus -type quag3 -variant -cipher cipher_variant.txt -crib crib.txt -ngramsize 5 -ngramfile english_quintgrams.txt -keywordlen 7 -cyclewordlen 7 -nhillclimbs 2500 -nrestarts 15000 -backtrackprob 0.15 -slipprob 0.0005 -verbose```

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

```$ ./colossus -type quag1 -cipher cipher_quagmire_1_indicator.txt -ngramsize 5 -ngramfile english_quintgrams.txt -nhillclimbs 2500 -nrestarts 10000 -backtrackprob 0.15 -slipprob 0.0005 -plaintextkeywordlen 6 -cyclewordlen 6 -verbose```

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

## Homophonic substitution

A homophonic substitution cipher uses a **ciphertext alphabet larger than the plaintext alphabet**: each plaintext letter is enciphered by any of several distinct ciphertext symbols (its *homophones*), chosen to flatten the ciphertext frequency profile (the Zodiac-408 cipher is the classic example). Colossus reads such ciphertexts as **comma-separated symbol tokens** (or, with `-delimiter`, any other separator; or one symbol per character), so the ciphertext alphabet is not limited to A–Z:

```
$ ./colossus -type homophonic -cipher homophonic_test.txt -ngramsize 5 -ngramfile english_quintgrams.txt -logprob -nrestarts 60 -nhillclimbs 2500 -backtrackprob 0.15 -slipprob 0.0005 -verbose
```

where `homophonic_test.txt` is e.g. `57,22,16,44,58,27,...`. The solver is a `CipherModel` plugged into the same slippery-shotgun / simulated-annealing engine as every other type. Its state is the many-to-one map `symbol → plaintext letter`; it hill-climbs that map with a **greedy coordinate move** (best letter for one symbol) plus a **letter-class swap** (exchange the homophone classes of two letters), and adds a **monogram chi-squared penalty** (`-weightmono`, default 1.0) that stops the map collapsing many symbols onto a few common letters — the failure mode that lets a wrong map out-score the truth on raw n-grams alone.

Because a homophonic map has far more degrees of freedom than a 26→26 substitution, **higher-order n-grams matter**: with quadgrams the solver typically recovers ~98% of a few-hundred-symbol cipher, and with quintgrams (`-ngramsize 5 -ngramfile english_quintgrams.txt`) it reaches ~100%. The `-logprob` flag selects an AZDecrypt-style n-gram fitness — log-probabilities with a floor that *penalises* implausible (unseen) n-grams rather than merely not rewarding them — which is cipher-agnostic and can be used on any cipher type, but is most useful here and with high-order n-grams.

Test ciphers can be minted with the standalone generator (`make homophonic_gen`, then `./tools/homophonic_gen plaintext.txt 60 1 > cipher.txt 2> solution.txt`).

## Playfair

The **Playfair** cipher is a digraphic substitution over a **5×5 keyed grid** of 25 letters (J merged into I, the ACA convention). Plaintext is split into letter pairs and each pair is enciphered by the rectangle/row/column rule on the grid. Colossus forces a 25-letter alphabet for `-type playfair`, so the n-gram table is built over the same 25 letters; the only unknown is the grid, carried as a permutation of `0..24`.

The attack is the classic simulated-annealing Playfair break: a hill climb / anneal over the grid with n-gram fitness, the move set a dominant **single-cell swap** plus **row/column swaps** and **grid reflections** (the larger moves escape the local optima a cell swap cannot). Cyclic row/column *rotations* are deliberately excluded — they re-encipher identically, so the recovered grid is unique only up to such a rotation, though the recovered plaintext is unique.

```bash
$ ./colossus -type playfair -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt -logprob -nrestarts 6 -nhillclimbs 400000 -inittemp 0.08 -backtrackprob 0.3
```

```
Result Score: -4.50 | Words: 0 | grid=OSABCDEFGHILMNQUVWXZKRYPT
...
recovered 5x5 grid (row major):
    O S A B C
    D E F G H
    I L M N Q
    U V W X Z
    K R Y P T
```

Playfair is genuinely near the limit of a quadgram attack: `-logprob` (AZDecrypt-style fitness, which *penalises* implausible n-grams) is effectively required, recovery is reliable from roughly 600 characters upward, and falls off a cliff below a few hundred. Annealing is the default and far stronger than `-method shotgun` here. Per-type search defaults (`6×400000`, `inittemp 0.08`, `backtrack 0.30`) are compiled in, so the budget flags above can be omitted. Test ciphers can be minted with the standalone generator (`make playfair_gen`, then `./tools/playfair_gen plaintext.txt KEYWORD > cipher.txt 2> solution.txt`).

## Bifid

The **bifid** cipher (Félix Delastelle) combines a Polybius-square substitution with a transposition by *fractionation*. Each plaintext letter is replaced by its (row, column) coordinates in a 5×5 keyed square (J merged into I, the ACA convention); the message is processed in blocks of a fixed **period**. Within a block the row coordinates are written out first and the column coordinates second, forming one coordinate stream, which is then re-paired consecutively and read back through the square to give the ciphertext. The fractionation smears each plaintext letter across two ciphertext letters, so a bifid resists the digraph attack that breaks Playfair.

```bash
$ ./colossus -type bifid -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt -logprob -verbose
```

Breaking it is two coupled problems. The **period** is recovered first, by an index-of-coincidence test: for the true period every within-block ciphertext position is built from one coordinate class (row-row or column-column letters) and so shares a single, mildly non-uniform distribution, which raises the columnar IoC at that period above the background. (The IoC also rises at *multiples* of the true period, so Colossus does not trust the single top peak — it anneals the top `-nperiods` candidates, default 5, as independent searches and lets the n-gram score discard the wrong periods, which decrypt to gibberish.) The **square** is then recovered exactly as in the Playfair attack: a simulated-annealing hill climb over the 25-cell key square with an n-gram fitness, the move set a dominant single-cell swap plus row/column swaps and grid reflections. Pin a known period with `-period N`, or bound the estimator's scan with `-maxperiod` (default `min(20, len/2)`).

Like Playfair, bifid is near the limit of a quadgram attack, so `-logprob` is effectively required; recovery is reliable from roughly 350 characters upward and falls off below that. The primitives are written generically over the square side, so a 6×6 (36-cell) square is supported once a 36-letter alphabet is active. Test ciphers can be minted with the standalone generator (`make bifid_gen`, then `./tools/bifid_gen plaintext.txt KEYWORD 7 > cipher.txt 2> solution.txt`).

## Trifid

The **trifid** cipher lifts bifid into **three dimensions**: each letter splits into (layer, row, column) coordinates over a **keyed 3×3×3 cube**, the block's layers-then-rows-then-columns coordinate stream is regrouped into consecutive triples that index new cube cells, and the block size is the **period**. A 3×3×3 cube has **27 cells**, one more than the 26-letter alphabet, so trifid runs on a **27-symbol alphabet — A–Z plus a 27th symbol `+`**.

```bash
$ ./colossus -type trifid -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt -logprob -period 7 -nrestarts 6 -nhillclimbs 300000 -inittemp 0.08 -backtrackprob 0.3
```

```
Result Score: -4.26 | Words: 0 | period=7 | cube=KYRSBAPOTMQNX+ZUWVCEDILJFHG
...
recovered 3x3x3 cube (cell major):
    layer 1:      layer 2:      layer 3:
      K Y R         M Q N         C E D
      S B A         X + Z         I L J
      P O T         U W V         F H G
```

The cube attack is the same anneal as bifid/Playfair (cell-swap-dominated plus structured plane-swap/reflection moves along the cube's three axes), and the period is recovered exactly as bifid's (top-`-nperiods` candidates annealed, the n-gram score picking the winner). Like bifid it effectively needs `-logprob`, but because three coordinates carry more signal it wants a little more text — recovery is reliable from roughly 450 characters upward. Pin a known period with `-period N`. Test ciphers can be minted with the standalone generator (`make trifid_gen`, then `./tools/trifid_gen plaintext.txt KEYWORD 7 > cipher.txt 2> solution.txt`).

## Hill

The **Hill** cipher is a **polygraphic substitution**: a block of `k` plaintext letters (a column vector) is multiplied by a `k×k` key matrix **mod 26**, so it runs on the **full 26-letter alphabet unchanged**. Colossus carries the *decryption* matrix `D` as its state (`plain = D·cipher mod 26`), hill-climbs it directly, and inverts it only at report time to display the recovered encryption key. The block size `k` has no IoC-style estimator, so the solver simply **sweeps `k = 2..5`** (one config each; `-period` pins one) and lets the n-gram score pick the winner.

```bash
$ ./colossus -type hill -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt -logprob -period 2 -nrestarts 20 -nhillclimbs 40000 -inittemp 0.10 -backtrackprob 0.25
```

```
Result Score: -4.10 | Words: 0 | k=2 | decrypt-matrix=ZWBX | encrypt-key=HILL
...
recovered 2x2 decryption matrix (row major, mod 26):
    25 22
     1 23
encryption key = (decryption matrix)^-1 mod 26:
     7  8
    11 11
```

The attack is a matrix anneal: mostly change one element to a different random value (the fine move), occasionally randomise a whole row, rarely add a random multiple of one row to another (a coarse jump). **A singular decryption matrix (determinant not coprime to 26) is penalised** — unlike Playfair/Bifid/Trifid a Hill matrix is a bijection only when invertible, and a singular one collapses the ciphertext onto a repetitive low-entropy string that would otherwise out-score real plaintext on n-grams. The search lever is **restarts, not iterations** (the matrices are small and the climbs converge fast), so the schedule favours many short restarts. Like the other near-the-limit types it effectively needs `-logprob`; `k=2` and `k=3` are reliably breakable ciphertext-only, `k≥4` is exercised only by the primitive round-trip tests. Test ciphers can be minted with the standalone generator (`make hill_gen`, then `./tools/hill_gen plaintext.txt KEYWORD 2 > cipher.txt 2> solution.txt`; the keyword seeds the `k×k` matrix).

## Phillips

The **Phillips** cipher is a **periodic monographic substitution over 8 keyed Polybius squares** derived from a single base 5×5 square. Plaintext is split into blocks of 5 letters; block `b` is enciphered with square `(b mod 8)`, each letter mapped to the one diagonally down-right with wrap, so the overall period is 40. The 8 squares are derived from the base by a fixed row-reinsertion table. Like Playfair/Bifid it runs on the 25-letter (J→I) grid, and the only unknown is the base square.

```bash
$ ./colossus -type phillips -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt -logprob -nrestarts 4 -nhillclimbs 200000 -inittemp 0.08 -backtrackprob 0.3
```

```
Result Score: -4.26 | Words: 0 | variant=row | grid=PHILSDAGONBCEFKMQRTUVWXYZ
...
recovered 5x5 grid (row major):
    P H I L S
    D A G O N
    B C E F K
    M Q R T U
    V W X Y Z
```

Because the only unknown is that base square, the attack is **identical to Playfair's** (cell-swap-dominated anneal + row/column swaps and reflections) — but *monographic* (no digraph prep) and with **no period to estimate** (block size 5 and the 8-square cycle are fixed). Carrying more signal per character than digraphic Playfair, it recovers reliably from only **~200 characters**. Three variants choose how the 8 squares are built, all sharing the solver: `phillips` (the ACA-standard **Row** type), `phillips-c` (**Column**), and `phillips-rc` (**Row-Column**). Like the other square types it effectively needs `-logprob`. Test ciphers can be minted with the standalone generator (`make phillips_gen`, then `./tools/phillips_gen plaintext.txt KEYWORD row > cipher.txt 2> solution.txt`; the variant arg is `row`/`col`/`rowcol`).

## Transposition ciphers

Colossus also solves a portfolio of **pure transposition** ciphers, which rearrange the plaintext letters rather than substituting them. These bypass the keyword/cycleword/period machinery entirely and are solved by optimisation: the shotgun/slip hill climber searches the transposition's own parameter space (a small parameter vector, a column-order permutation, or a full permutation key, depending on the type) under the same n-gram scoring. Cipher and plaintext have the same letter histogram, so the n-gram score alone separates a correct rearrangement from a wrong one.

| `-type` | cipher | what is searched |
| --- | --- | --- |
| `transmatrix` | K3-style double-rotation matrix | the transform's `w1,w2,direction` |
| `transperoffset` | periodic decimation | period `d`, offset `n` |
| `transposition` | general (any permutation) | the full permutation key, columnar-seeded, with an anti-gaming structure term |
| `transcol` / `transcol2` | single / double **columnar** | the per-stage column-order permutation(s) |
| `railfence` | rail-fence / zigzag | rail count (+ offset) |
| `route` | route transposition | grid shape + route path |
| `amsco` | AMSCO (1–2 letters per cell) | column order |
| `myszkowski` | Myszkowski (repeated key letters) | the keyed column order |
| `redefence` | Redefence (keyed rail-fence) | rail count + key |
| `cadenus` | Cadenus | column order + per-column rotation |
| `nihilist` | Nihilist transposition | row/column permutation |
| `swagman` | Swagman | the Latin-square key |
| `grille` | turning grille | the grille holes |

For example, a single columnar transposition:

```bash
$ ./colossus -type transcol -cipher cipher.txt -ngramsize 4 -ngramfile english_quadgrams.txt -nrestarts 40 -nhillclimbs 8000
```

```
Result Score: 3.36 | Words: 0
ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESS...
stage 1 (K=9, dir=tb) order: 5 6 7 4 3 0 8 1 2
```

The dedicated columnar solver (`transcol`/`transcol2`) optimises only the small column-order permutation: single columnar sweeps the column count over `-mincols..-maxcols` (default 2..30), double randomises `(K1,K2)` per restart and anneals both keys, and read direction is opt-in via `-readdir tb|bt|both` (default `tb`). The general `transposition` solver instead hill-climbs the **full permutation key** and adds a periodic-redundancy **structure term** (`-weightstructure`, default 4) so the climb can't game the n-gram score with a non-columnar layout. The rail-fence, route, AMSCO, Myszkowski, Redefence, Cadenus, Nihilist, Swagman, and turning-grille types each have their own dedicated solver over that cipher's natural key space. All are stochastic — run more restarts/iterations for harder ciphers.

Note these `-type` values (a transposition cipher solved on its own) are distinct from the `-transmatrix`/`-transperoffset` **post-decrypt stage** flags, which apply a fixed, user-supplied transposition after a polyalphabetic solve.
