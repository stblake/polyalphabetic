#!/bin/bash
#
# run_tests.sh — accuracy regression suite for the colossus solver.
#
# Each test in the manifest below is solved with a FIXED -seed (so a given build
# is fully reproducible), the recovered plaintext is pulled from the last field
# of the solver's ">>> ..." CSV summary line, and compared character-for-character
# against a sibling ".solution" file (bare A-Z plaintext). Per-test and overall
# accuracy are reported; the suite exits non-zero if any test drops below the
# pass threshold, so a refactor that quietly degrades the solver is caught fast.
#
# Usage:
#   ./run_tests.sh                 # run every test (fast + slow)
#   ./run_tests.sh --fast          # only the fast tier (a few seconds; use while iterating)
#   ./run_tests.sh --slow          # only the slow tier (the heavier ciphers)
#   ./run_tests.sh -v              # also print the recovered text on failure
#   ./run_tests.sh vigenere q3     # run only tests whose name matches a filter
#   ./run_tests.sh --generate      # (re)create .solution files from current output
#   THRESHOLD=95 ./run_tests.sh    # override pass threshold (percent, default 99)
#   SEED=7 ./run_tests.sh          # override the fixed RNG seed for all tests
#
# Adding a test: append a "name|type|cipher|extra-args" line to the manifest, then
# run "./run_tests.sh --generate <name>" to mint name.solution from a verified
# solve. ONLY generate a .solution once you've confirmed the recovered text is
# correct — generation bakes the current output in as the regression baseline.

cd "$(dirname "$0")" || exit 2
BIN=../../colossus
NGRAMS=../../english_quadgrams.txt
NG="-ngramsize 4 -ngramfile $NGRAMS"
COMMON="-backtrackprob 0.15 -slipprob 0.0005"
SEED=${SEED:-1}
THRESHOLD=${THRESHOLD:-99}
VERBOSE=0
TIER=all

[ -x "$BIN" ] || { echo "error: $BIN not built (run 'make' in the repo root)"; exit 2; }
[ -f "$NGRAMS" ] || { echo "error: $NGRAMS not found"; exit 2; }

GENERATE=0
filters=()
for a in "$@"; do
    case "$a" in
        -v) VERBOSE=1 ;;
        --generate|-g) GENERATE=1 ;;
        --fast) TIER=fast ;;
        --slow) TIER=slow ;;
        --all)  TIER=all ;;
        *)  filters+=("$a") ;;
    esac
done

# Pull the recovered plaintext (last comma-separated field of the ">>>" summary).
recovered_plaintext() { grep '^>>> ' | tail -1 | awk -F', ' '{print $NF}'; }

# Character accuracy of $1 (recovered) against $2 (expected), as a percentage of
# the expected length. Mismatched lengths count every excess/missing char wrong.
accuracy() {
    awk -v r="$1" -v s="$2" 'BEGIN {
        n = length(s); if (n == 0) { print "0.0"; exit }
        m = 0;
        for (i = 1; i <= n; i++) if (substr(r, i, 1) == substr(s, i, 1)) m++;
        printf "%.1f", 100.0 * m / n;
    }'
}

# --- Manifest -------------------------------------------------------------------
# tier | name | type | cipher-file | extra solver args
#
# tier is "fast" (a few seconds; the default-iteration set) or "slow" (the heavier
# ciphers). Every entry recovers its plaintext to 100% with seed=1 and quadgrams;
# budgets were trimmed to the smallest that still lands on the solution at this seed
# (with headroom), so the whole suite runs in ~2 min instead of ~45. The seed makes
# the search reproducible — a bit-identical refactor stays green; a behavioural
# regression drops accuracy. (Times below are indicative wall-clock on the author's box.)
read -r -d '' MANIFEST <<'EOF'
# --- substitution: straight alphabets ---
fast | cipher_vigenere       | vig  | cipher_vigenere.txt  | -nrestarts 200 -nhillclimbs 500
fast | cipher_beaufort       | beau | cipher_beaufort.txt  | -nrestarts 600 -nhillclimbs 1500
fast | porta_aca             | porta| porta_aca.txt        | -cyclewordlen 11 -stochasticcycle -nrestarts 400 -nhillclimbs 800
fast | porta_aca_longer      | porta| porta_aca_longer.txt | -maxcyclewordlen 15 -stochasticcycle -nrestarts 500 -nhillclimbs 800
fast | cipher_gronsfeld      | gron | cipher_gronsfeld.txt | -nrestarts 200 -nhillclimbs 500
# --- Quagmire I-IV (Kryptos K2 plaintext) ---
fast | cipher_quagmire_1_longer | q1 | cipher_quagmire_1_longer.txt | -plaintextkeywordlen 5 -cyclewordlen 7 -nrestarts 300 -nhillclimbs 1500
fast | cipher_quagmire_2_longer | q2 | cipher_quagmire_2_longer.txt | -ciphertextkeywordlen 6 -cyclewordlen 7 -nrestarts 300 -nhillclimbs 1500
fast | cipher_quagmire_3_longer | q3 | cipher_quagmire_3_longer.txt | -plaintextkeywordlen 5 -ciphertextkeywordlen 5 -cyclewordlen 7 -nrestarts 300 -nhillclimbs 1500
slow | cipher_quagmire_4_longer | q4 | cipher_quagmire_4_longer.txt | -plaintextkeywordlen 5 -ciphertextkeywordlen 6 -cyclewordlen 6 -maxcyclewordlen 12 -nrestarts 800 -nhillclimbs 2000
# --- Quagmire ACA puzzles (p125-p131) ---
slow | q2_p125_1 | q2 | q2_p125_1.txt | -plaintextkeywordlen 5 -ciphertextkeywordlen 5 -nrestarts 300 -nhillclimbs 1500
slow | q2_p125_2 | q2 | q2_p125_2.txt | -plaintextkeywordlen 6 -ciphertextkeywordlen 6 -nrestarts 300 -nhillclimbs 1500
fast | q3_p127   | q3 | q3_p127.txt   | -plaintextkeywordlen 8 -ciphertextkeywordlen 8 -cyclewordlen 8 -nrestarts 300 -nhillclimbs 2000
fast | q3_p128   | q3 | q3_p128.txt   | -plaintextkeywordlen 5 -ciphertextkeywordlen 5 -cyclewordlen 5 -nrestarts 200 -nhillclimbs 1000
slow | q4_p130   | q4 | q4_p130.txt   | -plaintextkeywordlen 4 -ciphertextkeywordlen 7 -cyclewordlen 5 -nrestarts 800 -nhillclimbs 3000
slow | q4_p131   | q4 | q4_p131.txt   | -plaintextkeywordlen 5 -ciphertextkeywordlen 5 -cyclewordlen 5 -nrestarts 800 -nhillclimbs 3000
# --- autokey ---
fast | autokey_len97_wl8               | auto     | autokey_len97_wl8.txt               | -cyclewordlen 8  -nrestarts 8000 -nhillclimbs 800
fast | autokey_len97_wl21              | auto     | autokey_len97_wl21.txt              | -cyclewordlen 21 -nrestarts 4000 -nhillclimbs 800
fast | example_autokey_beaufort        | autobeau | example_autokey_beaufort.txt        | -cyclewordlen 7  -nrestarts 8000 -nhillclimbs 800
fast | example_autokey_beaufort_longer | autobeau | example_autokey_beaufort_longer.txt | -cyclewordlen 14 -nrestarts 4000 -nhillclimbs 800
# --- homophonic substitution (ciphertext alphabet > plaintext; comma-separated symbols) ---
fast | homophonic_test | homophonic | homophonic_test.txt | -nrestarts 12 -nhillclimbs 30000
# --- Playfair (digraphic substitution, 5x5 grid; 25-letter alphabet forced, J->I) ---
slow | playfair_pride | playfair | playfair_pride.txt | -logprob -nrestarts 6 -nhillclimbs 400000 -inittemp 0.08 -backtrackprob 0.3
# --- Bifid (fractionation over a 5x5 keyed square; 25-letter alphabet forced, J->I) ---
slow | bifid_pride | bifid | bifid_pride.txt | -logprob -period 7 -nrestarts 4 -nhillclimbs 200000 -inittemp 0.08 -backtrackprob 0.3
# --- Trifid (fractionation over a 3x3x3 keyed cube; 27-symbol alphabet A..Z + '+') ---
slow | trifid_pride | trifid | trifid_pride.txt | -logprob -period 7 -nrestarts 6 -nhillclimbs 300000 -inittemp 0.08 -backtrackprob 0.3
# --- Hill (polygraphic substitution by a k x k matrix mod 26; full 26-letter alphabet) ---
fast | hill_k2 | hill | hill_k2.txt | -logprob -period 2 -nrestarts 20 -nhillclimbs 40000 -inittemp 0.10 -backtrackprob 0.25
# --- Phillips (8-square keyed-Polybius substitution, period 40; 25-letter alphabet, J->I) ---
slow | phillips_pride    | phillips    | phillips_pride.txt    | -logprob -nrestarts 4 -nhillclimbs 200000 -inittemp 0.08 -backtrackprob 0.3
slow | phillips_c_pride  | phillips-c  | phillips_c_pride.txt  | -logprob -nrestarts 4 -nhillclimbs 200000 -inittemp 0.08 -backtrackprob 0.3
slow | phillips_rc_pride | phillips-rc | phillips_rc_pride.txt | -logprob -nrestarts 4 -nhillclimbs 200000 -inittemp 0.08 -backtrackprob 0.3
# --- Two-Square / Four-Square (digraphic over two keyed 5x5 squares; 25-letter, J->I) ---
slow | twosquare_pride    | twosquare    | twosquare_pride.txt    | -logprob -nrestarts 4 -nhillclimbs 250000 -inittemp 0.08 -backtrackprob 0.3
slow | twosquare_v_pride  | twosquare-v  | twosquare_v_pride.txt  | -logprob -nrestarts 4 -nhillclimbs 250000 -inittemp 0.08 -backtrackprob 0.3
slow | foursquare_pride   | foursquare   | foursquare_pride.txt   | -logprob -nrestarts 6 -nhillclimbs 300000 -inittemp 0.08 -backtrackprob 0.3
# --- ADFGX (keyed-square fractionation + keyed columnar; 25-letter alphabet, J->I) ---
slow | adfgx_decl | adfgx | adfgx_decl.txt | -logprob -mincols 6 -maxcols 6 -nrestarts 8 -nhillclimbs 200000 -inittemp 0.08 -backtrackprob 0.3
# --- Nihilist Substitution (periodic additive over a keyed 5x5 square; numeric ciphertext) ---
# Three addition conventions (carry / no-carry / mod-100); nihilist_sub_kl is a carry cipher
# built with KEYED row/col labels, which the (fixed-label) solver recovers as a relabelled square.
slow | nihilist_sub_carry | nihilist-sub      | nihilist_sub_carry.txt | -logprob -period 6 -nrestarts 5 -nhillclimbs 150000 -inittemp 0.08 -backtrackprob 0.3
slow | nihilist_sub_nc    | nihilist-sub-nc   | nihilist_sub_nc.txt    | -logprob -period 6 -nrestarts 5 -nhillclimbs 150000 -inittemp 0.08 -backtrackprob 0.3
slow | nihilist_sub_m100  | nihilist-sub-m100 | nihilist_sub_m100.txt  | -logprob -period 6 -nrestarts 5 -nhillclimbs 150000 -inittemp 0.08 -backtrackprob 0.3
slow | nihilist_sub_kl    | nihilist-sub      | nihilist_sub_kl.txt    | -logprob -period 6 -nrestarts 5 -nhillclimbs 150000 -inittemp 0.08 -backtrackprob 0.3
# --- pure transposition ---
fast | transmatrix_solve   | transmatrix   | transmatrix_solve.txt   | -nrestarts 400 -nhillclimbs 2000
slow | transposition_solve | transposition | transposition_solve.txt | -nrestarts 6000 -nhillclimbs 6000
slow | transcol_single     | transcol      | transcol_single_tb.txt  | -nrestarts 40 -nhillclimbs 8000
fast | transcol_l_test     | transcol-l    | transcol_l_test.txt     | -logprob -mincols 10 -maxcols 10 -nrestarts 50 -nhillclimbs 15000
fast | transtile_test      | transtile     | transtile_test.txt      | -logprob -tile 2 2 -mincols 8 -maxcols 8 -nrestarts 60 -nhillclimbs 15000
fast | railfence_aca       | railfence     | railfence_aca.txt       | -maxcols 12
fast | route_ragged        | route         | route_ragged.txt        |
slow | amsco_aca           | amsco         | amsco_aca.txt           | -mincols 4 -maxcols 12 -nrestarts 60 -nhillclimbs 6000
fast | myszkowski_aca      | myszkowski    | myszkowski_aca.txt      | -nrestarts 30 -nhillclimbs 4000
fast | redefence_aca       | redefence     | redefence_aca.txt       | -maxcols 7 -nrestarts 15 -nhillclimbs 3000
slow | cadenus_aca         | cadenus       | cadenus_aca.txt         | -nrestarts 200 -nhillclimbs 6000
slow | nihilist_aca        | nihilist      | nihilist_aca.txt        | -nrestarts 400 -nhillclimbs 6000
slow | swagman_aca         | swagman       | swagman_aca.txt         | -nrestarts 300 -nhillclimbs 6000
fast | grille_aca          | grille        | grille_aca.txt          | -nrestarts 300 -nhillclimbs 6000
EOF

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

pass=0; fail=0; total=0; acc_sum=0; t_start=$SECONDS
[ "$GENERATE" = 0 ] && { printf '%-32s %8s %6s   %s\n' "TEST" "ACCURACY" "TIME" "RESULT"
                         printf '%-32s %8s %6s   %s\n' "----" "--------" "----" "------"; }

while IFS='|' read -r tier name type cipher extra; do
    tier=$(trim "$tier")
    [ -z "$tier" ] && continue
    case "$tier" in \#*) continue ;; esac
    name=$(trim "$name"); type=$(trim "$type"); cipher=$(trim "$cipher"); extra=$(trim "$extra")

    case "$TIER" in
        fast) [ "$tier" = "fast" ] || continue ;;
        slow) [ "$tier" = "slow" ] || continue ;;
    esac

    if [ ${#filters[@]} -gt 0 ]; then
        match=0
        for f in "${filters[@]}"; do [[ "$name" == *"$f"* ]] && match=1; done
        [ $match -eq 0 ] && continue
    fi

    t0=$SECONDS
    got=$("$BIN" -type "$type" -cipher "$cipher" $NG $COMMON -seed "$SEED" $extra 2>/dev/null | recovered_plaintext)
    secs=$((SECONDS - t0))

    if [ "$GENERATE" = 1 ]; then
        printf '%s\n' "$got" > "${name}.solution"
        printf '%-32s wrote %s.solution (%d chars)\n' "$name" "$name" "${#got}"
        continue
    fi

    sol="${name}.solution"
    if [ ! -f "$sol" ]; then
        printf '%-32s %8s %6s   %s\n' "$name" "-" "-" "NO .solution (skipped)"
        continue
    fi
    expected=$(tr -d '[:space:]' < "$sol")
    acc=$(accuracy "$got" "$expected")
    total=$((total + 1))
    acc_sum=$(awk -v a="$acc_sum" -v b="$acc" 'BEGIN{printf "%.4f", a + b}')

    if awk -v a="$acc" -v t="$THRESHOLD" 'BEGIN{exit !(a + 0 >= t + 0)}'; then
        printf '%-32s %7s%% %5ss   PASS\n' "$name" "$acc" "$secs"; pass=$((pass + 1))
    else
        printf '%-32s %7s%% %5ss   FAIL\n' "$name" "$acc" "$secs"; fail=$((fail + 1))
        [ "$VERBOSE" = 1 ] && { echo "    expected: $expected"; echo "    got:      $got"; }
    fi
done <<< "$MANIFEST"

[ "$GENERATE" = 1 ] && { echo "Generated .solution files. Verify them, then commit."; exit 0; }

echo "-------------------------------------------------------------"
if [ "$total" -gt 0 ]; then
    mean=$(awk -v s="$acc_sum" -v n="$total" 'BEGIN{printf "%.1f", s / n}')
else
    mean=0.0
fi
echo "TOTAL: $pass/$total passed, mean accuracy ${mean}% in $((SECONDS - t_start))s (tier=${TIER}, threshold ${THRESHOLD}%, seed ${SEED})"
[ "$fail" -eq 0 ]
