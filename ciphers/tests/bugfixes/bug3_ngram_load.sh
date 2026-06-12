#!/bin/bash
# Bug 3: load_ngrams() looped on while(!feof(fp)). Because !feof is still false
# after the last good line, the final line gets re-read; on a trailing/malformed
# line fscanf("%s\t%d") fails to fill freq, leaving a STALE value that is then
# assigned to a spurious ngram index -- corrupting the table and the
# normalization total (which scales every cipher's score). The fix loops on
# fscanf(...) == 2, so malformed/trailing lines are ignored.
#
# bug3_ng_test.c replicates the loader both ways. We run it on a malformed file
# (final line "ZZZZ" with no count) and on a well-formed file.
cd "$(dirname "$0")" || exit 1
gcc -O2 -o /tmp/bug3_ng_test bug3_ng_test.c -lm || exit 1

echo "=== Malformed final line: OLD injects bogus 'ZZZZ', NEW ignores it ==="
/tmp/bug3_ng_test bug3_quad_malformed.txt ZZZZ
echo
echo "=== Well-formed input: OLD and NEW identical (fix is a no-op here) ==="
/tmp/bug3_ng_test bug3_quad_ok.txt QXZW
