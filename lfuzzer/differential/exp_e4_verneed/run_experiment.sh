#!/usr/bin/env bash
#
# run_experiment.sh -- Verneed vna_next corruption: fail-fast (bfd) vs fail-slow (gold)
#
# WHAT THIS DOES
#   1. Builds libv.so: a shared library that both DEFINES a versioned symbol
#      (foo@@VERS_1.0, via .gnu.version_d) and REQUIRES a versioned glibc
#      symbol (printf@GLIBC_2.x, via .gnu.version_r / Verneed).
#   2. Corrupts the vna_next field of the first Vernaux entry in
#      .gnu.version_r, producing libv_corrupt.so.
#   3. Links a trivial object against libv_corrupt.so with BOTH the BFD
#      linker and the gold linker, and records exit code / stderr for each.
#   4. Repeats the link with a THIRD, uncorrupted library (libw.so) added
#      after the corrupted one on the command line, using --trace-symbol
#      to observe whether each linker still looks at input files that come
#      AFTER the corrupted one (this is the practical fail-fast/fail-slow
#      probe -- exit code and wall-clock time alone do not distinguish them,
#      see RESULTS below).
#
# REQUIREMENTS (already built per the research environment, not built here):
#   BFD ld:  ~/binutils-build-afl-bfd-clean/ld/ld-new
#   gold ld: ~/binutils-build-gold/gold/ld-new
#   corrupt_verneed.py must sit next to this script.
#
# Safe to re-run: everything is generated fresh into the current directory.

set -uo pipefail   # NOTE: no -e -- we WANT to continue past the linkers'
                    # nonzero exit codes so we can inspect/report them.

BFD_LD=~/binutils-build-afl-bfd-clean/ld/ld-new
GOLD_LD=~/binutils-build-gold/gold/ld-new
DYNLINKER=/lib64/ld-linux-x86-64.so.2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

for f in "$BFD_LD" "$GOLD_LD"; do
  if [ ! -x "$f" ]; then
    echo "FATAL: linker not found/executable: $f" >&2
    exit 1
  fi
done

echo '################################################################'
echo '# STEP 1: build libv.so with a real .gnu.version_d AND .gnu.version_r'
echo '################################################################'

cat > libv.c << 'EOF'
#include <stdio.h>

/* Internal implementation under a distinct name so .symver can alias
 * it to the public versioned name foo@@VERS_1.0 (aliasing a symbol to
 * its own literal name causes a multiple-definition error).
 *
 * foo_impl() calls printf() so linking libv.so pulls in a real
 * *versioned* glibc symbol (printf@GLIBC_2.x). That is what forces
 * the linker to emit a genuine, non-empty .gnu.version_r (Verneed)
 * table referencing glibc's version definitions -- the table this
 * experiment corrupts.
 */
int foo_impl(void) {
    printf("hello from foo\n");
    return 42;
}
__asm__(".symver foo_impl,foo@@VERS_1.0");
EOF

cat > libv.map << 'EOF'
VERS_1.0 {
    global: foo;
    local: *;
};
EOF

gcc -shared -fPIC -Wl,--version-script=libv.map -o libv.so libv.c
echo "[build libv.so] exit=$?"
echo
echo '--- readelf -V libv.so (confirm version_d AND version_r are populated) ---'
readelf -V libv.so
echo

echo '################################################################'
echo '# STEP 2: corrupt vna_next in .gnu.version_r -> libv_corrupt.so'
echo '################################################################'
python3 corrupt_verneed.py libv.so libv_corrupt.so
echo

echo '################################################################'
echo '# STEP 3: build the trivial consumer object(s)'
echo '################################################################'
cat > main.c << 'EOF'
/* References foo() so the linker must pull in libv_corrupt.so as a
 * NEEDED shared object and parse its .gnu.version_r table.
 */
extern int foo(void);
int callfoo(void) { return foo(); }
EOF
gcc -c -fPIC -o main.o main.c
echo "[build main.o] exit=$?"

# A second, entirely valid (uncorrupted) shared library + a consumer that
# references it too, used in STEP 5 to probe fail-fast vs fail-slow.
cat > libw.c << 'EOF'
int bar(void) { return 7; }
EOF
gcc -shared -fPIC -o libw.so libw.c
echo "[build libw.so] exit=$?"

cat > main2.c << 'EOF'
extern int foo(void);
extern int bar(void);
int callall(void) { return foo() + bar(); }
EOF
gcc -c -fPIC -o main2.o main2.c
echo "[build main2.o] exit=$?"
echo

echo '################################################################'
echo '# STEP 4 (control/sanity): link against the CLEAN libv.so'
echo '#   -- proves the corruption, not our procedure, is what breaks things'
echo '################################################################'
echo '--- bfd + clean libv.so ---'
"$BFD_LD" -shared -o out_bfd_clean.so main.o -L. -lv --dynamic-linker "$DYNLINKER"
echo "exit=$?"
echo '--- gold + clean libv.so ---'
"$GOLD_LD" -shared -o out_gold_clean.so main.o -L. -lv --dynamic-linker "$DYNLINKER"
echo "exit=$?"
echo

echo '################################################################'
echo '# STEP 5: THE EXPERIMENT -- link against libv_corrupt.so'
echo '################################################################'
echo '--- bfd + libv_corrupt.so (single corrupt input) ---'
/usr/bin/time -f 'elapsed=%es' "$BFD_LD" -shared -o out_bfd_corrupt.so main.o -L. -lv_corrupt --dynamic-linker "$DYNLINKER"
echo "BFD_EXIT=$?"
[ -f out_bfd_corrupt.so ] && echo '  -> out_bfd_corrupt.so WAS produced' || echo '  -> NO output file produced'
echo
echo '--- gold + libv_corrupt.so (single corrupt input) ---'
/usr/bin/time -f 'elapsed=%es' "$GOLD_LD" -shared -o out_gold_corrupt.so main.o -L. -lv_corrupt --dynamic-linker "$DYNLINKER"
echo "GOLD_EXIT=$?"
[ -f out_gold_corrupt.so ] && echo '  -> out_gold_corrupt.so WAS produced' || echo '  -> NO output file produced'
echo

echo '################################################################'
echo '# STEP 6: fail-fast vs fail-slow PROBE'
echo '#   Link order: main2.o  libv_corrupt.so(BROKEN)  libw.so(FINE)'
echo '#   --trace-symbol=bar prints a line every time any file'
echo '#   references or defines "bar". If a linker prints the'
echo '#   "./libw.so: definition of bar" line, it proves that linker'
echo '#   kept opening/processing input files AFTER hitting the'
echo '#   corrupted Verneed table, instead of aborting immediately.'
echo '################################################################'
echo '--- bfd: corrupt lib THEN valid lib, tracing symbol bar ---'
"$BFD_LD" -shared -o out_bfd_multi.so main2.o -L. -lv_corrupt -lw     --trace-symbol=bar --dynamic-linker "$DYNLINKER"
echo "BFD_MULTI_EXIT=$?"
echo
echo '--- gold: corrupt lib THEN valid lib, tracing symbol bar ---'
"$GOLD_LD" -shared -o out_gold_multi.so main2.o -L. -lv_corrupt -lw     --trace-symbol=bar --dynamic-linker "$DYNLINKER"
echo "GOLD_MULTI_EXIT=$?"
echo

echo '################################################################'
echo '# DONE. See the transcript above for full stderr from each linker.'
echo '################################################################'
