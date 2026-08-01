#!/usr/bin/env bash
#
# run_experiment.sh -- exp_e6_auxtag
#
# Empirically confirms (via GDB, against a debug build of ld.so) that an
# EXTRATAGIDX-colliding fake DT_ tag sets l_info[AUXTAG] in glibc's rtld,
# but never actually triggers dl-deps.c's auxiliary-library-load code path.
#
# Everything this script touches lives in this directory
# (~/PE/Lfuzzer/exp_e6_auxtag/); it does not modify anything outside it.
#
# Requires (already built/present per the task, not built by this script):
#   ~/PE/Lfuzzer/prac.elf                 - base test binary
#   ~/glibc/build-dbg/elf/ld.so           - glibc rtld built with debug info
#   ~/glibc/glibc-2.39/elf/dl-deps.c      - source, for GDB "file:line" breakpoints
#
# Usage: bash run_experiment.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BASE_PRAC="$HOME/PE/Lfuzzer/prac.elf"
LDSO="$HOME/glibc/build-dbg/elf/ld.so"
LIBPATH="$HOME/glibc/build-dbg"

echo "############################################################"
echo "# Step 0: sanity-check required inputs exist"
echo "############################################################"
for f in "$BASE_PRAC" "$LDSO"; do
  if [[ ! -f "$f" ]]; then
    echo "MISSING REQUIRED FILE: $f" >&2
    exit 1
  fi
done
echo "OK: found $BASE_PRAC and $LDSO"
echo

echo "############################################################"
echo "# Step 1: copy the base test binary into this experiment dir"
echo "############################################################"
cp -v "$BASE_PRAC" ./prac.elf
echo

echo "############################################################"
echo "# Step 2: craft prac_auxtag_collision.elf (patch DT_DEBUG's tag"
echo "#         field to 0xDEADBEEFFFFFFFFD)"
echo "############################################################"
python3 patch_auxtag.py
echo

echo "############################################################"
echo "# Step 3: readelf -d sanity diff (unpatched vs patched)"
echo "############################################################"
readelf -d ./prac.elf > readelf_unpatched.txt
readelf -d ./prac_auxtag_collision.elf > readelf_patched.txt
echo "--- readelf -d diff (unpatched vs patched) ---"
diff -u readelf_unpatched.txt readelf_patched.txt || true
echo "(readelf does not know tag 0xdeadbeefffffffd, so it will show as an"
echo " unrecognized/processor-specific tag rather than as DEBUG -- expected.)"
echo

echo "############################################################"
echo "# Step 4: baseline run -- confirm both files still execute cleanly"
echo "#         under the debug ld.so (no unrelated crash before we even"
echo "#         reach dl-deps.c)"
echo "############################################################"
echo "--- unpatched ---"
"$LDSO" --library-path "$LIBPATH" ./prac.elf; echo "exit code: $?"
echo "--- patched ---"
"$LDSO" --library-path "$LIBPATH" ./prac_auxtag_collision.elf; echo "exit code: $?"
echo

echo "############################################################"
echo "# Step 5: GDB instrumentation run -- UNPATCHED prac.elf"
echo "############################################################"
gdb --batch -x probe.gdb \
    --args "$LDSO" --library-path "$LIBPATH" ./prac.elf \
    > gdb_unpatched.log 2>&1 || true
cat gdb_unpatched.log
echo

echo "############################################################"
echo "# Step 6: GDB instrumentation run -- PATCHED prac_auxtag_collision.elf"
echo "############################################################"
gdb --batch -x probe.gdb \
    --args "$LDSO" --library-path "$LIBPATH" ./prac_auxtag_collision.elf \
    > gdb_patched.log 2>&1 || true
cat gdb_patched.log
echo

echo "############################################################"
echo "# Step 7: summary"
echo "############################################################"
echo "--- BP222 (l_info gate) hits, unpatched ---"
grep -c "BP222" gdb_unpatched.log || true
echo "--- BP222 (l_info gate) hits, patched ---"
grep -c "BP222" gdb_patched.log || true
echo
echo "--- AUXTAG slot state, unpatched ---"
grep -A1 "l_info\[AUXTAG\]" gdb_unpatched.log || true
echo "--- AUXTAG slot state, patched ---"
grep -A1 "l_info\[AUXTAG\]" gdb_patched.log || true
echo
echo "--- BP266 (literal AUXILIARY/FILTER check) hit count, unpatched ---"
grep -c "BP266" gdb_unpatched.log || true
echo "--- BP266 (literal AUXILIARY/FILTER check) hit count, patched ---"
grep -c "BP266" gdb_patched.log || true
echo
# NOTE: match the literal "[BP271]" tag prefix, not the bare substring
# "BP271" -- the closing status line printed after 'run' also contains the
# word "BP271" in its English text, which would inflate a naive grep -c by
# one even when the breakpoint itself was never actually hit.
echo "--- BP271 (branch body / would-call-openaux) hit count, unpatched ---"
grep -c '^\[BP271\]' gdb_unpatched.log || true
echo "--- BP271 (branch body / would-call-openaux) hit count, patched ---"
grep -c '^\[BP271\]' gdb_patched.log || true
echo
echo "Done. Logs: gdb_unpatched.log gdb_patched.log readelf_unpatched.txt readelf_patched.txt"
