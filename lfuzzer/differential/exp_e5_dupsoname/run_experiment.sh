#!/usr/bin/env bash
# ============================================================================
# exp_e5_dupsoname: duplicate DT_SONAME entries -- does "last wins" hold
# identically on BFD ld and gold?
#
# Pipeline:
#   1. Build libvictim.so with DT_SONAME = "libfirst.so.1"
#   2. Use mutate_dynamic.py to splice in a SECOND, LAST-IN-FILE-ORDER
#      DT_SONAME entry pointing at a different string ("libBAD").
#   3. Build a tiny consumer that depends on libvictim (forced with
#      --no-as-needed so the dependency is recorded even though the
#      consumer only references one symbol).
#   4. Link the consumer against the MUTATED library with BOTH:
#        - BFD ld  (~/binutils-build-afl-bfd-clean/ld/ld-new)
#        - gold    (~/binutils-build-gold/gold/ld-new)
#      using `gcc -B <dir-with-ld-symlink>` to force gcc's collect2 to
#      invoke our custom linker binary instead of the system one.
#   5. Compare what DT_NEEDED string each produced executable recorded
#      for the victim dependency.
#
# Everything happens inside this script's directory; no files outside
# ~/PE/Lfuzzer/exp_e5_dupsoname/ are touched.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

BFD_LD=~/binutils-build-afl-bfd-clean/ld/ld-new
GOLD_LD=~/binutils-build-gold/gold/ld-new

for f in "$BFD_LD" "$GOLD_LD"; do
    [ -x "$f" ] || { echo "FATAL: linker not found/executable: $f" >&2; exit 1; }
done

echo "================================================================"
echo "STEP 1: build libvictim.so (DT_SONAME = libfirst.so.1)"
echo "================================================================"
cat > empty.c << 'EOF'
/* Trivial exported symbol so the .so has something real to link against. */
int exported_victim_value = 42;
EOF
gcc -shared -fPIC -Wl,-soname,libfirst.so.1 -o libvictim.so empty.c
echo "--- readelf -d libvictim.so (BEFORE mutation) ---"
readelf -d libvictim.so | grep -E 'SONAME|RELACOUNT'

echo
echo "================================================================"
echo "STEP 2: splice in a second, conflicting DT_SONAME entry"
echo "================================================================"
python3 mutate_dynamic.py libvictim.so libvictim_dupsoname.so libBAD
echo "--- readelf -d libvictim_dupsoname.so (AFTER mutation, full dump) ---"
readelf -d libvictim_dupsoname.so

echo
echo "--- sanity check: how many DT_SONAME entries does readelf see now? ---"
SONAME_COUNT=$(readelf -d libvictim_dupsoname.so | grep -c 'SONAME' || true)
echo "SONAME entry count: $SONAME_COUNT"
if [ "$SONAME_COUNT" -ne 2 ]; then
    echo "FATAL: expected exactly 2 DT_SONAME entries after mutation, got $SONAME_COUNT" >&2
    exit 1
fi

echo
echo "================================================================"
echo "STEP 3: build consumer that depends on the (mutated) victim lib"
echo "================================================================"
cat > consumer.c << 'EOF'
#include <stdio.h>
extern int exported_victim_value;
int main(void) {
    printf("exported_victim_value = %d\n", exported_victim_value);
    return 0;
}
EOF

echo
echo "================================================================"
echo "STEP 4: link consumer against libvictim_dupsoname.so with each linker"
echo "================================================================"
# gcc's -fuse-ld= only accepts a fixed keyword set (bfd/gold/lld/mold) on
# stock GCC, not an arbitrary path -- so instead we use the standard trick
# of `-B <dir>` containing a file literally named `ld`, which makes gcc's
# collect2 driver invoke that binary instead of searching PATH.
rm -rf ld_bfd_dir ld_gold_dir
mkdir -p ld_bfd_dir ld_gold_dir
ln -sf "$BFD_LD"  ld_bfd_dir/ld
ln -sf "$GOLD_LD" ld_gold_dir/ld

# -lvictim_dupsoname resolves via -L. to ./libvictim_dupsoname.so.
# --no-as-needed forces the DT_NEEDED entry to be recorded even though
# the mutated file's declared soname(s) are bogus.
# -rpath . lets the produced binaries actually locate the lib at runtime
# too (not required for this experiment, which only inspects readelf -d,
# but costs nothing and keeps the artifacts runnable for further poking).

echo "--- linking with BFD ld ---"
gcc -B ld_bfd_dir -o out_bfd consumer.c -L. -lvictim_dupsoname \
    -Wl,--no-as-needed -Wl,-rpath,. 2>&1 | tee link_bfd.log
BFD_EXIT=${PIPESTATUS[0]}
echo "BFD link exit code: $BFD_EXIT"

echo
echo "--- linking with gold ---"
gcc -B ld_gold_dir -o out_gold consumer.c -L. -lvictim_dupsoname \
    -Wl,--no-as-needed -Wl,-rpath,. 2>&1 | tee link_gold.log
GOLD_EXIT=${PIPESTATUS[0]}
echo "gold link exit code: $GOLD_EXIT"

echo
echo "================================================================"
echo "STEP 5: compare recorded DT_NEEDED for the victim dependency"
echo "================================================================"
echo "--- readelf -d out_bfd ---"
readelf -d out_bfd 2>&1 | tee readelf_bfd.txt

echo
echo "--- readelf -d out_gold ---"
readelf -d out_gold 2>&1 | tee readelf_gold.txt

echo
BFD_NEEDED=$(grep 'NEEDED' readelf_bfd.txt | grep -v 'libc.so' || true)
GOLD_NEEDED=$(grep 'NEEDED' readelf_gold.txt | grep -v 'libc.so' || true)
echo "BFD  recorded NEEDED line : $BFD_NEEDED"
echo "gold recorded NEEDED line : $GOLD_NEEDED"

echo
echo "================================================================"
echo "VERDICT"
echo "================================================================"
if [ -z "$BFD_NEEDED" ] || [ -z "$GOLD_NEEDED" ]; then
    echo "INCONCLUSIVE: one or both linkers did not record a NEEDED entry"
    echo "referencing the victim lib -- see readelf_bfd.txt / readelf_gold.txt"
    exit 0
fi

if [ "$BFD_NEEDED" = "$GOLD_NEEDED" ]; then
    echo "MATCH: both linkers recorded the identical DT_NEEDED string:"
    echo "    $BFD_NEEDED"
    if echo "$BFD_NEEDED" | grep -q 'libBAD'; then
        echo "-> This is the SECOND (last-in-file-order) DT_SONAME value."
        echo "-> PREDICTION CONFIRMED: both linkers use 'last DT_SONAME wins'."
    elif echo "$BFD_NEEDED" | grep -q 'libfirst.so.1'; then
        echo "-> This is the FIRST DT_SONAME value, not the last."
        echo "-> PREDICTION NOT CONFIRMED as stated: both linkers agree, but"
        echo "   the behavior is 'first wins', not 'last wins'."
    else
        echo "-> Recorded value matches neither expected string verbatim; inspect manually."
    fi
else
    echo "MISMATCH: linkers disagree on the recorded DT_NEEDED string!"
    echo "  BFD : $BFD_NEEDED"
    echo "  gold: $GOLD_NEEDED"
    echo "-> PREDICTION NOT CONFIRMED: behavior differs between linkers."
fi
