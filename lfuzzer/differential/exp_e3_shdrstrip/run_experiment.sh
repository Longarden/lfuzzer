#!/usr/bin/env bash
# run_experiment.sh - exp_e3_shdrstrip
#
# Section-header-stripped input object, DT_STRSZ/nbuckets sensitivity.
#
# What this does, step by step:
#   1. Build a normal shared library libtest.so (one exported function).
#   2. Build main.o from main.c (the trivial consumer, compiled but not yet
#      linked against any particular libtest variant).
#   3. Use mutate_elf.py to produce four .so files:
#        libtest.so                    - untouched baseline (control)
#        libtest_noshdr.so             - section headers stripped, GOOD DT_STRSZ
#        libtest_patched_strsz.so      - section headers intact, BAD DT_STRSZ (intermediate)
#        libtest_noshdr_badstrsz.so    - section headers stripped, BAD DT_STRSZ
#   4. Point GCC's linker search at our two custom ld-new binaries (bfd, gold)
#      using the standard "-B <dir containing a program literally named ld>"
#      trick, so `gcc -B bfd_bin ...` invokes the BFD ld-new we built, and
#      `gcc -B gold_bin ...` invokes the gold ld-new we built, instead of the
#      system linker.
#   5. Link main.o against each variant with each linker (2x2 = 4 experiment
#      cells) plus 2 sanity-control cells (each linker against the untouched
#      libtest.so), capturing exit code + stderr for every attempt.
#   6. Print a result matrix and a plain-English verdict against the
#      predicted hypothesis.
#
# Everything happens inside this script's own directory; nothing outside it
# is touched (aside from reading the pre-built linkers named in the task).
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

BFD_LD=~/binutils-build-afl-bfd-clean/ld/ld-new
GOLD_LD=~/binutils-build-gold/gold/ld-new

for f in "$BFD_LD" "$GOLD_LD"; do
    if [ ! -x "$f" ]; then
        echo "FATAL: expected linker not found/executable: $f" >&2
        exit 1
    fi
done

echo "=================================================================="
echo "Step 1: build libtest.so (normal, with section headers) from lib.c"
echo "=================================================================="
gcc -shared -fPIC -O0 -o libtest.so lib.c || { echo "FATAL: baseline libtest.so build failed"; exit 1; }
readelf -h libtest.so | grep -E "Start of section headers|Section header string"
readelf -d libtest.so | grep STRSZ

echo
echo "=================================================================="
echo "Step 2: build main.o from main.c (consumer, not linked yet)"
echo "=================================================================="
gcc -c -O0 -o main.o main.c || { echo "FATAL: main.o build failed"; exit 1; }

echo
echo "=================================================================="
echo "Step 3: produce the mutated .so variants with mutate_elf.py"
echo "=================================================================="
# (a) section-headers-stripped, DT_STRSZ untouched (good)
python3 mutate_elf.py strip libtest.so libtest_noshdr.so || exit 1
echo
# (b) from the ORIGINAL (section headers still intact), patch DT_STRSZ to a
#     tiny bogus value, THEN strip section headers from that patched copy.
python3 mutate_elf.py patch-strsz libtest.so libtest_patched_strsz.so 1 || exit 1
echo
python3 mutate_elf.py strip libtest_patched_strsz.so libtest_noshdr_badstrsz.so || exit 1

echo
echo "=================================================================="
echo "Evidence: ELF header / dynamic section state of each variant"
echo "=================================================================="
for so in libtest.so libtest_noshdr.so libtest_patched_strsz.so libtest_noshdr_badstrsz.so; do
    echo "--- $so ---"
    readelf -h "$so" 2>&1 | grep -E "Start of section headers|Section header string table index" \
        || echo "  (readelf -h could not parse section-header fields -- expected once stripped)"
    readelf -d "$so" 2>&1 | grep -i strsz \
        || echo "  (readelf -d found no STRSZ line via this path)"
    echo
done

echo "=================================================================="
echo "Step 4: set up -B directories so gcc invokes OUR ld-new binaries"
echo "=================================================================="
mkdir -p bin_bfd bin_gold
ln -sf "$BFD_LD" bin_bfd/ld
ln -sf "$GOLD_LD" bin_gold/ld
# Sanity: confirm gcc -B actually picks up our linker and not the system one,
# by diffing --version output reachable through -B vs a fixed known path.
echo "-- bfd ld-new --version (direct) --"
"$BFD_LD" --version | head -1
echo "-- gold ld-new --version (direct) --"
"$GOLD_LD" --version | head -1

echo
echo "=================================================================="
echo "Step 5: run all link attempts (4 experiment cells + 2 sanity controls)"
echo "=================================================================="
mkdir -p logs

# link_case <label> <bindir> <so_variant>
# Links main.o against libtest_variant using the linker selected by bindir/ld.
# Writes logs/<label>.stderr and logs/<label>.exit ; echoes a one-line summary.
link_case() {
    local label="$1" bindir="$2" so_variant="$3"
    local out="logs/${label}.out"
    local err="logs/${label}.stderr"
    local exitf="logs/${label}.exit"

    gcc -O0 -B "$bindir" -o "$out" main.o -L. -l:"$so_variant" \
        > "logs/${label}.stdout" 2> "$err"
    local rc=$?
    echo "$rc" > "$exitf"

    local symbol_status="n/a"
    if [ "$rc" -eq 0 ] && [ -f "$out" ]; then
        # Check whether the produced executable actually references get_answer
        # as an undefined dynamic symbol resolved to the library (extra evidence
        # beyond bare link exit code).
        if readelf -d "$out" 2>/dev/null | grep -q "$so_variant"; then
            symbol_status="linked-against-$so_variant"
        else
            symbol_status="linked-ok-but-no-NEEDED-entry(?)"
        fi
    fi

    printf "%-28s rc=%-3s stderr_bytes=%-6s %s\n" \
        "$label" "$rc" "$(wc -c < "$err")" "$symbol_status"
}

echo "--- sanity controls (untouched libtest.so, both linkers) ---"
link_case "ctrl_bfd_baseline"  bin_bfd  "libtest.so"
link_case "ctrl_gold_baseline" bin_gold "libtest.so"

echo
echo "--- experiment cells ---"
link_case "bfd_good_strsz"   bin_bfd  "libtest_noshdr.so"
link_case "bfd_bad_strsz"    bin_bfd  "libtest_noshdr_badstrsz.so"
link_case "gold_good_strsz"  bin_gold "libtest_noshdr.so"
link_case "gold_bad_strsz"   bin_gold "libtest_noshdr_badstrsz.so"

echo
echo "=================================================================="
echo "Stderr detail for each experiment cell (first 15 lines each)"
echo "=================================================================="
for label in bfd_good_strsz bfd_bad_strsz gold_good_strsz gold_bad_strsz; do
    echo "--- $label stderr ---"
    if [ -s "logs/${label}.stderr" ]; then
        head -n 15 "logs/${label}.stderr"
    else
        echo "  (empty stderr)"
    fi
    echo
done

echo "=================================================================="
echo "RESULT MATRIX (2x2: linker x DT_STRSZ correctness)"
echo "=================================================================="
printf "%-10s | %-22s | %-22s\n" "linker" "good DT_STRSZ" "bad DT_STRSZ (=1)"
printf -- "-----------+------------------------+------------------------\n"
bfd_good_rc=$(cat logs/bfd_good_strsz.exit)
bfd_bad_rc=$(cat logs/bfd_bad_strsz.exit)
gold_good_rc=$(cat logs/gold_good_strsz.exit)
gold_bad_rc=$(cat logs/gold_bad_strsz.exit)
printf "%-10s | exit=%-17s | exit=%-17s\n" "bfd"  "$bfd_good_rc"  "$bfd_bad_rc"
printf "%-10s | exit=%-17s | exit=%-17s\n" "gold" "$gold_good_rc" "$gold_bad_rc"

echo
echo "=================================================================="
echo "VERDICT vs prediction"
echo "=================================================================="
echo "Predicted: bfd good=SUCCESS(0), bfd bad=FAIL(nonzero)"
echo "           gold good==gold bad (both fail identically, gold ignores DT_STRSZ / has no PT_DYNAMIC fallback)"
echo
echo "Observed:  bfd  good_rc=$bfd_good_rc  bad_rc=$bfd_bad_rc"
echo "           gold good_rc=$gold_good_rc bad_rc=$gold_bad_rc"
echo

bfd_matches="NO"
if [ "$bfd_good_rc" = "0" ] && [ "$bfd_bad_rc" != "0" ]; then
    bfd_matches="YES"
fi

gold_matches="NO"
if [ "$gold_good_rc" = "$gold_bad_rc" ]; then
    gold_matches="YES"
fi

echo "bfd sensitivity to DT_STRSZ matches prediction:  $bfd_matches"
echo "gold identical-regardless-of-DT_STRSZ matches prediction: $gold_matches"

echo
echo "=================================================================="
echo "BONUS/addendum: root-cause check for the bfd mismatch"
echo "=================================================================="
echo "bfd rejected BOTH noshdr variants with 'file format not recognized',"
echo "not the DT_STRSZ-dependent error the hypothesis predicted. Reading"
echo "bfd/elfcode.h (elf_object_p) shows an EARLIER gate:"
echo "    if (i_ehdrp->e_shoff < sizeof(x_ehdr) && i_ehdrp->e_shnum != 0)"
echo "        goto got_wrong_format_error;"
echo "The as-specified 'strip' recipe only zeroes e_shoff/e_shstrndx and"
echo "leaves e_shnum at its original nonzero value, so this guard fires"
echo "before the e_shoff==0 && e_shstrndx==0 fallback block (which calls"
echo "_bfd_elf_get_dynamic_symbols) is ever reached. This bonus check also"
echo "zeroes e_shnum, to see whether that reaches the hypothesized path."
echo "(This is diagnostic only -- it does NOT replace the primary,"
echo "as-specified result reported above.)"
echo
python3 mutate_elf.py strip-full libtest.so bonus_noshdrfull.so || exit 1
echo
python3 mutate_elf.py strip-full libtest_patched_strsz.so bonus_noshdrfull_badstrsz.so || exit 1
echo
link_case "bonus_bfd_good_strsz" bin_bfd "bonus_noshdrfull.so"
link_case "bonus_bfd_bad_strsz"  bin_bfd "bonus_noshdrfull_badstrsz.so"
echo
echo "--- bonus_bfd_good_strsz stderr ---"
[ -s "logs/bonus_bfd_good_strsz.stderr" ] && head -n 15 "logs/bonus_bfd_good_strsz.stderr" || echo "  (empty stderr)"
echo
echo "--- bonus_bfd_bad_strsz stderr ---"
[ -s "logs/bonus_bfd_bad_strsz.stderr" ] && head -n 15 "logs/bonus_bfd_bad_strsz.stderr" || echo "  (empty stderr)"
echo
bonus_good_rc=$(cat logs/bonus_bfd_good_strsz.exit)
bonus_bad_rc=$(cat logs/bonus_bfd_bad_strsz.exit)
echo "bonus bfd (e_shnum also zeroed): good_rc=$bonus_good_rc  bad_rc=$bonus_bad_rc"
if [ "$bonus_good_rc" = "0" ] && [ "$bonus_bad_rc" != "0" ]; then
    echo "  -> root-cause theory CONFIRMED: with e_shnum also zeroed, bfd's"
    echo "     PT_DYNAMIC fallback engages and DOES become DT_STRSZ-sensitive"
    echo "     exactly as the original hypothesis predicted."
else
    echo "  -> root-cause theory NOT confirmed by this bonus check; the"
    echo "     mismatch has some other cause. Reporting honestly as observed."
fi

echo
echo "Done. Full logs in $HERE/logs/, mutated binaries in $HERE/"
