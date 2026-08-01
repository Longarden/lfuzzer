#!/usr/bin/env bash
#
# exp_e2_pie: PIE executable used as a -shared link input.
#
# Research question:
#   If we take a genuine Position-Independent Executable (PIE, e_type=ET_DYN,
#   DT_FLAGS_1 & DF_1_PIE set) and hand it to a linker as an ordinary input
#   file to a `-shared` link, do BFD ld and gold behave the same way?
#
# Prediction being tested:
#   - BFD ld (ld-new from binutils-build-afl-bfd-clean) reads DT_FLAGS_1 from
#     input objects and, on seeing DF_1_PIE, refuses the link with a fatal
#     error containing "cannot use executable file" and produces no out.so.
#   - gold (ld-new from binutils-build-gold) does NOT consult DT_FLAGS_1 on
#     input objects at all, so it treats pie.elf as an ordinary DSO input
#     and succeeds (or at worst emits an unrelated warning).
#
# This script is self-contained: it builds pie.c from scratch, confirms via
# readelf that the resulting binary really is a PIE (ET_DYN + DF_1_PIE),
# then runs both linkers with -shared and captures exit codes + stderr.
#
# All work happens in this directory only. Nothing outside it is touched.

set -u  # do NOT use -e: we WANT to capture non-zero exit codes, not abort on them

# ---------------------------------------------------------------------------
# 0. Setup
# ---------------------------------------------------------------------------
WORKDIR="$HOME/PE/Lfuzzer/exp_e2_pie"
BFD_LD="$HOME/binutils-build-afl-bfd-clean/ld/ld-new"
GOLD_LD="$HOME/binutils-build-gold/gold/ld-new"

mkdir -p "$WORKDIR"
cd "$WORKDIR" || { echo "FATAL: cannot cd into $WORKDIR"; exit 1; }

echo "=================================================================="
echo " exp_e2_pie -- working dir: $(pwd)"
echo "=================================================================="

# Sanity-check the prebuilt linkers exist before we do anything else.
for tool in "$BFD_LD" "$GOLD_LD"; do
    if [ ! -x "$tool" ]; then
        echo "FATAL: expected linker not found or not executable: $tool"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 1. Build a genuine PIE executable from scratch
# ---------------------------------------------------------------------------
# A minimal C program is enough -- we only care about the ELF metadata
# (e_type, DT_FLAGS_1), not what the program actually does at runtime.
cat > pie.c << 'EOF'
#include <stdio.h>

int main(void)
{
    printf("hello from a PIE executable\n");
    return 0;
}
EOF

echo
echo "---- Step 1: compiling pie.c as a PIE executable ----"
# -fPIE -pie: explicit, even though it's the gcc default on modern Ubuntu,
# so the intent is unambiguous and the script is portable to distros where
# PIE is not the default.
gcc -fPIE -pie -o pie.elf pie.c
GCC_STATUS=$?
echo "gcc exit code: $GCC_STATUS"
if [ $GCC_STATUS -ne 0 ] || [ ! -f pie.elf ]; then
    echo "FATAL: failed to build pie.elf, aborting experiment"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Confirm pie.elf is really a PIE: e_type == DYN, DT_FLAGS_1 has DF_1_PIE
# ---------------------------------------------------------------------------
echo
echo "---- Step 2a: readelf -h pie.elf (checking e_type) ----"
readelf -h pie.elf | tee readelf_header.txt
E_TYPE=$(grep -i "Type:" readelf_header.txt | awk '{print $2}')
echo "Parsed e_type: $E_TYPE"

echo
echo "---- Step 2b: readelf -d pie.elf (checking DT_FLAGS_1 / DF_1_PIE) ----"
readelf -d pie.elf | tee readelf_dynamic.txt
if grep -qi "PIE" readelf_dynamic.txt; then
    echo "CONFIRMED: DT_FLAGS_1 contains a PIE-related flag."
else
    echo "WARNING: no PIE flag string found in DT_FLAGS_1 output."
fi

# Verdict on the precondition (not the final experiment result, just a
# sanity gate so we don't proceed testing a non-PIE binary by mistake).
if [ "$E_TYPE" = "DYN" ] && grep -qi "PIE" readelf_dynamic.txt; then
    echo
    echo "==> Precondition satisfied: pie.elf is a genuine PIE (ET_DYN + DF_1_PIE)."
    PRECONDITION_OK=1
else
    echo
    echo "==> WARNING: pie.elf does NOT look like a genuine PIE by our checks."
    echo "    (e_type=$E_TYPE). Continuing anyway to record what actually happens,"
    echo "    but treat the main-experiment result with caution."
    PRECONDITION_OK=0
fi

# ---------------------------------------------------------------------------
# 3. Main experiment: use pie.elf as a -shared link input for both linkers
# ---------------------------------------------------------------------------
echo
echo "---- Step 3a: BFD ld  ->  $BFD_LD -shared -o out_bfd.so pie.elf ----"
rm -f out_bfd.so
"$BFD_LD" -shared -o out_bfd.so pie.elf > bfd_stdout.txt 2> bfd_stderr.txt
BFD_EXIT=$?
echo "BFD ld exit code: $BFD_EXIT"
echo "BFD ld stderr:"
cat bfd_stderr.txt
echo "out_bfd.so produced? $( [ -f out_bfd.so ] && echo YES || echo NO )"

echo
echo "---- Step 3b: gold    ->  $GOLD_LD -shared -o out_gold.so pie.elf ----"
rm -f out_gold.so
"$GOLD_LD" -shared -o out_gold.so pie.elf > gold_stdout.txt 2> gold_stderr.txt
GOLD_EXIT=$?
echo "gold exit code: $GOLD_EXIT"
echo "gold stderr:"
cat gold_stderr.txt
echo "out_gold.so produced? $( [ -f out_gold.so ] && echo YES || echo NO )"

# ---------------------------------------------------------------------------
# 4. If gold produced out_gold.so, inspect it briefly (what did it become?)
# ---------------------------------------------------------------------------
if [ -f out_gold.so ]; then
    echo
    echo "---- Step 4: readelf -h out_gold.so (what gold actually produced) ----"
    readelf -h out_gold.so | tee gold_out_header.txt
fi
if [ -f out_bfd.so ]; then
    echo
    echo "---- Step 4: readelf -h out_bfd.so (what BFD ld actually produced) ----"
    readelf -h out_bfd.so | tee bfd_out_header.txt
fi

# ---------------------------------------------------------------------------
# 5. Diff / summarize stderr between the two linkers
# ---------------------------------------------------------------------------
echo
echo "---- Step 5: diff of BFD ld stderr vs gold stderr ----"
diff -u bfd_stderr.txt gold_stderr.txt
echo "(diff exit code $?: 0 = identical, 1 = differ, >1 = error)"

# ---------------------------------------------------------------------------
# 6. Verdict: did reality match the prediction?
# ---------------------------------------------------------------------------
echo
echo "=================================================================="
echo " VERDICT"
echo "=================================================================="
echo "Precondition (pie.elf is genuine PIE): $([ $PRECONDITION_OK -eq 1 ] && echo PASS || echo FAIL)"
echo

BFD_MATCHES_PREDICTION=0
if [ $BFD_EXIT -ne 0 ] && grep -qi "cannot use executable file" bfd_stderr.txt && [ ! -f out_bfd.so ]; then
    BFD_MATCHES_PREDICTION=1
fi
echo "BFD ld prediction (fatal error w/ 'cannot use executable file', no out.so): $([ $BFD_MATCHES_PREDICTION -eq 1 ] && echo MATCHED || echo DID_NOT_MATCH)"

GOLD_MATCHES_PREDICTION=0
if [ $GOLD_EXIT -eq 0 ] && [ -f out_gold.so ]; then
    GOLD_MATCHES_PREDICTION=1
fi
echo "gold prediction (succeeds, produces out.so, treats input as ordinary DSO): $([ $GOLD_MATCHES_PREDICTION -eq 1 ] && echo MATCHED || echo DID_NOT_MATCH)"

echo
if [ $BFD_MATCHES_PREDICTION -eq 1 ] && [ $GOLD_MATCHES_PREDICTION -eq 1 ]; then
    echo "OVERALL: prediction fully MATCHED observed behavior."
else
    echo "OVERALL: prediction did NOT fully match -- see per-linker verdicts above"
    echo "and the raw stderr/exit codes captured in this directory for the real behavior."
fi
echo "=================================================================="
