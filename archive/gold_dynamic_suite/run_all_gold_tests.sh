#!/usr/bin/env bash
# =============================================================================
# run_all_gold_tests.sh
#   Consolidated gold-vs-BFD DYNAMIC-section robustness suite.
#
#   Exercises, in ONE file, every DYNAMIC field for which gold and BFD ld
#   diverge when consuming a shared-object / special ELF input. Each field
#   rebuilds (reusing the ALREADY-PROVEN build+mutate logic and the exact
#   mutator helpers from exp_e1..e5) a malformed-or-special input, then hands
#   the SAME input with IDENTICAL args to BOTH ld-new binaries, capturing:
#       exit code   +   stderr   +   whether an output file was produced,
#   diffs the two, and prints a one-line PASS/OBSERVED verdict per field,
#   followed by a final summary table.
#
# GOLD-FIRST FINDING (source-confirmed, binutils-2.42):
#   gold/dynobj.cc  Sized_dynobj::read_dynamic() (line 249) is the ONLY place
#   gold reads an input object's .dynamic. Its switch (lines 293-326) has
#   cases for exactly THREE tags:  DT_NULL (295), DT_SONAME (300),
#   DT_NEEDED (312).  Everything else falls through `default: break;` (324)
#   and is silently dropped. So DT_RUNPATH/DT_RPATH (#4), DT_FLAGS_1 (#7),
#   DT_STRSZ (#6/#9), and DT_VERNEED (#5) are NEVER consulted by gold from an
#   input object -- the absence of a case IS the finding. DT_SONAME (#3) is
#   the control: gold DOES read it, so gold and BFD agree there.
#
# SAFETY / IDEMPOTENCE:
#   - Does NOT use -e (linker failures are expected data, not fatal).
#   - Never `rm -rf` its own directory. Only removes the specific generated
#     in_e* subdirs and the results file it recreates. Safe to re-run.
# =============================================================================
set -uo pipefail

# ---- the two linkers under test (given, prebuilt) ---------------------------
BFD_LD=/home/garden/binutils-build-afl-bfd-clean/ld/ld-new
GOLD_LD=/home/garden/binutils-build-gold/gold/ld-new

# ---- reused, already-proven mutator helpers (by absolute path) --------------
MUT_STRIP=/home/garden/PE/Lfuzzer/exp_e3_shdrstrip/mutate_elf.py
MUT_VERNEED=/home/garden/PE/Lfuzzer/exp_e4_verneed/corrupt_verneed.py
MUT_SONAME=/home/garden/PE/Lfuzzer/exp_e5_dupsoname/mutate_dynamic.py

# ---- isolated suite directory ----------------------------------------------
SUITE=/home/garden/PE/Lfuzzer/gold_dynamic_suite
mkdir -p "$SUITE"
cd "$SUITE" || { echo "FATAL: cannot cd into $SUITE"; exit 1; }

RESULTS="$SUITE/_results.tsv"
: > "$RESULTS"   # truncate (idempotent), never rm the dir

# ---- preflight --------------------------------------------------------------
for f in "$BFD_LD" "$GOLD_LD" "$MUT_STRIP" "$MUT_VERNEED" "$MUT_SONAME"; do
    if [ ! -e "$f" ]; then echo "FATAL: missing dependency: $f"; exit 1; fi
done
echo "=============================================================================="
echo " gold_dynamic_suite : consolidated DYNAMIC-field robustness runner"
echo " suite dir : $SUITE"
echo " BFD  ld   : $("$BFD_LD"  --version | head -1)"
echo " gold ld   : $("$GOLD_LD" --version | head -1)"
echo "=============================================================================="

# ---------------------------------------------------------------------------
# run_case <name> <expect DIVERGE|CONTROL> <workdir> -- <ld args...>
#   Runs BOTH linkers with identical args inside <workdir>, adding only a
#   per-linker "-o out_<linker>_<name>". Captures rc, stderr, output-exists,
#   computes divergence, prints a live block, and appends a results row.
# ---------------------------------------------------------------------------
run_case() {
    local name="$1" expect="$2" workdir="$3"; shift 3
    [ "$1" = "--" ] && shift
    local -a ldargs=( "$@" )

    local out_bfd="out_bfd_${name}" out_gold="out_gold_${name}"
    local bfd_rc gold_rc bfd_out gold_out diverged verdict note

    ( cd "$workdir" && rm -f "$out_bfd" "$out_gold" \
        "${name}_bfd.err" "${name}_gold.err" )

    ( cd "$workdir" && "$BFD_LD"  -o "$out_bfd"  "${ldargs[@]}" \
        >"${name}_bfd.out"  2>"${name}_bfd.err" )
    bfd_rc=$?
    ( cd "$workdir" && "$GOLD_LD" -o "$out_gold" "${ldargs[@]}" \
        >"${name}_gold.out" 2>"${name}_gold.err" )
    gold_rc=$?

    [ -s "$workdir/$out_bfd"  ] && bfd_out=yes  || bfd_out=no
    [ -s "$workdir/$out_gold" ] && gold_out=yes || gold_out=no

    # divergence = disagreement on success(rc==0) OR on output production
    local bfd_ok=$([ "$bfd_rc" -eq 0 ] && echo 1 || echo 0)
    local gold_ok=$([ "$gold_rc" -eq 0 ] && echo 1 || echo 0)
    if [ "$bfd_ok" != "$gold_ok" ] || [ "$bfd_out" != "$gold_out" ]; then
        diverged=yes
    else
        diverged=no
    fi

    # first non-empty stderr line from each (the "what diverged" evidence)
    local bfd_msg gold_msg
    bfd_msg=$(grep -m1 -E '.' "$workdir/${name}_bfd.err" 2>/dev/null | cut -c1-72)
    gold_msg=$(grep -m1 -E '.' "$workdir/${name}_gold.err" 2>/dev/null | cut -c1-72)
    [ -z "$bfd_msg" ]  && bfd_msg='(no stderr)'
    [ -z "$gold_msg" ] && gold_msg='(no stderr)'

    if [ "$expect" = "DIVERGE" ]; then
        [ "$diverged" = yes ] && verdict=PASS || verdict=OBSERVED
    else # CONTROL: expect identical behaviour
        [ "$diverged" = no ]  && verdict=PASS || verdict=OBSERVED
    fi
    note="$bfd_msg"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$bfd_rc" "$gold_rc" "$bfd_out" "$gold_out" \
        "$diverged" "$verdict" "$note" >> "$RESULTS"

    echo
    echo "------------------------------------------------------------------------------"
    echo " CASE $name   expect=$expect"
    echo "   args: ${ldargs[*]}"
    echo "   BFD  -> rc=$bfd_rc  output=$bfd_out   | $bfd_msg"
    echo "   gold -> rc=$gold_rc  output=$gold_out   | $gold_msg"
    echo "   diverged=$diverged   VERDICT=$verdict"
    echo "------------------------------------------------------------------------------"
}

# =============================================================================
# BUILD + RUN each field
# =============================================================================

# ---------------------------------------------------------------------------
# E1  DT_RUNPATH / DT_RPATH  (#4)  -- gold read_dynamic() has NO case for it
#   libA.so NEEDs libC.so, findable ONLY via libA.so's own DT_RUNPATH.
#   Identical args include --copy-dt-needed-entries (pre-2.22 default that
#   lets a linker USE symbols found via a NEEDED object's own runpath).
#   BFD consults libA.so's RUNPATH and links; gold does not even recognise
#   the flag (it never reads RUNPATH from an input object).
# ---------------------------------------------------------------------------
echo; echo "########## build E1 (DT_RUNPATH #4) ##########"
rm -rf in_e1; mkdir -p in_e1/hidden
(
  cd in_e1
  cat > libC.c <<'EOF'
int c_func(void) { return 42; }
EOF
  gcc -fPIC -shared -o libC.so libC.c -Wl,-soname,libC.so
  cat > libA.c <<'EOF'
extern int c_func(void);
int a_helper(void) { return c_func() + 1; }
EOF
  gcc -fPIC -shared -o libA.so libA.c -L. -lC -Wl,-soname,libA.so \
      -Wl,--enable-new-dtags,-rpath,"$(pwd)/hidden"
  mv libC.so hidden/
  cat > main.c <<'EOF'
extern int c_func(void);
int main(void) { return c_func(); }
EOF
  gcc -fPIC -c -o main.o main.c
  echo "  libA.so dynamic tags:"; readelf -d libA.so | grep -E 'NEEDED|RUNPATH|RPATH' | sed 's/^/    /'
)
run_case e1_runpath DIVERGE "$SUITE/in_e1" -- --copy-dt-needed-entries -e main main.o libA.so

# ---------------------------------------------------------------------------
# E2  DT_FLAGS_1 / DF_1_PIE  (#7)  -- gold read_dynamic() has NO case for it
#   A genuine PIE (ET_DYN + DF_1_PIE) handed to `-shared`. BFD reads
#   DT_FLAGS_1, sees DF_1_PIE, refuses ("cannot use executable file"),
#   no output. gold never reads DT_FLAGS_1 -> treats it as an ordinary DSO
#   input and produces an output .so.
# ---------------------------------------------------------------------------
echo; echo "########## build E2 (DT_FLAGS_1/DF_1_PIE #7) ##########"
rm -rf in_e2; mkdir -p in_e2
(
  cd in_e2
  cat > pie.c <<'EOF'
#include <stdio.h>
int main(void){ printf("hello from a PIE executable\n"); return 0; }
EOF
  gcc -fPIE -pie -o pie.elf pie.c
  echo "  pie.elf type:"; readelf -h pie.elf | grep -i 'Type:' | sed 's/^/    /'
  echo "  pie.elf flags:"; readelf -d pie.elf | grep -i 'FLAGS_1\|PIE' | sed 's/^/    /'
)
run_case e2_pie DIVERGE "$SUITE/in_e2" -- -shared pie.elf

# ---------------------------------------------------------------------------
# E3  DT_STRSZ / stripped section headers  (#6/#9)
#   A DSO with section headers stripped (e_shoff/e_shstrndx zeroed) but
#   e_shnum left nonzero. BFD's elfcode.h object gate rejects it outright
#   ("file format not recognized") -> BFD requires section headers to
#   consume a DSO. gold parses the input from PT_DYNAMIC / program headers
#   instead and accepts it. Divergence = section-header dependence.
# ---------------------------------------------------------------------------
echo; echo "########## build E3 (STRSZ / stripped shdrs #6/#9) ##########"
rm -rf in_e3; mkdir -p in_e3
(
  cd in_e3
  cat > lib.c <<'EOF'
int get_answer(void){ return 42; }
EOF
  cat > main.c <<'EOF'
#include <stdio.h>
int get_answer(void);
int main(void){ printf("answer=%d\n", get_answer()); return 0; }
EOF
  gcc -shared -fPIC -O0 -o libtest.so lib.c
  gcc -c -fPIC -O0 -o main.o main.c
  python3 "$MUT_STRIP" strip libtest.so libtest_noshdr.so
  echo "  libtest_noshdr.so shoff:"; readelf -h libtest_noshdr.so 2>&1 | grep -i 'section headers' | sed 's/^/    /'
)
run_case e3_shdrstrip DIVERGE "$SUITE/in_e3" -- -shared main.o libtest_noshdr.so

# ---------------------------------------------------------------------------
# E4  DT_VERNEED / .gnu.version_r  (#5)  -- gold read_dynamic() ignores it
#   libv.so requires a versioned glibc symbol -> real .gnu.version_r.
#   corrupt_verneed.py sets vna_next of the first Vernaux to a huge bogus
#   offset. BFD walks/validates the Verneed chain; gold does not consult
#   DT_VERNEED from an input object. Capture whatever each does.
# ---------------------------------------------------------------------------
echo; echo "########## build E4 (DT_VERNEED #5) ##########"
rm -rf in_e4; mkdir -p in_e4
(
  cd in_e4
  cat > libv.c <<'EOF'
#include <stdio.h>
int foo_impl(void){ printf("hello from foo\n"); return 42; }
__asm__(".symver foo_impl,foo@@VERS_1.0");
EOF
  cat > libv.map <<'EOF'
VERS_1.0 { global: foo; local: *; };
EOF
  gcc -shared -fPIC -Wl,--version-script=libv.map -o libv.so libv.c
  python3 "$MUT_VERNEED" libv.so libv_corrupt.so >/dev/null
  cat > main.c <<'EOF'
extern int foo(void);
int callfoo(void){ return foo(); }
EOF
  gcc -c -fPIC -o main.o main.c
  echo "  libv_corrupt.so version_r present:"; readelf -d libv_corrupt.so 2>/dev/null | grep -i 'VERNEED\|VERNEEDNUM' | sed 's/^/    /'
)
run_case e4_verneed DIVERGE "$SUITE/in_e4" -- -shared main.o -L. -lv_corrupt

# ---------------------------------------------------------------------------
# E5  DT_SONAME  (#3)  -- CONTROL: gold DOES read DT_SONAME (dynobj.cc:300)
#   Duplicate DT_SONAME (second/last entry = "libBAD"). Both linkers read
#   DT_SONAME; expectation is they AGREE (identical DT_NEEDED recorded).
#   This is the positive control proving the harness detects "same".
# ---------------------------------------------------------------------------
echo; echo "########## build E5 (DT_SONAME #3, CONTROL) ##########"
rm -rf in_e5; mkdir -p in_e5
(
  cd in_e5
  cat > empty.c <<'EOF'
int exported_victim_value = 42;
EOF
  gcc -shared -fPIC -Wl,-soname,libfirst.so.1 -o libvictim.so empty.c
  python3 "$MUT_SONAME" libvictim.so libvictim_dupsoname.so libBAD >/dev/null
  cat > consumer.c <<'EOF'
extern int exported_victim_value;
int use_it(void){ return exported_victim_value; }
EOF
  gcc -c -fPIC -o consumer.o consumer.c
  echo -n "  DT_SONAME entries in mutated lib: "; readelf -d libvictim_dupsoname.so | grep -c SONAME
)
run_case e5_soname CONTROL "$SUITE/in_e5" -- -shared consumer.o -L. -lvictim_dupsoname --no-as-needed

# E5 extra: confirm both linkers recorded the SAME DT_NEEDED soname string
if [ -s "in_e5/out_bfd_e5_soname" ] && [ -s "in_e5/out_gold_e5_soname" ]; then
    e5_bfd_needed=$(readelf -d in_e5/out_bfd_e5_soname  2>/dev/null | grep NEEDED | grep -v 'libc.so' | sed 's/.*\[\(.*\)\]/\1/' | tr -d ' ')
    e5_gold_needed=$(readelf -d in_e5/out_gold_e5_soname 2>/dev/null | grep NEEDED | grep -v 'libc.so' | sed 's/.*\[\(.*\)\]/\1/' | tr -d ' ')
    echo
    echo "   E5 recorded DT_NEEDED  BFD='$e5_bfd_needed'  gold='$e5_gold_needed'  (control: expect equal, = last SONAME 'libBAD')"
fi

# =============================================================================
# FINAL SUMMARY TABLE
# =============================================================================
echo
echo "=============================================================================="
echo " FINAL SUMMARY"
echo "=============================================================================="
printf '┌───────────────┬──────┬──────┬────────┬────────┬─────────┬──────────┐\n'
printf '│ %-13s │ %-4s │ %-4s │ %-6s │ %-6s │ %-7s │ %-8s │\n' \
    "field" "bfd" "gold" "bfd" "gold" "diver" "verdict"
printf '│ %-13s │ %-4s │ %-4s │ %-6s │ %-6s │ %-7s │ %-8s │\n' \
    "" "rc" "rc" "out.so" "out.so" "ged" ""
printf '├───────────────┼──────┼──────┼────────┼────────┼─────────┼──────────┤\n'
while IFS=$'\t' read -r name brc grc bout gout div verd note; do
    printf '│ %-13s │ %-4s │ %-4s │ %-6s │ %-6s │ %-7s │ %-8s │\n' \
        "$name" "$brc" "$grc" "$bout" "$gout" "$div" "$verd"
done < "$RESULTS"
printf '└───────────────┴──────┴──────┴────────┴────────┴─────────┴──────────┘\n'

echo
echo " Per-field 'what diverged' (BFD first-stderr-line):"
while IFS=$'\t' read -r name brc grc bout gout div verd note; do
    printf '   %-13s : %s\n' "$name" "$note"
done < "$RESULTS"

echo
n_pass=$(cut -f7 "$RESULTS" | grep -c PASS)
n_total=$(wc -l < "$RESULTS")
echo " $n_pass / $n_total fields matched their expected behaviour (PASS)."
echo " (E1-E4 expect DIVERGE = gold ignores the field; E5 is the DT_SONAME CONTROL = expect AGREE.)"
echo "=============================================================================="
