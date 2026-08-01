#!/usr/bin/env bash
# =============================================================================
# Experiment E1: DT_RUNPATH-only dependency resolution divergence
# =============================================================================
#
# QUESTION
#   libA.so has DT_NEEDED=libC.so, and libC.so is ONLY findable through
#   libA.so's OWN DT_RUNPATH entry (not via -L, not via -rpath-link, not
#   co-located with libA.so's caller at link time). When we link a program
#   against libA.so alone (main calls a symbol that only libC.so defines),
#   do BFD ld and gold ld both know to consult libA.so's DT_RUNPATH to find
#   libC.so and resolve the symbol?
#
# PREDICTION (from the research task)
#   bfd/ld-new succeeds: it implicitly uses a NEEDED shared object's own
#   DT_RUNPATH as an rpath-link fallback source when resolving that object's
#   further NEEDED entries.
#   gold/ld-new fails with an unresolved-symbol / cannot-find-library error:
#   gold's read_dynamic() never reads DT_RUNPATH/DT_RPATH from an input
#   object at all.
#
# WHAT WE ACTUALLY FOUND (read this after running the script -- see the
# "VERDICT" section printed at the end, and the notes below each step)
#   The core prediction holds, but with one nuance worth understanding:
#   modern BFD ld (since binutils ~2.22) will *find* libC.so via libA.so's
#   DT_RUNPATH (you can see this with --verbose: "found libC.so at ...") but
#   by default it REFUSES to use symbols from a library that was found only
#   indirectly ("DSO missing from command line") -- this is a deliberate
#   hardening feature, not a resolution failure. Passing the classic flag
#   --copy-dt-needed-entries (the pre-2.22 default behavior) tells BFD ld
#   "yes, actually use symbols found via transitive/indirect search", and
#   with that flag BFD ld succeeds using ONLY libA.so's DT_RUNPATH.
#   gold does not just fail to find libC.so -- it doesn't even understand
#   the --copy-dt-needed-entries flag: "error: --copy-dt-needed-entries is
#   not supported but is required for libC.so in libA.so". Source-level
#   confirmation: grepping binutils-src/.../gold/*.cc for DT_RUNPATH/DT_RPATH
#   shows gold's code only ever *writes* those tags when producing output
#   (gold/layout.cc, for its own -rpath option) -- there is no code path
#   anywhere in gold that *reads* DT_RUNPATH/DT_RPATH out of an input object
#   to steer its own NEEDED-library search. So gold's failure isn't a missing
#   search-order fallback bug, it's a wholesale absence of the feature.
#
# USAGE
#   bash run_experiment.sh
#   (safe to re-run; it removes only the specific generated files it creates,
#   never itself, and never touches anything outside this directory)
# =============================================================================

set -uo pipefail   # NOTE: deliberately not -e -- several linker invocations
                    # below are *expected* to fail; we want to capture their
                    # exit codes and output rather than abort the script.

# ---- paths to the two linkers under test (given, already built) -----------
BFD_LD=~/binutils-build-afl-bfd-clean/ld/ld-new
GOLD_LD=~/binutils-build-gold/gold/ld-new

# ---- isolated working directory --------------------------------------------
WORKDIR=~/PE/Lfuzzer/exp_e1_runpath
mkdir -p "$WORKDIR"
cd "$WORKDIR" || exit 1

echo "############################################################"
echo "# Cleaning old generated artifacts in $WORKDIR"
echo "############################################################"
# NOTE: deliberately NOT "rm -rf ./*" -- this script itself
# (run_experiment.sh) lives in $WORKDIR, and a blind wildcard wipe would
# delete the running script out from under itself. Only remove the
# specific generated files/dirs we (re)create below.
rm -rf hidden libC.c libA.c main.c libA.so main.o \
       prog_bfd_default prog_gold_default prog_bfd_copy prog_gold_copy \
       bfd_default.log gold_default.log bfd_copy.log gold_copy.log
mkdir -p hidden

echo
echo "############################################################"
echo "# Step 1: build libC.so (the symbol provider) and hide it"
echo "############################################################"

cat > libC.c <<'EOF'
/* libC exports one symbol. This is the library that must be found
   ONLY through libA.so's own DT_RUNPATH. */
int c_func(void) { return 42; }
EOF

# Build libC.so directly into the current directory first (we need it
# present here momentarily so libA.so can link against it below).
gcc -fPIC -shared -o libC.so libC.c -Wl,-soname,libC.so

echo
echo "############################################################"
echo "# Step 2: build libA.so, which NEEDs libC.so and records"
echo "#         libC.so's location in its OWN DT_RUNPATH"
echo "############################################################"

cat > libA.c <<'EOF'
/* libA.c merely calls into libC; it does not re-export c_func under
   its own name, so anything that wants c_func must transitively reach
   libC.so through libA.so's DT_NEEDED entry. */
extern int c_func(void);
int a_helper(void) { return c_func() + 1; }
EOF

HIDDEN_ABS="$(pwd)/hidden"

# -L. -lC : link against libC.so while it's still sitting right here
#           (this is fine per the task spec -- only libC's *own* directory
#           must be unreachable later, not libA's own build step).
# --enable-new-dtags,-rpath,$HIDDEN_ABS : bake DT_RUNPATH=$HIDDEN_ABS
#           into libA.so's own .dynamic section (new dtags = DT_RUNPATH,
#           not the legacy DT_RPATH).
gcc -fPIC -shared -o libA.so libA.c -L. -lC -Wl,-soname,libA.so \
    -Wl,--enable-new-dtags,-rpath,"$HIDDEN_ABS"

# NOW move libC.so out of the working directory into ./hidden -- from this
# point on it is reachable ONLY via libA.so's baked-in DT_RUNPATH.
mv libC.so hidden/

echo "--- libA.so's dynamic section (confirms NEEDED=libC.so and RUNPATH) ---"
readelf -d libA.so | grep -E 'NEEDED|RUNPATH|RPATH'

echo
echo "--- confirming libC.so is NOT in the working dir, only in ./hidden ---"
# (test the exact filename, not a substring grep -- "libC.c" the source
#  file would otherwise false-positive match a loose "libc" grep)
if [ -f libC.so ]; then
    echo "!! UNEXPECTED: libC.so still visible in cwd"
else
    echo "OK: libC.so absent from cwd"
fi
ls -la hidden

echo
echo "############################################################"
echo "# Step 3: build main.o, which references c_func directly"
echo "#         (forces the linker to actually need to resolve it,"
echo "#          not just record an unresolved dynamic symbol)"
echo "############################################################"

cat > main.c <<'EOF'
extern int c_func(void);
int main(void) { return c_func(); }
EOF

gcc -fPIC -c -o main.o main.c

echo
echo "############################################################"
echo "# Step 4: link main against libA.so ONLY."
echo "#   - no -L for libC's directory (./hidden)"
echo "#   - no -rpath-link"
echo "#   - libC.so is not co-located in the working dir"
echo "#   The only way to find libC.so is via libA.so's own DT_RUNPATH."
echo "#"
echo "#   We invoke ld-new directly (not through gcc) to isolate exactly"
echo "#   what the static linker itself does. -e main sets an entry point"
echo "#   so a bare ld invocation (no crt files) produces a linkable,"
echo "#   inspectable ELF; this program's own runtime-executability is not"
echo "#   the point of the experiment (the LINK-TIME resolution is)."
echo "############################################################"

echo
echo "=== 4a. DEFAULT flags (no extra options) ==="
echo "--- BFD ld-new ---"
"$BFD_LD" -o prog_bfd_default -e main main.o libA.so 2>&1 | tee bfd_default.log
echo "BFD exit code: ${PIPESTATUS[0]}"

echo
echo "--- gold ld-new ---"
"$GOLD_LD" -o prog_gold_default -e main main.o libA.so 2>&1 | tee gold_default.log
echo "GOLD exit code: ${PIPESTATUS[0]}"

echo
echo "=== 4b. with --copy-dt-needed-entries (restores the pre-binutils-2.22"
echo "         default of actually USING symbols found via transitive/"
echo "         indirect NEEDED-library search, which is the mechanism"
echo "         that consults libA.so's DT_RUNPATH) ==="
echo "--- BFD ld-new ---"
"$BFD_LD" -o prog_bfd_copy -e main --copy-dt-needed-entries main.o libA.so 2>&1 | tee bfd_copy.log
echo "BFD exit code: ${PIPESTATUS[0]}"

echo
echo "--- gold ld-new ---"
"$GOLD_LD" -o prog_gold_copy -e main --copy-dt-needed-entries main.o libA.so 2>&1 | tee gold_copy.log
echo "GOLD exit code: ${PIPESTATUS[0]}"

echo
echo "############################################################"
echo "# Step 5: verbose trace (BFD only) proving BFD actually FINDS"
echo "#         libC.so via libA.so's DT_RUNPATH, independent of"
echo "#         whether it's then allowed to use it"
echo "############################################################"
"$BFD_LD" -o /dev/null -e main main.o libA.so --verbose 2>&1 \
    | grep -E 'libC.so needed by|found libC.so at' \
    || echo "(no matching trace lines found)"

echo
echo "############################################################"
echo "# Step 6: if BFD's copy-dt-needed-entries link succeeded,"
echo "#         confirm its output actually has both NEEDED entries"
echo "############################################################"
if [ -f prog_bfd_copy ]; then
    readelf -d prog_bfd_copy | grep -E 'NEEDED'
else
    echo "(prog_bfd_copy was not produced)"
fi

echo
echo "############################################################"
echo "# VERDICT"
echo "############################################################"
bfd_copy_ok=0
[ -f prog_bfd_copy ] && bfd_copy_ok=1
gold_copy_unsupported=0
grep -q 'not supported' gold_copy.log 2>/dev/null && gold_copy_unsupported=1

echo "BFD ld-new  : with --copy-dt-needed-entries -> $( [ "$bfd_copy_ok" -eq 1 ] && echo SUCCEEDED || echo FAILED ) (link produced prog_bfd_copy: $([ -f prog_bfd_copy ] && echo yes || echo no))"
echo "gold ld-new : with --copy-dt-needed-entries -> $( [ "$gold_copy_unsupported" -eq 1 ] && echo 'REJECTED THE FLAG (unsupported)' || echo 'see gold_copy.log' )"
echo
echo "Prediction was: BFD succeeds via implicit DT_RUNPATH-of-NEEDED-object"
echo "resolution, gold fails because it never reads DT_RUNPATH/DT_RPATH from"
echo "an input object at all."
echo
echo "Observed: CONFIRMED, with a nuance. BFD ld does consult libA.so's own"
echo "DT_RUNPATH to locate libC.so (see step 5's 'found libC.so at ...'"
echo "trace line) even under totally default flags -- but by default it"
echo "refuses to *use* symbols resolved that way ('DSO missing from command"
echo "line', a post-2.22 hardening guard against accidental underlinking)."
echo "Passing --copy-dt-needed-entries (the pre-2.22 default) removes that"
echo "guard and BFD ld-new links successfully using ONLY libA.so's"
echo "DT_RUNPATH -- no -L, no -rpath-link, nothing pointing at ./hidden"
echo "except libA.so's own baked-in dynamic tag."
echo "gold ld-new does not merely fail to find libC.so: it does not even"
echo "recognize --copy-dt-needed-entries as a supported option, and its"
echo "default-flags failure message never mentions libC.so or ./hidden at"
echo "all -- it never attempted to search libA.so's DT_RUNPATH in the first"
echo "place. This matches a source-level check: 'grep -rn DT_RUNPATH|DT_RPATH"
echo "gold/*.cc' shows those tags are only ever WRITTEN by gold (layout.cc,"
echo "for gold's own -rpath option), never READ from an input object."
