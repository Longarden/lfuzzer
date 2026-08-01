#!/usr/bin/env bash
# build_harness.sh — V1 in-process ASan harness builder (COMPILABLE SKELETON)
#
# WHAT THIS IS: a build skeleton for asan_harness.c. It is intentionally NOT a
# turn-key build — the glibc source TU paths and internal include/define set are
# TODO and must be filled against your local glibc checkout. It degrades
# gracefully: if a required tool or path is missing it PRINTS which one and exits
# non-zero, so this script itself never phantom-succeeds.
#
# TWO SUPPORTED FRONTENDS (pick with $HARNESS_ENGINE):
#   afl    -> afl-clang-fast, AFL++ persistent + AFL_USE_ASAN (default; WOOT'20)
#   libf   -> clang -fsanitize=address,fuzzer (LLVM libFuzzer; llvm.org/docs/LibFuzzer.html)
#
# Neither builds a full glibc. We compile the SPECIFIC translation units that
# contain the dynamic-parsing entrypoints (elf/dl-load.c, elf/dl-version.c and
# the get-dynamic-info.h include site) against glibc's internal headers, plus
# asan_harness.c, and link a single fuzz binary.
set -euo pipefail

# --------------------------------------------------------------------------- #
# 0. config
# --------------------------------------------------------------------------- #
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HARNESS_OUT:-$HERE/build}"
ENGINE="${HARNESS_ENGINE:-afl}"

# TODO: point these at your glibc SOURCE tree and its configured build dir.
# The build dir is where `configure` ran, so the generated headers
# (config.h, gnu/lib-names.h, the *-generated* stubs) exist.
GLIBC_SRC="${GLIBC_SRC:-$HOME/glibc}"                 # TODO: glibc source checkout
GLIBC_BUILD="${GLIBC_BUILD:-$HOME/glibc/build}"       # TODO: `configure`d build dir

# The TUs holding the entrypoints under test (see entrypoints.md).
# NOTE: these are glibc-internal and rely on the include/define set below.
ENTRY_TUS_TODO=(
  "$GLIBC_SRC/elf/dl-version.c"   # EP2 _dl_check_map_versions (verneed walk)
  # EP1 elf_get_dynamic_info is a header (elf/get-dynamic-info.h) #include'd by
  #     asan_harness.c directly — no separate TU.
  # EP3 elf/dl-load.c is heavy + pulls the whole loader; enable only for EP3 mode.
)

# --------------------------------------------------------------------------- #
# 1. tool + path preflight (graceful degrade — report the missing thing)
# --------------------------------------------------------------------------- #
need() { command -v "$1" >/dev/null 2>&1 || { echo "MISSING TOOL: $1 ($2)"; MISS=1; }; }
have_path() { [ -e "$1" ] || { echo "MISSING PATH: $1 ($2)"; MISS=1; }; }

MISS=0
case "$ENGINE" in
  afl)  need afl-clang-fast "AFL++ instrumenting compiler (apt: afl++ / build from source)";;
  libf) need clang          "LLVM clang with -fsanitize=fuzzer";;
  *)    echo "unknown HARNESS_ENGINE=$ENGINE (want: afl | libf)"; exit 2;;
esac
have_path "$GLIBC_SRC"   "set GLIBC_SRC=/path/to/glibc source checkout"
have_path "$GLIBC_BUILD" "set GLIBC_BUILD=/path/to/configured glibc build dir"
have_path "$HERE/asan_harness.c" "harness source (should sit next to this script)"

if [ "$MISS" -ne 0 ]; then
  echo
  echo "==> preflight failed. Fix the MISSING items above and re-run."
  echo "    (this is expected on a fresh checkout — the harness is a scaffold.)"
  exit 1
fi
mkdir -p "$OUT"

# --------------------------------------------------------------------------- #
# 2. include / define set for compiling glibc-internal code out-of-tree
# --------------------------------------------------------------------------- #
# TODO: this is the fiddliest part. glibc internals expect its private include
# search order and a pile of feature macros. The list below is the STARTING
# point — expect to add -include and -D flags as the compiler complains. Keep
# every addition here (not scattered) so the fixture stays reproducible.
GLIBC_INCLUDES_TODO=(
  -I"$GLIBC_SRC/include"
  -I"$GLIBC_SRC/elf"
  -I"$GLIBC_SRC/sysdeps/x86_64"
  -I"$GLIBC_SRC/sysdeps/unix/sysv/linux/x86_64"
  -I"$GLIBC_BUILD"                 # generated headers land here
)
GLIBC_DEFINES_TODO=(
  -D_GNU_SOURCE
  -D_RTLD_LOCAL_
  # -DSHARED / -DIS_IN(rtld) style macros may be required for the real TUs;
  # add as the build demands. Document each here with a one-line reason.
)

WARN="-Wall -Wextra -Wno-unused-parameter"

# --------------------------------------------------------------------------- #
# 3a. sanity build: standalone demo (no glibc TU, proves the skeleton compiles)
# --------------------------------------------------------------------------- #
# This ALWAYS works — it does not touch glibc. Use it in CI to catch skeleton
# rot. It links against the TODO() stub so it will FAIL AT LINK until you either
# provide TODO_unimplemented or fill the real paths — which is the intended
# "this is not finished yet" signal.
echo "==> [sanity] building standalone demo (HARNESS_STANDALONE_DEMO)"
CC_SANITY="${CC:-cc}"
set +e
"$CC_SANITY" $WARN -DHARNESS_STANDALONE_DEMO -fsanitize=address \
  -o "$OUT/asan_harness_demo" "$HERE/asan_harness.c"
rc=$?
set -e
if [ $rc -ne 0 ]; then
  echo "    (expected) demo link failed on unresolved TODO_unimplemented — the"
  echo "    skeleton is compiling but the harness is intentionally unfinished."
fi

# --------------------------------------------------------------------------- #
# 3b. real build (TODO — needs the glibc TUs + include/define set filled)
# --------------------------------------------------------------------------- #
echo "==> [real] building V1 fuzz target with engine=$ENGINE"

if [ "$ENGINE" = "afl" ]; then
  # AFL++ source-mode instrumentation + real ASan.
  #   AFL_USE_ASAN=1        : afl-clang-fast injects ASan AND keeps edge instr.
  #   AFL_LLVM_CMPLOG=1     : (optional) build a 2nd CMPLOG binary to blast
  #                           through DT_ magic/offset compares (RedQueen). V2
  #                           leans on this; wire it as a sibling binary.
  #   persistent mode       : asan_harness.c's LLVMFuzzerTestOneInput is driven
  #                           by AFL's libFuzzer-compat shim OR an AFL_LOOP()
  #                           wrapper for the 100–1000x exec/s win (WOOT'20).
  export AFL_USE_ASAN=1
  CC="afl-clang-fast"
  SAN_FLAGS=""                     # AFL_USE_ASAN supplies ASan
  FUZZ_DRIVER="-fsanitize=fuzzer-no-link"   # provides LLVMFuzzer* entry glue
else
  # LLVM libFuzzer + ASan, in-process persistent by construction.
  CC="clang"
  SAN_FLAGS="-fsanitize=address,fuzzer"
  FUZZ_DRIVER=""                   # -fsanitize=fuzzer links libFuzzer main
fi

echo "    NOTE: the command below is the TEMPLATE. It will not succeed until the"
echo "    TODO glibc paths (ENTRY_TUS_TODO) and include/define set are real."
cat <<EOF

  # ----- fill-in build command (template) -----
  $CC $WARN $SAN_FLAGS $FUZZ_DRIVER \\
      ${GLIBC_DEFINES_TODO[*]} \\
      ${GLIBC_INCLUDES_TODO[*]} \\
      "$HERE/asan_harness.c" \\
      ${ENTRY_TUS_TODO[*]} \\
      -o "$OUT/v1_harness"
  # --------------------------------------------

EOF

# Guard: refuse to claim success while the glibc TU is a placeholder path.
if [ ! -e "${ENTRY_TUS_TODO[0]}" ]; then
  echo "==> real build SKIPPED: entry TU not found (${ENTRY_TUS_TODO[0]})."
  echo "    Fill GLIBC_SRC/GLIBC_BUILD + the TODO include/define set, then"
  echo "    replace this guard with the templated command above."
  exit 3
fi

# TODO: once paths are real, run the templated command here and, for AFL, also
# build the CMPLOG sibling:  AFL_LLVM_CMPLOG=1 $CC ... -o "$OUT/v1_harness_cmplog"
echo "==> (real build body is TODO — see template)"
