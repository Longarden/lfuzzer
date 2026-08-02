#!/usr/bin/env bash
# build_harness.sh — V1 in-process REAL-ASan harness builder (working, not a skeleton)
#
# asan_harness.c is SELF-CONTAINED: it re-implements ld.so's ELF64 .dynamic /
# PHDR / verneed(versym) pointer walks with the loader's exact "trust the
# attacker-controlled offset" model, running the input image inside a tight ASan
# heap allocation. No glibc build is required for the guaranteed path.
#
# THREE build targets (default: build every one the toolchain supports):
#   A) libfuzzer : clang -g -O1 -fsanitize=address,fuzzer      -> build/v1_libfuzzer
#   B) afl       : AFL_USE_ASAN=1 afl-clang-fast -fsanitize=fuzzer (AFL++ persistent,
#                  links /usr/lib/afl/libAFLDriver.a)           -> build/v1_afl
#   G) glibc     : gated 2nd option. Locates get-dynamic-info.h under $GLIBC_SRC and
#                  compiles with -DUSE_GLIBC_INTERNAL -DGLIBC_SRC_ELF=<dir> -I<dir>.
#                  Degrades with a clear message if the header is not found.
#   (demo)       : clang -fsanitize=address -DHARNESS_STANDALONE_DEMO -> build/v1_demo
#                  a no-libFuzzer single-file smoke tester (./build/v1_demo x.elf).
#
# Citations: AFL++ persistent mode — Fioraldi et al., WOOT'20.
#            LLVM libFuzzer — llvm.org/docs/LibFuzzer.html
#
# Pure bash, non-interactive. Select a subset with:  ./build_harness.sh [target...]
#   targets: libfuzzer | afl | glibc | demo | all   (default: all)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/asan_harness.c"
OUT="${HARNESS_OUT:-$HERE/build}"
GLIBC_SRC="${GLIBC_SRC:-$HOME/glibc}"          # glibc source checkout to search for headers
mkdir -p "$OUT"

# ── which targets to build ─────────────────────────────────────────────────────
TARGETS=("$@"); [ ${#TARGETS[@]} -eq 0 ] && TARGETS=(all)
want() { for t in "${TARGETS[@]}"; do [ "$t" = "all" ] && return 0; [ "$t" = "$1" ] && return 0; done; return 1; }

have() { command -v "$1" >/dev/null 2>&1; }
BUILT=(); SKIPPED=(); RC=0

[ -f "$SRC" ] || { echo "FATAL: harness source not found: $SRC"; exit 2; }

# ── A) libFuzzer + ASan ────────────────────────────────────────────────────────
if want libfuzzer || want demo; then
  if have clang; then
    if want libfuzzer; then
      echo "==> [A] libFuzzer: clang -fsanitize=address,fuzzer"
      if clang -g -O1 -fsanitize=address,fuzzer "$SRC" -o "$OUT/v1_libfuzzer"; then
        BUILT+=("build/v1_libfuzzer  (libFuzzer + ASan, in-process persistent)")
      else RC=1; SKIPPED+=("libfuzzer: clang build FAILED"); fi
    fi
    if want demo; then
      echo "==> [demo] clang -fsanitize=address -DHARNESS_STANDALONE_DEMO"
      if clang -g -O1 -fsanitize=address -DHARNESS_STANDALONE_DEMO "$SRC" -o "$OUT/v1_demo"; then
        BUILT+=("build/v1_demo       (standalone one-file smoke tester)")
      else RC=1; SKIPPED+=("demo: clang build FAILED"); fi
    fi
  else
    SKIPPED+=("libfuzzer/demo: clang not found (install clang; needs -fsanitize=fuzzer support)")
  fi
fi

# ── B) AFL++ persistent + ASan ─────────────────────────────────────────────────
# afl-clang-fast + -fsanitize=fuzzer links AFL++'s libFuzzer-compat driver
# (libAFLDriver.a): the same LLVMFuzzerTestOneInput body runs in AFL persistent
# mode. AFL_USE_ASAN=1 injects real AddressSanitizer alongside edge coverage.
if want afl; then
  if have afl-clang-fast; then
    echo "==> [B] AFL++: AFL_USE_ASAN=1 afl-clang-fast -fsanitize=fuzzer (persistent)"
    if AFL_USE_ASAN=1 afl-clang-fast -fsanitize=fuzzer "$SRC" -o "$OUT/v1_afl"; then
      BUILT+=("build/v1_afl        (AFL++ persistent + ASan; run with afl-fuzz -i corpus -o out)")
      # Optional CMPLOG sibling (RedQueen) — blasts through DT_/magic compares. V2 leans on it.
      if AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 afl-clang-fast -fsanitize=fuzzer "$SRC" -o "$OUT/v1_afl_cmplog" 2>/dev/null; then
        BUILT+=("build/v1_afl_cmplog (CMPLOG/RedQueen sibling for -c in afl-fuzz)")
      fi
    else RC=1; SKIPPED+=("afl: afl-clang-fast build FAILED"); fi
  else
    SKIPPED+=("afl: afl-clang-fast not found (apt install afl++ / build AFLplusplus)")
  fi
fi

# ── G) gated glibc-internal entrypoint (SECOND option) ─────────────────────────
# Locate the REAL get-dynamic-info.h and, if present, compile the harness with
# the internal-entrypoint gate enabled. The harness's USE_GLIBC_INTERNAL block
# requires -DGLIBC_SRC_ELF=<glibc>/elf; without it the TU #error's on purpose.
# NOTE: the actual elf_get_dynamic_info() *call* needs glibc's private include/
# define set (a full glibc-TU build); this target proves the gate + include path
# and degrades clearly when the source tree is absent.
if want glibc; then
  echo "==> [G] gated glibc-internal: searching for get-dynamic-info.h under $GLIBC_SRC"
  HDR="$(find "$GLIBC_SRC" -name get-dynamic-info.h 2>/dev/null | head -1)"
  if [ -z "$HDR" ]; then
    echo "    NOT FOUND: no get-dynamic-info.h under $GLIBC_SRC."
    echo "    -> gated glibc path DEGRADED (skipped). Set GLIBC_SRC=/path/to/glibc source"
    echo "       checkout to enable it. The guaranteed libfuzzer/afl builds are unaffected."
    SKIPPED+=("glibc: header not found under $GLIBC_SRC (degraded, non-fatal)")
  elif ! have clang; then
    SKIPPED+=("glibc: clang not found")
  else
    ELFDIR="$(dirname "$HDR")"
    echo "    found: $HDR"
    echo "    compiling with -DUSE_GLIBC_INTERNAL -DGLIBC_SRC_ELF=$ELFDIR -I$ELFDIR"
    if clang -g -O1 -fsanitize=address,fuzzer \
         -DUSE_GLIBC_INTERNAL -DGLIBC_SRC_ELF="$ELFDIR" -I"$ELFDIR" \
         "$SRC" -o "$OUT/v1_glibc" 2>"$OUT/v1_glibc.buildlog"; then
      BUILT+=("build/v1_glibc      (gate ON; glibc source located at $ELFDIR)")
      echo "    NOTE: this binary still runs the self-contained walker. A LIVE"
      echo "    elf_get_dynamic_info() call requires a glibc-TU build with glibc's"
      echo "    private include/define set (_RTLD_LOCAL_, IS_IN(rtld), ...)."
    else
      RC=1
      echo "    glibc-internal compile FAILED (expected out-of-tree). See $OUT/v1_glibc.buildlog"
      SKIPPED+=("glibc: out-of-tree compile failed — needs full glibc-TU include set")
    fi
  fi
fi

# ── summary + run hints ────────────────────────────────────────────────────────
echo
echo "──────────────────────────────────────────────────────────────────────────"
echo "BUILT:"
if [ ${#BUILT[@]} -eq 0 ]; then echo "  (nothing)"; else printf '  ✔ %s\n' "${BUILT[@]}"; fi
if [ ${#SKIPPED[@]} -ne 0 ]; then echo "SKIPPED / DEGRADED:"; printf '  - %s\n' "${SKIPPED[@]}"; fi
echo "──────────────────────────────────────────────────────────────────────────"
echo "RUN HINTS:"
echo "  seed corpus:   ./corpus_from_crashes.sh          # -> ./corpus/ (valid \\x7fELF only)"
echo "  libFuzzer:     ./build/v1_libfuzzer corpus/ -dict=elf.dict -runs=2000000"
echo "  AFL++:         afl-fuzz -i corpus -o out -x elf.dict -- ./build/v1_afl @@"
echo "  AFL++ +cmplog: afl-fuzz -i corpus -o out -c ./build/v1_afl_cmplog -- ./build/v1_afl @@"
echo "  demo/one-shot: ./build/v1_demo some.elf          # single-file ASan smoke"
echo
echo "  ASan fires here are CANDIDATES. Confirmation = V5 CASR + Tier-B stock-ld.so"
echo "  replay (lfuzzer.triage.tri_oracle). See README.md."
exit $RC
