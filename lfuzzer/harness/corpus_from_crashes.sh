#!/usr/bin/env bash
# corpus_from_crashes.sh — build a V1 seed corpus for the ASan harness by sampling
# REAL crash ELFs from prior Lfuzzer runs into ./corpus/ (valid \x7fELF only).
#
# Mirrors the intent of ../../rebuild_seeds.sh (categorized sampling), retargeted
# at the in-process harness: libFuzzer/AFL want a *directory* of diverse, valid
# ELF64 images to mutate. Coverage-guided mutation then discovers the OOB reads
# the raw crashers don't themselves trigger (their wild pointers are clamped to
# "skip" by in_map; the harness hunts in-bounds-start / body-overshoot bugs).
#
# Sources (each optional; missing ones are skipped, never fatal):
#   1. dynamic-field fuzz outputs : $LF/out_dynamic_v3/*.elf           (the big pool)
#   2. AFL/QEMU crash dirs        : $LF/out_*/**/crashes*/            (id:* files)
#   3. curated templates          : lfuzzer-clean/templates/*.elf      (valid baselines)
#
# Env knobs:
#   CORPUS_DIR (default ./corpus)   N_DYNAMIC (default 400)   N_CRASHES (default 200)
#   LF_ROOT    (default ~/PE/Lfuzzer)   TEMPLATES (default ../../templates)
#
# Pure bash, non-interactive. Idempotent: wipes and rebuilds CORPUS_DIR.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS_DIR="${CORPUS_DIR:-$HERE/corpus}"
LF_ROOT="${LF_ROOT:-$HOME/PE/Lfuzzer}"
TEMPLATES="${TEMPLATES:-$HERE/../../templates}"
N_DYNAMIC="${N_DYNAMIC:-400}"
N_CRASHES="${N_CRASHES:-200}"

rm -rf "$CORPUS_DIR"
mkdir -p "$CORPUS_DIR"

# is $1 a real ELF? (magic \x7fELF) — the one hard filter, like rebuild_seeds.sh
is_elf() { [ -f "$1" ] && [ "$(head -c 4 "$1" 2>/dev/null)" = $'\x7fELF' ]; }

copied=0
take() {  # take <src> <dest-basename-prefix>
  local src="$1" pfx="$2"
  is_elf "$src" || return 0
  # content-addressed name -> automatic dedup across sources
  local h; h="$(sha1sum "$src" 2>/dev/null | cut -c1-12)"
  [ -z "$h" ] && return 0
  local dst="$CORPUS_DIR/${pfx}_${h}.elf"
  [ -e "$dst" ] && return 0
  cp "$src" "$dst" && copied=$((copied+1))
}

echo "==> corpus dir: $CORPUS_DIR"

# 1) dynamic-field pool (main source) — sample N_DYNAMIC at random
DYN="$LF_ROOT/out_dynamic_v3"
if [ -d "$DYN" ]; then
  echo "==> [1] sampling $N_DYNAMIC from out_dynamic_v3/"
  ls "$DYN"/*.elf 2>/dev/null | shuf | head -n "$N_DYNAMIC" | while read -r f; do
    is_elf "$f" && cp "$f" "$CORPUS_DIR/dyn_$(sha1sum "$f" | cut -c1-12).elf"
  done
else
  echo "==> [1] SKIP: $DYN not found"
fi

# 2) AFL/QEMU crash directories — id:* files across every out_* run
echo "==> [2] harvesting up to $N_CRASHES from out_*/**/crashes*/"
mapfile -t CRASH_FILES < <(find "$LF_ROOT" -type d -name 'crashes*' 2>/dev/null \
                             -exec find {} -maxdepth 1 -type f -name 'id:*' \; 2>/dev/null \
                           | shuf | head -n "$N_CRASHES")
for f in "${CRASH_FILES[@]:-}"; do
  [ -n "$f" ] && take "$f" "crash"
done

# 3) curated templates — always include valid baselines (keeps coverage of the
#    "well-formed" path so mutation has good starting structure)
if [ -d "$TEMPLATES" ]; then
  echo "==> [3] adding templates/*.elf"
  for f in "$TEMPLATES"/*.elf; do take "$f" "tmpl"; done
else
  echo "==> [3] SKIP: $TEMPLATES not found"
fi

TOTAL="$(ls "$CORPUS_DIR" 2>/dev/null | wc -l)"
echo
echo "──────────────────────────────────────────────────────────────────────────"
echo "seed corpus built: $CORPUS_DIR"
echo "  total files : $TOTAL   (all valid \\x7fELF)"
echo "  from dynamic : $(ls "$CORPUS_DIR" | grep -c '^dyn_')"
echo "  from crashes : $(ls "$CORPUS_DIR" | grep -c '^crash_')"
echo "  from templates: $(ls "$CORPUS_DIR" | grep -c '^tmpl_')"
echo "──────────────────────────────────────────────────────────────────────────"
echo "next:  ./build/v1_libfuzzer $CORPUS_DIR -dict=elf.dict"
echo "  or:  afl-fuzz -i $CORPUS_DIR -o out -x elf.dict -- ./build/v1_afl @@"
[ "$TOTAL" -gt 0 ] || { echo "WARNING: corpus is empty — check LF_ROOT ($LF_ROOT)"; exit 1; }
