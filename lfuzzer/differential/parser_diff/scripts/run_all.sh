#!/bin/bash
set -u
BASE=/tmp/parser_sweep
STAGE=$BASE/corpus
RESULTS=$BASE/results.tsv
LOG=$BASE/progress.log
mkdir -p "$STAGE"
: > "$RESULTS"; : > "$LOG"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# ---- 1) 스테이징 (ELF 소스 → ext4) ----
declare -A SRC=(
 [wsl_seg_crashes]=/home/garden/PE/Lfuzzer/crashes
 [wsl_classified]=/home/garden/PE/Lfuzzer/classified_crashes
 [wsl_overlap]=/home/garden/PE/Lfuzzer/crashes_overlap
 [wsl_in_elf]=/home/garden/PE/Lfuzzer/in_elf
 [wsl_in_elf_v2]=/home/garden/PE/Lfuzzer/in_elf_v2
 [wsl_in_seed]=/home/garden/PE/Lfuzzer/in_seed
 [wsl_verneed]=/home/garden/PE/Lfuzzer/exp_e4_verneed
 [wsl_exploit]=/home/garden/PE/Lfuzzer/exploit_test
 [win_field_perm]=/mnt/c/Users/dmsak/Desktop/pe/crashes_perm
 [win_crashes]=/mnt/c/Users/dmsak/Desktop/pe/crashes
 [win_boundary]=/mnt/c/Users/dmsak/Desktop/pe/crashes_boundary
 [win_aflelf]=/mnt/c/Users/dmsak/Desktop/AFL_ELF_Fuzzing
 [win_ref]=/mnt/c/Users/dmsak/Desktop/elf_fuzzer_ref
)
for tag in "${!SRC[@]}"; do
  src="${SRC[$tag]}"
  [ -d "$src" ] || { log "skip $tag (없음)"; continue; }
  mkdir -p "$STAGE/$tag"
  cp -a "$src/." "$STAGE/$tag/" 2>/dev/null
  log "staged $tag : $(find "$STAGE/$tag" -type f | wc -l) files"
done
TOTAL=$(find "$STAGE" -type f | wc -l)
log "TOTAL staged files: $TOTAL"

# ---- 2) ELF만 필터해서 리스트 작성 ----
FILELIST=$BASE/elf_files.txt
find "$STAGE" -type f -print0 | xargs -0 -P "$(nproc)" -I{} bash -c \
  'f="$1"; [ "$(head -c4 "$f" 2>/dev/null | xxd -p)" = "7f454c46" ] && echo "$f"' _ {} > "$FILELIST"
NELF=$(wc -l < "$FILELIST")
log "ELF-magic files: $NELF (스윕 대상)"

# ---- 3) 파서 리플레이 스윕 ----
check_one() {
  local f="$1"
  local specs=("readelf::readelf -a" "objdumpx::objdump -x" "objdumpd::objdump -d" "nm::nm -aD" "llvmobjdump::llvm-objdump -x")
  for spec in "${specs[@]}"; do
    local name="${spec%%::*}"; local cmd="${spec##*::}"
    ( ulimit -v 3000000 2>/dev/null; timeout -s KILL 5 $cmd "$f" ) >/dev/null 2>&1
    local rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -ge 128 ]; then
      printf "%s\t%s\t%s\n" "$name" "$rc" "$f"
    fi
  done
}
export -f check_one
log "sweep 시작 ($NELF files x 5 parsers)"
xargs -a "$FILELIST" -P "$(nproc)" -I{} bash -c "check_one \"\$1\"" _ {} >> "$RESULTS"
log "sweep 완료: $(wc -l < "$RESULTS") crash-hits"
echo DONE > "$BASE/sweep.done"
