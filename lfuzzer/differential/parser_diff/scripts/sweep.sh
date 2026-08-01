#!/bin/bash
# ELF 파서 코퍼스 리플레이 하네스 (읽기전용)
OUT=/tmp/parser_sweep
RESULTS="$OUT/results.tsv"
CORPUS=(/home/garden/PE/Lfuzzer/crashes /home/garden/PE/Lfuzzer/classified_crashes)
: > "$RESULTS"

check_one() {
  local f="$1"
  # name::command 쌍
  local specs=("readelf::readelf -a" "objdumpx::objdump -x" "objdumpd::objdump -d" "nm::nm -a" "llvmobjdump::llvm-objdump -x")
  for spec in "${specs[@]}"; do
    local name="${spec%%::*}"; local cmd="${spec##*::}"
    ( ulimit -v 3000000 2>/dev/null; timeout -s KILL 5 $cmd "$f" ) >/dev/null 2>&1
    local rc=$?
    # 크래시 신호만: 124=timeout, 137=kill(timeout강제/OOM), 139=SEGV, 134=ABRT, 136=FPE, 132=ILL, 138=BUS
    if [ "$rc" -eq 124 ] || [ "$rc" -ge 128 ]; then
      printf "%s\t%s\t%s\n" "$name" "$rc" "$f"
    fi
  done
}
export -f check_one

find "${CORPUS[@]}" -type f -print0 2>/dev/null \
  | xargs -0 -P "$(nproc)" -I{} bash -c "check_one \"\$1\"" _ {} \
  >> "$RESULTS"
echo "DONE" > "$OUT/sweep.done"
wc -l "$RESULTS"
