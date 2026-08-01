#!/bin/bash
# ASAN readelf/objdump 로 silent OOB 사냥 (build.done 후 실행)
set -u
RE=/tmp/bsrc/binutils/readelf
OD=/tmp/bsrc/binutils/objdump
CORP=/tmp/parser_sweep/corpus
OUT=/tmp/asan_sweep; mkdir -p "$OUT/reports"
HITS="$OUT/hits.tsv"; : > "$HITS"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=86:handle_abort=1"
# 코퍼스 없으면 재스테이징 스킵 — 있는 것만
[ -d "$CORP" ] || { echo "corpus 없음(재부팅?) — 재생성 필요"; exit 2; }

check() {
  local f="$1"
  for pair in "RE::$RE::-a" "OD::$OD::-x"; do
    local nm="${pair%%::*}"; local rest="${pair#*::}"; local bin="${rest%%::*}"; local opt="${rest##*::}"
    local err; err=$(timeout -s KILL 15 "$bin" "$opt" "$f" 2>&1 >/dev/null); local rc=$?
    if [ "$rc" -eq 86 ] || [ "$rc" -ge 128 ] || echo "$err" | grep -q "ERROR: AddressSanitizer"; then
      local sig; sig=$(echo "$err" | grep -m1 -E "ERROR: AddressSanitizer|SUMMARY:")
      printf "%s\t%s\t%s\t%s\n" "$nm" "$rc" "$f" "$sig" >> "$HITS"
      # ASAN 리포트 저장 (파일별)
      echo "$err" > "$OUT/reports/$(basename "$f").$nm.txt"
    fi
  done
}
export -f check; export RE OD HITS OUT ASAN_OPTIONS
N=$(find "$CORP" -type f | wc -l)
echo "ASAN 스윕 시작: $N 파일 x 2도구 (readelf/objdump ASAN)"
find "$CORP" -type f -print0 | xargs -0 -P 4 -I{} bash -c "check \"\$1\"" _ {}
echo "완료. hits: $(wc -l < "$HITS")"
echo "유니크 ASAN 서명:"; cut -f4 "$HITS" | sort | uniq -c | sort -rn | head
echo DONE > "$OUT/sweep.done"
