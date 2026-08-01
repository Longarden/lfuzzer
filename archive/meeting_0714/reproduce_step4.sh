#!/usr/bin/env bash
# step4: 분석기(readelf/objdump/pyelftools) vs 디버그 ld.so 실제 처리 결과 differential 재현 스크립트
# 사용법: bash reproduce_step4.sh   (WSL Ubuntu, HOME=/home/garden 가정)
set -uo pipefail

SEED_DIR="$HOME/PE/Lfuzzer"
WORKDIR="$HOME/PE/Lfuzzer/meeting_0714_step4"
POC="$SEED_DIR/prac_extratag_poc.elf"
BASE="$SEED_DIR/prac.elf"
OUT="$WORKDIR/artifacts/repro_output.txt"
ALT_READELF="$HOME/binutils-build-afl-bfd-clean/binutils/readelf"
DBG_LDSO="$HOME/glibc/build-dbg/elf/ld.so"
DBG_LIBDIR="$HOME/glibc/build-dbg"

mkdir -p "$WORKDIR/artifacts"
: > "$OUT"

log() { echo -e "$@" | tee -a "$OUT"; }

log "=========================================="
log "0. PoC 파일 정보"
log "=========================================="
log "PoC: $POC"
file "$POC" | tee -a "$OUT"
log ""

log "=========================================="
log "1. 시스템 readelf (Ubuntu 패키지 2.42) -d 출력"
log "=========================================="
readelf -d "$POC" 2>&1 | tee -a "$OUT"
readelf --version | head -1 | tee -a "$OUT"
log ""

log "=========================================="
log "2. 별도 빌드 readelf (binutils-build-afl-bfd-clean, 소스빌드 2.42) -d 출력"
log "=========================================="
if [ -x "$ALT_READELF" ]; then
  "$ALT_READELF" -d "$POC" 2>&1 | tee -a "$OUT"
  "$ALT_READELF" --version | head -1 | tee -a "$OUT"
else
  log "[스킵] $ALT_READELF 없음"
fi
log ""

log "=========================================="
log "3. objdump -p (Dynamic Section)"
log "=========================================="
objdump -p "$POC" | sed -n '/Dynamic Section/,/^$/p' | tee -a "$OUT"
objdump --version | head -1 | tee -a "$OUT"
log ""

log "=========================================="
log "4. pyelftools 파싱 결과"
log "=========================================="
python3 "$WORKDIR/pyelftools_dump.py" "$POC" 2>&1 | tee -a "$OUT"
log ""

log "=========================================="
log "5. Ghidra headless 가용성"
log "=========================================="
if command -v analyzeHeadless >/dev/null 2>&1; then
  log "analyzeHeadless 발견됨: $(command -v analyzeHeadless)"
else
  log "[미설치] analyzeHeadless 없음 (표준 경로 및 PATH 탐색 결과 없음). 20분 초과 우려로 설치 시도는 스킵."
fi
log ""

log "=========================================="
log "6. 디버그 ld.so로 실제 실행 (분석기가 <unknown>이라 한 태그를 로더가 어떻게 다루는지)"
log "=========================================="
log "-- baseline (패치 안 한 prac.elf) --"
"$DBG_LDSO" --library-path "$DBG_LIBDIR" "$BASE" 2>&1 | tee -a "$OUT"
log "EXIT(base)=$?"
log ""
log "-- PoC (DT_DEBUG 태그를 0xDEADBEEFFFFFFFFD로 패치) --"
"$DBG_LDSO" --library-path "$DBG_LIBDIR" "$POC" 2>&1 | tee -a "$OUT"
log "EXIT(poc)=$?"
log ""

log "=========================================="
log "7. gdb로 elf_get_dynamic_info() 내부 l_info[] 슬롯 대입 시점 캡처"
log "   (get-dynamic-info.h:68 'info[i] = dyn;' 에서 i==60 조건 breakpoint)"
log "=========================================="
gdb -q --batch \
  -ex "break elf/get-dynamic-info.h:68 if i == 60" \
  -ex "run --library-path $DBG_LIBDIR $POC" \
  -ex "print i" \
  -ex "print/x dyn->d_tag" \
  -ex "print *dyn" \
  -ex "continue" \
  "$DBG_LDSO" 2>&1 | tee -a "$OUT"
log ""

log "재현 완료. 전체 로그: $OUT"
