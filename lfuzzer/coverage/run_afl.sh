#!/usr/bin/env bash
# =============================================================================
# run_afl.sh — 커버리지 가이드 퍼징(afl 엔진) 구동  [Phase 4 / ②]
# =============================================================================
# 결정(2026-08-28 deep-dive):
#   SUT      = GNU ld(bfd) + gold  (둘 다 afl 계측 빌드 존재)
#   엔진     = afl-fuzz + structure_aware 커스텀뮤테이터 + elf.dict + cmplog
#   피드백   = afl 커버리지 비트맵(큐/energy 는 afl 제공)
#
# 계측 빌드(WSL, 이미 존재):
#   bfd  : ~/binutils-build-afl-bfd/ld/ld-new
#   gold : ~/binutils-build-afl-gold-clean/gold/ld-new
#
# 이 스크립트는 afl-fuzz 를 '진짜 링커' 에 물린다. 변이 대상은 링커가 입력으로
# 읽는 손상된 공유객체(libv_corrupt.so 계열, exp_e4_verneed 참고)이고, afl 의
# @@ 가 그 입력 파일 자리에 들어간다.
#
# 사용:
#   ./run_afl.sh bfd           # bfd ld 대상
#   ./run_afl.sh gold          # gold 대상
#   SEEDS=path OUT=path ./run_afl.sh bfd
# =============================================================================
set -euo pipefail

TARGET="${1:-bfd}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"          # lfuzzer-clean 루트

# --- 계측 링커 경로(결정된 빌드) --------------------------------------------
case "$TARGET" in
  bfd)  LD_BIN="${LD_BFD:-$HOME/binutils-build-afl-bfd/ld/ld-new}"; LDFLAG="";;
  gold) LD_BIN="${LD_GOLD:-$HOME/binutils-build-afl-gold-clean/gold/ld-new}"; LDFLAG="";;
  *) echo "usage: $0 {bfd|gold}"; exit 2;;
esac
[ -x "$LD_BIN" ] || { echo "계측 링커 없음: $LD_BIN (binutils afl 빌드 확인)"; exit 1; }

# --- 입출력 -----------------------------------------------------------------
SEEDS="${SEEDS:-$REPO_ROOT/seeds_so}"           # 유효 .so 시드 풀(전략1 산출물)
OUT="${OUT:-$REPO_ROOT/afl_out_$TARGET}"
DICT="${DICT:-$HERE/elf.dict}"
WORK="${WORK:-$REPO_ROOT/afl_work_$TARGET}"

# --- elf.dict 생성(numbers.py → dict) ---------------------------------------
if [ ! -f "$DICT" ]; then
  echo "[dict] 생성: $DICT"
  ( cd "$REPO_ROOT" && python3 -m lfuzzer.coverage.gen_afl_dict "$DICT" )
fi

# --- 링커 래퍼: afl @@ 를 '손상 라이브러리' 자리에 물린다 --------------------
# exp_e4_verneed 패턴: ld -shared -o /dev/null main.o -L. -l<corrupt>
# 여기선 @@(변이 .so)를 직접 입력으로 넘긴다. main.o 는 고정 유효 오브젝트.
mkdir -p "$WORK"
MAIN_O="${MAIN_O:-$WORK/main.o}"
if [ ! -f "$MAIN_O" ]; then
  printf 'extern int bar(); int _start(){ return bar(); }\n' > "$WORK/main.c"
  gcc -c -fPIC -nostdlib -o "$MAIN_O" "$WORK/main.c" 2>/dev/null || \
    { echo "main.o 빌드 실패 — MAIN_O 를 직접 지정하세요"; exit 1; }
fi
WRAP="$WORK/ld_target.sh"
cat > "$WRAP" <<WRAPEOF
#!/usr/bin/env bash
# afl 이 넘긴 변이 파일(\$1)을 링커 입력으로 물린다. 계측 forkserver 는
# exec 된 ld-new 안에 있으므로 afl 이 커버리지를 정상 수집한다.
exec "$LD_BIN" $LDFLAG -shared -o /dev/null "$MAIN_O" "\$1" 2>/dev/null
WRAPEOF
chmod +x "$WRAP"

[ -d "$SEEDS" ] || { echo "시드 폴더 없음: $SEEDS (유효 .so 를 넣으세요)"; exit 1; }

# --- afl 환경(구조인식 커스텀뮤테이터 + cmplog) -----------------------------
export AFL_PYTHON_MODULE=lfuzzer.mutators.structure_aware
export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
export AFL_CUSTOM_MUTATOR_ONLY="${AFL_CUSTOM_MUTATOR_ONLY:-0}"   # havoc 병행(0) / 전용(1)
export AFL_DISABLE_TRIM=1
export AFL_SKIP_CPUFREQ=1

echo "[afl] target=$TARGET  ld=$LD_BIN"
echo "[afl] mutator=structure_aware  dict=$DICT  seeds=$SEEDS  out=$OUT"
echo "[afl] cmplog=on(-c 0)  피드백=ON(커버리지 가이드)"

# -c 0 : cmplog(RedQueen) — magic/비교상수 통과 상보
exec afl-fuzz -i "$SEEDS" -o "$OUT" -x "$DICT" -c 0 -- "$WRAP" @@
