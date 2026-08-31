#!/usr/bin/env bash
# =============================================================================
# run_campaign.sh — blind 성능 비교 캠페인 (afl 제거판)
# =============================================================================
# afl 없이(coverage-guided 아님) 무작위 blind 변이로 두 arm 병렬 실행 후
# CASR 버킷팅 표 생성. 원본 77버킷 파이프라인과 같은 blind 철학.
#   A 제안(blind)  structure_aware 4축 뮤테이터 blind 루프(run_nofeedback)
#   B Melkor       규칙기반 생성 → 링커 평가
# 종료 후 summarize_campaign.py 로 CASR 버킷팅.
#
# ⚠ WSL2: /tmp 는 tmpfs → distro 셧다운 시 소실. RUN 은 영속 경로(~/lfuzz_run) 사용.
# 사용:  BUDGET=1800 KIND=gold LD=<링커> RUN=~/lfuzz_run bash run_campaign.sh
# =============================================================================
set -u

BUDGET="${BUDGET:-1800}"
REPO="${REPO:-/mnt/c/Users/dmsak/Desktop/01_SWSEC/lfuzzer/.claude/worktrees/cov-upgrade}"
LD="${LD:-$HOME/binutils-build-afl-bfd-clean/ld/ld-new}"
KIND="${KIND:-bfd}"
MELKOR="${MELKOR:-$HOME/melkor_repro/Melkor_ELF_Fuzzer/melkor}"
RUN="${RUN:-$HOME/lfuzz_run}"
SEED_SO="${SEED_SO:-$RUN/libv.so}"
MAIN_O="${MAIN_O:-$RUN/main.o}"
MELKOR_SEED="${MELKOR_SEED:-$RUN/prac.elf}"
export PYTHONPATH="$REPO"

cd "$RUN" || exit 1
mkdir -p seeds camp; cp -f "$SEED_SO" seeds/ 2>/dev/null
echo "[campaign/blind] budget=${BUDGET}s ld=$LD (afl 없음, 무작위 blind)"
date +"%s" > camp/start.txt

# --- Arm A: 제안(blind) = structure_aware 4축 뮤테이터, 피드백 없음 ---------
run_A() {
  python3 -m lfuzzer.coverage.run_nofeedback --target "$KIND" --ld "$LD" \
      --main-o "$MAIN_O" --seeds seeds --out camp/proposed_crashes \
      --seconds "$BUDGET" > camp/A_proposed.log 2>&1
  echo done > camp/A.done
}

# --- Arm B: Melkor (생성 → 링커 평가) ---------------------------------------
run_B() {
  local end=$(( $(date +%s) + BUDGET )); local ev=0 cr=0
  rm -rf camp/melkor_crashes camp/melkor_gen; mkdir -p camp/melkor_crashes camp/melkor_gen
  cd camp/melkor_gen
  while [ "$(date +%s)" -lt "$end" ]; do
    rm -rf orcs_*; "$MELKOR" -A -n 200 "$MELKOR_SEED" >/dev/null 2>&1
    for orc in orcs_*/*; do
      [ -f "$orc" ] || continue
      [ "$(date +%s)" -lt "$end" ] || break
      timeout 3 "$LD" -shared -o /dev/null "$MAIN_O" "$orc" >/dev/null 2>&1
      rc=$?; ev=$((ev+1))
      if [ "$rc" -ge 128 ] || [ "$rc" -eq 124 ]; then
        cp "$orc" "../melkor_crashes/mk_${ev}_rc${rc}.elf" 2>/dev/null; cr=$((cr+1))
      fi
    done
  done
  cd "$RUN"; echo "execs=$ev crashes=$cr" > camp/C_melkor.log; echo done > camp/B.done
}

run_A & PA=$!
run_B & PB=$!
echo "[campaign/blind] launched A(proposed-blind)=$PA B(melkor)=$PB ; 대기(${BUDGET}s)..."
wait "$PA" "$PB"
date +"%s" > camp/end.txt
echo "[campaign/blind] 종료. CASR 요약..."
python3 -m lfuzzer.coverage.summarize_campaign --run "$RUN" --ld "$LD" --main-o "$MAIN_O" \
    --kind "$KIND" --blind > camp/REPORT.md 2>camp/summarize.err || cat camp/summarize.err
echo "[campaign/blind] REPORT: $RUN/camp/REPORT.md"; cat camp/REPORT.md
