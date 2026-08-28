#!/usr/bin/env bash
# =============================================================================
# run_campaign.sh — 3-arm 성능 비교 캠페인 (논문 표1)  [Phase 3-4 / ①②]
# =============================================================================
# 동일 SUT(계측 bfd ld) + 동일 시간예산으로 3 arm 병렬 실행:
#   A 제안       afl-fuzz + structure_aware(피드백 ON)
#   B nofeedback 동일 뮤테이터 blind 루프(§4.2 ablation)
#   C melkor     규칙기반 베이스라인(생성→ld 평가)
# 종료 후 summarize_campaign.py 로 CASR 버킷팅 + 표 생성.
#
# bound: BUDGET 초(기본 3600 = 1h, 표준논문 짧은-비교 tier). 논문 헤드라인 48h.
# 사용:
#   BUDGET=3600 ./run_campaign.sh
# =============================================================================
set -u

BUDGET="${BUDGET:-3600}"
REPO="${REPO:-/mnt/c/Users/dmsak/Desktop/01_SWSEC/lfuzzer/.claude/worktrees/cov-upgrade}"
LD="${LD:-$HOME/binutils-build-afl-bfd-clean/ld/ld-new}"
KIND="${KIND:-bfd}"       # 트리아지 버킷 접두(bfd|gold)
MELKOR="${MELKOR:-$HOME/melkor_repro/Melkor_ELF_Fuzzer/melkor}"
RUN="${RUN:-/tmp/lfuzz_run}"
SEED_SO="${SEED_SO:-$RUN/libv.so}"
MAIN_O="${MAIN_O:-$RUN/main.o}"
MELKOR_SEED="${MELKOR_SEED:-$RUN/prac.elf}"
export PYTHONPATH="$REPO"

cd "$RUN" || exit 1
mkdir -p seeds camp; cp -f "$SEED_SO" seeds/ 2>/dev/null
echo "[campaign] budget=${BUDGET}s ld=$LD"
echo "[campaign] arms: A=proposed(afl) B=nofeedback C=melkor  → 병렬"
date +"%s" > camp/start.txt

# --- Arm A: 제안 (afl-fuzz + structure_aware) -------------------------------
run_A() {
  rm -rf camp/afl_out; mkdir -p camp/afl_out
  export AFL_PYTHON_MODULE=lfuzzer.mutators.structure_aware
  export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1
  timeout "$BUDGET" afl-fuzz -i seeds -o camp/afl_out \
      -- "$LD" -shared -o /dev/null "$MAIN_O" @@ > camp/A_afl.log 2>&1
  echo "A_done" > camp/A.done
}

# --- Arm B: no-feedback (동일 뮤테이터 blind) --------------------------------
run_B() {
  python3 -m lfuzzer.coverage.run_nofeedback --target bfd --ld "$LD" \
      --main-o "$MAIN_O" --seeds seeds --out camp/nofb_crashes \
      --seconds "$BUDGET" > camp/B_nofb.log 2>&1
  echo "B_done" > camp/B.done
}

# --- Arm C: Melkor (생성 → ld 평가) -----------------------------------------
run_C() {
  local end=$(( $(date +%s) + BUDGET ))
  local ev=0 cr=0
  rm -rf camp/melkor_crashes; mkdir -p camp/melkor_crashes camp/melkor_gen
  cd camp/melkor_gen
  while [ "$(date +%s)" -lt "$end" ]; do
    rm -rf orcs_*; "$MELKOR" -A -n 200 "$MELKOR_SEED" >/dev/null 2>&1
    for orc in orcs_*/*; do
      [ -f "$orc" ] || continue
      [ "$(date +%s)" -lt "$end" ] || break
      timeout 3 "$LD" -shared -o /dev/null "$MAIN_O" "$orc" >/dev/null 2>&1
      rc=$?; ev=$((ev+1))
      # 음수(128+sig)/timeout(124) → 크래시. bash 는 sig 를 128+n 로 준다.
      if [ "$rc" -ge 128 ] || [ "$rc" -eq 124 ]; then
        cp "$orc" "../melkor_crashes/mk_${ev}_rc${rc}.elf" 2>/dev/null
        cr=$((cr+1))
      fi
    done
  done
  cd "$RUN"
  echo "execs=$ev crashes=$cr" > camp/C_melkor.log
  echo "C_done" > camp/C.done
}

run_A & PA=$!
run_B & PB=$!
run_C & PC=$!
echo "[campaign] launched PIDs A=$PA B=$PB C=$PC ; 대기(${BUDGET}s)..."
wait "$PA" "$PB" "$PC"
date +"%s" > camp/end.txt
echo "[campaign] 3 arm 종료. 요약 생성..."
python3 -m lfuzzer.coverage.summarize_campaign --run "$RUN" --ld "$LD" --main-o "$MAIN_O" \
    --kind "$KIND" > camp/REPORT.md 2>camp/summarize.err || cat camp/summarize.err
echo "[campaign] REPORT: $RUN/camp/REPORT.md"
cat camp/REPORT.md
