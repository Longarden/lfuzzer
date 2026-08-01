#!/bin/bash
# 478개 SIGSEGV 를 세 가지 차원으로 분류:
#  1. 파일 크기 분포 (변형 패턴 힌트)
#  2. PHT (LOAD 개수, PHDR 위치) 구조 분포
#  3. ld.so 실행 직전 마지막 syscall (어느 단계서 죽음)

SRC=~/PE/Lfuzzer/classified_crashes
LD=/lib64/ld-linux-x86-64.so.2
OUT=~/PE/Lfuzzer/triage_report.txt

> $OUT

total=$(ls $SRC | wc -l)
echo "==============================" | tee -a $OUT
echo "  TRIAGE REPORT (total: $total)" | tee -a $OUT
echo "==============================" | tee -a $OUT
echo "" | tee -a $OUT

# ─────────────────────────────────────────────
# 1. 파일 크기 분포
# ─────────────────────────────────────────────
echo "[1] 파일 크기 분포 (bytes)" | tee -a $OUT
echo "------------------------------" | tee -a $OUT
for f in $SRC/*; do
    [ -f "$f" ] && stat -c '%s' "$f"
done | awk '
{
    if ($1 < 1000) b["    < 1KB"]++
    else if ($1 < 5000) b[" 1~5 KB"]++
    else if ($1 < 10000) b[" 5~10KB"]++
    else if ($1 < 20000) b["10~20KB"]++
    else b["   >20KB"]++
}
END { for (k in b) printf "  %-10s : %d\n", k, b[k] }
' | sort | tee -a $OUT
echo "" | tee -a $OUT

# ─────────────────────────────────────────────
# 2. PHT 구조 분포
# ─────────────────────────────────────────────
echo "[2] PHT 구조 (LOAD 개수 기준)" | tee -a $OUT
echo "------------------------------" | tee -a $OUT
for f in $SRC/*; do
    [ ! -f "$f" ] && continue
    n=$(readelf -lW "$f" 2>/dev/null | grep -c '^  LOAD')
    echo "$n"
done | sort | uniq -c | sort -rn | head -10 | awk '{printf "  LOAD %s개 : %s개 파일\n", $2, $1}' | tee -a $OUT
echo "" | tee -a $OUT

# ─────────────────────────────────────────────
# 3. 마지막 syscall (sample 50개만 — 478개 다 돌면 15분)
# ─────────────────────────────────────────────
echo "[3] 마지막 syscall 분포 (sample 50개)" | tee -a $OUT
echo "------------------------------" | tee -a $OUT
ls $SRC | head -50 | while read fname; do
    f=$SRC/$fname
    [ ! -f "$f" ] && continue
    last=$(timeout 2 strace $LD "$f" 2>&1 | grep -oE '^[a-z_]+\(' | tail -1 | tr -d '(' )
    [ -z "$last" ] && last="(none)"
    echo "$last"
done | sort | uniq -c | sort -rn | head -10 | awk '{printf "  %-20s : %s회\n", $2, $1}' | tee -a $OUT
echo "" | tee -a $OUT

# ─────────────────────────────────────────────
# 4. 대표 SIGSEGV 1개 직접 보기
# ─────────────────────────────────────────────
SAMPLE=$(ls $SRC | head -1)
echo "[4] 대표 SIGSEGV 한 개 분석" | tee -a $OUT
echo "------------------------------" | tee -a $OUT
echo "  파일: $SAMPLE" | tee -a $OUT
echo "  PHT:" | tee -a $OUT
readelf -lW $SRC/$SAMPLE 2>/dev/null | grep -E 'Type|LOAD|PHDR|INTERP|DYNAMIC' | head -10 | sed 's/^/    /' | tee -a $OUT
echo "" | tee -a $OUT
echo "  마지막 syscall 직전:" | tee -a $OUT
timeout 2 strace $LD $SRC/$SAMPLE 2>&1 | tail -8 | sed 's/^/    /' | tee -a $OUT
echo "" | tee -a $OUT

echo "==============================" | tee -a $OUT
echo "  보고서 저장 위치: $OUT" | tee -a $OUT
echo "==============================" | tee -a $OUT
