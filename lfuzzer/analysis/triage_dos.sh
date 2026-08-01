#!/bin/bash
# DoS 451 건의 트리아지:
#  1. 시드 카테고리별 분포 (어느 변형에서 출발했나)
#  2. PHT 구조 분포 (LOAD 개수, 슬롯 순서)
#  3. strace 마지막 syscall 패턴 (어디서 무한 처리)
LD=/lib64/ld-linux-x86-64.so.2
OUT=/home/garden/PE/Lfuzzer/out_qemu_v2
QV2=/home/garden/PE/Lfuzzer/in_elf_v2
REPORT=/home/garden/PE/Lfuzzer/triage_dos_report.txt
WORK=/tmp/dos_triage

rm -rf $WORK
mkdir -p $WORK

# 모든 hangs (DoS 의심) 절대경로 수집
> $WORK/list
for sub in main qsub1 qsub2 default; do
    [ -d "$OUT/$sub/hangs" ] && ls "$OUT/$sub/hangs"/id:* 2>/dev/null >> $WORK/list
done
total=$(wc -l < $WORK/list)

{
echo "=================================="
echo "  DoS 451 건 트리아지 (총 $total)"
echo "=================================="

# ─── 1. 시드 출처 추적 ───
echo ""
echo "[1] AFL queue 의 시드 출처 (src 번호)"
echo "    → AFL 의 queue 안 시드 N 번이 출발선"
cat $WORK/list | while read f; do
    basename "$f"
done | grep -oE 'src:[0-9]+' | sort | uniq -c | sort -rn | head -15 | \
awk '{printf "    %5d  %s\n", $1, $2}'

# ─── 2. PHT 구조 분포 ───
echo ""
echo "[2] PHT 구조 (LOAD 개수)"
cat $WORK/list | xargs -I{} -P 16 bash -c '
    readelf -lW "$1" 2>/dev/null | grep -c "^  LOAD"
' _ {} | sort | uniq -c | sort -rn | head -10 | \
awk '{printf "    LOAD %s개 : %s 파일\n", $2, $1}'

# ─── 3. 첫 슬롯이 무엇인지 ───
echo ""
echo "[3] PHT 첫 슬롯 종류 (대부분 PHDR 정상 vs 변형)"
cat $WORK/list | xargs -I{} -P 16 bash -c '
    readelf -lW "$1" 2>/dev/null | grep -E "^  (PHDR|LOAD|INTERP|DYNAMIC|NOTE|GNU_)" | head -1 | awk "{print \$1}"
' _ {} | sort | uniq -c | sort -rn | head | \
awk '{printf "    %-15s : %s\n", $2, $1}'

# ─── 4. 마지막 syscall 패턴 (sample 60) ───
echo ""
echo "[4] strace 마지막 syscall (sample 60, timeout 3초)"
shuf -n 60 $WORK/list | xargs -I{} -P 16 bash -c '
    timeout 3 strace '$LD' "$1" 2>&1 | grep -oE "^[a-z_]+\(" | tail -3 | tr -d "(" | tr "\n" "," | sed "s/,$//"
    echo ""
' _ {} | sort | uniq -c | sort -rn | head -15 | \
awk '{printf "    %4d  %s %s %s\n", $1, $2, $3, $4}'

# ─── 5. 반복 syscall 검출 (loop 시그널) ───
echo ""
echo "[5] strace 의 같은 syscall 5회 이상 반복 (loop 시그널, sample 30)"
shuf -n 30 $WORK/list | xargs -I{} -P 16 bash -c '
    out=$(timeout 3 strace '$LD' "$1" 2>&1 | grep -oE "^[a-z_]+\(" | head -100)
    # 같은 syscall 5회 이상 반복하면 loop 후보
    echo "$out" | uniq -c | sort -rn | head -1
' _ {} 2>/dev/null | awk '$1>=5 {print $2}' | sort | uniq -c | sort -rn | head | \
awk '{printf "    %4d  %s 반복 (loop 후보)\n", $1, $2}'

# ─── 6. 결정타: ELF 의 PT_DYNAMIC 안 DT_NEEDED 개수 ───
echo ""
echo "[6] DT_NEEDED 개수 분포 (라이브러리 의존성 폭주 후보)"
cat $WORK/list | xargs -I{} -P 16 bash -c '
    readelf -dW "$1" 2>/dev/null | grep -c "NEEDED"
' _ {} 2>/dev/null | sort | uniq -c | sort -rn | head | \
awk '{printf "    DT_NEEDED %s개 : %s 파일\n", $2, $1}'

echo ""
echo "=================================="
echo "  보고서: $REPORT"
echo "=================================="
} | tee $REPORT
