#!/bin/bash
# 100개 sample 의 si_addr 와 si_code 분포 — "진짜 다른 버그 몇 개" 추정
SRC=~/PE/Lfuzzer/classified_crashes
LD=/lib64/ld-linux-x86-64.so.2

echo "=============================="
echo "  si_addr + si_code 분포 (sample 100)"
echo "=============================="
echo ""

echo "[A] si_code (SIGSEGV 종류) 분포"
echo "------------------------------"
ls $SRC | shuf -n 100 | while read fname; do
    timeout 2 strace $LD "$SRC/$fname" 2>&1 | grep -oE 'si_code=[A-Z_]+' | head -1
done | sort | uniq -c | sort -rn | awk '{printf "  %-20s : %s회\n", $2, $1}'

echo ""
echo "[B] si_addr 분포 (NULL 근처 vs 큰 주소)"
echo "------------------------------"
ls $SRC | shuf -n 100 | while read fname; do
    addr=$(timeout 2 strace $LD "$SRC/$fname" 2>&1 | grep -oE 'si_addr=0x[0-9a-f]+' | head -1)
    [ -z "$addr" ] && continue
    val=$(echo "$addr" | grep -oE '0x[0-9a-f]+')
    n=$((val))
    if   [ $n -eq 0 ]; then echo "NULL"
    elif [ $n -lt 256 ]; then echo "NULL+small (0~0xff)"
    elif [ $n -lt 65536 ]; then echo "NULL+medium (0x100~0xffff)"
    elif [ $n -lt 16777216 ]; then echo "small_int (0x10000~0xffffff)"
    else echo "large_addr (>0x1000000)"
    fi
done | sort | uniq -c | sort -rn | awk '{printf "  %-30s : %s회\n", $2 " " $3, $1}'

echo ""
echo "[C] 종합 — 진짜 다른 패턴 수 추정"
echo "------------------------------"
ls $SRC | shuf -n 100 | while read fname; do
    timeout 2 strace $LD "$SRC/$fname" 2>&1 | grep -oE 'si_code=[A-Z_]+.*si_addr=0x[0-9a-f]+' | head -1
done | sort | uniq -c | sort -rn | head -10 | awk '{printf "  [%s회] %s %s\n", $1, $2, $3}'
