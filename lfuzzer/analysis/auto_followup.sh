#!/bin/bash
# QEMU+v2 fuzz 끝난 후 자동 후속 진행
set -u
SRC_BASE=/home/garden/PE/Lfuzzer/out_qemu_v2
DEST=/home/garden/PE/Lfuzzer/classified_qemu_v2
LD=/lib64/ld-linux-x86-64.so.2
REPORT=/home/garden/PE/Lfuzzer/auto_followup_report.txt
REP=/home/garden/PE/Lfuzzer/representatives_v2

> $REPORT
exec > >(tee -a $REPORT) 2>&1

echo "============================================"
echo "  QEMU+v2 fuzz 자동 후속 진행"
echo "============================================"
echo ""

# 1. 통합 분류
echo "[1] hangs 통합 분류"
rm -rf $DEST
mkdir -p $DEST
total=0; real_crash=0; real_hang=0; other=0
for sub in main qsub1 qsub2; do
    DIR=$SRC_BASE/$sub/hangs
    [ ! -d "$DIR" ] && continue
    for f in $DIR/id:*; do
        [ ! -f "$f" ] && continue
        total=$((total+1))
        timeout 2 $LD "$f" > /dev/null 2>&1
        rc=$?
        case $rc in
            139)
                real_crash=$((real_crash+1))
                cp "$f" "$DEST/${sub}_$(basename "$f")"
                ;;
            124) real_hang=$((real_hang+1)) ;;
            *)   other=$((other+1)) ;;
        esac
    done
done
echo "  total: $total / crashes: $real_crash / hangs: $real_hang / other: $other"
echo ""

# 2. si_code 분포
echo "[2] si_code 분포 (sample 100)"
ls $DEST 2>/dev/null | shuf -n 100 | while read fn; do
    timeout 2 $LD "$DEST/$fn" 2>&1 | grep -oE 'si_code=[A-Z_]+' | head -1
done | sort | uniq -c | sort -rn | awk '{printf "  %s : %s\n", $2, $1}'
echo ""

# 2b. si_addr 분포
echo "[2b] si_addr 분포 (sample 100)"
ls $DEST 2>/dev/null | shuf -n 100 | while read fn; do
    out=$(timeout 2 $LD "$DEST/$fn" 2>&1 | grep -oE 'si_addr=0x[0-9a-f]+' | head -1)
    [ -z "$out" ] && continue
    val=$(echo "$out" | grep -oE '0x[0-9a-f]+')
    n=$((val))
    if   [ $n -lt 256 ]; then echo "NULL+small"
    elif [ $n -lt 65536 ]; then echo "NULL+medium"
    elif [ $n -lt 16777216 ]; then echo "small_int"
    else echo "large_addr"
    fi
done | sort | uniq -c | sort -rn | awk '{printf "  %s : %s\n", $2, $1}'
echo ""

# 3. 패밀리 대표 추출
echo "[3] 패밀리 대표 추출"
rm -rf $REP
mkdir -p $REP
pn=""; pl=""; pa=""; pk=""
for f in $DEST/*; do
    [ ! -f "$f" ] && continue
    info=$(timeout 2 $LD "$f" 2>&1 | grep -oE 'si_code=[A-Z_]+.*si_addr=0x[0-9a-f]+' | head -1)
    [ -z "$info" ] && continue
    code=$(echo "$info" | grep -oE 'si_code=[A-Z_]+' | head -1)
    addr_hex=$(echo "$info" | grep -oE 'si_addr=0x[0-9a-f]+' | grep -oE '0x[0-9a-f]+')
    ai=$((addr_hex))
    [ -z "$pn" ] && [ "$code" = "si_code=SEGV_MAPERR" ] && [ $ai -lt 256 ] && { cp "$f" "$REP/family1_v2.elf"; pn="$(basename $f)"; }
    [ -z "$pl" ] && [ "$code" = "si_code=SEGV_MAPERR" ] && [ $ai -ge 16777216 ] && { cp "$f" "$REP/family2_v2.elf"; pl="$(basename $f)"; }
    [ -z "$pa" ] && [ "$code" = "si_code=SEGV_ACCERR" ] && { cp "$f" "$REP/family3_v2.elf"; pa="$(basename $f)"; }
    [ -z "$pk" ] && [ "$code" = "si_code=SI_KERNEL" ] && { cp "$f" "$REP/family4_v2.elf"; pk="$(basename $f)"; }
    [ -n "$pn" ] && [ -n "$pl" ] && [ -n "$pa" ] && [ -n "$pk" ] && break
done
echo "  family1 (NULL+small) : $pn"
echo "  family2 (large_addr) : $pl"
echo "  family3 (ACCERR)     : $pa"
echo "  family4 (SI_KERNEL)  : $pk"
echo ""

# 4. gdb bt
echo "[4] gdb backtrace 분석"
for n in 1 2 3 4; do
    f="$REP/family${n}_v2.elf"
    [ ! -f "$f" ] && { echo "  family$n SKIP"; continue; }
    echo ""
    echo "  ── family$n ──"
    timeout 8 gdb -batch -q -ex 'set pagination off' -ex "run $f" -ex 'bt 10' --args $LD "$f" 2>&1 \
        | grep -E '^#|Program received|si_addr' | head -10 | sed 's/^/    /'
done

echo ""
echo "============================================"
echo "  완료. 보고서: $REPORT"
echo "============================================"
