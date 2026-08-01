#!/bin/bash
# 멀티 fuzz 결과 (main+sub1+sub2+sub3) 의 hangs 를 통합 분류
LD=/lib64/ld-linux-x86-64.so.2
OUT=/home/garden/PE/Lfuzzer/out_multi
DEST=/home/garden/PE/Lfuzzer/classified_multi

rm -rf $DEST
mkdir -p $DEST

real_crash=0
real_hang=0
other=0
total=0

for sub in main sub1 sub2 sub3; do
    DIR=$OUT/$sub/hangs
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

echo "=== Multi-fuzz classification ==="
echo "total examined          : $total"
echo "real crashes (SIGSEGV)  : $real_crash"
echo "real hangs (timeout)    : $real_hang"
echo "other exit codes        : $other"
echo ""
echo "real crashes saved at: $DEST"
ls $DEST 2>/dev/null | wc -l
