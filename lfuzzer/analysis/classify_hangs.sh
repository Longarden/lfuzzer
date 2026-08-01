#!/bin/bash
LD=/lib64/ld-linux-x86-64.so.2
OUT=~/PE/Lfuzzer/out_dl_qemu_v2
DEST=~/PE/Lfuzzer/classified_crashes

rm -rf $DEST
mkdir -p $DEST

real_crash=0
real_hang=0
other=0
total=0

for sub in default sub1 sub2 sub3 sub4 sub5; do
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

echo "=== summary ==="
echo "total examined          : $total"
echo "real crashes (SIGSEGV)  : $real_crash"
echo "real hangs (timeout)    : $real_hang"
echo "other exit codes        : $other"
echo ""
echo "real crashes saved at: $DEST"
ls $DEST 2>/dev/null | wc -l
