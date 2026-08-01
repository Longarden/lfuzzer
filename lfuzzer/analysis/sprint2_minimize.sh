#!/bin/bash
# Sprint 2: 4 패밀리 대표 ELF 를 afl-tmin 으로 최소화
# 같은 SIGSEGV 유지하면서 입력 크기 줄임
SRC=~/PE/Lfuzzer/representatives
DEST=~/PE/Lfuzzer/minimal_repros
LD=/lib64/ld-linux-x86-64.so.2
TMIN=~/AFLplusplus/afl-tmin

rm -rf $DEST
mkdir -p $DEST

for fname in family1_null_deref family2_garbage_ptr family3_perm_violation family4_si_kernel; do
    in_file="$SRC/${fname}.elf"
    out_file="$DEST/${fname}_min.elf"

    [ ! -f "$in_file" ] && { echo "SKIP $fname (no source)"; continue; }

    echo ""
    echo "=== Minimizing $fname ==="
    orig_size=$(stat -c '%s' "$in_file")
    echo "Original size: $orig_size bytes"

    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    timeout 300 $TMIN -Q -i "$in_file" -o "$out_file" \
        -- $LD @@ 2>&1 | tail -10

    if [ -f "$out_file" ]; then
        min_size=$(stat -c '%s' "$out_file")
        echo "→ Minimized: $min_size bytes (orig $orig_size)"
    fi
done

echo ""
echo "=== Sprint 2: minimal repro 4종 완료 ==="
ls -la $DEST
