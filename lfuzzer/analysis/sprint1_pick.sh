#!/bin/bash
# Sprint 1: 478개 SIGSEGV 중 4 패밀리 대표 1개씩 추출
SRC=~/PE/Lfuzzer/classified_crashes
DEST=~/PE/Lfuzzer/representatives
LD=/lib64/ld-linux-x86-64.so.2

rm -rf $DEST
mkdir -p $DEST

picked_null=""
picked_large=""
picked_accerr=""
picked_kernel=""

for f in $SRC/*; do
    [ ! -f "$f" ] && continue
    info=$(timeout 2 strace $LD "$f" 2>&1 | grep -oE 'si_code=[A-Z_]+.*si_addr=0x[0-9a-f]+' | head -1)
    [ -z "$info" ] && continue

    code=$(echo "$info" | grep -oE 'si_code=[A-Z_]+' | head -1)
    addr=$(echo "$info" | grep -oE 'si_addr=0x[0-9a-f]+' | head -1)
    addr_hex=$(echo "$addr" | grep -oE '0x[0-9a-f]+')
    addr_int=$((addr_hex))

    # 패밀리 1: NULL+small (MAPERR + addr < 256)
    if [ -z "$picked_null" ] && [ "$code" = "si_code=SEGV_MAPERR" ] && [ $addr_int -lt 256 ]; then
        cp "$f" "$DEST/family1_null_deref.elf"
        picked_null="$(basename $f) [$info]"
    fi

    # 패밀리 2: large_addr (MAPERR + addr > 0x1000000)
    if [ -z "$picked_large" ] && [ "$code" = "si_code=SEGV_MAPERR" ] && [ $addr_int -ge 16777216 ]; then
        cp "$f" "$DEST/family2_garbage_ptr.elf"
        picked_large="$(basename $f) [$info]"
    fi

    # 패밀리 3: SEGV_ACCERR
    if [ -z "$picked_accerr" ] && [ "$code" = "si_code=SEGV_ACCERR" ]; then
        cp "$f" "$DEST/family3_perm_violation.elf"
        picked_accerr="$(basename $f) [$info]"
    fi

    # 패밀리 4: SI_KERNEL
    if [ -z "$picked_kernel" ] && [ "$code" = "si_code=SI_KERNEL" ]; then
        cp "$f" "$DEST/family4_si_kernel.elf"
        picked_kernel="$(basename $f) [$info]"
    fi

    [ -n "$picked_null" ] && [ -n "$picked_large" ] && [ -n "$picked_accerr" ] && [ -n "$picked_kernel" ] && break
done

echo "=== Sprint 1: 4 패밀리 대표 추출 완료 ==="
echo ""
echo "패밀리 1 (NULL deref)    : $picked_null"
echo "패밀리 2 (쓰레기 포인터)  : $picked_large"
echo "패밀리 3 (권한 위반)     : $picked_accerr"
echo "패밀리 4 (SI_KERNEL)     : $picked_kernel"
echo ""
echo "저장 위치: $DEST"
ls -la $DEST
