#!/bin/bash
LD=/lib64/ld-linux-x86-64.so.2
SRC=/home/garden/PE/Lfuzzer/classified_crashes
DEST=/home/garden/PE/Lfuzzer/representatives/family4_si_kernel.elf

for f in $SRC/*; do
    [ ! -f "$f" ] && continue
    code=$(timeout 2 $LD "$f" 2>&1 | grep -oE 'si_code=[A-Z_]+' | head -1)
    if [ "$code" = "si_code=SI_KERNEL" ]; then
        cp "$f" "$DEST"
        echo "FOUND: $(basename "$f")"
        echo "saved to: $DEST"
        echo "si_code: $code"
        timeout 2 $LD "$f" 2>&1 | grep -E 'si_signo|si_code|si_addr|killed' | head -3
        exit 0
    fi
done
echo "no SI_KERNEL crash found"
