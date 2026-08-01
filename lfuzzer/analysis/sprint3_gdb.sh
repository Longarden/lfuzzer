#!/bin/bash
# Sprint 3: 4 패밀리 minimal repro 각각을 gdb 로 백트레이스
# libc6-dbg 설치돼있으면 ld.so 함수 이름 + 줄번호까지 보임
SRC=~/PE/Lfuzzer/minimal_repros
LD=/lib64/ld-linux-x86-64.so.2
REPORT=~/PE/Lfuzzer/sprint3_bt_report.txt

> $REPORT

echo "==============================" | tee -a $REPORT
echo "  Sprint 3: gdb backtrace 분석" | tee -a $REPORT
echo "==============================" | tee -a $REPORT
echo "" | tee -a $REPORT

for fname in family1_null_deref family2_garbage_ptr family3_perm_violation family4_si_kernel; do
    in_file="$SRC/${fname}_min.elf"
    if [ ! -f "$in_file" ]; then
        # minimal 없으면 representative 로 fallback
        in_file=~/PE/Lfuzzer/representatives/${fname}.elf
    fi
    [ ! -f "$in_file" ] && { echo "SKIP $fname (no file)" | tee -a $REPORT; continue; }

    echo "" | tee -a $REPORT
    echo "─────────────────────────────────────────" | tee -a $REPORT
    echo "[$fname]  $(basename $in_file)" | tee -a $REPORT
    echo "─────────────────────────────────────────" | tee -a $REPORT

    # strace 로 마지막 syscall + signal
    echo "strace 마지막 5줄:" | tee -a $REPORT
    timeout 3 strace $LD "$in_file" 2>&1 | tail -5 | sed 's/^/  /' | tee -a $REPORT

    echo "" | tee -a $REPORT
    echo "gdb backtrace:" | tee -a $REPORT

    # gdb 가 우리 깨진 ELF 를 BFD 로 못 열 수 있어서 ld.so 를 직접 띄움
    timeout 10 gdb -batch -q \
        -ex 'set pagination off' \
        -ex 'set confirm off' \
        -ex "run $in_file" \
        -ex 'bt 12' \
        -ex 'info registers rip rsp rdi rsi' \
        --args $LD "$in_file" 2>&1 \
        | grep -E '^#|received signal|Program received|si_addr|rip|rsp|rdi|rsi' \
        | head -20 | sed 's/^/  /' | tee -a $REPORT
done

echo "" | tee -a $REPORT
echo "==============================" | tee -a $REPORT
echo "  보고서 저장: $REPORT" | tee -a $REPORT
echo "==============================" | tee -a $REPORT
