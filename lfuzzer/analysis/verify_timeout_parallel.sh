#!/bin/bash
# 30초 timeout 으로 모든 v2 hangs 진짜 검증 (병렬 16)
LD=/lib64/ld-linux-x86-64.so.2
OUT=/home/garden/PE/Lfuzzer/out_qemu_v2
REPORT=/home/garden/PE/Lfuzzer/verify_timeout_report.txt
WORK=/tmp/vto_work
LIST=/tmp/vto_list

mkdir -p $WORK
> $LIST

# 모든 hangs 파일 절대경로로 모음
for sub in main qsub1 qsub2 default; do
    if [ -d "$OUT/$sub/hangs" ]; then
        ls "$OUT/$sub/hangs"/id:* 2>/dev/null >> $LIST
    fi
done

total=$(wc -l < $LIST)

# 한 파일 처리 함수
test_one() {
    f="$1"
    timeout 30 $LD "$f" > /dev/null 2>&1
    echo "$?"
}
export -f test_one
export LD

# 병렬 16 으로 실행, 결과는 stdout 으로
cat $LIST | xargs -I{} -P 16 bash -c 'test_one "$@"' _ {} > $WORK/results.txt

# 결과 집계
{
    echo "=================================="
    echo "  Timeout 30 검증 결과"
    echo "=================================="
    echo ""
    echo "총 검사: $total"
    echo ""
    echo "exit code 분포:"
    sort $WORK/results.txt | uniq -c | sort -rn | awk '
    {
        rc=$2
        cnt=$1
        if (rc==139)      printf "  %4d  SIGSEGV (139)              ⭐\n", cnt
        else if (rc==124) printf "  %4d  진짜 DoS / hang (124, 30초 초과) ⭐\n", cnt
        else if (rc==137) printf "  %4d  SIGKILL (137)\n", cnt
        else if (rc==0)   printf "  %4d  정상 종료 (0) = QEMU 오버헤드\n", cnt
        else if (rc==127) printf "  %4d  execve 실패 (127)\n", cnt
        else              printf "  %4d  기타 exit %s\n", cnt, rc
    }'
    echo ""
    echo "보고서: $REPORT"
} | tee $REPORT
