#!/bin/bash
set -u
BASE=/tmp/parser_sweep
R=$BASE/results.tsv
O=$BASE/triage; mkdir -p "$O"
REP="$O/report.txt"; : > "$REP"
say(){ echo "$*" | tee -a "$REP"; }

[ -s "$R" ] || { say "results.tsv 비어있음 — 파서 크래시 0건 (코퍼스가 파서엔 tolerant)"; exit 0; }

declare -A CMD=( [readelf]="readelf -a" [objdumpx]="objdump -x" [objdumpd]="objdump -d" [nm]="nm -aD" [llvmobjdump]="llvm-objdump -x" )

say "############ 파서 리플레이 트리아지 ############"
say "총 crash-hit(라인): $(wc -l < "$R")"
say "유니크 크래시 파일: $(cut -f3 "$R" | sort -u | wc -l)"
say ""
say "== 1) tool별 =="; cut -f1 "$R" | sort | uniq -c | sort -rn | tee -a "$REP"
say ""
say "== 2) 신호별 (124=timeout/OOM-loop 137=KILL/OOM 139=SEGV 134=ABRT 136=FPE 138=BUS) =="
cut -f2 "$R" | sort | uniq -c | sort -rn | tee -a "$REP"
say ""
say "== 3) 소스코퍼스(tag)별 유니크파일 — 세그먼트 vs 필드 가설검증 =="
cut -f3 "$R" | sed -E "s|$BASE/corpus/([^/]+)/.*|\1|" | sort | uniq -c | sort -rn | tee -a "$REP"
say ""
say "== 4) 차등: 파일별 죽은 tool 집합 (binutils전용 vs llvm전용 vs 공통) =="
awk -F"\t" "{seen[\$3]=seen[\$3] \" \" \$1} END{for(f in seen){s=seen[f]; print s}}" "$R" \
  | sed -E "s/^ +//" | tr \" \" \"\n\" | paste -sd, - >/dev/null 2>&1
awk -F"\t" "{s[\$3]=s[\$3]\",\"\$1} END{for(f in s){g=s[f]; c[g]++} for(k in c) print c[k]\"\t\"k}" "$R" \
  | sort -rn | head -30 | tee -a "$REP"
say ""
say "== 5) gdb 백트레이스 서명 클러스터링 (그룹당 최대 25샘플) =="
gdbsig(){ # $1=cmd(with args) $2=file
  gdb -q -batch -nx -ex "set pagination off" -ex "run" \
      -ex "printf \"SIG=%d ADDR=%p\n\", \$_siginfo.si_signo, \$_siginfo._sifields._sigfault.si_addr" \
      -ex "bt 3" --args $1 "$2" 2>/dev/null \
   | grep -E "SIG=|#[0-9]" | tr "\n" "|" 
}
# (tool,signal) 그룹마다 대표 클러스터
for grp in $(cut -f1,2 "$R" | sort -u | tr "\t" ":"); do
  tool="${grp%%:*}"; sig="${grp##*:}"
  cmd="${CMD[$tool]:-$tool}"
  [ "$sig" = "124" ] && { say "[$tool sig=124] timeout/OOM-loop (gdb 스킵)"; continue; }
  say "--- 그룹 $tool sig=$sig ---"
  declare -A seen=(); n=0
  while IFS=$"\t" read -r t rc f; do
    [ "$t" = "$tool" ] && [ "$rc" = "$sig" ] || continue
    s=$(gdbsig "$cmd" "$f")
    key=$(echo "$s" | md5sum | cut -c1-10)
    if [ -z "${seen[$key]:-}" ]; then seen[$key]="$f"; say "  [클러스터 $key] 대표: $f"; say "     $s"; fi
    n=$((n+1)); [ $n -ge 25 ] && break
  done < <(awk -F"\t" -v tt="$tool" -v ss="$sig" "\$1==tt && \$2==ss" "$R")
  unset seen
done
say ""
say "== 대표 크래시 파일 목록 저장: $O/representatives.txt =="
cut -f1,2,3 "$R" | sort -u -t$"\t" -k1,2 | awk -F"\t" "!s[\$1\$2]++{print}" > "$O/representatives.txt"
say "완료. 리포트: $REP"
