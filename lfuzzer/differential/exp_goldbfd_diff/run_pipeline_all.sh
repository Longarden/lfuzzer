#!/usr/bin/env bash
# 전 실험을 다 수행하고 각각 로그 저장 + 마스터 요약표 생성.
set +e
cd "$(dirname "$0")"
D=pipeline_runs; mkdir -p "$D"
SUM="$D/SUMMARY.md"
echo "# 전 실험 파이프라인 실측 ($(date '+%Y-%m-%d %H:%M'))" > "$SUM"
echo "" >> "$SUM"
echo "| 실험 | BFD rc | GOLD rc | DIVERGED | 결론 |" >> "$SUM"
echo "|---|---|---|---|---|" >> "$SUM"
for f in $(ls exp_*.py | sort); do
  log="$D/${f%.py}.log"
  timeout 200 python3 "$f" > "$log" 2>&1
  brc=$(grep -oE 'BFD +rc=[0-9-]+' "$log" | head -1 | grep -oE '[0-9-]+$')
  grc=$(grep -oE 'GOLD +rc=[0-9-]+' "$log" | head -1 | grep -oE '[0-9-]+$')
  div=$(grep -q 'DIVERGED' "$log" && echo 'Y' || echo '-')
  con=$(grep -E '결론:' "$log" | head -1 | sed 's/.*결론: *//' | cut -c1-60)
  echo "| ${f%.py} | ${brc:-?} | ${grc:-?} | $div | ${con:-(로그참조)} |" >> "$SUM"
  echo "done: $f (rc BFD=$brc GOLD=$grc div=$div)"
done
echo "" >> "$SUM"
echo "개별 로그: pipeline_runs/<실험>.log — 재현시 그 로그의 크래프팅/명령 참조" >> "$SUM"
echo "===== 완료. 요약: $SUM ====="
