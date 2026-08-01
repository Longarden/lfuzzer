#!/usr/bin/env bash
# Gold vs BFD differential 실험 일괄 실행. 사용자가 ! 로 직접.
#   cd ~/PE/Lfuzzer/exp_goldbfd_diff && bash run_all.sh
set -uo pipefail   # -e 안 씀: 실험이 실패(fatal)를 관찰하는 게 목적
cd "$(dirname "$0")"
for f in exp_d03_pie.py exp_d19_justsymbols.py exp_d22_runpath.py exp_d02_dynstr_nonul.py; do
  echo; echo "########################  $f  ########################"
  python3 "$f" 2>&1 || echo "[$f 비정상 종료 — 위 로그 확인]"
done
echo; echo "완료. 각 실험의 'DIVERGED / 결론' 줄을 보고 예측과 맞는지 확인."
