# -*- coding: utf-8 -*-
"""lfuzzer.coverage — 커버리지 가이드 피드백 배선(afl 엔진) + 조기기각 측정.

- gen_afl_dict: numbers.py 위험값 풀 → AFL++ dictionary(elf.dict)
- (스크립트) run_afl.sh: 계측 ld/gold 에 afl-fuzz + structure_aware 커스텀뮤테이터
- (스크립트) run_nofeedback.sh: 피드백 OFF 대조(§4.2 ablation)
- measure_early_reject: 조기기각률 측정(논문 목표 10%대)
순수 import 부작용 없음.
"""
