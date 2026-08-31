# -*- coding: utf-8 -*-
"""lfuzzer.coverage — blind 캠페인 러너 + 조기기각 측정 (afl 제거판).

- run_nofeedback: structure_aware 4축 뮤테이터 blind 루프(커버리지/큐 없음)
- (스크립트) run_campaign.sh: blind 제안 vs Melkor 병렬 + CASR 요약
- summarize_campaign: 크래시 → CASR 고유버킷 표
- measure_early_reject: 조기기각률 측정
순수 import 부작용 없음.
"""
