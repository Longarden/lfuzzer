#!/usr/bin/env python3
"""
lfuzzer.triage — V5 grounded triage pipeline.

설계(PIPELINE_VARIANTS.md 요약):
  퍼저가 뱉은 크래시 후보를 '실제 재현되는 CONFIRMED 버그'로 승격시키는 접지(grounded)
  파이프라인. 지표(metric)는 CONFIRMED 고유 버그 수뿐이며 커버리지는 지표가 아니다.

  단계:
    1) TriOracle.confirm  — stock ld.so / debug-assert ld.so / gold·bfd 차등으로 재현 검증
    2) CasrDedup.bucket   — casr(있으면) 또는 gdb-백트레이스 폴백으로 스택해시 버킷팅
    3) MCPAdvisor.advise  — (선택) LLM 자문. ADVISORY ONLY. 인용 없는 주장은 코드에서 DROP.
    4) TriagePipeline     — 위를 엮어 Verdict 를 낸다.

  권한 계층(엄수):
    - CASR / 도구 결과가 authoritative.
    - MCP/LLM 은 ADVISORY ONLY — 판정하지 않는다. 인용된 tool-result 가 없는 LLM 주장은 버린다.
    - 카운트(지표) 코드는 mcp_advisor 출력을 절대 읽지 않는다.

  이식성: 외부 도구(casr/gdb/디버그 로더/gold·bfd)가 없어도 import 는 에러 없이 성공하고,
  실행 시 '무슨 도구가 없어서 무엇을 못했는지'를 보고하며 graceful degrade 한다.
"""
from __future__ import annotations

from .tri_oracle import TriOracle, TriResult
from .casr_dedup import CasrDedup, DedupResult
from .mcp_advisor import MCPAdvisor, LLMBackend, NullBackend, AdviceResult
from .pipeline import TriagePipeline, Verdict

__all__ = [
    "TriOracle", "TriResult",
    "CasrDedup", "DedupResult",
    "MCPAdvisor", "LLMBackend", "NullBackend", "AdviceResult",
    "TriagePipeline", "Verdict",
]
