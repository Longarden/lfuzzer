#!/usr/bin/env python3
"""
mcp_advisor.py — LLM/MCP 자문 계층. ADVISORY ONLY.

권한 계층(엄수, PIPELINE_VARIANTS.md):
  - LLM/MCP 는 절대 판정(adjudicate)하지 않는다. CASR/도구 결과가 authoritative.
  - 인용된 tool-result(evidence dict 의 실제 키)가 없는 LLM 주장은 코드에서 DROP 된다.
  - 지표(카운트) 코드는 이 모듈 출력을 절대 읽지 않는다.

계약:
  LLMBackend.suggest(evidence: dict) -> dict
     backend 가 내놓는 raw 제안. 신뢰하지 않는다.
     기대 형태:
        {
          "splits": [ {"cite": "<evidence_key>", "reason": str, "label": str}, ... ],
          "nl_repro": str | None,
        }
  MCPAdvisor.advise(evidence) -> AdviceResult{splits:[verified], nl_repro, dropped}
     - split 의 "cite" 가 evidence 에 실재하는 키가 아니면 그 split 을 버린다.
     - 인용 없는(=근거 없는) 주장 수를 dropped 로 카운트.
     - nl_repro 는 문자열일 때만 통과, 아니면 None.

기본 backend 는 NullBackend — 아무것도 제안하지 않는다(자문 꺼짐).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:                              # Protocol: py3.8+
    from typing import Protocol, runtime_checkable
except ImportError:              # pragma: no cover
    from typing_extensions import Protocol, runtime_checkable  # type: ignore


@runtime_checkable
class LLMBackend(Protocol):
    """LLM 백엔드 계약. 단 하나의 메서드만 요구한다."""
    def suggest(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """evidence(tool 출력 dict)를 받아 raw 제안 dict 를 반환."""
        ...


class NullBackend:
    """기본 백엔드. 아무 제안도 하지 않는다(자문 비활성 상태)."""
    def suggest(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        return {}


@dataclass
class AdviceResult:
    splits: List[dict] = field(default_factory=list)   # 인용 검증을 통과한 것만
    nl_repro: Optional[str] = None
    dropped: int = 0                                    # 인용 없어 버린 주장 수

    def as_dict(self) -> dict:
        return {"splits": self.splits, "nl_repro": self.nl_repro,
                "dropped": self.dropped}


class MCPAdvisor:
    """자문 어댑터. backend 출력에 인용 규칙을 강제해 걸러낸 결과만 돌려준다."""

    def __init__(self, backend: Optional[LLMBackend] = None):
        self.backend = backend or NullBackend()

    # ── 인용 검증 핵심 ─────────────────────────────────────────────────────
    @staticmethod
    def _cited(item: Any, evidence: Dict[str, Any]) -> bool:
        """item 이 evidence 의 실재 키를 인용하면 True.
        허용 형태: {"cite": key} 또는 {"cites": [key, ...]}.
        하나라도 evidence 에 없는 키면(=근거 없는 인용) 그 항목은 탈락."""
        if not isinstance(item, dict):
            return False
        keys: List[Any] = []
        if "cite" in item:
            keys.append(item["cite"])
        if "cites" in item and isinstance(item["cites"], (list, tuple)):
            keys.extend(item["cites"])
        if not keys:
            return False   # 인용 자체가 없음 → 근거 없는 주장
        # 모든 인용이 evidence 에 실재해야 통과(하나라도 허위면 DROP)
        return all(k in evidence for k in keys)

    def advise(self, evidence: Dict[str, Any]) -> AdviceResult:
        """backend 제안을 받아 인용 규칙으로 필터링한 AdviceResult 반환."""
        if not isinstance(evidence, dict):
            evidence = {}
        try:
            raw = self.backend.suggest(evidence) or {}
        except Exception:
            # backend 가 터져도 파이프라인은 산다(ADVISORY 는 실패해도 무해).
            return AdviceResult(splits=[], nl_repro=None, dropped=0)
        if not isinstance(raw, dict):
            return AdviceResult(splits=[], nl_repro=None, dropped=0)

        verified: List[dict] = []
        dropped = 0
        for sp in (raw.get("splits") or []):
            if self._cited(sp, evidence):
                verified.append(sp)
            else:
                dropped += 1

        nl = raw.get("nl_repro")
        nl_repro = nl if isinstance(nl, str) and nl.strip() else None

        return AdviceResult(splits=verified, nl_repro=nl_repro, dropped=dropped)


# ── 자기검증 데모: 인용 없는 제안이 DROP 됨을 증명 ─────────────────────────────
if __name__ == "__main__":
    import sys

    class _FakeBackend:
        """의도적으로 '인용된 것 1개 + 인용 없는 것 2개'를 섞어 낸다."""
        def suggest(self, evidence):
            return {
                "splits": [
                    {"cite": "casr_report", "label": "split-A",
                     "reason": "different CrashSeverity"},          # 통과(실재 키)
                    {"cite": "hallucinated_tool", "label": "split-B",
                     "reason": "made-up"},                          # DROP(허위 키)
                    {"label": "split-C", "reason": "no citation"},  # DROP(인용 없음)
                ],
                "nl_repro": "run loader on the mutated verneed ELF",
            }

    evidence = {
        "casr_report": {"CrashSeverity": {"ShortDescription": "SourceAv"}},
        "bt": ["#0 strcmp", "#1 _dl_map_object"],
        # 'hallucinated_tool' 은 일부러 넣지 않는다.
    }

    print("=" * 72)
    print(" MCPAdvisor 자기검증: 인용 없는 주장은 DROP")
    print("=" * 72)

    # 1) NullBackend: 아무것도 나오지 않아야
    null_res = MCPAdvisor().advise(evidence)
    assert null_res.splits == [] and null_res.dropped == 0
    print(f"  [NullBackend] splits={null_res.splits} dropped={null_res.dropped}  OK")

    # 2) FakeBackend: 3개 중 1개만 통과, 2개 DROP
    res = MCPAdvisor(_FakeBackend()).advise(evidence)
    print(f"  [FakeBackend] verified splits = {[s['label'] for s in res.splits]}")
    print(f"                dropped         = {res.dropped}")
    print(f"                nl_repro        = {res.nl_repro!r}")
    assert len(res.splits) == 1, "인용된 split 1개만 남아야"
    assert res.splits[0]["label"] == "split-A"
    assert res.dropped == 2, "허위 인용 + 인용 없음 = 2개 DROP"
    assert res.nl_repro is not None
    print("-" * 72)
    print("  PASS: 인용된 tool-result 없는 LLM 주장은 반환 전에 버려진다.")
    sys.exit(0)
