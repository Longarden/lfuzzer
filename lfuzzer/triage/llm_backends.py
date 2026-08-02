#!/usr/bin/env python3
"""
llm_backends.py — ③ 자문의 LLMBackend 구현들. mcp_advisor.LLMBackend 계약 준수:
    suggest(evidence: dict) -> {"splits":[{"cite":<key>,"label","reason"}], "nl_repro": str}

두 백엔드:
  KBBackend        : 'me-as-backend'. advisory_kb(내 분석)와 실제 evidence를 join.
                     인용은 evidence 키만 사용 → mcp_advisor가 근거 없는 건 DROP.
  AnthropicBackend : API 키가 있으면 Claude로 같은 형태를 생성(미래/라이브용).
                     키 없으면 빈 dict(=자문 꺼짐)로 안전 강등.

핵심 규칙: 자문은 CASR/tool 결과(authoritative)를 '해설'만 한다. 판정 안 함.
"""
from __future__ import annotations
import os
from typing import Any, Dict, Optional

from . import advisory_kb


def _narrative(casr: dict, site: Optional[dict], field: Optional[str],
               tri: Optional[dict]) -> str:
    """5단 서술을 evidence 근거로 조립. site 미상이면 정직하게 축약(지어내지 않음)."""
    sev = casr.get("severity") or "-"
    fn = casr.get("site") or "??"
    cnt = casr.get("count")
    sig = (tri or {}).get("stock_sig") or "?"
    lines = []
    lines.append(f"어디서 : {(site or {}).get('where') or f'ld.so {fn} (심볼 미상 가능)'}")
    lines.append(f"무엇으로: {field or '바이트레벨 뮤테이션(필드 미태그)'}")
    if site:
        lines.append(f"검증누락: {site['missing_validation']}")
        lines.append(f"될수있다: {site['impact']}")
        lines.append(f"근거   : CASR={sev} · stock={sig} · {cnt}건 · spec={site['spec_ptr']}")
    else:
        lines.append(f"검증누락: (crash-site가 KB에 없어 근거 있는 원인 서술 보류)")
        lines.append(f"될수있다: CASR 등급 {sev} 수준까지만 근거 있음")
        lines.append(f"근거   : CASR={sev} · stock={sig} · {cnt}건")
    return "\n".join(lines)


class KBBackend:
    """me-as-backend. advisory_kb + evidence join. evidence 키만 인용한다."""

    def suggest(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        casr = evidence.get("casr_report") or {}
        site = evidence.get("site_kb")       # dict | None (report builder가 KB히트일때만 넣음)
        field = evidence.get("field_hint")   # str  | None
        tri = evidence.get("tri_oracle")

        splits = []
        # (1) 결과 주장 — CASR(authoritative)에 근거. 항상 통과.
        splits.append({"cite": "casr_report", "label": "result",
                       "reason": f"CASR {casr.get('severity','?')} @ {casr.get('site','?')} "
                                 f"({casr.get('count','?')} crashes)"})
        # (2) 검증누락 주장 — site_kb 인용. KB에 없으면 DROP(가드레일 실증).
        splits.append({"cite": "site_kb", "label": "missing_validation",
                       "reason": (site.get("missing_validation") if site
                                  else "unmapped site — advisory withheld")})
        # (3) 영향 주장 — site_kb 인용.
        splits.append({"cite": "site_kb", "label": "impact",
                       "reason": (site.get("impact") if site
                                  else "unmapped site — impact withheld")})
        # (4) 유발 필드 주장 — field_hint 인용. 필드 미태그면 DROP.
        splits.append({"cite": "field_hint", "label": "field",
                       "reason": field or "no field-encoded trigger"})

        return {"splits": splits, "nl_repro": _narrative(casr, site, field, tri)}


class AnthropicBackend:
    """라이브 Claude 백엔드(미래용). ANTHROPIC_API_KEY 없으면 자문 꺼짐."""

    def __init__(self, model: str = "claude-sonnet-5", max_tokens: int = 400):
        self.model = model
        self.max_tokens = max_tokens
        self.key = os.environ.get("ANTHROPIC_API_KEY")

    def suggest(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        if not self.key:
            return {}                      # 키 없음 → NullBackend처럼 동작
        try:
            import anthropic, json
        except Exception:
            return {}
        keys = list(evidence.keys())
        prompt = (
            "You are an ADVISORY-ONLY assistant. CASR/tool results are authoritative; "
            "you never adjudicate. Given this triage evidence (JSON), produce a 5-line "
            "Korean narrative (어디서/무엇으로/검증누락/될수있다/근거) as nl_repro, and a "
            "list of splits. EVERY split MUST cite an evidence key that exists in this list: "
            f"{keys}. Do not invent keys. Respond as JSON "
            '{"splits":[{"cite":<key>,"label":str,"reason":str}],"nl_repro":str}.\n\n'
            f"evidence = {json.dumps(evidence, ensure_ascii=False)[:4000]}"
        )
        try:
            client = anthropic.Anthropic()
            msg = client.messages.create(
                model=self.model, max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}])
            txt = msg.content[0].text
            i, j = txt.find("{"), txt.rfind("}")
            return json.loads(txt[i:j + 1]) if i >= 0 else {}
        except Exception:
            return {}                      # 라이브 실패해도 자문은 무해하게 꺼짐
