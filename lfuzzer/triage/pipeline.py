#!/usr/bin/env python3
"""
pipeline.py — V5 접지 트리아지 파이프라인 (TriagePipeline).

흐름(크래시 1건):
    TriOracle.confirm(crash_elf)
      └─ confirmed 아니면 → 여기서 종료(버킷/자문 생략, 지표에 안 잡힘)
    confirmed 면:
        CasrDedup.bucket(crash_elf)          # authoritative 버킷/severity
        MCPAdvisor.advise(evidence)          # 선택, ADVISORY ONLY
    → Verdict{confirmed, bucket_key, severity, splits, tool_used}

지표(metric = unique CONFIRMED bugs)는 Verdict.confirmed / bucket_key 로만 센다.
splits(자문)는 절대 카운트에 쓰지 않는다.

배치: process(dir) 는 디렉토리의 *.elf 를 모두 처리해 Verdict 리스트를 반환.
외부 도구가 없어도 죽지 않고 graceful degrade.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    from .tri_oracle import TriOracle, TriResult
    from .casr_dedup import CasrDedup, DedupResult
    from .mcp_advisor import MCPAdvisor, LLMBackend, NullBackend
except Exception:                 # pragma: no cover - 단독 실행 폴백
    from tri_oracle import TriOracle, TriResult          # type: ignore
    from casr_dedup import CasrDedup, DedupResult         # type: ignore
    from mcp_advisor import MCPAdvisor, LLMBackend, NullBackend  # type: ignore


@dataclass
class Verdict:
    """한 크래시에 대한 최종 판정. 지표 코드는 confirmed/bucket_key 만 읽는다."""
    crash: str
    confirmed: bool
    bucket_key: Optional[str] = None
    severity: Optional[str] = None
    splits: List[dict] = field(default_factory=list)   # ADVISORY, 비-지표
    tool_used: Optional[str] = None
    # 진단/재현용 원재료
    tri: Optional[TriResult] = None
    dropped_advice: int = 0
    nl_repro: Optional[str] = None

    def summary(self) -> str:
        if not self.confirmed:
            miss = ""
            if self.tri and self.tri.missing:
                miss = f"  (skip: {', '.join(self.tri.missing)})"
            return f"UNCONFIRMED  {os.path.basename(self.crash)}{miss}"
        sev = self.severity or "-"
        adv = f"  advice_splits={len(self.splits)} dropped={self.dropped_advice}" \
            if (self.splits or self.dropped_advice) else ""
        return (f"CONFIRMED    {os.path.basename(self.crash)}  "
                f"bucket={self.bucket_key}  sev={sev}  via={self.tool_used}{adv}")


class TriagePipeline:
    """오라클 → dedup → (선택)자문 을 엮는 파이프라인."""

    def __init__(self,
                 oracle: Optional[TriOracle] = None,
                 dedup: Optional[CasrDedup] = None,
                 advisor: Optional[MCPAdvisor] = None,
                 backend: Optional[LLMBackend] = None):
        self.oracle = oracle or TriOracle()
        self.dedup = dedup or CasrDedup()
        # advisor 우선; 없으면 backend 로 구성; 둘 다 없으면 NullBackend(자문 꺼짐)
        self.advisor = advisor or MCPAdvisor(backend or NullBackend())

    # ── 단건 ────────────────────────────────────────────────────────────────
    def process(self, crash_elf: str) -> Verdict:
        tri = self.oracle.confirm(crash_elf)
        if not tri.confirmed:
            return Verdict(crash=crash_elf, confirmed=False, tri=tri)

        # authoritative 버킷팅
        dd: DedupResult = self.dedup.bucket(crash_elf)

        # ADVISORY 자문: 오라클/버킷 결과를 인용 가능한 evidence 로 넘긴다.
        evidence: Dict[str, object] = {}
        evidence.update(tri.as_evidence())               # key: 'tri_oracle'
        evidence["casr_report"] = {
            "bucket_key": dd.bucket_key, "top_frame": dd.top_frame,
            "severity": dd.severity_or_None, "tool_used": dd.tool_used,
            "signal": dd.signal, "frames": dd.frames,
        }
        if dd.frames:
            evidence["bt"] = dd.frames
        advice = self.advisor.advise(evidence)

        return Verdict(
            crash=crash_elf, confirmed=True,
            bucket_key=dd.bucket_key, severity=dd.severity_or_None,
            splits=advice.splits, tool_used=dd.tool_used, tri=tri,
            dropped_advice=advice.dropped, nl_repro=advice.nl_repro,
        )

    # ── 배치 ────────────────────────────────────────────────────────────────
    def process_dir(self, crash_dir: str) -> List[Verdict]:
        """디렉토리의 *.elf 를 모두 트리아지. 없으면 빈 리스트."""
        if not crash_dir or not os.path.isdir(crash_dir):
            return []
        verdicts: List[Verdict] = []
        for fn in sorted(os.listdir(crash_dir)):
            if fn.endswith(".elf"):
                verdicts.append(self.process(os.path.join(crash_dir, fn)))
        return verdicts

    def unique_confirmed(self, verdicts: List[Verdict]) -> Dict[str, int]:
        """지표 계산: CONFIRMED 만, bucket_key 로 고유화한 카운트.
        (자문 splits 는 절대 여기 관여하지 않는다.)"""
        buckets: Dict[str, int] = {}
        for v in verdicts:
            if v.confirmed and v.bucket_key:
                buckets[v.bucket_key] = buckets.get(v.bucket_key, 0) + 1
        return buckets


# ── 데모 ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, sys, glob

    print("=" * 72)
    print(" TriagePipeline 데모")
    print("=" * 72)

    pipe = TriagePipeline()

    # 1) 실제 크래시 디렉토리가 있으면 그걸 쓴다(환경변수/레거시 경로).
    candidates = [
        os.environ.get("LFUZZER_CRASH_DIR"),
        os.path.expanduser("~/PE/Lfuzzer/out_dynamic_v3"),
        os.path.expanduser("~/PE/Lfuzzer/classified_crashes"),
    ]
    crash_dir = next((c for c in candidates
                      if c and os.path.isdir(c) and glob.glob(os.path.join(c, "*.elf"))),
                     None)

    made_tmp = False
    if crash_dir is None:
        # 2) 없으면 합성 크래시로 파이프라인이 끝까지 도는지 보인다.
        crash_dir = tempfile.mkdtemp(prefix="triage_demo_")
        with open(os.path.join(crash_dir, "synthetic__deadbeef__sig11.elf"), "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 60)
        made_tmp = True
        print(f"  (실제 크래시 디렉토리 없음 → 합성 1건으로 데모: {crash_dir})")
    else:
        print(f"  크래시 디렉토리: {crash_dir}")

    try:
        # 데모는 앞쪽 몇 건만.
        elfs = sorted(glob.glob(os.path.join(crash_dir, "*.elf")))[:5]
        verdicts = [pipe.process(e) for e in elfs]
        print("-" * 72)
        for v in verdicts:
            print("  " + v.summary())
        print("-" * 72)
        buckets = pipe.unique_confirmed(verdicts)
        n_conf = sum(1 for v in verdicts if v.confirmed)
        print(f"  처리 {len(verdicts)}건 | CONFIRMED {n_conf}건 | "
              f"고유 버킷 {len(buckets)}개  (= 지표: unique CONFIRMED bugs)")
        for bk, n in sorted(buckets.items(), key=lambda x: -x[1]):
            print(f"    x{n:<3} {bk}")
    finally:
        if made_tmp:
            import shutil
            shutil.rmtree(crash_dir, ignore_errors=True)
    sys.exit(0)
