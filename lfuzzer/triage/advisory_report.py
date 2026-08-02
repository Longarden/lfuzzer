#!/usr/bin/env python3
"""
advisory_report.py — ③ MCP/LLM 자문 리포트 생성기.

흐름:
  results_full.json(전체 트리아지) → confirmed 버킷별 그룹 → 대표 크래시를 casr-gdb로
  재실행해 crash-site(함수) 확보 → evidence 구성 → MCPAdvisor(KBBackend).advise
  (인용 없는 주장 DROP) → 버킷별 5단 서술을 advisory_report.{md,json}로.

CASR 숫자(지표)는 절대 안 바꾼다. 이건 '해설' 레이어다.
??? (pc=junk, 심볼 없음) 버킷은 (A) 정직 서술만 한다.

실행:
  export PATH="$HOME/.cargo/bin:$PATH"
  python3 -m lfuzzer.triage.advisory_report \
     --results ~/PE/Lfuzzer/triage_run_full_2026-08-02/results_full.json \
     --out     ~/PE/Lfuzzer/triage_run_full_2026-08-02 [--limit N] [--backend kb|anthropic]
"""
from __future__ import annotations
import argparse, collections, json, os, re, subprocess, sys, tempfile

REPO = "/home/garden/PE/lfuzzer-clean"
sys.path.insert(0, REPO)
from lfuzzer import config                                   # noqa: E402
from lfuzzer.triage.mcp_advisor import MCPAdvisor            # noqa: E402
from lfuzzer.triage.llm_backends import KBBackend, AnthropicBackend  # noqa: E402
from lfuzzer.triage import advisory_kb                       # noqa: E402

_FRAME = re.compile(r"#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?([A-Za-z_][\w:.]*)\s*\(")
_INFN = re.compile(r"\bin\s+([A-Za-z_][\w:.]*)")
_FIELD = re.compile(r"field_\d+_seg(\d+)_p_(\w+)")


def casr_site(loader: str, crash: str) -> str:
    """대표 크래시를 casr-gdb로 재실행해 최상위 심볼 프레임 함수명 반환('??' 가능)."""
    td = tempfile.mkdtemp(prefix="adv_")
    rep = os.path.join(td, "r.casrep")
    try:
        subprocess.run(["casr-gdb", "-o", rep, "--", loader, crash],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        if not os.path.exists(rep):
            return "??"
        d = json.load(open(rep, errors="replace"))
        for entry in (d.get("Stacktrace") or []):
            s = str(entry)
            m = _FRAME.search(s) or _INFN.search(s)
            if m and m.group(1) != "??":
                return m.group(1)
        return "??"
    except Exception:
        return "??"
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0, help="상위 N개 버킷만(0=전부)")
    ap.add_argument("--backend", choices=["kb", "anthropic"], default="kb")
    args = ap.parse_args()

    data = json.load(open(args.results))
    recs = [r for r in data["records"] if r.get("confirmed")]

    # 버킷별 그룹 + 대표(필드태그 있는 파일 우선)
    groups = collections.defaultdict(list)
    for r in recs:
        if r.get("bucket_key"):
            groups[r["bucket_key"]].append(r)
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    if args.limit:
        ordered = ordered[:args.limit]

    backend = AnthropicBackend() if args.backend == "anthropic" else KBBackend()
    advisor = MCPAdvisor(backend)
    loader = config.LOADER

    out_rows = []
    hijack_total = 0
    for bucket, members in ordered:
        rep = next((m for m in members if m["name"].startswith("field_")), members[0])
        # 필드 추출
        field = None
        fm = _FIELD.search(rep["name"])
        if fm:
            field = f"seg{fm.group(1)} p_{fm.group(2)}"
        # crash-site (casr 재실행)
        site_fn = casr_site(loader, rep["crash"])
        if site_fn == "??":
            hijack_total += len(members)
        kb = advisory_kb.lookup_site(site_fn)
        fh = advisory_kb.lookup_field(field)

        evidence = {
            "casr_report": {"severity": rep.get("severity"), "site": site_fn,
                            "count": len(members), "bucket_key": bucket},
            "tri_oracle": {"stock_sig": rep.get("stock_sig"), "stock_rc": rep.get("stock_rc")},
        }
        if kb:
            evidence["site_kb"] = kb
        if fh:
            evidence["field_hint"] = fh

        adv = advisor.advise(evidence)
        out_rows.append({
            "bucket_key": bucket, "count": len(members), "severity": rep.get("severity"),
            "site": site_fn, "field": field, "rep": rep["name"],
            "narrative": adv.nl_repro, "kept_splits": [s["label"] for s in adv.splits],
            "dropped": adv.dropped, "kb_hit": bool(kb),
        })

    # ── JSON ──
    json.dump({"n_buckets": len(out_rows), "backend": args.backend,
               "hijack_unsymbolized": hijack_total, "rows": out_rows},
              open(os.path.join(args.out, "advisory_report.json"), "w"),
              ensure_ascii=False, indent=2)

    # ── Markdown ──
    L = []
    L.append(f"# ③ MCP/LLM 자문 리포트 (backend={args.backend})")
    L.append("")
    L.append("CASR 숫자(지표)는 authoritative — 이 리포트는 '해설'만. 인용 없는 주장은 DROP됨.")
    L.append(f"버킷 {len(out_rows)}개 · 심볼없음(제어흐름 하이재킹류) 총 {hijack_total}건 = (A) 정직 서술.")
    L.append("")
    kb_hits = sum(1 for r in out_rows if r["kb_hit"])
    tot_drop = sum(r["dropped"] for r in out_rows)
    L.append(f"KB 히트 {kb_hits}/{len(out_rows)} 버킷 · 가드레일 DROP 총 {tot_drop}건(근거 없는 자문 자동 폐기).")
    L.append("")
    for r in out_rows:
        L.append(f"## {r['site']}  ({r['count']}건, CASR {r['severity'] or '-'})")
        L.append(f"`{r['bucket_key']}`  대표 `{r['rep'][:48]}`" + (f"  필드 {r['field']}" if r['field'] else ""))
        L.append("```")
        L.append(r["narrative"])
        L.append("```")
        L.append(f"자문 채택 splits: {', '.join(r['kept_splits'])}  ·  DROP {r['dropped']}"
                 + ("" if r["kb_hit"] else "  ← KB 미등록 site: 원인/영향 서술 보류(정직)"))
        L.append("")
    open(os.path.join(args.out, "advisory_report.md"), "w").write("\n".join(L))

    print(f"[advisory] {len(out_rows)} buckets, kb_hit={kb_hits}, dropped_total={tot_drop}, "
          f"hijack={hijack_total} -> advisory_report.md/.json")


if __name__ == "__main__":
    main()
