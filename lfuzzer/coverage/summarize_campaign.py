#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
summarize_campaign.py — blind 캠페인 결과 → 표(markdown)  [afl 제거판]

각 arm 의 크래시를 CASR(gold_casr.LinkerCasrDedup)로 버킷팅해 '고유 결함
후보' 수를 센다. afl/커버리지 없음(무작위 blind 비교).

arm A(제안 blind)  = camp/proposed_crashes/*.so + camp/A_proposed.log
arm B(Melkor)      = camp/melkor_crashes/*.elf + camp/C_melkor.log

사용:
  python3 -m lfuzzer.coverage.summarize_campaign --run <RUN> --ld <링커>
      --main-o main.o --kind {bfd|gold} [--blind] [--triage-cap 80]
(--blind 은 호환용 플래그, 무시해도 동일 — 이 판은 항상 blind)
"""
from __future__ import annotations

import os
import re
import sys
import glob
import argparse

from lfuzzer.triage.gold_casr import LinkerCasrDedup


def _bucket_dir(dd, files, cap):
    import collections
    buckets = collections.Counter()
    used = None
    for f in files[:cap]:
        try:
            r = dd.bucket(f)
            buckets[r.bucket_key] += 1
            used = r.tool_used
        except Exception:
            continue
    return len(buckets), used, buckets


def _execs_from_log(path, pat=r"execs=(\d+)"):
    if not os.path.exists(path):
        return 0
    m = re.findall(pat, open(path, errors="replace").read())
    return int(m[-1]) if m else 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--ld", required=True)
    ap.add_argument("--main-o", required=True)
    ap.add_argument("--kind", default="bfd", choices=["bfd", "gold"])
    ap.add_argument("--triage-cap", type=int, default=80)
    ap.add_argument("--blind", action="store_true", help="호환용(항상 blind)")
    args = ap.parse_args(argv)

    run, cap = args.run, args.triage_cap
    dd = LinkerCasrDedup(linker=args.ld, main_o=args.main_o, kind=args.kind)

    try:
        t0 = int(open(os.path.join(run, "camp", "start.txt")).read())
        t1 = int(open(os.path.join(run, "camp", "end.txt")).read())
        elapsed = t1 - t0
    except Exception:
        elapsed = -1

    # Arm A: 제안(blind)
    a_exec = _execs_from_log(os.path.join(run, "camp", "A_proposed.log"))
    a_files = sorted(glob.glob(os.path.join(run, "camp", "proposed_crashes", "*.so")))
    a_bk, a_tool, _ = _bucket_dir(dd, a_files, cap)

    # Arm B: Melkor
    b_exec = _execs_from_log(os.path.join(run, "camp", "C_melkor.log"))
    b_files = sorted(glob.glob(os.path.join(run, "camp", "melkor_crashes", "*.elf")))
    b_bk, b_tool, _ = _bucket_dir(dd, b_files, cap)

    tool = a_tool or b_tool or "gdb-fallback"

    print("# blind 캠페인 결과 (afl 없음, 무작위 변이)")
    print()
    print(f"- 시간예산: {elapsed}s (arm 병렬) · SUT: {args.kind} 링커")
    print(f"- 트리아지: CASR({tool}), 버킷=고유 결함 후보 · triage-cap={cap}(샘플)")
    print()
    print("| 기법 | execs | 원시 크래시 | 고유 버킷(CASR) |")
    print("|------|------:|-----------:|---------------:|")
    print(f"| 제안 (4축 구조보존, blind) | {a_exec} | {len(a_files)} | {a_bk} |")
    print(f"| Melkor (규칙기반) | {b_exec} | {len(b_files)} | {b_bk} |")
    print()
    print("해석: 동일 SUT·동일 시간예산·afl 없음(무작위). 4축 구조보존 변이 vs Melkor")
    print("단일필드 변조의 고유 결함 다양성 대조. (원시 크래시 수는 참고, 공정지표=버킷)")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
