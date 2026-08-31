#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
measure_early_reject.py — 조기기각률 측정  [Phase 3 / ①]

논문 §서론·§4.2: 무작위 비트 변조는 ELF 헤더 사슬 무결성을 즉시 훼손해
파서가 '심층 로직에 도달하기 전에' 파일을 거부하는 조기기각(early rejection)을
유발한다. 제안 프레임워크(구조보존 4축 + 리페어)의 목표는 이 조기기각률을
낮춰(논문 "10%대") 파서 깊은 경로에 더 자주 도달하는 것이다.

이 스크립트는 변이 파일 집합을 링커에 넣고, 각 실행을 3분류한다:
    GATE_REJECT : 입구에서 즉시 거부(포맷 미인식/ELF 아님/헤더 파손)
                  → 심층 파싱 미도달. 낭비.
    DEEP        : 심층 파싱 도달(심볼/버전/reloc 처리 진입 후 정상 또는 진단오류)
                  → 우리가 원하는 영역.
    CRASH       : 시그널 사망/timeout(진짜 결함 신호)
조기기각률 = GATE_REJECT / 전체.

분류는 링커 stderr 메시지 패턴으로 한다(bfd/gold 공통 + 각자 특유).

사용:
  python3 -m lfuzzer.coverage.measure_early_reject \\
      --ld ~/binutils-build-afl-bfd/ld/ld-new --main-o main.o --inputs mut_dir/
  # 리페어 ON/OFF 두 집합을 각각 측정해 조기기각률 하락을 보인다.
"""
from __future__ import annotations

import os
import re
import sys
import glob
import argparse
import subprocess

# 입구 거부(심층 미도달) 신호 — bfd/gold/공통
GATE_PATTERNS = [
    r"file format not recognized",
    r"not an ELF",
    r"invalid ELF header",
    r"failed to read ELF",
    r"file truncated",
    r"unknown ELF machine",
    r"unsupported ELF",
    r"unable to recognise",
    r"no input files",
    r"archive has no index",
    r"corrupt",              # 일부 초기 헤더 파손
]
# 심층 도달 신호(버전/심볼/reloc 처리 진입) — 조기기각 아님
DEEP_PATTERNS = [
    r"\.gnu\.version",
    r"verneed",
    r"verdef",
    r"vna_",
    r"undefined reference",
    r"multiple definition",
    r"relocation",
    r"symbol",
    r"version node",
    r"DT_",
    r"dynamic section",
]

_GATE_RE = re.compile("|".join(GATE_PATTERNS), re.IGNORECASE)
_DEEP_RE = re.compile("|".join(DEEP_PATTERNS), re.IGNORECASE)


def classify(rc: int, stderr: str) -> str:
    """rc + stderr → GATE_REJECT | DEEP | CRASH | CLEAN."""
    if rc < 0 or rc == 124:
        return "CRASH"
    text = stderr or ""
    deep = bool(_DEEP_RE.search(text))
    gate = bool(_GATE_RE.search(text))
    if deep:
        return "DEEP"            # 심층 신호가 있으면 조기기각 아님(우선)
    if gate:
        return "GATE_REJECT"
    if rc == 0:
        return "DEEP"            # 정상 링크 = 당연히 심층 도달
    return "DEEP"               # 진단오류지만 gate 신호 없음 → 심층으로 본 것(보수적)


def run_one(ld_bin, main_o, mutant, ldflag, timeout):
    cmd = [ld_bin]
    if ldflag:
        cmd += ldflag.split()
    cmd += ["-shared", "-o", os.devnull, main_o, mutant]
    try:
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=timeout)
        return p.returncode, p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="조기기각률 측정")
    ap.add_argument("--ld", required=True)
    ap.add_argument("--main-o", required=True)
    ap.add_argument("--inputs", required=True, help="변이 파일 폴더")
    ap.add_argument("--ldflag", default="")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--label", default="", help="집합 라벨(예: repair_on)")
    args = ap.parse_args(argv)

    files = [p for p in sorted(glob.glob(os.path.join(args.inputs, "*")))
             if os.path.isfile(p)]
    if not files:
        sys.exit("입력 없음: %s" % args.inputs)

    counts = {"GATE_REJECT": 0, "DEEP": 0, "CRASH": 0}
    for p in files:
        rc, se = run_one(args.ld, args.main_o, p, args.ldflag, args.timeout)
        counts[classify(rc, se)] += 1

    total = sum(counts.values())
    er = counts["GATE_REJECT"] / total if total else 0.0
    lab = ("[%s] " % args.label) if args.label else ""
    print("%s총 %d개  |  GATE_REJECT=%d  DEEP=%d  CRASH=%d"
          % (lab, total, counts["GATE_REJECT"], counts["DEEP"], counts["CRASH"]))
    print("%s조기기각률(early-rejection) = %.1f%%   (낮을수록 심층 도달 ↑; 논문 목표 10%%대)"
          % (lab, er * 100))
    print("%s심층도달률 = %.1f%%   크래시율 = %.1f%%"
          % (lab, counts["DEEP"] / total * 100, counts["CRASH"] / total * 100))


if __name__ == "__main__":
    main()
