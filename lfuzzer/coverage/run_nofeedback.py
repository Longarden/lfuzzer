#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_nofeedback.py — 피드백 OFF 대조군(§4.2 ablation)  [Phase 4 / ②]

목적: "커버리지 피드백이 크래시 검출을 늘리는가?" 를 뮤테이터를 고정한 채
격리 측정한다. run_afl.sh(피드백 ON, afl 큐/energy/비트맵) 와 동일한
structure_aware 뮤테이터·동일한 링커·동일한 시드를 쓰되, **커버리지·큐·energy
없이** blind 루프로 돈다. 두 조건의 고유 크래시 수를 비교한다.

  피드백 ON  : afl-fuzz  (run_afl.sh)   — 새 엣지 → 큐 적재 → 재변이
  피드백 OFF : 이 스크립트              — 시드에서 매번 독립 변이, 되먹임 없음

동일하게 고정: 뮤테이터(structure_aware.fuzz), SUT(ld/gold), 시드, 시간예산.
차이: 피드백 루프 유무. → 크래시 수 차이 = 피드백 효과(§4.2 주장 재현).

사용(WSL):
  python3 -m lfuzzer.coverage.run_nofeedback --target bfd --seconds 3600 \\
      --seeds seeds_so --ld ~/binutils-build-afl-bfd/ld/ld-new --main-o main.o
크래시는 out_nofeedback_<target>/ 에 저장, 요약 통계 출력.
"""
from __future__ import annotations

import os
import sys
import time
import glob
import argparse
import hashlib
import subprocess
import tempfile

from lfuzzer.mutators import structure_aware as SA


def is_crash(rc: int) -> bool:
    """음수 rc(시그널 사망) 또는 124(timeout) = 크래시. (autorun_v3 규약과 동치)"""
    return rc < 0 or rc == 124


def run_linker(ld_bin: str, main_o: str, mutant_path: str, ldflag: str,
               timeout: float) -> int:
    """변이 .so 를 링커 입력으로 물려 실행. 반환 rc(음수=시그널, 124=timeout)."""
    cmd = [ld_bin]
    if ldflag:
        cmd += ldflag.split()
    cmd += ["-shared", "-o", os.devnull, main_o, mutant_path]
    try:
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout)
        return p.returncode
    except subprocess.TimeoutExpired:
        return 124


def main(argv=None):
    ap = argparse.ArgumentParser(description="피드백 OFF blind 대조군")
    ap.add_argument("--target", default="bfd", choices=["bfd", "gold"])
    ap.add_argument("--ld", required=True, help="계측 링커 경로(afl 아니어도 됨)")
    ap.add_argument("--main-o", required=True, help="고정 유효 오브젝트(main.o)")
    ap.add_argument("--seeds", required=True, help="유효 .so 시드 폴더")
    ap.add_argument("--out", default=None, help="크래시 저장 폴더")
    ap.add_argument("--seconds", type=float, default=3600, help="시간예산(초)")
    ap.add_argument("--timeout", type=float, default=3.0, help="링커 1회 timeout")
    ap.add_argument("--ldflag", default="", help="추가 링커 플래그")
    ap.add_argument("--seed", type=int, default=0, help="뮤테이터 RNG 시드")
    args = ap.parse_args(argv)

    out = args.out or ("out_nofeedback_%s" % args.target)
    os.makedirs(out, exist_ok=True)

    seeds = []
    for p in sorted(glob.glob(os.path.join(args.seeds, "*"))):
        if os.path.isfile(p):
            with open(p, "rb") as f:
                seeds.append(bytearray(f.read()))
    if not seeds:
        sys.exit("시드 없음: %s" % args.seeds)

    mut = SA.StructureAwareMutator(seed=args.seed)
    rng = mut.rng

    n_exec = 0
    n_crash = 0
    seen = set()                     # 고유 크래시(바이트 해시) — 큐/피드백은 아님
    t0 = time.time()
    deadline = t0 + args.seconds
    print("[nofeedback] target=%s ld=%s seeds=%d budget=%.0fs"
          % (args.target, args.ld, len(seeds), args.seconds))

    while time.time() < deadline:
        base = seeds[rng.randrange(len(seeds))]       # 매번 원본 시드에서(되먹임 X)
        mutant = mut.fuzz(bytes(base), None, max(len(base) * 2, 4096))
        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as tf:
            tf.write(bytes(mutant))
            mpath = tf.name
        try:
            rc = run_linker(args.ld, args.main_o, mpath, args.ldflag, args.timeout)
            n_exec += 1
            if is_crash(rc):
                h = hashlib.sha1(bytes(mutant)).hexdigest()[:12]
                if h not in seen:
                    seen.add(h)
                    n_crash += 1
                    with open(os.path.join(out, "crash_%s_rc%d.so" % (h, rc)), "wb") as f:
                        f.write(bytes(mutant))
        finally:
            os.unlink(mpath)

        if n_exec % 500 == 0:
            el = time.time() - t0
            print("  execs=%d unique_crash=%d rate=%.1f/s elapsed=%.0fs"
                  % (n_exec, n_crash, n_exec / max(el, 1e-9), el))

    el = time.time() - t0
    print("[nofeedback 종료] execs=%d unique_crash=%d elapsed=%.0fs"
          % (n_exec, n_crash, el))
    print("  → run_afl.sh(피드백 ON) 의 고유크래시와 비교하면 §4.2 효과 정량화")
    print("  → 크래시 .so 는 %s/ (다음: triage 로 CASR 버킷팅)" % out)


if __name__ == "__main__":
    main()
