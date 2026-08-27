#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gold_casr.py — 링커(gold/bfd) 크래시 CASR 버킷팅  [Phase 5 / gold-CASR 신규]

배경(2026-08-28 결정): 기존 CasrDedup(casr_dedup.py)은 **런타임 로더(ld.so)**
경로만 버킷팅한다 — 재현이 `[loader, crash_elf]` 형태이기 때문. 그러나 gold/bfd
링커의 크래시는 '링킹 중'에 발생하므로 재현 명령이 다르다:

    gold -shared -o /dev/null <main.o> <crash.so>

이 모듈은 casr_dedup 의 '검증된' 파싱 프리미티브(_stack_hash/_FRAME_RE/
DedupResult/_casr_bucket)를 그대로 재사용하되, 재현 argv 만 링커식으로 바꾼다.
ld.so 경로(casr_dedup)는 손대지 않으므로 회귀 없음.

버킷 키에는 링커 종류를 접두(`gold:` / `bfd:`)해 gold·bfd 버킷이 섞이지 않게 한다.

반환: casr_dedup.DedupResult (tool_used ∈ {'casr','gdb-fallback'})

사용:
  from lfuzzer.triage.gold_casr import LinkerCasrDedup
  dd = LinkerCasrDedup(linker="~/binutils-build-gold/gold/ld-new",
                       main_o="main.o", kind="gold")
  res = dd.bucket("crash_ab12.so")     # → DedupResult(bucket_key="gold:...")
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import hashlib
from typing import List, Optional

# casr_dedup 의 검증된 프리미티브 재사용(중복 구현 금지)
from lfuzzer.triage.casr_dedup import (
    DedupResult, _stack_hash, _SIG_RE, _FRAME_RE,
    _casr_bucket, _casr_available,
    GDB_TIMEOUT, CASR_TIMEOUT,
)


def _linker_argv(linker: str, main_o: str, crash_so: str,
                 extra: str = "") -> List[str]:
    """gold/bfd 재현 argv. exp_e4_verneed 패턴과 동치."""
    argv = [linker]
    if extra:
        argv += extra.split()
    argv += ["-shared", "-o", os.devnull, main_o, crash_so]
    return argv


def _linker_gdb_backtrace(argv: List[str], nframes: int = 8
                          ) -> "tuple[str, List[str]]":
    """gdb --args <argv> 로 링커를 돌려 (signal, [frame,...]) 추출.
    casr_dedup._gdb_backtrace 와 동일 파서, argv 만 링커식."""
    try:
        out = subprocess.run(
            ["gdb", "--batch", "-ex", "run", "-ex", f"bt {nframes}",
             "--args"] + argv,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=GDB_TIMEOUT, text=True).stdout
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", [])
    except FileNotFoundError:
        return ("NO_GDB", [])
    except Exception:  # noqa
        return ("GDB_ERR", [])

    sig = "?"
    m = _SIG_RE.search(out)
    if m:
        sig = m.group(1)
    frames: List[str] = []
    for ln in out.splitlines():
        fm = _FRAME_RE.match(ln.strip())
        if fm and fm.group(1) != "??":
            frames.append(fm.group(1))
    return (sig, frames)


def _linker_casr_report(argv: List[str]) -> Optional[dict]:
    """casr-gdb -- <argv> 로 report(JSON) 생성. 실패 시 None."""
    import json
    tmpdir = tempfile.mkdtemp(prefix="casr_ld_")
    report = os.path.join(tmpdir, "out.casrep")
    try:
        subprocess.run(
            ["casr-gdb", "-o", report, "--"] + argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=CASR_TIMEOUT)
        if not os.path.exists(report):
            return None
        with open(report, "r", errors="replace") as f:
            return json.load(f)
    except (subprocess.TimeoutExpired, FileNotFoundError,
            json.JSONDecodeError, OSError):
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class LinkerCasrDedup:
    """gold/bfd 링커 크래시 → 버킷. casr 우선, 없으면 gdb 폴백.

    kind: 'gold' | 'bfd' — 버킷 키 접두로 두 링커 버킷을 분리.
    """

    def __init__(self, linker: str, main_o: str, kind: str = "gold",
                 extra: str = "", prefer_casr: bool = True):
        self.linker = os.path.expanduser(linker)
        self.main_o = os.path.expanduser(main_o)
        self.kind = kind
        self.extra = extra
        self.prefer_casr = prefer_casr

    def bucket(self, crash_so: str) -> DedupResult:
        # 재현 불가(링커/main.o 부재) → 내용 해시로라도 dedup 보장
        if not (os.path.exists(self.linker) and os.path.exists(self.main_o)):
            h = "nofile"
            try:
                h = hashlib.sha1(open(crash_so, "rb").read()).hexdigest()[:12]
            except OSError:
                pass
            return DedupResult(bucket_key=f"{self.kind}:no-linker:{h}",
                               top_frame="??", severity_or_None=None,
                               tool_used="gdb-fallback")

        argv = _linker_argv(self.linker, self.main_o, crash_so, self.extra)

        # 1) CASR
        if self.prefer_casr and _casr_available():
            rep = _linker_casr_report(argv)
            if rep is not None:
                res = _casr_bucket(rep)
                # 링커 종류 접두 부여(gold/bfd 버킷 분리)
                res.bucket_key = f"{self.kind}:{res.bucket_key}"
                return res

        # 2) gdb 폴백
        sig, frames = _linker_gdb_backtrace(argv)
        bucket_key, _major, top = _stack_hash(sig, frames)
        return DedupResult(bucket_key=f"{self.kind}:{bucket_key}",
                           top_frame=top, severity_or_None=None,
                           tool_used="gdb-fallback", signal=sig,
                           frames=frames or None)


# ── 데모/자체검증 ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa
        pass
    print("=" * 72)
    print(" LinkerCasrDedup 데모 (gold/bfd 크래시 버킷팅)")
    print("=" * 72)
    print("  casr-gdb :", "있음" if _casr_available() else "없음 → gdb 폴백")

    # 버킷 접두 분리 검증(도구 없이 결정적): 같은 스택도 gold/bfd 는 다른 버킷
    from lfuzzer.triage.casr_dedup import _stack_hash as sh
    bk, _, top = sh("SIGSEGV", ["_bfd_elf_slurp_version_tables", "elf_link_add_object_symbols"])
    gold_key = f"gold:{bk}"
    bfd_key = f"bfd:{bk}"
    assert gold_key != bfd_key, "gold/bfd 버킷은 접두로 분리되어야"
    print(f"  [접두분리 self-test] OK  top={top}")
    print(f"    gold_key = {gold_key}")
    print(f"    bfd_key  = {bfd_key}")
    print("  → 실제 사용: LinkerCasrDedup(linker, main_o, kind).bucket(crash.so)")
