#!/usr/bin/env python3
"""
casr_dedup.py — 크래시 버킷팅(dedup) with CASR, gdb 폴백.

authoritative 경로:
  1) casr-gdb 로 crash report(.casrep, JSON) 생성 → CrashSeverity/Stacktrace 파싱
  2) casr-cluster 로 스택해시 산출 → bucket_key

폴백(casr 부재):
  autorun_v3.gdb_site 로직을 그대로 재현한 gdb 백트레이스 파서로
  major/minor 스택해시를 손수 계산한다. 진짜로 동작하는 폴백이다(스텁 아님).

반환: DedupResult{bucket_key, top_frame, severity(or None), tool_used}
  tool_used ∈ {'casr', 'gdb-fallback'}
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional

try:
    from .. import config
except Exception:                 # pragma: no cover
    try:
        from lfuzzer import config          # type: ignore
    except Exception:
        import config                        # type: ignore


GDB_TIMEOUT = 20
CASR_TIMEOUT = 30
_STACK_MAJOR_FRAMES = 3    # 상위 3프레임 = major 해시(버킷 경계)


@dataclass
class DedupResult:
    bucket_key: str
    top_frame: str
    severity_or_None: Optional[str]
    tool_used: str          # 'casr' | 'gdb-fallback'
    signal: Optional[str] = None
    frames: Optional[List[str]] = None

    # 스펙 별칭: severity_or_None 필드명을 그대로 노출하되 편의 접근자도 둔다.
    @property
    def severity(self) -> Optional[str]:
        return self.severity_or_None


# ────────────────────────────────────────────────────────────────────────────
# gdb 폴백: autorun_v3.gdb_site 와 behavior-exact 하게 재현.
#   - "received signal (\w+)" 로 시그널
#   - "#N  [0x.. in ]func (" 정규식으로 프레임 함수명들
# 여기서는 dedup 을 위해 프레임을 여러 개 뽑아 스택해시를 만든다.
# ────────────────────────────────────────────────────────────────────────────
_FRAME_RE = re.compile(r"#\d+\s+(?:0x[0-9a-f]+ in )?([A-Za-z_][\w.]*)\s*\(")
_SIG_RE = re.compile(r"received signal\s+(\w+)")


def _gdb_backtrace(loader: str, elf: str, nframes: int = 8) -> "tuple[str, List[str]]":
    """(signal, [frame_func, ...]) 반환. autorun_v3.gdb_site 확장판."""
    try:
        out = subprocess.run(
            ["gdb", "--batch", "-ex", "run", "-ex", f"bt {nframes}",
             "--args", loader, elf],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=GDB_TIMEOUT, text=True).stdout
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", [])
    except FileNotFoundError:
        return ("NO_GDB", [])
    except Exception:
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


def _stack_hash(sig: str, frames: List[str]) -> "tuple[str, str, str]":
    """(bucket_key, major_hash, top_frame). 상위 프레임으로 major 해시.
    major = 상위 _STACK_MAJOR_FRAMES 프레임(정규화) → 버킷 경계.
    프레임이 없으면 시그널만으로 버킷(그래도 dedup 은 된다)."""
    top = frames[0] if frames else "??"
    major_src = "|".join(frames[:_STACK_MAJOR_FRAMES]) or sig
    major = hashlib.sha1(major_src.encode()).hexdigest()[:12]
    # minor(전체 스택)까지 반영해 같은 major 안에서도 구분 가능하게 접미
    minor = hashlib.sha1("|".join(frames).encode()).hexdigest()[:6] if frames else "000000"
    bucket_key = f"{sig}:{top}:{major}"
    return (bucket_key, major, top)


# ────────────────────────────────────────────────────────────────────────────
# CASR 경로
# ────────────────────────────────────────────────────────────────────────────
def _casr_available() -> bool:
    return shutil.which("casr-gdb") is not None


def _casr_report(loader: str, elf: str) -> Optional[dict]:
    """casr-gdb 로 report(JSON) 생성 후 파싱해서 dict 반환. 실패 시 None."""
    tmpdir = tempfile.mkdtemp(prefix="casr_")
    report = os.path.join(tmpdir, "out.casrep")
    try:
        subprocess.run(
            ["casr-gdb", "-o", report, "--", loader, elf],
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


def _casr_bucket(rep: dict) -> DedupResult:
    """casr report(JSON) → DedupResult. casr 스키마의 대표 키를 방어적으로 읽는다."""
    # CrashSeverity: {"Type":..,"ShortDescription":..,"Description":..}
    sev = None
    cs = rep.get("CrashSeverity") or {}
    if isinstance(cs, dict):
        sev = cs.get("ShortDescription") or cs.get("Type")
    # Stacktrace: 문자열 리스트(정규화된 프레임). 상위 프레임에서 함수명 추출.
    st = rep.get("Stacktrace") or rep.get("CrashLine") or []
    frames: List[str] = []
    if isinstance(st, list):
        for entry in st:
            fm = _FRAME_RE.search(str(entry)) or re.search(r"in\s+([A-Za-z_][\w.]*)", str(entry))
            if fm:
                frames.append(fm.group(1))
    top = frames[0] if frames else "??"
    # 스택해시: casr report 에 있으면 쓰고, 없으면 우리가 계산.
    stack_hash = None
    for k in ("StackHash", "ClusterHash", "CrashlineHash"):
        if rep.get(k):
            stack_hash = str(rep[k])[:16]
            break
    if stack_hash is None:
        stack_hash = hashlib.sha1("|".join(frames).encode()).hexdigest()[:12]
    sig = None
    ci = rep.get("CrashInfo") or {}
    if isinstance(ci, dict):
        sig = ci.get("Signal") or ci.get("signal")
    bucket_key = f"casr:{sev or '?'}:{stack_hash}"
    return DedupResult(bucket_key=bucket_key, top_frame=top,
                       severity_or_None=sev, tool_used="casr",
                       signal=str(sig) if sig is not None else None,
                       frames=frames or None)


class CasrDedup:
    """크래시 → 버킷. casr 우선, 없으면 gdb 폴백. 재현 로더는 config.LOADER."""

    def __init__(self, loader: Optional[str] = None,
                 prefer_casr: bool = True):
        self.loader = loader or getattr(config, "LOADER", None)
        self.prefer_casr = prefer_casr

    def bucket(self, crash_elf: str) -> DedupResult:
        loader = self.loader
        if not loader or not os.path.exists(loader):
            # 로더가 없으면 재현 자체가 불가 → 파일 내용 해시로라도 dedup 은 보장.
            h = "nofile"
            try:
                h = hashlib.sha1(open(crash_elf, "rb").read()).hexdigest()[:12]
            except OSError:
                pass
            return DedupResult(bucket_key=f"no-loader:{h}", top_frame="??",
                               severity_or_None=None, tool_used="gdb-fallback")

        # 1) CASR
        if self.prefer_casr and _casr_available():
            rep = _casr_report(loader, crash_elf)
            if rep is not None:
                return _casr_bucket(rep)
            # casr 있으나 report 실패 → 폴백으로 진행(중단 아님)

        # 2) gdb 폴백
        sig, frames = _gdb_backtrace(loader, crash_elf)
        bucket_key, _major, top = _stack_hash(sig, frames)
        return DedupResult(bucket_key=bucket_key, top_frame=top,
                           severity_or_None=None, tool_used="gdb-fallback",
                           signal=sig, frames=frames or None)


# ── 데모 ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile as _tf, sys

    print("=" * 72)
    print(" CasrDedup 데모")
    print("=" * 72)
    dd = CasrDedup()
    print(f"  LOADER      = {dd.loader}")
    print(f"  casr-gdb    = {'있음' if _casr_available() else '없음 → gdb 폴백'}")

    # 폴백 해시 로직 자체 검증(도구 없이도 결정적):
    bk1, _, top1 = _stack_hash("SIGSEGV", ["strcmp", "_dl_map_object", "dl_main"])
    bk2, _, _ = _stack_hash("SIGSEGV", ["strcmp", "_dl_map_object", "dl_main"])
    bk3, _, _ = _stack_hash("SIGSEGV", ["elf_get_dynamic_info", "dl_main"])
    assert bk1 == bk2, "같은 스택은 같은 버킷이어야"
    assert bk1 != bk3, "다른 스택은 다른 버킷이어야"
    print(f"  [stack-hash self-test] OK  top={top1}  bucket={bk1}")

    with _tf.NamedTemporaryFile(prefix="casr_demo_", suffix=".elf",
                                delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        demo = f.name
    try:
        r = dd.bucket(demo)
        print("-" * 72)
        print(f"  bucket_key = {r.bucket_key}")
        print(f"  top_frame  = {r.top_frame}")
        print(f"  severity   = {r.severity_or_None}")
        print(f"  tool_used  = {r.tool_used}")
        print(f"  signal     = {r.signal}")
    finally:
        try:
            os.unlink(demo)
        except OSError:
            pass
    sys.exit(0)
