#!/usr/bin/env python3
"""
tri_oracle.py — 크래시 후보 재현 검증 오라클 (TriOracle).

한 크래시 ELF 를 세 경로로 다시 돌려 '정말 버그냐'를 접지한다:
  (1) stock ld.so         : config.LOADER 로 직접 실행 → 시그널/타임아웃이면 재현
  (2) debug+assert ld.so  : LFUZZER_DEBUG_LOADER (있으면). glibc assert 발화를 잡는다.
                            없으면 graceful — assert_rc=None, has_assertion=None.
  (3) gold vs bfd 차등     : config.GOLD / config.BFD 로 같은 입력을 링크(직접 실행)해
                            rc 가 갈리는지 본다. 둘 중 하나라도 없으면 그 쪽은 None.

confirmed 판정(엄수):
    reproduces as signal/timeout on stock   OR   assert-fires on debug
  gold/bfd 차등은 보조 증거일 뿐 confirmed 를 좌우하지 않는다.

stdlib + subprocess 전용. 모든 외부 실행은 타임아웃을 건다.
외부 도구가 없으면 import/실행 모두 죽지 않고 '무엇이 없었는지'를 결과에 담는다.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

# --- config 접근 (패키지/단독 실행 양쪽에서 안전하게) ---------------------------
try:                              # 정상: 패키지의 일부로 임포트
    from .. import config
except Exception:                 # pragma: no cover - 단독 실행 폴백
    try:
        from lfuzzer import config          # type: ignore
    except Exception:
        import config                        # type: ignore


# ── 타임아웃(초) ────────────────────────────────────────────────────────────────
STOCK_TIMEOUT = 5
ASSERT_TIMEOUT = 8      # 디버그 빌드는 느리다
LINK_TIMEOUT = 20


def _sig_of(rc: Optional[int]) -> Optional[str]:
    """returncode → 사람이 읽는 시그널/타임아웃 라벨. 정상종료면 None."""
    if rc is None:
        return None
    if rc == 124:
        return "TIMEOUT"
    if rc < 0:
        return f"SIG{-rc}"
    return None


def _run(cmd: List[str], timeout: int, capture: bool = False):
    """(rc, text) 반환. rc: 음수=시그널, 124=타임아웃, -999=실행 불가.
    capture=True 면 stderr+stdout 텍스트를 합쳐 반환(없으면 '')."""
    out = subprocess.PIPE if capture else subprocess.DEVNULL
    err = subprocess.STDOUT if capture else subprocess.DEVNULL
    try:
        r = subprocess.run(cmd, stdout=out, stderr=err, timeout=timeout)
        text = ""
        if capture and r.stdout is not None:
            text = r.stdout.decode("utf-8", errors="replace")
        return r.returncode, text
    except subprocess.TimeoutExpired:
        return 124, ""
    except FileNotFoundError:
        return -999, ""
    except Exception:
        return -999, ""


@dataclass
class TriResult:
    """확인 결과. field_diff/증거 dict 로도 쉽게 풀리도록 평면적으로 유지."""
    stock_rc: Optional[int] = None
    stock_sig: Optional[str] = None
    assert_rc: Optional[int] = None
    has_assertion: Optional[bool] = None       # None = 디버그 로더 부재로 판단 불가
    gold_rc: Optional[int] = None
    bfd_rc: Optional[int] = None
    diverged: bool = False
    confirmed: bool = False
    # 진단용: 무슨 도구가 없어서 무엇을 건너뛰었는지
    missing: List[str] = field(default_factory=list)
    assertion_text: Optional[str] = None

    def as_evidence(self) -> dict:
        """mcp_advisor 에 넘길 tool-result 형태(인용 키의 원천)."""
        return {
            "tri_oracle": {
                "stock_rc": self.stock_rc, "stock_sig": self.stock_sig,
                "assert_rc": self.assert_rc, "has_assertion": self.has_assertion,
                "gold_rc": self.gold_rc, "bfd_rc": self.bfd_rc,
                "diverged": self.diverged, "confirmed": self.confirmed,
            }
        }


class TriOracle:
    """세 경로 재현 오라클. 인스턴스는 로더/링커 경로를 config 에서 해석해 캐시한다."""

    def __init__(self,
                 loader: Optional[str] = None,
                 debug_loader: Optional[str] = None,
                 debug_libpath: Optional[str] = None,
                 gold: Optional[str] = None,
                 bfd: Optional[str] = None):
        # 명시 인자 > config/env
        self.loader = loader or getattr(config, "LOADER", None)
        self.debug_loader = (debug_loader
                             or os.environ.get("LFUZZER_DEBUG_LOADER"))
        self.debug_libpath = (debug_libpath
                             or os.environ.get("LFUZZER_DEBUG_LIBPATH"))
        self.gold = gold or getattr(config, "GOLD", None)
        self.bfd = bfd or getattr(config, "BFD", None)

    # ── (1) stock ld.so ─────────────────────────────────────────────────────
    def _run_stock(self, crash_elf: str, res: TriResult) -> None:
        if not self.loader or not os.path.exists(self.loader):
            res.missing.append("stock-loader(config.LOADER)")
            return
        rc, _ = _run([self.loader, crash_elf], STOCK_TIMEOUT)
        if rc == -999:
            res.missing.append("stock-loader(exec-failed)")
            return
        res.stock_rc = rc
        res.stock_sig = _sig_of(rc)

    # ── (2) debug+assert ld.so ──────────────────────────────────────────────
    def _run_debug(self, crash_elf: str, res: TriResult) -> None:
        if not self.debug_loader or not os.path.exists(self.debug_loader):
            res.missing.append("debug-loader(LFUZZER_DEBUG_LOADER)")
            return  # has_assertion 은 None 으로 남겨 '판단 불가'를 표현
        cmd = [self.debug_loader]
        if self.debug_libpath:
            cmd += ["--library-path", self.debug_libpath]
        cmd += [crash_elf]
        rc, text = _run(cmd, ASSERT_TIMEOUT, capture=True)
        if rc == -999:
            res.missing.append("debug-loader(exec-failed)")
            return
        res.assert_rc = rc
        m = re.search(r"Assertion `([^']+)' failed", text)
        res.has_assertion = bool(m)
        if m:
            res.assertion_text = m.group(1)[:120]

    # ── (3) gold vs bfd 차등 ────────────────────────────────────────────────
    def _link_one(self, linker: Optional[str], crash_elf: str,
                  which: str, res: TriResult) -> Optional[int]:
        if not linker or not os.path.exists(linker):
            res.missing.append(f"{which}(config.{which.upper()})")
            return None
        # 직접 실행: 링커에 크래시 ELF 를 입력 오브젝트로 먹인다.
        # 산출물은 버린다(재현 rc 만 관심). -o /dev/null 로 부작용 최소화.
        rc, _ = _run([linker, crash_elf, "-o", os.devnull], LINK_TIMEOUT)
        if rc == -999:
            res.missing.append(f"{which}(exec-failed)")
            return None
        return rc

    def _run_diff(self, crash_elf: str, res: TriResult) -> None:
        res.gold_rc = self._link_one(self.gold, crash_elf, "gold", res)
        res.bfd_rc = self._link_one(self.bfd, crash_elf, "bfd", res)
        if res.gold_rc is not None and res.bfd_rc is not None:
            res.diverged = (res.gold_rc != res.bfd_rc)

    # ── 공개 API ────────────────────────────────────────────────────────────
    def confirm(self, crash_elf: str) -> TriResult:
        """crash_elf 를 세 경로로 재현 검증하고 TriResult 를 반환한다."""
        res = TriResult()
        if not os.path.exists(crash_elf):
            res.missing.append(f"crash-elf-not-found:{crash_elf}")
            return res

        self._run_stock(crash_elf, res)
        self._run_debug(crash_elf, res)
        self._run_diff(crash_elf, res)

        stock_repro = res.stock_sig is not None      # SIGxx 또는 TIMEOUT
        assert_fired = res.has_assertion is True
        res.confirmed = bool(stock_repro or assert_fired)
        return res


# ── 데모 ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, sys

    print("=" * 72)
    print(" TriOracle 데모")
    print("=" * 72)
    orc = TriOracle()
    print(f"  LOADER       = {orc.loader}")
    print(f"  DEBUG_LOADER = {orc.debug_loader}  (env LFUZZER_DEBUG_LOADER)")
    print(f"  GOLD         = {orc.gold}")
    print(f"  BFD          = {orc.bfd}")

    # 합성 입력: 진짜 ELF 가 아니어도 파이프라인이 죽지 않음을 보인다.
    with tempfile.NamedTemporaryFile(prefix="trioracle_demo_", suffix=".elf",
                                     delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)   # 헤더 흉내만 낸 쓰레기
        demo = f.name
    try:
        r = orc.confirm(demo)
        print("-" * 72)
        print(f"  stock_rc={r.stock_rc} stock_sig={r.stock_sig}")
        print(f"  assert_rc={r.assert_rc} has_assertion={r.has_assertion}")
        print(f"  gold_rc={r.gold_rc} bfd_rc={r.bfd_rc} diverged={r.diverged}")
        print(f"  confirmed={r.confirmed}")
        if r.missing:
            print(f"  (없어서 건너뛴 것: {', '.join(r.missing)})")
    finally:
        try:
            os.unlink(demo)
        except OSError:
            pass
    sys.exit(0)
