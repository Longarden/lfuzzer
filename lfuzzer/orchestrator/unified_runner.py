#!/usr/bin/env python3
"""
lfuzzer/orchestrator/unified_runner.py
   — collect-once, dual-oracle 통합 퍼징 루프의 '뼈대(skeleton)'.

무엇을 하나 (한 줄)
-------------------
뮤턴트 1개당 관측 벡터(observation vector)를 '단 한 번' 수집하고, 그 하나의
관측을 서로 다른 두 오라클에 동시에 먹인다:
  · crash-path   → V5 TriagePipeline   (진짜 크래시인가? CASR 권위 판정)
  · divergence-path → V3 nezha_oracle  (gold vs bfd 가 갈리는가?)
한 번 수집해서 두 판정을 뽑기 때문에 링크/실행을 오라클마다 반복하지 않는다.

빌드 순서(V5,V1,V2,V3,V4) → 이 파일에서 각 스테이지가 부르는 모듈
----------------------------------------------------------------------
  V5  crash triage      : lfuzzer.triage.pipeline.TriagePipeline
                          (crash-path 오라클. CASR 가 authoritative)
  V1  harness / target  : lfuzzer.harness            (실행 대상 래퍼; 향후 연결)
  V2  generation        : lfuzzer.mutators.structure_aware  (구조 인지 뮤테이션)
  V3  differential      : lfuzzer.differential.nezha_oracle (divergence 오라클)
  V4  glue              : *바로 이 파일* — 위 넷을 collect-once 루프로 묶는 접착제

설계 불변식 (docs/PIPELINE_VARIANTS.md)
---------------------------------------
  · 지표(metric) = unique CONFIRMED bug 수. coverage 는 AFL 엔진의 연료지 지표 아님.
  · MCP/LLM = ADVISORY ONLY. 판정 못 함. CASR 가 권위(authoritative).
    도구 결과 인용 없는 LLM 주장은 DROP (이 파일은 애초에 LLM 을 호출하지 않는다).
  · 외부 도구(casr/gdb/debug-loader/gold/bfd)가 없어도 import·dry-run 은 반드시 성공.
    무거운 조각은 전부 try/except 뒤에 두고, 없으면 '무엇이 없었는지'를 보고한다.

관측 벡터(ObservationVector)가 담는 5개 채널
--------------------------------------------
  (1) ld.so 직접 실행      : config.LOADER 로 뮤턴트를 로드 (dl-load 재현)
  (2) gold 링크&실행       : config.GOLD  로 링크 → 산출물 실행
  (3) bfd  링크&실행       : config.BFD   로 링크 → 산출물 실행
  (4) readelf -a           : 정적 구조 덤프
  (5) objdump -x           : 정적 헤더/섹션 덤프
  (2)+(3) 이 divergence 오라클의 입력, (1)~(3) 의 크래시 신호가 crash 오라클의 입력.

stdlib + subprocess 전용. 서드파티 import 없음(pyelftools 조차 안 씀).
직접 실행:  python -m lfuzzer.orchestrator.unified_runner   # dry-run 데모
"""
from __future__ import annotations

import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# config 해석 — 없어도 죽지 않게 shim 폴백
# ---------------------------------------------------------------------------
try:
    from lfuzzer import config  # 정상 경로: 패키지로 실행될 때
except Exception:  # pragma: no cover - 단독 실행/경로 문제시 최소 shim
    class _CfgShim:
        BFD = shutil.which("ld.bfd") or shutil.which("ld")
        GOLD = shutil.which("ld.gold") or shutil.which("gold")
        LOADER = next((p for p in [
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"] if os.path.exists(p)), None)
        GHIDRA = None
        REPO_ROOT = str(Path(__file__).resolve().parents[2])
    config = _CfgShim()  # type: ignore


# 디버그+assert glibc 로더(있으면 우선). 태스크 요구: LFUZZER_DEBUG_LOADER.
DEBUG_LOADER = os.environ.get("LFUZZER_DEBUG_LOADER", "").strip() or None

DEFAULT_TIMEOUT = float(os.environ.get("LFUZZER_TIMEOUT", "10"))


# ===========================================================================
# 관측 프리미티브
# ===========================================================================
@dataclass
class ToolResult:
    """도구 1회 실행 결과. 도구 부재/타임아웃/크래시를 1급 상태로 표현한다."""
    name: str                       # 스테이지 라벨 (예: "ld.so", "gold-link")
    cmd: List[str] = field(default_factory=list)
    rc: Optional[int] = None        # 종료코드(음수면 시그널). None=실행 안 됨
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    tool_missing: Optional[str] = None   # 없어서 못 돈 도구 이름(있으면 skip 사유)
    error: Optional[str] = None          # 예외 메시지

    # ---- 파생 신호 (오라클이 읽는 요약) ----
    @property
    def ran(self) -> bool:
        return self.rc is not None or self.timed_out

    @property
    def signal(self) -> Optional[int]:
        """POSIX 관례상 rc<0 이면 -signum 로 죽은 것."""
        if self.rc is not None and self.rc < 0:
            return -self.rc
        return None

    @property
    def crashed(self) -> bool:
        """크래시 신호: 시그널 사망(SIGSEGV/SIGABRT/…) 또는 128+n 코드."""
        if self.signal in (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS,
                            signal.SIGILL, signal.SIGFPE):
            return True
        if self.rc is not None and self.rc >= 128 and self.rc not in (0,):
            sig = self.rc - 128
            if sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS,
                       signal.SIGILL, signal.SIGFPE):
                return True
        # 산출물/스트림에 sanitizer/asan 흔적
        blob = (self.stderr or "") + (self.stdout or "")
        needles = ("AddressSanitizer", "SUMMARY: ", "Segmentation fault",
                   "*** stack smashing", "core dumped")
        return any(n in blob for n in needles)

    def summary(self) -> str:
        if self.tool_missing:
            return f"SKIP(no {self.tool_missing})"
        if self.error:
            return f"ERROR:{self.error}"
        if self.timed_out:
            return "TIMEOUT"
        tag = ""
        if self.crashed:
            tag = " <CRASH>"
        if self.signal:
            return f"rc={self.rc} sig={self.signal}{tag}"
        return f"rc={self.rc}{tag}"


@dataclass
class ObservationVector:
    """뮤턴트 1개에 대한 5채널 관측. 두 오라클이 공유하는 '단일 수집물'."""
    mutant_path: str
    ldso: ToolResult
    gold_link: ToolResult
    gold_run: ToolResult
    bfd_link: ToolResult
    bfd_run: ToolResult
    readelf: ToolResult
    objdump: ToolResult
    collected_at: float = field(default_factory=time.time)

    def channels(self) -> List[ToolResult]:
        return [self.ldso, self.gold_link, self.gold_run,
                self.bfd_link, self.bfd_run, self.readelf, self.objdump]

    def any_crash(self) -> bool:
        return any(c.crashed for c in
                   (self.ldso, self.gold_link, self.gold_run,
                    self.bfd_link, self.bfd_run))

    def pretty(self) -> str:
        lines = [f"ObservationVector  mutant={self.mutant_path}"]
        for c in self.channels():
            lines.append(f"   {c.name:<12} : {c.summary()}")
        return "\n".join(lines)


@dataclass
class OracleVerdict:
    """오라클 하나의 판정. adjudicated=True 는 '이 오라클이 발화했다'."""
    oracle: str                 # "crash(V5)" | "divergence(V3)"
    fired: bool
    label: str                  # 사람이 읽는 사유
    authoritative: bool = False # CASR 등 권위 도구가 실제로 판정했는가
    detail: Dict[str, str] = field(default_factory=dict)


# ===========================================================================
# 저수준 실행 헬퍼
# ===========================================================================
def _run(cmd: List[str], name: str, timeout: float = DEFAULT_TIMEOUT,
         cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None
         ) -> ToolResult:
    """subprocess 1회 실행 → ToolResult. 예외/타임아웃/도구부재를 상태로 흡수."""
    if not cmd:
        return ToolResult(name=name, error="empty command")
    exe = cmd[0]
    # 절대경로가 아니면 PATH 조회로 실재 확인
    if os.sep not in exe and not os.path.isabs(exe):
        resolved = shutil.which(exe)
        if resolved is None:
            return ToolResult(name=name, cmd=cmd, tool_missing=exe)
    elif not os.path.exists(exe):
        return ToolResult(name=name, cmd=cmd, tool_missing=exe)

    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           cwd=cwd, env=env)
        return ToolResult(
            name=name, cmd=cmd, rc=r.returncode,
            stdout=r.stdout.decode("utf-8", "replace"),
            stderr=r.stderr.decode("utf-8", "replace"),
            duration_s=time.time() - t0)
    except subprocess.TimeoutExpired:
        return ToolResult(name=name, cmd=cmd, timed_out=True,
                          duration_s=time.time() - t0)
    except Exception as e:  # 파일 깨짐/권한 등
        return ToolResult(name=name, cmd=cmd, error=f"{type(e).__name__}:{e}",
                          duration_s=time.time() - t0)


# ===========================================================================
# 통합 러너
# ===========================================================================
class UnifiedRunner:
    """collect-once dual-oracle 루프의 오케스트레이션 스켈레톤.

    무거운 조각(V5 TriagePipeline / V3 nezha_oracle / V2 structure_aware /
    V1 harness)은 전부 지연 import + try/except 로 감싼다. 없으면 로컬 폴백
    오라클로 대체하고, 어떤 모듈이 빠졌는지 self.missing 에 기록한다.
    """

    def __init__(self, workdir: Optional[str] = None,
                 timeout: float = DEFAULT_TIMEOUT, verbose: bool = True):
        self.timeout = timeout
        self.verbose = verbose
        self._own_workdir = workdir is None
        self.workdir = workdir or tempfile.mkdtemp(prefix="lfuzz_unified_")
        self.missing: List[str] = []     # 스캐폴드 미존재 모듈 기록

        self.loader = DEBUG_LOADER or getattr(config, "LOADER", None)
        self.gold = getattr(config, "GOLD", None)
        self.bfd = getattr(config, "BFD", None)

        # ---- V5: crash 오라클 (지연 로드) ----
        self._triage = self._load_triage()
        # ---- V3: divergence 오라클 (지연 로드) ----
        self._nezha = self._load_nezha()
        # ---- V2: 생성기 (지연 로드) ----
        self._structure_aware = self._load_structure_aware()
        # ---- V1: harness (향후 실행 대상 래퍼) ----
        self._harness = self._load_harness()

    # ---- 스캐폴드 지연 로더 -------------------------------------------------
    def _load_triage(self):
        try:
            from lfuzzer.triage.pipeline import TriagePipeline  # V5
            return TriagePipeline()
        except Exception as e:
            self.missing.append(f"triage.pipeline.TriagePipeline ({e.__class__.__name__})")
            return None

    def _load_nezha(self):
        try:
            from lfuzzer.differential import nezha_oracle  # V3
            return nezha_oracle
        except Exception as e:
            self.missing.append(f"differential.nezha_oracle ({e.__class__.__name__})")
            return None

    def _load_structure_aware(self):
        try:
            from lfuzzer.mutators import structure_aware  # V2
            return structure_aware
        except Exception as e:
            self.missing.append(f"mutators.structure_aware ({e.__class__.__name__})")
            return None

    def _load_harness(self):
        try:
            from lfuzzer import harness  # V1
            return harness
        except Exception as e:
            self.missing.append(f"harness ({e.__class__.__name__})")
            return None

    # ---- V2 생성 ----------------------------------------------------------
    def generate(self, template_bytes: bytes, seed: int = 0) -> bytes:
        """structure_aware(V2) 로 구조 인지 뮤테이션. 없으면 바이트 폴백."""
        if self._structure_aware is not None:
            for fn_name in ("mutate", "mutate_bytes", "generate"):
                fn = getattr(self._structure_aware, fn_name, None)
                if callable(fn):
                    try:
                        out = fn(template_bytes)  # 기대 시그니처: bytes->bytes
                        if isinstance(out, (bytes, bytearray)):
                            return bytes(out)
                    except Exception:
                        break  # 폴백으로
        return self._fallback_mutate(template_bytes, seed)

    @staticmethod
    def _fallback_mutate(data: bytes, seed: int) -> bytes:
        """구조 인지 생성기가 없을 때의 최소 대체: ELF64 e_phoff 근방 바이트 플립.
        진짜 뮤테이션이 아니라 collect 루프를 흐르게 하는 자극제일 뿐."""
        b = bytearray(data) if data else bytearray(b"\x7fELF" + b"\x00" * 60)
        if len(b) >= 0x40:
            idx = 0x20 + (seed % 8)   # e_phoff(0x20) 근처 1바이트
            b[idx] ^= (0x01 << (seed % 8)) & 0xFF
        else:
            b.append(seed & 0xFF)
        return bytes(b)

    # ---- collect-once: 5채널 관측 수집 -----------------------------------
    def collect(self, mutant_bytes: bytes) -> ObservationVector:
        """뮤턴트를 디스크에 쓰고 5채널을 '한 번' 관측한다."""
        mut = os.path.join(self.workdir, "mutant.elf")
        with open(mut, "wb") as f:
            f.write(mutant_bytes)
        try:
            os.chmod(mut, 0o755)
        except OSError:
            pass

        ldso = self._run_ldso(mut)
        gold_link, gold_run = self._run_linker(self.gold, "gold", mut)
        bfd_link, bfd_run = self._run_linker(self.bfd, "bfd", mut)
        readelf = _run(["readelf", "-a", mut], "readelf", self.timeout)
        objdump = _run(["objdump", "-x", mut], "objdump", self.timeout)

        return ObservationVector(
            mutant_path=mut, ldso=ldso,
            gold_link=gold_link, gold_run=gold_run,
            bfd_link=bfd_link, bfd_run=bfd_run,
            readelf=readelf, objdump=objdump)

    def _run_ldso(self, mut: str) -> ToolResult:
        """(1) ld.so 직접 실행: LOADER 로 뮤턴트 로드(dl-load 경로 재현)."""
        if not self.loader:
            return ToolResult(name="ld.so", tool_missing="LOADER")
        # 디버그 로더 사용시 어썰트 활성 환경 힌트
        env = dict(os.environ)
        env.setdefault("LD_WARN", "1")
        return _run([self.loader, "--inhibit-cache", mut], "ld.so",
                    self.timeout, env=env)

    def _run_linker(self, linker: Optional[str], tag: str, mut: str
                    ) -> Tuple[ToolResult, ToolResult]:
        """(2)/(3) 링크&실행: gcc -B 트릭으로 특정 ld 강제(goldbfd common 방식).
        반환: (link_result, run_result). 링크 실패시 run 은 SKIP 로 표기."""
        if not linker:
            miss = ToolResult(name=f"{tag}-link", tool_missing=f"{tag.upper()} linker")
            return miss, ToolResult(name=f"{tag}-run", tool_missing="link failed")
        if shutil.which("gcc") is None:
            miss = ToolResult(name=f"{tag}-link", tool_missing="gcc")
            return miss, ToolResult(name=f"{tag}-run", tool_missing="gcc")

        # -B<dir> 로 이 링커를 'ld' 로 위장시켜 gcc 가 쓰게 한다.
        bindir = os.path.join(self.workdir, f"ldwrap_{tag}")
        os.makedirs(bindir, exist_ok=True)
        link = os.path.join(bindir, "ld")
        try:
            if os.path.lexists(link):
                os.remove(link)
            os.symlink(os.path.abspath(linker), link)
        except OSError as e:
            miss = ToolResult(name=f"{tag}-link", error=f"symlink:{e}")
            return miss, ToolResult(name=f"{tag}-run", tool_missing="link failed")

        out = os.path.join(self.workdir, f"a_{tag}.out")
        # 뮤턴트 ELF 를 링크 입력으로 준다(그 자체가 obj/so 로 취급되게).
        link_res = _run(["gcc", f"-B{bindir}", "-nostartfiles",
                         "-o", out, mut], f"{tag}-link", self.timeout,
                        cwd=self.workdir)
        link_res.name = f"{tag}-link"

        if link_res.rc == 0 and os.path.exists(out):
            run_res = _run([out], f"{tag}-run", self.timeout, cwd=self.workdir)
        else:
            run_res = ToolResult(name=f"{tag}-run", tool_missing="link produced no exe")
        return link_res, run_res

    # ---- dual-oracle: 하나의 관측 → 두 판정 ------------------------------
    def adjudicate(self, obs: ObservationVector) -> Dict[str, OracleVerdict]:
        """crash-path(V5) 와 divergence-path(V3) 를 같은 관측으로 판정."""
        return {
            "crash": self._crash_oracle(obs),
            "divergence": self._divergence_oracle(obs),
        }

    def _crash_oracle(self, obs: ObservationVector) -> OracleVerdict:
        """V5: 진짜 크래시인가. TriagePipeline 이 있으면 그쪽이 권위(CASR).
        없으면 관측의 시그널/asan 흔적만으로 '후보'만 표기(권위 아님)."""
        if self._triage is not None:
            for fn_name in ("triage", "run", "process", "adjudicate"):
                fn = getattr(self._triage, fn_name, None)
                if callable(fn):
                    try:
                        res = fn(obs.mutant_path)   # 기대: 경로 → 판정 객체
                        fired = bool(getattr(res, "confirmed", res))
                        label = getattr(res, "summary", lambda: str(res))
                        label = label() if callable(label) else str(label)
                        return OracleVerdict(
                            oracle="crash(V5)", fired=fired,
                            label=f"TriagePipeline: {label}",
                            authoritative=True)
                    except Exception as e:
                        return OracleVerdict(
                            oracle="crash(V5)", fired=False,
                            label=f"TriagePipeline error: {e}", authoritative=False)
        # 폴백: 권위 없는 신호 스캔
        hits = [c.name for c in obs.channels() if c.crashed]
        return OracleVerdict(
            oracle="crash(V5)", fired=bool(hits),
            label=("crash-signal on " + ", ".join(hits)) if hits
                  else "no crash signal",
            authoritative=False,
            detail={"note": "TriagePipeline(V5) 미로드 → CASR 권위판정 없음(후보만)"})

    def _divergence_oracle(self, obs: ObservationVector) -> OracleVerdict:
        """V3: gold vs bfd 가 갈리는가. nezha_oracle 있으면 그쪽 사용.
        없으면 rc/시그널/stderr-유무의 로컬 비교로 후보 표기."""
        if self._nezha is not None:
            for fn_name in ("check", "diff", "adjudicate", "compare"):
                fn = getattr(self._nezha, fn_name, None)
                if callable(fn):
                    try:
                        res = fn(obs)
                        fired = bool(getattr(res, "diverged", res))
                        label = getattr(res, "summary", lambda: str(res))
                        label = label() if callable(label) else str(label)
                        return OracleVerdict(
                            oracle="divergence(V3)", fired=fired,
                            label=f"nezha_oracle: {label}", authoritative=True)
                    except Exception as e:
                        return OracleVerdict(
                            oracle="divergence(V3)", fired=False,
                            label=f"nezha_oracle error: {e}", authoritative=False)
        # 폴백: goldbfd diff_report 규칙과 동일한 '갈림' 판정
        return self._fallback_divergence(obs)

    @staticmethod
    def _fallback_divergence(obs: ObservationVector) -> OracleVerdict:
        g_link, b_link = obs.gold_link, obs.bfd_link
        g_run, b_run = obs.gold_run, obs.bfd_run
        reasons = []
        # 링크 단계: 둘 다 실제로 돌았을 때만 비교 의미
        if g_link.ran and b_link.ran:
            if g_link.rc != b_link.rc:
                reasons.append(f"link rc gold={g_link.rc} vs bfd={b_link.rc}")
            if bool(g_link.stderr.strip()) != bool(b_link.stderr.strip()):
                reasons.append("link stderr presence differs")
        if g_run.ran and b_run.ran:
            if g_run.rc != b_run.rc:
                reasons.append(f"run rc gold={g_run.rc} vs bfd={b_run.rc}")
            if g_run.crashed != b_run.crashed:
                reasons.append("run crash differs")
        comparable = (g_link.ran and b_link.ran) or (g_run.ran and b_run.ran)
        return OracleVerdict(
            oracle="divergence(V3)", fired=bool(reasons),
            label="; ".join(reasons) if reasons else
                  ("no divergence" if comparable else "not comparable (linker missing)"),
            authoritative=False,
            detail={"note": "nezha_oracle(V3) 미로드 → 로컬 rc/stderr 비교(후보만)"})

    # ---- 한 뮤턴트 처리: collect → dual adjudicate ------------------------
    def run_once(self, mutant_bytes: bytes) -> Tuple[ObservationVector,
                                                     Dict[str, OracleVerdict]]:
        obs = self.collect(mutant_bytes)
        verdicts = self.adjudicate(obs)
        if self.verbose:
            print(obs.pretty())
            for v in verdicts.values():
                mark = "FIRE" if v.fired else "----"
                auth = "authoritative" if v.authoritative else "advisory/candidate"
                print(f"   [{mark}] {v.oracle:<15} ({auth}) : {v.label}")
        return obs, verdicts

    # ---- 루프: 템플릿을 반복 뮤테이트 -------------------------------------
    def run_loop(self, template_bytes: bytes, iterations: int = 1
                 ) -> List[Tuple[ObservationVector, Dict[str, OracleVerdict]]]:
        results = []
        for i in range(iterations):
            if self.verbose:
                print(f"\n── iteration {i} " + "─" * 40)
            mut = self.generate(template_bytes, seed=i)
            results.append(self.run_once(mut))
        return results

    def cleanup(self):
        if self._own_workdir and os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)


# ===========================================================================
# 템플릿 확보 (없으면 최소 ELF64 헤더 합성)
# ===========================================================================
def _load_template() -> Tuple[bytes, str]:
    """REPO_ROOT 아래 templates/seeds 에서 ELF 하나 찾고, 없으면 합성 바이트."""
    root = Path(getattr(config, "REPO_ROOT", ".") or ".")
    for sub in ("templates", "seeds", "seed", "samples", "corpus"):
        d = root / sub
        if d.is_dir():
            for p in sorted(d.rglob("*")):
                if p.is_file() and p.stat().st_size >= 64:
                    try:
                        with open(p, "rb") as f:
                            head = f.read(4)
                        if head == b"\x7fELF":
                            return open(p, "rb").read(), str(p)
                    except OSError:
                        continue
    return _synth_elf64(), "<synthesized ELF64 header>"


def _synth_elf64() -> bytes:
    """최소 ELF64 EHDR(64B) 합성. 유효한 매직/클래스만 세팅, 뒤는 0.
    진짜 로드 가능한 바이너리가 아니라 collect 파이프를 흐르게 하는 자극."""
    b = bytearray(64)
    b[0:4] = b"\x7fELF"
    b[4] = 2          # EI_CLASS = ELFCLASS64
    b[5] = 1          # EI_DATA  = ELFDATA2LSB
    b[6] = 1          # EI_VERSION
    struct.pack_into("<H", b, 0x10, 2)    # e_type = ET_EXEC
    struct.pack_into("<H", b, 0x12, 0x3e) # e_machine = x86-64
    struct.pack_into("<I", b, 0x14, 1)    # e_version
    struct.pack_into("<H", b, 0x34, 64)   # e_ehsize
    struct.pack_into("<H", b, 0x36, 56)   # e_phentsize
    return bytes(b)


# ===========================================================================
# __main__ : dry-run 데모
# ===========================================================================
def _main() -> int:
    print("=" * 72)
    print(" lfuzzer.orchestrator.unified_runner — collect-once dual-oracle dry-run")
    print("=" * 72)

    runner = UnifiedRunner(verbose=True)

    print("\n[env] 해석된 도구 경로:")
    for label, val in (("LOADER", runner.loader), ("GOLD", runner.gold),
                       ("BFD", runner.bfd),
                       ("readelf", shutil.which("readelf")),
                       ("objdump", shutil.which("objdump")),
                       ("gcc", shutil.which("gcc"))):
        print(f"   {label:<8} = {val if val else '<없음 → 해당 채널 SKIP>'}")

    if runner.missing:
        print("\n[scaffold] 아직 없는 모듈(폴백 오라클/생성기로 대체):")
        for m in runner.missing:
            print(f"   - {m}")
    else:
        print("\n[scaffold] V5/V3/V2/V1 모듈 전부 로드됨.")

    template, src = _load_template()
    print(f"\n[template] {src}  ({len(template)} bytes)")

    print("\n[loop] 1 iteration 뮤테이트 → collect → dual adjudicate")
    results = runner.run_loop(template, iterations=1)

    # 요약
    print("\n" + "─" * 72)
    obs, verdicts = results[0]
    fired = [v.oracle for v in verdicts.values() if v.fired]
    print(f" 요약: 관측 {len(obs.channels())}채널 수집됨. "
          f"발화 오라클 = {fired if fired else '없음(도구 부재시 정상)'}")
    print(" 불변식 확인: LLM 미호출 · CASR 권위 · coverage 는 지표 아님.")
    print("─" * 72)

    runner.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
