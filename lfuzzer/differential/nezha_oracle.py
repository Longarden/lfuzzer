#!/usr/bin/env python3
"""
lfuzzer/differential/nezha_oracle.py — V3 in-loop delta-diversity 차등 오라클.

무엇을 하나 (한 줄)
-------------------
같은 입력 ELF 를 여러 구현(gold / bfd / ld.so)에 먹여 '관측 벡터'를 뽑고,
구현들 사이의 *의미 차이(delta)* 가 새로운지(novel)·얼마나 심각한지(tier)를
판정해 AFL 의 virtual-edge 피드백으로 되돌린다. 버그 자체를 판정하지 않는다 —
'다르다'는 신호만 만들고, 진짜 CONFIRMED 판정은 CASR/triage 가 한다
(config/DESIGN: LLM·오라클은 ADVISORY, CASR 가 authoritative).

이론적 근거 (인용)
------------------
  • NEZHA (Petsios et al., IEEE S&P 2017): differential fuzzing 을
    '동작 비대칭(behavioral asymmetry)' 을 novelty 로 쓰는 문제로 재정의.
    δ-diversity = 구현별 출력 튜플을 하나의 좌표로 보고, 처음 보는 좌표
    조합을 커버리지처럼 취급한다. 본 모듈의 delta_diversity() 가 그 좌표
    조합의 신규성을 점수화한다.
  • Frankencerts (Brubaker et al., IEEE S&P 2014): 여러 SSL/TLS 구현에
    같은 (변형)입력을 주고 accept/reject 불일치를 버그 신호로 삼은 원조
    differential 기법. 본 모듈의 HARD tier(accept-vs-reject) 판정이 이
    'unanimity 위반' 아이디어를 ELF 링커/로더에 옮긴 것.

운영상 위치 (throughput-negative)
---------------------------------
이 오라클은 메인 AFL 커버리지 트랙과 corpus 를 공유하는 *병렬 트랙*으로
돈다. 매 실행마다 N개 구현을 subprocess 로 재실행하므로 exec/s 를 깎는다
(그래서 별도 트랙). 대신 커버리지만으로는 절대 안 보이는 '의미 분기'를
새 엣지로 주입해, 링커 A는 받고 B는 거부하는 부류의 로직 버그를 유도한다.
커버리지는 metric 이 아니라 엔진이다(DESIGN). metric 은 unique CONFIRMED.

의존성 정책
-----------
Python 3.9+, stdlib + subprocess 만. 서드파티(pyelftools 등) 금지 —
의미 지문(fingerprint) 은 외부 `readelf` 덤프를 정규화해서 만들고, readelf
가 없으면 내장 struct 기반 최소 파서로 폴백한다. gold/bfd/ld.so/readelf 가
하나도 없어도 import 는 성공해야 하며, observe() 는 어떤 도구가 없었는지
status/notes 에 실어 graceful 하게 degrade 한다.

CLI
---
    python -m lfuzzer.differential.nezha_oracle [input.elf ...]
        인자 없으면 template ELF 자동 탐색, 그것도 없으면 self-test 만.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

try:
    from lfuzzer import config as _config
except Exception:  # pragma: no cover - config 는 항상 있어야 하지만 방어적으로
    _config = None


# ===========================================================================
# 0. 상수 / 도구 해석
# ===========================================================================
STATUS_CLASSES = ("accept-clean", "reject-diagnostic", "crash", "timeout")
TIERS = ("benign", "soft", "hard")

# 실행 구현 식별자.  gold/bfd = 링크타임 소비자, ldso = 런타임 로더.
IMPLS = ("gold", "bfd", "ldso")

_TIMEOUT_S = 15
# 크래시로 간주할 시그널 종료(음수 rc = -signal, subprocess 관례).
_CRASH_SIGNALS = {-4, -6, -7, -8, -11, -31}  # ILL,ABRT,BUS,FPE,SEGV,SYS

# stderr 에 이게 있으면 rc 와 무관하게 crash 로 승격(ASan/새니타이저/커널 메시지).
_CRASH_STDERR_RE = re.compile(
    r"(AddressSanitizer|Segmentation fault|SIGSEGV|SIGABRT|"
    r"stack smashing|heap-buffer-overflow|core dumped|"
    r"double free|munmap_chunk|malloc\(\): )",
    re.IGNORECASE,
)


def _tool_path(impl: str) -> Optional[str]:
    """impl → 실행 바이너리 경로(config 우선, 없으면 None). import 실패 안 함."""
    if _config is None:
        return None
    return {
        "gold": getattr(_config, "GOLD", None),
        "bfd": getattr(_config, "BFD", None),
        "ldso": getattr(_config, "LOADER", None),
    }.get(impl)


def _which_readelf() -> Optional[str]:
    import shutil
    return shutil.which("readelf")


# ===========================================================================
# 1. 관측 벡터
# ===========================================================================
@dataclass(frozen=True)
class SemanticFingerprint:
    """구현이 입력 ELF 를 처리한 결과의 *정규화된* 의미 요약.

    canonicalize 대상(모두 순서 독립 → 정렬해 저장):
      symver     : 심볼-버전 해석 결과 [(sym, version), ...]
      dt_tags    : emit/관측된 DT_ 태그 이름 집합
      relocs     : reloc 종류별 개수 [(RELTYPE, count), ...]
      pt_load    : PT_LOAD 세그먼트들의 (권한flags) 목록 + 개수

    TODO(fingerprint canonicalizer): 지금은 입력 ELF 의 readelf 덤프를
    구현 공통으로 읽는 skeleton 이다. 진짜 δ-diversity 를 완성하려면 각
    구현이 *emit/resolve 한* 산출물을 읽어야 한다:
      - gold/bfd: 링크 결과 산출 오브젝트를 다시 readelf 로 파싱
      - ldso:     LD_DEBUG=reloc,symbols 런타임 로그 → 실제 해석된 심볼/reloc
    그 배선이 들어오면 아래 from_readelf() 를 impl 별 소스로 분기한다.
    """
    symver: Tuple[Tuple[str, str], ...] = ()
    dt_tags: Tuple[str, ...] = ()
    relocs: Tuple[Tuple[str, int], ...] = ()
    pt_load: Tuple[str, ...] = ()
    pt_load_count: int = 0

    def canon_hash(self) -> str:
        """정규화된 지문의 안정 해시(hash-class 용). 필드 순서 고정 + 정렬됨."""
        payload = repr((self.symver, self.dt_tags, self.relocs,
                        self.pt_load, self.pt_load_count)).encode()
        return hashlib.sha1(payload).hexdigest()[:16]

    # --- 보안 관련 하위지문: 이게 갈리면 무조건 HARD ------------------------
    def security_tuple(self) -> Tuple:
        """보안상 의미 있는 부분만 뽑은 튜플.
        RELRO/BIND_NOW(DT_FLAGS), 각 PT_LOAD 권한(W^X), PT_LOAD 개수.
        두 구현이 여기서 갈리면 = 한쪽이 더 느슨한 메모리 권한을 산출 = HARD."""
        sec_tags = tuple(t for t in self.dt_tags
                         if t in ("BIND_NOW", "FLAGS", "FLAGS_1", "TEXTREL"))
        return (sec_tags, self.pt_load, self.pt_load_count)


@dataclass
class ObservationVector:
    """한 구현이 한 입력을 처리한 관측 결과. NEZHA 의 '구현별 출력 좌표' 1축."""
    impl: str
    status_class: str                       # STATUS_CLASSES 중 하나
    diagnostic_class_id: str                 # 정규화된 진단(에러) 클래스 id
    fingerprint: SemanticFingerprint = field(default_factory=SemanticFingerprint)
    returncode: Optional[int] = None
    tool_path: Optional[str] = None
    notes: str = ""                          # 어떤 도구가 없었는지 등 degrade 사유
    raw_stderr_head: str = ""                # 디버깅용(정규화 전 앞부분)

    def coord(self) -> Tuple[str, str, str]:
        """이 축의 δ-diversity 좌표: (상태클래스, 진단클래스, 의미해시)."""
        return (self.status_class, self.diagnostic_class_id,
                self.fingerprint.canon_hash())

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["coord"] = self.coord()
        return d


# ===========================================================================
# 2. 진단(에러) 정규화  →  diagnostic_class_id
# ===========================================================================
# 경로/주소/숫자/따옴표 내용 등 '인스턴스마다 달라지는' 노이즈를 지운다.
_NORM_SUBS = [
    (re.compile(r"0x[0-9a-fA-F]+"), "0xADDR"),
    (re.compile(r"\b[0-9]+\b"), "N"),
    (re.compile(r"/[^\s:'\"]+"), "PATH"),          # 절대/상대 경로
    (re.compile(r"'[^']*'"), "'S'"),               # 따옴표 안 심볼/파일명
    (re.compile(r"\"[^\"]*\""), "\"S\""),
    (re.compile(r"\s+"), " "),
]


def normalize_diagnostic(stderr: str) -> str:
    """stderr → 인스턴스 노이즈 제거된 정규 진단 문자열(대표형)."""
    s = (stderr or "").strip()
    if not s:
        return ""
    # 링커/로더 프로그램 이름 접두(예: "ld: ", "ld.gold: ") 제거
    lines = []
    for ln in s.splitlines():
        ln = re.sub(r"^[^:]*ld(\.gold|\.bfd|-linux[^:]*)?:\s*", "", ln.strip())
        for rx, rep in _NORM_SUBS:
            ln = rx.sub(rep, ln)
        ln = ln.strip()
        if ln:
            lines.append(ln)
    # 여러 줄이면 정렬해 순서 흔들림 제거 후 대표화
    canon = " | ".join(sorted(set(lines)))
    return canon


def _diag_class_id(stderr: str) -> str:
    canon = normalize_diagnostic(stderr)
    if not canon:
        return "none"
    return "d:" + hashlib.sha1(canon.encode()).hexdigest()[:10]


# ===========================================================================
# 3. readelf 정규화 덤프 → SemanticFingerprint
# ===========================================================================
def _run(cmd: List[str], **kw) -> Tuple[int, str, str]:
    """(rc, out, err). 타임아웃/미존재 예외를 status 로 흡수."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=_TIMEOUT_S, **kw)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except FileNotFoundError as e:
        return -127, "", f"ENOENT:{e}"
    except Exception as e:  # 방어적: 어떤 환경 이슈든 오라클을 죽이지 않는다
        return -1, "", f"ERROR:{e}"


def _parse_readelf(dump_dl: str, dump_V: str) -> SemanticFingerprint:
    """readelf -d -l (dump_dl) + readelf -V (dump_V) 텍스트를 정규 지문으로.

    파서는 관대(lenient)하게: 형식이 조금 달라도 죽지 않고 뽑을 수 있는 것만.
    """
    dt_tags: List[str] = []
    pt_load: List[str] = []
    symver: List[Tuple[str, str]] = []

    # --- DT_ 태그: "(NEEDED)", "(FLAGS_1)" 처럼 괄호 안 이름을 취한다 ------
    for m in re.finditer(r"\(([A-Z_0-9]+)\)", dump_dl):
        name = m.group(1)
        # DT_NULL 같은 종결자·순수 값은 스킵, 의미 태그만
        if name not in ("NULL",):
            dt_tags.append(name)

    # --- PT_LOAD 권한: readelf -l 의 세그먼트 표에서 LOAD 행 뒤 Flg 열(RWE) --
    #   두 줄 포맷:  "  LOAD  0xoff 0xvaddr ... 0xfilesz 0xmemsz  R E  0x1000"
    for ln in dump_dl.splitlines():
        if re.search(r"\bLOAD\b", ln):
            # 끝쪽의 R/W/E 플래그 묶음을 찾는다(정렬 무관하게 문자만)
            fm = re.search(r"\b([RWE ]{1,5})\b\s+0x[0-9a-fA-F]+\s*$", ln)
            flags = ""
            if fm:
                flags = "".join(sorted(c for c in fm.group(1) if c in "RWE"))
            pt_load.append(flags or "?")

    # --- 심볼-버전 해석: readelf -V 의 .gnu.version_r / _d 항목 ------------
    #   "Name: GLIBC_2.2.5" 류를 버전으로, 앞 심볼과 페어링은 skeleton 단계
    for m in re.finditer(r"Name:\s*([A-Za-z0-9_.]+)", dump_V):
        symver.append(("*", m.group(1)))

    return SemanticFingerprint(
        symver=tuple(sorted(set(symver))),
        dt_tags=tuple(sorted(set(dt_tags))),
        relocs=(),  # TODO: readelf -r 파싱은 impl-emit 배선 때 함께
        pt_load=tuple(pt_load),          # 순서 = 세그먼트 순서(의미 있음)
        pt_load_count=len(pt_load),
    )


def _minimal_fingerprint(path: str) -> SemanticFingerprint:
    """readelf 부재 시 폴백: struct 로 PT_LOAD 개수/권한만이라도 뽑는다(ELF64).

    Program header 만 읽는다. 실패하면 빈 지문(graceful)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return SemanticFingerprint()
        is64 = data[4] == 2
        little = data[5] == 1
        if not is64:
            return SemanticFingerprint()  # 32-bit 는 skeleton 범위 밖
        end = "<" if little else ">"
        e_phoff = struct.unpack_from(end + "Q", data, 0x20)[0]
        e_phentsize = struct.unpack_from(end + "H", data, 0x36)[0]
        e_phnum = struct.unpack_from(end + "H", data, 0x38)[0]
        pt_load: List[str] = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + 8 > len(data):
                break
            p_type, p_flags = struct.unpack_from(end + "II", data, off)
            if p_type == 1:  # PT_LOAD
                fl = ""
                if p_flags & 4: fl += "R"
                if p_flags & 2: fl += "W"
                if p_flags & 1: fl += "E"
                pt_load.append("".join(sorted(fl)) or "?")
        return SemanticFingerprint(pt_load=tuple(pt_load),
                                   pt_load_count=len(pt_load))
    except Exception:
        return SemanticFingerprint()


def fingerprint_input(path: str) -> Tuple[SemanticFingerprint, str]:
    """입력 ELF 의 정규 지문 + 사용한 소스 note. (구현 공통 skeleton)"""
    readelf = _which_readelf()
    if readelf is None:
        return _minimal_fingerprint(path), "readelf-absent:struct-fallback"
    rc1, out_dl, _ = _run([readelf, "-d", "-l", "--wide", path])
    rc2, out_V, _ = _run([readelf, "-V", "--wide", path])
    if rc1 < 0 and rc2 < 0:
        return _minimal_fingerprint(path), "readelf-failed:struct-fallback"
    return _parse_readelf(out_dl, out_V), "readelf"


# ===========================================================================
# 4. observe() — 구현 실행 → ObservationVector
# ===========================================================================
def _classify_status(rc: int, stderr: str) -> str:
    if rc == 124 or (stderr or "").strip() == "TIMEOUT":
        return "timeout"
    if rc in _CRASH_SIGNALS or _CRASH_STDERR_RE.search(stderr or ""):
        return "crash"
    if rc == 0:
        return "accept-clean"
    # rc != 0, 시그널 아님 → 진단과 함께 거부
    return "reject-diagnostic"


def _impl_command(impl: str, tool: str, input_elf: str, workdir: str) -> List[str]:
    """impl 별 실행 커맨드 생성.

    ldso : 로더로 직접 실행(정적/PIE 실행 재현 경로). 인자 없이 로드만 시도.
    gold/bfd : 입력을 링크 입력으로 소비시켜 파서/링크 경로를 태운다.
      -r(관계형) + 출력 버림으로 '읽고 파싱'까지를 최소 실행한다.
    """
    if impl == "ldso":
        # ./ld-linux-x86-64.so.2 <elf>  — 로더가 헤더/PT_DYNAMIC 를 해석
        return [tool, "--", os.path.abspath(input_elf)]
    # gold/bfd: 입력 ELF 를 오브젝트처럼 먹여 파싱/병합 경로 진입
    out = os.path.join(workdir, "nezha_link.out")
    return [tool, "-r", os.path.abspath(input_elf), "-o", out]


def observe(input_elf: str, impl: str,
            workdir: Optional[str] = None) -> ObservationVector:
    """입력 ELF 를 impl 에 먹여 ObservationVector 반환.

    도구가 없으면 status 는 놔두되 notes 에 사유를 싣고 지문만 채운다
    (import·호출 어느 쪽도 예외를 던지지 않는다 — DESIGN: graceful degrade).
    """
    if impl not in IMPLS:
        raise ValueError(f"unknown impl {impl!r}; expected one of {IMPLS}")

    tool = _tool_path(impl)
    fp, fp_note = fingerprint_input(input_elf)

    if tool is None or not os.path.exists(input_elf):
        why = ("tool-absent" if tool is None else "input-missing")
        return ObservationVector(
            impl=impl,
            status_class="reject-diagnostic" if why == "input-missing"
                         else "accept-clean",
            diagnostic_class_id="unavailable:" + why,
            fingerprint=fp,
            returncode=None,
            tool_path=tool,
            notes=f"{why}; fingerprint-source={fp_note}; "
                  f"status is a placeholder (impl not run)",
        )

    import tempfile
    _own_wd = workdir is None
    wd = workdir or tempfile.mkdtemp(prefix="nezha_")
    try:
        cmd = _impl_command(impl, tool, input_elf, wd)
        rc, out, err = _run(cmd, cwd=wd)
        status = _classify_status(rc, err)
        return ObservationVector(
            impl=impl,
            status_class=status,
            diagnostic_class_id=_diag_class_id(err),
            fingerprint=fp,
            returncode=rc,
            tool_path=tool,
            notes=f"fingerprint-source={fp_note}",
            raw_stderr_head=(err or "")[:400],
        )
    finally:
        if _own_wd:
            import shutil
            shutil.rmtree(wd, ignore_errors=True)


# ===========================================================================
# 5. diverged() — tier 판정 (benign / soft / hard)
# ===========================================================================
def diverged(vecs: List[ObservationVector]) -> Tuple[bool, str]:
    """구현별 관측 벡터 리스트 → (분기했나?, tier).

    tier 규칙 (심각도 오름차순):
      hard :  ┌ accept-vs-reject         (한쪽 accept-clean, 다른쪽 reject-diagnostic)
              ├ crash-vs-clean           (한쪽 crash/timeout, 다른쪽 accept-clean)
              └ security-fingerprint 불일치 (RELRO/BIND_NOW/PT_LOAD 권한·개수 상이)
              → Frankencerts 의 'unanimity 위반' = 진짜 로직 갈림. triage 로.
      soft :  같은 status-class 인데 의미 지문(canon_hash) 이 갈림
              (예: 양쪽 accept 지만 emit DT 태그/심볼버전 상이) — 조사 가치 있음.
      benign: status 도 의미 지문도 동일. 진단 문구만 다른 것도 여기(노이즈).

    관측 벡터가 1개 이하면 분기 정의 불가 → (False, 'benign').
    실행 안 된(placeholder) 벡터는 tier 판정에서 제외한다(가짜 HARD 방지).
    """
    real = [v for v in vecs if not v.diagnostic_class_id.startswith("unavailable:")]
    if len(real) < 2:
        return (False, "benign")

    statuses = {v.status_class for v in real}
    accepts = any(v.status_class == "accept-clean" for v in real)
    rejects = any(v.status_class == "reject-diagnostic" for v in real)
    crashes = any(v.status_class in ("crash", "timeout") for v in real)

    # --- HARD: accept-vs-reject / crash-vs-clean --------------------------
    if accepts and rejects:
        return (True, "hard")
    if crashes and accepts:
        return (True, "hard")

    # --- HARD: 보안 지문 불일치 -------------------------------------------
    sec = {v.fingerprint.security_tuple() for v in real}
    if len(sec) > 1:
        return (True, "hard")

    # --- SOFT: 같은 status 인데 의미 지문 갈림 ----------------------------
    fps = {v.fingerprint.canon_hash() for v in real}
    if len(fps) > 1:
        return (True, "soft")

    # --- 모두 같은 status + 같은 의미 지문 --------------------------------
    #     status-class 자체가 여러개인데(예: crash-vs-timeout) 위에서 안 걸린
    #     경우는 soft 로(둘 다 비정상이나 종류가 다름).
    if len(statuses) > 1:
        return (True, "soft")

    # 진단 문구만 다른 것은 benign(anti-flooding 이 이후 dedup).
    return (False, "benign")


# ===========================================================================
# 6. Anti-flooding 원장 (canonicalize → hash-class → allowlist → dedup)
# ===========================================================================
# 알려진 무해 분기 클래스(원장이 처음부터 흘려보냄). 운영하며 채운다.
# 키 = (tier, divergence-class-hash) 또는 tier 단독('benign').
_BENIGN_ALLOWLIST = {
    "benign",  # tier=benign 은 전부 무해
}


def _divergence_class(vecs: List[ObservationVector], tier: str) -> str:
    """분기 사건의 안정 클래스 id. 같은 '종류'의 분기를 하나로 접기 위함.
    구성 = tier + 각 구현의 정렬된 (impl,status,diag,sechash)."""
    parts = []
    for v in sorted(vecs, key=lambda x: x.impl):
        sec = hashlib.sha1(
            repr(v.fingerprint.security_tuple()).encode()).hexdigest()[:8]
        parts.append(f"{v.impl}:{v.status_class}:{v.diagnostic_class_id}:{sec}")
    payload = (tier + "|" + "|".join(parts)).encode()
    return f"{tier}:" + hashlib.sha1(payload).hexdigest()[:12]


class DivergenceLedger:
    """중복 분기 폭주 방지 원장. 파이프라인:

        canonicalize  → 각 벡터를 정규 지문/진단으로 (이미 observe 에서 됨)
        hash-class    → _divergence_class() 로 분기 사건을 한 클래스로 접음
        allowlist     → _BENIGN_ALLOWLIST 에 있으면 흘림(리포트 안 함)
        dedup-first   → 같은 클래스는 '첫 인스턴스'만 통과, 이후는 카운트만

    통과(=처음 본 non-benign 클래스) 시에만 True 를 돌려 상위(triage/AFL
    엣지 주입)에 신규 분기임을 알린다. seen 카운트는 통계로 보존.
    """
    def __init__(self, allowlist: Optional[set] = None) -> None:
        self._seen: Dict[str, int] = {}
        self._allow = set(allowlist) if allowlist is not None else set(_BENIGN_ALLOWLIST)

    def consider(self, vecs: List[ObservationVector]) -> Tuple[bool, str, str]:
        """(is_novel, tier, class_id). is_novel=True 면 처음 본 실제 분기."""
        is_div, tier = diverged(vecs)
        cls = _divergence_class(vecs, tier)
        # allowlist: tier 단독 또는 클래스 id 로 등록 가능
        if not is_div or tier in self._allow or cls in self._allow:
            self._seen[cls] = self._seen.get(cls, 0) + 1
            return (False, tier, cls)
        first_time = cls not in self._seen
        self._seen[cls] = self._seen.get(cls, 0) + 1
        return (first_time, tier, cls)

    def stats(self) -> Dict[str, int]:
        return dict(sorted(self._seen.items()))

    def unique_classes(self) -> int:
        return len(self._seen)


# ===========================================================================
# 7. delta_diversity() — AFL virtual-edge novelty 점수
# ===========================================================================
def delta_diversity(history: List[ObservationVector],
                    vec: ObservationVector) -> float:
    """NEZHA δ-diversity novelty: vec 이 history 대비 얼마나 새 좌표를 여는가.

    반환 [0,1] float. AFL 은 이걸 가상 엣지 히트로 환산(예: score>0 이면
    새 virtual edge 로 취급, 크기로 우선순위) — 커버리지처럼 corpus 를 키운다.

    좌표 성분(각 독립 novelty):
      • status_class        (본 적 없는 상태 → 큰 가중)
      • diagnostic_class_id (본 적 없는 진단 → 중간)
      • fingerprint.canon_hash (본 적 없는 의미 지문 → 중간)
      • (status, diag, fp) 3튜플 조합 (본 적 없는 조합 → 잔여)

    history 가 비면 만점(1.0): 최초 관측은 정의상 전부 신규.
    """
    if not history:
        return 1.0

    seen_status = {h.status_class for h in history}
    seen_diag = {h.diagnostic_class_id for h in history}
    seen_fp = {h.fingerprint.canon_hash() for h in history}
    seen_combo = {h.coord() for h in history}

    W_STATUS, W_DIAG, W_FP, W_COMBO = 0.40, 0.25, 0.25, 0.10
    score = 0.0
    if vec.status_class not in seen_status:
        score += W_STATUS
    if vec.diagnostic_class_id not in seen_diag:
        score += W_DIAG
    if vec.fingerprint.canon_hash() not in seen_fp:
        score += W_FP
    if vec.coord() not in seen_combo:
        score += W_COMBO
    return round(min(1.0, score), 4)


# ===========================================================================
# 8. 편의: 한 입력을 전 구현에 돌려 원장에 넣기
# ===========================================================================
def observe_all(input_elf: str,
                impls: Tuple[str, ...] = IMPLS) -> List[ObservationVector]:
    """입력을 모든 impl 에 관측. (병렬 AFL 트랙에서 매 흥미 입력마다 호출)"""
    return [observe(input_elf, impl) for impl in impls]


# ===========================================================================
# 9. __main__ 데모
# ===========================================================================
def _find_template_elf() -> Optional[str]:
    """데모용 ELF 탐색: REPO_ROOT/seeds|templates|corpus, 그다음 /bin/true."""
    roots = []
    if _config is not None:
        rr = getattr(_config, "REPO_ROOT", None)
        if rr:
            for sub in ("seeds", "templates", "corpus", "template"):
                roots.append(os.path.join(rr, sub))
    for r in roots:
        if os.path.isdir(r):
            for name in sorted(os.listdir(r)):
                p = os.path.join(r, name)
                if os.path.isfile(p):
                    try:
                        with open(p, "rb") as f:
                            if f.read(4) == b"\x7fELF":
                                return p
                    except Exception:
                        pass
    for fallback in ("/bin/true", "/bin/ls", "/usr/bin/true"):
        if os.path.exists(fallback):
            return fallback
    return None


def _demo(inputs: List[str]) -> int:
    print("=" * 72)
    print(" nezha_oracle — V3 delta-diversity 차등 오라클 데모")
    print(" (NEZHA S&P'17 · Frankencerts S&P'14 기반, ADVISORY only)")
    print("=" * 72)

    # 도구 가용성 요약
    for impl in IMPLS:
        t = _tool_path(impl)
        mark = "OK " if (t and os.path.exists(t)) else "absent"
        print(f"  [{mark:>6}] {impl:<5} → {t}")
    print(f"  [{'OK ' if _which_readelf() else 'absent':>6}] readelf → {_which_readelf()}")
    print("-" * 72)

    if not inputs:
        tmpl = _find_template_elf()
        if tmpl:
            print(f"  입력 미지정 → template ELF 사용: {tmpl}")
            inputs = [tmpl]
        else:
            print("  입력도 template ELF 도 없음 → self-test 만 수행.")
            return _self_test()

    ledger = DivergenceLedger()
    history: List[ObservationVector] = []
    for elf in inputs:
        print(f"\n[input] {elf}")
        vecs = observe_all(elf)
        for v in vecs:
            nov = delta_diversity(history, v)
            history.append(v)
            print(f"    {v.impl:<5} status={v.status_class:<17} "
                  f"diag={v.diagnostic_class_id:<16} "
                  f"fp={v.fingerprint.canon_hash()} δ={nov} "
                  f"pt_load={v.fingerprint.pt_load}")
            if v.notes:
                print(f"          note: {v.notes}")
        novel, tier, cls = ledger.consider(vecs)
        is_div, _ = diverged(vecs)
        verdict = ">>> DIVERGED <<<" if is_div else "(구현 합치)"
        flag = "  [NOVEL→AFL edge]" if novel else ("  [dup/allowlisted]" if is_div else "")
        print(f"    ── tier={tier:<7} {verdict}{flag}  class={cls}")

    print("-" * 72)
    print(f"  원장 unique 분기 클래스: {ledger.unique_classes()}")
    for cls, n in ledger.stats().items():
        print(f"      {n:>3}x  {cls}")
    print("=" * 72)
    return 0


def _self_test() -> int:
    """도구 없이도 로직을 검증하는 순수 단위 테스트(합성 벡터)."""
    print("  [self-test] 합성 관측 벡터로 tier/novelty/ledger 검증")
    ok = True

    def mk(impl, status, diag="none", pt=("RE", "RW"), tags=()):
        return ObservationVector(
            impl=impl, status_class=status, diagnostic_class_id=diag,
            fingerprint=SemanticFingerprint(pt_load=pt, pt_load_count=len(pt),
                                            dt_tags=tuple(sorted(tags))))

    # 1) accept vs reject → hard
    d, t = diverged([mk("gold", "accept-clean"), mk("bfd", "reject-diagnostic", "d:x")])
    ok &= (d and t == "hard"); print(f"    accept-vs-reject → {t} {'OK' if d and t=='hard' else 'FAIL'}")

    # 2) crash vs clean → hard
    d, t = diverged([mk("ldso", "crash"), mk("bfd", "accept-clean")])
    ok &= (d and t == "hard"); print(f"    crash-vs-clean   → {t} {'OK' if d and t=='hard' else 'FAIL'}")

    # 3) 보안 지문(PT_LOAD 권한) 불일치 → hard
    d, t = diverged([mk("gold", "accept-clean", pt=("RE", "RW")),
                     mk("bfd", "accept-clean", pt=("RWE",))])
    ok &= (d and t == "hard"); print(f"    secfp-mismatch   → {t} {'OK' if d and t=='hard' else 'FAIL'}")

    # 4) 같은 status, DT 태그만 다름 → soft
    d, t = diverged([mk("gold", "accept-clean", tags=("NEEDED",)),
                     mk("bfd", "accept-clean", tags=("NEEDED", "RPATH"))])
    ok &= (d and t == "soft"); print(f"    dt-tag-diff      → {t} {'OK' if d and t=='soft' else 'FAIL'}")

    # 5) 완전 동일 → benign
    d, t = diverged([mk("gold", "accept-clean"), mk("bfd", "accept-clean")])
    ok &= (not d and t == "benign"); print(f"    identical        → {t} {'OK' if not d else 'FAIL'}")

    # 6) novelty: 최초=1.0, 반복=0.0
    h: List[ObservationVector] = []
    v1 = mk("gold", "accept-clean")
    n1 = delta_diversity(h, v1); h.append(v1)
    n2 = delta_diversity(h, mk("bfd", "accept-clean"))
    ok &= (n1 == 1.0 and n2 == 0.0)
    print(f"    novelty first/repeat = {n1}/{n2} {'OK' if n1==1.0 and n2==0.0 else 'FAIL'}")

    # 7) 원장 dedup: 같은 hard 분기 두 번 → 첫번째만 novel
    lg = DivergenceLedger()
    pair = [mk("gold", "accept-clean"), mk("bfd", "reject-diagnostic", "d:x")]
    a, _, _ = lg.consider(pair)
    b, _, _ = lg.consider(pair)
    ok &= (a and not b)
    print(f"    ledger dedup first/second = {a}/{b} {'OK' if a and not b else 'FAIL'}")

    print("-" * 72)
    print(f"  self-test: {'ALL OK' if ok else 'FAILURES ABOVE'}")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    raise SystemExit(_demo(sys.argv[1:]))
