#!/usr/bin/env python3
"""
spec_extractor.py — ELF 스펙의 '권위 있는 단일 소스'를 정본 헤더에서 추출한다.

전략1(프론트엔드) 파이프라인의 첫 단계. 하드코딩 리스트가 아니라
CANONICAL 헤더 /usr/include/elf.h 를 실제로 파싱해서 스펙 지식베이스를
만든다. 논문의 "68종 동적 태그(DT_)" · 프로그램헤더 세그먼트(PT_) ·
섹션(SHT_) 타입을 값과 함께 구조화한다.

왜 헤더를 파싱하나 (SOTA 근거)
------------------------------
DT_/PT_/SHT_ 상수는 배포판·glibc 버전마다 조금씩 다르고, GNU 확장
(DT_VERNEED=0x6ffffffe, PT_GNU_STACK, SHT_GNU_verneed …)은 값이 크고
범위(range) 기반이다. 사람이 리스트를 박아두면 (1) 버전이 어긋나고
(2) 조용히 낡는다. 정본 헤더를 파싱하면 '그 시스템에서 링커/로더가 실제로
쓰는 값' 과 항상 일치한다. 이 시스템에서 gcc/ld 로 컴파일한 시드가
바로 이 스펙을 exercise 하므로, 스펙 소스는 반드시 같은 헤더여야 한다.

파싱 방법
---------
- `#define NAME VALUE` 를 정규식으로 훑는다. VALUE 는 세 형태를 지원:
    (1) 16진수      0x6ffffffe
    (2) 10진수      21
    (3) 산술 참조    (DT_LOOS + 1) / (DT_ADDRRNGLO + 2)
- (3) 은 다른 #define 값을 참조하므로 2-pass 로 해석한다:
    pass1) 즉시 정수(0x../10진수)만 심볼테이블에 채운다.
    pass2) 산술식을 심볼테이블 기준으로 반복 해석(고정점)한다.
      의존이 아직 안 풀리면 다음 라운드로 미루고, 더 이상 진전이 없으면 포기.
- 접두사(DT_/PT_/SHT_/EM_/ET_/STB_/STT_/PF_/SHF_)로 그룹을 나눈다.

방어성
------
- 헤더가 없거나 못 읽으면 예외를 던지지 않고 '명시된' 최소 폴백 세트를
  쓰되, source="fallback" 로 분명히 표시한다. 추출된 것처럼 조용히
  하드코딩하지 않는다(논문 무결성 요구).
- stdlib 전용(re, json, os). 임포트 부작용 없음(추출은 호출 시점에만).
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEFAULT_HEADER = "/usr/include/elf.h"

# 추출 대상 접두사 -> 그룹명. 접두사가 긴 것부터 매칭해야
# STT_ 가 ST_ 로 오분류되지 않는다(여기선 완전 접두사라 무관하나 순서 유지).
_PREFIX_GROUPS = [
    ("DT_", "dt"),
    ("PT_", "pt"),
    ("SHT_", "sht"),
    ("EM_", "em"),
    ("ET_", "et"),
    ("STB_", "stb"),
    ("STT_", "stt"),
    ("PF_", "pf"),
    ("SHF_", "shf"),
]

# `#define  NAME  VALUE  [/* comment */]` 형태만 잡는다(함수형 매크로 제외).
_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$"
)
# 값 뒤에 붙는 주석 제거용
_COMMENT_RE = re.compile(r"/\*.*?\*/|//.*$")
# 16진수 / 10진수 리터럴 (뒤의 U/L 접미사 허용)
_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+[uUlL]*$")
_DEC_RE = re.compile(r"^[0-9]+[uUlL]*$")
# 식별자 토큰(산술식 안의 심볼 참조 탐지용)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class SpecEntry:
    """스펙 상수 1개. name=상수명, value=해석된 정수, group=접두사 그룹,
    note=원본 표현식/주석 등 부가정보(디버깅·추적용)."""
    name: str
    value: int
    group: str
    note: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value,
                "group": self.group, "note": self.note}


@dataclass
class ElfSpec:
    """추출된 ELF 스펙 지식베이스. 그룹별 SpecEntry 리스트 + 출처 메타.

    source: "elf.h" (정본 파싱) 또는 "fallback" (헤더 부재 시 최소 세트).
    header_path: 실제로 읽은 경로(폴백이면 None).
    """
    dt_tags: List[SpecEntry] = field(default_factory=list)
    pt_types: List[SpecEntry] = field(default_factory=list)
    sht_types: List[SpecEntry] = field(default_factory=list)
    em_machines: List[SpecEntry] = field(default_factory=list)
    et_types: List[SpecEntry] = field(default_factory=list)
    stb_bindings: List[SpecEntry] = field(default_factory=list)
    stt_types: List[SpecEntry] = field(default_factory=list)
    pf_flags: List[SpecEntry] = field(default_factory=list)
    shf_flags: List[SpecEntry] = field(default_factory=list)
    source: str = "elf.h"
    header_path: Optional[str] = None

    # 그룹명 -> 필드명 매핑(내부 라우팅용)
    _GROUP_ATTR = {
        "dt": "dt_tags",
        "pt": "pt_types",
        "sht": "sht_types",
        "em": "em_machines",
        "et": "et_types",
        "stb": "stb_bindings",
        "stt": "stt_types",
        "pf": "pf_flags",
        "shf": "shf_flags",
    }

    def add(self, entry: SpecEntry) -> None:
        attr = self._GROUP_ATTR.get(entry.group)
        if attr is not None:
            getattr(self, attr).append(entry)

    def groups(self) -> Dict[str, List[SpecEntry]]:
        """그룹명 -> 엔트리 리스트 딕셔너리(순회·요약용)."""
        return {g: getattr(self, a) for g, a in self._GROUP_ATTR.items()}

    def to_dict(self) -> dict:
        d = {g: [e.to_dict() for e in ents]
             for g, ents in self.groups().items()}
        d["source"] = self.source
        d["header_path"] = self.header_path
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def counts(self) -> Dict[str, int]:
        return {g: len(ents) for g, ents in self.groups().items()}


# ---------------------------------------------------------------------------
# 값 파싱 프리미티브
# ---------------------------------------------------------------------------
def _strip_comment(text: str) -> str:
    """값 표현식 뒤에 붙은 C 주석을 제거하고 양끝 공백을 정리."""
    return _COMMENT_RE.sub("", text).strip()


def _parse_literal(token: str) -> Optional[int]:
    """단일 토큰이 즉시 해석 가능한 정수 리터럴이면 그 값을, 아니면 None.
    U/L 접미사(0x6ffffffeU, 21L 등)를 허용한다."""
    t = token.strip()
    if _HEX_RE.match(t):
        return int(t.rstrip("uUlL"), 16)
    if _DEC_RE.match(t):
        return int(t.rstrip("uUlL"), 10)
    return None


def _eval_arith(expr: str, symbols: Dict[str, int]) -> Optional[int]:
    """산술식을 심볼테이블 기준으로 해석. 성공하면 정수, 미해결이면 None.

    지원 범위(방어적으로 최소): 괄호, + - * , 정수 리터럴, 이미 알려진 심볼.
    식 안의 모든 식별자가 symbols 에 있어야 하고, 안전한 문자만 있을 때만
    eval 한다(임의 코드 실행 방지). elf.h 의 `(DT_LOOS + 1)` 류를 커버.
    """
    e = _strip_comment(expr)
    if not e:
        return None
    # 단일 리터럴이면 바로
    lit = _parse_literal(e)
    if lit is not None:
        return lit

    # 식별자 검사 전에 수치 리터럴을 공백으로 지운다 — 안 그러면 0xef5 의
    # 꼬리 'xef5' 가 식별자로 오인돼(정규식이 letter 시작을 찾음) 산술 참조가
    # 통째로 실패한다(0xNNN 을 쓰는 GNU DT_ range 정의가 대표 사례).
    e_nolit = re.sub(r"\b0[xX][0-9a-fA-F]+[uUlL]*\b", " ", e)
    e_nolit = re.sub(r"\b[0-9]+[uUlL]*\b", " ", e_nolit)
    # 리터럴을 지운 표현식에서만 식별자를 뽑아 symbols 소속을 검증
    idents = set(_IDENT_RE.findall(e_nolit))
    for name in idents:
        if name not in symbols:
            return None

    # 리터럴 접미사(U/L) 제거 — eval 이 이해 못 함
    cleaned = re.sub(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]+\b",
                     lambda m: m.group(1), e)
    # 안전 문자만 허용: 영숫자(식별자 letter 포함)·언더스코어·괄호·공백 +
    # 산술/비트 연산자(+ - * / << >> | & ^ ~). 식별자는 위에서 이미 symbols
    # 소속을 검증했고 __builtins__ 를 막았으므로 임의 코드 실행은 불가.
    # 점(.)·대괄호·따옴표·세미콜론 등은 애초에 매칭 안 되어 거부된다.
    if not re.fullmatch(r"[0-9A-Za-z_+\-*/<>|&^~()\s]+", cleaned):
        return None
    try:
        # 심볼만 노출한 제한 네임스페이스에서 평가(빌트인 차단)
        val = eval(cleaned, {"__builtins__": {}}, dict(symbols))  # noqa: S307
    except Exception:
        return None
    if isinstance(val, int):
        return val
    return None


def _group_for(name: str) -> Optional[str]:
    """상수명 -> 그룹명. 어느 접두사에도 안 맞으면 None."""
    for prefix, group in _PREFIX_GROUPS:
        if name.startswith(prefix):
            return group
    return None


# ---------------------------------------------------------------------------
# 핵심 추출기
# ---------------------------------------------------------------------------
def extract_spec(header_path: str = DEFAULT_HEADER) -> ElfSpec:
    """정본 헤더를 실제로 파싱해 ElfSpec 을 만든다(REAL parse).

    2-pass 해석:
      pass1) 모든 #define 을 수집. 즉시 리터럴은 symbols 에 채우고,
             산술식은 pending 으로 보류.
      pass2) pending 을 고정점까지 반복 해석(참조가 풀릴 때마다 진전).
    그런 다음 DT_/PT_/SHT_/... 접두사 상수만 골라 ElfSpec 에 담는다.

    헤더를 못 읽으면 _fallback_spec() 반환(source="fallback").
    """
    text = _read_header(header_path)
    if text is None:
        return _fallback_spec()

    symbols: Dict[str, int] = {}          # 해석 완료된 name -> value
    order: List[str] = []                 # 등장 순서 보존(중복 시 최초만)
    pending: Dict[str, str] = {}          # 아직 미해결인 name -> raw expr
    notes: Dict[str, str] = {}            # name -> 원본 표현식(추적용)

    # ---- pass1: 스캔 ----
    for line in text.splitlines():
        m = _DEFINE_RE.match(line)
        if not m:
            continue
        name, raw_val = m.group(1), m.group(2)
        expr = _strip_comment(raw_val)
        if not expr:
            continue
        if name not in notes:
            notes[name] = expr
            order.append(name)
        lit = _parse_literal(expr)
        if lit is not None:
            symbols.setdefault(name, lit)
        else:
            pending.setdefault(name, expr)

    # ---- pass2: 산술식 고정점 해석 ----
    # 매 라운드 최소 1개라도 풀리면 계속. 진전이 없으면 종료(미해결은 버림).
    progress = True
    while pending and progress:
        progress = False
        for name in list(pending.keys()):
            val = _eval_arith(pending[name], symbols)
            if val is not None:
                symbols[name] = val
                del pending[name]
                progress = True

    # ---- ElfSpec 조립 (등장 순서 유지, 대상 접두사만) ----
    spec = ElfSpec(source="elf.h", header_path=header_path)
    seen = set()
    for name in order:
        if name in seen or name not in symbols:
            continue
        group = _group_for(name)
        if group is None:
            continue
        seen.add(name)
        spec.add(SpecEntry(name=name, value=symbols[name],
                           group=group, note=notes.get(name, "")))
    return spec


def _read_header(header_path: str) -> Optional[str]:
    """헤더 파일을 읽어 문자열로. 없거나 못 읽으면 None(예외 없음)."""
    try:
        if not header_path or not os.path.isfile(header_path):
            return None
        with open(header_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# 폴백 (헤더 부재 시 — source="fallback" 로 명시)
# ---------------------------------------------------------------------------
def _fallback_spec() -> ElfSpec:
    """정본 헤더가 없을 때만 쓰는 최소 세트. source="fallback" 로 표시해
    '추출된 것처럼' 위장하지 않는다. 실제 파이프라인은 Linux 에서 헤더를
    파싱하는 게 정상 경로다."""
    spec = ElfSpec(source="fallback", header_path=None)
    # 링커/로더가 반드시 보는 핵심 상수만. 값은 System V gABI/GNU 표준.
    dt = [
        ("DT_NULL", 0), ("DT_NEEDED", 1), ("DT_PLTRELSZ", 2), ("DT_PLTGOT", 3),
        ("DT_HASH", 4), ("DT_STRTAB", 5), ("DT_SYMTAB", 6), ("DT_RELA", 7),
        ("DT_RELASZ", 8), ("DT_RELAENT", 9), ("DT_STRSZ", 10),
        ("DT_SYMENT", 11), ("DT_INIT", 12), ("DT_FINI", 13), ("DT_SONAME", 14),
        ("DT_RPATH", 15), ("DT_SYMBOLIC", 16), ("DT_REL", 17), ("DT_RELSZ", 18),
        ("DT_RELENT", 19), ("DT_PLTREL", 20), ("DT_DEBUG", 21),
        ("DT_TEXTREL", 22), ("DT_JMPREL", 23), ("DT_BIND_NOW", 24),
        ("DT_INIT_ARRAY", 25), ("DT_FINI_ARRAY", 26), ("DT_INIT_ARRAYSZ", 27),
        ("DT_FINI_ARRAYSZ", 28), ("DT_RUNPATH", 29), ("DT_FLAGS", 30),
        ("DT_GNU_HASH", 0x6ffffef5), ("DT_VERSYM", 0x6ffffff0),
        ("DT_RELACOUNT", 0x6ffffff9), ("DT_FLAGS_1", 0x6ffffffb),
        ("DT_VERDEF", 0x6ffffffc), ("DT_VERDEFNUM", 0x6ffffffd),
        ("DT_VERNEED", 0x6ffffffe), ("DT_VERNEEDNUM", 0x6fffffff),
    ]
    pt = [
        ("PT_NULL", 0), ("PT_LOAD", 1), ("PT_DYNAMIC", 2), ("PT_INTERP", 3),
        ("PT_NOTE", 4), ("PT_SHLIB", 5), ("PT_PHDR", 6), ("PT_TLS", 7),
        ("PT_GNU_EH_FRAME", 0x6474e550), ("PT_GNU_STACK", 0x6474e551),
        ("PT_GNU_RELRO", 0x6474e552), ("PT_GNU_PROPERTY", 0x6474e553),
    ]
    sht = [
        ("SHT_NULL", 0), ("SHT_PROGBITS", 1), ("SHT_SYMTAB", 2),
        ("SHT_STRTAB", 3), ("SHT_RELA", 4), ("SHT_HASH", 5),
        ("SHT_DYNAMIC", 6), ("SHT_NOTE", 7), ("SHT_NOBITS", 8),
        ("SHT_REL", 9), ("SHT_SHLIB", 10), ("SHT_DYNSYM", 11),
        ("SHT_INIT_ARRAY", 14), ("SHT_FINI_ARRAY", 15),
        ("SHT_GNU_HASH", 0x6ffffff6), ("SHT_GNU_verdef", 0x6ffffffd),
        ("SHT_GNU_verneed", 0x6ffffffe), ("SHT_GNU_versym", 0x6fffffff),
    ]
    et = [("ET_NONE", 0), ("ET_REL", 1), ("ET_EXEC", 2), ("ET_DYN", 3),
          ("ET_CORE", 4)]
    em = [("EM_386", 3), ("EM_X86_64", 62), ("EM_AARCH64", 183)]
    stb = [("STB_LOCAL", 0), ("STB_GLOBAL", 1), ("STB_WEAK", 2)]
    stt = [("STT_NOTYPE", 0), ("STT_OBJECT", 1), ("STT_FUNC", 2),
           ("STT_SECTION", 3), ("STT_FILE", 4), ("STT_TLS", 6)]
    pf = [("PF_X", 1), ("PF_W", 2), ("PF_R", 4)]
    shf = [("SHF_WRITE", 1), ("SHF_ALLOC", 2), ("SHF_EXECINSTR", 4),
           ("SHF_TLS", 0x400)]
    for group, pairs in (("dt", dt), ("pt", pt), ("sht", sht), ("et", et),
                         ("em", em), ("stb", stb), ("stt", stt),
                         ("pf", pf), ("shf", shf)):
        for name, value in pairs:
            spec.add(SpecEntry(name=name, value=value, group=group,
                               note="fallback"))
    return spec


# ---------------------------------------------------------------------------
# 요약
# ---------------------------------------------------------------------------
def summary(spec: ElfSpec) -> str:
    """"DT_: 68, PT_: 12, SHT_: 26 ..." 형태의 한 줄 요약(+ 출처)."""
    label = {
        "dt": "DT_", "pt": "PT_", "sht": "SHT_", "em": "EM_", "et": "ET_",
        "stb": "STB_", "stt": "STT_", "pf": "PF_", "shf": "SHF_",
    }
    parts = [f"{label[g]}: {n}" for g, n in spec.counts().items()]
    return f"[{spec.source}] " + ", ".join(parts)


if __name__ == "__main__":
    # UTF-8 stdout 강제 (Windows 콘솔에서 한글/기호 깨짐 방지)
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    header = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HEADER
    spec = extract_spec(header)
    print("=" * 72)
    print(" ELF Spec Extractor (spec_extractor.py)")
    print("=" * 72)
    print(" source     :", spec.source)
    print(" header_path:", spec.header_path)
    print(" summary    :", summary(spec))
    print("-" * 72)
    for group, ents in spec.groups().items():
        print(f" {group:>4} : {len(ents):3d} entries")
        for e in ents[:4]:
            print(f"        {e.name:<20} = 0x{e.value:x}")
        if len(ents) > 4:
            print(f"        ... (+{len(ents) - 4} more)")
    print("-" * 72)
    if spec.source == "fallback":
        print(" NOTE: 헤더 미발견 → 폴백 최소 세트 사용. Linux 에서 재실행하면")
        print("       /usr/include/elf.h 를 실제 파싱한다.")
