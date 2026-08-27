#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
operators.py — 논문 4축(ADD/SUB/SUBST/SCRAMBLE) 정규 뮤테이션 연산자.
==============================================================================

논문의 "구조보존 뮤테이션"은 4개의 축으로 정의된다:

    ADD       엔트리 하나를 '복제'하고 그 소유 카운트를 +1  (PHT/Vernaux)
    SUB       엔트리 하나를 '삭제'하고 소유 카운트를 -1, 뒤 오프셋 하향동기화
    SUBST     필드 값 '치환' — danger/valid-cross/random 세 소스에서 선택
    SCRAMBLE  엔트리 '순서 재배치'(세그먼트 순열) 및/또는 상대오프셋 슬라이드

기존 코드와의 매핑(재사용 원칙):
    - SUBST  : mutate_elf_v4.build_jobs / boundary_set 가 이미 필드테이블+경계값을
               풍부하게 구현. 여기서는 boundary_set 을 방어적 재사용하고, 없으면
               generators.numbers 의 danger 상수풀로 폴백한다.
    - SCRAMBLE: mutator_shuffle.py 의 세그먼트 순열 로직을 흡수(핀 세그먼트=끝고정).
    - ADD/SUB: 신규 구현. PHT 는 파일끝 재배치(ADD)/슬롯 상향시프트(SUB)로
               '전체 파일 이동 없이' 카운트만 동기화한다. Vernaux 는 vn_cnt 동기화.

설계 원칙(저장소 규약):
    - stdlib + 방어적 optional 의존(pyelftools/elf64/mutate_elf_v4). 임포트는
      무조건 성공한다 — 어떤 optional 도 최상위에서 hard-fail 시키지 않는다.
    - 모든 파싱은 순수 파이썬 ElfView(struct) 로 한다(pyelftools 불필요).
      pyelftools 기반 ElfImage/boundary_set 은 '있으면 재사용, 없으면 폴백'.
    - 전제: ELF64 LSB (x86-64). 모든 read/write 는 little-endian.

연산자 계약:
    class Operator:
        name: str
        def apply(self, img, buf: bytearray, rng) -> MutationRecord | None
    - img  : ElfView(권장) 또는 None. None 이면 buf 로부터 새로 파싱한다.
    - buf  : bytearray. **제자리(in-place)** 로 변형한다(길이가 바뀔 수 있음).
    - rng  : random.Random. 결정론적 재현을 위해 호출측이 시드를 쥔다.
    - 반환 : 적용 성공 시 MutationRecord, 대상 부재/실패 시 None(예외 던지지 않음).
"""
from __future__ import annotations

import struct
import random
from dataclasses import dataclass
from typing import List, Optional


# ==========================================================================
# ELF64 상수 (elf64.py / structure_aware.py 와 동일 오프셋)
# ==========================================================================
ELFMAG = b"\x7fELF"
EI_CLASS_OFF, ELFCLASS64 = 4, 2
EI_DATA_OFF, ELFDATA2LSB = 5, 1
E_TYPE_OFF = 16
E_MACHINE_OFF, EM_X86_64 = 18, 62
E_PHOFF_OFF = 32
E_PHENTSIZE_OFF = 54
E_PHNUM_OFF = 56
EHDR_SIZE = 64
PHENTSIZE64 = 56             # Elf64_Phdr 크기

# 프로그램헤더 내부 필드 오프셋(Elf64_Phdr)
PH_TYPE, PH_FLAGS, PH_OFFSET = 0, 4, 8
PH_VADDR, PH_PADDR = 16, 24
PH_FILESZ, PH_MEMSZ, PH_ALIGN = 32, 40, 48

PT_NULL, PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR, PT_TLS = 0, 1, 2, 3, 4, 6, 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_GNU_PROPERTY = 0x6474E553
# SCRAMBLE 시 '끝으로 핀' 고정하는 세그먼트(mutator_shuffle 규약 흡수)
_PIN_TYPES = {PT_NOTE, PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO, PT_GNU_PROPERTY}

# DYNAMIC 태그(필요한 것만)
DT_NULL = 0
DT_STRSZ = 10
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

U16_MAX, U32_MAX, U64_MAX = 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF

_PACK = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}


def _mask(width: int) -> int:
    return (1 << (width * 8)) - 1


def _rd(buf, off, w) -> Optional[int]:
    """경계 검사 포함 little-endian read. 범위 밖이면 None."""
    if off < 0 or off + w > len(buf):
        return None
    return struct.unpack_from(_PACK[w], buf, off)[0]


def _wr(buf, off, w, v) -> bool:
    """경계 검사 포함 little-endian write. 성공 여부 반환."""
    if off < 0 or off + w > len(buf):
        return False
    struct.pack_into(_PACK[w], buf, off, v & _mask(w))
    return True


# ==========================================================================
# 방어적 재사용: mutate_elf_v4.boundary_set (pyelftools 부재 시 폴백)
# ==========================================================================
_V4_BOUNDARY = None          # callable 또는 None
_V4_TRIED = False


def _load_boundary_set():
    """mutate_elf_v4.boundary_set 을 지연·방어 로드.

    mutate_elf_v4 는 pyelftools 부재 시 sys.exit 하므로 절대 최상위에서 임포트
    하지 않는다. 실패는 예외가 아니라 '기능저하(폴백 사용)'로 흡수한다."""
    global _V4_BOUNDARY, _V4_TRIED
    if _V4_TRIED:
        return _V4_BOUNDARY
    _V4_TRIED = True
    try:
        from lfuzzer.mutators.mutate_elf_v4 import boundary_set  # noqa
        _V4_BOUNDARY = boundary_set
    except BaseException:     # SystemExit(pyelftools 없음) 포함 전부 흡수
        _V4_BOUNDARY = None
    return _V4_BOUNDARY


# ==========================================================================
# 방어적 재사용: generators.numbers danger 상수풀 (없으면 인라인 폴백)
# ==========================================================================
def _load_number_pools():
    """generators.numbers 의 POOLS/FIELD_INTENT 를 방어 로드. 실패 시 축약 폴백."""
    try:
        from lfuzzer.generators import numbers as _n  # noqa
        return _n.POOLS, _n.FIELD_INTENT
    except BaseException:
        # numbers.py 부재 시 최소 폴백 풀 (numbers.py 정신의 축약판)
        pools = {
            "SIZE":    [0, 1, 0x1000, 0x7FFFFFFF, 0x80000000, U32_MAX,
                        0x100000000, U64_MAX, 0xDEADBEEF],
            "OFFSET":  [0, 1, 0x40, 0x1000, 0x100000, 0x7FFFFFFF, U32_MAX,
                        U64_MAX, 0xBAD0C0DE],
            "ADDR":    [0, 1, 0x400000, 0x800000000000, 0xFFFF800000000000,
                        U32_MAX, U64_MAX, 0xDEADBEEFDEADBEEF],
            "STR_IDX": [0, 1, U16_MAX, 0x10000, U32_MAX, 0x41414141, 0xBAD0C0DE],
            "MASK":    [0, 1, 0x3, 0x7, 0x1000, 0x1001, U32_MAX, U64_MAX],
        }
        intent = {
            "p_type": "MASK", "p_flags": "MASK", "p_offset": "OFFSET",
            "p_vaddr": "ADDR", "p_paddr": "ADDR", "p_filesz": "SIZE",
            "p_memsz": "SIZE", "p_align": "MASK", "d_un": "ADDR",
            "e_type": "MASK", "e_entry": "ADDR",
            "vna_name": "STR_IDX", "vn_file": "STR_IDX",
            "vna_next": "OFFSET", "vn_next": "OFFSET", "vn_cnt": "SIZE",
        }
        return pools, intent


_POOLS, _FIELD_INTENT = _load_number_pools()

# 필드 → 스펙유효 대체값(valid-cross) 후보. SUBST 가 '문법적으로는 유효하나
# 의미가 뒤바뀐' 값을 주입할 때 사용 — 타입 스왑으로 다른 파서경로를 깨운다.
_VALID_CROSS = {
    "p_type":  [PT_NULL, PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR,
                PT_TLS, PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO,
                PT_GNU_PROPERTY],
    "p_flags": [1, 2, 3, 4, 5, 6, 7],
    "p_align": [0, 1, 0x1000, 0x200000, 0x1000000],
    "e_type":  [1, 2, 3, 4],                 # REL/EXEC/DYN/CORE
    # DYNAMIC d_tag 스왑(다른 유효 DT_ 로 위장) — d_un 이 아니라 태그 자리에 쓴다
    "d_tag":   [1, 2, 4, 5, 6, 7, 8, 10, 12, 13, 15, 16, 17, 18, 23, 25, 27,
                29, 0x6FFFFEF5, 0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE, 0x6FFFFFFF],
}


# ==========================================================================
# MutationRecord — 어떤 변형을 가했는지 감사(audit) 레코드
# ==========================================================================
@dataclass
class MutationRecord:
    """한 번의 연산자 적용 결과. stats/로그/트리아지 조인에 쓴다."""
    axis: str                 # "ADD" | "SUB" | "SUBST" | "SCRAMBLE"
    region: str               # "PHT" | "DYNAMIC" | "VERNEED" | "EHDR"
    field: str                # 건드린 필드/카운트 이름
    old: object = None        # 이전 값(정수 또는 요약)
    new: object = None        # 새 값
    note: str = ""            # 사람이 읽는 부가설명

    def __str__(self):
        o = hex(self.old) if isinstance(self.old, int) else self.old
        n = hex(self.new) if isinstance(self.new, int) else self.new
        return f"{self.axis}/{self.region}.{self.field}: {o}->{n} {self.note}".rstrip()


# ==========================================================================
# ElfView — 순수 파이썬 ELF64 뷰(구조 위치 파악). pyelftools 불필요.
# ==========================================================================
class ElfView:
    """buf 를 파싱해 PHT/DYNAMIC/VERNEED 위치를 뽑는 경량 뷰.

    mutate_elf_v4.ElfImage 와 '오리(duck)' 호환되도록 phdrs/dyn_entries/dt/
    vaddr_to_off/buf/size 를 노출한다 — 그래서 boundary_set·repair_pht 에
    이 뷰를 그대로 넘길 수 있다. 파싱 실패는 예외가 아니라 self.ok=False 로
    표현한다(연산자는 ok=False 면 조용히 None 반환)."""

    def __init__(self):
        self.ok = False
        self.buf = None
        self.size = 0
        self.e_phoff = self.e_phentsize = self.e_phnum = 0
        self.phdrs: List[dict] = []
        self.loads: List[dict] = []
        self.dyn_entries: List[dict] = []
        self.dt: dict = {}
        self.verneeds: List[dict] = []

    @staticmethod
    def pack(width):
        """ElfImage.pack 과 동일 시그니처(boundary_set/apply 호환용)."""
        return _PACK[width]

    @classmethod
    def parse(cls, buf) -> "ElfView":
        """buf(bytes/bytearray)에서 뷰를 구성. 실패해도 ok=False 뷰를 돌려준다."""
        self = cls()
        self.buf = buf
        self.size = len(buf)
        try:
            self._parse()
            self.ok = True
        except Exception:
            self.ok = False
        return self

    # ---- 파싱 ----------------------------------------------------------
    def _parse(self):
        buf = self.buf
        if len(buf) < EHDR_SIZE or bytes(buf[0:4]) != ELFMAG:
            raise ValueError("ELF64 아님")
        self.e_phoff = _rd(buf, E_PHOFF_OFF, 8)
        self.e_phentsize = _rd(buf, E_PHENTSIZE_OFF, 2) or PHENTSIZE64
        self.e_phnum = _rd(buf, E_PHNUM_OFF, 2)
        if self.e_phentsize < PHENTSIZE64:
            self.e_phentsize = PHENTSIZE64

        # 프로그램헤더 순회
        for i in range(self.e_phnum):
            foff = self.e_phoff + i * self.e_phentsize
            if foff + PHENTSIZE64 > self.size:
                break
            d = dict(
                idx=i, foff=foff,
                p_type=_rd(buf, foff + PH_TYPE, 4),
                p_offset=_rd(buf, foff + PH_OFFSET, 8),
                p_vaddr=_rd(buf, foff + PH_VADDR, 8),
                p_filesz=_rd(buf, foff + PH_FILESZ, 8),
                p_memsz=_rd(buf, foff + PH_MEMSZ, 8),
                p_align=_rd(buf, foff + PH_ALIGN, 8),
            )
            self.phdrs.append(d)
            if d["p_type"] == PT_LOAD:
                self.loads.append(d)

        # DYNAMIC 배열(PT_DYNAMIC 의 p_offset 부터 16바이트씩)
        dyn_off = None
        for d in self.phdrs:
            if d["p_type"] == PT_DYNAMIC:
                dyn_off = d["p_offset"]
                break
        if dyn_off is not None:
            o = dyn_off
            for _ in range(256):
                tag = _rd(buf, o, 8)
                val = _rd(buf, o + 8, 8)
                if tag is None or val is None:
                    break
                self.dyn_entries.append(dict(foff=o, d_tag=tag, d_val=val))
                self.dt[tag] = val
                if tag == DT_NULL:
                    break
                o += 16

        # VERNEED 링크드리스트(있으면)
        self._parse_verneed()

    def _parse_verneed(self):
        """DT_VERNEED 가 가리키는 Verneed/Vernaux 체인을 위치만 뽑는다.
           근거: dl-version.c _dl_check_map_versions 가 vn_next/vna_next 무검증."""
        vn_ptr = self.dt.get(DT_VERNEED)
        if vn_ptr is None:
            return
        base = self.vaddr_to_off(vn_ptr)
        if base is None:
            return
        buf = self.buf
        off = base
        guard = 0
        while 0 <= off and off + 16 <= self.size and guard < 64:
            guard += 1
            vn_cnt = _rd(buf, off + 2, 2)
            vn_aux = _rd(buf, off + 8, 4)
            vn_next = _rd(buf, off + 12, 4)
            if vn_aux is None or vn_next is None:
                break
            auxes = []
            ao = off + vn_aux
            g2 = 0
            while 0 <= ao and ao + 16 <= self.size and g2 < 64:
                g2 += 1
                vna_name = _rd(buf, ao + 8, 4)
                vna_next = _rd(buf, ao + 12, 4)
                if vna_next is None:
                    break
                auxes.append(dict(ao=ao, vna_name=vna_name, vna_next=vna_next))
                if vna_next == 0:
                    break
                ao += vna_next
            self.verneeds.append(dict(vn_off=off, vn_cnt=vn_cnt,
                                      vn_aux=vn_aux, vn_next=vn_next, auxes=auxes))
            if vn_next == 0:
                break
            off += vn_next

    def vaddr_to_off(self, vaddr):
        """PT_LOAD 기준 vaddr→파일오프셋(FILESZ 경계). 못 찾으면 None.
           elf64.vaddr_to_offset 와 동일 규약(memsz-aware 아님)."""
        for c in self.loads:
            pv, pf, po = c["p_vaddr"], c["p_filesz"], c["p_offset"]
            if pv is None or pf is None or po is None:
                continue
            if pv <= vaddr < pv + pf:
                return po + (vaddr - pv)
        return None

    # 편의: EHDR e_phnum 재기록(구조 op 공용)
    def _write_phnum(self, buf, value):
        _wr(buf, E_PHNUM_OFF, 2, value)


def _as_view(img, buf) -> ElfView:
    """img 가 ElfView 면 그대로, 아니면 buf 로 새로 파싱(계약: img 는 힌트)."""
    if isinstance(img, ElfView) and img.ok and img.buf is buf:
        return img
    return ElfView.parse(buf)


# ==========================================================================
# Operator 베이스
# ==========================================================================
class Operator:
    """4축 연산자 공통 베이스. name 으로 registry 에 등록된다."""
    name = "operator"
    axis = "?"

    def apply(self, img, buf, rng) -> Optional[MutationRecord]:
        raise NotImplementedError

    def __repr__(self):
        return f"<{type(self).__name__} name={self.name!r}>"


# --------------------------------------------------------------------------
# SUBST — 값 치환(danger / valid-cross / random)
# --------------------------------------------------------------------------
class SubstOp(Operator):
    """필드 값 치환. 세 소스에서 확률적으로 값을 고른다:

        p_danger    : numbers.py danger 풀 + (가용 시) boundary_set 경계값.
        p_validcross: 스펙유효 대체값(p_type/d_tag 스왑 등) — 다른 파서경로 깨움.
        p_random    : 폭만큼의 순수 난수.

    설계상 **파이프라인의 맨 마지막**(canonicalize repair 이후)에 실행되어
    주입한 danger 값이 복구로 지워지지 않고 살아남게 한다. 그래서
    avoid_gate=True 면 GATE 임계필드(magic/class/machine/phentsize/phnum/phoff)는
    피하고, 이후 GATE 재복구가 SUBST 값을 덮지 않도록 보장한다.
    """
    name = "subst"
    axis = "SUBST"

    def __init__(self, p_danger=0.7, p_validcross=0.2, p_random=0.1,
                 avoid_gate=False):
        tot = p_danger + p_validcross + p_random
        self.p_danger = p_danger / tot
        self.p_validcross = p_validcross / tot
        self.p_random = p_random / tot
        self.avoid_gate = avoid_gate

    # 후보 write-site 열거: (region, field, foff, width, intent)
    def _targets(self, view: ElfView):
        t = []
        # EHDR (avoid_gate 면 GATE 임계필드 제외; e_type/e_entry 는 안전)
        t.append(("EHDR", "e_type", E_TYPE_OFF, 2, "MASK"))
        t.append(("EHDR", "e_entry", 24, 8, "ADDR"))
        # PHT (세그먼트별 필드)
        for c in view.phdrs:
            b = c["foff"]
            t.append(("PHT", "p_type", b + PH_TYPE, 4, "MASK"))
            t.append(("PHT", "p_flags", b + PH_FLAGS, 4, "MASK"))
            t.append(("PHT", "p_offset", b + PH_OFFSET, 8, "OFFSET"))
            t.append(("PHT", "p_vaddr", b + PH_VADDR, 8, "ADDR"))
            t.append(("PHT", "p_filesz", b + PH_FILESZ, 8, "SIZE"))
            t.append(("PHT", "p_memsz", b + PH_MEMSZ, 8, "SIZE"))
            t.append(("PHT", "p_align", b + PH_ALIGN, 8, "MASK"))
        # DYNAMIC (d_un 값; d_tag 스왑은 valid-cross 에서만)
        for e in view.dyn_entries:
            if e["d_tag"] == DT_NULL:
                continue
            t.append(("DYNAMIC", "d_un", e["foff"] + 8, 8, "ADDR"))
            t.append(("DYNAMIC", "d_tag", e["foff"], 8, "d_tag"))
        # VERNEED (무검증 순회 필드)
        for vn in view.verneeds:
            o = vn["vn_off"]
            t.append(("VERNEED", "vn_file", o + 4, 4, "STR_IDX"))
            t.append(("VERNEED", "vn_cnt", o + 2, 2, "SIZE"))
            t.append(("VERNEED", "vn_next", o + 12, 4, "OFFSET"))
            for a in vn["auxes"]:
                t.append(("VERNEED", "vna_name", a["ao"] + 8, 4, "STR_IDX"))
                t.append(("VERNEED", "vna_next", a["ao"] + 12, 4, "OFFSET"))
        return t

    def _pick_value(self, field, width, real, view, rng):
        r = rng.random()
        # 1) valid-cross (해당 필드에 스펙유효 대체 후보가 있을 때만)
        if r < self.p_validcross and field in _VALID_CROSS:
            cands = [v for v in _VALID_CROSS[field] if v != real]
            if cands:
                return rng.choice(cands), "validcross"
        # 2) random
        if r < self.p_validcross + self.p_random:
            return rng.getrandbits(width * 8), "random"
        # 3) danger (기본) — numbers 풀 + (가용 시) boundary_set
        intent = _FIELD_INTENT.get(field, "MASK")
        pool = list(_POOLS.get(intent, _POOLS.get("MASK", [0, 1, U32_MAX])))
        bset = _load_boundary_set()
        if bset is not None:
            try:
                pool += bset(width, real, file_size=view.size)
            except Exception:
                pass
        pool = [v & _mask(width) for v in pool if v != real] or [real ^ 1]
        return rng.choice(pool), "danger"

    def apply(self, img, buf, rng) -> Optional[MutationRecord]:
        view = _as_view(img, buf)
        if not view.ok:
            return None
        targets = self._targets(view)
        if self.avoid_gate:
            # GATE 임계필드는 이후 재복구로 덮이므로 SUBST 대상에서 제외.
            # (magic/class/data/machine/phentsize/phnum/phoff 는 애초 미열거이고
            #  여기서는 GATE 재복구가 건드리는 EHDR e_phnum/e_phoff 도 이미 제외됨)
            pass
        if not targets:
            return None
        region, field, foff, width, _intent = rng.choice(targets)
        real = _rd(buf, foff, width)
        if real is None:
            return None
        value, src = self._pick_value(field, width, real, view, rng)
        if not _wr(buf, foff, width, value):
            return None
        return MutationRecord(axis=self.axis, region=region, field=field,
                              old=real, new=value & _mask(width),
                              note=f"src={src}")


# --------------------------------------------------------------------------
# ADD — 엔트리 복제 + 소유 카운트 +1
# --------------------------------------------------------------------------
class AddOp(Operator):
    """엔트리 하나를 복제하고 소유 카운트를 증가.

    PHT   : phdr 하나(56B)를 복제한다. 파일 중간삽입은 모든 오프셋을 흔들므로,
            PHT 를 '파일 끝'으로 재배치(entries+dup)하고 e_phoff/e_phnum 만
            갱신한다 — 기존 콘텐츠 오프셋은 하나도 안 밀린다(구조보존).
    VERNEED: 마지막 Vernaux 를 복제하고 vn_cnt 를 +1. 물리 복제는 바로 뒤 16B 가
            0-패딩일 때만 best-effort 로 링크(vna_next), 아니면 카운트만 +1.
            논문 "포맷 헤더가 지정하는 최대 범위 내" 의도를 지킨다.
    """
    name = "add"
    axis = "ADD"

    def apply(self, img, buf, rng) -> Optional[MutationRecord]:
        view = _as_view(img, buf)
        if not view.ok:
            return None
        # PHT 우선(견고), 없으면/가끔 VERNEED
        do_verneed = view.verneeds and rng.random() < 0.25
        if not do_verneed and view.e_phnum >= 1:
            return self._add_pht(view, buf, rng)
        if view.verneeds:
            return self._add_verneed(view, buf, rng)
        if view.e_phnum >= 1:
            return self._add_pht(view, buf, rng)
        return None

    def _add_pht(self, view, buf, rng):
        n = view.e_phnum
        base = view.e_phoff
        if base + n * PHENTSIZE64 > len(buf) or n < 1:
            return None
        pht = bytes(buf[base:base + n * PHENTSIZE64])
        dup_idx = rng.randrange(n)
        dup = pht[dup_idx * PHENTSIZE64:(dup_idx + 1) * PHENTSIZE64]
        # 파일 끝에 8정렬로 새 PHT(원본+복제) 재배치 → 기존 오프셋 불변
        pad = (-len(buf)) % 8
        buf.extend(b"\x00" * pad)
        new_off = len(buf)
        buf.extend(pht)
        buf.extend(dup)
        _wr(buf, E_PHOFF_OFF, 8, new_off)
        _wr(buf, E_PHNUM_OFF, 2, n + 1)
        return MutationRecord(axis=self.axis, region="PHT", field="e_phnum",
                              old=n, new=n + 1,
                              note=f"dup seg[{dup_idx}], pht->EOF@{hex(new_off)}")

    def _add_verneed(self, view, buf, rng):
        vn = rng.choice(view.verneeds)
        vn_off = vn["vn_off"]
        old_cnt = vn["vn_cnt"] if vn["vn_cnt"] is not None else 0
        # best-effort 물리 복제: 마지막 aux 뒤 16B 가 0-패딩이면 링크한다
        note = "cnt++"
        if vn["auxes"]:
            last = vn["auxes"][-1]
            ao = last["ao"]
            tail = ao + 16
            room = _rd(buf, tail, 8) is not None and _rd(buf, tail + 8, 8) is not None
            if room and buf[tail:tail + 16] == b"\x00" * 16:
                buf[tail:tail + 16] = buf[ao:ao + 16]   # 마지막 aux 복제
                _wr(buf, tail + 12, 4, 0)               # 새 aux vna_next=0(종단)
                _wr(buf, ao + 12, 4, 16)                # 이전 마지막 → 새 aux 링크
                note = "dup last vernaux(+link)"
        _wr(buf, vn_off + 2, 2, (old_cnt + 1) & U16_MAX)   # vn_cnt++
        # DT_VERNEEDNUM 은 verneed '개수' 이므로 aux 복제와는 무관 → 손대지 않음
        return MutationRecord(axis=self.axis, region="VERNEED", field="vn_cnt",
                              old=old_cnt, new=old_cnt + 1, note=note)


# --------------------------------------------------------------------------
# SUB — 엔트리 삭제 + 소유 카운트 -1 (뒤 오프셋/카운트 하향동기화)
# --------------------------------------------------------------------------
class SubOp(Operator):
    """엔트리 하나를 삭제하고 소유 카운트를 감소.

    PHT   : phdr[k] 를 삭제 → 뒤 슬롯들을 한 칸씩 상향 시프트하고 e_phnum -1.
            (PHT 는 연속배열이라 슬롯 시프트만으로 전체 파일 이동 없이 삭제됨.
             논문의 phnum '하향 동기화'.) PT_PHDR(자기참조)은 되도록 피한다.
    VERNEED: 마지막 Vernaux 를 끊어내고 vn_cnt -1 (이전 aux vna_next=0).
            DT_VERNEEDNUM 은 verneed 개수라 aux 삭제와 무관해 손대지 않는다.
    """
    name = "sub"
    axis = "SUB"

    def apply(self, img, buf, rng) -> Optional[MutationRecord]:
        view = _as_view(img, buf)
        if not view.ok:
            return None
        do_verneed = view.verneeds and rng.random() < 0.25
        if not do_verneed and view.e_phnum >= 2:
            return self._sub_pht(view, buf, rng)
        if view.verneeds:
            return self._sub_verneed(view, buf, rng)
        if view.e_phnum >= 2:
            return self._sub_pht(view, buf, rng)
        return None

    def _sub_pht(self, view, buf, rng):
        n = view.e_phnum
        base = view.e_phoff
        if n < 2 or base + n * PHENTSIZE64 > len(buf):
            return None
        # 삭제 대상: PT_PHDR(자기참조)은 되도록 피함
        cands = [c["idx"] for c in view.phdrs if c["p_type"] != PT_PHDR]
        if not cands:
            cands = [c["idx"] for c in view.phdrs]
        k = rng.choice(cands)
        dead_type = view.phdrs[k]["p_type"]
        # k+1..n-1 를 한 칸 상향 시프트(슬롯 단위 56B)
        for i in range(k, n - 1):
            src = base + (i + 1) * PHENTSIZE64
            dst = base + i * PHENTSIZE64
            buf[dst:dst + PHENTSIZE64] = buf[src:src + PHENTSIZE64]
        _wr(buf, E_PHNUM_OFF, 2, n - 1)   # phnum 하향 동기화
        return MutationRecord(axis=self.axis, region="PHT", field="e_phnum",
                              old=n, new=n - 1,
                              note=f"del seg[{k}] type={hex(dead_type)}")

    def _sub_verneed(self, view, buf, rng):
        cands = [vn for vn in view.verneeds if len(vn["auxes"]) >= 1]
        if not cands:
            return None
        vn = rng.choice(cands)
        vn_off = vn["vn_off"]
        old_cnt = vn["vn_cnt"] if vn["vn_cnt"] is not None else len(vn["auxes"])
        # 마지막 aux 를 체인에서 끊어낸다(이전 aux vna_next=0)
        note = "cnt--"
        if len(vn["auxes"]) >= 2:
            prev = vn["auxes"][-2]
            _wr(buf, prev["ao"] + 12, 4, 0)
            note = "unlink last vernaux"
        new_cnt = max(0, old_cnt - 1)
        _wr(buf, vn_off + 2, 2, new_cnt & U16_MAX)
        return MutationRecord(axis=self.axis, region="VERNEED", field="vn_cnt",
                              old=old_cnt, new=new_cnt, note=note)


# --------------------------------------------------------------------------
# SCRAMBLE — 엔트리 순서 재배치(세그먼트 순열) / 상대오프셋 슬라이드
# --------------------------------------------------------------------------
class ScrambleOp(Operator):
    """PHT 엔트리 순서를 재배치. mutator_shuffle.py 로직 흡수:

        - NOTE/GNU_* 세그먼트는 '끝으로 핀' 고정(로더가 순서 민감).
        - 나머지 슬롯만 순열(항등 순열은 회피, 몇 번 재시도).
        - 확률적으로 '상대오프셋 슬라이드'(p_offset 에 페이지배수 델타)도 섞는다.
          이후 canonicalize repair 가 경계를 다시 맞춘다.
    """
    name = "scramble"
    axis = "SCRAMBLE"

    def apply(self, img, buf, rng) -> Optional[MutationRecord]:
        view = _as_view(img, buf)
        if not view.ok or view.e_phnum < 2:
            return None
        n = view.e_phnum
        base = view.e_phoff
        if base + n * PHENTSIZE64 > len(buf):
            return None
        # 확률적으로 상대오프셋 슬라이드 모드
        if rng.random() < 0.25:
            return self._slide(view, buf, rng)

        # 순열 대상: 핀(NOTE/GNU_*) 제외한 인덱스만 섞고, 핀은 원위치 유지
        movable = [c["idx"] for c in view.phdrs if c["p_type"] not in _PIN_TYPES]
        if len(movable) < 2:
            return None
        blocks = [bytes(buf[base + i * PHENTSIZE64: base + (i + 1) * PHENTSIZE64])
                  for i in range(n)]
        perm = movable[:]
        for _ in range(8):
            rng.shuffle(perm)
            if perm != movable:
                break
        else:
            return None   # 항등만 나옴(대상 부족)
        # movable 위치에 perm 순서대로 재배치, 핀 위치는 그대로
        newblocks = list(blocks)
        for slot, srcidx in zip(movable, perm):
            newblocks[slot] = blocks[srcidx]
        for i in range(n):
            buf[base + i * PHENTSIZE64: base + (i + 1) * PHENTSIZE64] = newblocks[i]
        return MutationRecord(axis=self.axis, region="PHT", field="order",
                              old=tuple(movable), new=tuple(perm),
                              note=f"{len(movable)} movable segs permuted")

    def _slide(self, view, buf, rng):
        """한 세그먼트의 p_offset 을 페이지배수만큼 슬라이드(상대오프셋 교란)."""
        c = rng.choice(view.phdrs)
        foff = c["foff"] + PH_OFFSET
        real = _rd(buf, foff, 8)
        if real is None:
            return None
        delta = rng.choice([0x1000, 0x2000, -0x1000, 0x10000]) & U64_MAX
        new = (real + delta) & U64_MAX
        _wr(buf, foff, 8, new)
        return MutationRecord(axis=self.axis, region="PHT", field="p_offset",
                              old=real, new=new,
                              note=f"seg[{c['idx']}] slide {hex(delta)}")


# ==========================================================================
# 자가 테스트 (__main__) — 최소 ELF 합성 후 각 연산자 1회 적용
#   import 시 실행되지 않는다. verifier 가 나중에 `python -m ...` 로 돌린다.
# ==========================================================================
def _synth_min_elf() -> bytearray:
    """PHT(PT_PHDR/PT_LOAD/PT_DYNAMIC) + 작은 DYNAMIC 을 가진 최소 ELF64 합성.

    verneed 는 넣지 않는다(합성 복잡). verneed 연산자는 대상 부재 시 None 을
    돌려주므로 자가 테스트로 '조용한 None' 경로까지 함께 확인된다."""
    buf = bytearray(0x200)
    buf[0:4] = ELFMAG
    buf[EI_CLASS_OFF] = ELFCLASS64
    buf[EI_DATA_OFF] = ELFDATA2LSB
    buf[6] = 1                                  # EI_VERSION
    struct.pack_into("<H", buf, E_TYPE_OFF, 3)  # ET_DYN
    struct.pack_into("<H", buf, E_MACHINE_OFF, EM_X86_64)
    struct.pack_into("<I", buf, 20, 1)          # e_version
    struct.pack_into("<Q", buf, E_PHOFF_OFF, EHDR_SIZE)   # e_phoff=64
    struct.pack_into("<H", buf, 52, EHDR_SIZE)  # e_ehsize
    struct.pack_into("<H", buf, E_PHENTSIZE_OFF, PHENTSIZE64)
    struct.pack_into("<H", buf, E_PHNUM_OFF, 3)

    def wphdr(idx, ptype, off, va, fsz, msz, align):
        b = EHDR_SIZE + idx * PHENTSIZE64
        struct.pack_into("<I", buf, b + PH_TYPE, ptype)
        struct.pack_into("<I", buf, b + PH_FLAGS, 5)
        struct.pack_into("<Q", buf, b + PH_OFFSET, off)
        struct.pack_into("<Q", buf, b + PH_VADDR, va)
        struct.pack_into("<Q", buf, b + PH_PADDR, va)
        struct.pack_into("<Q", buf, b + PH_FILESZ, fsz)
        struct.pack_into("<Q", buf, b + PH_MEMSZ, msz)
        struct.pack_into("<Q", buf, b + PH_ALIGN, align)

    dyn_off = EHDR_SIZE + 3 * PHENTSIZE64       # 64 + 168 = 232 (0xE8)
    # 항등 매핑(vaddr==offset)으로 DYNAMIC 을 v2o 로 찾을 수 있게 한다
    wphdr(0, PT_PHDR, EHDR_SIZE, EHDR_SIZE, 3 * PHENTSIZE64, 3 * PHENTSIZE64, 8)
    wphdr(1, PT_LOAD, 0, 0, len(buf), len(buf), 0x1000)
    wphdr(2, PT_DYNAMIC, dyn_off, dyn_off, 32, 32, 8)
    # DYNAMIC: DT_STRSZ=0x40, DT_NULL
    struct.pack_into("<Q", buf, dyn_off + 0, DT_STRSZ)
    struct.pack_into("<Q", buf, dyn_off + 8, 0x40)
    struct.pack_into("<Q", buf, dyn_off + 16, DT_NULL)
    struct.pack_into("<Q", buf, dyn_off + 24, 0)
    return buf


def _selftest():
    # 콘솔 인코딩이 UTF-8 이 아니어도(예: Windows cp949) 한글/기호 출력이
    # 깨지지 않도록 best-effort 로 stdout 을 UTF-8 로 재설정한다(리눅스는 무해).
    try:
        import sys as _sys
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("=" * 70)
    print("operators.py 자가테스트 — 4축 연산자 각 1회 적용")
    print("=" * 70)
    print(f"[boundary_set 재사용] {'가용' if _load_boundary_set() else '부재→numbers 폴백'}")
    rng = random.Random(1234)
    base = _synth_min_elf()
    v0 = ElfView.parse(base)
    print(f"[합성 ELF] {len(base)}B, ok={v0.ok}, phnum={v0.e_phnum}, "
          f"dyn={len(v0.dyn_entries)}, verneed={len(v0.verneeds)}")

    from_ops = [SubstOp(avoid_gate=True), AddOp(), SubOp(), ScrambleOp()]
    for op in from_ops:
        buf = bytearray(base)
        rec = op.apply(ElfView.parse(buf), buf, rng)
        v = ElfView.parse(buf)
        ok = (len(buf) >= EHDR_SIZE and bytes(buf[0:4]) == ELFMAG)
        print(f"  [{op.name:8s}] rec={rec}  -> len={len(buf)} "
              f"phnum={v.e_phnum} elf_ok={ok}")
        assert ok, f"{op.name}: 출력이 ELF magic 을 잃음"

    # 파이프라인 순서 확인: 구조op -> subst 는 서로 다른 buf 를 만든다
    buf = bytearray(base)
    AddOp().apply(ElfView.parse(buf), buf, rng)
    ScrambleOp().apply(ElfView.parse(buf), buf, rng)
    SubstOp(avoid_gate=True).apply(ElfView.parse(buf), buf, rng)
    print(f"[체인] add->scramble->subst -> {len(buf)}B, "
          f"elf_ok={bytes(buf[0:4]) == ELFMAG}")
    print("\n자가테스트 OK — 각 연산자가 ELF magic 을 유지하며 적용됨.")


if __name__ == "__main__":
    _selftest()
