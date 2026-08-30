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
# 재배치/심볼 위치 태그(로더 충실 — SHT 없이도 이걸로 재배치/심볼 순회)
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_JMPREL = 23
DT_PLTRELSZ = 2

# ---- 섹션헤더(Elf64_Shdr) — EHDR 내 SHT 위치 + 엔트리 내부 오프셋 ----
E_SHOFF_OFF = 40            # 0x28  e_shoff (u64)
E_SHENTSIZE_OFF = 58        # 0x3A  e_shentsize (u16)
E_SHNUM_OFF = 60            # 0x3C  e_shnum (u16)
E_SHSTRNDX_OFF = 62         # 0x3E  e_shstrndx (u16)
SHENTSIZE64 = 64            # Elf64_Shdr 크기
SH_NAME, SH_TYPE, SH_FLAGS = 0x00, 0x04, 0x08
SH_ADDR, SH_OFFSET, SH_SIZE = 0x10, 0x18, 0x20
SH_LINK, SH_INFO, SH_ADDRALIGN, SH_ENTSIZE = 0x28, 0x2C, 0x30, 0x38
SHT_SYMTAB, SHT_RELA, SHT_NOTE, SHT_DYNSYM = 2, 4, 7, 11

# ---- 심볼(Elf64_Sym, 24B) 내부 오프셋 ----
SYMENT64 = 24
ST_NAME, ST_INFO, ST_OTHER, ST_SHNDX, ST_VALUE, ST_SIZE = 0x00, 0x04, 0x05, 0x06, 0x08, 0x10

# ---- 노트(Elf64_Nhdr, 12B 헤더 + name + desc) ----
N_NAMESZ, N_DESCSZ, N_TYPE = 0x00, 0x04, 0x08

# ---- 재배치(Elf64_Rela, 24B) 내부 오프셋 ----
RELAENT64 = 24
R_OFFSET, R_INFO, R_ADDEND = 0x00, 0x08, 0x10

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
    # DYNAMIC d_tag 스왑(다른 유효 DT_ 로 위장) — d_un 이 아니라 태그 자리에 쓴다.
    # 표준 DT_ 0~37 전부 + GNU/OS(0x6ffffxxx) + PROC 경계 = 로더의 68개 DT 핸들러 전부 겨냥.
    "d_tag":   list(range(1, 38)) + [   # 0(DT_NULL) 제외 — 중간 relabel 시 배열 조기절단(리뷰)
        0x6000000D, 0x6FFFFDFF, 0x6FFFFEF5, 0x6FFFFEF6, 0x6FFFFEF7, 0x6FFFFEF8,
        0x6FFFFEF9, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x6FFFFEFD, 0x6FFFFEFE,
        0x6FFFFEFF, 0x6FFFFFF0, 0x6FFFFFF9, 0x6FFFFFFA, 0x6FFFFFFB, 0x6FFFFFFC,
        0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF, 0x70000000, 0x7FFFFFFF],
    # SHT: 유효 sh_type 스왑(다른 파서 서브루틴 깨움: SYMTAB/RELA/NOTE/DYNSYM/GROUP…)
    "sh_type": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 14, 17, 0x6FFFFFF6, 0x6FFFFFFF],
    # 심볼 타입/바인딩(st_info) 유효 조합
    "st_info": [0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x20, 0x22],
    # 특수 섹션 인덱스(SHN_UNDEF/ABS/COMMON…)
    "st_shndx": [0, 0xFFF1, 0xFFF2, 0xFFFF, 0xFF00],
    # 노트 타입(GNU_PROPERTY/ABI/BUILD_ID 등)
    "n_type":  [1, 2, 3, 4, 5, 0x100, 0xFFFFFFFF],
}

# 확장 리전 필드 → danger 풀 매핑. numbers.py 가 이미 정의했으면 존중(setdefault),
# 없을 때만 채운다. (SUBST._pick_value 가 _FIELD_INTENT[field] 로 풀을 고른다.)
for _f, _intent in {
    "sh_name": "STR_IDX", "sh_type": "MASK", "sh_flags": "MASK",
    "sh_offset": "OFFSET", "sh_size": "SIZE", "sh_link": "STR_IDX",
    "sh_info": "STR_IDX", "sh_entsize": "SIZE",
    "st_name": "STR_IDX", "st_info": "MASK", "st_shndx": "STR_IDX",
    "st_value": "ADDR", "st_size": "SIZE",
    "n_namesz": "SIZE", "n_descsz": "SIZE", "n_type": "MASK",
    "r_offset": "ADDR", "r_info": "ADDR", "r_addend": "ADDR",
}.items():
    _FIELD_INTENT.setdefault(_f, _intent)


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
        # 확장 리전(전체 메타데이터 커버) — 기존 duck 계약에 '추가만' 한다.
        self.e_shoff = self.e_shentsize = self.e_shnum = 0
        self.sections: List[dict] = []   # SHT 엔트리 (sh_* + foff)
        self.syms: List[dict] = []       # .dynsym/.symtab 엔트리 (foff, kind)
        self.notes: List[dict] = []      # PT_NOTE/SHT_NOTE 노트 (foff)
        self.relas: List[dict] = []      # Elf64_Rela 엔트리 (foff, kind)

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

        # 확장 리전(있으면). 각 파서는 실패해도 조용히 빈 리스트를 남긴다.
        self._parse_sht()      # 섹션헤더 (링커 SUT: readelf/objdump/ld·gold)
        self._parse_syms()     # 심볼 테이블 (.dynsym 우선; SHT 있으면 .symtab 도)
        self._parse_notes()    # 노트 (PT_NOTE 세그먼트)
        self._parse_relas()    # 재배치 (DT_RELA/DT_JMPREL — 로더 충실)

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

    # ---- 확장 리전 파서(전체 메타데이터) — 각각 내부 흡수, 실패해도 빈 리스트 ----
    def _parse_sht(self):
        """섹션헤더 테이블. e_shoff@0x28/e_shentsize@0x3A/e_shnum@0x3C 로 순회."""
        try:
            buf = self.buf
            self.e_shoff = _rd(buf, E_SHOFF_OFF, 8) or 0
            self.e_shentsize = _rd(buf, E_SHENTSIZE_OFF, 2) or SHENTSIZE64
            self.e_shnum = _rd(buf, E_SHNUM_OFF, 2) or 0
            if self.e_shentsize < SHENTSIZE64:
                self.e_shentsize = SHENTSIZE64
            if self.e_shoff == 0 or self.e_shnum == 0:
                return
            for i in range(min(self.e_shnum, 4096)):
                foff = self.e_shoff + i * self.e_shentsize
                if foff + SHENTSIZE64 > self.size:
                    break
                self.sections.append(dict(
                    idx=i, foff=foff,
                    sh_name=_rd(buf, foff + SH_NAME, 4),
                    sh_type=_rd(buf, foff + SH_TYPE, 4),
                    sh_offset=_rd(buf, foff + SH_OFFSET, 8),
                    sh_size=_rd(buf, foff + SH_SIZE, 8),
                    sh_link=_rd(buf, foff + SH_LINK, 4),
                    sh_entsize=_rd(buf, foff + SH_ENTSIZE, 8),
                ))
        except Exception:
            pass

    def _parse_syms(self, cap=128):
        """심볼 테이블. SHT 의 SHT_SYMTAB/SHT_DYNSYM 섹션에서 Elf64_Sym 순회.
           (SHT 부재 stripped .so 는 심볼 리전이 비지만 다른 리전은 정상.)"""
        try:
            buf = self.buf
            for s in self.sections:
                if s["sh_type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                    continue
                off = s["sh_offset"]
                sz = s["sh_size"]
                ent = s["sh_entsize"] or SYMENT64
                if off is None or sz is None or ent <= 0:
                    continue
                n = min(sz // ent, cap)
                kind = "dynsym" if s["sh_type"] == SHT_DYNSYM else "symtab"
                for i in range(n):
                    fo = off + i * ent
                    if fo + SYMENT64 > self.size:
                        break
                    self.syms.append(dict(foff=fo, kind=kind, idx=i))
        except Exception:
            pass

    def _parse_notes(self, cap=64):
        """노트. PT_NOTE 세그먼트를 순회하며 Elf64_Nhdr 헤더 위치를 뽑는다.
           entry = n_namesz(4) n_descsz(4) n_type(4) + name(4정렬) + desc(4정렬)."""
        try:
            buf = self.buf
            def align4(x):
                return (x + 3) & ~3
            for ph in self.phdrs:
                if ph.get("p_type") != PT_NOTE:
                    continue
                start = ph["p_offset"]
                length = ph["p_filesz"]
                if start is None or length is None:
                    continue
                o = start
                end = min(self.size, start + length)
                guard = 0
                while o + 12 <= end and guard < cap:
                    guard += 1
                    namesz = _rd(buf, o + N_NAMESZ, 4)
                    descsz = _rd(buf, o + N_DESCSZ, 4)
                    if namesz is None or descsz is None:
                        break
                    self.notes.append(dict(foff=o))
                    step = 12 + align4(namesz) + align4(descsz)
                    if step <= 0:
                        break
                    o += step
        except Exception:
            pass

    def _parse_relas(self, cap=256):
        """재배치. DT_RELA/DT_RELASZ + DT_JMPREL/DT_PLTRELSZ 로 위치·개수 파악(로더 충실).
           SHT 가 있으면 SHT_RELA 섹션도 흡수(정적 파서 커버)."""
        try:
            buf = self.buf
            seen = set()
            def add_table(vaddr, total, kind):
                base = self.vaddr_to_off(vaddr) if vaddr is not None else None
                if base is None or total is None or total < RELAENT64:
                    return
                for i in range(min(total // RELAENT64, cap)):
                    fo = base + i * RELAENT64
                    if fo in seen or fo + RELAENT64 > self.size:
                        continue
                    seen.add(fo)
                    self.relas.append(dict(foff=fo, kind=kind, idx=i))
            add_table(self.dt.get(DT_RELA), self.dt.get(DT_RELASZ), "rela_dyn")
            add_table(self.dt.get(DT_JMPREL), self.dt.get(DT_PLTRELSZ), "rela_plt")
            # SHT_RELA (파일오프셋 직접) — 정적 파서용 보강
            for s in self.sections:
                if s["sh_type"] != SHT_RELA:
                    continue
                off, sz = s["sh_offset"], s["sh_size"]
                if off is None or sz is None:
                    continue
                for i in range(min(sz // RELAENT64, cap)):
                    fo = off + i * RELAENT64
                    if fo in seen or fo + RELAENT64 > self.size:
                        continue
                    seen.add(fo)
                    self.relas.append(dict(foff=fo, kind="rela_sht", idx=i))
        except Exception:
            pass

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


def _dt_foff(view, tag):
    """DYNAMIC 엔트리 중 d_tag==tag 의 파일오프셋(d_un 은 +8). 없으면 None.
    중복 태그면 last-wins — view.dt / _dyn_foffs(last-wins)와 일치시켜 구조op↔repair
    가 같은 엔트리를 보게 한다(리뷰: first/last 불일치 desync 방지)."""
    found = None
    for e in view.dyn_entries:
        if e["d_tag"] == tag:
            found = e["foff"]
    return found


def _symtab_sections(view):
    """유효 오프셋/크기를 가진 .symtab/.dynsym 섹션 목록(구조축 ADD/SUB 대상)."""
    return [s for s in view.sections
            if s["sh_type"] in (SHT_SYMTAB, SHT_DYNSYM)
            and s.get("sh_offset") and s.get("sh_size")]


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
        # SHT (섹션헤더 — 정적 파서 readelf/objdump + 링커 ld/gold)
        for s in view.sections:
            b = s["foff"]
            t.append(("SHT", "sh_name", b + SH_NAME, 4, "STR_IDX"))
            t.append(("SHT", "sh_type", b + SH_TYPE, 4, "MASK"))
            t.append(("SHT", "sh_flags", b + SH_FLAGS, 8, "MASK"))
            t.append(("SHT", "sh_offset", b + SH_OFFSET, 8, "OFFSET"))
            t.append(("SHT", "sh_size", b + SH_SIZE, 8, "SIZE"))
            t.append(("SHT", "sh_link", b + SH_LINK, 4, "STR_IDX"))
            t.append(("SHT", "sh_info", b + SH_INFO, 4, "STR_IDX"))
            t.append(("SHT", "sh_entsize", b + SH_ENTSIZE, 8, "SIZE"))
        # SYMTAB (.dynsym/.symtab — 심볼 해석 do_lookup_x / readelf -s)
        for sym in view.syms:
            b = sym["foff"]
            t.append(("SYMTAB", "st_name", b + ST_NAME, 4, "STR_IDX"))
            t.append(("SYMTAB", "st_info", b + ST_INFO, 1, "MASK"))
            t.append(("SYMTAB", "st_shndx", b + ST_SHNDX, 2, "STR_IDX"))
            t.append(("SYMTAB", "st_value", b + ST_VALUE, 8, "ADDR"))
            t.append(("SYMTAB", "st_size", b + ST_SIZE, 8, "SIZE"))
        # NOTE (PT_NOTE — _dl_process_pt_gnu_property / readelf -n)
        for nt in view.notes:
            b = nt["foff"]
            t.append(("NOTE", "n_namesz", b + N_NAMESZ, 4, "SIZE"))
            t.append(("NOTE", "n_descsz", b + N_DESCSZ, 4, "SIZE"))
            t.append(("NOTE", "n_type", b + N_TYPE, 4, "MASK"))
        # RELA (재배치 — elf_machine_rela / readelf -r)
        for rl in view.relas:
            b = rl["foff"]
            t.append(("RELA", "r_offset", b + R_OFFSET, 8, "ADDR"))
            t.append(("RELA", "r_info", b + R_INFO, 8, "ADDR"))
            t.append(("RELA", "r_addend", b + R_ADDEND, 8, "ADDR"))
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
        # 가용한 구조 리전 중 무작위 선택(PHT/VERNEED/SHT/RELA/SYMTAB)
        choices = []
        if view.e_phnum >= 1:
            choices.append("pht")
        if view.verneeds:
            choices.append("verneed")
        if view.e_shnum >= 1 and view.sections:
            choices.append("sht")
        if _dt_foff(view, DT_RELASZ) is not None and view.relas:
            choices.append("rela")
        if _symtab_sections(view):
            choices.append("sym")
        if len(view.dyn_entries) >= 2:
            choices.append("dyn")
        if not choices:
            return None
        pick = rng.choice(choices)
        if pick == "pht":
            return self._add_pht(view, buf, rng)
        if pick == "verneed":
            return self._add_verneed(view, buf, rng)
        if pick == "sht":
            return self._add_sht(view, buf, rng)
        if pick == "rela":
            return self._add_rela(view, buf, rng)
        if pick == "sym":
            return self._add_sym(view, buf, rng)
        return self._add_dyn(view, buf, rng)

    def _add_dyn(self, view, buf, rng):
        """DYNAMIC 엔트리 증설: non-NULL 엔트리를 복제해 DT_NULL 자리에 쓰고 그 뒤에 새
        DT_NULL 을 놓는다(DT_NULL 뒤 16B 여유가 있을 때). 배열 시프트 없이 +1 엔트리."""
        ents = view.dyn_entries
        # 마지막이 '진짜' DT_NULL 일 때만(파서가 256캡/경계브레이크로 끊겼으면 아님) — 리뷰
        if len(ents) < 2 or ents[-1]["d_tag"] != DT_NULL:
            return None
        null_foff = ents[-1]["foff"]
        if null_foff + 32 > len(buf):
            return None
        # DT_NULL 뒤 16B 가 0-패딩일 때만 새 DT_NULL 을 놓는다(인접 섹션 오손상 방지 — 리뷰)
        if bytes(buf[null_foff + 16:null_foff + 32]) != b"\x00" * 16:
            return None
        src = rng.choice(ents[:-1])
        buf[null_foff:null_foff + 16] = buf[src["foff"]:src["foff"] + 16]  # DT_NULL 자리에 복제
        struct.pack_into("<Q", buf, null_foff + 16, DT_NULL)              # 새 DT_NULL
        struct.pack_into("<Q", buf, null_foff + 24, 0)
        return MutationRecord(axis=self.axis, region="DYNAMIC", field="entry",
                              old=None, new=hex(src["d_tag"]), note="dup dyn entry(+DT_NULL)")

    def _add_rela(self, view, buf, rng):
        """재배치 엔트리 증설: DT_RELASZ 를 RELAENT 만큼 +1엔트리(상위 크기 연동).
           여유(0-패딩)가 있으면 마지막 엔트리를 물리 복제(VERNEED ADD 와 동일 패턴)."""
        szf = _dt_foff(view, DT_RELASZ)
        if szf is None:
            return None
        cur = _rd(buf, szf + 8, 8)
        if cur is None:
            return None
        # 물리 복제 best-effort: rela_dyn 마지막 엔트리 뒤가 0-패딩이면 복제
        note = "relasz += ent"
        dyn = [r for r in view.relas if r["kind"] == "rela_dyn"]
        if dyn:
            last = max(dyn, key=lambda r: r["foff"])["foff"]
            tail = last + RELAENT64
            if tail + RELAENT64 <= view.size and buf[tail:tail + RELAENT64] == b"\x00" * RELAENT64:
                buf[tail:tail + RELAENT64] = buf[last:last + RELAENT64]
                note = "dup last rela(+relasz)"
        _wr(buf, szf + 8, 8, (cur + RELAENT64) & U64_MAX)
        return MutationRecord(axis=self.axis, region="RELA", field="DT_RELASZ",
                              old=cur, new=cur + RELAENT64, note=note)

    def _add_sym(self, view, buf, rng):
        """심볼 엔트리 증설: 소유 섹션(.dynsym/.symtab) sh_size 를 SYMENT 만큼 +1엔트리.
           여유(0-패딩)면 마지막 심볼 물리 복제. (링커 SUT 는 sh_size 로 심볼수 계산.)"""
        secs = _symtab_sections(view)
        if not secs:
            return None
        s = rng.choice(secs)
        cur = s["sh_size"]
        if cur is None:
            return None
        note = "sh_size += syment"
        off = s["sh_offset"]
        if off is not None and cur >= SYMENT64:
            last = off + cur - SYMENT64
            tail = off + cur
            if tail + SYMENT64 <= view.size and buf[tail:tail + SYMENT64] == b"\x00" * SYMENT64:
                buf[tail:tail + SYMENT64] = buf[last:last + SYMENT64]
                note = "dup last sym(+sh_size)"
        _wr(buf, s["foff"] + SH_SIZE, 8, (cur + SYMENT64) & U64_MAX)
        return MutationRecord(axis=self.axis, region="SYMTAB", field="sh_size",
                              old=cur, new=cur + SYMENT64, note=f"{s.get('kind', 'sym')}: {note}")

    def _add_sht(self, view, buf, rng):
        """섹션헤더 하나를 복제하고 e_shnum +1. PHT 와 동일 전략:
           SHT 를 '파일 끝'으로 재배치(entries+dup)하고 e_shoff/e_shnum 만 갱신 →
           기존 콘텐츠 오프셋 불변(구조보존)."""
        n = view.e_shnum
        base = view.e_shoff
        ent = view.e_shentsize or SHENTSIZE64
        if n < 1 or base + n * ent > len(buf):
            return None
        sht = bytes(buf[base:base + n * ent])
        dup_idx = rng.randrange(n)
        dup = sht[dup_idx * ent:(dup_idx + 1) * ent]
        pad = (-len(buf)) % 8
        buf.extend(b"\x00" * pad)
        new_off = len(buf)
        buf.extend(sht)
        buf.extend(dup)
        _wr(buf, E_SHOFF_OFF, 8, new_off)
        _wr(buf, E_SHNUM_OFF, 2, (n + 1) & U16_MAX)
        return MutationRecord(axis=self.axis, region="SHT", field="e_shnum",
                              old=n, new=n + 1,
                              note=f"dup sec[{dup_idx}], sht->EOF@{hex(new_off)}")

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
        choices = []
        if view.e_phnum >= 2:
            choices.append("pht")
        if view.verneeds:
            choices.append("verneed")
        if view.e_shnum >= 2 and len(view.sections) >= 2:
            choices.append("sht")
        szf = _dt_foff(view, DT_RELASZ)
        if szf is not None:
            rc = _rd(buf, szf + 8, 8)
            if rc is not None and rc >= 2 * RELAENT64:
                choices.append("rela")
        if [s for s in _symtab_sections(view) if s["sh_size"] >= 2 * SYMENT64]:
            choices.append("sym")
        if len(view.dyn_entries) >= 3:          # non-NULL >= 2 (하나 지워도 남음)
            choices.append("dyn")
        if not choices:
            return None
        pick = rng.choice(choices)
        if pick == "pht":
            return self._sub_pht(view, buf, rng)
        if pick == "verneed":
            return self._sub_verneed(view, buf, rng)
        if pick == "sht":
            return self._sub_sht(view, buf, rng)
        if pick == "rela":
            return self._sub_rela(view, buf, rng)
        if pick == "sym":
            return self._sub_sym(view, buf, rng)
        return self._sub_dyn(view, buf, rng)

    def _sub_dyn(self, view, buf, rng):
        """DYNAMIC 엔트리 삭제: k 엔트리 제거 후 뒤(DT_NULL 포함)를 16B 위로 시프트,
        끝 16B 를 DT_NULL 로. (배열 축소 = 로더가 그 태그 없이 동작 → 누락 모사)."""
        ents = view.dyn_entries
        # 마지막이 '진짜' DT_NULL 일 때만(파서 256캡/경계브레이크면 아님) — 리뷰
        if not ents or ents[-1]["d_tag"] != DT_NULL:
            return None
        non_null = ents[:-1]
        if len(non_null) < 2:
            return None
        k = rng.randrange(len(non_null))
        kfoff = non_null[k]["foff"]
        end = ents[-1]["foff"] + 16              # DT_NULL 끝 오프셋
        if end > len(buf):
            return None
        buf[kfoff:end - 16] = buf[kfoff + 16:end]
        struct.pack_into("<Q", buf, end - 16, DT_NULL)
        struct.pack_into("<Q", buf, end - 16 + 8, 0)
        return MutationRecord(axis=self.axis, region="DYNAMIC", field="entry",
                              old=hex(non_null[k]["d_tag"]), new=None, note="del dyn entry")

    def _sub_rela(self, view, buf, rng):
        """재배치 하향동기화: DT_RELASZ 를 RELAENT 만큼 -1엔트리(마지막 엔트리 소실 모사)."""
        szf = _dt_foff(view, DT_RELASZ)
        if szf is None:
            return None
        cur = _rd(buf, szf + 8, 8)
        if cur is None or cur < 2 * RELAENT64:
            return None
        new = cur - RELAENT64
        _wr(buf, szf + 8, 8, new & U64_MAX)
        return MutationRecord(axis=self.axis, region="RELA", field="DT_RELASZ",
                              old=cur, new=new, note="relasz -= ent")

    def _sub_sym(self, view, buf, rng):
        """심볼 하향동기화: 소유 섹션 sh_size 를 SYMENT 만큼 -1엔트리."""
        secs = [s for s in _symtab_sections(view) if s["sh_size"] >= 2 * SYMENT64]
        if not secs:
            return None
        s = rng.choice(secs)
        cur = s["sh_size"]
        new = cur - SYMENT64
        _wr(buf, s["foff"] + SH_SIZE, 8, new & U64_MAX)
        return MutationRecord(axis=self.axis, region="SYMTAB", field="sh_size",
                              old=cur, new=new, note=f"{s.get('kind', 'sym')}: sh_size -= syment")

    def _sub_sht(self, view, buf, rng):
        """섹션헤더 하나를 삭제하고 e_shnum -1. PHT 와 동일: 뒤 슬롯 상향시프트.
           idx 0(SHT_NULL)은 되도록 피하고, e_shstrndx 가 범위를 벗어나면 클램프."""
        n = view.e_shnum
        base = view.e_shoff
        ent = view.e_shentsize or SHENTSIZE64
        if n < 2 or base + n * ent > len(buf):
            return None
        cands = [c["idx"] for c in view.sections if c["idx"] != 0]
        if not cands:
            cands = [c["idx"] for c in view.sections]
        k = rng.choice(cands)
        for i in range(k, n - 1):
            src = base + (i + 1) * ent
            dst = base + i * ent
            buf[dst:dst + ent] = buf[src:src + ent]
        _wr(buf, E_SHNUM_OFF, 2, (n - 1) & U16_MAX)
        shstr = _rd(buf, E_SHSTRNDX_OFF, 2)
        if shstr is not None and shstr >= n - 1:
            _wr(buf, E_SHSTRNDX_OFF, 2, (n - 2) & U16_MAX)
        return MutationRecord(axis=self.axis, region="SHT", field="e_shnum",
                              old=n, new=n - 1, note=f"del sec[{k}]")

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
        if not view.ok:
            return None
        modes = []
        if view.e_phnum >= 2 and view.e_phoff + view.e_phnum * PHENTSIZE64 <= len(buf):
            modes.append("slide")
            modes.append("pht")
        tables = self._scramble_tables(view)
        if tables:
            modes.append("table")
        if not modes:
            return None
        m = rng.choice(modes)
        if m == "slide":
            return self._slide(view, buf, rng)
        if m == "table":
            return self._permute_table(view, buf, rng, tables)
        return self._permute_pht(view, buf, rng)

    def _permute_pht(self, view, buf, rng):
        """PHT 순열: 핀(NOTE/GNU_*)은 끝 고정, 나머지 슬롯만 섞는다."""
        n = view.e_phnum
        base = view.e_phoff
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
            return None
        newblocks = list(blocks)
        for slot, srcidx in zip(movable, perm):
            newblocks[slot] = blocks[srcidx]
        for i in range(n):
            buf[base + i * PHENTSIZE64: base + (i + 1) * PHENTSIZE64] = newblocks[i]
        return MutationRecord(axis=self.axis, region="PHT", field="order",
                              old=tuple(movable), new=tuple(perm),
                              note=f"{len(movable)} movable segs permuted")

    def _scramble_tables(self, view):
        """순열 가능한 고정-stride 테이블 목록: (region, base, stride, count, skip0).
           SHT/RELA(dyn)/SYMTAB 엔트리를 '순서만' 뒤섞는다(바이트 보존)."""
        out = []
        # SHT: idx0(NULL) 고정 → 순열 대상 >= 2 이려면 e_shnum >= 3
        if view.e_shnum >= 3 and view.sections:
            ent = view.e_shentsize or SHENTSIZE64
            if view.e_shoff + view.e_shnum * ent <= view.size:
                out.append(("SHT", view.e_shoff, ent, view.e_shnum, True))
        # RELA(dyn): 연속 배열
        dyn = sorted([r["foff"] for r in view.relas if r["kind"] == "rela_dyn"])
        if len(dyn) >= 2 and dyn[-1] - dyn[0] == (len(dyn) - 1) * RELAENT64:
            out.append(("RELA", dyn[0], RELAENT64, len(dyn), False))
        # SYMTAB: 소유 섹션의 엔트리(idx0 null 고정 → count>=3)
        for s in _symtab_sections(view):
            ent = s["sh_entsize"] or SYMENT64
            cnt = s["sh_size"] // ent if ent else 0
            if cnt >= 3 and s["sh_offset"] + cnt * ent <= view.size:
                out.append(("SYMTAB", s["sh_offset"], ent, cnt, True))
                break
        # DYNAMIC: non-NULL 엔트리 순열(16B stride, DT_NULL 은 끝 고정)
        de = view.dyn_entries
        cnt = len(de) - 1                        # non-NULL 개수
        if cnt >= 2 and all(de[i]["foff"] == de[0]["foff"] + i * 16 for i in range(cnt)):
            out.append(("DYNAMIC", de[0]["foff"], 16, cnt, False))
        return out

    def _permute_table(self, view, buf, rng, tables):
        region, base, stride, count, skip0 = rng.choice(tables)
        idxs = list(range(1 if skip0 else 0, count))
        if len(idxs) < 2:
            return None
        blocks = [bytes(buf[base + i * stride: base + (i + 1) * stride]) for i in range(count)]
        perm = idxs[:]
        for _ in range(8):
            rng.shuffle(perm)
            if perm != idxs:
                break
        else:
            return None
        newblocks = list(blocks)
        for slot, srcidx in zip(idxs, perm):
            newblocks[slot] = blocks[srcidx]
        for i in range(count):
            buf[base + i * stride: base + (i + 1) * stride] = newblocks[i]
        return MutationRecord(axis=self.axis, region=region, field="order",
                              old=tuple(idxs), new=tuple(perm),
                              note=f"{len(idxs)} {region} entries permuted")

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

    # 섹션헤더 테이블(SHT) 3개: [0]=NULL, [1]=PROGBITS(유효), [2]=PROGBITS.
    # 버퍼 끝(0x200=512) 안에 배치: sht_off=320, 3*64=192 → 320..512 정확히 채움.
    sht_off = 320
    struct.pack_into("<Q", buf, E_SHOFF_OFF, sht_off)
    struct.pack_into("<H", buf, E_SHENTSIZE_OFF, SHENTSIZE64)
    struct.pack_into("<H", buf, E_SHNUM_OFF, 3)
    struct.pack_into("<H", buf, E_SHSTRNDX_OFF, 0)
    # sec[1] PROGBITS: 파일 내 유효 오프셋/크기
    s1 = sht_off + 1 * SHENTSIZE64
    struct.pack_into("<I", buf, s1 + SH_TYPE, 1)        # SHT_PROGBITS
    struct.pack_into("<Q", buf, s1 + SH_OFFSET, 64)
    struct.pack_into("<Q", buf, s1 + SH_SIZE, 64)
    # sec[2] PROGBITS
    s2 = sht_off + 2 * SHENTSIZE64
    struct.pack_into("<I", buf, s2 + SH_TYPE, 1)
    struct.pack_into("<Q", buf, s2 + SH_OFFSET, 128)
    struct.pack_into("<Q", buf, s2 + SH_SIZE, 64)
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
          f"dyn={len(v0.dyn_entries)}, verneed={len(v0.verneeds)}, "
          f"sht={len(v0.sections)}, sym={len(v0.syms)}, "
          f"note={len(v0.notes)}, rela={len(v0.relas)}")
    # 확장 리전 파싱 확인: 합성 ELF 는 SHT 3섹션을 갖는다.
    assert len(v0.sections) >= 2, f"SHT 파싱 실패: sections={len(v0.sections)}"

    # SUBST 가 확장 리전(SHT 등)을 실제로 타깃하는지 — write-site 목록에 SHT 존재
    _subst = SubstOp(avoid_gate=True)
    _regions = {r for (r, _f, _o, _w, _i) in _subst._targets(v0)}
    print(f"[SUBST 타깃 리전] {sorted(_regions)}")
    assert "SHT" in _regions, f"SUBST 가 SHT 를 타깃 못 함: {_regions}"

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
