#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
canonicalize.py — 뮤테이션 후 ELF64 포맷유효성 정규화기 (Phase 2 ③)
==============================================================================

역할 — SEMANTIC 정규화(canonicalize repair)
-------------------------------------------
구조 뮤테이션(operators.py 의 ADD/SUB/SCRAMBLE) 이 끝난 뒤, 파일은 대개
"헤더는 남았지만 헤더가 '지정하는 카운트/크기/포인터' 가 실제 바이트와
어긋난" 상태가 된다. 링커(ld/gold) 나 로더(ld.so) 는 입구 게이트를 통과한
뒤 그 카운트/크기/포인터를 **무검증으로** 따라가다 죽거나, 반대로 너무
어긋나면 파서가 조기 return 해 깊은 경로에 못 간다.

이 모듈은 그 SEMANTIC 층만 '문법적으로 정합' 하게 되돌린다 — 즉
    "헤더가 말하는 것 == 파일에 실제로 있는 것"
을 다시 맞춰, 링커가 엔트리 게이트를 지나 안쪽 순회 코드까지 도달하게 한다.
값을 '흥미롭게' 만드는 것은 이 모듈의 일이 아니다(그건 SUBST 가 마지막에 한다).

계약(중요)
----------
  - GATE 임계필드(magic/EI_CLASS/e_machine/e_phentsize/PHT 경계) 는 **건드리지
    않는다**. 그건 structure_aware._repair_gate_fields 의 소관이다.
  - **멱등(idempotent)**: 이미 정합인 필드는 재기록하지 않는다. canonicalize 를
    두 번 돌려도 결과가 같다. 각 복구는 '범위 밖일 때만' 범위 안 값으로 쓴다.
  - **절대 예외를 밖으로 던지지 않는다**: 모든 복구는 best-effort. 실패는
    예외가 아니라 반환 노트에 문자열로 기록한다.
  - stdlib + operators.ElfView(순수 파서) 만 필수. pyelftools 는 방어적 optional
    이며 부재해도 무해하다. 최상위 임포트는 무조건 성공한다.
  - ELF64 LSB (x86-64) 전제. 모든 read/write 는 little-endian, 경계검사 포함.

level 의미(정규화 깊이)
-----------------------
    "gate"     추가 정규화 없음(GATE 는 호출측 소관) → no-op.
    "pht"      PHT 교차필드 불변식만(repair_pht 상당).
    "semantic" pht + DYNAMIC(STRSZ/REL*/VER*NUM/포인터) + 버전(versym) 정규화.
    "full"     semantic + 섹션헤더(SHT) 불변식.
  레벨은 누적(gate ⊂ pht ⊂ semantic ⊂ full). 기본값 "semantic".

구현하는 불변식(각 항목은 개별 guard + 개별 note)
-------------------------------------------------
  DYNAMIC:
    · DT_STRTAB/DT_SYMTAB/DT_HASH/DT_VERNEED 의 d_ptr 가 어떤 PT_LOAD 범위 안에
      들어가도록(범위 밖이면 첫 PT_LOAD 시작 vaddr 로 클램프).
    · DT_STRSZ == DT_STRTAB 부터 그 포함 PT_LOAD 영역 끝까지의 span.
    · DT_RELAENT==24, DT_RELENT==16, DT_SYMENT==24;
      DT_RELASZ 는 24의 배수, DT_RELSZ 는 16의 배수(초과분 버림).
    · DT_VERNEEDNUM == vn_next 로 실제 순회한 Verneed 개수.
    · DT_VERDEFNUM == vd_next 로 실제 순회한 Verdef 개수.
  버전:
    · .gnu.version(versym) 각 엔트리 인덱스 ≤ (verdef+verneed 정의 수). 초과분은
      전역(1)으로 클램프(플래그 비트 보존).
  SHDR(=level "full"; GNU ld/gold 는 SHT 를 읽으므로 링커 SUT 에 유효):
    · e_shnum==0/e_shoff==0 → SHT 부재로 보고 SHT 복구는 깔끔히 건너뜀.
    · e_shentsize==64; e_shoff + e_shnum*64 ≤ 파일크기(넘으면 e_shnum 클램프);
      e_shstrndx < e_shnum.
    · 각 sh_offset + sh_size ≤ 파일크기(SHT_NOBITS 제외); sh_link < e_shnum;
      SHT_REL/RELA 의 sh_info < e_shnum, SHT_SYMTAB/DYNSYM 의 sh_info ≤ 심볼수.
"""
from __future__ import annotations

import struct
from typing import List, Optional

# --------------------------------------------------------------------------
# 방어적 임포트: operators.ElfView(순수 파서). 없으면 canonicalize 는 조용히
# skip 노트를 돌려준다(hard-fail 금지).
# --------------------------------------------------------------------------
try:
    from lfuzzer.mutators.operators import ElfView  # noqa
except BaseException:  # 패키지 경로가 안 잡히는 실행맥락 대비 sibling 폴백
    try:
        from operators import ElfView  # type: ignore  # noqa
    except BaseException:
        ElfView = None  # type: ignore

# 방어적 optional pyelftools — 현재 로직은 순수파서로 충분하므로 참조만 하고
# 부재해도 무해하다(향후 교차검증용). 최상위에서 절대 hard-fail 시키지 않는다.
try:
    from elftools.elf.elffile import ELFFile  # noqa
    _HAVE_PYELFTOOLS = True
except BaseException:
    ELFFile = None  # type: ignore
    _HAVE_PYELFTOOLS = False


# ==========================================================================
# ELF64 상수 (elf64.py / mutate_elf_v4.py 와 동일 값)
# ==========================================================================
# DYNAMIC 태그
DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_VERSYM = 0x6FFFFFF0
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

# 정규 엔트리 크기(스펙 고정)
RELAENT = 24    # Elf64_Rela
RELENT = 16     # Elf64_Rel
SYMENT = 24     # Elf64_Sym

# PT_/SHT_ 상수
PT_LOAD = 1
PT_DYNAMIC = 2
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11

# EHDR 내 SHT 관련 필드 오프셋(elf64.py 참조)
E_SHOFF_OFF = 0x28
E_SHENTSIZE_OFF = 0x3A
E_SHNUM_OFF = 0x3C
E_SHSTRNDX_OFF = 0x3E
SHENTSIZE64 = 64        # Elf64_Shdr 크기
EHDR_SIZE = 64

# Elf64_Shdr 내부 오프셋
SH_TYPE, SH_OFFSET, SH_SIZE, SH_LINK, SH_INFO, SH_ENTSIZE = 0x04, 0x18, 0x20, 0x28, 0x2C, 0x38

# versym 플래그/마스크
VERSYM_HIDDEN = 0x8000
VERSYM_MASK = 0x7FFF

_DT_NAMES = {
    DT_HASH: "DT_HASH", DT_STRTAB: "DT_STRTAB", DT_SYMTAB: "DT_SYMTAB",
    DT_RELA: "DT_RELA", DT_RELASZ: "DT_RELASZ", DT_RELAENT: "DT_RELAENT",
    DT_STRSZ: "DT_STRSZ", DT_SYMENT: "DT_SYMENT", DT_REL: "DT_REL",
    DT_RELSZ: "DT_RELSZ", DT_RELENT: "DT_RELENT", DT_VERSYM: "DT_VERSYM",
    DT_VERDEF: "DT_VERDEF", DT_VERDEFNUM: "DT_VERDEFNUM",
    DT_VERNEED: "DT_VERNEED", DT_VERNEEDNUM: "DT_VERNEEDNUM",
}

_PACK = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}


# --------------------------------------------------------------------------
# 경계검사 포함 little-endian read/write (operators._rd/_wr 와 동치)
# --------------------------------------------------------------------------
def _rd(buf, off, w) -> Optional[int]:
    if off < 0 or off + w > len(buf):
        return None
    return struct.unpack_from(_PACK[w], buf, off)[0]


def _wr(buf, off, w, v) -> bool:
    if off < 0 or off + w > len(buf):
        return False
    struct.pack_into(_PACK[w], buf, off, v & ((1 << (w * 8)) - 1))
    return True


def _is_pow2_or_01(x) -> bool:
    return x in (0, 1) or (x & (x - 1)) == 0


def _dt_name(tag) -> str:
    return _DT_NAMES.get(tag, hex(tag))


def _dyn_foffs(view) -> dict:
    """d_tag -> 그 엔트리의 파일오프셋(마지막 채택, view.dt 와 동일 규약).
       d_un 은 foff+8 에 있다."""
    m = {}
    for e in view.dyn_entries:
        m[e["d_tag"]] = e["foff"]
    return m


# ==========================================================================
# 공개 API
# ==========================================================================
_LEVELS = {"gate": 0, "pht": 1, "semantic": 2, "full": 3}


def canonicalize(buf: bytearray, *, level: str = "semantic") -> List[str]:
    """뮤테이션된 ELF64 를 제자리(in-place)로 포맷정합화하고 복구노트를 돌려준다.

    절대 예외를 던지지 않는다(best-effort). 반환값은 사람이 읽는 복구노트 리스트
    (빈 리스트면 '고칠 게 없었음' 또는 'skip'). level 의미는 모듈 docstring 참조.
    """
    notes: List[str] = []
    lvl = _LEVELS.get(level, _LEVELS["semantic"])

    # gate: 추가 정규화 없음(GATE 는 호출측 소관)
    if lvl <= _LEVELS["gate"]:
        return notes

    if not isinstance(buf, bytearray):
        # 제자리 수정 불가 — 조용히 보고만 한다.
        notes.append("skip: buf 가 bytearray 아님(제자리 수정 불가)")
        return notes
    if ElfView is None:
        notes.append("skip: operators.ElfView 부재")
        return notes

    try:
        view = ElfView.parse(buf)
    except BaseException as e:  # 파서가 던져도 흡수
        notes.append(f"skip: 파싱 예외({type(e).__name__})")
        return notes
    if not view.ok:
        notes.append("skip: ELF64 아님(파싱 실패)")
        return notes

    # 1) PHT 교차필드(level >= pht)
    _run(notes, "pht", _repair_pht, buf, view)

    # 2) SEMANTIC(level >= semantic): DYNAMIC + 버전
    if lvl >= _LEVELS["semantic"]:
        # 포인터를 먼저 PT_LOAD 안으로 넣고(→ strtab 이동 가능), 그 다음 재파싱해
        # 이후 복구(STRSZ/VER*NUM/versym)가 '이동 후' 실제 위치를 보게 한다.
        _run(notes, "dyn.ptr", _repair_dyn_ptrs_in_load, buf, view)
        try:
            view = ElfView.parse(buf)   # 포인터/PHT 변경 반영 재파싱
        except BaseException:
            pass
        if view.ok:
            _run(notes, "dyn.strsz", _repair_strsz, buf, view)
            _run(notes, "dyn.relent", _repair_rel_entsizes, buf, view)
            _run(notes, "dyn.verneednum", _repair_verneednum, buf, view)
            _run(notes, "dyn.verdefnum", _repair_verdefnum, buf, view)
            _run(notes, "versym", _repair_versym, buf, view)

    # 3) FULL(level >= full): 섹션헤더
    if lvl >= _LEVELS["full"]:
        _run(notes, "sht", _repair_sht, buf, view)

    return notes


def _run(notes: List[str], tag: str, fn, *args) -> None:
    """개별 복구를 격리 실행: 반환노트를 모으고, 예외는 흡수해 노트로 남긴다."""
    try:
        msg = fn(*args)
    except BaseException as e:  # 어떤 복구 실패도 파이프라인을 끊지 않음
        notes.append(f"{tag}: 예외 {type(e).__name__}: {e}")
        return
    if not msg:
        return
    if isinstance(msg, list):
        notes.extend(msg)
    else:
        notes.append(msg)


# ==========================================================================
# PHT 교차필드 (mutate_elf_v4.repair_pht 순수-파이썬 등가)
#   p_align ∈ {0,1,2^n} · p_filesz ≤ p_memsz · p_offset+p_filesz ≤ 파일 ·
#   p_vaddr ≡ p_offset (mod p_align)
# ==========================================================================
def _repair_pht(buf, view) -> Optional[str]:
    size = len(buf)
    changed = 0
    for c in view.phdrs:
        base = c["foff"]
        p_off = _rd(buf, base + 8, 8)
        p_va = _rd(buf, base + 16, 8)
        p_fsz = _rd(buf, base + 32, 8)
        p_msz = _rd(buf, base + 40, 8)
        p_al = _rd(buf, base + 48, 8)
        if None in (p_off, p_va, p_fsz, p_msz, p_al):
            continue
        # 1) align 정상화
        if not _is_pow2_or_01(p_al) or p_al > (1 << 30):
            p_al = 0x1000
            _wr(buf, base + 48, 8, p_al)
            changed += 1
        # 2) filesz ≤ memsz
        if p_fsz > p_msz:
            p_msz = p_fsz
            _wr(buf, base + 40, 8, p_msz)
            changed += 1
        # 3) offset+filesz ≤ 파일크기
        if p_off > size:
            p_off = size
            _wr(buf, base + 8, 8, p_off)
            changed += 1
        if p_off + p_fsz > size:
            p_fsz = max(0, size - p_off)
            _wr(buf, base + 32, 8, p_fsz)
            if p_fsz > p_msz:
                _wr(buf, base + 40, 8, p_fsz)
            changed += 1
        # 4) vaddr ≡ offset (mod align)
        if p_al > 1:
            want = p_off % p_al
            if (p_va % p_al) != want:
                p_va = (p_va - (p_va % p_al)) + want
                _wr(buf, base + 16, 8, p_va)
                changed += 1
    return f"pht: {changed}개 필드 정규화" if changed else None


# ==========================================================================
# DYNAMIC 포인터가 PT_LOAD 범위 안에 오도록
# ==========================================================================
_PTRS_IN_LOAD = (DT_HASH, DT_STRTAB, DT_SYMTAB, DT_VERNEED)


def _repair_dyn_ptrs_in_load(buf, view) -> Optional[List[str]]:
    if not view.loads:
        return None
    foffs = _dyn_foffs(view)
    # 안전한 목표 vaddr = 첫 PT_LOAD 시작(반드시 그 load 안에 들어감)
    target = None
    for L in view.loads:
        if L["p_vaddr"] is not None and L["p_filesz"]:
            target = L["p_vaddr"]
            break
    if target is None:
        return None
    notes: List[str] = []
    for tag in _PTRS_IN_LOAD:
        if tag not in foffs:
            continue
        val = view.dt.get(tag)
        if val is None:
            continue
        if view.vaddr_to_off(val) is None:   # 어떤 PT_LOAD 에도 안 들어감
            if _wr(buf, foffs[tag] + 8, 8, target):
                notes.append(f"dyn.ptr {_dt_name(tag)}: {hex(val)} "
                             f"(PT_LOAD 밖) -> {hex(target)}")
    return notes or None


# ==========================================================================
# DT_STRSZ == strtab 부터 포함 PT_LOAD 영역 끝까지 span
# ==========================================================================
def _repair_strsz(buf, view) -> Optional[str]:
    foffs = _dyn_foffs(view)
    if DT_STRSZ not in foffs or DT_STRTAB not in view.dt:
        return None
    strtab_va = view.dt.get(DT_STRTAB)
    if strtab_va is None:
        return None
    region_end_va = None
    for L in view.loads:
        pv, pf = L["p_vaddr"], L["p_filesz"]
        if pv is None or pf is None:
            continue
        if pv <= strtab_va < pv + pf:
            region_end_va = pv + pf
            break
    if region_end_va is None:
        return None
    span = region_end_va - strtab_va
    cur = view.dt.get(DT_STRSZ)
    if cur != span:
        if _wr(buf, foffs[DT_STRSZ] + 8, 8, span):
            return f"dyn.DT_STRSZ: {hex(cur)} -> {hex(span)} (strtab..load끝)"
    return None


# ==========================================================================
# REL/RELA 엔트리 크기 + 크기 배수 정합
# ==========================================================================
def _repair_rel_entsizes(buf, view) -> Optional[List[str]]:
    foffs = _dyn_foffs(view)
    notes: List[str] = []
    # 1) ENT 는 스펙 고정값으로
    for tag, canon in ((DT_RELAENT, RELAENT), (DT_RELENT, RELENT),
                       (DT_SYMENT, SYMENT)):
        if tag in foffs:
            cur = view.dt.get(tag)
            if cur != canon and _wr(buf, foffs[tag] + 8, 8, canon):
                notes.append(f"dyn.{_dt_name(tag)}: {hex(cur)} -> {canon}")
    # 2) SZ 는 대응 ENT 의 배수(초과분 버림 → 항상 안전·멱등)
    for szt, ent in ((DT_RELASZ, RELAENT), (DT_RELSZ, RELENT)):
        if szt in foffs:
            cur = view.dt.get(szt)
            if cur is not None and ent and (cur % ent) != 0:
                new = cur - (cur % ent)
                if _wr(buf, foffs[szt] + 8, 8, new):
                    notes.append(f"dyn.{_dt_name(szt)}: {hex(cur)} -> "
                                 f"{hex(new)} ({ent}의 배수)")
    return notes or None


# ==========================================================================
# DT_VERNEEDNUM / DT_VERDEFNUM == 실제 순회 개수
# ==========================================================================
def _repair_verneednum(buf, view) -> Optional[str]:
    foffs = _dyn_foffs(view)
    if DT_VERNEEDNUM not in foffs:
        return None
    actual = len(view.verneeds)   # ElfView 가 vn_next 로 이미 순회함
    cur = view.dt.get(DT_VERNEEDNUM)
    if cur != actual:
        if _wr(buf, foffs[DT_VERNEEDNUM] + 8, 8, actual):
            return f"dyn.DT_VERNEEDNUM: {hex(cur)} -> {actual}"
    return None


def _repair_verdefnum(buf, view) -> Optional[str]:
    foffs = _dyn_foffs(view)
    if DT_VERDEFNUM not in foffs:
        return None
    count = _count_verdefs(buf, view)
    if count is None:
        return None
    cur = view.dt.get(DT_VERDEFNUM)
    if cur != count:
        if _wr(buf, foffs[DT_VERDEFNUM] + 8, 8, count):
            return f"dyn.DT_VERDEFNUM: {hex(cur)} -> {count}"
    return None


def _count_verdefs(buf, view) -> Optional[int]:
    """DT_VERDEF 체인을 vd_next 로 순회해 개수를 센다.
       Elf64_Verdef(20B): vd_version(0,H) vd_flags(2,H) vd_ndx(4,H) vd_cnt(6,H)
                          vd_hash(8,I) vd_aux(12,I) vd_next(16,I)."""
    vd_ptr = view.dt.get(DT_VERDEF)
    if vd_ptr is None:
        return None
    off = view.vaddr_to_off(vd_ptr)
    if off is None:
        return 0   # 포인터가 안 잡히면 정의 0개로 본다
    size = len(buf)
    count = 0
    guard = 0
    while 0 <= off and off + 20 <= size and guard < 256:
        guard += 1
        count += 1
        vd_next = _rd(buf, off + 16, 4)
        if not vd_next:
            break
        off += vd_next
    return count


# ==========================================================================
# .gnu.version(versym) 인덱스 클램프
# ==========================================================================
def _repair_versym(buf, view) -> Optional[str]:
    if DT_VERSYM not in view.dt:
        return None
    voff = view.vaddr_to_off(view.dt.get(DT_VERSYM))
    if voff is None:
        return None
    symcount = _symbol_count(buf, view)
    if not symcount or symcount <= 0:
        return None
    nverdef = _count_verdefs(buf, view) or 0
    naux = sum(len(vn.get("auxes", [])) for vn in view.verneeds)
    # 사용가능한 최대 버전 인덱스(0=local,1=global 예약 이후로 정의가 쌓임).
    # 넉넉히 잡아 과다클램프를 피한다.
    maxidx = 1 + nverdef + naux
    clamped = 0
    for i in range(symcount):
        o = voff + 2 * i
        val = _rd(buf, o, 2)
        if val is None:
            break
        idx = val & VERSYM_MASK
        flag = val & VERSYM_HIDDEN
        if idx > maxidx and idx not in (0, 1):
            _wr(buf, o, 2, flag | 1)   # 전역(1)으로, 플래그 비트는 보존
            clamped += 1
    if clamped:
        return f"versym: OOB 인덱스 {clamped}개 클램프(max={maxidx})"
    return None


def _symbol_count(buf, view) -> Optional[int]:
    """동적 심볼 수(=versym 엔트리 수) 추정.
       1순위 DT_HASH nchain(정확), 2순위 .dynsym 섹션 sh_size/entsize."""
    # 1) DT_HASH: [nbucket(u32), nchain(u32), ...]; nchain == 심볼 수
    h = view.dt.get(DT_HASH)
    if h is not None:
        ho = view.vaddr_to_off(h)
        if ho is not None:
            nchain = _rd(buf, ho + 4, 4)
            if nchain is not None and 0 < nchain < 0x100000:
                return nchain
    # 2) SHT 의 .dynsym
    sh = _find_section_by_type(buf, SHT_DYNSYM)
    if sh is not None:
        ent = sh["sh_entsize"] or SYMENT
        if ent:
            return sh["sh_size"] // ent
    return None


# ==========================================================================
# 섹션헤더(SHT) 불변식 (level "full")
# ==========================================================================
def _iter_shdrs(buf):
    """(e_shoff, e_shentsize, e_shnum, e_shstrndx) 를 돌려주거나, SHT 부재면 None."""
    if len(buf) < EHDR_SIZE:
        return None
    e_shoff = _rd(buf, E_SHOFF_OFF, 8)
    e_shnum = _rd(buf, E_SHNUM_OFF, 2)
    if not e_shoff or not e_shnum:
        return None
    e_shentsize = _rd(buf, E_SHENTSIZE_OFF, 2)
    e_shstrndx = _rd(buf, E_SHSTRNDX_OFF, 2)
    return e_shoff, e_shentsize, e_shnum, e_shstrndx


def _find_section_by_type(buf, stype) -> Optional[dict]:
    """주어진 sh_type 의 첫 섹션헤더 필드를 dict 로. 없으면 None.
       (versym 심볼수 추정에서 .dynsym 을 찾는 데 쓴다.)"""
    meta = _iter_shdrs(buf)
    if meta is None:
        return None
    e_shoff, e_shentsize, e_shnum, _ = meta
    stride = e_shentsize if e_shentsize else SHENTSIZE64
    size = len(buf)
    for i in range(e_shnum):
        o = e_shoff + i * stride
        if o + SHENTSIZE64 > size:
            break
        t = _rd(buf, o + SH_TYPE, 4)
        if t == stype:
            return dict(entry_off=o,
                        sh_type=t,
                        sh_offset=_rd(buf, o + SH_OFFSET, 8) or 0,
                        sh_size=_rd(buf, o + SH_SIZE, 8) or 0,
                        sh_entsize=_rd(buf, o + SH_ENTSIZE, 8) or 0)
    return None


def _repair_sht(buf, view) -> Optional[List[str]]:
    size = len(buf)
    if size < EHDR_SIZE:
        return None
    e_shoff = _rd(buf, E_SHOFF_OFF, 8)
    e_shnum = _rd(buf, E_SHNUM_OFF, 2)
    if not e_shoff or not e_shnum:
        return "sht: 부재(e_shoff/e_shnum==0) → SHT 복구 건너뜀"

    notes: List[str] = []

    # e_shentsize == 64
    e_shentsize = _rd(buf, E_SHENTSIZE_OFF, 2)
    if e_shentsize != SHENTSIZE64:
        _wr(buf, E_SHENTSIZE_OFF, 2, SHENTSIZE64)
        notes.append(f"sht: e_shentsize {e_shentsize} -> {SHENTSIZE64}")
        e_shentsize = SHENTSIZE64

    # e_shoff + e_shnum*64 ≤ 파일크기 → e_shnum 클램프
    if e_shoff > size:
        _wr(buf, E_SHNUM_OFF, 2, 0)
        notes.append(f"sht: e_shoff {hex(e_shoff)} > 파일크기 → e_shnum=0(SHT 비활성)")
        return notes
    max_shnum = (size - e_shoff) // SHENTSIZE64
    if e_shnum > max_shnum:
        _wr(buf, E_SHNUM_OFF, 2, max_shnum & 0xFFFF)
        notes.append(f"sht: e_shnum {e_shnum} -> {max_shnum} (파일 내 수용)")
        e_shnum = max_shnum
    if e_shnum == 0:
        notes.append("sht: 수용 가능한 섹션 0개")
        return notes

    # e_shstrndx < e_shnum
    e_shstrndx = _rd(buf, E_SHSTRNDX_OFF, 2)
    if e_shstrndx is not None and e_shstrndx >= e_shnum:
        _wr(buf, E_SHSTRNDX_OFF, 2, (e_shnum - 1) & 0xFFFF)
        notes.append(f"sht: e_shstrndx {e_shstrndx} -> {e_shnum - 1}")

    # 섹션별
    fixed_size = fixed_link = fixed_info = 0
    for i in range(e_shnum):
        o = e_shoff + i * SHENTSIZE64
        if o + SHENTSIZE64 > size:
            break
        sh_type = _rd(buf, o + SH_TYPE, 4)
        sh_off = _rd(buf, o + SH_OFFSET, 8)
        sh_size = _rd(buf, o + SH_SIZE, 8)
        sh_link = _rd(buf, o + SH_LINK, 4)
        sh_info = _rd(buf, o + SH_INFO, 4)
        # sh_offset + sh_size ≤ 파일크기 (SHT_NOBITS 는 파일공간 미점유 → 예외)
        if sh_type != SHT_NOBITS and sh_off is not None and sh_size is not None:
            if sh_off > size:
                _wr(buf, o + SH_OFFSET, 8, size)
                _wr(buf, o + SH_SIZE, 8, 0)
                fixed_size += 1
            elif sh_off + sh_size > size:
                _wr(buf, o + SH_SIZE, 8, max(0, size - sh_off))
                fixed_size += 1
        # sh_link < e_shnum
        if sh_link is not None and sh_link >= e_shnum:
            _wr(buf, o + SH_LINK, 4, 0)
            fixed_link += 1
        # sh_info: 타입별 의미검사
        if sh_type in (SHT_REL, SHT_RELA):
            # 재배치가 적용될 섹션 인덱스 → e_shnum 미만
            if sh_info is not None and sh_info >= e_shnum:
                _wr(buf, o + SH_INFO, 4, 0)
                fixed_info += 1
        elif sh_type in (SHT_SYMTAB, SHT_DYNSYM):
            # 마지막 지역심볼+1 → 심볼 총수 이하
            ent = _rd(buf, o + SH_ENTSIZE, 8) or SYMENT
            nsym = (sh_size // ent) if (ent and sh_size is not None) else 0
            if sh_info is not None and sh_info > nsym:
                _wr(buf, o + SH_INFO, 4, nsym & 0xFFFFFFFF)
                fixed_info += 1

    if fixed_size:
        notes.append(f"sht: sh_offset/sh_size {fixed_size}개 클램프")
    if fixed_link:
        notes.append(f"sht: sh_link {fixed_link}개 클램프")
    if fixed_info:
        notes.append(f"sht: sh_info {fixed_info}개 클램프")
    return notes or None


# ==========================================================================
# 자가 테스트 (__main__) — import 시 실행 안 됨. verifier 가 `python ...` 로 돌린다.
#   최소 ELF 합성 → DT_STRSZ / sh_size / DT_VERNEEDNUM 손상 → canonicalize →
#   각 필드가 범위로 복구됐는지 assert + 멱등성 확인.
# ==========================================================================
def _synth_elf_with_dyn_sht() -> "tuple":
    """PT_LOAD(전체파일 커버) + PT_DYNAMIC + DYNAMIC + strtab + Verneed(1) + SHT(2)
    를 갖춘 최소 ELF64 합성. (offset,정보) 를 함께 돌려줘 테스트가 오프셋을 안다."""
    ELFMAG = b"\x7fELF"
    # 레이아웃(연속 배치, vaddr==offset 항등)
    ehdr = 0
    pht = 64                      # 3 phdr * 56 = 168
    dyn = pht + 3 * 56            # 232
    n_dyn = 6                     # STRTAB,STRSZ,SYMTAB,VERNEED,VERNEEDNUM,NULL
    strtab = dyn + n_dyn * 16     # 328
    strtab_len = 16
    verneed = strtab + strtab_len  # 344
    verneed_len = 32              # Verneed(16)+Vernaux(16)
    sht = verneed + verneed_len   # 376
    n_sec = 2
    filesize = sht + n_sec * SHENTSIZE64  # 376 + 128 = 504

    buf = bytearray(filesize)
    buf[0:4] = ELFMAG
    buf[4] = 2                    # EI_CLASS = ELFCLASS64
    buf[5] = 1                    # EI_DATA  = ELFDATA2LSB
    buf[6] = 1                    # EI_VERSION
    struct.pack_into("<H", buf, 16, 3)     # e_type = ET_DYN
    struct.pack_into("<H", buf, 18, 62)    # e_machine = EM_X86_64
    struct.pack_into("<I", buf, 20, 1)     # e_version
    struct.pack_into("<Q", buf, 0x20, pht)         # e_phoff
    struct.pack_into("<H", buf, 52, EHDR_SIZE)     # e_ehsize
    struct.pack_into("<H", buf, 54, 56)            # e_phentsize
    struct.pack_into("<H", buf, 56, 3)             # e_phnum
    struct.pack_into("<Q", buf, E_SHOFF_OFF, sht)  # e_shoff
    struct.pack_into("<H", buf, E_SHENTSIZE_OFF, SHENTSIZE64)
    struct.pack_into("<H", buf, E_SHNUM_OFF, n_sec)
    struct.pack_into("<H", buf, E_SHSTRNDX_OFF, 0)

    def wphdr(idx, ptype, off, va, fsz, msz, align):
        b = pht + idx * 56
        struct.pack_into("<I", buf, b + 0, ptype)
        struct.pack_into("<I", buf, b + 4, 5)      # p_flags RX
        struct.pack_into("<Q", buf, b + 8, off)
        struct.pack_into("<Q", buf, b + 16, va)
        struct.pack_into("<Q", buf, b + 24, va)
        struct.pack_into("<Q", buf, b + 32, fsz)
        struct.pack_into("<Q", buf, b + 40, msz)
        struct.pack_into("<Q", buf, b + 48, align)

    # phdr0: 전체 파일을 덮는 PT_LOAD(항등 매핑) → 모든 vaddr 가 파일 안으로 매핑
    wphdr(0, PT_LOAD, 0, 0, filesize, filesize, 0x1000)
    wphdr(1, PT_DYNAMIC, dyn, dyn, n_dyn * 16, n_dyn * 16, 8)
    wphdr(2, PT_LOAD, 0, 0, filesize, filesize, 0x1000)  # 여분(무해)

    # DYNAMIC 엔트리
    correct_strsz = filesize - strtab   # 176
    dynrows = [
        (DT_STRTAB, strtab),
        (DT_STRSZ, correct_strsz),
        (DT_SYMTAB, strtab),
        (DT_VERNEED, verneed),
        (DT_VERNEEDNUM, 1),
        (DT_NULL, 0),
    ]
    off_strsz = off_verneednum = None
    for i, (tag, val) in enumerate(dynrows):
        eo = dyn + i * 16
        struct.pack_into("<Q", buf, eo, tag & 0xFFFFFFFFFFFFFFFF)
        struct.pack_into("<Q", buf, eo + 8, val)
        if tag == DT_STRSZ:
            off_strsz = eo + 8
        elif tag == DT_VERNEEDNUM:
            off_verneednum = eo + 8

    # strtab: NUL 로 시작하는 최소 문자열 테이블
    buf[strtab:strtab + strtab_len] = b"\x00libc.so.6\x00\x00\x00\x00\x00\x00"[:strtab_len]

    # Verneed(1) + Vernaux(1)
    struct.pack_into("<H", buf, verneed + 0, 1)    # vn_version
    struct.pack_into("<H", buf, verneed + 2, 1)    # vn_cnt
    struct.pack_into("<I", buf, verneed + 4, 1)    # vn_file (strtab idx)
    struct.pack_into("<I", buf, verneed + 8, 16)   # vn_aux → +16
    struct.pack_into("<I", buf, verneed + 12, 0)   # vn_next = 0(종단)
    aux = verneed + 16
    struct.pack_into("<I", buf, aux + 0, 0)        # vna_hash
    struct.pack_into("<H", buf, aux + 4, 0)        # vna_flags
    struct.pack_into("<H", buf, aux + 6, 2)        # vna_other (버전 인덱스)
    struct.pack_into("<I", buf, aux + 8, 1)        # vna_name
    struct.pack_into("<I", buf, aux + 12, 0)       # vna_next = 0(종단)

    # SHT: [0]=SHT_NULL, [1]=SHT_PROGBITS(파일공간 점유; sh_size 를 손상시킬 대상)
    sec1 = sht + 1 * SHENTSIZE64
    struct.pack_into("<I", buf, sec1 + SH_TYPE, 1)          # SHT_PROGBITS
    struct.pack_into("<Q", buf, sec1 + SH_OFFSET, strtab)   # 파일 내 유효 오프셋
    correct_shsize = filesize - strtab                      # 176
    struct.pack_into("<Q", buf, sec1 + SH_SIZE, correct_shsize)
    struct.pack_into("<I", buf, sec1 + SH_LINK, 0)
    off_shsize = sec1 + SH_SIZE

    info = dict(off_strsz=off_strsz, off_verneednum=off_verneednum,
                off_shsize=off_shsize, correct_strsz=correct_strsz,
                correct_shsize=correct_shsize, filesize=filesize)
    return buf, info


def _selftest():
    # 콘솔 인코딩이 UTF-8 이 아니어도 한글/기호가 안 깨지게 stdout 을 UTF-8 로.
    try:
        import sys as _sys
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("=" * 72)
    print("canonicalize.py 자가테스트 — 손상 3종 복구 + 멱등성")
    print("=" * 72)
    print(f"[pyelftools] {'가용' if _HAVE_PYELFTOOLS else '부재(무해)'}"
          f"  [ElfView] {'가용' if ElfView is not None else '부재(치명)'}")

    buf, info = _synth_elf_with_dyn_sht()
    print(f"[합성 ELF] {info['filesize']}B  "
          f"(정답: STRSZ={info['correct_strsz']}, "
          f"sh_size={info['correct_shsize']}, VERNEEDNUM=1)")

    # --- 손상 주입 ---
    struct.pack_into("<Q", buf, info["off_strsz"], 0xDEADBEEF)       # DT_STRSZ
    struct.pack_into("<Q", buf, info["off_shsize"], 0xFFFFFFFF)      # sh_size
    struct.pack_into("<Q", buf, info["off_verneednum"], 99)         # DT_VERNEEDNUM
    print("[손상] DT_STRSZ=0xDEADBEEF, sh_size=0xFFFFFFFF, DT_VERNEEDNUM=99")

    # --- 1차 canonicalize (full) ---
    notes = canonicalize(buf, level="full")
    print(f"[canonicalize level=full] 복구노트 {len(notes)}개:")
    for n in notes:
        print(f"   - {n}")

    got_strsz = struct.unpack_from("<Q", buf, info["off_strsz"])[0]
    got_shsize = struct.unpack_from("<Q", buf, info["off_shsize"])[0]
    got_vnum = struct.unpack_from("<Q", buf, info["off_verneednum"])[0]
    print(f"[복구 후] DT_STRSZ={got_strsz}, sh_size={got_shsize}, "
          f"DT_VERNEEDNUM={got_vnum}")

    assert got_strsz == info["correct_strsz"], \
        f"DT_STRSZ 복구 실패: {got_strsz} != {info['correct_strsz']}"
    assert got_shsize == info["correct_shsize"], \
        f"sh_size 복구 실패: {got_shsize} != {info['correct_shsize']}"
    assert got_vnum == 1, f"DT_VERNEEDNUM 복구 실패: {got_vnum} != 1"

    # --- 멱등성: 2차 실행은 세 필드를 안 바꿔야 한다 ---
    snapshot = bytes(buf)
    notes2 = canonicalize(buf, level="full")
    strsz2 = struct.unpack_from("<Q", buf, info["off_strsz"])[0]
    shsize2 = struct.unpack_from("<Q", buf, info["off_shsize"])[0]
    vnum2 = struct.unpack_from("<Q", buf, info["off_verneednum"])[0]
    assert (strsz2, shsize2, vnum2) == (got_strsz, got_shsize, got_vnum), \
        "멱등성 위반: 2차 실행이 이미 정합인 필드를 바꿈"
    assert bytes(buf) == snapshot, "멱등성 위반: 2차 실행이 버퍼를 변경함"
    print(f"[멱등성] 2차 실행 노트 {len(notes2)}개, 세 필드 불변 → OK")

    # --- 게이트 레벨은 no-op ---
    b2 = bytearray(snapshot)
    assert canonicalize(b2, level="gate") == [] and bytes(b2) == snapshot, \
        "gate 레벨이 no-op 이 아님"

    # --- 예외 안전: 쓰레기 입력에도 안 죽고 skip 노트만 ---
    junk = bytearray(b"not an elf file at all")
    jn = canonicalize(junk, level="full")
    print(f"[비-ELF 입력] 노트={jn}")

    print("\n자가테스트 OK — 3종 손상 복구 + 멱등성 + gate no-op + 예외안전.")


if __name__ == "__main__":
    _selftest()
