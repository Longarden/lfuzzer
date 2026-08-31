#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
constructive.py — 조작값을 '유효하게 구성(construct)' 하는 repair.
==============================================================================
기존 canonicalize.py 는 클램프(shrink-to-fit): 큰 카운트/크기를 실제에 맞춰 '줄여'
유효화한다 → 뮤테이션 의도(큰 값)가 사라져 테스팅이 덜 된다.

이 모듈은 반대 방향 = grow-to-match:
  · 카운트(e_phnum/e_shnum)가 실제 엔트리보다 크면 → 파일을 늘려 진짜 엔트리로 채워
    그 큰 카운트를 '유효하게' 만든다(로더가 그만큼 진짜 순회 → 더 깊은 크래시).
  · grow 가 물리적으로 불가한 huge/음수 magnitude(0xFFFFFFFF, U64_MAX 등)는
    확률적(p_clamp, 기본 0.5)으로 clamp 하거나 그대로 통과(passthrough)시킨다.
  · 나머지 불일치(offset/size/index/pointer)는 canonicalize 를 p_clamp 확률로만 적용
    (아니면 조작값 그대로 통과) → "항상 클램프해서 테스팅 덜함" 을 방지.

설계 원칙(저장소 규약): stdlib + operators.ElfView + canonicalize 만. 예외 안 던짐.
전제: ELF64 LSB. 모든 read/write little-endian.

논문 4축 대응:
  ADD/SUB   : 카운트 grow/shrink = 이미 연산자가 구성적. 여기선 카운트↔실제 정합만 보강.
  SUBST     : 값 치환으로 생긴 huge/음수/불일치 → grow 또는 5:5 clamp/passthrough.
  SCRAMBLE  : 순서만 바뀜(카운트 불변) → 별도 grow 불필요, canonicalize 정합만.
"""
from __future__ import annotations

import os
import struct
import random
from typing import List, Optional

# EHDR/PHT/SHT 오프셋(elf64 규약)
E_PHOFF, E_PHENTSIZE, E_PHNUM = 0x20, 0x36, 0x38
E_SHOFF, E_SHENTSIZE, E_SHNUM = 0x28, 0x3A, 0x3C
PHENTSIZE64, SHENTSIZE64 = 56, 64

DEFAULT_CAP_ENTRIES = 2000        # grow 상한(엔트리 수). 2000*64 ≈ 128KB.


def _u16(b, o):
    if o + 2 > len(b):
        return None
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    if o + 4 > len(b):
        return None
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    if o + 8 > len(b):
        return None
    return struct.unpack_from("<Q", b, o)[0]


_PT_BASE = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8})
_SHT_BASE = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19})


def _pt_ok(t):
    """유효 p_type: 기본 타입 또는 OS(0x60000000-0x6FFFFFFF)/PROC(0x70000000-0x7FFFFFFF) 범위.
    GNU(EH_FRAME/STACK/RELRO/PROPERTY/SFRAME 등)는 OS 범위라 여기서 '유효' → 안 건드림(리뷰2)."""
    return t in _PT_BASE or 0x60000000 <= t <= 0x7FFFFFFF


def _sht_ok(t):
    """유효 sh_type: 기본 + OS/PROC/USER(0x60000000 이상). GNU_HASH/verdef/verneed/versym 등 보존."""
    return t in _SHT_BASE or t >= 0x60000000


def _fix_enums(buf, view, rng, notes):
    """SUBST 로 깨진 enum/타입 필드를 '유효값'으로 스냅 → 파서/로더가 그 타입 핸들러로
    진입(깊은 경로). p_type/p_flags/sh_type/st_info. 이미 유효한 값은 건드리지 않는다.
    (semantic 단계라 파이프라인에서 확률적으로 적용 = 유효/wild 스펙트럼 유지.)"""
    n = 0
    _PF_VALID = 7 | 0x0FF00000 | 0xF0000000     # R/W/X + PF_MASKOS + PF_MASKPROC
    for c in view.phdrs:                        # p_type, p_flags
        b = c["foff"]
        t = _u32(buf, b + 0)
        if t is not None and not _pt_ok(t):
            # 싱글턴 타입(2=DYNAMIC/3=INTERP/6=PHDR) 은 제외 — 중복 생성 시 파서 오염(리뷰2).
            _w(buf, b + 0, 4, rng.choice((1, 4, 7)))   # LOAD/NOTE/TLS
            n += 1
        fl = _u32(buf, b + 4)
        if fl is not None and (fl & ~_PF_VALID):    # 예약비트(OS/PROC) 밖 쓰레기만 정리
            _w(buf, b + 4, 4, fl & _PF_VALID)
            n += 1
    for s in view.sections:                     # sh_type (GNU/OS 타입은 _sht_ok 로 보존)
        t = _u32(buf, s["foff"] + 4)
        if t is not None and not _sht_ok(t):
            _w(buf, s["foff"] + 4, 4, rng.choice((1, 2, 3, 4, 6, 8, 9, 11)))
            n += 1
    for sym in view.syms:                        # st_info = (bind<<4)|type
        fo = sym["foff"]
        if fo + 5 <= len(buf):
            info = buf[fo + 4]
            typ, bind = info & 0xF, info >> 4
            if typ > 6 or bind > 2:
                buf[fo + 4] = ((min(bind, 2) << 4) | min(typ, 6)) & 0xFF
                n += 1
    if n:
        notes.append(f"enum: {n}개 필드 유효값 스냅(p_type/flags/sh_type/st_info)")


def _grow_table(buf: bytearray, notes: List[str], rng: random.Random,
                cap_entries: int, *, which: str, ref_len: int) -> None:
    """카운트(e_phnum/e_shnum)가 파일에 실제로 들어있는 것보다 크면 grow-to-match.
    cap 초과(huge)면 passthrough. fit 은 ref_len(grow 전 길이) 기준으로 계산해
    앞선 PHT grow 의 EOF append 가 SHT fit 을 오염시키지 않게 한다(리뷰 ④)."""
    if which == "pht":
        off_field, num_field, name, ent = E_PHOFF, E_PHNUM, "e_phnum", PHENTSIZE64
    else:
        off_field, num_field, name, ent = E_SHOFF, E_SHNUM, "e_shnum", SHENTSIZE64
    num_off = num_field
    # 엔트리 stride 는 ELF64 스펙 고정값(56/64)을 쓴다. 물리 엔트리는 항상 이 간격으로
    # 놓여 있고(변조된 e_phentsize 는 필드값일 뿐 실제 배치를 안 옮김), GATE 가 e_phentsize
    # 를 56 으로 복원하므로 로더의 walk 도 56/64. 변조된 entsize 를 stride 로 쓰면(리뷰 2)
    # fit=0→전엔트리 0 화(실제 PT_DYNAMIC 소실) + 메모리 폭증 회귀가 나므로 쓰지 않는다.

    tbl_off = _u64(buf, off_field)
    n = _u16(buf, num_field)
    if tbl_off is None or n is None or n == 0:
        return
    if tbl_off == 0 or tbl_off > ref_len:
        return  # 테이블 위치 자체가 파일 밖 → 손대지 않음(canonicalize/gate 소관)

    fit = max(0, (ref_len - tbl_off) // ent)    # grow 전 길이 기준 수용 엔트리 수
    if n <= fit:
        return  # 이미 카운트만큼 실제로 있음 → 정합, grow 불필요

    # n > fit : 카운트가 실제보다 큼
    if n <= cap_entries:
        # ★constructive grow★: 테이블을 파일끝으로 옮기고 n개 엔트리로 채운다.
        #   앞쪽은 기존 엔트리 복사, 부족분은 엔트리[0] 복제(유효한 진짜 엔트리).
        old = bytes(buf[tbl_off: tbl_off + fit * ent])
        pad = (-len(buf)) % 8
        buf.extend(b"\x00" * pad)
        new_off = len(buf)
        buf.extend(old)
        proto = old[:ent] if len(old) >= ent else (b"\x00" * ent)
        for _ in range(n - fit):
            buf.extend(proto)              # 부족분을 엔트리0 복제로 채움
        struct.pack_into("<Q", buf, off_field, new_off)
        notes.append(f"constructive: {name}={n} → 테이블 EOF@{hex(new_off)}로 grow "
                     f"({fit}→{n} 실엔트리, {n-fit}개 복제채움)")
    else:
        # huge: 물리적 grow 불가 → passthrough(조작값 그대로). ★clamp 안 함★:
        # clamp(줄이기)는 뮤테이션을 삭제해 메타데이터 경우의 수를 줄인다. 큰 값을
        # 그대로 두면 로더가 그만큼 OOB 순회하다 크래시 — 그게 테스트하려는 케이스다.
        notes.append(f"huge: {name}={n} > cap({cap_entries}) → passthrough(조작값 유지)")


# ── DT 태그 + PHT 내부 오프셋(vaddr-구조 grow / 메모리·enum 필드용) ──
DT_STRTAB, DT_STRSZ, DT_SYMTAB = 5, 10, 6
DT_RELA, DT_RELASZ, DT_RELAENT = 7, 8, 9
DT_SYMENT = 11
DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFFE, 0x6FFFFFFF
PH_OFFSET, PH_VADDR, PH_PADDR, PH_FILESZ, PH_MEMSZ, PH_ALIGN = 8, 16, 24, 32, 40, 48
CAP_GROW_BYTES = 16 * 1024 * 1024      # vaddr-구조 grow 상한(파일 증가 바이트)
_VALID_ALIGN = (0, 1, 0x1000, 0x200000, 0x1000000)


def _w(buf, off, w, v):
    if 0 <= off and off + w <= len(buf):
        struct.pack_into({2: "<H", 4: "<I", 8: "<Q"}[w], buf, off, v & ((1 << (8 * w)) - 1))


def _dyn_foffs(view) -> dict:
    return {e["d_tag"]: e["foff"] for e in view.dyn_entries}


def _last_load(view):
    """파일 끝에 가장 가까운 '정상' PT_LOAD(EOF 확장 대상).
    p_offset 이 파일 밖이거나 필드가 비정상인 로드는 제외(리뷰 ②: 음수 filesz 방지)."""
    best = None
    for L in view.loads:
        po, pf, pv = L.get("p_offset"), L.get("p_filesz"), L.get("p_vaddr")
        if po is None or pf is None or pv is None:
            continue
        if po > view.size or pf > view.size:      # 파일 밖 오프셋/거대 filesz 제외
            continue
        if best is None or (po + pf) > (best["p_offset"] + best["p_filesz"]):
            best = L
    return best


def _grow_vaddr_struct(buf, view, notes, *, ptr_tag, size_tag, cur_off, cur_size,
                       new_size, ent, name, cap=CAP_GROW_BYTES):
    """vaddr-addressed 구조를 new_size 바이트로 grow.
    스펙 §0: vaddr구조는 PT_LOAD 파일창 안에 있어야 로더가 본다 → 확장본을 EOF에 붙이고
    '마지막 PT_LOAD'의 p_filesz/p_memsz를 늘려 그 새 바이트를 파일백킹+매핑되게 하고,
    DT 포인터를 새 vaddr로, DT 크기를 new_size로 갱신한다.
    grow 불가(cap 초과/PT_LOAD 부재)면 손대지 않음(passthrough)."""
    if new_size <= cur_size:
        return False
    if new_size > cap:
        notes.append(f"{name}: new_size {new_size} > cap → passthrough")
        return False
    L = _last_load(view)
    if L is None or L.get("p_vaddr") is None or L.get("p_offset") is None:
        notes.append(f"{name}: PT_LOAD 없음 → passthrough")
        return False
    # 사전검증(변형 전): new_off/new_va/new_filesz 오버플로우·범위 (리뷰 ②⑤)
    pad = (-len(buf)) % 8
    new_off = len(buf) + pad
    new_va = L["p_vaddr"] + (new_off - L["p_offset"])
    new_filesz = (new_off + new_size) - L["p_offset"]
    if not (0 <= new_va < (1 << 64)) or not (0 < new_filesz < (1 << 64)):
        notes.append(f"{name}: new_va/filesz 오버플로우 → passthrough")
        return False
    # 확장본 = 기존내용 + 부족분(ent단위면 마지막 엔트리 복제, 아니면 0패딩)
    content = bytes(buf[cur_off:cur_off + cur_size]) if (0 <= cur_off and cur_off + cur_size <= len(buf)) else b""
    extra = new_size - len(content)
    if extra < 0:
        return False
    if ent and len(content) >= ent:
        reps = (extra + ent - 1) // ent
        content = content + content[-ent:] * reps
    else:
        content = content + b"\x00" * extra
    content = content[:new_size]
    # 변형 실행
    buf.extend(b"\x00" * pad)
    buf.extend(content)
    Lbase = L["foff"]
    _w(buf, Lbase + PH_FILESZ, 8, new_filesz)
    if (L.get("p_memsz") or 0) < new_filesz:
        _w(buf, Lbase + PH_MEMSZ, 8, new_filesz)
    foffs = _dyn_foffs(view)
    if ptr_tag in foffs:
        _w(buf, foffs[ptr_tag] + 8, 8, new_va)
    if size_tag is not None and size_tag in foffs:
        _w(buf, foffs[size_tag] + 8, 8, new_size)
    notes.append(f"{name}: grow {cur_size}→{new_size}B @EOF vaddr={hex(new_va)} (PT_LOAD 확장)")
    return True


def _grow_dt_sized(buf, view, notes, ptr_tag, size_tag, ent, name, cap):
    """DT 포인터+크기로 정의된 vaddr-구조(strtab/rela)를 크기 태그값까지 grow-to-match."""
    foffs = _dyn_foffs(view)
    if ptr_tag not in foffs or size_tag not in foffs:
        return
    ptr_va, S = view.dt.get(ptr_tag), view.dt.get(size_tag)
    if ptr_va is None or S is None or S == 0:
        return
    off = view.vaddr_to_off(ptr_va)
    if off is None:
        return  # 포인터가 PT_LOAD 밖 → grow가 위치 못 잡음, passthrough
    # 이 구조가 속한 PT_LOAD 파일창에서 현재 확보 바이트
    L = None
    for c in view.loads:
        pv, pf = c.get("p_vaddr"), c.get("p_filesz")
        if pv is not None and pf is not None and pv <= ptr_va < pv + pf:
            L = c
            break
    if L is None:
        return
    avail = (L["p_offset"] + L["p_filesz"]) - off
    if S <= avail:
        return  # 이미 S 바이트 있음
    _grow_vaddr_struct(buf, view, notes, ptr_tag=ptr_tag, size_tag=size_tag,
                       cur_off=off, cur_size=max(0, avail), new_size=S, ent=ent, name=name, cap=cap)


def _fix_pht_memory(buf, view, rng, notes):
    """PHT의 '파일 안 늘려도 되는' 필드를 constructive하게 유효화(스펙 A/E 클래스):
      p_memsz ≥ p_filesz · p_paddr:=p_vaddr · p_align 유효 2의거듭제곱 ·
      p_vaddr ≡ p_offset (mod p_align) 위로 nudge (값 유지, 아래로 안 내림)."""
    fixed = 0
    for c in view.phdrs:
        b = c["foff"]
        p_off = _u64(buf, b + PH_OFFSET)
        p_va = _u64(buf, b + PH_VADDR)
        p_fsz = _u64(buf, b + PH_FILESZ)
        p_msz = _u64(buf, b + PH_MEMSZ)
        p_al = _u64(buf, b + PH_ALIGN)
        if None in (p_off, p_va, p_fsz, p_msz, p_al):
            continue
        # align 유효 2의거듭제곱 (vaddr nudge 전에 확정)
        if not (p_al in (0, 1) or (p_al & (p_al - 1)) == 0) or p_al > (1 << 30):
            p_al = rng.choice(_VALID_ALIGN)
            _w(buf, b + PH_ALIGN, 8, p_al)
            fixed += 1
        # vaddr ≡ offset (mod align): 위로 nudge(값 유지). 오버플로우면 스킵(리뷰 ⑥)
        if p_al > 1:
            want = p_off % p_al
            cur = p_va % p_al
            if cur != want:
                cand = p_va + ((want - cur) % p_al)
                if cand < (1 << 64):
                    p_va = cand
                    _w(buf, b + PH_VADDR, 8, p_va)
                    fixed += 1
        # memsz ≥ filesz (메모리만, 파일 안 늘림)
        if p_msz < p_fsz:
            _w(buf, b + PH_MEMSZ, 8, p_fsz)
            fixed += 1
        # paddr := vaddr (nudge 이후 '최종' vaddr 로 동기 — 리뷰 ⑥ 순서버그)
        if _u64(buf, b + PH_PADDR) != p_va:
            _w(buf, b + PH_PADDR, 8, p_va)
    if fixed:
        notes.append(f"pht-mem: {fixed}개 필드 constructive(memsz/align/vaddr-congruence)")


def constructive_repair(buf: bytearray, rng: Optional[random.Random] = None, *,
                        p_clamp: float = 0.0,
                        cap_entries: int = DEFAULT_CAP_ENTRIES) -> List[str]:
    """조작값 유효화 repair. 반환: 복구노트. 절대 예외 안 던짐.

    1) 카운트 grow-to-match (e_phnum/e_shnum), grow 불가(huge)면 passthrough
    2) 나머지 불일치: 기본 passthrough(조작값 유지). p_clamp>0 면 그 확률로 canonicalize(clamp).
       ★clamp 기본 OFF★ — clamp(줄이기)는 뮤테이션을 삭제해 메타데이터 경우의 수를 줄인다.
    """
    notes: List[str] = []
    if not isinstance(buf, bytearray):
        return ["skip: bytearray 아님"]
    if rng is None:
        rng = random.Random()

    ref_len = len(buf)   # grow 전 길이 = fit 계산 기준(리뷰 ④: PHT append 가 SHT fit 오염 방지)

    def _reparse():
        try:
            from lfuzzer.mutators.operators import ElfView
            v = ElfView.parse(buf)
            return v if v.ok else None
        except Exception:
            return None

    # 1) 카운트 grow (PHT/SHT). 각 grow 개별 예외격리(리뷰 ⑦)
    for which in ("pht", "sht"):
        try:
            _grow_table(buf, notes, rng, cap_entries, which=which, ref_len=ref_len)
        except Exception as e:
            notes.append(f"{which} count-grow 예외: {type(e).__name__}")

    # 2) PHT 메모리·enum → ★재파싱★ → strtab grow → ★재파싱★ → rela grow (각 단계 격리·재파싱)
    view = _reparse()
    if view is not None:
        try:
            _fix_pht_memory(buf, view, rng, notes)   # 메모리/정렬/congruence
            _fix_enums(buf, view, rng, notes)        # p_type/flags/sh_type/st_info 유효값 스냅
        except Exception as e:
            notes.append(f"pht-mem/enum 예외: {type(e).__name__}")
        view = _reparse()                            # nudge/enum 반영(리뷰 ①: staleness)
    if view is not None:
        try:
            _grow_dt_sized(buf, view, notes, DT_STRTAB, DT_STRSZ, 0, "strtab", CAP_GROW_BYTES)
        except Exception as e:
            notes.append(f"strtab-grow 예외: {type(e).__name__}")
        view = _reparse()                            # strtab grow 반영
    if view is not None:
        try:
            _grow_dt_sized(buf, view, notes, DT_RELA, DT_RELASZ, 24, "rela", CAP_GROW_BYTES)
        except Exception as e:
            notes.append(f"rela-grow 예외: {type(e).__name__}")

    # 3) 나머지 = clamp OFF(기본 passthrough). p_clamp>0 이면 그 확률로만 canonicalize(clamp).
    if p_clamp > 0 and rng.random() < p_clamp:
        try:
            from lfuzzer.repair.canonicalize import canonicalize
            notes.extend(canonicalize(buf, level="full"))
        except Exception as e:
            notes.append(f"canonicalize 예외: {type(e).__name__}")
    else:
        notes.append("passthrough: 나머지 조작값 유지(clamp OFF)")

    return notes


# ── 자가테스트: import 시 실행 안 됨. verifier 가 `python -m ...` 로 돌린다. ──
def _mk_min_elf(phnum=3, shnum=0):
    """최소 ELF64(EHDR + phnum phdr, 선택적 shnum shdr)."""
    ph_off = 64
    sh_off = ph_off + max(phnum, 1) * PHENTSIZE64
    size = sh_off + shnum * SHENTSIZE64 + 64
    buf = bytearray(size)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2
    buf[5] = 1
    struct.pack_into("<Q", buf, E_PHOFF, ph_off)
    struct.pack_into("<H", buf, E_PHENTSIZE, PHENTSIZE64)
    struct.pack_into("<H", buf, E_PHNUM, phnum)
    if shnum:
        struct.pack_into("<Q", buf, E_SHOFF, sh_off)
        struct.pack_into("<H", buf, E_SHENTSIZE, SHENTSIZE64)
        struct.pack_into("<H", buf, E_SHNUM, shnum)
    return buf


def _selftest():
    """검증기: (1)카운트 grow (2)huge 5:5 clamp/passthrough (3)실제 .so magic 보존."""
    try:
        import sys as _s
        _s.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("=" * 68)
    print("constructive.py 검증기")
    print("=" * 68)

    # (1a) e_phnum grow-to-match
    buf = _mk_min_elf(phnum=3)
    struct.pack_into("<H", buf, E_PHNUM, 50)              # 조작: 50 주장
    constructive_repair(buf, random.Random(1), p_clamp=1.0)
    phnum = struct.unpack_from("<H", buf, E_PHNUM)[0]
    phoff = struct.unpack_from("<Q", buf, E_PHOFF)[0]
    real = (len(buf) - phoff) // PHENTSIZE64
    assert phnum == 50 and real >= 50, f"e_phnum grow 실패: phnum={phnum} real={real}"
    assert bytes(buf[0:4]) == b"\x7fELF"
    print(f"[1a] e_phnum=50 → grow OK (실엔트리 {real}, 값유지 {phnum})")

    # (1b) e_shnum grow-to-match
    buf = _mk_min_elf(phnum=2, shnum=2)
    struct.pack_into("<H", buf, E_SHNUM, 40)
    constructive_repair(buf, random.Random(2), p_clamp=1.0)
    shnum = struct.unpack_from("<H", buf, E_SHNUM)[0]
    shoff = struct.unpack_from("<Q", buf, E_SHOFF)[0]
    sreal = (len(buf) - shoff) // SHENTSIZE64
    assert shnum == 40 and sreal >= 40, f"e_shnum grow 실패: shnum={shnum} real={sreal}"
    print(f"[1b] e_shnum=40 → grow OK (실엔트리 {sreal}, 값유지 {shnum})")

    # (2) huge(> cap) → 항상 passthrough (clamp OFF). 조작값이 그대로 유지돼야 한다.
    passthru = 0
    for s in range(200):
        b = _mk_min_elf(phnum=3)
        struct.pack_into("<H", b, E_PHNUM, 0xFFFF)         # huge (cap 2000 초과)
        constructive_repair(b, random.Random(s))           # 기본 p_clamp=0
        if struct.unpack_from("<H", b, E_PHNUM)[0] == 0xFFFF:
            passthru += 1
    print(f"[2] huge e_phnum=0xFFFF: passthrough {passthru}/200 (clamp OFF)")
    assert passthru == 200, f"passthrough 실패(clamp 발생?): {passthru}/200"

    # (3) 실제 .so: fuzz 후 constructive 반복 → magic 보존 + 무예외
    import os
    so = os.path.expanduser("~/seeds_mass/verdef1.so")
    if os.path.exists(so):
        data = bytearray(open(so, "rb").read())
        rng = random.Random(9)
        ok = 0
        for _ in range(200):
            b = bytearray(data)
            # 임의 필드 몇 개를 huge로 조작 후 constructive
            for off in (E_PHNUM, E_SHNUM):
                struct.pack_into("<H", b, off, rng.choice([50, 0xFFFF, 200]))
            constructive_repair(b, rng, p_clamp=0.5)
            if len(b) >= 64 and bytes(b[0:4]) == b"\x7fELF":
                ok += 1
        assert ok == 200, f"magic 보존 실패: {ok}/200"
        print(f"[3] 실제 .so 200회: magic 보존 {ok}/200, 무예외 OK")
        # (4) vaddr-구조 grow: DT_STRSZ 조작 → strtab grow → readelf 파싱성공
        import struct as _st, subprocess, tempfile
        from lfuzzer.mutators.operators import ElfView
        b = bytearray(open(so, "rb").read())
        v = ElfView.parse(b)
        sf = None
        for e in v.dyn_entries:
            if e["d_tag"] == DT_STRSZ:
                sf = e["foff"]
                break
        if sf is not None:
            old = _st.unpack_from("<Q", b, sf + 8)[0]
            _st.pack_into("<Q", b, sf + 8, old + 40000)      # +40KB (cap 이내)
            before = len(b)
            notes = constructive_repair(b, random.Random(5))
            grew = any("strtab: grow" in n for n in notes)
            with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as tf:
                tf.write(bytes(b))
                p = tf.name
            rc = subprocess.run(["readelf", "-d", p], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10).returncode
            os.unlink(p)
            v2 = ElfView.parse(b)
            print(f"[4] strtab grow: len {before}→{len(b)}, grew={grew}, "
                  f"readelf rc={rc}, 재파싱 strsz={v2.dt.get(DT_STRSZ)}")
            assert grew, "strtab grow 안 일어남"
            assert rc == 0, f"grown ELF readelf 파싱 실패 rc={rc}"
            assert v2.dt.get(DT_STRSZ) == old + 40000, "DT_STRSZ 값 유지 실패"
    else:
        print("[3][4] seeds_mass/verdef1.so 없음 → 실제 .so 검증 스킵")

    print("\n검증기 OK — 카운트 grow + vaddr구조 grow + magic보존 + readelf파싱 전부 통과.")


if __name__ == "__main__":
    _selftest()
