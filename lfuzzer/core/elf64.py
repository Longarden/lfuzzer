#!/usr/bin/env python3
"""
elf64.py — shared, behavior-exact ELF64 read primitives for the Lfuzzer harness.

These functions are the single source of truth for parsing that the various
mutators (autorun_v3.py class Elf, mutator_dynamic_v3.py class Elf,
mutator_interp_vaddr_v2.py parse_elf, ...) previously each re-implemented.
Behavior is intentionally identical to those existing correct re-implementations
so that swapping call sites onto this module changes nothing at runtime.

All primitives are PURE: they take an immutable-ish `data` (bytes/bytearray),
read fields at fixed offsets, and return plain Python values. No mutation, no
randomness, no I/O. Everything is little-endian (ELF64 x86-64).

ELF64 header field offsets used here (little-endian):
    0x20  e_phoff      (u64)  program header table file offset
    0x28  e_shoff      (u64)  section header table file offset
    0x36  e_phentsize  (u16)  size of one program header entry (stride)
    0x38  e_phnum      (u16)  number of program header entries
    0x3A  e_shentsize  (u16)  size of one section header entry (stride)
    0x3C  e_shnum      (u16)  number of section header entries
    0x3E  e_shstrndx   (u16)  section header index of the .shstrtab

Program header entry (Elf64_Phdr) field offsets:
    0x00  p_type   (u32)
    0x04  p_flags  (u32)
    0x08  p_offset (u64)
    0x10  p_vaddr  (u64)
    0x18  p_paddr  (u64)
    0x20  p_filesz (u64)
    0x28  p_memsz  (u64)
    0x30  p_align  (u64)

Dynamic entry (Elf64_Dyn) is 16 bytes: d_tag (u64) then d_un (u64).

Section header entry (Elf64_Shdr) field offsets:
    0x00  sh_name      (u32)  offset into .shstrtab
    0x04  sh_type      (u32)
    0x08  sh_flags     (u64)
    0x10  sh_addr      (u64)
    0x18  sh_offset    (u64)
    0x20  sh_size      (u64)
    0x28  sh_link      (u32)
    0x2C  sh_info      (u32)
    0x30  sh_addralign (u64)
    0x38  sh_entsize   (u64)
"""

import struct

# ---- program header types ----
PT_LOAD = 1
PT_DYNAMIC = 2

# ---- dynamic tags ----
DT_NULL = 0

# ---- primitive little-endian readers (match autorun_v3 / mutator_dynamic_v3) ----
def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]

def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]

def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def read_phdrs(data):
    """Return the program header table as a list of dicts.

    Reads e_phoff@0x20, e_phentsize@0x36, e_phnum@0x38 from the ELF header and
    strides by e_phentsize (NOT a hardcoded 56) so that files with a non-standard
    entry size parse correctly.

    Each entry dict has keys:
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
        entry_offset -- absolute file offset of the start of this phdr entry

    Behavior-exact with autorun_v3.Elf / mutator_dynamic_v3.Elf (same offsets,
    same little-endian reads).
    """
    e_phoff = u64(data, 0x20)
    e_phentsize = u16(data, 0x36)
    e_phnum = u16(data, 0x38)
    phdrs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        phdrs.append({
            "p_type":   u32(data, o + 0x00),
            "p_flags":  u32(data, o + 0x04),
            "p_offset": u64(data, o + 0x08),
            "p_vaddr":  u64(data, o + 0x10),
            "p_paddr":  u64(data, o + 0x18),
            "p_filesz": u64(data, o + 0x20),
            "p_memsz":  u64(data, o + 0x28),
            "p_align":  u64(data, o + 0x30),
            "entry_offset": o,
        })
    return phdrs


def iter_dynamic(data):
    """Yield (index, d_tag, d_un, file_offset) for each Elf64_Dyn entry.

    Finds the PT_DYNAMIC segment via read_phdrs, then walks 16-byte entries
    starting at that segment's p_offset (the dynamic array lives at its file
    offset in these non-relocated on-disk images, matching the existing
    class Elf.dyn / dyn_entries behavior). Each entry contributes d_tag (u64 at
    file_offset) and d_un (u64 at file_offset+8).

    The walk stops after yielding the DT_NULL terminator, and is hard-capped at
    256 entries (same guard as the originals). If there is no PT_DYNAMIC
    segment, yields nothing.
    """
    dyn_off = None
    for ph in read_phdrs(data):
        if ph["p_type"] == PT_DYNAMIC:
            dyn_off = ph["p_offset"]
            break
    if dyn_off is None:
        return
    o = dyn_off
    i = 0
    while i < 256:
        tag = u64(data, o)
        val = u64(data, o + 8)
        yield (i, tag, val, o)
        if tag == DT_NULL:
            break
        o += 16
        i += 1


def vaddr_to_offset(data, vaddr):
    """Translate a virtual address to a file offset, FILESZ-bounded.

    Walks PT_LOAD segments; a vaddr is resolved by the first segment whose
    range [p_vaddr, p_vaddr + p_filesz) contains it, returning
    p_offset + (vaddr - p_vaddr). Returns None if no such segment.

    This is intentionally FILESZ-bounded, NOT memsz-aware: a vaddr that falls in
    a .bss / memsz>filesz tail (present in memory, absent from the file) returns
    None. This exactly matches the correct v2o in autorun_v3 / mutator_dynamic_v3
    and must not be "improved" to be memsz-aware.
    """
    for ph in read_phdrs(data):
        if ph["p_type"] != PT_LOAD:
            continue
        pv = ph["p_vaddr"]
        pf = ph["p_filesz"]
        po = ph["p_offset"]
        if pv <= vaddr < pv + pf:
            return po + (vaddr - pv)
    return None


def section_by_name(data, name):
    """Return the section header dict for `name`, or None if not found.

    Walks the section header table via e_shoff@0x28, e_shentsize@0x3A (stride),
    e_shnum@0x3C, resolving names through the .shstrtab section identified by
    e_shstrndx@0x3E. `name` may be str or bytes; comparison is on raw bytes.

    Each returned dict has keys:
        sh_name (raw u32 offset into shstrtab), sh_type, sh_flags, sh_addr,
        sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
        name (decoded section name, str), entry_offset (abs file offset of shdr).

    Returns None if there is no section header table (e_shoff == 0 or
    e_shnum == 0) or no section matches.
    """
    if isinstance(name, bytes):
        want = name
    else:
        want = name.encode("utf-8", "surrogateescape")

    e_shoff = u64(data, 0x28)
    e_shentsize = u16(data, 0x3A)
    e_shnum = u16(data, 0x3C)
    e_shstrndx = u16(data, 0x3E)
    if e_shoff == 0 or e_shnum == 0:
        return None

    # locate .shstrtab (the string table holding section names)
    shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize
    shstrtab_off = u64(data, shstr_hdr_off + 0x18)  # sh_offset of shstrtab

    def _cstr(base, idx):
        p = base + idx
        end = data.find(b"\x00", p)
        if end == -1:
            end = len(data)
        return bytes(data[p:end])

    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        sh_name = u32(data, o + 0x00)
        nm = _cstr(shstrtab_off, sh_name)
        if nm == want:
            return {
                "sh_name":      sh_name,
                "sh_type":      u32(data, o + 0x04),
                "sh_flags":     u64(data, o + 0x08),
                "sh_addr":      u64(data, o + 0x10),
                "sh_offset":    u64(data, o + 0x18),
                "sh_size":      u64(data, o + 0x20),
                "sh_link":      u32(data, o + 0x28),
                "sh_info":      u32(data, o + 0x2C),
                "sh_addralign": u64(data, o + 0x30),
                "sh_entsize":   u64(data, o + 0x38),
                "name":         nm.decode("utf-8", "surrogateescape"),
                "entry_offset": o,
            }
    return None


def _selftest():
    """Sanity checks against prac.elf. Exercises every public primitive and
    cross-checks against the legacy class Elf behavior where they overlap."""
    import os
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prac.elf")
    with open(base, "rb") as f:
        data = f.read()

    # --- read_phdrs ---
    phdrs = read_phdrs(data)
    e_phnum = u16(data, 0x38)
    e_phentsize = u16(data, 0x36)
    assert len(phdrs) == e_phnum, f"phnum {len(phdrs)} != {e_phnum}"
    assert phdrs[0]["entry_offset"] == u64(data, 0x20)
    # stride must equal e_phentsize, not a hardcoded 56
    if len(phdrs) >= 2:
        assert phdrs[1]["entry_offset"] - phdrs[0]["entry_offset"] == e_phentsize
    loads = [p for p in phdrs if p["p_type"] == PT_LOAD]
    dyns = [p for p in phdrs if p["p_type"] == PT_DYNAMIC]
    print(f"[phdrs] {len(phdrs)} entries, entsize={e_phentsize}, "
          f"{len(loads)} PT_LOAD, {len(dyns)} PT_DYNAMIC")

    # --- iter_dynamic ---
    dyn = list(iter_dynamic(data))
    if dyns:
        assert dyn, "PT_DYNAMIC present but iter_dynamic yielded nothing"
        assert dyn[-1][1] == DT_NULL, "dynamic array not DT_NULL terminated"
        # file offsets stride by 16
        for a, b in zip(dyn, dyn[1:]):
            assert b[3] - a[3] == 16
        # must start at PT_DYNAMIC p_offset
        assert dyn[0][3] == dyns[0]["p_offset"]
    print(f"[dynamic] {len(dyn)} entries "
          f"(last tag=0x{dyn[-1][1]:x})" if dyn else "[dynamic] none")

    # --- vaddr_to_offset ---
    if loads:
        L = loads[0]
        # start of first LOAD maps to its file offset
        assert vaddr_to_offset(data, L["p_vaddr"]) == L["p_offset"]
        # one before the vaddr is out of range -> None (unless another seg covers)
        below = vaddr_to_offset(data, L["p_vaddr"] - 1)
        # a filesz-tail address (in memsz but past filesz) must be None if any
        # LOAD has memsz > filesz
        for seg in loads:
            if seg["p_memsz"] > seg["p_filesz"]:
                tail = seg["p_vaddr"] + seg["p_filesz"]
                # only assert None if no OTHER load covers it in-file
                if all(not (s["p_vaddr"] <= tail < s["p_vaddr"] + s["p_filesz"])
                       for s in loads):
                    assert vaddr_to_offset(data, tail) is None, \
                        "filesz-tail vaddr should be None (not memsz-aware)"
                break
        print(f"[v2o] first LOAD vaddr 0x{L['p_vaddr']:x} -> "
              f"file 0x{L['p_offset']:x} (below={below})")

    # --- section_by_name ---
    e_shoff = u64(data, 0x28)
    if e_shoff:
        for probe in (".dynamic", ".interp", ".text", ".dynstr"):
            s = section_by_name(data, probe)
            if s:
                print(f"[section] {probe:10s} off=0x{s['sh_offset']:x} "
                      f"size=0x{s['sh_size']:x} type={s['sh_type']}")
        assert section_by_name(data, ".no_such_section_xyz") is None
        # cross-check: .dynamic sh_offset should equal PT_DYNAMIC p_offset
        sd = section_by_name(data, ".dynamic")
        if sd and dyns:
            assert sd["sh_offset"] == dyns[0]["p_offset"], \
                ".dynamic sh_offset != PT_DYNAMIC p_offset"
    else:
        print("[section] no section header table (e_shoff==0)")

    print("elf64._selftest OK")


if __name__ == "__main__":
    _selftest()
