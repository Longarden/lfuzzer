#!/usr/bin/env python3
"""
patch_auxtag.py -- craft prac_auxtag_collision.elf

Takes the base test binary (prac.elf, a copy is made in this experiment's own
working directory so we never touch the shared original) and overwrites its
spare/inert DT_DEBUG dynamic-section entry's TAG field (not its value) with

    0xDEADBEEFFFFFFFFD

Why this specific tag:
  - DT_AUXILIARY is defined as 0x7ffffffd (see /usr/include/elf.h).
  - glibc's DT_EXTRATAGIDX(tag) macro (elf.h) computes an l_info[] slot index
    from a tag by sign-extending/shifting only the LOW 32 BITS of the tag:
        #define DT_EXTRATAGIDX(tag) \
            ((Elf32_Word)-((Elf32_Sword)(tag)<<1>>1)-1)
    It takes an Elf32_Sword, i.e. it silently truncates a 64-bit d_tag to
    its low 32 bits before doing the index arithmetic.
  - DT_EXTRATAGIDX(0x7ffffffd) == 2   (this is DT_AUXILIARY's real slot)
  - A 64-bit tag whose low 32 bits are also 0xFFFFFFFD, e.g.
        0xDEADBEEFFFFFFFFD
    also gets DT_EXTRATAGIDX(...) == 2, i.e. it computes to the SAME l_info[]
    slot as a real DT_AUXILIARY entry (AUXTAG = DT_NUM + DT_THISPROCNUM +
    DT_VERSIONTAGNUM + DT_EXTRATAGIDX(DT_AUXILIARY), see dl-deps.c:36-37),
    even though as a full 64-bit value it is NOT equal to DT_AUXILIARY.
  - The DT_DEBUG entry (tag 0x15 / 21) is chosen as the patch site because
    it is inert for a PIE executable being run directly (glibc/rtld fills it
    in at runtime; the on-disk value is not otherwise load-bearing), same
    technique as ~/PE/Lfuzzer/craft_extratag_poc.py.

Output: prac_auxtag_collision.elf, a byte-for-byte copy of the input file
except for one 8-byte tag field inside the PT_DYNAMIC segment.
"""
import struct
import sys
import os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prac.elf")
DST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prac_auxtag_collision.elf")

DT_DEBUG = 21
NEW_TAG = 0xDEADBEEFFFFFFFFD

with open(SRC, "rb") as f:
    data = bytearray(f.read())

# --- locate PT_DYNAMIC via the ELF64 program header table ---
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)

dyn_off = dyn_size = None
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from("<IIQQQQQQ", data, off)
    if p_type == 2:  # PT_DYNAMIC
        dyn_off, dyn_size = p_offset, p_filesz
        break

if dyn_off is None:
    print("ERROR: no PT_DYNAMIC segment found in", SRC)
    sys.exit(1)

n_entries = dyn_size // 16
patched = False
for i in range(n_entries):
    entry_off = dyn_off + i * 16
    tag, val = struct.unpack_from("<qQ", data, entry_off)
    if tag == DT_DEBUG:
        print(f"found DT_DEBUG entry #{i} at file offset 0x{entry_off:x} "
              f"(tag=0x{tag:x} val=0x{val:x})")
        struct.pack_into("<QQ", data, entry_off, NEW_TAG, val)
        print(f"  -> patched tag field to 0x{NEW_TAG:016x}  (value field left as 0x{val:x})")
        patched = True
        break

if not patched:
    print("ERROR: no DT_DEBUG entry found to overwrite")
    sys.exit(1)

with open(DST, "wb") as f:
    f.write(data)
print("wrote", DST)
