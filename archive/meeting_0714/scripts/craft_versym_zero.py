#!/usr/bin/env python3
"""step1: DYNAMIC의 버전 관련 d_ptr(DT_VERSYM / DT_VERNEED)을 0으로 지운 변종 ELF 생성.
SHT(.gnu.version Addr=0x50e)는 그대로 둔다. 런타임이 SHT로 폴백하는지 검증용.
DT_VERSYM=0x6ffffff0, DT_VERNEED=0x6ffffffe.  d_tag는 유지하고 d_un(값)만 0으로.
"""
import struct, sys

SRC = "/home/garden/PE/Lfuzzer/prac.elf"
TARGETS = {
    "versym":  (0x6ffffff0,),                  # DT_VERSYM만 0
    "verneed": (0x6ffffffe, 0x6fffffff),       # DT_VERNEED + VERNEEDNUM 0
    "both":    (0x6ffffff0, 0x6ffffffe, 0x6fffffff),
}

def craft(mode, dst):
    with open(SRC, "rb") as f:
        data = bytearray(f.read())
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    dyn_off = dyn_size = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type == 2:  # PT_DYNAMIC
            p_offset = struct.unpack_from("<Q", data, off + 8)[0]
            p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
            dyn_off, dyn_size = p_offset, p_filesz
            break
    assert dyn_off is not None, "no PT_DYNAMIC"
    tags = TARGETS[mode]
    hit = []
    for i in range(dyn_size // 16):
        eo = dyn_off + i * 16
        tag, val = struct.unpack_from("<QQ", data, eo)
        if tag in tags:
            struct.pack_into("<QQ", data, eo, tag, 0)   # keep tag, zero value
            hit.append((hex(tag), hex(val), hex(eo)))
    with open(dst, "wb") as f:
        f.write(data)
    print(f"[{mode}] zeroed {len(hit)} entries -> {dst}")
    for t, v, o in hit:
        print(f"    tag {t}  old_val {v}  @file_off {o}  -> new_val 0x0")

if __name__ == "__main__":
    base = "/home/garden/PE/Lfuzzer/meeting_0714_step1/out"
    for mode in ("versym", "verneed", "both"):
        craft(mode, f"{base}/prac_{mode}_zero.elf")
