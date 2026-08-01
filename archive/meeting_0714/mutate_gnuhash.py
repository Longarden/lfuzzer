#!/usr/bin/env python3
"""
step2: DT_GNU_HASH loader-robustness mutator.
glibc ld.so 가 손상된 GNU hash 메타데이터를 얼마나 방어하는지 측정하기 위한
변종 ELF 생성기. 두 축을 건드린다:
  (1) DT_GNU_HASH 의 d_ptr (동적 테이블이 가리키는 해시테이블 주소)
  (2) .gnu.hash 헤더 4워드: nbuckets / symbias / maskwords(bloom) / shift
pyelftools 로 구조를 파싱해 정확한 file offset 을 얻고, struct 로 바이트를 패치한다.
"""
import struct, sys, os
from elftools.elf.elffile import ELFFile

SRC = os.path.expanduser("~/PE/Lfuzzer/prac.elf")
OUTDIR = os.path.expanduser("~/PE/Lfuzzer/meeting_0714_step2/variants")
DT_GNU_HASH = 0x6ffffef5

def load():
    with open(SRC, "rb") as f:
        return bytearray(f.read())

def parse_offsets():
    """DT_GNU_HASH 동적엔트리의 d_ptr 파일오프셋과, .gnu.hash 섹션의 파일오프셋 반환."""
    with open(SRC, "rb") as f:
        elf = ELFFile(f)
        # .gnu.hash 섹션 file offset
        sec = elf.get_section_by_name(".gnu.hash")
        gnu_off = sec["sh_offset"]
        gnu_vaddr = sec["sh_addr"]
        # PT_DYNAMIC 안에서 DT_GNU_HASH 엔트리 위치
        dyn = None
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_DYNAMIC":
                dyn = seg
                break
        dyn_off = dyn["p_offset"]
        # 엔트리 순회: 각 엔트리 16바이트 (d_tag q, d_un Q)
        raw = load()
        i = 0
        gnuhash_dptr_off = None
        while True:
            eoff = dyn_off + i*16
            tag, val = struct.unpack_from("<qQ", raw, eoff)
            if tag == DT_GNU_HASH:
                gnuhash_dptr_off = eoff + 8   # d_un 필드
            if tag == 0:  # DT_NULL
                break
            i += 1
        return gnuhash_dptr_off, gnu_off, gnu_vaddr

def write_variant(name, mutate):
    data = load()
    mutate(data)
    path = os.path.join(OUTDIR, name)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o755)
    print(f"wrote {path}")

def main():
    dptr_off, gnu_off, gnu_vaddr = parse_offsets()
    print(f"DT_GNU_HASH d_ptr file offset = 0x{dptr_off:x}")
    print(f".gnu.hash file offset = 0x{gnu_off:x}, vaddr = 0x{gnu_vaddr:x}")

    # ---- 축1: d_ptr 손상 ----
    def set_dptr(v):
        return lambda d: struct.pack_into("<Q", d, dptr_off, v)
    write_variant("A1_dptr_zero.elf",      set_dptr(0x0))
    write_variant("A2_dptr_oob.elf",       set_dptr(0xdeadbeef000))  # 범위밖 큰 값
    write_variant("A3_dptr_strtab.elf",    set_dptr(0x480))          # 다른 유효섹션(STRTAB)

    # ---- 축2: .gnu.hash 헤더 4워드 손상 (d_ptr 정상 유지) ----
    # 헤더: [0]=nbuckets [1]=symbias [2]=maskwords(bloom nwords) [3]=shift
    def set_word(idx, v):
        return lambda d: struct.pack_into("<I", d, gnu_off + idx*4, v)
    write_variant("B1_nbuckets_zero.elf",     set_word(0, 0))          # % nbuckets -> 0으로 나눔
    write_variant("B2_maskwords_nonpow2.elf", set_word(2, 3))          # bloom nwords 비-2의거듭제곱 -> assert
    write_variant("B3_maskwords_huge.elf",    set_word(2, 0x10000000)) # 2^28 (pow2, assert통과) -> 포인터 폭주
    write_variant("B4_symbias_huge.elf",      set_word(1, 0xffffffff)) # chain_zero = hash32 - symbias 폭주

if __name__ == "__main__":
    main()
