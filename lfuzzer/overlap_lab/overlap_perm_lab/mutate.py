#!/usr/bin/env python3
"""
mutate.py — 0508 미팅 액션 A를 위한 PHT 변형기.

목표: 데이터/텍스트/RELRO 세그먼트가 텍스트 영역을 침범하도록 PHT를 수정해서
ld.so 가 동일 가상주소 범위에 충돌하는 매핑을 적용할 때 권한 규칙
(후자 우선 / 최소 권한 / PHT 순서 / vaddr 순서)이 무엇인지 관찰 가능하게 한다.

산출물: variants/<TARGET>/V*_<label>
"""

import os, struct, sys, shutil
from elftools.elf.elffile import ELFFile

PHDR_SIZE = 56
F_TYPE, F_FLAGS, F_OFFSET, F_VADDR, F_PADDR, F_FILESZ, F_MEMSZ, F_ALIGN = \
    0, 4, 8, 16, 24, 32, 40, 48

PT_LOAD      = 1
PT_DYNAMIC   = 2
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552


def load_phdr_info(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        b = e_phoff + i * PHDR_SIZE
        rec = {
            'idx': i,
            'type':   struct.unpack_from('<I', data, b + F_TYPE)[0],
            'flags':  struct.unpack_from('<I', data, b + F_FLAGS)[0],
            'offset': struct.unpack_from('<Q', data, b + F_OFFSET)[0],
            'vaddr':  struct.unpack_from('<Q', data, b + F_VADDR)[0],
            'filesz': struct.unpack_from('<Q', data, b + F_FILESZ)[0],
            'memsz':  struct.unpack_from('<Q', data, b + F_MEMSZ)[0],
            'align':  struct.unpack_from('<Q', data, b + F_ALIGN)[0],
        }
        segs.append(rec)
    return data, e_phoff, segs


def find_load(segs, flags):
    return [s for s in segs if s['type'] == PT_LOAD and s['flags'] == flags]

def find_one(segs, t):
    for s in segs:
        if s['type'] == t:
            return s
    return None


def patch_field(data, e_phoff, seg_idx, field_off, value, size=8):
    abs_off = e_phoff + seg_idx * PHDR_SIZE + field_off
    fmt = '<Q' if size == 8 else '<I'
    struct.pack_into(fmt, data, abs_off, value)


def write_variant(target, label, data, out_dir):
    out_path = os.path.join(out_dir, label)
    with open(out_path, 'wb') as f:
        f.write(data)
    os.chmod(out_path, 0o755)
    print(f'  -> {out_path}')
    return out_path


def make_variants(target):
    raw, e_phoff, segs = load_phdr_info(target)
    out_dir = os.path.join('variants', os.path.basename(target))
    os.makedirs(out_dir, exist_ok=True)

    text  = find_load(segs, 0x5)[0]   # R-X
    rodat = find_load(segs, 0x4)
    data_ = find_load(segs, 0x6)[0]   # RW
    relro = find_one(segs, PT_GNU_RELRO)

    print(f'[{target}] text@{text["vaddr"]:#x} data@{data_["vaddr"]:#x} '
          f'relro={"-" if not relro else hex(relro["vaddr"])}')

    # V0 — baseline (no change), copy for sanity
    write_variant(target, 'V0_base', bytearray(raw), out_dir)

    # V1 — data PT_LOAD vaddr 이동: 텍스트 페이지(0x401000) 위로 침범
    # p_vaddr ≡ p_offset (mod p_align) 유지하기 위해 같은 페이지 오프셋 사용
    d = bytearray(raw)
    new_vaddr = text['vaddr'] + (data_['offset'] & (data_['align'] - 1)) # 401000 + (2df0 & 0xfff) = 401000 + 0xdf0 = 401df0
    patch_field(d, e_phoff, data_['idx'], F_VADDR, new_vaddr)
    patch_field(d, e_phoff, data_['idx'], F_PADDR, new_vaddr)
    patch_field(d, e_phoff, data_['idx'], F_FLAGS, 0x7, size=4) # RWX. size=4 명시 안 하면 인접 p_offset까지 0으로 밀어버리는 버그 있었음
    write_variant(target, 'V1_data_over_text', d, out_dir)

    # V2 — text PT_LOAD vaddr 이동: 데이터 페이지 위로 침범
    d = bytearray(raw)
    new_vaddr = data_['vaddr'] & ~(text['align'] - 1)
    patch_field(d, e_phoff, text['idx'], F_VADDR, new_vaddr | (text['offset'] & (text['align'] - 1)))
    patch_field(d, e_phoff, text['idx'], F_PADDR, new_vaddr | (text['offset'] & (text['align'] - 1)))
    write_variant(target, 'V2_text_over_data', d, out_dir)

    # V3 — text PT_LOAD memsz 확장: 텍스트가 RO+data 영역 끝까지 커버
    d = bytearray(raw)
    new_memsz = (data_['vaddr'] + data_['memsz']) - text['vaddr'] + 0x1000
    patch_field(d, e_phoff, text['idx'], F_MEMSZ, new_memsz)
    write_variant(target, 'V3_text_memsz_extend', d, out_dir)

    # V4 — PT_GNU_RELRO 를 텍스트 페이지 위로 이동
    if relro is not None:
        d = bytearray(raw)
        patch_field(d, e_phoff, relro['idx'], F_VADDR, text['vaddr'])
        patch_field(d, e_phoff, relro['idx'], F_PADDR, text['vaddr'])
        patch_field(d, e_phoff, relro['idx'], F_MEMSZ, 0x1000)
        patch_field(d, e_phoff, relro['idx'], F_FILESZ, 0x1000)
        write_variant(target, 'V4_relro_over_text', d, out_dir)

    # V5 — PHT entry swap: 텍스트와 데이터의 phdr 위치를 맞바꿔
    #       PHT 순서가 매핑 순서를 결정하는지 확인
    d = bytearray(raw)
    a = e_phoff + text['idx']  * PHDR_SIZE
    b = e_phoff + data_['idx'] * PHDR_SIZE
    A = bytes(d[a:a+PHDR_SIZE])
    B = bytes(d[b:b+PHDR_SIZE])
    d[a:a+PHDR_SIZE] = B
    d[b:b+PHDR_SIZE] = A
    write_variant(target, 'V5_phdr_swap_text_data', d, out_dir)

    # V6 — V1 + V5 결합: 데이터를 텍스트 위로 침범시키고 PHT에서 텍스트보다 먼저 등장
    d = bytearray(raw)
    new_vaddr = text['vaddr'] + (data_['offset'] & (data_['align'] - 1))
    patch_field(d, e_phoff, data_['idx'], F_VADDR, new_vaddr)
    patch_field(d, e_phoff, data_['idx'], F_PADDR, new_vaddr)
    a = e_phoff + text['idx']  * PHDR_SIZE
    b = e_phoff + data_['idx'] * PHDR_SIZE
    A = bytes(d[a:a+PHDR_SIZE])
    B = bytes(d[b:b+PHDR_SIZE])
    d[a:a+PHDR_SIZE] = B
    d[b:b+PHDR_SIZE] = A
    write_variant(target, 'V6_data_over_text_first', d, out_dir)

    # V7 — GNU_STACK 엔트리를 PT_LOAD 로 재활용해 텍스트 페이지에 RWX 오버레이.
    # 원본 LOAD 4개는 그대로 둠 → .got/.dynamic/.data 가 살아있고 entry point 코드도 보존.
    # 같은 파일 영역(text)을 같은 vaddr 에 한 번 더 매핑하되 flags 만 RWX → 권한 충돌 관찰용.
    stack = find_one(segs, PT_GNU_STACK)
    if stack is not None:
        d = bytearray(raw)
        si = stack['idx']
        patch_field(d, e_phoff, si, F_TYPE,   PT_LOAD,        size=4)
        patch_field(d, e_phoff, si, F_FLAGS,  0x7,            size=4)   # RWX
        patch_field(d, e_phoff, si, F_OFFSET, text['offset'])           # text 와 동일한 파일 영역
        patch_field(d, e_phoff, si, F_VADDR,  text['vaddr'])
        patch_field(d, e_phoff, si, F_PADDR,  text['vaddr'])
        patch_field(d, e_phoff, si, F_FILESZ, text['filesz'])
        patch_field(d, e_phoff, si, F_MEMSZ,  0x1000)
        patch_field(d, e_phoff, si, F_ALIGN,  0x1000)
        write_variant(target, 'V7_overlay_rwx_on_text', d, out_dir)

        # V8 — V7 와 동일하지만 오버레이 flags 를 R 로만 줌 (텍스트보다 *약한* 권한).
        # OR 결합이면 여전히 R+X 로 실행 가능, later-wins 면 R 만 남아 EIP fetch 시 SEGV.
        d = bytearray(raw)
        si = stack['idx']
        patch_field(d, e_phoff, si, F_TYPE,   PT_LOAD,        size=4)
        patch_field(d, e_phoff, si, F_FLAGS,  0x4,            size=4)   # R only
        patch_field(d, e_phoff, si, F_OFFSET, text['offset'])
        patch_field(d, e_phoff, si, F_VADDR,  text['vaddr'])
        patch_field(d, e_phoff, si, F_PADDR,  text['vaddr'])
        patch_field(d, e_phoff, si, F_FILESZ, text['filesz'])
        patch_field(d, e_phoff, si, F_MEMSZ,  0x1000)
        patch_field(d, e_phoff, si, F_ALIGN,  0x1000)
        write_variant(target, 'V8_overlay_r_only_on_text', d, out_dir)


def main():
    targets = sys.argv[1:] or ['target_norelro', 'target_partial', 'target_full']
    for t in targets:
        if not os.path.exists(t):
            print(f'  (skip) {t} not found')
            continue
        make_variants(t)


if __name__ == '__main__':
    main()
