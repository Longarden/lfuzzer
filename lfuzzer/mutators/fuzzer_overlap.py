# fuzzer_overlap.py — 06단계: 세그먼트 겹치기(Overlap) 테스트
# 두 LOAD 세그먼트의 p_vaddr 범위가 겹치도록 조작
# ELF 스펙 미정의 영역 → ld.so / 커널의 실제 동작 확인
#
# ELF 스펙(psABI): LOAD 세그먼트들은 p_vaddr 오름차순 정렬
# 스펙은 겹침을 명시적으로 금지하지 않음
# → ld.so가 겹치는 경우를 어떻게 처리하는지 알 수 없음 ← 탐구 포인트

import struct, os, subprocess
# elf64 프리미티브는 방어적으로 가져온다(임포트 부작용/하드페일 방지). 경로에
# 없으면 None → 직접 실행(main) 때만 필요하므로 임포트 자체는 언제나 성공한다.
try:
    import elf64  # shared, behavior-exact ELF64 read primitives (single source of truth)
except Exception:  # noqa
    try:
        from lfuzzer.core import elf64
    except Exception:  # noqa
        elf64 = None

# NOTE: PHDR_SIZE is intentionally kept as a hardcoded stride (not elf64.read_phdrs,
# which strides by e_phentsize). The in-place patch()/patch_multi() write path below
# indexes phdr entries at seg_idx * PHDR_SIZE, so the read side must use the SAME
# stride to stay byte-identical. For prac.elf e_phentsize == 56, so this equals
# read_phdrs; the two only diverge on non-standard e_phentsize files, which this
# hardcoded-56 patcher was never able to handle anyway.
PHDR_SIZE = 56

def get_phdr_info(data):
    e_phoff = elf64.u64(data, 0x20)
    e_phnum = elf64.u16(data, 0x38)
    return e_phoff, e_phnum

def get_field(data, seg_idx, field_offset, field_size):
    e_phoff, _ = get_phdr_info(data)
    abs_off = e_phoff + seg_idx * PHDR_SIZE + field_offset
    read = elf64.u64 if field_size == 8 else elf64.u32
    return read(data, abs_off)

def patch(data, seg_idx, field_offset, field_size, value):
    e_phoff, _ = get_phdr_info(data)
    abs_off = e_phoff + seg_idx * PHDR_SIZE + field_offset
    patched = bytearray(data)
    fmt = "<Q" if field_size == 8 else "<I"
    struct.pack_into(fmt, patched, abs_off, value)
    return bytes(patched)

def patch_multi(data, patches):
    """여러 필드를 한 번에 패치 — patches = [(seg_idx, field_off, field_size, value), ...]"""
    e_phoff, _ = get_phdr_info(data)
    patched = bytearray(data)
    for seg_idx, field_offset, field_size, value in patches:
        abs_off = e_phoff + seg_idx * PHDR_SIZE + field_offset
        fmt = "<Q" if field_size == 8 else "<I"
        struct.pack_into(fmt, patched, abs_off, value)
    return bytes(patched)

def run(elf_bytes, label, log_path):
    tmp = "./mutated_tmp"
    with open(tmp, "wb") as f:
        f.write(elf_bytes)
    os.chmod(tmp, 0o755)
    try:
        r = subprocess.run([tmp], timeout=3,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        status = f"exit={r.returncode}"
        if r.returncode != 0:
            status += f" | {r.stderr[:120].decode(errors='replace')}"
    except subprocess.TimeoutExpired:
        status = "TIMEOUT"
    except Exception as e:
        status = f"ERROR:{e}"

    line = f"{label} | {status}\n"
    with open(log_path, "a") as f:
        f.write(line)
    print(line.strip())

    if "exit=0" not in status:
        os.makedirs("crashes_overlap", exist_ok=True)
        with open(f"crashes_overlap/{label}.elf", "wb") as f:
            f.write(elf_bytes)
    return status


def main():
    # ── 설정 ──
    INPUT = "prac.elf"
    LOG   = "overlap_log.txt"

    with open(INPUT, "rb") as f:
        original = f.read()

    e_phoff, e_phnum = get_phdr_info(original)

    # LOAD 세그먼트 전체 정보 수집
    PT_LOAD = 1
    load_segs = []
    print("LOAD 세그먼트 목록:")
    for i in range(e_phnum):
        base   = e_phoff + i * PHDR_SIZE
        p_type = elf64.u32(original, base)
        if p_type == PT_LOAD:
            vaddr  = get_field(original, i, 16, 8)
            filesz = get_field(original, i, 32, 8)
            memsz  = get_field(original, i, 40, 8)
            load_segs.append((i, vaddr, filesz, memsz))
            print(f"  seg{i}: vaddr={hex(vaddr)}  end={hex(vaddr+memsz)}  "
                  f"filesz={hex(filesz)}  memsz={hex(memsz)}")

    print(f"\nLOAD 세그먼트 {len(load_segs)}개")
    print("=" * 60)

    # ────────────────────────────────────────────────────────────
    # 테스트 1: 완전 겹침 — seg[j].vaddr = seg[i].vaddr
    # 연속된 두 LOAD의 시작 주소를 동일하게
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 1] 완전 겹침: seg[j].vaddr = seg[i].vaddr")
    for k in range(len(load_segs) - 1):
        i, v0, f0, m0 = load_segs[k]
        j, v1, f1, m1 = load_segs[k + 1]
        mutated = patch(original, j, 16, 8, v0)
        run(mutated, f"ov_full_{i}_{j}", LOG)

    # ────────────────────────────────────────────────────────────
    # 테스트 2: 부분 겹침 — seg[j].vaddr = seg[i].vaddr + memsz/2
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 2] 부분 겹침: seg[j].vaddr = seg[i].vaddr + memsz//2")
    for k in range(len(load_segs) - 1):
        i, v0, f0, m0 = load_segs[k]
        j, v1, f1, m1 = load_segs[k + 1]
        new_v = v0 + m0 // 2
        mutated = patch(original, j, 16, 8, new_v)
        run(mutated, f"ov_half_{i}_{j}", LOG)

    # ────────────────────────────────────────────────────────────
    # 테스트 3: 역순 vaddr — 연속된 두 세그먼트 주소 교환
    # 스펙: "LOAD는 vaddr 오름차순" 위반
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 3] 역순: 연속된 두 LOAD의 vaddr 교환")
    for k in range(len(load_segs) - 1):
        i, v0, f0, m0 = load_segs[k]
        j, v1, f1, m1 = load_segs[k + 1]
        mutated = patch_multi(original, [
            (i, 16, 8, v1),
            (j, 16, 8, v0),
        ])
        run(mutated, f"ov_swap_{i}_{j}", LOG)

    # ────────────────────────────────────────────────────────────
    # 테스트 4: 마지막 LOAD를 첫 번째 LOAD 주소로 이동
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 4] 마지막 LOAD → 첫 번째 LOAD 주소")
    if len(load_segs) >= 2:
        first_i, first_v, _, _ = load_segs[0]
        last_i,  last_v,  _, _ = load_segs[-1]
        mutated = patch(original, last_i, 16, 8, first_v)
        run(mutated, "ov_last_to_first", LOG)

    # ────────────────────────────────────────────────────────────
    # 테스트 5: 모든 LOAD를 동일한 vaddr로
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 5] 모든 LOAD를 seg[0].vaddr로 완전 겹침")
    if load_segs:
        base_vaddr = load_segs[0][1]
        patches = [(seg_i, 16, 8, base_vaddr) for seg_i, *_ in load_segs]
        mutated = patch_multi(original, patches)
        run(mutated, "ov_all_same", LOG)

    # ────────────────────────────────────────────────────────────
    # 테스트 6: 첫 LOAD memsz를 확장 → 다음 LOAD와 겹치도록
    # vaddr는 건드리지 않고 크기만 늘리는 방식
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 6] 첫 LOAD memsz 확장 → 다음 세그먼트 주소까지 커버")
    if len(load_segs) >= 2:
        i, v0, f0, m0 = load_segs[0]
        j, v1, f1, m1 = load_segs[1]
        # seg[0]의 끝이 seg[1]의 끝을 넘어서도록
        new_memsz = (v1 + m1) - v0 + 0x2000
        mutated = patch(original, i, 40, 8, new_memsz)
        run(mutated, "ov_memsz_cover_next", LOG)

    # ────────────────────────────────────────────────────────────
    # 테스트 7: 인접 (gap=0) — seg[j].vaddr = seg[i].vaddr + memsz
    # 겹침은 아니지만 갭 없이 딱 붙은 경우 (경계값)
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 7] 인접 배치: seg[j].vaddr = seg[i].vaddr + memsz (갭 없음)")
    for k in range(len(load_segs) - 1):
        i, v0, f0, m0 = load_segs[k]
        j, v1, f1, m1 = load_segs[k + 1]
        new_v = v0 + m0  # 딱 붙임 (페이지 정렬 무시)
        mutated = patch(original, j, 16, 8, new_v)
        run(mutated, f"ov_adjacent_{i}_{j}", LOG)

    # ────────────────────────────────────────────────────────────
    # 테스트 8: vaddr=0 (NULL 주소) 로 이동
    # ────────────────────────────────────────────────────────────
    print("\n[테스트 8] LOAD 세그먼트 vaddr=0 (NULL 주소)")
    for seg_i, v, f, m in load_segs:
        mutated = patch(original, seg_i, 16, 8, 0)
        run(mutated, f"ov_vaddr_null_seg{seg_i}", LOG)

    print(f"\n완료. 로그: {LOG} / crashes_overlap/ 폴더 확인")


if __name__ == "__main__":
    main()
