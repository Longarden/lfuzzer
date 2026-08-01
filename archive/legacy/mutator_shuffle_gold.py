# mutator_shuffle_gold.py — gold 링커 ELF 세그먼트 셔플링 뮤테이터
import struct, itertools, math
from tqdm import tqdm
from lfuzzer import run_elf

PHDR_SIZE = 56
PT_LOAD = 1
PT_NOTE = 4
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK    = 0x6474e551
PT_GNU_RELRO    = 0x6474e552
PT_GNU_PROPERTY = 0x6474e553

TYPE_NAMES = {
    0:"NULL", 1:"LOAD", 2:"DYNAMIC", 3:"INTERP", 4:"NOTE",
    6:"PHDR", PT_GNU_EH_FRAME:"GNU_EH_FRAME", PT_GNU_STACK:"GNU_STACK",
    PT_GNU_RELRO:"GNU_RELRO", PT_GNU_PROPERTY:"GNU_PROPERTY"
}

def get_phdr_info(data):
    e_phoff     = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum     = struct.unpack_from("<H", data, 0x38)[0]
    return e_phoff, e_phentsize, e_phnum

def get_seg_types(data):
    e_phoff, e_phentsize, e_phnum = get_phdr_info(data)
    return [
        struct.unpack_from("<I", data, e_phoff + i * e_phentsize)[0]
        for i in range(e_phnum)
    ]

def reorder_segments(data, new_order):
    e_phoff, e_phentsize, _ = get_phdr_info(data)
    headers = [
        data[e_phoff + i*e_phentsize : e_phoff + (i+1)*e_phentsize]
        for i in range(len(new_order))
    ]
    patched = bytearray(data)
    for new_pos, old_pos in enumerate(new_order):
        start = e_phoff + new_pos * e_phentsize
        patched[start:start + e_phentsize] = headers[old_pos]
    return bytes(patched)


INPUT_ELF = "prac_gold.elf"
LOG       = "shuffle_gold_log.txt"
CRASH_DIR = "crashes_gold"

with open(INPUT_ELF, "rb") as f:
    original = f.read()

e_phoff, e_phentsize, e_phnum = get_phdr_info(original)
seg_types = get_seg_types(original)

print("=== 세그먼트 목록 (gold) ===")
for i, t in enumerate(seg_types):
    print(f"  [{i}] {TYPE_NAMES.get(t, hex(t))}")

slots = []
for i, t in enumerate(seg_types):
    if t in (PT_NOTE, PT_GNU_PROPERTY, PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO):
        continue
    slots.append([i])

print(f"\n슬롯 {len(slots)}개 -> {math.factorial(len(slots)):,}가지\n")

original_order = tuple(range(len(slots)))
crash_count = 0

all_perms = [
    p for p in itertools.permutations(range(len(slots)))
    if p != original_order
]

with tqdm(
    total=len(all_perms),
    unit="case",
    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] 비정상: {postfix}"
) as pbar:

    for perm in all_perms:
        new_order = []
        for slot_idx in perm:
            new_order.extend(slots[slot_idx])
        for i, t in enumerate(seg_types):
            if t in (PT_NOTE, PT_GNU_STACK, PT_GNU_RELRO, PT_GNU_PROPERTY, PT_GNU_EH_FRAME):
                new_order.append(i)

        label = f"shuf_{'_'.join(TYPE_NAMES.get(seg_types[slots[s][0]], hex(seg_types[slots[s][0]])) for s in perm)}"
        mutated = reorder_segments(original, new_order)
        status = run_elf(mutated, label, LOG, CRASH_DIR)

        if "exit=0" not in status:
            crash_count += 1
            tqdm.write(f"  [!] {label} -> {status}")

        pbar.set_postfix_str(str(crash_count))
        pbar.update(1)

print(f"\n완료. 총: {len(all_perms):,} / 비정상: {crash_count}")
print(f"로그: {LOG} / 크래시: {CRASH_DIR}/")
