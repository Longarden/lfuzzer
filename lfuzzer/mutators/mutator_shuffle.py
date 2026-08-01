# mutator_shuffle.py — 세그먼트 순서 셔플링 뮤테이터 (ld / gold 겸용)
import argparse, itertools, math
from tqdm import tqdm
from lfuzzer import run_elf  # ELF 실행 및 결과 확인 함수
from elf64 import read_phdrs, u16, u64  # 공유 ELF64 PHT 파싱 프리미티브

PT_LOAD = 1         # LOAD 세그먼트 타입
PT_NOTE = 4         # NOTE 세그먼트 타입
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK    = 0x6474e551
PT_GNU_RELRO    = 0x6474e552
PT_GNU_PROPERTY = 0x6474e553

# 세그먼트 타입을 사람이 읽기 쉽게 매핑
TYPE_NAMES = {
    0:"NULL", 1:"LOAD", 2:"DYNAMIC", 3:"INTERP", 4:"NOTE",
    6:"PHDR", PT_GNU_EH_FRAME:"GNU_EH_FRAME", PT_GNU_STACK:"GNU_STACK",
    PT_GNU_RELRO:"GNU_RELRO", PT_GNU_PROPERTY:"GNU_PROPERTY"
}

# ELF 헤더에서 Program Header 관련 정보 추출 (elf64 프리미티브와 동일 오프셋)
def get_phdr_info(data):
    e_phoff     = u64(data, 0x20)  # PHDR 시작 오프셋
    e_phentsize = u16(data, 0x36)  # PHDR 하나 크기
    e_phnum     = u16(data, 0x38)  # PHDR 개수
    return e_phoff, e_phentsize, e_phnum

# 각 세그먼트의 타입 리스트 반환 (공유 elf64.read_phdrs 사용)
def get_seg_types(data):
    return [ph["p_type"] for ph in read_phdrs(data)]

# 세그먼트 순서를 new_order 기준으로 재배치
def reorder_segments(data, new_order):
    e_phoff, e_phentsize, _ = get_phdr_info(data)

    # 기존 헤더들을 리스트로 저장
    headers = [
        data[e_phoff + i*e_phentsize : e_phoff + (i+1)*e_phentsize]
        for i in range(len(new_order))
    ]

    patched = bytearray(data)

    # new_order 순서대로 헤더 재배치
    for new_pos, old_pos in enumerate(new_order):
        start = e_phoff + new_pos * e_phentsize
        patched[start:start + e_phentsize] = headers[old_pos]

    return bytes(patched)


# ===== 타겟 설정 (ld / gold) =====
# gold 뮤테이터는 입력/로그/크래시 디렉토리와 출력 라벨만 달랐던 ~95% 클론이었다.
TARGETS = {
    "ld": {
        "INPUT_ELF": "prac.elf",
        "LOG":       "shuffle_log.txt",
        "CRASH_DIR": "crashes_shuffle",
        "SEG_LABEL": "세그먼트 목록",
    },
    "gold": {
        "INPUT_ELF": "prac_gold.elf",
        "LOG":       "shuffle_gold_log.txt",
        "CRASH_DIR": "crashes_gold",
        "SEG_LABEL": "세그먼트 목록 (gold)",
    },
}

parser = argparse.ArgumentParser(description="세그먼트 순서 셔플링 뮤테이터")
parser.add_argument("--target", choices=("ld", "gold"), default="ld",
                    help="퍼징 타겟 링커 (기본: ld)")
args = parser.parse_args()

cfg       = TARGETS[args.target]
INPUT_ELF = cfg["INPUT_ELF"]   # 입력 ELF 파일
LOG       = cfg["LOG"]         # 실행 로그
CRASH_DIR = cfg["CRASH_DIR"]   # 크래시 저장 디렉토리

# ELF 파일 읽기
with open(INPUT_ELF, "rb") as f:
    original = f.read()

# PHDR 정보 및 세그먼트 타입 추출
e_phoff, e_phentsize, e_phnum = get_phdr_info(original)
seg_types = get_seg_types(original)

# ===== 세그먼트 목록 출력 =====
print(f"=== {cfg['SEG_LABEL']} ===")
for i, t in enumerate(seg_types):
    print(f"  [{i}] {TYPE_NAMES.get(t, hex(t))}")

# ===== 셔플 전략 구성 =====
slots = []       # 셔플 단위 (개별 슬롯)

for i, t in enumerate(seg_types):
    if t==PT_NOTE or t==PT_GNU_PROPERTY or t==PT_GNU_EH_FRAME or t==PT_GNU_STACK or t==PT_GNU_RELRO:
        continue
    else:
        slots.append([i])   # 개별 슬롯



print(f"\n슬롯 {len(slots)}개 -> {math.factorial(len(slots)):,}가지\n")

# 원래 순서 (변형 제외용)
original_order = tuple(range(len(slots)))

crash_count = 0

# 가능한 모든 순열 생성 (원본 순서 제외)
all_perms = [
    p for p in itertools.permutations(range(len(slots)))
    if p != original_order
]

# ===== 퍼징 시작 =====
with tqdm(
    total=len(all_perms),
    unit="case",
    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] 비정상: {postfix}"
) as pbar:

    for perm in all_perms:
        new_order = []

        # 슬롯 순서를 실제 세그먼트 인덱스로 펼침
        for slot_idx in perm:
            new_order.extend(slots[slot_idx])

        # NOTE 세그먼트는 항상 마지막에 추가
        for i, t in enumerate(seg_types):
            if t==PT_NOTE or t==PT_GNU_STACK or t==PT_GNU_RELRO or t==PT_GNU_PROPERTY or t==PT_GNU_EH_FRAME:
                new_order.append(i)

        # 테스트 케이스 이름 생성
        label = f"shuf_{'_'.join(TYPE_NAMES.get(seg_types[slots[s][0]], hex(seg_types[slots[s][0]])) for s in perm)}"

        # ELF 변형
        mutated = reorder_segments(original, new_order)

        # 실행 및 상태 확인
        status = run_elf(mutated, label, LOG, CRASH_DIR)

        # 비정상 종료 (크래시 등) 카운트
        if "exit=0" not in status:
            crash_count += 1
            tqdm.write(f"  [!] {label} -> {status}")

        # 진행 상황 업데이트
        pbar.set_postfix_str(str(crash_count))
        pbar.update(1)

# ===== 결과 출력 =====
print(f"\n완료. 총: {len(all_perms):,} / 비정상: {crash_count}")
print(f"로그: {LOG} / 크래시: {CRASH_DIR}/")
