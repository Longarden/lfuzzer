# mutator_field.py — ELF Program Header의 특정 필드를 변형하는 퍼저

import struct
import random
from lfuzzer import run_elf   # ELF를 실행하고 결과(정상/크래시)를 반환하는 함수
from tqdm import tqdm         # 진행률 표시용 라이브러리

PHDR_SIZE = 56  # ELF64 기준 Program Header 하나의 크기 (바이트 단위)

# ELF Program Header 내부 필드 정의
# key: 필드 이름
# value: (해당 필드의 시작 오프셋, 크기)
FIELDS = {
    "p_flags":  (4,  4),   # 권한 (읽기/쓰기/실행)
    "p_offset": (8,  8),   # 파일 내에서의 위치
    "p_vaddr":  (16, 8),   # 메모리에 로드될 주소
    "p_filesz": (32, 8),   # 파일에서 차지하는 크기
    "p_memsz":  (40, 8),   # 메모리에서 차지하는 크기
    "p_align":  (48, 8),   # 정렬 기준
}


# ELF 헤더에서 Program Header의 위치와 개수를 가져오는 함수
def get_phdr_info(data):
    # e_phoff: Program Header Table 시작 위치 (offset 0x20)
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]

    # e_phnum: Program Header 개수 (offset 0x38)
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    return e_phoff, e_phnum


# ELF의 특정 세그먼트(seg_idx)의 특정 필드(field_name)를 변형하는 함수
def mutate(data, seg_idx, field_name):
    # Program Header 위치와 개수 가져오기
    e_phoff, e_phnum = get_phdr_info(data)

    # 세그먼트 인덱스가 범위를 벗어나면 무시
    if seg_idx >= e_phnum:
        return None

    # 선택한 필드의 위치와 크기
    field_off, field_size = FIELDS[field_name]

    # 실제 파일 내 절대 위치 계산
    # = Program Header 시작 + (세그먼트 인덱스 * PHDR 크기) + 필드 오프셋
    abs_offset = e_phoff + seg_idx * PHDR_SIZE + field_off

    # 원본 데이터를 복사해서 수정할 준비
    patched = bytearray(data)

    # 데이터 크기에 따라 struct 포맷 결정 (8바이트면 Q, 4바이트면 I)
    fmt = "<Q" if field_size == 8 else "<I"

    # 현재 필드의 원래 값 읽기
    orig = struct.unpack_from(fmt, data, abs_offset)[0]

    # 해당 필드가 가질 수 있는 최대값 계산
    max_val = (1 << (field_size * 8)) - 1

    # ===== 퍼징 전략 =====
    # 80%: 기존 값 주변에서 살짝 변형 → 구조 유지 (깊은 버그 유도)
    # 20%: 완전 랜덤 값 → 구조 파괴 (엣지 케이스 탐색)

    if random.random() < 0.8:
        # 기존 값 기준으로 +- 범위 내에서 변형
        delta = random.randint(-0x3000, 0x3000)
        rand_val = orig + delta
    else:
        # 완전히 랜덤한 값 생성
        rand_val = random.randint(0, max_val)

    # 값이 범위를 벗어나지 않도록 보정
    rand_val = max(0, min(rand_val, max_val))

    # 계산된 값을 해당 위치에 덮어쓰기
    struct.pack_into(fmt, patched, abs_offset, rand_val)

    # 변형된 ELF 반환
    return bytes(patched)


# ===== 실행 설정 =====
INPUT_ELF = "prac.elf"        # 입력 ELF 파일
LOG       = "field_log.txt"   # 실행 결과 로그 파일
CRASH_DIR = "crashes_field"  # 크래시 발생 시 파일 저장 디렉토리
ROUNDS    = 50000             # 총  횟수


def main():
    # ELF 파일을 바이너리 모드로 읽기
    with open(INPUT_ELF, "rb") as f:
        original = f.read()

    # Program Header 정보 확인
    e_phoff, e_phnum = get_phdr_info(original)
    print(f"세그먼트 수: {e_phnum} / 라운드: {ROUNDS}\n")

    crash_count = 0  # 비정상 종료 횟수 카운트

    # ===== 퍼징 루프 =====
    for i in tqdm(range(ROUNDS)):
        # 랜덤으로 세그먼트 선택
        seg_idx = random.randint(0, e_phnum - 1)

        # 랜덤으로 필드 선택
        field = random.choice(list(FIELDS.keys()))

        # 테스트 케이스 이름 (로그/파일 구분용)
        label = f"field_{i:05d}_seg{seg_idx}_{field}"

        # ELF 변형 수행
        mutated = mutate(original, seg_idx, field)

        if mutated:
            # 변형된 ELF 실행
            status = run_elf(mutated, label, LOG, CRASH_DIR)

            # exit=0이 아니면 비정상 종료로 판단
            if "exit=0" not in status:
                crash_count += 1

        # 일정 간격마다 진행 상황 출력
        if i % 1000 == 0 and i != 0:
            print(f"[{i}/{ROUNDS}] crashes={crash_count}")

    # ===== 결과 출력 =====
    print("\n===== 결과 =====")
    print(f"총 실행: {ROUNDS}")
    print(f"비정상 종료: {crash_count}")
    print(f"로그: {LOG}")
    print(f"크래시 디렉토리: {CRASH_DIR}/")


# 프로그램 시작점
if __name__ == "__main__":
    main()