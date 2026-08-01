#!/usr/bin/env python3
"""
numbers.py — Melkor numbers.h 대응. 반쯤 유효한(semi-valid) 테스트 값 풀.

Melkor의 generators.c는 numbers.h에 박아둔 상수 배열에서 rand()로 하나를 골라
"완전 쓰레기"가 아니라 "경계에서 파서를 흔드는" 값을 돌려준다. 이 모듈이 그
상수 배열이다. generators.py가 여기서 값을 뽑는다. (I/O·난수 없음, 순수 상수.)

의도(intent)별로 그룹핑한다 — 뮤테이터가 필드의 의미에 맞는 풀을 고를 수 있게:
    SIZES    p_filesz / p_memsz / sh_size / DT_STRSZ 등 '크기' 필드
    OFFSETS  p_offset / sh_offset / e_phoff / e_shoff 등 파일 오프셋
    ADDRS    p_vaddr / p_paddr / sh_addr / DT_STRTAB 등 가상주소·포인터
    STR_IDX  sh_name / vna_name / st_name 등 문자열테이블 인덱스
    MASKS    p_flags / sh_flags / p_align 등 비트마스크·정렬

모든 값은 little-endian ELF64(x86-64) 기준. 64비트 필드에 그대로 pack 가능한
0..0xFFFFFFFFFFFFFFFF 범위. 32비트 필드에 쓸 때는 호출측이 & 0xFFFFFFFF 로 자른다
(elf64 primitive의 p32/p64 와 동일 규약).

Melkor 정신: 정수 오버플로 유발 크기, 페이지 경계, OOB 오프셋/주소,
비출력·포맷스트링 문자열 인덱스, 값이 튀는 마스크.
"""

# ===== 자주 쓰는 매직 상수 (재사용용 별칭) =====
U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF
U64_MAX = 0xFFFFFFFFFFFFFFFF
S32_MAX = 0x7FFFFFFF            # signed int 최대 (부호 뒤집힘 경계)
S32_MIN_AS_U = 0x80000000      # signed int 최소를 unsigned로 본 값
S64_MAX = 0x7FFFFFFFFFFFFFFF   # signed long 최대
PAGE = 0x1000                  # 표준 x86-64 페이지

# 눈에 띄는 마커 값 — 크래시 덤프/로그에서 '이건 퍼저가 넣은 값' 이라고 바로 보임
BAD_MARKERS = [
    0xBAD0C0DE,
    0xDEADBEEF,
    0xCAFEBABE,
    0xFEEDFACE,
    0x41414141,          # 'AAAA'
    0x4141414141414141,  # 'AAAAAAAA'
    0xDEADBEEFDEADBEEF,
]

# ===== SIZES: 크기 필드(정수 오버플로/언더플로 유발) =====
# 0/1 경계, signed 뒤집힘, all-ones, 페이지 배수, 마커.
SIZES = [
    0x0,
    0x1,
    0x2,
    0x7,
    PAGE,                # 정확히 한 페이지
    PAGE - 1,            # 페이지 경계 아래
    PAGE + 1,            # 페이지 경계 위
    0x10000,             # 64KiB
    0x100000,            # 1MiB (strsz+여유 계열)
    S32_MAX,             # 0x7fffffff — int 곱셈 오버플로 직전
    S32_MIN_AS_U,        # 0x80000000 — signed로 음수가 되는 크기
    U32_MAX,             # 0xffffffff — 32비트 all-ones
    U32_MAX - 1,
    0x100000000,         # 32비트 경계 바로 위 (u32 트렁케이션 함정)
    S64_MAX,             # 0x7fffffffffffffff
    U64_MAX,             # 0xffffffffffffffff — 64비트 all-ones
    0xBAD0C0DE,
    0xDEADBEEF,
]

# ===== OFFSETS: 파일 오프셋(파일 밖으로 나가는 OOB) =====
# 대부분 파일 크기 기준 상대값이 필요하므로 generators가 file_size를 더해 쓴다.
# 여기 값들은 '절대' 또는 '상대 델타' 두 용도로 모두 쓰인다.
OFFSETS = [
    0x0,
    0x1,
    0x40,                # ELF 헤더 끝(첫 프로그램헤더가 보통 여기)
    PAGE,
    PAGE + 0x40,
    0x1000,
    0x10000,
    0x100000,            # 파일보다 한참 뒤 (OOB read 유도)
    S32_MAX,
    S32_MIN_AS_U,
    U32_MAX,
    0x1000000000,        # 64GiB 근처 — mmap/pread 거부 경계
    S64_MAX,
    U64_MAX,
    0xFFFFFFFFFFFF,       # 48비트 all-ones (canonical addr 경계 근처)
    0xBAD0C0DE,
]

# 파일 크기에 더해서 '항상 파일 밖'을 만드는 델타 (generators.gen_offset(oob=True))
OFFSET_OOB_DELTAS = [
    0x1,
    0x40,
    PAGE,
    0x1000,
    0x100000,
    0x1000000,
]

# ===== ADDRS: 가상주소·포인터(로더가 역참조하는 값) =====
# non-canonical, null, 커널공간, all-ones 등 ld.so가 접근하면 SIGSEGV 나는 주소.
ADDRS = [
    0x0,                       # NULL 역참조
    0x1,
    0x8,
    PAGE,
    0x400000,                  # 전형적 실행 기준주소
    0x7FFFFFFFF000,            # 유저공간 상단 근처
    0x800000000000,            # non-canonical 시작 (48비트 위)
    0xFFFF800000000000,        # 커널공간(non-canonical) 하단
    0xFFFFFFFF80000000,
    S32_MAX,
    S32_MIN_AS_U,
    U32_MAX,
    S64_MAX,
    U64_MAX,                   # -1 포인터
    0xDEADBEEF,
    0xDEADBEEFDEADBEEF,
    0xBAD0C0DE,
]

# ===== STR_IDX: 문자열테이블 인덱스(strtab OOB / 포맷스트링 / 비출력) =====
# sh_name·vna_name·st_name 등이 strtab 크기를 넘어가면 strlen이 폭주하거나
# readelf/objdump가 쓰레기를 문자열로 출력한다. 정수 인덱스 풀:
STR_IDX = [
    0x0,                 # \0 (빈 문자열, 보통 유효)
    0x1,
    U16_MAX,             # 0xffff
    0x10000,
    S32_MAX,
    S32_MIN_AS_U,
    U32_MAX,             # strtab 훨씬 밖 -> OOB strlen
    0x41414141,
    0xBAD0C0DE,
]

# 문자열 '내용' 페이로드 — 인덱스가 아니라 strtab에 심을 바이트열이 필요할 때.
# 포맷스트링/비출력/오버롱 — 분석기(readelf/objdump/Ghidra)를 흔든다.
# generators.gen_str_payload()가 여기서 고른다.
STR_PAYLOADS = [
    b"%s%s%s%s%s%s%s%s",        # 포맷스트링 (naive printf 경로)
    b"%n%n%n%n",                # write 계열 포맷지시자
    b"%p%p%p%p%p%p",            # 포인터 누출
    b"%99999999d",              # 폭 지정자 폭주
    b"\x1b[31mANSI\x1b[0m",     # 터미널 이스케이프 주입
    b"\x07\x08\x0c\x0e\x7f",    # 비출력 제어문자
    b"\xff\xfe\xfd\xfc",        # 비-UTF8 바이트
    b"A" * 256,                 # 오버롱 (스택버퍼 가정 초과)
    b"A" * 4096,                # 페이지 크기 오버롱
    b"../../../../etc/passwd",  # 경로 주입 (DT_NEEDED/RPATH 흐름)
    b"\x00hidden",              # 조기 NUL (파싱 조기종료 vs 실제내용)
]

# ===== MASKS: 비트마스크·정렬(p_flags/sh_flags/p_align) =====
# 정렬은 2의 거듭제곱이어야 정상 — 비-거듭제곱/0/거대값으로 정렬 검증을 흔든다.
MASKS = [
    0x0,                 # 정렬 0 / 권한 없음
    0x1,                 # X only / align=1
    0x2,                 # W only
    0x3,                 # 비-2의거듭제곱 정렬 (검증 트리거)
    0x4,                 # R only
    0x7,                 # RWX (W^X 위반 유도)
    PAGE,                # 정상 페이지 정렬
    PAGE + 1,            # 0x1001 — 비정렬
    0x10000,
    0x200000,            # 2MiB huge page 정렬
    S32_MAX,
    U32_MAX,
    S64_MAX,
    U64_MAX,             # 전 비트 1 — 정렬로는 불가능한 값
]

# ===== 필드명 -> 의도 풀 매핑 (generators.gen_for_field 디스패처가 사용) =====
# 키는 mutator_field_v2.PH_FIELDS / mutator_dynamic_v3 및 SHDR 필드명과 맞춤.
FIELD_INTENT = {
    # --- PHT (Elf64_Phdr) ---
    "p_type":   "MASK",     # 타입은 보통 존재 타입에서 고르지만 폴백은 마스크성
    "p_flags":  "MASK",
    "p_offset": "OFFSET",
    "p_vaddr":  "ADDR",
    "p_paddr":  "ADDR",
    "p_filesz": "SIZE",
    "p_memsz":  "SIZE",
    "p_align":  "MASK",
    # --- SHDR (Elf64_Shdr) ---
    "sh_name":      "STR_IDX",
    "sh_type":      "MASK",
    "sh_flags":     "MASK",
    "sh_addr":      "ADDR",
    "sh_offset":    "OFFSET",
    "sh_size":      "SIZE",
    "sh_link":      "MASK",
    "sh_info":      "MASK",
    "sh_addralign": "MASK",
    "sh_entsize":   "SIZE",
    # --- .dynamic (Elf64_Dyn) + VERNEED 보조 필드 ---
    "d_tag":     "MASK",
    "d_un":      "ADDR",    # 대부분 포인터/주소 성격
    "DT_STRTAB": "ADDR",
    "DT_STRSZ":  "SIZE",
    "DT_SYMTAB": "ADDR",
    "DT_VERNEED":"ADDR",
    "DT_AUDIT":  "STR_IDX",
    "DT_NEEDED": "STR_IDX",
    "vna_name":  "STR_IDX",
    "vn_file":   "STR_IDX",
    "vna_next":  "OFFSET",
    "vn_next":   "OFFSET",
    "vn_cnt":    "SIZE",
    # --- ELF 헤더 파일 오프셋 ---
    "e_phoff":  "OFFSET",
    "e_shoff":  "OFFSET",
    "e_entry":  "ADDR",
}

# 의도 태그 -> 실제 풀 (generators가 참조)
POOLS = {
    "SIZE":    SIZES,
    "OFFSET":  OFFSETS,
    "ADDR":    ADDRS,
    "STR_IDX": STR_IDX,
    "MASK":    MASKS,
}


if __name__ == "__main__":
    # 풀 크기·중복 점검 데모 (순수 상수라 실행해도 부작용 없음)
    for name in ("SIZES", "OFFSETS", "ADDRS", "STR_IDX", "MASKS"):
        pool = globals()[name]
        uniq = len(set(pool))
        print(f"{name:8s} {len(pool):3d} values ({uniq} unique)"
              + ("  <-- 중복 있음" if uniq != len(pool) else ""))
    print(f"STR_PAYLOADS   {len(STR_PAYLOADS)} payloads")
    print(f"FIELD_INTENT   {len(FIELD_INTENT)} field mappings")
    print("sample SIZES  :", [hex(v) for v in SIZES[:6]])
    print("sample ADDRS  :", [hex(v) for v in ADDRS[:6]])
