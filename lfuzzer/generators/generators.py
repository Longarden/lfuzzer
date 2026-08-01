#!/usr/bin/env python3
"""
generators.py — Melkor generators.c 대응. numbers.py 풀에서 값을 뽑는다.

Melkor의 generators.c는 numbers.h 배열 + rand()로 '반쯤 유효한' 테스트 값을
돌려준다. 이 모듈이 그 역할. 규약:

  - import 시점에 random 을 절대 건드리지 않는다 (전역 random.seed 오염 금지).
    자체 random.Random 인스턴스를 들고 다닌다 -> 결정적 재현 가능.
  - 시드 가능: Generators(seed=...) 또는 모듈 함수 seed(n) 으로 고정하면
    mutator_field_v2 의 --seed 재현성 요구와 같은 성질을 갖는다.
  - stdlib 전용 (import random, struct). elf64 primitive 규약과 호환:
    반환값은 0..U64_MAX 정수. 32비트 필드에 쓸 때는 호출측이 & 0xFFFFFFFF.

제공 함수 (Melkor gen_* 대응):
    gen_size()            SIZES 풀에서 하나
    gen_offset(file_size) OFFSETS 풀 (oob=True 면 file_size 밖으로 강제)
    gen_addr()            ADDRS 풀에서 하나
    gen_str_index()       STR_IDX 풀에서 하나
    gen_str_payload()     STR_PAYLOADS 에서 바이트 페이로드
    gen_mask()            MASKS 풀에서 하나
    gen_for_field(name)   필드명 -> 의도 -> 알맞은 풀 디스패처
    gen_packed(name, ...) 필드 폭에 맞춰 struct.pack 한 bytes 까지

뮤테이터가 하드코딩 리스트(예: mutator_dynamic_v3 의 big=[0xffffffff,...])를
이 함수들로 교체하면 값 소스가 numbers.py 한 곳으로 모인다.
"""

import random
import struct

from . import numbers as N


class Generators:
    """시드 가능한 값 생성기. 자체 RNG 를 들고 있어 전역 random 을 오염시키지 않는다.

    사용:
        g = Generators(seed=1234)      # 완전 재현
        g.gen_size(); g.gen_addr()
        g.gen_for_field("p_offset", file_size=len(data))
    """

    def __init__(self, seed=None):
        # seed=None 이면 random.Random 이 알아서 OS 엔트로피로 시드 (여전히 전역과 독립)
        self.rng = random.Random(seed)
        self._seed = seed

    def reseed(self, seed):
        """RNG 를 다시 시드. 같은 seed 면 이후 시퀀스가 동일하게 재현된다."""
        self.rng.seed(seed)
        self._seed = seed

    # ---- 개별 풀 게터 (Melkor gen_<type>) ----
    def gen_size(self):
        """크기 필드용 반쯤유효 값 (정수 오버플로/언더플로 경계)."""
        return self.rng.choice(N.SIZES)

    def gen_offset(self, file_size=None, oob=False):
        """파일 오프셋 값.

        oob=True 이고 file_size 가 주어지면 '항상 파일 밖'을 보장한다
        (file_size + 델타). 아니면 OFFSETS 풀에서 그냥 하나 고른다.
        """
        if oob and file_size is not None:
            return file_size + self.rng.choice(N.OFFSET_OOB_DELTAS)
        return self.rng.choice(N.OFFSETS)

    def gen_addr(self):
        """가상주소/포인터 값 (null·non-canonical·커널공간·-1 등)."""
        return self.rng.choice(N.ADDRS)

    def gen_str_index(self):
        """문자열테이블 인덱스 (strtab OOB 유도 정수)."""
        return self.rng.choice(N.STR_IDX)

    def gen_str_payload(self):
        """strtab 에 심을 바이트 페이로드 (포맷스트링/비출력/오버롱). bytes 반환."""
        return self.rng.choice(N.STR_PAYLOADS)

    def gen_mask(self):
        """비트마스크/정렬 값 (p_flags/sh_flags/p_align 등)."""
        return self.rng.choice(N.MASKS)

    def gen_marker(self):
        """눈에 띄는 마커 값 — 크래시에서 '퍼저가 넣은 값' 이라고 바로 식별."""
        return self.rng.choice(N.BAD_MARKERS)

    # ---- 디스패처 (Melkor gen_for_field 스타일) ----
    def gen_for_field(self, field_name, file_size=None):
        """필드명 -> 의도 -> 알맞은 풀. numbers.FIELD_INTENT 로 라우팅.

        모르는 필드명은 안전하게 SIZES 풀로 폴백한다 (전 필드가 크기로 오독돼도
        정수형 값이라 pack 은 항상 성공).
        """
        intent = N.FIELD_INTENT.get(field_name)
        if intent == "OFFSET":
            return self.gen_offset(file_size=file_size)
        if intent == "ADDR":
            return self.gen_addr()
        if intent == "STR_IDX":
            return self.gen_str_index()
        if intent == "MASK":
            return self.gen_mask()
        if intent == "SIZE":
            return self.gen_size()
        # 미지 필드 -> 폴백
        return self.gen_size()

    # ---- 필드 폭까지 맞춰 pack (elf64 primitive 규약과 정렬) ----
    def gen_packed(self, field_name, width, file_size=None, little_endian=True):
        """gen_for_field 값을 필드 폭(width: 2/4/8 바이트)에 맞게 struct.pack.

        width 로 마스킹(& 0xFFFF / 0xFFFFFFFF / ...)한 뒤 little-endian 으로 pack.
        elf64 의 p16/p32/p64 규약(하위 비트만 취함)과 동일하게 동작한다.
        반환: (raw_int, packed_bytes)
        """
        raw = self.gen_for_field(field_name, file_size=file_size)
        fmt = {2: "H", 4: "I", 8: "Q"}.get(width)
        if fmt is None:
            raise ValueError(f"지원하지 않는 필드 폭: {width} (2/4/8 만 가능)")
        mask = (1 << (width * 8)) - 1
        endian = "<" if little_endian else ">"
        return raw, struct.pack(endian + fmt, raw & mask)


# ===== 모듈 레벨 편의 함수 (전역 인스턴스, import 시 random 미사용) =====
# 전역 인스턴스는 seed=None (독립 RNG). 재현이 필요하면 seed(n) 을 먼저 호출.
_DEFAULT = Generators()


def seed(n):
    """모듈 레벨 편의 함수들의 RNG 를 시드. 전역 random 은 건드리지 않는다."""
    _DEFAULT.reseed(n)


def gen_size():
    return _DEFAULT.gen_size()


def gen_offset(file_size=None, oob=False):
    return _DEFAULT.gen_offset(file_size=file_size, oob=oob)


def gen_addr():
    return _DEFAULT.gen_addr()


def gen_str_index():
    return _DEFAULT.gen_str_index()


def gen_str_payload():
    return _DEFAULT.gen_str_payload()


def gen_mask():
    return _DEFAULT.gen_mask()


def gen_for_field(field_name, file_size=None):
    return _DEFAULT.gen_for_field(field_name, file_size=file_size)


def gen_packed(field_name, width, file_size=None, little_endian=True):
    return _DEFAULT.gen_packed(field_name, width, file_size=file_size,
                               little_endian=little_endian)


if __name__ == "__main__":
    # 결정적 데모: 같은 seed -> 같은 출력 (재현성 확인)
    g = Generators(seed=0xC0FFEE)
    print("== seed=0xC0FFEE, 필드별 gen_for_field 샘플 ==")
    for fld in ("p_offset", "p_vaddr", "p_filesz", "p_align",
                "sh_name", "d_un", "DT_STRSZ", "vna_name"):
        vals = [g.gen_for_field(fld, file_size=0x2000) for _ in range(3)]
        print(f"  {fld:10s} -> " + ", ".join(hex(v) for v in vals))

    print("\n== 개별 게터 샘플 ==")
    print("  gen_size   :", [hex(g.gen_size()) for _ in range(4)])
    print("  gen_offset :", [hex(g.gen_offset()) for _ in range(4)])
    print("  gen_addr   :", [hex(g.gen_addr()) for _ in range(4)])
    print("  gen_mask   :", [hex(g.gen_mask()) for _ in range(4)])
    print("  gen_offset(oob, file_size=0x2000):",
          [hex(g.gen_offset(file_size=0x2000, oob=True)) for _ in range(4)])
    print("  gen_str_payload:", g.gen_str_payload())

    print("\n== gen_packed (필드 폭 반영) ==")
    raw, packed = g.gen_packed("p_offset", 8, file_size=0x2000)
    print(f"  p_offset raw=0x{raw:x} packed={packed.hex()}")
    raw, packed = g.gen_packed("sh_name", 4)
    print(f"  sh_name  raw=0x{raw:x} packed={packed.hex()} (u32 트렁케이션 확인)")

    print("\n== 재현성: 같은 seed 두 인스턴스는 동일 시퀀스 ==")
    a = Generators(seed=42)
    b = Generators(seed=42)
    sa = [a.gen_size() for _ in range(5)]
    sb = [b.gen_size() for _ in range(5)]
    print("  a:", [hex(v) for v in sa])
    print("  b:", [hex(v) for v in sb])
    print("  동일?", sa == sb)
