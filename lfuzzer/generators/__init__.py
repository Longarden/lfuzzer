#!/usr/bin/env python3
# lfuzzer/generators/__init__.py
# Melkor의 generators.c + numbers.h 대응 계층.
#   numbers.py = 반쯤 유효한 테스트 값 풀(SIZES/OFFSETS/ADDRS/STR_IDX/MASKS)
#   generators.py = 그 풀에서 값을 뽑는 시드 가능 RNG 함수들(gen_size/gen_offset/...)
# 뮤테이터(mutator_field_v2 / mutator_dynamic_v3 등)가 하드코딩 리스트 대신
# 이 계층을 채택하면 값 소스가 한 곳으로 모인다.
from . import numbers
from .generators import (
    Generators,
    gen_size,
    gen_offset,
    gen_addr,
    gen_str_index,
    gen_mask,
    gen_for_field,
    seed as seed_global,
)

__all__ = [
    "numbers",
    "Generators",
    "gen_size",
    "gen_offset",
    "gen_addr",
    "gen_str_index",
    "gen_mask",
    "gen_for_field",
    "seed_global",
]
