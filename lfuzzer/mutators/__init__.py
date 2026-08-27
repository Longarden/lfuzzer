# -*- coding: utf-8 -*-
"""
lfuzzer.mutators — ELF 뮤테이터 패키지.

4축 정규 연산자 레지스트리(registry)를 패키지 최상위로 re-export 한다.
import 부작용은 없다: operators 는 모든 optional 의존(pyelftools/elf64/numbers)을
방어적으로 흡수하므로 이 패키지를 임포트해도 hard-fail 하지 않는다.

    from lfuzzer.mutators import all_operators, structural_operators, get_operator
"""
from lfuzzer.mutators.registry import (
    OPERATORS,
    get_operator,
    all_operators,
    structural_operators,
)

__all__ = [
    "OPERATORS",
    "get_operator",
    "all_operators",
    "structural_operators",
]
