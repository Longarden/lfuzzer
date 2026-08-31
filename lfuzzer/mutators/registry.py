#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
registry.py — 4축 정규 연산자(operators.py) 조회 레지스트리.
==============================================================================

파이프라인(structure_aware._structure_aware_mutate)이 연산자를 이름/역할로
꺼내 쓰기 위한 얇은 조회층. import 부작용 없음(operators 임포트만 하며,
operators 는 모든 optional 의존을 방어적으로 흡수하므로 hard-fail 하지 않는다).

    OPERATORS              : name -> Operator 클래스 매핑
    get_operator(name)     : 이름으로 '클래스' 반환(인스턴스화는 호출측; 파라미터
                             주입 위해 클래스를 준다. 예: SubstOp(avoid_gate=True))
    all_operators()        : 네 축 연산자 '인스턴스' 리스트(기본 파라미터)
    structural_operators() : 구조변경 축(add/sub/scramble) 인스턴스 리스트
"""
from __future__ import annotations

from typing import List

from lfuzzer.mutators.operators import (
    Operator, AddOp, SubOp, SubstOp, ScrambleOp,
)

# name -> 클래스 (논문 4축)
OPERATORS = {
    "add": AddOp,
    "sub": SubOp,
    "subst": SubstOp,
    "scramble": ScrambleOp,
}

# 구조를 바꾸는(엔트리 추가/삭제/재배치) 축 — SUBST(값치환)는 제외
_STRUCTURAL_NAMES = ("add", "sub", "scramble")


def get_operator(name: str):
    """이름으로 연산자 '클래스'를 반환. 미등록이면 KeyError.

    클래스를 돌려주는 이유: SubstOp(avoid_gate=True) 처럼 호출측이 파라미터를
    주입해 인스턴스화할 수 있게 하기 위함(파이프라인이 avoid_gate 를 켠다)."""
    return OPERATORS[name]


def all_operators() -> List[Operator]:
    """네 축 연산자의 기본 파라미터 인스턴스 리스트."""
    return [OPERATORS[n]() for n in ("add", "sub", "subst", "scramble")]


def structural_operators() -> List[Operator]:
    """구조변경 축(add/sub/scramble) 인스턴스 리스트."""
    return [OPERATORS[n]() for n in _STRUCTURAL_NAMES]
