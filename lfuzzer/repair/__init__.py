# -*- coding: utf-8 -*-
"""
lfuzzer.repair — 포맷유효성(format-validity) 정규화 계층.

Phase 2 ③ canonicalize repair. 구조 뮤테이션(ADD/SUB/SCRAMBLE)이 흔들어놓은
ELF64 파일을 '링커 입구 게이트를 통과해 안쪽 파서까지 도달'할 정도로만
구조 정합화한다. GATE(magic/class/phentsize/PHT 경계)는 structure_aware 의
_repair_gate_fields 소관이고, 여기 canonicalize 는 그 다음 층 —
DYNAMIC/SHDR/버전 불변식의 SEMANTIC 정규화 — 만 담당한다.

    from lfuzzer.repair import canonicalize

import 부작용은 없다: operators.ElfView 와 optional pyelftools 를 방어적으로
흡수하므로 이 패키지를 임포트해도 hard-fail 하지 않는다.
"""
from lfuzzer.repair.canonicalize import canonicalize

__all__ = ["canonicalize"]
