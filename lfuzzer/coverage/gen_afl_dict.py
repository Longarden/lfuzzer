#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_afl_dict.py — numbers.py 위험값 풀 + ELF 토큰 → AFL++ dictionary(elf.dict)

논문 §3.3.1 SUBST 의 "numbers.h 상수 사전" 을 AFL++ 가 havoc 단계에서
삽입하는 dictionary 로 변환한다. 구조인식 뮤테이터(structure_aware)가 '어디를'
칠지 안다면, 이 dict 는 '어떤 값이' 경계를 흔드는지를 havoc 에 보강한다
(RedQueen/CMPLOG 상보 — 주석은 structure_aware.py 참고).

출력 형식(AFL++ dictionary):
    name="\\x12\\x34..."      # 토큰당 한 줄, 이스케이프된 바이트열

사용:
    python3 -m lfuzzer.coverage.gen_afl_dict > elf.dict
    afl-fuzz -x elf.dict ...

포함 토큰:
    1) numbers.py POOLS(SIZE/OFFSET/ADDR/STR_IDX/MASK) 정수를 2/4/8바이트 LE 로
    2) STR_PAYLOADS 문자열(포맷스트링·경로주입·오버롱)
    3) ELF 구조 토큰: ELFMAG, PT_*, DT_*, EM_*, SHT_* 상수
순수 stdlib. I/O 는 stdout 뿐(파일 인자 주면 그리로).
"""
from __future__ import annotations

import sys
import struct

from lfuzzer.generators import numbers as N


# ELF 구조 토큰(정수) — havoc 이 의미있는 상수를 넣도록
PT_TOKENS = {
    "PT_LOAD": 1, "PT_DYNAMIC": 2, "PT_INTERP": 3, "PT_NOTE": 4,
    "PT_PHDR": 6, "PT_TLS": 7, "PT_GNU_EH_FRAME": 0x6474E550,
    "PT_GNU_STACK": 0x6474E551, "PT_GNU_RELRO": 0x6474E552,
    "PT_GNU_PROPERTY": 0x6474E553,
}
DT_TOKENS = {
    "DT_NULL": 0, "DT_NEEDED": 1, "DT_STRTAB": 5, "DT_SYMTAB": 6,
    "DT_RELA": 7, "DT_RELASZ": 8, "DT_STRSZ": 10, "DT_SYMENT": 11,
    "DT_RPATH": 15, "DT_RUNPATH": 29, "DT_FLAGS": 30,
    "DT_GNU_HASH": 0x6FFFFEF5, "DT_VERSYM": 0x6FFFFFF0,
    "DT_VERNEED": 0x6FFFFFFE, "DT_VERNEEDNUM": 0x6FFFFFFF,
    "DT_VERDEF": 0x6FFFFFFC, "DT_VERDEFNUM": 0x6FFFFFFD,
}
EM_TOKENS = {"EM_386": 3, "EM_X86_64": 62, "EM_AARCH64": 183}
SHT_TOKENS = {
    "SHT_SYMTAB": 2, "SHT_STRTAB": 3, "SHT_RELA": 4, "SHT_DYNAMIC": 6,
    "SHT_NOBITS": 8, "SHT_DYNSYM": 11, "SHT_GNU_verneed": 0x6FFFFFFE,
}


def _esc(b: bytes) -> str:
    """AFL dictionary 바이트 이스케이프( \\xNN + 출력가능문자는 그대로 )."""
    out = []
    for c in b:
        if c == 0x22:            # "
            out.append('\\"')
        elif c == 0x5C:          # backslash
            out.append("\\\\")
        elif 0x20 <= c < 0x7F:
            out.append(chr(c))
        else:
            out.append("\\x%02x" % c)
    return "".join(out)


def _int_tokens():
    """POOLS 의 정수를 2/4/8바이트 LE 로 방출(폭마다 별도 토큰)."""
    seen = set()
    for pool_name, pool in N.POOLS.items():
        for v in pool:
            for width, packer in ((2, "<H"), (4, "<I"), (8, "<Q")):
                mask = (1 << (width * 8)) - 1
                try:
                    b = struct.pack(packer, v & mask)
                except struct.error:
                    continue
                key = (b,)
                if key in seen:
                    continue
                seen.add(key)
                yield f"{pool_name.lower()}_{width}b_{v & mask:x}", b


def generate() -> list[str]:
    """dictionary 라인 리스트 생성."""
    lines = []
    lines.append("# elf.dict — lfuzzer 생성 (numbers.py POOLS + ELF 토큰)")
    lines.append('# 사용: afl-fuzz -x elf.dict ...')
    lines.append("")

    # 1) ELFMAG
    lines.append('elfmag="\\x7fELF"')

    # 2) 구조 토큰(4바이트 LE — 대부분 32비트 필드)
    for label, tbl in (("pt", PT_TOKENS), ("dt", DT_TOKENS),
                       ("em", EM_TOKENS), ("sht", SHT_TOKENS)):
        for name, val in tbl.items():
            b = struct.pack("<I", val & 0xFFFFFFFF)
            lines.append(f'{name.lower()}="{_esc(b)}"')

    # 3) numbers.py 정수 풀
    for name, b in _int_tokens():
        lines.append(f'{name}="{_esc(b)}"')

    # 4) 문자열 페이로드(포맷스트링·경로·오버롱은 상한만)
    for i, s in enumerate(N.STR_PAYLOADS):
        b = bytes(s)
        if len(b) > 128:               # AFL dict 토큰 과대 방지
            b = b[:128]
        lines.append(f'strpay_{i}="{_esc(b)}"')

    return lines


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    # 콘솔 인코딩 무관하게 UTF-8 출력(Windows cp949 에서도 안전)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa — 구버전/리다이렉트 환경 폴백
        pass
    lines = generate()
    text = "\n".join(lines) + "\n"
    if argv:
        with open(argv[0], "w", encoding="utf-8") as f:
            f.write(text)
        sys.stderr.write("elf.dict 작성: %s (%d 토큰줄)\n"
                         % (argv[0], sum(1 for l in lines if "=" in l)))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
