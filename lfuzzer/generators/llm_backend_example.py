#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_backend_example.py — LLM 백엔드로 유효 ELF 시드 대량 생성 (전략1 실행 예제)

seed_builder.build_pool 에 넣을 "LLM 생성 레시피" 집합을 담았다. 원래는 LLM이
스펙(spec_extractor)을 받아 다각화된 컴파일가능 소스를 뽑는 자리인데, 여기서는
그 산출물을 정적으로 담아 재현 가능한 예제로 둔다(카탈로그 SEED_DIVERSITY_CATALOG.md
의 다양성 축 커버). 실제 LLM API 를 꽂으려면 build_pool(recipes=None,
llm_backend=<callable(prompt)->{"files","build"}>) 를 쓰면 된다.

사용(Linux, gcc/readelf 필요):
    PYTHONPATH=<repo> python3 -m lfuzzer.generators.llm_backend_example --out ~/seeds_mass
→ 46 레시피 컴파일 → readelf 검증 → DT×PT×SHT dedup → 구조고유 유효 시드풀.
(참고 실측: 46 레시피 → 18 구조고유 시드)
"""
from __future__ import annotations

import os
import sys
import argparse

from lfuzzer.generators.seed_builder import build_pool, metadata_signature

_C_MIN = "int g;\nint foo(){return g+1;}\nint bar(){return foo();}\n"


def _so(name, extra_c="", flags="", vmap=None, files=None):
    f = {"a.c": _C_MIN + extra_c}
    build = "gcc -shared -fPIC %s a.c -o libseed.so" % flags
    if vmap:
        f["v.map"] = vmap
        build = ("gcc -shared -fPIC -Wl,--version-script=v.map %s a.c -o libseed.so"
                 % flags)
    if files:
        f.update(files)
    return {"name": name, "files": f, "build": [build], "product": "libseed.so"}


def _exe(name, extra_c="", flags=""):
    return {"name": name,
            "files": {"m.c": "extern int foo();int main(){return foo();}\n" + extra_c,
                      "a.c": _C_MIN},
            "build": ["gcc -fPIC -c a.c -o a.o", "gcc %s m.c a.o -o seed_exe" % flags],
            "product": "seed_exe"}


def recipes() -> list:
    """LLM(Claude) 생성 레시피 46종 — 카탈로그 다양성 축 커버."""
    R = []
    # 1) 버저닝: verdef 1/2/3 + 체인
    R += [_so("verdef1", vmap="V1{global:foo;bar;};"),
          _so("verdef2", vmap="V1{global:foo;}; V2{global:bar;}V1;"),
          _so("verdef3", vmap="A{global:foo;}; B{global:bar;}A; C{local:*;}B;")]
    # 2) 해시 스타일
    for h in ("sysv", "gnu", "both"):
        R += [_so("hash_%s" % h, flags="-Wl,--hash-style=%s" % h)]
    # 3) TLS 4모델
    for m in ("global-dynamic", "local-dynamic", "initial-exec", "local-exec"):
        R += [_so("tls_%s" % m.replace("-", "_"),
                  "__thread int t __attribute__((tls_model(\"%s\")))=1;\nint gett(){return t;}" % m)]
    # 4) CET/property 4레벨
    for c in ("none", "branch", "return", "full"):
        R += [_so("cet_%s" % c, flags="-fcf-protection=%s" % c)]
    # 5) DF 플래그
    for z in ("now", "nodelete", "nodlopen", "origin", "global", "initfirst", "interpose"):
        R += [_so("df_%s" % z, flags="-Wl,-z,%s" % z)]
    # 6) RELRO/execstack
    R += [_so("relro_full", flags="-Wl,-z,relro,-z,now"),
          _so("relro_no", flags="-Wl,-z,norelro"),
          _so("execstack", flags="-Wl,-z,execstack"),
          _so("noexecstack", flags="-Wl,-z,noexecstack")]
    # 7) RPATH vs RUNPATH
    R += [_so("runpath", flags="-Wl,-rpath,/opt/lib,--enable-new-dtags"),
          _so("rpath", flags="-Wl,-rpath,/opt/lib,--disable-new-dtags")]
    # 8) SONAME
    R += [_so("soname", flags="-Wl,-soname,libx.so.1")]
    # 9) IFUNC
    R += [_so("ifunc", "static int impl(){return 7;}\nstatic void*res(){return impl;}\n"
                       "int fn() __attribute__((ifunc(\"res\")));")]
    # 10) 가시성/weak
    R += [_so("vis_hidden", flags="-fvisibility=hidden"),
          _so("weak", "__attribute__((weak)) int wk(){return 2;}")]
    # 11) ctor 우선순위
    R += [_so("ctor_prio", "__attribute__((constructor(101))) void c1(){}\n"
                           "__attribute__((constructor(150))) void c2(){}\n"
                           "__attribute__((destructor)) void d1(){}")]
    # 12) build-id
    for b in ("sha1", "md5", "none"):
        R += [_so("buildid_%s" % b, flags="-Wl,--build-id=%s" % b)]
    # 13) 페이지정렬/separate-code
    R += [_so("page2m", flags="-Wl,-z,max-page-size=0x200000"),
          _so("sep_code", flags="-Wl,-z,separate-code"),
          _so("nosep_code", flags="-Wl,-z,noseparate-code")]
    # 14) 압축 디버그섹션
    R += [_so("compress_zlib", flags="-g -Wl,--compress-debug-sections=zlib")]
    # 15) 커스텀 섹션 + asm 노트
    R += [_so("custom_sec", "int x __attribute__((section(\".mycustom\")))=5;")]
    R += [{"name": "asm_note",
           "files": {"a.c": _C_MIN,
                     "n.s": ".section .note.myvendor,\"a\",@note\n.align 4\n"
                            ".long 4f-3f\n.long 6f-5f\n.long 0x1234\n3:.asciz \"XYZ\"\n"
                            "4:.align 4\n5:.long 0xdeadbeef\n6:.align 4\n"},
           "build": ["gcc -shared -fPIC a.c n.s -o libseed.so"], "product": "libseed.so"}]
    # 16) 객체타입/symbolic
    R += [_exe("pie_exe", flags="-pie"), _exe("nopie_exe", flags="-no-pie"),
          _so("bsymbolic", flags="-Wl,-Bsymbolic"),
          _so("bsym_func", flags="-Wl,-Bsymbolic-functions")]
    # 17) RELR (pack-relative-relocs)
    R += [{"name": "relr",
           "files": {"m.c": "int arr[64];int main(){int s=0;for(int i=0;i<64;i++)s+=arr[i];return s;}\n"},
           "build": ["gcc -pie -fPIE -Wl,-z,pack-relative-relocs m.c -o seed_exe"],
           "product": "seed_exe"}]
    return R


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="LLM 백엔드 유효시드 대량 생성 예제")
    ap.add_argument("--out", default="seeds_mass", help="시드 출력 폴더")
    args = ap.parse_args(argv)
    R = recipes()
    print("LLM 생성 레시피: %d개" % len(R))
    seeds = build_pool(R, os.path.expanduser(args.out))
    print("=== 유효·구조고유 시드: %d개 → %s ===" % (len(seeds), args.out))
    for p in sorted(seeds):
        print("  ", os.path.basename(p), "  ", metadata_signature(p)[:80], "...")


if __name__ == "__main__":
    main()
