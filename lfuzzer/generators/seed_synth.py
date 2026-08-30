#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
seed_synth.py — 전략1: helloworld 시드 합성기(메타데이터 다양성).
==============================================================================
논문 §3.2 "명세 추출 + 규격만족 컴파일가능 소스 생성" 의 구현.

각 시드는:
  · 정상 실행 시 "hello world <id>" 출력 (baseline 깨끗 = 크래시 0),
  · 특정 ELF 메타데이터 피처(섹션/세그먼트/DT태그/심볼/재배치)를 유발하도록
    소스조각 + 컴파일/링크 플래그를 조합.
시드풀 전체가 뮤테이터(operators)가 건드리는 모든 리전/태그를 포함하도록 피처를
랜덤 조합한다 → 4축 뮤테이션 대상이 시드에 실제로 존재.

피처 → 유발 메타데이터:
  tls          PT_TLS/.tdata/TPOFF/DT_FLAGS      __thread
  verneed      DT_VERNEED/VERSYM/.gnu.version_r  버전심볼(GLIBC_2.x)
  buildid      PT_NOTE/.note.gnu.build-id        -Wl,--build-id=sha1
  property     PT_GNU_PROPERTY/.note.gnu.property -fcf-protection=full
  relro_now    PT_GNU_RELRO/DT_BIND_NOW/FLAGS_1  -Wl,-z,relro,-z,now
  soname       DT_SONAME                         -Wl,-soname
  runpath      DT_RUNPATH                        -Wl,--enable-new-dtags,-rpath
  ifunc        IRELATIVE/DT_RELACOUNT            __attribute__((ifunc))
  initfini     DT_INIT/FINI/INIT_ARRAY           constructor/destructor
  hashboth     DT_HASH + DT_GNU_HASH             -Wl,--hash-style=both
  libs         다중 DT_NEEDED                     -lm/-lpthread/-ldl
  eh           PT_GNU_EH_FRAME/.eh_frame         -fexceptions
  manysyms     큰 symtab/hidden/weak             함수 다수 + visibility

빌드(실험별 링커):
  bfd:  gcc -fPIE -pie [flags] src.c [libs]
  gold: gcc -fPIE -pie -fuse-ld=gold [flags] src.c [libs]
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass, field
from typing import List

_HDRS = {"m": "#include <math.h>", "pthread": "#include <pthread.h>",
         "dl": "#include <dlfcn.h>"}


@dataclass
class Synth:
    idx: int
    headers: List[str] = field(default_factory=lambda: ["#include <stdio.h>"])
    globals: List[str] = field(default_factory=list)
    funcs: List[str] = field(default_factory=list)
    pre_main: List[str] = field(default_factory=list)   # 전역 스코프 조각
    main_body: List[str] = field(default_factory=list)
    cflags: List[str] = field(default_factory=list)
    lflags: List[str] = field(default_factory=list)      # -Wl,... 등
    libs: List[str] = field(default_factory=list)         # m/pthread/dl
    features: List[str] = field(default_factory=list)

    def source(self) -> str:
        L = list(dict.fromkeys(self.headers))            # 중복 헤더 제거(순서보존)
        L.append("")
        L.append("int g0 = 1;")
        L += self.globals
        L += self.pre_main
        L += self.funcs
        L.append("")
        L.append("int main(void) {")
        L.append(f'    printf("hello world {self.idx}\\n");')
        L += ["    " + b for b in self.main_body]
        L.append("    return 0;")
        L.append("}")
        return "\n".join(L) + "\n"


# ── 피처 적용기: Synth 를 변형해 특정 메타데이터를 유발 ──
def _f_tls(s, r):
    for t in range(r.randint(1, 3)):
        s.globals.append(f"__thread int tl{t} = {r.randint(1,9)};")
    s.main_body.append("{ extern __thread int tl0; volatile int _t = tl0; (void)_t; }")


def _f_verneed(s, r):
    # 버전 심볼(예: memcpy@GLIBC / powf@GLIBC_2.27) → verneed/versym
    s.headers.append("#include <string.h>")
    s.main_body.append('{ char a[8],b[8]="hi"; memcpy(a,b,3); volatile int _=a[0]; (void)_; }')


def _f_buildid(s, r):
    s.lflags.append("-Wl,--build-id=sha1")


def _f_property(s, r):
    s.cflags.append("-fcf-protection=full")


def _f_relro_now(s, r):
    s.lflags += ["-Wl,-z,relro", "-Wl,-z,now"]


def _f_soname(s, r):
    s.lflags.append(f"-Wl,-soname,lib{s.idx}.so")


def _f_runpath(s, r):
    s.lflags += ["-Wl,--enable-new-dtags", "-Wl,-rpath,/opt/x"]


def _f_ifunc(s, r):
    s.pre_main += [
        "static int impl_a(void){ return 1; }",
        "static void* resolver(void){ return (void*)impl_a; }",
        "int myfn(void) __attribute__((ifunc(\"resolver\")));",
    ]
    s.main_body.append("{ volatile int _i = myfn(); (void)_i; }")


def _f_initfini(s, r):
    s.pre_main += [
        "__attribute__((constructor)) static void _ci(void){ g0 += 1; }",
        "__attribute__((destructor)) static void _cd(void){ g0 -= 1; }",
    ]


def _f_hashboth(s, r):
    s.lflags.append("-Wl,--hash-style=both")


def _f_libs(s, r):
    for l in r.sample(["m", "pthread", "dl"], r.randint(1, 3)):
        s.libs.append(l)
        s.headers.append(_HDRS[l])
        if l == "m":
            s.main_body.append("{ volatile double _d = sqrt(3.0); (void)_d; }")
        elif l == "pthread":
            s.main_body.append("{ volatile unsigned long _p=(unsigned long)pthread_self(); (void)_p; }")
        elif l == "dl":
            s.main_body.append('{ void*_h=dlopen("libc.so.6",1); (void)_h; }')


def _f_eh(s, r):
    s.cflags.append("-fexceptions")


def _f_manysyms(s, r):
    hidden = r.random() < 0.5
    for fn in range(r.randint(3, 10)):
        vis = "__attribute__((visibility(\"hidden\"))) " if (hidden and fn % 2 == 0) else ""
        wk = "__attribute__((weak)) " if (fn % 3 == 0) else ""
        s.funcs.append(f"{wk}{vis}int fx{fn}(int a){{ return a+g0+{r.randint(1,50)}; }}")
    s.main_body.append("{ volatile int _m = fx0(g0); (void)_m; }")


_FEATURES = {
    "tls": _f_tls, "verneed": _f_verneed, "buildid": _f_buildid,
    "property": _f_property, "relro_now": _f_relro_now, "soname": _f_soname,
    "runpath": _f_runpath, "ifunc": _f_ifunc, "initfini": _f_initfini,
    "hashboth": _f_hashboth, "libs": _f_libs, "eh": _f_eh, "manysyms": _f_manysyms,
}
FEATURE_NAMES = list(_FEATURES)


def synth(idx: int) -> Synth:
    """시드 idx 를 위한 Synth 생성 — 피처 랜덤부분집합(항상 1개 이상)으로 메타 다양화."""
    r = random.Random(idx * 100003 + 7)
    s = Synth(idx=idx)
    k = r.randint(2, 6)                                # 시드당 피처 2~6개
    chosen = r.sample(FEATURE_NAMES, min(k, len(FEATURE_NAMES)))
    for name in chosen:
        try:
            _FEATURES[name](s, r)
            s.features.append(name)
        except Exception:
            pass
    return s


def build_cmd(s: Synth, src_path: str, out_path: str, linker: str) -> list:
    """실험별 링커로 빌드 명령(리스트). linker ∈ {'bfd','gold'}."""
    cmd = ["gcc", "-fPIE", "-pie", "-O0"]
    if linker == "gold":
        cmd.append("-fuse-ld=gold")
    cmd += s.cflags + s.lflags + [src_path]
    for l in dict.fromkeys(s.libs):
        cmd.append("-l" + l)
    cmd += ["-o", out_path]
    return cmd


def generate(n: int, src_dir: str):
    """n 개 소스 + 빌드메타 생성. 반환: [(name, Synth)]."""
    os.makedirs(src_dir, exist_ok=True)
    for f in os.listdir(src_dir):
        if f.endswith(".c"):
            os.remove(os.path.join(src_dir, f))
    out = []
    for i in range(n):
        s = synth(i)
        name = "s%04d" % i
        open(os.path.join(src_dir, name + ".c"), "w").write(s.source())
        out.append((name, s))
    return out


if __name__ == "__main__":
    # 자가확인: 3개 합성 후 소스/빌드명령 출력
    import sys
    for i in range(3):
        s = synth(i)
        print("=== seed %d features=%s ===" % (i, s.features))
        print("cflags=%s lflags=%s libs=%s" % (s.cflags, s.lflags, s.libs))
        print(s.source())
