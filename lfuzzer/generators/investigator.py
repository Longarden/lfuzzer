#!/usr/bin/env python3
"""
investigator.py — 스펙(ElfSpec) → LLM 프롬프트 + 결정적 빌드 레시피.

전략1 파이프라인 2단계. 추출된 스펙을 받아서, LLM 이 다양한 스펙-준수
소스코드를 생성하도록 프롬프트를 자동 조립하고, LLM 없이도 파이프라인이
돌아가도록 '결정적 빌드 레시피 매트릭스'를 만든다.

세 다양성 축 (핵심 설계)
------------------------
시드풀은 세 축으로 구조적으로 갈린다 — DT_ 태그만이 아니라:
    (1) DT_  동적 태그 조합    (SONAME/RPATH/RUNPATH/BIND_NOW/INIT_ARRAY…)
    (2) PT_  세그먼트 조합      (LOAD 권한/개수, NOTE, GNU_STACK/RELRO/
                                PROPERTY, TLS, INTERP, DYNAMIC 유무·조합)
    (3) SHT_ 섹션 조합          (NOTE, INIT/FINI_ARRAY, GNU verdef/verneed/
                                versym, GNU_HASH, RELA/REL, DYNSYM/SYMTAB,
                                NOBITS(.bss), PROGBITS 포함·배치)
각 조합은 반드시 실제 gcc/ld 로 컴파일·링크 가능한 '정공법' 으로 만든다
(링크플래그 / 링커스크립트 / gcc attribute / asm .note). 컴파일 불가한
조합은 seed_builder 가 조용히 스킵한다.

focus 축 (build_llm_prompt / recipe_matrix 가 공유하는 다양성 셀렉터)
    "verneed"       버전 의존(VERNEED/VERSYM) — --version-script + 외부 심볼
    "verdef"        버전 정의(VERDEF) — 자기 버전 노드를 export
    "many-dyn-tags" DT_ 태그를 최대한 많이 켠다(SONAME/RPATH/RELRO/NOW…)
    "extra-segments"세그먼트 다양화(NOTE/GNU_STACK/GNU_PROPERTY/RELRO…)
    "rich-sections" 섹션 다양화(커스텀 section/INIT·FINI array/NOTE…)
    "tls"           PT_TLS + SHT_TLS(.tdata/.tbss) — __thread
    "init-fini"     INIT_ARRAY/FINI_ARRAY(constructor/destructor)

레시피 형태 (seed_builder 가 그대로 소비)
    {"name": str,
     "files": {"파일명": "내용", ...},   # C/asm/버전스크립트/링커스크립트
     "build": ["gcc ...", "ld ...", ...], # 순차 실행 셸 커맨드(cc/ld)
     "focus": str,
     "expect": {"pt": [...], "sht": [...], "dt": [...]}}  # 기대 메타(문서용)

- stdlib 전용. 임포트 부작용 없음. LLM 백엔드는 seed_builder 쪽에서
  pluggable callable 로 주입(여기선 프롬프트 문자열만 만든다).
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from .spec_extractor import ElfSpec, extract_spec

# 산출물 파일명 규약(모든 레시피 공통) — seed_builder 가 이 이름으로 링크한다.
OUT_SO = "libseed.so"
OUT_EXE = "seed_exe"

# 다양성 축 목록(외부에서 순회용)
FOCUS_AXES = [
    "verneed", "verdef", "many-dyn-tags", "extra-segments",
    "rich-sections", "tls", "init-fini",
]


# ---------------------------------------------------------------------------
# LLM 프롬프트 빌더
# ---------------------------------------------------------------------------
def build_llm_prompt(spec: ElfSpec, focus: str = "many-dyn-tags") -> str:
    """ElfSpec + focus 축으로 LLM 지시 프롬프트를 조립한다.

    LLM 은 '컴파일 가능한 C(+선택 asm/버전스크립트/링커스크립트) + gcc/ld
    빌드 커맨드' 를 생성해 유효한 .so/실행파일을 만들도록 지시받는다.
    출력은 반드시 엄격한 JSON 블록:
        {"files": {"name": content, ...}, "build": ["cmd", ...]}
    """
    dt_names = [e.name for e in spec.dt_tags]
    pt_names = [e.name for e in spec.pt_types]
    sht_names = [e.name for e in spec.sht_types]

    focus_hint = _FOCUS_HINTS.get(focus, _FOCUS_HINTS["many-dyn-tags"])

    # 스펙에서 실제로 뽑힌 이름을 프롬프트에 실어 '그 시스템 값' 에 고정한다.
    dt_list = ", ".join(dt_names[:60]) if dt_names else "(스펙 비어있음)"
    pt_list = ", ".join(pt_names) if pt_names else "(스펙 비어있음)"
    sht_list = ", ".join(sht_names) if sht_names else "(스펙 비어있음)"

    return f"""역할: 너는 ELF 퍼징용 '유효 시드' 생성기다. 목표는 취약점 유발이
아니라, 스펙을 정확히 준수하면서 메타데이터가 다양한 '잘 만들어진' ELF64
파일을 만드는 것이다(benign valid-ELF 생성).

이 시스템의 ELF 스펙(정본 헤더 {spec.source} 에서 추출):
- DT_ 동적 태그({len(dt_names)}종): {dt_list}
- PT_ 세그먼트 타입: {pt_list}
- SHT_ 섹션 타입: {sht_list}

다양성 축(focus) = "{focus}":
{focus_hint}

요구사항:
1. gcc/ld 로 실제 컴파일·링크되는 C 소스를 작성한다(필요시 asm, 버전
   스크립트 .map, 링커스크립트 .ld 를 추가). 산출물은 {OUT_SO}(공유
   오브젝트) 또는 {OUT_EXE}(실행파일).
2. 위 focus 축이 요구하는 PT_ 세그먼트 / SHT_ 섹션 / DT_ 태그 조합이
   실제로 결과 ELF 에 나타나게 만든다(readelf -l -S -d 로 확인 가능해야 함).
3. 링크는 -fPIC -shared, 버전스크립트는 -Wl,--version-script=, RELRO 는
   -Wl,-z,relro,-z,now, soname 은 -Wl,-soname= 처럼 '정공법' 플래그로.
4. 절대 취약/손상된 헤더를 만들지 마라. 무결성 검증(readelf)을 통과해야 한다.

출력 형식(엄격): 아래 스키마의 JSON '한 블록만' 출력. 설명 금지.
{{"files": {{"main.c": "<C 소스>", "seed.map": "<버전스크립트>"}},
  "build": ["gcc -fPIC -shared ... -o {OUT_SO}", "..."]}}
"""


# focus 축별 LLM 힌트(프롬프트에 삽입). 세그먼트/섹션 다양성을 1급으로.
_FOCUS_HINTS: Dict[str, str] = {
    "verneed": (
        "  외부 라이브러리의 '버전 있는 심볼'을 참조해 SHT_GNU_verneed +\n"
        "  SHT_GNU_versym + DT_VERNEED/DT_VERSYM 이 생기게 하라\n"
        "  (예: libc 의 memcpy@GLIBC_2.14). readelf -V 에 Version needs 표시."
    ),
    "verdef": (
        "  --version-script 로 자기 심볼에 버전 노드를 정의해\n"
        "  SHT_GNU_verdef + DT_VERDEF/DT_VERDEFNUM 이 생기게 하라."
    ),
    "many-dyn-tags": (
        "  가능한 많은 DT_ 태그를 켜라: DT_SONAME(-soname), DT_RPATH/\n"
        "  DT_RUNPATH(-rpath/--enable-new-dtags), DT_BIND_NOW(-z now),\n"
        "  DT_FLAGS/DT_FLAGS_1(-z relro,now), DT_INIT_ARRAY/DT_FINI_ARRAY\n"
        "  (constructor/destructor), DT_NEEDED(외부 lib 링크)."
    ),
    "extra-segments": (
        "  세그먼트(PT_)를 다양화하라: PT_NOTE(asm .note 또는 --build-id),\n"
        "  PT_GNU_STACK(-z noexecstack/execstack), PT_GNU_RELRO(-z relro),\n"
        "  PT_GNU_PROPERTY(-fcf-protection), PT_TLS(__thread), 그리고\n"
        "  PT_LOAD 개수/권한(R/RW/RX) 조합을 바꿔라."
    ),
    "rich-sections": (
        "  섹션(SHT_)을 다양화하라: 커스텀 __attribute__((section(\"x\")))\n"
        "  로 SHT_PROGBITS 추가, INIT_ARRAY/FINI_ARRAY, SHT_NOTE(asm .note),\n"
        "  SHT_NOBITS(.bss 큰 배열), SHT_RELA/REL, SHT_DYNSYM."
    ),
    "tls": (
        "  __thread 변수로 PT_TLS 세그먼트 + .tdata/.tbss(SHT_PROGBITS/\n"
        "  SHT_NOBITS, SHF_TLS) 를 만들고 DT_ 에 TLS 관련 흔적을 남겨라."
    ),
    "init-fini": (
        "  __attribute__((constructor))/((destructor)) 여러 개로\n"
        "  DT_INIT_ARRAY/DT_FINI_ARRAY + SHT_INIT_ARRAY/SHT_FINI_ARRAY 를\n"
        "  채워라(우선순위 constructor(101) 등으로 개수도 늘려라)."
    ),
}


# ---------------------------------------------------------------------------
# 결정적 레시피 매트릭스 (LLM 없이도 돌아가는 정공법 빌드셋)
# ---------------------------------------------------------------------------
def recipe_matrix(spec: Optional[ElfSpec] = None) -> List[dict]:
    """LLM 없이 쓰는 결정적 빌드 레시피 집합. 세 축(DT/PT/SHT) 다양화.

    spec 은 참고용(현재는 축 존재 확인). 각 레시피는 seed_builder 가
    그대로 소비하는 {"name","files","build","focus","expect"} 딕셔너리다.
    모든 빌드는 -fPIC -shared 로 libseed.so 를 만들거나 실행파일을 만든다.
    """
    recipes: List[dict] = []
    recipes.append(_r_baseline())
    recipes.append(_r_soname_rpath())
    recipes.append(_r_relro_now())
    recipes.append(_r_noexecstack())
    recipes.append(_r_execstack())
    recipes.append(_r_build_id_note())
    recipes.append(_r_asm_note())
    recipes.append(_r_init_fini_arrays())
    recipes.append(_r_tls())
    recipes.append(_r_custom_sections())
    recipes.append(_r_bss_nobits())
    recipes.append(_r_version_script_verdef())
    recipes.append(_r_verneed_extern())
    recipes.append(_r_cf_protection())
    recipes.append(_r_multi_load_exec())
    return recipes


# ----- 개별 레시피 (정공법: 링크플래그/스크립트/attribute/asm) -----
def _base_c(body: str = "", extra_top: str = "") -> str:
    """공용 C 스켈레톤. body 는 함수 본문, extra_top 은 전역 선언."""
    return (
        "/* lfuzzer 유효시드: 스펙 준수 benign ELF. */\n"
        "#include <stddef.h>\n"
        f"{extra_top}"
        "int seed_entry(int x) {\n"
        f"{body}"
        "    return x + 1;\n"
        "}\n"
    )


def _r_baseline() -> dict:
    """최소 공유 오브젝트. PT_LOAD/PT_DYNAMIC/DT_ 기본 + SHT_DYNSYM 등."""
    return {
        "name": "baseline_so",
        "focus": "many-dyn-tags",
        "files": {"main.c": _base_c()},
        "build": [f"gcc -fPIC -shared -O0 main.c -o {OUT_SO}"],
        "expect": {"pt": ["PT_LOAD", "PT_DYNAMIC", "PT_GNU_STACK"],
                   "sht": ["SHT_DYNSYM", "SHT_DYNAMIC", "SHT_STRTAB"],
                   "dt": ["DT_HASH", "DT_STRTAB", "DT_SYMTAB"]},
    }


def _r_soname_rpath() -> dict:
    """DT_SONAME + DT_RUNPATH. -soname / -rpath + new-dtags(정공법)."""
    return {
        "name": "soname_runpath",
        "focus": "many-dyn-tags",
        "files": {"main.c": _base_c()},
        "build": [
            "gcc -fPIC -shared -O0 main.c "
            "-Wl,-soname,libseed.so.1 "
            "-Wl,--enable-new-dtags -Wl,-rpath,/opt/seedlib "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_LOAD", "PT_DYNAMIC"],
                   "sht": ["SHT_DYNAMIC"],
                   "dt": ["DT_SONAME", "DT_RUNPATH"]},
    }


def _r_relro_now() -> dict:
    """PT_GNU_RELRO + DT_BIND_NOW/DT_FLAGS. -z relro -z now."""
    return {
        "name": "relro_now",
        "focus": "extra-segments",
        "files": {"main.c": _base_c()},
        "build": [
            "gcc -fPIC -shared -O0 main.c "
            "-Wl,-z,relro -Wl,-z,now "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_GNU_RELRO"],
                   "sht": ["SHT_DYNAMIC"],
                   "dt": ["DT_BIND_NOW", "DT_FLAGS", "DT_FLAGS_1"]},
    }


def _r_noexecstack() -> dict:
    """PT_GNU_STACK(비실행). -z noexecstack."""
    return {
        "name": "noexecstack",
        "focus": "extra-segments",
        "files": {"main.c": _base_c()},
        "build": [
            "gcc -fPIC -shared -O0 main.c -Wl,-z,noexecstack "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_GNU_STACK"], "sht": [], "dt": []},
    }


def _r_execstack() -> dict:
    """PT_GNU_STACK(실행 가능 플래그). -z execstack — 세그먼트 권한 다양화."""
    return {
        "name": "execstack",
        "focus": "extra-segments",
        "files": {"main.c": _base_c()},
        "build": [
            "gcc -fPIC -shared -O0 main.c -Wl,-z,execstack "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_GNU_STACK"], "sht": [], "dt": []},
    }


def _r_build_id_note() -> dict:
    """PT_NOTE + SHT_NOTE(.note.gnu.build-id). --build-id."""
    return {
        "name": "build_id_note",
        "focus": "extra-segments",
        "files": {"main.c": _base_c()},
        "build": [
            "gcc -fPIC -shared -O0 main.c -Wl,--build-id "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_NOTE"],
                   "sht": ["SHT_NOTE"], "dt": []},
    }


def _r_asm_note() -> dict:
    """asm .note 로 커스텀 PT_NOTE/SHT_NOTE 삽입(정공법 인라인 asm)."""
    note_asm = (
        "/* 커스텀 ELF note 섹션: 이름 'LFZ', 타입 1, 페이로드 4바이트 */\n"
        ".section .note.lfuzzer, \"a\", @note\n"
        "    .align 4\n"
        "    .long 4\n"          # namesz ("LFZ\0")
        "    .long 4\n"          # descsz
        "    .long 1\n"          # type
        "    .asciz \"LFZ\"\n"
        "    .align 4\n"
        "    .long 0x5346465A\n"  # desc payload
        "    .align 4\n"
    )
    return {
        "name": "asm_custom_note",
        "focus": "rich-sections",
        "files": {"main.c": _base_c(), "note.s": note_asm},
        "build": [
            "gcc -fPIC -shared -O0 main.c note.s "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_NOTE"],
                   "sht": ["SHT_NOTE"], "dt": []},
    }


def _r_init_fini_arrays() -> dict:
    """DT_INIT_ARRAY/DT_FINI_ARRAY + SHT_INIT_ARRAY/SHT_FINI_ARRAY.
    constructor/destructor attribute(정공법)."""
    top = (
        "__attribute__((constructor(101))) static void c1(void){}\n"
        "__attribute__((constructor(102))) static void c2(void){}\n"
        "__attribute__((destructor(101)))  static void d1(void){}\n"
    )
    return {
        "name": "init_fini_arrays",
        "focus": "init-fini",
        "files": {"main.c": _base_c(extra_top=top)},
        "build": [f"gcc -fPIC -shared -O0 main.c -o {OUT_SO}"],
        "expect": {"pt": ["PT_LOAD"],
                   "sht": ["SHT_INIT_ARRAY", "SHT_FINI_ARRAY"],
                   "dt": ["DT_INIT_ARRAY", "DT_FINI_ARRAY",
                          "DT_INIT_ARRAYSZ", "DT_FINI_ARRAYSZ"]},
    }


def _r_tls() -> dict:
    """PT_TLS + .tdata/.tbss(SHF_TLS). __thread 변수(정공법)."""
    top = (
        "__thread int tls_counter = 7;\n"
        "__thread int tls_zero;\n"
    )
    body = "    tls_counter += x; tls_zero += x;\n"
    return {
        "name": "tls_segment",
        "focus": "tls",
        "files": {"main.c": _base_c(body=body, extra_top=top)},
        "build": [f"gcc -fPIC -shared -O0 main.c -o {OUT_SO}"],
        "expect": {"pt": ["PT_TLS"],
                   "sht": ["SHT_PROGBITS", "SHT_NOBITS"], "dt": []},
    }


def _r_custom_sections() -> dict:
    """커스텀 SHT_PROGBITS 섹션 여러 개. section attribute(정공법)."""
    top = (
        "__attribute__((section(\"seed_data\")))  int sd[4] = {1,2,3,4};\n"
        "__attribute__((section(\"seed_ro\")))    const int sr = 0x55;\n"
        "__attribute__((used,section(\"seed_txt\"))) static int f(void){return 9;}\n"
    )
    body = "    x += sd[0] + sr + f();\n"
    return {
        "name": "custom_sections",
        "focus": "rich-sections",
        "files": {"main.c": _base_c(body=body, extra_top=top)},
        "build": [f"gcc -fPIC -shared -O0 main.c -o {OUT_SO}"],
        "expect": {"pt": ["PT_LOAD"],
                   "sht": ["SHT_PROGBITS"], "dt": []},
    }


def _r_bss_nobits() -> dict:
    """SHT_NOBITS(.bss) 크게. 초기화 안 된 큰 배열(정공법)."""
    top = "int big_bss[4096];\n"
    body = "    big_bss[x & 4095] = x;\n"
    return {
        "name": "bss_nobits",
        "focus": "rich-sections",
        "files": {"main.c": _base_c(body=body, extra_top=top)},
        "build": [f"gcc -fPIC -shared -O0 main.c -o {OUT_SO}"],
        "expect": {"pt": ["PT_LOAD"],
                   "sht": ["SHT_NOBITS"], "dt": []},
    }


def _r_version_script_verdef() -> dict:
    """SHT_GNU_verdef + DT_VERDEF/DT_VERDEFNUM. --version-script(정공법)."""
    version_map = (
        "LFZ_1.0 {\n"
        "    global: seed_entry;\n"
        "    local: *;\n"
        "};\n"
        "LFZ_1.1 {\n"
        "    global: seed_entry_v2;\n"
        "} LFZ_1.0;\n"
    )
    top = "int seed_entry_v2(int x){ return x + 2; }\n"
    return {
        "name": "version_script_verdef",
        "focus": "verdef",
        "files": {"main.c": _base_c(extra_top=top), "seed.map": version_map},
        "build": [
            "gcc -fPIC -shared -O0 main.c "
            "-Wl,--version-script=seed.map "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_LOAD", "PT_DYNAMIC"],
                   "sht": ["SHT_GNU_verdef", "SHT_GNU_versym"],
                   "dt": ["DT_VERDEF", "DT_VERDEFNUM", "DT_VERSYM"]},
    }


def _r_verneed_extern() -> dict:
    """SHT_GNU_verneed + DT_VERNEED. 외부(libc) 버전 심볼 참조(정공법).

    printf 를 부르면 libc 의 버전 있는 심볼에 대한 VERNEED 가 생긴다.
    실행파일로 링크(-lc 자동)."""
    body = ""
    top = (
        "extern int puts(const char *);\n"
        "int main(void){ puts(\"seed\"); return 0; }\n"
    )
    # seed_entry 는 유지하되 main 을 별도 제공 → 실행파일
    c_src = (
        "/* lfuzzer 유효시드: 외부 버전 심볼 참조로 VERNEED 유발. */\n"
        f"{top}"
        "int seed_entry(int x){ return x + 1; }\n"
    )
    return {
        "name": "verneed_extern_exe",
        "focus": "verneed",
        "files": {"main.c": c_src},
        "build": [f"gcc -O0 -no-pie main.c -o {OUT_EXE}"],
        "expect": {"pt": ["PT_LOAD", "PT_DYNAMIC", "PT_INTERP"],
                   "sht": ["SHT_GNU_verneed", "SHT_GNU_versym"],
                   "dt": ["DT_VERNEED", "DT_VERNEEDNUM", "DT_VERSYM",
                          "DT_NEEDED"]},
    }


def _r_cf_protection() -> dict:
    """PT_GNU_PROPERTY + .note.gnu.property. -fcf-protection(정공법)."""
    return {
        "name": "cf_protection_property",
        "focus": "extra-segments",
        "files": {"main.c": _base_c()},
        "build": [
            "gcc -fPIC -shared -O0 -fcf-protection=full main.c "
            "-Wl,-z,relro "
            f"-o {OUT_SO}"
        ],
        "expect": {"pt": ["PT_GNU_PROPERTY", "PT_NOTE", "PT_GNU_RELRO"],
                   "sht": ["SHT_NOTE"], "dt": ["DT_FLAGS_1"]},
    }


def _r_multi_load_exec() -> dict:
    """실행파일: PT_INTERP + 여러 PT_LOAD(권한 R/RX/RW 분리). -no-pie."""
    c_src = (
        "/* lfuzzer 유효시드: 표준 실행파일(PT_INTERP + 다중 PT_LOAD). */\n"
        "#include <stddef.h>\n"
        "const char msg[] = \"lfuzzer-seed\";\n"
        "static int acc = 0;\n"
        "int compute(int x){ acc += x; return acc + (int)msg[0]; }\n"
        "int main(void){ return compute(3) & 0; }\n"
    )
    return {
        "name": "multi_load_exe",
        "focus": "extra-segments",
        "files": {"main.c": c_src},
        "build": [f"gcc -O0 -no-pie main.c -o {OUT_EXE}"],
        "expect": {"pt": ["PT_LOAD", "PT_INTERP", "PT_DYNAMIC",
                          "PT_GNU_STACK"],
                   "sht": ["SHT_PROGBITS", "SHT_NOBITS", "SHT_DYNSYM"],
                   "dt": ["DT_NEEDED", "DT_INIT"]},
    }


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    header = sys.argv[1] if len(sys.argv) > 1 else "/usr/include/elf.h"
    spec = extract_spec(header)

    print("=" * 72)
    print(" Investigator (investigator.py)")
    print("=" * 72)
    print(" spec source:", spec.source)
    recipes = recipe_matrix(spec)
    print(f" recipe_matrix: {len(recipes)}개 레시피")
    print("-" * 72)
    for r in recipes:
        pt = ",".join(r["expect"]["pt"]) or "-"
        sht = ",".join(r["expect"]["sht"]) or "-"
        dt = ",".join(r["expect"]["dt"]) or "-"
        print(f" [{r['focus']:>14}] {r['name']}")
        print(f"        files={list(r['files'])} build#{len(r['build'])}")
        print(f"        PT={pt}")
        print(f"        SHT={sht}")
        print(f"        DT={dt}")
    print("-" * 72)
    print(" build_llm_prompt 샘플 (focus=verneed) 앞 400자:")
    p = build_llm_prompt(spec, focus="verneed")
    print(p[:400])
    print("   ... (총 {} 자)".format(len(p)))
    # JSON 스키마 확인
    _ = json.dumps({"files": {"a": "b"}, "build": ["c"]})
