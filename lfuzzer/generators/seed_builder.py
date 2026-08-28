#!/usr/bin/env python3
"""
seed_builder.py — 레시피/LLM출력 → 컴파일 → 무결성 검증 → 시드풀(dedup).

전략1 파이프라인 3단계(마지막). investigator 의 레시피(또는 LLM 백엔드가
낸 {"files","build"})를 받아 실제 gcc/ld 로 컴파일하고, readelf 로 물리·
포맷 무결성을 검증한 뒤, 메타데이터(정렬된 DT_/PT_/SHT_ 집합) 시그니처로
구조적 중복을 제거해 '다양한 유효 시드 풀' 을 만든다.

핵심 함수
    build_seed(recipe, outdir)      임시 dir 에 파일 쓰고 build 커맨드 실행,
                                    산출 ELF 를 outdir 로 이동. 실패 시 None.
    validate_seed(path)             readelf -h -d -l 로 ELF64 + PT_DYNAMIC +
                                    파싱 가능한 DYNAMIC 확인(무결성 검증).
    metadata_signature(path)        (정렬된 DT/PT/SHT 집합) 시그니처 → 세 축
                                    다양성 dedup 키.
    build_pool(recipes, outdir, llm_backend=None)
                                    레시피(또는 LLM출력) 순회 → build+validate
                                    +dedup → 유효 시드 경로 리스트.

규약
    - 절대 raise 하지 않는다(build 실패/검증 실패/도구 부재는 None/False/[]).
    - subprocess + stdlib 전용. 임포트 부작용 없음.
    - gcc/ld/readelf 는 Linux 에서만 존재 → Windows 에서는 build/validate 가
      조용히 실패(None/False)하고, 파이프라인 구조 자체는 py_compile 된다.
    - llm_backend: callable(prompt:str) -> dict{"files":..,"build":..}.
      None 이면 investigator.recipe_matrix 를 쓴다(오프라인 가능).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Dict, List, Optional

from .investigator import (
    FOCUS_AXES,
    OUT_EXE,
    OUT_SO,
    build_llm_prompt,
    recipe_matrix,
)
from .spec_extractor import extract_spec

# 산출물로 인정하는 파일명(투자자 레시피 규약과 일치)
_OUTPUT_NAMES = (OUT_SO, OUT_EXE)
# 빌드/검증 타임아웃(초) — 무한 대기 방지
_BUILD_TIMEOUT = 60
_READELF_TIMEOUT = 20

LLMBackend = Callable[[str], dict]


# ---------------------------------------------------------------------------
# 도구 탐지 (없으면 조용히 None)
# ---------------------------------------------------------------------------
def _tool(name: str) -> Optional[str]:
    """PATH 에서 도구 절대경로. 없으면 None(예외 없음)."""
    return shutil.which(name)


def _run(cmd, cwd=None, timeout=_BUILD_TIMEOUT):
    """셸 커맨드 실행. (returncode, stdout, stderr) 반환. 실패해도 예외 없음.
    cmd 는 문자열(shell=True) 또는 리스트. 도구 부재/타임아웃은 rc!=0 로."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            shell=isinstance(cmd, str),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)


# ---------------------------------------------------------------------------
# 1) build_seed
# ---------------------------------------------------------------------------
def build_seed(recipe: dict, outdir: str) -> Optional[str]:
    """레시피를 실제로 컴파일해 산출 ELF 를 outdir 로 옮긴다. 실패 시 None.

    절차:
      1. 임시 작업 dir 생성, recipe["files"] 를 그 안에 기록.
      2. recipe["build"] 커맨드를 순차 실행(하나라도 rc!=0 면 실패).
      3. libseed.so 또는 seed_exe 산출물 확인 → outdir/<name>_<recipe> 로 이동.
    """
    files = recipe.get("files") or {}
    build = recipe.get("build") or []
    if not files or not build:
        return None

    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError:
        return None

    with tempfile.TemporaryDirectory(prefix="lfuzzer_seed_") as work:
        # 1. 파일 기록
        try:
            for fname, content in files.items():
                # 경로 탈출 방지(파일명만 허용)
                safe = os.path.basename(str(fname))
                if not safe:
                    return None
                data = content if isinstance(content, (bytes, bytearray)) \
                    else str(content).encode("utf-8")
                with open(os.path.join(work, safe), "wb") as f:
                    f.write(data)
        except OSError:
            return None

        # 2. 빌드 커맨드 순차 실행
        for cmd in build:
            rc, _out, _err = _run(cmd, cwd=work, timeout=_BUILD_TIMEOUT)
            if rc != 0:
                return None

        # 3. 산출물 회수
        produced = None
        for name in _OUTPUT_NAMES:
            cand = os.path.join(work, name)
            if os.path.isfile(cand):
                produced = cand
                break
        if produced is None:
            return None

        recipe_name = re.sub(r"[^A-Za-z0-9_.-]", "_",
                             str(recipe.get("name", "seed")))
        ext = os.path.splitext(produced)[1]
        dest = os.path.join(outdir, f"{recipe_name}{ext}")
        try:
            shutil.copy2(produced, dest)
        except OSError:
            return None
        return dest


# ---------------------------------------------------------------------------
# 2) validate_seed (물리·포맷 무결성 검증)
# ---------------------------------------------------------------------------
def validate_seed(path: str) -> bool:
    """readelf -h -d -l 로 well-formed ELF64 인지 확인. 무결성 검증.

    통과 조건:
      - 파일이 ELF 매직(\\x7fELF)으로 시작하고 ELFCLASS64.
      - readelf -h 가 유효 EHDR 를 파싱.
      - readelf -l 에 프로그램 헤더(세그먼트)가 있고,
      - readelf -d 에 파싱 가능한 DYNAMIC(PT_DYNAMIC) 이 있다.
    readelf 부재/파일 부재는 False(예외 없음)."""
    if not path or not os.path.isfile(path):
        return False

    # 매직 바이트 선검사(도구 없이도 최소 판정)
    try:
        with open(path, "rb") as f:
            magic = f.read(5)
    except OSError:
        return False
    if magic[:4] != b"\x7fELF":
        return False
    if len(magic) < 5 or magic[4] != 2:   # EI_CLASS == ELFCLASS64
        return False

    readelf = _tool("readelf")
    if readelf is None:
        # Linux 도구가 없으면 무결성 '검증'을 확정할 수 없다 → 보수적으로 False.
        return False

    rc_h, out_h, _ = _run([readelf, "-h", path], timeout=_READELF_TIMEOUT)
    if rc_h != 0 or "ELF64" not in out_h:
        return False

    rc_l, out_l, _ = _run([readelf, "-l", path], timeout=_READELF_TIMEOUT)
    if rc_l != 0:
        return False
    # 세그먼트가 하나라도 있어야 하고, DYNAMIC 세그먼트 존재 확인
    if "DYNAMIC" not in out_l:
        return False

    rc_d, out_d, _ = _run([readelf, "-d", path], timeout=_READELF_TIMEOUT)
    if rc_d != 0:
        return False
    # 동적 섹션이 파싱되어 태그가 보여야 한다(빈 .dynamic 배제)
    if "Dynamic section" not in out_d and "(NULL)" not in out_d:
        return False
    return True


# ---------------------------------------------------------------------------
# 3) metadata_signature (세 축 다양성 dedup 키)
# ---------------------------------------------------------------------------
def metadata_signature(path: str) -> str:
    """시드의 (정렬된 DT_ 태그, PT_ 타입, SHT_ 섹션타입) 시그니처.

    구조적으로 구별되는 시드만 풀에 남기기 위한 dedup 키. readelf -d/-l/-S
    출력에서 DT_/PT_/SHT_ 토큰을 뽑아 정렬·중복제거해 문자열로 만든다.
    readelf 부재 시엔 파일 크기 기반 약한 시그니처로 폴백."""
    readelf = _tool("readelf")
    if readelf is None or not path or not os.path.isfile(path):
        try:
            size = os.path.getsize(path) if path and os.path.isfile(path) else 0
        except OSError:
            size = 0
        return f"nosig:size={size}"

    # 각 readelf 모드를 1회씩만 호출(중복 subprocess 제거)
    out_d = _run([readelf, "-d", path], timeout=_READELF_TIMEOUT)[1]
    out_l = _run([readelf, "-l", path], timeout=_READELF_TIMEOUT)[1]
    out_S = _run([readelf, "-S", path], timeout=_READELF_TIMEOUT)[1]

    # DT_: readelf -d 는 태그를 접두사 없이 괄호로 출력한다 — `(INIT_ARRAY)`,
    # `(STRTAB)`, `(GNU_HASH)`. 괄호 안 대문자 토큰에 DT_ 를 붙여 정규화.
    # (값 표기 `(bytes)` 는 소문자라 안 걸림)
    dt = {"DT_" + t for t in _extract_tokens(out_d, r"\(([A-Z][A-Z0-9_]*)\)")}
    dt |= _extract_tokens(out_d, r"\((DT_[A-Z0-9_]+)\)")   # 혹시 접두사 표기도
    dt |= _extract_tokens(out_d, r"\b(DT_[A-Z0-9_]+)\b")
    # PT_: 접두사 표기 + 'LOAD/DYNAMIC/GNU_STACK' 축약 표기 정규화
    pt = _extract_tokens(out_l, r"\b(PT_[A-Z0-9_]+)\b")
    pt |= _normalize_pt(out_l)
    # SHT_: 접두사 표기 + 'PROGBITS/NOBITS/DYNSYM' 축약 표기 정규화
    sht = _extract_tokens(out_S, r"\b(SHT_[A-Z0-9_]+)\b")
    sht |= _normalize_sht(out_S)

    dt_s = ",".join(sorted(dt))
    pt_s = ",".join(sorted(pt))
    sht_s = ",".join(sorted(sht))
    return f"DT[{dt_s}]|PT[{pt_s}]|SHT[{sht_s}]"


def _extract_tokens(text: str, pattern: str) -> set:
    """정규식으로 토큰 집합 추출(대소문자 그대로)."""
    if not text:
        return set()
    return set(re.findall(pattern, text))


# readelf -l 의 세그먼트 표기 → PT_* 정규화
_PT_WORDS = {
    "NULL": "PT_NULL", "LOAD": "PT_LOAD", "DYNAMIC": "PT_DYNAMIC",
    "INTERP": "PT_INTERP", "NOTE": "PT_NOTE", "SHLIB": "PT_SHLIB",
    "PHDR": "PT_PHDR", "TLS": "PT_TLS",
    "GNU_EH_FRAME": "PT_GNU_EH_FRAME", "GNU_STACK": "PT_GNU_STACK",
    "GNU_RELRO": "PT_GNU_RELRO", "GNU_PROPERTY": "PT_GNU_PROPERTY",
}
# readelf -S 의 섹션 타입 표기 → SHT_* 정규화
_SHT_WORDS = {
    "NULL": "SHT_NULL", "PROGBITS": "SHT_PROGBITS", "SYMTAB": "SHT_SYMTAB",
    "STRTAB": "SHT_STRTAB", "RELA": "SHT_RELA", "HASH": "SHT_HASH",
    "DYNAMIC": "SHT_DYNAMIC", "NOTE": "SHT_NOTE", "NOBITS": "SHT_NOBITS",
    "REL": "SHT_REL", "SHLIB": "SHT_SHLIB", "DYNSYM": "SHT_DYNSYM",
    "INIT_ARRAY": "SHT_INIT_ARRAY", "FINI_ARRAY": "SHT_FINI_ARRAY",
    "GNU_HASH": "SHT_GNU_HASH", "VERDEF": "SHT_GNU_verdef",
    "VERNEED": "SHT_GNU_verneed", "VERSYM": "SHT_GNU_versym",
}


def _normalize_pt(text: str) -> set:
    out = set()
    for word, canon in _PT_WORDS.items():
        if re.search(r"\b" + re.escape(word) + r"\b", text or ""):
            out.add(canon)
    return out


def _normalize_sht(text: str) -> set:
    out = set()
    for word, canon in _SHT_WORDS.items():
        if re.search(r"\b" + re.escape(word) + r"\b", text or ""):
            out.add(canon)
    return out


# ---------------------------------------------------------------------------
# 4) build_pool (레시피/LLM → build+validate+dedup)
# ---------------------------------------------------------------------------
def build_pool(recipes: Optional[List[dict]] = None,
               outdir: str = "seeds_llm",
               llm_backend: Optional[LLMBackend] = None,
               spec=None) -> List[str]:
    """레시피(또는 LLM 출력)로 시드풀을 만든다. 유효·구조적 고유 시드 경로 리스트.

    - llm_backend 가 주어지면 각 focus 축마다 build_llm_prompt 로 프롬프트를
      만들어 llm_backend(prompt) 를 호출, 반환 dict 를 레시피로 취급한다.
    - llm_backend 가 None 이면 recipes(없으면 recipe_matrix())를 쓴다.
    - 각 시드: build_seed → validate_seed → metadata_signature dedup.
    """
    if recipes is None:
        recipes = _gather_recipes(llm_backend, spec)

    seen_sig: Dict[str, str] = {}
    valid: List[str] = []
    for recipe in recipes:
        path = build_seed(recipe, outdir)
        if path is None:
            continue
        if not validate_seed(path):
            # 무결성 실패 시드는 폐기(파일도 정리)
            _safe_unlink(path)
            continue
        sig = metadata_signature(path)
        if sig in seen_sig:
            # 구조적 중복 → 폐기(다양성 유지)
            _safe_unlink(path)
            continue
        seen_sig[sig] = path
        valid.append(path)
    return valid


def _gather_recipes(llm_backend: Optional[LLMBackend], spec) -> List[dict]:
    """llm_backend 유무에 따라 레시피 소스를 고른다."""
    if spec is None:
        spec = extract_spec()
    if llm_backend is None:
        return recipe_matrix(spec)

    # LLM 백엔드: focus 축마다 프롬프트 → dict 레시피
    out: List[dict] = []
    for i, focus in enumerate(FOCUS_AXES):
        prompt = build_llm_prompt(spec, focus=focus)
        try:
            result = llm_backend(prompt)
        except Exception:
            continue
        if not isinstance(result, dict):
            continue
        if "files" not in result or "build" not in result:
            continue
        result.setdefault("name", f"llm_{focus}_{i}")
        result.setdefault("focus", focus)
        result.setdefault("expect", {"pt": [], "sht": [], "dt": []})
        out.append(result)
    return out


def _safe_unlink(path: str) -> None:
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    """python3 -m lfuzzer.generators.seed_builder --out seeds_llm
                 [--header /usr/include/elf.h]

    스펙 추출 → recipe_matrix 로 풀 빌드 → 유효·다양 시드 수 + 시그니처 출력.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    import argparse
    parser = argparse.ArgumentParser(
        prog="lfuzzer.generators.seed_builder",
        description="스펙-가이드 유효 ELF 시드풀 빌더(전략1 프론트엔드).")
    parser.add_argument("--out", default="seeds_llm",
                        help="시드 출력 디렉터리(기본 seeds_llm)")
    parser.add_argument("--header", default="/usr/include/elf.h",
                        help="파싱할 정본 ELF 헤더 경로")
    args = parser.parse_args(argv)

    spec = extract_spec(args.header)
    recipes = recipe_matrix(spec)

    print("=" * 72)
    print(" lfuzzer seed_builder — 유효 ELF 시드풀 빌드")
    print("=" * 72)
    print(" spec source :", spec.source)
    print(" header      :", spec.header_path)
    print(" recipes     :", len(recipes))
    print(" out dir     :", args.out)

    if _tool("gcc") is None or _tool("readelf") is None:
        print("-" * 72)
        print(" WARN: gcc/readelf 미탐지 → 실제 빌드/검증 불가(Windows 등).")
        print("       이 환경에선 파이프라인 구조만 확인된다. Linux 에서 재실행.")
        print("       탐지: gcc=%s readelf=%s" % (_tool("gcc"), _tool("readelf")))

    pool = build_pool(recipes, outdir=args.out, spec=spec)

    print("-" * 72)
    print(f" 유효·구조적 고유 시드: {len(pool)}개")
    for p in pool:
        sig = metadata_signature(p)
        print(f"   {os.path.basename(p)}")
        print(f"       sig={sig}")
    print("=" * 72)
    return 0 if pool or _tool("gcc") is None else 1


if __name__ == "__main__":
    sys.exit(main())
