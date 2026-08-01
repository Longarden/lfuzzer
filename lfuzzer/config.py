#!/usr/bin/env python3
"""
lfuzzer/config.py — Lfuzzer 전 스크립트가 공유하는 '경로 해석' 단일 소스.

왜 존재하나 (migration target)
------------------------------
지금까지 BFD/GOLD/Ghidra/loader/repo-root 경로는 각 스크립트에
하드코딩돼 있었다. 대표 사례가 exp_goldbfd_diff/common.py:

    BFD  = next((p for p in [
        f"{HOME}/binutils-build-afl-bfd-clean/ld/ld-new",
        "/usr/bin/ld", "/usr/bin/ld.bfd"] if os.path.exists(p)), None)
    GOLD = next((p for p in [
        f"{HOME}/binutils-build-gold/gold/ld-new",
        "/usr/bin/ld.gold", "/usr/bin/gold"] if os.path.exists(p)), None)

이 모듈은 그 '첫 번째로 존재하는 후보' 규칙을 그대로 유지하되,
맨 앞에 환경변수 오버라이드 한 단을 더한 것이다. 즉 우선순위는:

    (1) 환경변수 (LFUZZER_BFD / LFUZZER_GOLD / LFUZZER_GHIDRA /
        LFUZZER_LOADER / LFUZZER_REPO_ROOT)
    (2) 알려진 빌드 경로 (~/binutils-build-* 등)
    (3) 시스템 폴백 (/usr/bin/ld, /usr/bin/ld.gold, PATH 조회 …)

환경변수로 준 값은 '명시적 의도'이므로 존재 검사에 실패해도 그대로
채택하고 print_config() 에서 경고만 낸다 — 오타를 숨겨 조용히 엉뚱한
시스템 바이너리로 폴백하는 사고를 막기 위함.

stdlib 전용(os, shutil, pathlib). 임포트 부작용 없음(경로 해석은 순수 계산).

사용법
------
    from lfuzzer import config
    print(config.BFD, config.GOLD, config.GHIDRA, config.LOADER, config.REPO_ROOT)

    # 진단:
    python -m lfuzzer.config        # print_config() 실행
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import List, Optional

HOME = Path.home()


# ---------------------------------------------------------------------------
# 해석 프리미티브
# ---------------------------------------------------------------------------
def _first_existing(candidates: List[str]) -> Optional[str]:
    """후보 경로들 중 실제로 존재하는 첫 번째를 절대경로로 반환. 없으면 None.
    common.py 의 next((p for p in [...] if os.path.exists(p)), None) 규칙과 동일."""
    for c in candidates:
        if not c:
            continue
        p = Path(c).expanduser()
        if p.exists():
            return str(p.resolve())
    return None


def which(name: str) -> Optional[str]:
    """which(1) 스타일 존재 검사. PATH 에서 실행파일을 찾아 절대경로 반환(없으면 None).
    절대/상대 경로가 통째로 들어오면 그 경로 자체의 실행가능 여부로 판정한다."""
    return shutil.which(name)


def _resolve(env_var: str, build_paths: List[str],
             fallbacks: List[str]) -> Optional[str]:
    """공통 해석기: (1) 환경변수 → (2) 빌드 경로 → (3) 시스템 폴백.

    - 환경변수가 세팅돼 있으면 그 값을 무조건 채택한다(존재하지 않아도).
      환경변수는 사용자의 '명시적 의도'라 조용한 폴백보다 명시적 경고가 옳다.
      단, 값 앞뒤 공백은 제거하고 ~ 는 확장한다.
    - 그 외에는 build_paths + fallbacks 를 순서대로 훑어 첫 존재 경로 채택.
    - fallbacks 항목이 '/' 를 포함하지 않으면 PATH 조회(which)로 취급한다.
    """
    raw = os.environ.get(env_var)
    if raw and raw.strip():
        return str(Path(raw.strip()).expanduser())

    # 폴백 후보를 절대/상대 경로와 'PATH 이름'으로 분리 처리
    expanded_fallbacks: List[str] = []
    for fb in fallbacks:
        if "/" in fb or os.sep in fb:
            expanded_fallbacks.append(fb)
        else:
            hit = which(fb)
            if hit:
                expanded_fallbacks.append(hit)
    return _first_existing(build_paths + expanded_fallbacks)


# ---------------------------------------------------------------------------
# 각 경로의 후보 정의 (여기가 '알려진 빌드 경로'의 단일 소스)
# ---------------------------------------------------------------------------
_BFD_BUILD = [
    str(HOME / "binutils-build-afl-bfd-clean" / "ld" / "ld-new"),
]
_BFD_FALLBACK = ["/usr/bin/ld", "/usr/bin/ld.bfd", "ld.bfd", "ld"]

_GOLD_BUILD = [
    str(HOME / "binutils-build-gold" / "gold" / "ld-new"),
]
_GOLD_FALLBACK = ["/usr/bin/ld.gold", "/usr/bin/gold", "ld.gold", "gold"]

_GHIDRA_BUILD = [
    str(HOME / "ghidra_12.1.2_PUBLIC"),
]
_GHIDRA_FALLBACK = ["/opt/ghidra", "/usr/local/ghidra"]

_LOADER_BUILD = [
    "/lib64/ld-linux-x86-64.so.2",
]
_LOADER_FALLBACK = ["/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"]


def _resolve_repo_root() -> str:
    """REPO_ROOT: (1) LFUZZER_REPO_ROOT → (2) 이 파일 기준 패키지 부모 →
    (3) ~/PE/Lfuzzer(레거시) → (4) cwd. 항상 문자열을 반환(None 아님)."""
    raw = os.environ.get("LFUZZER_REPO_ROOT")
    if raw and raw.strip():
        return str(Path(raw.strip()).expanduser())
    # 이 파일: <repo>/lfuzzer/config.py → parents[1] == <repo>
    here = Path(__file__).resolve()
    pkg_parent = here.parents[1] if len(here.parents) >= 2 else here.parent
    if (pkg_parent / "lfuzzer").is_dir():
        return str(pkg_parent)
    legacy = HOME / "PE" / "Lfuzzer"
    if legacy.exists():
        return str(legacy)
    return str(Path.cwd())


# ---------------------------------------------------------------------------
# 해석된 값 (임포트 시 1회 계산; 부작용 없음)
# ---------------------------------------------------------------------------
BFD: Optional[str]       = _resolve("LFUZZER_BFD",    _BFD_BUILD,    _BFD_FALLBACK)
GOLD: Optional[str]      = _resolve("LFUZZER_GOLD",   _GOLD_BUILD,   _GOLD_FALLBACK)
GHIDRA: Optional[str]    = _resolve("LFUZZER_GHIDRA", _GHIDRA_BUILD, _GHIDRA_FALLBACK)
LOADER: Optional[str]    = _resolve("LFUZZER_LOADER", _LOADER_BUILD, _LOADER_FALLBACK)
REPO_ROOT: str           = _resolve_repo_root()


# print_config() 가 순회할 메타데이터 테이블
_ENTRIES = [
    # (이름, 값, 환경변수, 필수여부, 없을 때 깨지는 것)
    ("BFD",       BFD,       "LFUZZER_BFD",       True,
     "gold-vs-BFD differential (exp_goldbfd_diff/*, exp_d*/exp_r*) 링크 단계"),
    ("GOLD",      GOLD,      "LFUZZER_GOLD",      True,
     "gold-vs-BFD differential 의 GOLD 링커 측 실행"),
    ("GHIDRA",    GHIDRA,    "LFUZZER_GHIDRA",    False,
     "Ghidra 분석기 차등(DumpDynamic.java 등 headless 분석). Java 21 필요"),
    ("LOADER",    LOADER,    "LFUZZER_LOADER",    True,
     "ld.so 런타임 로더 실험(직접 ./ld-linux ... 실행, dl-load 재현)"),
    ("REPO_ROOT", REPO_ROOT, "LFUZZER_REPO_ROOT", True,
     "seed/templates/out 경로 계산의 기준점"),
]


def _exists(value: Optional[str]) -> bool:
    return bool(value) and Path(value).expanduser().exists()


def print_config() -> int:
    """해석 결과를 사람이 읽게 출력하고 누락을 경고한다.
    반환값: 존재하지 않는 '필수' 경로 개수(0 이면 정상). CI 게이트로 쓸 수 있게 정수 반환."""
    print("=" * 72)
    print(" Lfuzzer 경로 설정 (config.py)")
    print("=" * 72)
    missing_required = 0
    for name, value, env_var, required, breaks in _ENTRIES:
        ok = _exists(value)
        src = "ENV" if os.environ.get(env_var, "").strip() else "auto"
        mark = "OK " if ok else ("MISSING" if required else "absent ")
        tag = "(필수)" if required else "(선택)"
        print(f"  [{mark:>7}] {name:<10} {tag}")
        print(f"            value    = {value if value else '<해석 실패>'}")
        print(f"            source   = {src}   (override: {env_var})")
        if not ok:
            print(f"            !! 경로 없음 → 깨지는 것: {breaks}")
            if src == "ENV":
                print(f"            !! {env_var} 로 준 경로가 실제로 존재하지 않음(오타 의심)")
            if required:
                missing_required += 1
    print("-" * 72)
    if missing_required:
        print(f" 결과: 필수 경로 {missing_required}개 누락 → 해당 실험은 실패한다.")
        print(" 조치: 위 override 환경변수로 실제 경로를 지정하거나 빌드하라.")
    else:
        print(" 결과: 필수 경로 모두 해석됨.")
    print("=" * 72)
    return missing_required


if __name__ == "__main__":
    import sys
    sys.exit(1 if print_config() else 0)
