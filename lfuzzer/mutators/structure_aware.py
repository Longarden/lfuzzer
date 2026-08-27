#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
structure_aware.py — V2 구조인식 뮤테이터 (AFL++ custom-mutator API 인터페이스)
==============================================================================

역할 (PIPELINE_VARIANTS.md V2)
------------------------------
AFL++ 가 로드하는 **파이썬 custom mutator** 로서, ELF 를 "바이트 뭉치"가 아니라
"구조체 문법(Ehdr → PHT → DYNAMIC → Verneed …)"으로 다루면서, 동시에
**유효성 그라디언트(validity gradient)** 를 제어한다.

핵심 아이디어 — 유효성 그라디언트
--------------------------------
너무 망가진 입력은 로더/링커의 **입구 검증(gate)** 에서 즉시 거부되어 깊은
코드경로에 도달하지 못한다. 반대로 완벽히 유효한 입력만 만들면 파서 버그를
못 건드린다. 그래서 두 층을 나눈다:

    GATE 필드   (반드시 복구):  ELF magic, EI_CLASS, e_machine, PHT 경계
                 └ 안 고치면 파일이 ELF 로 인식조차 안 됨 → 즉시 사망, 낭비.
    SEMANTIC 필드 (낮은 p_repair 로 선택 복구):
                 DT_STRSZ vs strtab 끝, p_filesz/p_memsz, sh_link, versym idx …
                 └ 일부러 불일치를 **살려둬서** 파서 안쪽 무검증 순회를 때린다.

    validity ▁▂▃▄▅▆▇█   ← GATE 는 항상 █(유효),  SEMANTIC 은 p_repair 로 조절

근거 문헌 (SOTA 대조군)
-----------------------
  AFLSmart (Pham et al., IEEE TSE 2019)
      "smart greybox fuzzing" — 입력을 가상 구조(virtual structure)로 파싱해
      chunk 단위 변형 + validity-preserving 연산. 본 모듈의 구조인식 골격이 대응.
  FormatFuzzer (Dutra, Gopinath, Zeller, ACM TOSEM 2024)
      바이너리 포맷 문법에서 고속 생성/파싱기를 뽑아 유효성 높은 입력 생성.
      우리의 grammar/field-aware core(_structure_aware_mutate) 의 지향점.
  RedQueen (Aschermann et al., NDSS 2019)
      입력↔비교 피연산자의 대응(input-to-state)을 추론해 magic/checksum 통과.
      → AFL++ 에서는 **CMPLOG** 로 구현됨. 아래 "상보 기법" 참고.

상보 기법 (이 뮤테이터와 함께 켤 것 — 대체가 아니라 보완)
--------------------------------------------------------
  CMPLOG (AFL++ -c) : DT_STRSZ, e_machine, vn_version 같은 매직/비교상수를
      런타임 비교로그로 풀어 통과시킨다. 구조인식이 "어디를 칠지"를 알면
      CMPLOG 는 "어떤 값이어야 통과하는지"를 알려주는 상보 관계.
  ELF dictionary (AFL++ -x elf.dict) : PT_*, DT_*, EM_*, ELFMAG, ABI 태그 등
      토큰 사전. havoc 이 의미있는 상수를 삽입하도록 도와 구조인식을 보강.

AFL++ custom mutator 로딩 (참고)
--------------------------------
    export AFL_PYTHON_MODULE=lfuzzer.mutators.structure_aware
    export PYTHONPATH=/path/to/lfuzzer-clean
    afl-fuzz -c 0 -x elf.dict -i seeds -o out -- ./target @@
AFL++ 는 모듈 최상위의 init/fuzz/describe/deinit 함수를 심볼로 찾는다.
아래에서 그 심볼들을 싱글턴 클래스에 위임하는 shim 으로 노출한다.

주의 (본 저장소 규약)
---------------------
  - stdlib + subprocess 만. 외부 도구/모듈 부재 시에도 **임포트는 무조건 성공**.
    repair_pht 는 mutate_elf_v4 에서 재사용하는데, 그 모듈은 pyelftools 를
    요구하므로 **지연·방어 임포트**한다. 없으면 순수 파이썬 폴백 복구를 쓰고
    무엇이 빠졌는지 report 한다.
  - grammar/field-aware core 는 아직 TODO. 지금은 진짜 시그니처 + 동작하는
    havoc 폴백 + GATE 복구까지가 실제 구현이고, 문법 인식 변형은 자리표시.
"""
from __future__ import annotations

import os
import sys
import struct
import random
from pathlib import Path

# --------------------------------------------------------------------------
# repair_pht 재사용 (mutate_elf_v4). pyelftools 가 없으면 그 모듈 임포트가
# sys.exit 하므로, 절대 최상위에서 import 하지 않는다 — 지연·방어 임포트.
# --------------------------------------------------------------------------
_REPAIR_PHT = None          # callable(buf, img) 또는 None
_REPAIR_IMPORT_ERR = None   # 왜 못 불러왔는지(진단 문자열)


def _load_repair_primitive():
    """mutate_elf_v4.repair_pht / ElfImage 를 지연 로드. (성공여부, 에러문자열).

    repair_pht 는 img.phdrs(각 PHT 엔트리의 파일오프셋)를 요구한다. 그 img 는
    ElfImage(path) 로만 만들어지고 pyelftools 파싱에 의존하므로, 여기서 함께
    가져온다. 실패는 예외가 아니라 '기능 저하 + 사유 보고'로 처리한다."""
    global _REPAIR_PHT, _REPAIR_IMPORT_ERR
    if _REPAIR_PHT is not None or _REPAIR_IMPORT_ERR is not None:
        return _REPAIR_PHT is not None, _REPAIR_IMPORT_ERR
    try:
        from lfuzzer.mutators.mutate_elf_v4 import repair_pht, ElfImage  # noqa
        _REPAIR_PHT = repair_pht
        globals()["_ElfImage"] = ElfImage
        return True, None
    except SystemExit as e:  # pyelftools 부재 시 mutate_elf_v4 가 sys.exit
        _REPAIR_IMPORT_ERR = f"mutate_elf_v4 임포트 실패(pyelftools 없음?): {e}"
    except Exception as e:   # noqa
        _REPAIR_IMPORT_ERR = f"repair_pht 로드 실패: {type(e).__name__}: {e}"
    return False, _REPAIR_IMPORT_ERR


# --------------------------------------------------------------------------
# ELF64 GATE 상수 — 이 값이 어긋나면 로더가 입구에서 즉사시킨다 → 항상 복구
# --------------------------------------------------------------------------
ELFMAG = b"\x7fELF"          # e_ident[0:4]
EI_CLASS_OFF, ELFCLASS64 = 4, 2       # 64-bit
EI_DATA_OFF, ELFDATA2LSB = 5, 1       # little-endian
E_MACHINE_OFF, EM_X86_64 = 18, 62     # e_machine (x86-64 전제)
E_PHOFF_OFF, E_PHENTSIZE_OFF, E_PHNUM_OFF = 32, 54, 56
E_TYPE_OFF, ET_DYN, ET_EXEC = 16, 3, 2
PHENTSIZE64 = 56             # Elf64_Phdr 크기(바이트)
EHDR_SIZE = 64

# SEMANTIC 필드 기본 복구확률(낮게). validity gradient 의 손잡이.
#   0.0 → 모순을 항상 살려둠(가장 공격적, gate 만 통과)
#   1.0 → 항상 정합(가장 보수적, 파서 안쪽엔 못 감)
DEFAULT_P_REPAIR_SEMANTIC = 0.15


def looks_like_elf64(buf) -> bool:
    """GATE 최소요건 통과 여부(빠른 사전판정)."""
    return (len(buf) >= EHDR_SIZE
            and bytes(buf[0:4]) == ELFMAG
            and buf[EI_CLASS_OFF] == ELFCLASS64)


# ==========================================================================
# 뮤테이터 본체
# ==========================================================================
class StructureAwareMutator:
    """구조인식 + 유효성 그라디언트 ELF 뮤테이터.

    AFL++ custom mutator 계약을 클래스로 감싼 골격. 실제 문법 인식 변형은
    _structure_aware_mutate 에 TODO 로 남겨두고, 지금은
      1) 동작하는 havoc 폴백(순수 파이썬),
      2) GATE 필드 강제 복구,
      3) SEMANTIC 필드 p_repair 선택 복구
    까지가 실제 구현이다.

    파라미터
    --------
    seed : int
        결정론적 재현을 위한 시드(AFL 이 init 에서 넘김).
    p_repair_semantic : float
        SEMANTIC 불변식을 고칠 확률. 낮을수록 모순을 더 살려둠.
        환경변수 LFUZZER_P_REPAIR 로 오버라이드.
    """

    def __init__(self, seed: int = 0, p_repair_semantic: float | None = None):
        self.seed = seed & 0xFFFFFFFF
        self.rng = random.Random(self.seed)
        env = os.environ.get("LFUZZER_P_REPAIR")
        if p_repair_semantic is None:
            p_repair_semantic = float(env) if env else DEFAULT_P_REPAIR_SEMANTIC
        self.p_repair_semantic = max(0.0, min(1.0, p_repair_semantic))
        # repair 프리미티브 가용성(부재 시 폴백). 최초 fuzz 때 지연 로드해도 됨.
        self._repair_ok, self._repair_err = _load_repair_primitive()
        self.stats = dict(calls=0, structure_aware=0, havoc=0,
                          gate_repairs=0, semantic_repairs=0)

    # ---- AFL++ 필수 엔트리 -------------------------------------------------
    def init(self, seed: int):
        """AFL 이 시작 시 1회 호출. 시드로 RNG 재시드."""
        self.seed = seed & 0xFFFFFFFF
        self.rng.seed(self.seed)

    def fuzz(self, buf, add_buf, max_size: int):
        """AFL 이 매 뮤테이션마다 호출하는 핵심 엔트리.

        시그니처(AFL++ python API 계약):
            buf      : bytes/bytearray — 현재 큐 엔트리(원본 시드)
            add_buf  : bytes/bytearray | None — 스플라이싱용 보조 입력
            max_size : int — 출력 상한(넘기면 AFL 이 자름)
        반환:
            bytearray — 변형된 입력(비어있으면 안 됨)

        전략:
            1) 구조인식 변형 시도(_structure_aware_mutate). 아직 TODO 골격이라
               현재는 확률적으로 havoc 폴백으로 위임.
            2) validity_gradient 적용: GATE 강제복구 + SEMANTIC 선택복구.
        """
        self.stats["calls"] += 1
        out = bytearray(buf) if buf else bytearray(ELFMAG)

        # 1) 변형 단계 -----------------------------------------------------
        used_saware = False
        if self.rng.random() < 0.5 and looks_like_elf64(out):
            out = self._structure_aware_mutate(out, add_buf, max_size)
            self.stats["structure_aware"] += 1
            used_saware = True
        else:
            out = self._havoc(out, add_buf, max_size)
            self.stats["havoc"] += 1

        # 2) 유효성 그라디언트 --------------------------------------------
        if used_saware:
            # 구조인식 경로는 내부에서 이미 [구조op→canonicalize→SUBST(마지막)]
            # 을 끝냈다. 논문 순서상 SUBST 는 복구 '이후' 주입되어야 살아남는데,
            # 여기서 SEMANTIC 확률복구를 또 돌리면 그 danger 값이 지워질 수 있다.
            # 따라서 GATE(입구검증)만 항상 재보장하고 SEMANTIC 재복구는 건너뛴다.
            self._repair_gate_fields(out)
        else:
            out = self.validity_gradient(out)

        if max_size and len(out) > max_size:
            out = out[:max_size]
        if not out:
            out = bytearray(ELFMAG)
        return out

    def describe(self, max_description_length: int = 0) -> str:
        """AFL 이 산출물에 붙일 짧은 설명(옵션 엔트리). 파일명 태깅에 쓰임."""
        s = ("saware" if self.stats["structure_aware"] >= self.stats["havoc"]
             else "havoc")
        d = f"structaware:{s}:p{self.p_repair_semantic:.2f}"
        if max_description_length and len(d) > max_description_length:
            d = d[:max_description_length]
        return d

    def deinit(self):
        """AFL 종료 시 정리(옵션). 현재 보유 자원 없음."""
        return None

    # ---- 변형: havoc 폴백(동작 구현) --------------------------------------
    def _havoc(self, buf, add_buf, max_size: int) -> bytearray:
        """구조 무관 havoc 폴백. 순수 파이썬, 외부 의존 없음.

        AFL 의 havoc 스테이지를 축소 모사: 바이트 플립/증감/랜덤치환,
        블록 삭제/복제, add_buf 스플라이스. 구조인식 core 가 완성되기 전까지
        기본 동력이자 안전망."""
        out = bytearray(buf)
        n = self.rng.randint(1, 8)          # 여러 변형 중첩
        for _ in range(n):
            if not out:
                out += bytes([self.rng.randrange(256)])
                continue
            op = self.rng.randrange(6)
            i = self.rng.randrange(len(out))
            if op == 0:                      # 비트 플립
                out[i] ^= 1 << self.rng.randrange(8)
            elif op == 1:                    # 바이트 랜덤치환
                out[i] = self.rng.randrange(256)
            elif op == 2:                    # ±1 산술(경계값 유도)
                out[i] = (out[i] + self.rng.choice((-1, 1))) & 0xFF
            elif op == 3 and len(out) > 4:   # 블록 삭제
                j = self.rng.randrange(len(out))
                lo, hi = sorted((i, j))
                hi = min(hi, lo + 64)
                del out[lo:hi]
            elif op == 4:                    # 흥미로운 상수 삽입(사전 축약판)
                val = self.rng.choice(
                    (0x00, 0xFF, 0x7F, 0x80,
                     0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF))
                width = self.rng.choice((1, 2, 4, 8))
                if i + width <= len(out):
                    struct.pack_into({1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[width],
                                     out, i, val & ((1 << (width * 8)) - 1))
            else:                            # add_buf 스플라이스
                if add_buf:
                    ab = bytes(add_buf)
                    k = self.rng.randrange(len(ab))
                    out[i:i] = ab[k:k + self.rng.randint(1, min(64, len(ab) - k))]
        if max_size and len(out) > max_size:
            out = out[:max_size]
        return out

    # ---- 변형: 구조인식 core (4축 파이프라인) -----------------------------
    def _structure_aware_mutate(self, buf, add_buf, max_size: int) -> bytearray:
        """논문 4축 뮤테이션을 '정해진 순서'로 디스패치한다.

        파이프라인(순서가 곧 설계):
            1) buf 를 ElfView(순수 파서)로 파싱. 실패/비ELF64 → havoc 폴백.
            2) 구조변경 축(ADD/SUB/SCRAMBLE) 1~2개를 registry 에서 골라 적용.
               각 op 뒤에는 오프셋이 바뀌므로 뷰를 재파싱한다.
            3) canonicalize repair: GATE(항상) + SEMANTIC(repair_pht) 를 '강제'로
               돌려 포맷 체인을 다시 유효하게 만든다(구조op가 흔든 경계 복구).
            4) SUBST 를 **맨 마지막**에 적용 — 복구 이후에 danger 값을 주입해야
               그 값이 지워지지 않고 살아남는다(핵심 순서). avoid_gate=True 로
               GATE 임계필드는 피해, 바깥 GATE 재복구(fuzz())도 이를 안 덮는다.
            5) bytearray 반환.

        근거(AFLSmart/FormatFuzzer): 입력을 가상구조로 파싱해 chunk 단위 연산 +
        validity-preserving 복구. CMPLOG/ELF-dict 와 상보(여긴 '어디'를 고른다).
        """
        # 1) 레지스트리/뷰 로드(방어적) — 실패하면 havoc 로 안전 폴백
        try:
            from lfuzzer.mutators import registry as _reg
            from lfuzzer.mutators.operators import ElfView
        except BaseException as e:   # 어떤 임포트 실패도 파이프라인을 끊지 않음
            self.stats["saware_import_err"] = f"{type(e).__name__}: {e}"
            return self._havoc(buf, add_buf, max_size)

        out = bytearray(buf)
        view = ElfView.parse(out)
        if not view.ok:
            return self._havoc(buf, add_buf, max_size)

        applied = []

        # 2) 구조변경 축 1~2개 적용(add/sub/scramble)
        structs = _reg.structural_operators()
        k = self.rng.randint(1, min(2, len(structs)))
        for op in self.rng.sample(structs, k):
            try:
                rec = op.apply(view, out, self.rng)
            except Exception:
                rec = None
            if rec is not None:
                applied.append(rec)
                view = ElfView.parse(out)      # 오프셋 변화 반영 재파싱

        # 3) canonicalize repair (GATE 항상 + SEMANTIC 강제)
        self._repair_gate_fields(out)
        self._repair_semantic_fields(out)

        # 4) SUBST 를 맨 마지막에(복구 이후 danger 주입 → 생존)
        try:
            subst = _reg.get_operator("subst")(avoid_gate=True)
            rec = subst.apply(ElfView.parse(out), out, self.rng)
            if rec is not None:
                applied.append(rec)
        except Exception:
            pass

        # 5) stats 기록 후 반환
        self.stats["ops_applied"] = self.stats.get("ops_applied", 0) + len(applied)
        for r in applied:
            key = "op_" + r.axis.lower()
            self.stats[key] = self.stats.get(key, 0) + 1
        self._last_saware_records = applied   # 디버깅/트리아지 조인용

        if max_size and len(out) > max_size:
            out = out[:max_size]
        return out

    # ======================================================================
    # 유효성 그라디언트
    # ======================================================================
    def validity_gradient(self, buf) -> bytearray:
        """GATE 는 항상, SEMANTIC 은 p_repair_semantic 확률로 복구.

        반환된 입력은 '로더 입구는 통과하되 안쪽 불변식은 (확률적으로) 깨진'
        상태 — 즉 유효성 스펙트럼의 중간대에 놓인다."""
        out = bytearray(buf)
        self._repair_gate_fields(out)                 # 반드시
        if self.rng.random() < self.p_repair_semantic:
            self._repair_semantic_fields(out)         # 가끔
        return out

    # ---- GATE: 반드시 복구 (입구 검증 통과 보장) --------------------------
    def _repair_gate_fields(self, buf) -> None:
        """ELF magic, EI_CLASS, EI_DATA, e_machine, PHT 경계를 강제 정상화.

        이걸 안 하면 대부분의 입력이 'ELF 아님'으로 즉시 버려져 커버리지가
        늘지 않는다(순수 낭비). 그래서 이 층만은 확률 없이 항상 적용."""
        if len(buf) < EHDR_SIZE:
            buf.extend(b"\x00" * (EHDR_SIZE - len(buf)))

        # magic / class / data / machine
        buf[0:4] = ELFMAG
        buf[EI_CLASS_OFF] = ELFCLASS64
        buf[EI_DATA_OFF] = ELFDATA2LSB
        struct.pack_into("<H", buf, E_MACHINE_OFF, EM_X86_64)

        # e_phentsize 는 반드시 56 (아니면 로더가 헤더배열 파싱 불가)
        struct.pack_into("<H", buf, E_PHENTSIZE_OFF, PHENTSIZE64)

        # PHT 경계: e_phoff + e_phnum*56 이 파일을 넘으면 OOB 로 즉사 → 클램프
        e_phoff = struct.unpack_from("<Q", buf, E_PHOFF_OFF)[0]
        e_phnum = struct.unpack_from("<H", buf, E_PHNUM_OFF)[0]
        if e_phoff > len(buf):
            e_phoff = EHDR_SIZE
            struct.pack_into("<Q", buf, E_PHOFF_OFF, e_phoff)
        if e_phnum == 0:
            e_phnum = 1
            struct.pack_into("<H", buf, E_PHNUM_OFF, e_phnum)
        max_phnum = max(0, (len(buf) - e_phoff) // PHENTSIZE64)
        if max_phnum == 0:
            # PHT 한 칸도 못 들어감 → 최소 한 칸 확보
            buf.extend(b"\x00" * (e_phoff + PHENTSIZE64 - len(buf)))
            max_phnum = 1
        if e_phnum > max_phnum:
            struct.pack_into("<H", buf, E_PHNUM_OFF, max_phnum)
        self.stats["gate_repairs"] += 1

    # ---- SEMANTIC: 낮은 확률로 복구 (모순을 대체로 살려둠) ----------------
    def _repair_semantic_fields(self, buf) -> None:
        """SEMANTIC 포맷정합을 lfuzzer.repair.canonicalize 로 일괄 복구.

        canonicalize 가 복구하는 불변식(Phase 2 ③):
            · PHT 교차필드 (p_align/filesz≤memsz/offset+filesz≤파일/vaddr≡offset)
            · DT_STRSZ == strtab..포함 PT_LOAD 끝 span
            · DT_RELASZ/DT_RELAENT · DT_RELSZ/DT_RELENT · DT_SYMENT 배수·고정값
            · DT_VERNEEDNUM/DT_VERDEFNUM == 실제 순회 개수
            · DT_STRTAB/SYMTAB/HASH/VERNEED 포인터를 PT_LOAD 범위 안으로
            · versym 인덱스 ≤ (verdef+verneed 정의 수) 클램프
            · (level="full") SHT: e_shentsize/e_shnum 경계·sh_link/sh_info·sh_size

        canonicalize 는 순수 파이썬 + operators.ElfView 라 pyelftools 불필요이고
        예외를 던지지 않는다. 링커(ld/gold)가 SHT 를 읽으므로 level="full" 로
        섹션헤더까지 정합화한다. 방어적 임포트 — 실패하면 기존 repair_pht /
        _repair_pht_pure 경로로 폴백한다(계약: 임포트는 절대 파이프라인을 끊지 않음).
        """
        try:
            from lfuzzer.repair.canonicalize import canonicalize
        except BaseException as e:   # noqa — 임포트 실패는 폴백으로 흡수
            self._canon_err = f"canonicalize 임포트 실패: {type(e).__name__}: {e}"
            self._repair_semantic_fallback(buf)
            return
        try:
            notes = canonicalize(buf, level="full")
            self._last_canon_notes = notes         # 디버깅/트리아지 조인용
            self.stats["semantic_repairs"] += 1
            self.stats["canon_notes"] = self.stats.get("canon_notes", 0) + len(notes)
        except BaseException as e:   # noqa — canonicalize 는 안 던지지만 이중 방어
            self._canon_err = f"canonicalize 호출 실패: {type(e).__name__}: {e}"
            self._repair_semantic_fallback(buf)

    def _repair_semantic_fallback(self, buf) -> None:
        """canonicalize 부재 시 폴백: 기존 repair_pht(재사용) → 순수 PHT 클램프.

        repair_pht(mutate_elf_v4) 는 ElfImage(path) 의 img.phdrs 를 요구하므로
        임시파일로 감싸 호출한다(pyelftools 가 있을 때만). 없으면 순수 폴백."""
        if not self._repair_ok:
            self._repair_ok, self._repair_err = _load_repair_primitive()
        if self._repair_ok and _REPAIR_PHT is not None:
            try:
                import tempfile
                ElfImage = globals().get("_ElfImage")
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tf.write(bytes(buf))
                    tmp = tf.name
                try:
                    img = ElfImage(tmp)          # pyelftools 로 PHT 위치 파싱
                    _REPAIR_PHT(buf, img)        # ← 재사용 프리미티브
                    self.stats["semantic_repairs"] += 1
                finally:
                    os.unlink(tmp)
                return
            except Exception as e:  # noqa — 복구는 best-effort
                self._repair_err = f"repair_pht 호출 실패: {type(e).__name__}: {e}"
        # 최종 폴백: pyelftools 없음 → 순수 파이썬 PHT 클램프(축약판)
        self._repair_pht_pure(buf)

    def _repair_pht_pure(self, buf) -> None:
        """repair_pht 순수-파이썬 축약 폴백(pyelftools 부재 시).

        e_phoff/e_phnum 만으로 PHT 를 훑어 p_offset+p_filesz ≤ 파일 만 클램프.
        정렬/vaddr 합동식까지는 안 본다(원본 repair_pht 가 authoritative)."""
        if len(buf) < EHDR_SIZE:
            return
        e_phoff = struct.unpack_from("<Q", buf, E_PHOFF_OFF)[0]
        e_phnum = struct.unpack_from("<H", buf, E_PHNUM_OFF)[0]
        for i in range(e_phnum):
            base = e_phoff + i * PHENTSIZE64
            if base + PHENTSIZE64 > len(buf):
                break
            p_off = struct.unpack_from("<Q", buf, base + 8)[0]
            p_fsz = struct.unpack_from("<Q", buf, base + 32)[0]
            p_msz = struct.unpack_from("<Q", buf, base + 40)[0]
            if p_off > len(buf):
                p_off = len(buf)
                struct.pack_into("<Q", buf, base + 8, p_off)
            if p_off + p_fsz > len(buf):
                p_fsz = max(0, len(buf) - p_off)
                struct.pack_into("<Q", buf, base + 32, p_fsz)
            if p_fsz > p_msz:
                struct.pack_into("<Q", buf, base + 40, p_fsz)
        self.stats["semantic_repairs"] += 1


# ==========================================================================
# AFL++ 모듈레벨 심볼 — 싱글턴에 위임 (AFL 은 이 함수들을 이름으로 찾는다)
# ==========================================================================
_MUTATOR: StructureAwareMutator | None = None


def init(seed):
    """AFL++ 진입점: 퍼징 시작 시 1회."""
    global _MUTATOR
    _MUTATOR = StructureAwareMutator(seed=int(seed) & 0xFFFFFFFF)
    _MUTATOR.init(int(seed) & 0xFFFFFFFF)


def fuzz(buf, add_buf, max_size):
    """AFL++ 진입점: 매 변형마다. init 가 선행 안 됐으면 지연 생성."""
    global _MUTATOR
    if _MUTATOR is None:
        _MUTATOR = StructureAwareMutator(seed=0)
    return _MUTATOR.fuzz(buf, add_buf, max_size)


def describe(max_description_length):
    """AFL++ 진입점(옵션): 산출물 태그."""
    if _MUTATOR is None:
        return "structaware:uninit"
    return _MUTATOR.describe(max_description_length)


def deinit():
    """AFL++ 진입점(옵션): 종료 정리."""
    if _MUTATOR is not None:
        _MUTATOR.deinit()


# ==========================================================================
# 데모 (__main__) — 템플릿 ELF 가 있으면 실제 변형 1회, 없으면 설명
# ==========================================================================
def _find_template() -> str | None:
    """저장소 templates/ 에서 데모용 ELF 하나 고른다(config.REPO_ROOT 기준)."""
    candidates = []
    try:
        from lfuzzer import config
        candidates.append(Path(config.REPO_ROOT) / "templates")
    except Exception:  # noqa
        pass
    candidates.append(Path(__file__).resolve().parents[2] / "templates")
    for d in candidates:
        try:
            if d.is_dir():
                for name in ("prac.elf", "prac_minimal_dl_load_885.elf",
                             "prac_gold.elf"):
                    p = d / name
                    if p.exists():
                        return str(p)
                elfs = sorted(d.glob("*.elf"))
                if elfs:
                    return str(elfs[0])
        except Exception:  # noqa
            continue
    return None


def main():
    print("=" * 74)
    print("structure_aware.py — V2 구조인식 뮤테이터 데모")
    print("=" * 74)

    ok, err = _load_repair_primitive()
    print(f"[repair_pht 재사용]  {'가용' if ok else '부재→폴백'}"
          + (f"  ({err})" if err else ""))

    m = StructureAwareMutator(seed=1234)
    print(f"[p_repair_semantic]  {m.p_repair_semantic}"
          f"  (LFUZZER_P_REPAIR 로 조절)")

    tmpl = _find_template()
    if not tmpl:
        print("\n템플릿 ELF 를 못 찾음(templates/*.elf).")
        print("→ fuzz() 는 여전히 동작한다. 합성 최소 ELF 로 시연:")
        buf = bytearray(64)
        buf[0:4] = ELFMAG
        buf[EI_CLASS_OFF] = ELFCLASS64
        struct.pack_into("<H", buf, E_PHOFF_OFF, 64)  # 임의
        seed = buf
    else:
        print(f"\n[템플릿]  {tmpl}")
        with open(tmpl, "rb") as f:
            seed = bytearray(f.read())

    print(f"[입력]    {len(seed)} bytes, "
          f"ELF64-gate={'통과' if looks_like_elf64(seed) else '실패'}")

    out = m.fuzz(seed, add_buf=None, max_size=max(len(seed) * 2, 512))
    print(f"[출력]    {len(out)} bytes, "
          f"ELF64-gate={'통과' if looks_like_elf64(out) else '실패(!)'}")
    print(f"[describe] {m.describe(64)}")
    print(f"[stats]   {m.stats}")

    # gate 는 항상 복구되어야 한다는 계약 확인
    assert looks_like_elf64(out), "GATE 복구 위반: 출력이 ELF 로 인식 안 됨"
    print("\nGATE 불변식 유지 확인 완료(magic/class/machine/phentsize).")
    print("상보 기법: CMPLOG(-c 0) + ELF dictionary(-x elf.dict) 함께 켤 것.")


if __name__ == "__main__":
    main()
