# Lfuzzer

**Lfuzzer**는 ELF64 / 동적 링커(glibc `ld.so`)를 노리는 퍼저이자, **gold vs BFD 차등(differential) 연구 툴킷**이다. 정상 ELF 입력을 정확히 세 개의 메타데이터 영역 — **섹션 헤더 테이블(SHDR)**, **`.dynamic` 배열(DT_ 태그)**, **프로그램 헤더 테이블(PHDR)** — 에 걸쳐 변이(mutate)시킨 뒤, 두 정적 링커(`ld.bfd`, `ld.gold`)로 링크하고, 런타임 로더(`ld.so`)로 적재하며, 분석기(`readelf`, `objdump`, Ghidra)로 관찰해 **이 도구들이 서로 어긋나는 지점**을 찾는다. 모듈 구조는 **Melkor**(Alejandro Hernandez, Black Hat 2014)를 의도적으로 그대로 본떴다 — `melkor.c → fuzz_<metadata>.c → generators.c + logger.c` 설계가 템플릿이며, 이를 파이썬 패키지로 재구성하고 Melkor에는 없는 **차등 관찰 계층(differential-observation layer)**을 얹었다.

> 방어적 보안 연구용이다. Lfuzzer는 링커/로더/파서의 견고성 버그를 찾고 그들이 어떻게 서로 어긋나는지를 규명하기 위해 존재하며, 이를 무기화하지 않는다.

> **파이프라인 & 로드맵**: 통합 파이프라인(collect-once → dual oracle)과 개선 실험군(V5→V1→V2→V3→V4) 설계·현황은 [`README.PIPELINE.md`](README.PIPELINE.md) 참고. 상세 설계는 [`docs/UNIFIED_PIPELINE.md`](docs/UNIFIED_PIPELINE.md), SOTA 대조·인용은 [`docs/PIPELINE_VARIANTS.md`](docs/PIPELINE_VARIANTS.md), 시각 도시는 [`docs/ARCHITECTURE.html`](docs/ARCHITECTURE.html).

> 영문 README는 [`README.en.md`](README.en.md)에 보존돼 있다.

---

## 개요

Lfuzzer는 준정상(semi-valid) 시드 ELF를 받아, 세 메타데이터 영역 중 하나에 **스펙 인지 변이 + 생성(spec-aware mutation + generation)**을 적용한 뒤, 소비자(consumer) 파이프라인에 통과시킨다.

```
              ┌─────────────┐
  시드 ELF ──▶│  mutators/  │──▶ 변이 ELF ──┬──▶ ld.bfd  (정적 링크)   ┐
              └─────────────┘               ├──▶ ld.gold (정적 링크)   ├─▶ differential/ ──▶ 어긋남(divergence)
                                            ├──▶ ld.so   (런타임 적재) │      + analysis/  ──▶ 트리아지/분류
                                            └──▶ readelf/objdump/Ghidra┘
```

연구 질문은 단순히 "크래시가 나는가?"가 아니라 **"같은 바이트를 두고 BFD·gold·ld.so·분석기가 어디서 서로 다르게 판단하는가?"**이다 — 그 틈(gap)이 곧 신호다.

---

## 왜 이렇게 접근하는가

| 축 | 순정 Melkor | Lfuzzer |
|----|-------------|---------|
| **표적** | ELF 메타데이터 소비자 일반 | **동적 링커(`ld.so`) + 정적 링커(BFD/gold)** 특정 |
| **범위** | 모든 ELF 메타데이터 계층 | **3개 영역**으로 좁힘: SHDR · `.dynamic` · PHDR |
| **신호** | 단일 소비자의 크래시/행(hang) | **차등**: gold vs BFD, 링커 vs 로더, 로더 vs 분석기 |
| **언어** | C | 파이썬 (구조적 미러링이지 포팅이 아님) |

- **동적 링커 집중.** `ld.so`는 동적 링크된 *모든* 프로그램을 실행하며, 프로세스 시작 시 공격자가 영향을 줄 수 있는 `.dynamic`/PHDR 데이터를 파싱한다. 가치가 높지만 퍼징이 덜 된 표면이다.
- **3영역 범위.** SHDR / `.dynamic` / PHDR로 제한하면 변이가 얕게 유지돼 링크·적재 가능성을 잃지 않으면서(아래 *의존성 계층* 참고) 링커와 로더가 실제로 다루는 메타데이터를 덮는다.
- **차등 관점.** 독립된 두 링커 구현(BFD, gold)에 로더와 분석기까지 더하면, 정답(ground truth) 없이도 오라클이 생긴다 — **동일 입력에 대한 어떤 불일치든 버그 후보**이며, 단일 도구가 크래시하지 않아도 성립한다.

---

## 아키텍처

Lfuzzer는 Melkor의 역할 분리를 유지한다. Melkor 모듈과 Lfuzzer 패키지의 대응은 다음과 같다.

| Melkor (C) | 역할 | Lfuzzer (Python) |
|------------|------|------------------|
| `melkor.c` (main) | fuzz + run + triage 루프 오케스트레이션 | `lfuzzer/orchestrator/` |
| `fuzz_<metadata>.c` | 메타데이터별 퍼징 **규칙** | `lfuzzer/mutators/` |
| `generators.c` + `numbers.h` | 준정상 테스트 데이터 생성 | `lfuzzer/generators/` |
| `logger.c` | 어떤 메타데이터를 퍼징했는지 기록 | `lfuzzer/logger/` |
| ELF read primitives | ELF 구조 파싱 | `lfuzzer/core/` |
| *(대응 없음)* | **gold-vs-BFD / 링커-vs-로더 차등** | `lfuzzer/differential/` |
| `test_fuzzed.sh` | 표적 대상 실행 + 분류 | `lfuzzer/analysis/` |

```
lfuzzer/
├── core/            # 정본 ELF64 read primitives (Melkor: ELF 파싱 계층)
│   ├── elf64.py           # u16/u32/u64 리더, read_phdrs, .dynamic 순회
│   ├── drivers/common.py  # 공용 드라이버 헬퍼
│   └── seeds/extract_phdr.py
├── mutators/        # 메타데이터별 퍼징 규칙 (Melkor: fuzz_<metadata>.c)
│   ├── mutate_elf_v4.py        # 최상위 변이 진입점
│   ├── mutator_field_v2.py     # PHT 필드 변이
│   ├── mutator_dynamic_v3.py   # .dynamic DT_ 태그 변이
│   ├── mutator_interp_vaddr_v2.py
│   ├── mutator_shuffle.py      # PHDR 엔트리 재배열
│   └── fuzzer_overlap.py       # PT_LOAD 세그먼트 중첩
├── generators/      # 준정상 값 생성 (Melkor: generators.c + numbers.h)  ── 신규
│   ├── generators.py
│   └── numbers.py
├── logger/          # 어떤 메타데이터 필드를 퍼징했는지 기록 (Melkor: logger.c)  ── 신규
│   └── logger.py
├── orchestrator/    # 자율 fuzz+triage 루프 (Melkor: melkor.c main)
│   ├── autorun_v3.py      # fuzz → link → run → triage 루프
│   └── lfuzzer.py         # run_elf 헬퍼
├── differential/    # Lfuzzer 고유: gold vs BFD / 링커 vs 로더 / 분석기 차등
│   ├── exp_goldbfd_diff/  # common.py + exp_d01..d24 + exp_r1..r8 + exp_display_all.py
│   │   └── ghidra_scripts/DumpDynamic.java
│   ├── parser_diff/       # 정적 파서 차등 리플레이
│   ├── exp_e1..e6/        # 집중 사례 연구 (runpath, pie, shdrstrip, verneed, dupsoname, auxtag)
│   └── tag_exp/
├── analysis/        # 트리아지 + 분류 (Melkor: test_fuzzed.sh)
│   ├── auto_gdb_classify.py    # gdb 기반 크래시 버킷팅
│   ├── strace_classify.py
│   ├── analyze_crashes.py
│   ├── triage_v3.py
│   ├── rerun_debug_ldso.py
│   └── drivers/{triage,verify}.py
├── exploit/         # 확정된 발견에 대한 PoC / 견고성 연구
│   ├── exploit_analyze_dtors.py
│   ├── exploit_test_relro_off.py
│   ├── craft_extratag_poc.py
│   ├── minimal_repro_dl_load_885.py
│   └── dl-load-885-robustness.patch
├── overlap_lab/     # PT_LOAD 중첩 순열 실험실
│   └── overlap_perm_lab/  # harness.py, mutate.py, detect_overlap.py, analyze.py, run.py, iter01-30.py
└── config.py        # 중앙집중 경로 (링커, 로더, Ghidra, 프로젝트 루트)
```

### 이어받은 Melkor 설계 원칙

1. 스펙 지식을 활용한 **하이브리드 변이 + 생성** (맹목적 비트플립이 아님).
2. **규칙 실행**을 확률 게이트로 구동 — 핵심 필드는 스스로 확률을 낮춰 입력이 준정상으로 남게 한다.
3. **메타데이터 의존성 계층**(`HDR → SHT/PHT → 심볼/reloc/문자열/dynamic 테이블`): 깊은 계층은 **가장 나중에, 혹은 아예 안** 퍼징해 의존성을 보존하고 커버리지를 높게 유지한다. Lfuzzer의 3영역 범위(SHDR/PHDR/`.dynamic`)는 의도적으로 얕고 지렛대가 큰 계층에 놓인다.
4. **templates/**에 시드 ELF를 둔다.
5. **실행 하니스**가 변이된 "orc"들을 표적에 던진다.

---

## 설치

```bash
pip install -r requirements.txt   # pyelftools (elftools.elf...), tqdm
```

**외부 도구** (`PATH`에 있거나 `lfuzzer/config.py`에 설정돼 있어야 함):

```
readelf   objdump   strace   gdb   valgrind
gcc   ld (BFD)   ld.gold   patchelf   ghidra
```

**커스텀 binutils 빌드(권장).** 차등 실험은 목적에 맞게 빌드한 링커 바이너리를 우선 쓰고, 없으면 시스템 것으로 폴백한다.

```bash
# BFD ld  (AFL 계측 클린 빌드)
~/binutils-build-afl-bfd-clean/ld/ld-new     # 폴백: /usr/bin/ld, /usr/bin/ld.bfd
# gold ld
~/binutils-build-gold/gold/ld-new            # 폴백: /usr/bin/ld.gold, /usr/bin/gold
```

Ghidra는 **Java 21**이 필요하다(`~/ghidra_12.1.2_PUBLIC`). 로더 경로는 `/lib64/ld-linux-x86-64.so.2`(또는 `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`).

---

## 빠른 시작

```bash
# 1) 시드 ELF 변이 (.dynamic DT_ 태그 예시; PHDR/SHDR은 모듈만 교체)
python -m lfuzzer.mutators.mutate_elf_v4 templates/prac.elf -o out/mutant.elf

# 2) 같은 변이체를 두 링커로 링크하고 차이 관찰
python lfuzzer/differential/exp_goldbfd_diff/exp_d01_strip_sht.py

# 3) 런타임 링커로 적재해 동작 관찰
python -m lfuzzer.orchestrator.lfuzzer out/mutant.elf     # ld.so 하에서 실행

# 4) 크래시/행을 트리아지·분류
python -m lfuzzer.analysis.auto_gdb_classify out/mutant.elf

# 혹은 전체 자율 루프 실행 (mutate → link → run → triage):
python -m lfuzzer.orchestrator.autorun_v3
```

---

## 차등 실험

`differential/exp_goldbfd_diff/` 스위트가 gold-vs-BFD 연구의 핵심이다. 각 `exp_dNN` / `exp_rN`은 **독립 실행 가능한** 가설로, 베이스 라이브러리를 만들고 변이 하나를 적용한 뒤 `-B<dir>` 래퍼 트릭(`common.py:link_with`)으로 두 링커에서 링크하고 어긋남을 보고한다.

```bash
cd lfuzzer/differential/exp_goldbfd_diff

./exp_d01_strip_sht.py        # 섹션 헤더 테이블 제거
./exp_d05_verneed_edge.py     # VERNEED 엣지 케이스
./exp_d07_dt_hash_nchain.py   # DT_HASH nchain 불일치
./exp_d22_runpath.py          # DT_RUNPATH 처리
./exp_r5_phdr_vs_sht.py       # PHDR vs SHT 관점 불일치
./exp_r7_ghidra_dtag.py       # Ghidra .dynamic 태그 판독 차이

./exp_display_all.py          # 전체 결과 집계·렌더
```

**번호 시리즈** (전부 `exp_goldbfd_diff/` 안):

| 시리즈 | 검증 대상 |
|--------|-----------|
| `exp_d01` … `exp_d24` | `.dynamic` / SHDR / 심볼 테이블 변이 대 두 링커 (SHT 제거, dynstr 비-NUL, PIE, audit, verneed/verdef 엣지, 해시 테이블, OSABI, shnum/shstrndx OOB, ET_CORE/ET_REL, syment, rpath/runpath 등) |
| `exp_r1, r5, r6, r7, r8` | 관점 교차 차이: 미끼 `.dynamic`, PHDR-vs-SHT, 미지 EHDR enum, Ghidra dtag / symcount 판독 |
| `ghidra_scripts/DumpDynamic.java` | `exp_r7/r8`이 쓰는 headless Ghidra `.dynamic` 덤퍼 |

> `exp_d18` 슬롯은 의도적으로 비어 있다. 시리즈는 `d01–d24`에서 `d18`을 뺀 것이다.

집중 사례 연구는 `differential/exp_e1..e6/`(runpath, PIE, SHDR 제거, VERNEED, 중복 SONAME, aux 태그)로 함께 있고, `differential/parser_diff/`는 같은 코퍼스를 정적 파서에 리플레이해 파서 견고성을 비교한다.

---

## 설정

머신별 경로는 전부 **`lfuzzer/config.py`**에 모아 두어 스크립트에 하드코딩된 경로가 없다. 각 항목은 존재하는 첫 후보로 해석되고, 없으면 시스템 도구로 폴백한다.

| 키 | 우선 | 폴백 |
|----|------|------|
| `BFD` | `~/binutils-build-afl-bfd-clean/ld/ld-new` | `/usr/bin/ld`, `/usr/bin/ld.bfd` |
| `GOLD` | `~/binutils-build-gold/gold/ld-new` | `/usr/bin/ld.gold`, `/usr/bin/gold` |
| `GHIDRA` | `~/ghidra_12.1.2_PUBLIC` (Java 21) | — |
| `LOADER` | `/lib64/ld-linux-x86-64.so.2` | `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` |
| `PROJECT_ROOT` | 레포 루트 | — |

환경변수로 덮거나 머신에 맞게 `config.py`를 직접 수정하면 된다.

---

## 저장소 구조

```
lfuzzer/            파이썬 패키지 (아키텍처 참고)
templates/          대표 시드 ELF (prac.elf 등)
docs/               ARCHITECTURE.html, MELKOR_MAPPING.md, *_0715.md 기획 문서
archive/            레거시 mutator, 회의 노트, 옛 gold/bfd 출력 덤프
README.md  README.en.md  LICENSE  requirements.txt  Makefile  pyproject.toml  .gitignore
```

**추적하지 않음** (생성 데이터, 약 15만 파일, `.gitignore` 처리됨): `out*/`, `in*/`, `crashes*/`, `glibc/`, `gcov/`, `classified_*/`, `representatives*/`, `overlap_perm_lab/iter*_out/`, `__pycache__/`, `*.log`, `*_report.txt`, `autorun_state.json`, 컴파일된 ELF 산출물.

---

## 크레딧

구조 설계는 **Melkor — An ELF File Format Fuzzer**, Alejandro Hernandez (IOActive), Black Hat USA 2014를 따랐다. Lfuzzer는 Melkor의 모듈 역할과 변이 철학을 파이썬으로 미러링하고, 링커/로더/분석기 차등 계층을 더했다.

## 라이선스

MIT. [LICENSE](LICENSE) 참고.
