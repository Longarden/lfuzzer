# Lfuzzer — 프로젝트 구조 & Mutator 정리

> 이 저장소(`github.com/Longarden/lfuzzer`)는 이전 세션이 휘발성 job tmp 폴더
> (`.claude/jobs/6652279a/tmp/lfuzzer`)에 clone해둔 채 방치돼 있던 것을
> 2026-08-21에 `C:\Users\dmsak\Desktop\01_SWSEC\lfuzzer` 로 영구 이동했다.
> `main` 브랜치(HEAD `bb444b7`)는 `origin/main`과 동기화 상태이고 clean하다.
> `readme-ko` 브랜치(로컬 + `origin/readme-ko` 모두 존재, 내용 동일)의 linked
> worktree(`.claude/worktrees/readme-ko`)는 이동 과정에서 절대경로 참조가 깨져
> git worktree로는 더 이상 동작하지 않는다 — 필요하면
> `git worktree add .claude/worktrees/readme-ko readme-ko` 로 재생성하면 된다
> (내용 손실 없음, origin에 안전하게 존재).

---

## 1. 전체 디렉터리 구조 (2026-08-21 기준 실제 상태)

원래 설계 문서(`docs/MELKOR_MAPPING.md`, `README.md`)가 그리던 구조에서
`structure_aware.py`, `unified_runner.py`, `nezha_oracle.py`, `triage/`,
`harness/` 가 이후 세션들에서 새로 추가됐다. 아래는 그걸 반영한 현재 실제 트리.

```
lfuzzer/                    # 저장소 루트 (git, origin=github.com/Longarden/lfuzzer)
├── lfuzzer/                 # 파이썬 패키지 본체
│   ├── core/                     # 정본 ELF64 read primitives (Melkor: ELF 파싱 계층)
│   │   ├── elf64.py                  # u16/u32/u64 리더, read_phdrs, iter_dynamic, vaddr_to_offset — 전 뮤테이터 공유 단일 소스
│   │   ├── common.py
│   │   └── extract_phdr.py
│   │
│   ├── mutators/             # 메타데이터별 퍼징 규칙 (Melkor: fuzz_<metadata>.c)
│   │   ├── mutate_elf_v4.py          # 최상위 필드테이블 뮤테이터 — EHDR+PHT+DYNAMIC+VERNEED 전수, violate/keep 2모드
│   │   ├── mutator_dynamic_v3.py     # .dynamic DT_ 태그 뮤테이터 (v4의 전신, VERNEED/AUDIT/PHDR 3카테고리)
│   │   ├── mutator_field_v2.py       # PHT 8필드 변이 (단일/콤보, 8워커 병렬, seed 재현)
│   │   ├── mutator_interp_vaddr_v2.py  # PT_INTERP p_vaddr 단일필드 변이 (4모드 위험위치)
│   │   ├── mutator_shuffle.py        # PHDR 엔트리 재배열 (순열 전수)
│   │   ├── fuzzer_overlap.py         # PT_LOAD 세그먼트 중첩 (8가지 패턴)
│   │   └── structure_aware.py        # ── 신규 · AFL++ custom mutator (GATE/SEMANTIC 유효성 그라디언트, 문법인식 core는 TODO/havoc 폴백)
│   │
│   ├── generators/           # 준정상 값 생성 (Melkor: generators.c + numbers.h) — 실제 구현됨
│   │   ├── numbers.py                # 5개 의도풀(SIZES/OFFSETS/ADDRS/STR_IDX/MASKS) + STR_PAYLOADS + FIELD_INTENT
│   │   └── generators.py             # numbers.py에서 값을 뽑는 시드가능 생성기, gen_for_field() 라우터 (뮤테이터 완전 이전은 아직)
│   │
│   ├── logger/                # 어떤 메타데이터 필드를 퍼징했는지 기록 (Melkor: logger.c) — 실제 구현됨
│   │   └── logger.py                 # FuzzLogger — region/field/rule/likelihood 기록, jsonl+json+txt 3중 출력
│   │
│   ├── orchestrator/          # 자율 fuzz+triage 루프 (Melkor: melkor.c main)
│   │   ├── autorun_v3.py             # fuzz → link → run → triage 루프, 카테고리 가중 랜덤선택, 60/40 예산분할
│   │   ├── lfuzzer.py                 # run_elf 헬퍼
│   │   └── unified_runner.py         # ── 신규 · collect-once/dual-oracle 통합 루프 (5채널 관측벡터 1회 수집 → crash+divergence 오라클 동시 공급)
│   │
│   ├── differential/          # Lfuzzer 고유: gold vs BFD / 링커 vs 로더 / 분석기 차등
│   │   ├── nezha_oracle.py           # ── 신규 · NEZHA δ-diversity 이식, accept/reject/crash/timeout × benign/soft/hard 등급화 (판정은 안 함, novelty 신호만)
│   │   ├── exp_goldbfd_diff/         # common.py + exp_d01..d24 + exp_r1..r8 + exp_display_all.py
│   │   │   └── ghidra_scripts/DumpDynamic.java
│   │   ├── parser_diff/              # 정적 파서 차등 리플레이
│   │   ├── exp_e3_shdrstrip/, exp_e4_verneed/, exp_e5_dupsoname/, exp_e6_auxtag/   # 집중 사례 연구
│   │   └── tag_exp/
│   │
│   ├── analysis/              # 트리아지 + 분류 (Melkor: test_fuzzed.sh)
│   │   ├── auto_gdb_classify.py, strace_classify.py, analyze_crashes.py, triage_v3.py, rerun_debug_ldso.py
│   │   ├── drivers/{triage,verify,driver_header,driver_segment,driver_dynamic}.py
│   │   └── *.sh                       # sprint1~3, classify_multi, triage_dos 등 실행 스크립트군 (미조사)
│   │
│   ├── triage/                 # ── 신규 · V5 크래시 확정 파이프라인 (MELKOR_MAPPING.md 미반영)
│   │   ├── pipeline.py               # TriagePipeline — TriOracle.confirm() 후 CasrDedup(authoritative) + MCPAdvisor(advisory only)
│   │   ├── casr_dedup.py             # CASR 우선, 없으면 gdb 백트레이스 파서 폴백 (tool_used: casr|gdb-fallback)
│   │   ├── tri_oracle.py             # 크래시 확정 판정기 (미상세조사)
│   │   └── mcp_advisor.py            # LLM 자문 래퍼, splits는 지표에 안 잡힘 (미상세조사)
│   │
│   ├── exploit/                # 확정된 발견에 대한 PoC / 견고성 연구
│   │   ├── exploit_analyze_dtors.py, exploit_test_relro_off.py, craft_extratag_poc.py, minimal_repro_dl_load_885.py
│   │
│   ├── overlap_lab/            # PT_LOAD 중첩 순열 실험실
│   │   └── overlap_perm_lab/         # harness.py, mutate.py, detect_overlap.py, analyze.py, run.py, iter01~30.py (미상세조사)
│   │
│   └── config.py               # 중앙집중 경로 해석기 — (1)환경변수 (2)알려진 빌드경로 (3)시스템 폴백 순, BFD/GOLD/GHIDRA/LOADER/REPO_ROOT
│
├── harness/                    # ── 신규 · AFL++ 하네스 (asan_harness.c, build_harness.sh, elf.dict, entrypoints.md)
├── templates/                  # 시드 ELF (prac.elf 등, 커밋별 해시 디렉토리 다수)
├── docs/                       # MELKOR_MAPPING.md, ARCHITECTURE.html, UNIFIED_PIPELINE.md, PIPELINE_VARIANTS.md 등 설계문서
├── archive/                    # 레거시/중복 (meeting_0714 시리즈, gold_bfd_output_diff 등)
├── README.md, README.PIPELINE.md, LICENSE, Makefile, pyproject.toml, requirements.txt
└── plan.md                     # 이 문서
```

---

## 2. Melkor ↔ Lfuzzer 모듈 매핑 (요약)

전체 설계원칙과 근거는 `docs/MELKOR_MAPPING.md`에 상세 서술되어 있음(§1 모듈표,
§2 설계원칙 3가지, §3 한 문단 요약). 핵심만 요약:

| Melkor (C) | 역할 | Lfuzzer (Python) |
|---|---|---|
| `melkor.c` (main) | fuzz+run+triage 루프 | `orchestrator/autorun_v3.py` |
| `fuzz_<metadata>.c` | 메타데이터별 규칙 | `mutators/*` |
| `generators.c`+`numbers.h` | 준정상 값 생성 | `generators/*` |
| `logger.c` | 어떤 필드를 건드렸는지 기록 | `logger/logger.py` |
| ELF read helpers | 파싱 프리미티브 | `core/elf64.py` |
| *(대응 없음)* | — | `differential/*` — **Lfuzzer 고유 확장** |
| `test_fuzzed.sh` | 타겟 실행+분류 | `analysis/*` |

**Lfuzzer만의 확장 (Melkor에 없음):**
- `differential/` — gold-vs-BFD 링크, 링커-vs-로더, readelf-vs-Ghidra 세 축의
  **불일치**를 버그 신호로 삼는 차등 오라클 레이어.
- `triage/` — 차등/크래시 신호를 CASR 기반으로 authoritative하게 확정하는
  V5 파이프라인. LLM 자문(`mcp_advisor.py`)은 advisory only, 지표에 안 잡힘.
- `structure_aware.py`, `unified_runner.py`, `nezha_oracle.py` — 위 두 확장을
  뒷받침하는 이후 세션에서 추가된 접착/전략 모듈 (아래 §4).

**설계원칙 3가지 (MELKOR_MAPPING.md §2 요약):**
1. **메타데이터 의존성 레벨 준수하되 의도적으로 축소** — Melkor의 "깊은 레벨은
   나중/안 건드려야 커버리지↑" 원칙은 그대로 따르되, Lfuzzer는 SHDR/.dynamic/PHDR
   3영역으로만 스코프를 좁힘(링커/로더의 구조적 계약이라 static-vs-runtime,
   gold-vs-BFD 불일치가 실제로 존재할 수 있는 지점이기 때문).
2. **likelihood-gated 규칙 실행** — Melkor의 함수포인터배열+`-l` 확률게이팅을
   Python의 명시적 함수리스트 + 가중 `random.choice` + 시간예산 분할(60/40)로 재현.
3. **차등 오라클 (Lfuzzer 고유)** — 단일 파서 크래시가 아니라 "같은 바이트를
   BFD/gold/ld.so/analyzer가 다르게 해석하는가"를 신호로 삼음 — 아무것도 안
   죽어도 버그일 수 있다는 것이 연구 기여점.

---

## 3. Mutator별 실제 동작 상세

### core/ — ELF64 원시 읽기 프리미티브

**`core/elf64.py`** — 모든 뮤테이터가 공유하는 단일 진실원. 이전에는
`autorun_v3.class Elf`, `mutator_dynamic_v3.class Elf`,
`mutator_interp_vaddr_v2.parse_elf`가 각자 재구현하던 것을 통합.
- `u16/u32/u64` 리틀엔디언 리더 → `read_phdrs(data)` (e_phoff@0x20, e_phentsize@0x36
  기준 stride, 하드코딩 56 아님) → `iter_dynamic(data)` (PT_DYNAMIC의 p_offset에서
  16바이트씩, DT_NULL까지 최대 256엔트리) → `vaddr_to_offset(data, vaddr)`
  (PT_LOAD 순회, **filesz 기준**, memsz-aware 아님이 명시적 계약) →
  `section_by_name(data, name)`.
- 모든 함수는 순수 함수(부작용/랜덤/IO 없음). `_selftest()`가 `prac.elf`로 자체 검증.

### mutators/ — Melkor `fuzz_<metadata>.c` 대응 규칙 모듈

**`mutate_elf_v4.py`** — 최상위 필드테이블 뮤테이터, v3의 확장판.
- "ELF 필드별 퍼징 전략 — 전수 정리" 문서를 코드화. v3(DT_VERNEED/AUDIT/STRTAB만)
  → EHDR + PHT + DYNAMIC + VERNEED 구조인식까지 전수 확장.
- **2모드**: 모든 필드에 `violate`(검사 자체를 타격) / `keep`(변형 후
  `repair_pht`로 교차필드 불변식 재계산 — 파서가 더 깊이 도달하게 함) 두 모드.
- **`boundary_set(width, real, file_size, strsz)`**: `{0, 1, 최댓값, 최댓값-1,
  부호경계, 페이지경계(0x1000)}` + 실제값 기준(`real, real±1, real+0x1000,
  real<<1`) + 파일크기/strtab 크기 기준 OOB.
- **`repair_pht` 불변식(keep 모드)**: `p_align ∈ {0,1,2^n}`,
  `p_filesz ≤ p_memsz`, `p_offset+p_filesz ≤ 파일크기`,
  `p_vaddr ≡ p_offset (mod p_align)`.
- **EHDR 대상**: e_type, e_entry, e_phoff, e_phentsize, e_phnum.
- **DYNAMIC 대상**: `PTR_TAGS`(HASH/STRTAB/SYMTAB/RELA/INIT/FINI/JMPREL/
  INIT_ARRAY/GNU_HASH/VERSYM/VERNEED/AUDIT) / `OFFSET_TAGS`(NEEDED/RPATH/
  RUNPATH) / `SIZE_TAGS`(STRSZ/RELASZ/RELSZ/PLTRELSZ/INIT_ARRAYSZ)로 분류해
  boundary_set 파라미터를 다르게 줌.
- **VERNEED 구조인식(우선순위 최고)**: DT_VERNEED가 가리키는 Verneed(16B)/
  Vernaux(16B) 링크드리스트를 직접 순회하며 `vn_file`, `vn_cnt`, `vn_next`,
  `vna_name`, `vna_next`를 개별 타격. 근거: glibc `dl-version.c
  _dl_check_map_versions`가 이 필드들을 무검증 순회.
- **CLI**: `--only ehdr,pht,pht_offset,dynamic,verneed`, `--modes violate,keep`,
  `--max`, `--list`. SHA1 중복제거 + `MANIFEST.tsv` 동봉.

**`mutator_dynamic_v3.py`** — DYNAMIC 인식 뮤테이터(v4의 전신, VERNEED/AUDIT/PHDR
3카테고리만). 시스템 `ld.so`를 execve로 직접 실행.
- `gen_verneed`: vna_name/vn_file `[0xffffffff, strsz+0x100000, 0x41414141,
  0x7fffffff]`; vna_next/vn_next `[0x0, 0xffffffff, 0x10, 0xfffffff0]`;
  vn_cnt `[0xffff, 0x7fff, 0x100]`.
- `gen_audit`: DT_DEBUG 엔트리를 **DT_AUDIT로 재활용**(태그 자체를 덮어씀)하고
  값에 `strsz+0x1000 / 0xffffffff / 0x0` 주입 — glibc
  `audit_list_add_dynamic_tag` 겨냥. DT_STRTAB을 `0x0/0xffffffff`로 깨는 콤보도 생성.
- `gen_phdr`: p_offset(`fsz+0x1000, 0xffffffffffff, 0x7fffffffffffffff`),
  p_filesz(`0xffffffff, 0x7fffffffffffffff`), p_memsz(`0x7fffffffffffffff`
  고정), p_align(`0x0, 0x3, 0x1001`) 개별 타격.
- `classify(rc)`: ok / timeout(DoS?) / signal_N / execve_fail / exit_N.

**`mutator_field_v2.py`** — PHT 8필드(`p_type,p_flags,p_offset,p_vaddr,p_paddr,
p_filesz,p_memsz,p_align`) 변형. 모드A(단일필드)/모드B(콤보), 8워커
`multiprocessing.Pool`, `--seed`로 완전 재현.
- `p_type`은 항상 현재 파일에 실재하는 타입 중에서만 선택. `p_flags` 80%
  R/W/X 비트 하나 토글·20% 완전랜덤. `p_align` 80% 원값의 절반/2배·20%
  `{0,1,0x1000,0x10000}`. offset/vaddr/paddr/filesz/memsz는 80%
  `원값±0x3000`(near)·20% 전체범위 랜덤.
- `classify()`가 SIGSEGV/SIGABRT/SIGBUS/TIMEOUT/EXECVE_REJECT/OK/OTHER로 세분화.

**`mutator_interp_vaddr_v2.py`** — PT_INTERP p_vaddr 단일필드 변형(재설계판).
glibc rtld.c의 `while(*cp != '\0')`가 p_filesz를 안 보고 NULL까지만 순회한다는
분석에 따라 **p_filesz 부풀림 가설을 폐기**, p_vaddr 하나만 위험 위치로 이동.
- 4모드: A(unmapped), B(page_edge — 매핑 끝 페이지경계 바로 너머),
  C(null — `0x0/0x1/0x8/0x10/0x100/0x318`), D(inside — PF_X LOAD 영역 내부).
- `is_crash` 재정의: 단순 양수 exit(예: exit 127)은 크래시로 안 침.
  SIGSEGV/ASAN 리포트/TIMEOUT만 진짜 크래시.

**`mutator_shuffle.py`** — PT_NOTE/GNU_PROPERTY/GNU_EH_FRAME/GNU_STACK/
GNU_RELRO 제외 슬롯의 모든 순열(`itertools.permutations`) 재배치.
`--target ld|gold`. 이 뮤테이터의 발견("PHDR < INTERP", "PHDR < DYNAMIC"
순서규칙)이 이후 "PHT 순서보다 DT_ 태그 그래프가 새 버그 광맥" 가설 전환의 계기.

**`fuzzer_overlap.py`** — PT_LOAD 세그먼트 중첩. ELF psABI가 p_vaddr 오름차순만
요구하고 중첩을 명시적으로 금지하지 않는 스펙 공백 탐구. 8패턴: 완전겹침,
절반겹침, 역순 스왑, 마지막→첫번째 이동, 전체 통일, memsz 확장으로 다음 덮기,
갭없는 인접배치, vaddr=0.

**`structure_aware.py`** *(신규, MELKOR_MAPPING.md 미반영)* — AFL++ custom
mutator(`init/fuzz/describe/deinit` 심볼 계약). SOTA 대조군: AFLSmart(TSE
2019)/FormatFuzzer(TOSEM 2024)/RedQueen(NDSS 2019, AFL++ CMPLOG로 상보).
- **"유효성 그라디언트"**: GATE(항상 강제 복구 — magic/EI_CLASS/e_machine/
  e_phentsize=56/PHT 경계 클램프) vs SEMANTIC(낮은 확률 `p_repair_semantic`
  기본 0.15로만 복구 — DT_STRSZ vs strtab 끝, p_filesz/memsz 등)으로 필드 분리.
  GATE를 안 고치면 파일이 즉시 "ELF 아님"으로 버려져 낭비, SEMANTIC은 일부러
  불일치를 살려둬 무검증 순회를 때리는 게 목적.
- **현재 상태**: 문법인식 core(`_structure_aware_mutate`)는 **TODO — havoc
  폴백으로 위임 중**. 실제 동작하는 건 (1) 순수 파이썬 havoc, (2) GATE 강제복구,
  (3) `mutate_elf_v4.repair_pht` 재사용 SEMANTIC 선택복구(지연 임포트,
  pyelftools 없으면 `_repair_pht_pure` 순수 폴백).

### generators/ — Melkor `generators.c`+`numbers.h` 대응 (실제 구현됨)

**`numbers.py`** — 순수 상수 풀(I/O·난수 없음). 5개 의도풀: `SIZES`(18개 —
0/1/PAGE±1/S32_MAX/S32_MIN_AS_U/U32_MAX/32비트경계/U64_MAX 등), `OFFSETS`(파일
OOB용, 64GiB 근처 mmap 거부 경계 포함), `ADDRS`(NULL/non-canonical 48비트
경계/커널공간 `0xFFFF800000000000`), `STR_IDX`(strtab OOB), `MASKS`(정렬·플래그,
비-2의거듭제곱 `0x3` 포함). `STR_PAYLOADS`: 포맷스트링(`%s%s...`,
`%n%n%n%n`), ANSI 이스케이프, 비출력 제어문자, 비-UTF8, 오버롱(256B/4096B),
경로주입(`../../../etc/passwd`), 조기 NUL. `FIELD_INTENT`: 필드명→의도 매핑.

**`generators.py`** — `numbers.py` 풀에서 값을 뽑는 시드가능 생성기. **자체
`random.Random` 인스턴스**를 들고 다녀 전역 random 시드를 오염시키지 않음.
API: `gen_size/gen_offset(oob=)/gen_addr/gen_str_index/gen_str_payload/
gen_mask/gen_marker` + `gen_for_field(field_name)`(FIELD_INTENT 라우팅, 미지
필드는 SIZES 폴백) + `gen_packed(field_name, width)`(struct.pack까지 처리).
**현재 각 뮤테이터에 흩어진 하드코딩 리스트(`mutator_dynamic_v3.big=[...]`,
`autorun_v3.rbig()`)를 이 모듈로 교체하는 게 목적이지만, 아직 완전 이전은
안 된 상태** — 대부분 뮤테이터가 여전히 인라인 값 유지.

### logger/logger.py — Melkor `logger.c` 대응 (실제 구현됨)

`FuzzLogger` 클래스 — region(PHDR/SHDR/DYNAMIC)/field/rule/offset/old→new/
likelihood(Melkor `-l` 대응, 기본 0.10)/seg_idx/case_id 기록.
`.jsonl`(스트리밍 append)+`.json`(요약)+`.txt`(리포트) 3중 출력, `flush()`가
동시 생성. `set_verdict(case_id, verdict)` — 변형과 실행이 시점 분리돼 있어
실행 후 case_id로 결과를 나중에 연결. **아직 기존 뮤테이터들이 이걸로 완전히
갈아타지 않은 상태**(각자 `log_per_field.txt`/크래시 파일명 라벨을 따로 사용).

### orchestrator/ — Melkor `melkor.c` main 대응

**`autorun_v3.py`** — 자율 fuzz+triage 루프. `mutate()`가 카테고리
(`verneed`×2가중, `dynrand`, `strtab`, `audit`, `phdr`, `reloc`) 중 하나를
`random.choice`로 선택 → 시스템 `ld.so` execve 실행 → 크래시 시 gdb로
`sig, top_frame` 추출해 distinct site 분류 → `ld.so --verify`로 비실행 재현
확인 → `autorun_state.json`에 라운드 간 상태 누적. `ITAGS`: dynrand가 태그
자체를 바꿀 때 쓰는 DT_ 후보풀. 예산 60%(mutate)/40%(triage) 분할.
`--seed` 없으면 자동생성해 state에 기록(재현성 보장).

**`unified_runner.py`** *(신규, MELKOR_MAPPING.md 미반영)* — "collect-once,
dual-oracle" 통합 루프. 뮤턴트 1개당 관측벡터를 **한 번만** 수집해
crash-path 오라클(V5 `TriagePipeline`)과 divergence-path 오라클
(`nezha_oracle`)에 동시 공급 — 오라클마다 링크/실행을 반복 안 하는 게 목적.
5채널: (1)ld.so 직접실행 (2)gold 링크&실행 (3)bfd 링크&실행 (4)`readelf -a`
(5)`objdump -x`. (2)+(3)이 divergence 오라클 입력, (1)~(3) 크래시 신호가
crash 오라클 입력. 지표는 unique CONFIRMED bug 수만(coverage는 엔진이지
지표가 아님). MCP/LLM은 advisory only, CASR가 authoritative.

### differential/ — Lfuzzer 고유 (Melkor 대응 없음)

**`nezha_oracle.py`** *(신규, MELKOR_MAPPING.md 미반영)* — NEZHA(Petsios et
al., IEEE S&P 2017) δ-diversity 이식. gold/bfd/ld.so 3구현(`IMPLS`) 출력
튜플을 한 좌표로 보고, 처음 보는 조합을 AFL virtual-edge 피드백으로 되돌림.
Frankencerts(2014) accept/reject 불일치 아이디어를 HARD tier로 반영.
`STATUS_CLASSES = (accept-clean, reject-diagnostic, crash, timeout)` ×
`TIERS = (benign, soft, hard)`. **"다르다"는 novelty 신호만 생성** — 진짜
CONFIRMED 판정은 CASR/triage 몫, 이 오라클 자체는 버그를 판정하지 않음.
메인 AFL 커버리지 트랙과 별도 병렬 트랙(구현마다 subprocess 재실행이라 exec/s
비용 있음).

`exp_goldbfd_diff/`(D01~D24 가설 + R1~R8 런타임 리플레이), `parser_diff/`,
`tag_exp/`는 `docs/MELKOR_MAPPING.md` §2c에 이미 상세 서술(변경 없음).

### triage/ *(신규, MELKOR_MAPPING.md 미반영)* — V5 크래시 확정 파이프라인

**`pipeline.py`**: `TriagePipeline` — 크래시 1건당 `TriOracle.confirm()`으로
먼저 진짜 크래시인지 확인(미확정이면 즉시 종료, 지표에 안 잡힘) → 확정되면
`CasrDedup.bucket()`(authoritative 버킷/severity) + `MCPAdvisor.advise()`
(선택, **advisory only**) → `Verdict{confirmed, bucket_key, severity, splits,
tool_used}` 반환. splits(LLM 자문)는 절대 카운트에 안 씀.
**`casr_dedup.py`**: CASR(`casr-gdb`+`casr-cluster`) 우선, 없으면
`autorun_v3.gdb_site` 로직을 재현한 gdb 백트레이스 파서 폴백(스텁 아님).
`tool_used ∈ {casr, gdb-fallback}`.
**`tri_oracle.py`, `mcp_advisor.py`**: 각각 크래시 확정 판정기 / LLM 자문
래퍼로 추정 — 이번 조사에서는 상세 미조사(헤더만 확인).

### 이번에 상세 조사하지 않은 영역
`analysis/*.sh`(sprint 스크립트군), `harness/`(AFL 하네스+엔트리포인트),
`overlap_lab/overlap_perm_lab/iter01~30.py`(30개 순열 실험 반복본) — 필요하면
별도로 조사.

---

## 4. `docs/MELKOR_MAPPING.md`에 아직 반영 안 된 신규 모듈

07-31 세션에서 처음 조립된 이후 추가된 4종 + `harness/`:

| 모듈 | 위치 | 비고 |
|---|---|---|
| `structure_aware.py` | `mutators/` | AFL++ custom mutator, 문법인식 core는 TODO(havoc 폴백) |
| `unified_runner.py` | `orchestrator/` | collect-once/dual-oracle 통합 루프 |
| `nezha_oracle.py` | `differential/` | NEZHA δ-diversity 이식 |
| `triage/` (디렉터리 전체) | 최상위 신규 패키지 | CASR 기반 크래시 확정 V5 파이프라인 |
| `harness/` | 저장소 루트 | AFL++ 하네스(asan_harness.c 등) |

`docs/MELKOR_MAPPING.md`의 §1 표는 이 5개를 아직 다루지 않는다 — 갱신 여부는
사용자 확인 필요(다음 할 일 참고).

---

## 5. 다음 액션 후보

- [ ] `docs/MELKOR_MAPPING.md` §1 표에 위 5개 신규 모듈 행 추가
- [ ] `generators/generators.py` / `logger/logger.py`로 각 뮤테이터의 인라인
      하드코딩 값(`mutator_dynamic_v3.big=[...]`, `autorun_v3.rbig()` 등)을
      실제로 이전(현재는 모듈만 존재하고 아직 소비되지 않음)
- [ ] `structure_aware.py`의 `_structure_aware_mutate` 문법인식 core 구현
      (현재 TODO/havoc 폴백)
- [ ] `.claude/worktrees/readme-ko` 정리 — 필요시 `git worktree add`로 재생성,
      불필요하면 디렉터리 삭제 후 로컬 `readme-ko` 브랜치만 유지
