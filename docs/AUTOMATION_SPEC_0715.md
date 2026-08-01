# Lfuzzer 자동화 모델 — Deep Interview Spec (2026-07-15)

## Metadata
- 방식: OMC deep-interview (Socratic), threshold 20%(default)
- 무게중심: **differential(의미-divergence) 중심 · ASAN은 "증거 계기"**
- 목표 한 줄: 흩어진 수작업(뮤테이트→여러 도구→크래시/desync→ASAN→트리아지)을 **시드로 재현되는 단일 자동 파이프라인**으로 배선한다.

---

## 확정 토폴로지 (5 컴포넌트, 연구가치 우선순위)

### 1. 생성 (Generation)
- **3영역**: 프로그램헤더(PHT) · 다이나믹 섹션(DT_ 그래프) · 섹션헤더(SHT). **한 파일엔 한 영역만** 뮤테이트(귀속 깔끔). 교차영역은 v1 제외(v1.1 후보).
- **도메인특화**: DT_ 엔트리 + 결합구조(VERNEED/VERDEF/GNU_HASH/versym/d_ptr + 인접 IFUNC/TLS). 전체-ELF 무작위는 얇은 대조군으로만(포화 영역).
- **커버리지 유도**: 구조인식 커스텀 뮤테이터 + **libFuzzer 커버리지 피드백**(컴포넌트 3의 하네스가 그대로 libFuzzer 타겟 → 피드백 공짜). AFL 바이트뮤테이션(구조 파괴) 대신.
- **재현성**: `--seed` 레이어 (이미 구현됨, refactor/mutation-optim-0715). 시드+region+field+value를 원장에 기록 → 크래시가 저장 ELF가 아니라 **로그에서 재현**.
- 재사용 자산: mutate_elf_v4(코퍼스 생성기), mutator_dynamic_v3(DT_ 메타), autorun_v3(구조인식 랜덤), exp_e*(1필드 프리미티브), elf64.py(공유 파서, 신규).

### 2. Differential 오라클 (지적 중심)
- **판정규칙**: 전부 기록 + **사후 랭킹**(ld.so연루 · 재현성 · 신규성). 버리지 않음.
- **divergence 2종**: ① 크래시-divergence(한 도구만 죽음) ② **의미-divergence(안 죽는데 해석 갈림 = evasion 광맥)**. ld.so를 대질의 앵커로.
- **v1 도구 세트 = 전부**: ld.so(런타임) · ASAN 하네스 · readelf · objdump · pyelftools · r2 · **Ghidra headless** · ld/gold ASAN(링크타임). 티어드 실행(치트 파서 전량 → 갈리는 것만 Ghidra 승격, Ghidra는 파일당 초~분).
- 재사용: exp_e2/run_exp.sh(멀티도구 diff 원형), exp_e3.link_case(per-cell 러너).

### 3. ASAN 계기 (증거엔진, extract-and-harness)
- 라이브 ld.so ASAN은 **부트스트랩 불가**(맨 처음 도는 코드 = ASAN 런타임보다 먼저 실행). 설정 토글로 못 뚫음.
- **해결 = extract-and-harness, fd-매핑 seam에서 절단**: 하네스(정상 부트스트랩된 ASAN 프로세스)가 뮤테이트 ELF를 `_dl_map_object_from_fd` 이하로 넘겨 로더 코드가 l_info를 스스로 채움 → 충실도 확보 + 부트스트랩 우회.
- **가짜버그 필터(필수)**: 하네스 ASAN 버그 → 같은 입력을 라이브 디버그 ld.so+GDB로 재실행해 그 함수·라인 **도달성 확인**. 안 닿으면 하네스 아티팩트로 기각. (당신 e6 방법 재사용) 하네스=정밀 오라클, 라이브=도달성 오라클, 곱해야 신뢰.
- 하네스 대상 함수: elf_get_dynamic_info(get-dynamic-info.h), dl-version.c(VERNEED/vna_name), dl-load.c:885(pt_gnu_property), dl-setup_hash.c(GNU_HASH).
- gold/readelf/objdump는 일반 바이너리라 `-fsanitize=address` 직접 빌드(부트스트랩 벽 없음).
- 하네스는 동시에 **libFuzzer 타겟** → 컴포넌트 1의 커버리지 피드백 제공.

### 4. 트리아지 + 원장 (풀 옵저버빌리티)
- **입력 1개당 1레코드**: seed · region · **도구별 관측벡터 전체**(differential 표) · 크래시/ASAN 판정 · 도달성게이트 결과 · 커버리지-신규? · ASAN 리포트.
- 24k+ 규모 → **컴팩트/컬럼나 저장**(예: parquet/sqlite, raw ELF 아닌 seed로 재현) 필요.
- 트리아지 싱크 재사용: auto_gdb_classify(frame0+rip, 신규성 게이트) · rerun_debug_ldso(디버그로더+library-path) · strace_classify(폴백). 단일 크래시 오라클(시그널사 OR ASAN OR 확증타임아웃)로 통일, direct-execve 금지.

### 5. 회귀 (검증 코퍼스)
- 기존 478/24k 데이터셋을 새 파이프라인에 재생 → 파이프 검증 + 소급 differential/ASAN 데이터. v1 포함.

---

## 전제작업 (Prereqs — 사용자가 WSL에서)
- [ ] Ghidra headless 설치(analyzeHeadless) + DYNAMIC/심볼 덤프 postScript
- [ ] ld/gold ASAN 빌드(`-fsanitize=address`; gold는 all-gold 격리빌드로 doc/aoutx.stamp 회피 — step3에서 확립)
- [ ] readelf/objdump ASAN 빌드
- [ ] libFuzzer 하네스(fd-매핑 seam) 스캐폴드 — 최초 PoC = elf_get_dynamic_info 하나
- [ ] r2/rizin 설치

## Non-Goals
- 라이브 ASAN rtld(부트스트랩 근본 불가) — 하네스로 대체
- IDA Free 무인 자동화(라이선스 금지) — 수동 스팟체크만, radare2가 대체
- 전체-ELF 깜깜이 퍼징을 주력으로(포화) — 얇은 대조군만
- 교차영역 동시 뮤테이션(v1) — 한 파일 한 영역

## Constraints
- WSL Ubuntu(HOME=/home/garden), CPU 코어 퍼징(GPU 불가), binutils-2.42-afl, glibc-2.39
- 이 대화 맥락에서 Claude Bash/Workflow/Artifact가 안전분류기에 자주 차단 → 실행은 사용자가 `!`로, Claude는 설계/해석. 분류기 우회 금지.
- **재현성 계약**: 모든 크래시/divergence는 seed+로그에서 재현(저장 ELF 의존 금지).

## Acceptance Criteria (테스트 가능)
- [ ] 같은 seed → 동일 뮤테이트 입력 + 동일 관측벡터 결정론적 재현
- [ ] 뮤테이트 ELF 1개가 v1 전 도구를 한 번에 통과, 도구별 관측행 산출
- [ ] differential 오라클이 도구판정 갈리는 입력 전부 플래그 + 랭킹(ld.so연루/재현/신규)
- [ ] ASAN 하네스가 로더 파싱함수 메모리버그 보고, **모든 보고는 라이브 도달성 게이트 통과분만** 인정
- [ ] libFuzzer 커버리지 피드백이 하네스 구동(신규커버리지 입력 보존)
- [ ] 478/24k 재생 → 풀 옵저버빌리티 원장 기록
- [ ] 회귀 무손실: 기존 확정 발견(EXTRATAGIDX desync, RUNPATH 하이재킹, 패밀리1/2) 재현

## 조립 순서 (권장)
```
elf64.py(완료) → 하네스 PoC(elf_get_dynamic_info, fd-seam, libFuzzer)
  → 도달성 게이트(rerun_debug_ldso 연결) → 멀티도구 러너(exp_e2 일반화, N도구)
  → differential 오라클 + 풀옵저 원장 → 시드 뮤테이션 디스패처(3영역)
  → 478/24k 회귀 → 랭커
```
```
```
