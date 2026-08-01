# Lfuzzer 전체 구조 감사 (2026-07-15)

멀티에이전트 워크플로우(5 클러스터 병렬 정독 → 종합 → 버그 대적검증) 산출물.
검증: 31개 버그 주장 중 CONFIRMED 23 / PLAUSIBLE 3 / REFUTED 4 / 미검증 1(안전분류기 차단).

---

## 1. 아키텍처 — 전체가 어떻게 도는가

타겟: GNU 툴체인 ELF 로더/링커 경로(glibc ld.so, BFD ld, gold, readelf).
구조: **5개 느슨하게 결합된 클러스터, 공유 코드 거의 없음.**

```
MUTATE ─┬─ (a) 구조인식 파이썬 뮤테이터: ELF64 PHT/DYNAMIC/VERNEED 직접 파싱 + raw 바이트 패치
        │       shuffle → field → field_v2 → dynamic_v3 → mutate_elf_v4 (+ interp_*)
        ├─ (b) AFL 리전 드라이버 (drivers/driver_*.py): AFL 바이트를 고정 구조영역에 타일링(결정론)
        └─ (c) 손으로 짠 결정론 differential 실험 (exp_e1..e6): 각자 상수 1개 뮤테이션
                                    │
RUN ────────────────────────────── │  ← 가장 약한 고리
        대부분 뮤테이트 ELF를 direct-execve (커널로더+ld.so만 닿음, execve 거부로 자주 튕김)
        건전한 레인만 ld.so 인자로 주거나 ld-new에 `-B` 심링크 트릭으로 먹임
                                    │
DETECT ──────────────────────────── │  ← 오라클 3개가 서로 모순
        exit!=0 (direct-exec, 오탐 범벅) / signal-or-timeout (autorun_v3) / AFL-signal-via-shell (run.sh, 시그널 은폐)
                                    │
TRIAGE ──────────────────────────── │  ← 성숙함
        auto_gdb_classify(병렬 (signal,frame0) 클러스터러) / triage_v3 / strace_classify(폴백)
        rerun_debug_ldso(디버그로더 리플레이) / minimal_repro_dl_load_885(단독재현 템플릿)
                                    │
LEDGER ──────────────────────────── autorun_v3 JSON 상태(rounds/runs/crashes/sites/seen_hashes, sha1 dedup)만 존재
```

**핵심 결론:** 프로젝트가 원하는 "랜덤 뮤테이트 → ld/gold/readelf/objdump/ghidra+ASAN 한 방에 → 자동 수집+트리아지" **엔드투엔드 루프는 하나로 배선돼 있지 않다.** 조각은 다 있지만 클러스터에 흩어져 있고, **크래시 정의와 실행 타겟에 대해 서로 합의가 안 돼 있다.**

---

## 2. 랜덤화 실태 — 재현성이 최대 부채

| 레짐 | 파일 | 상태 |
|---|---|---|
| 결정론/재현가능 (RNG 없음) | shuffle, shuffle_gold, mutate_elf_v4, dynamic_v3, exp_e1..e6, craft_extratag_poc, AFL 드라이버 | OK |
| 시드고정 재현가능 | auto_gdb_classify(seed=42), exp_e3 dry_run(Random(42)) | OK |
| **랜덤/재현불가 (문제)** | **mutator_field, field_v2(parallel은 pid^time), interp_vaddr_v2(pid^time), autorun_v3(전역 random 미시드, --seed 없음)** | **결함** |
| 죽은 RNG | interp_overflow(시드하지만 소비 안 함 → count N이면 N-1개 중복 실행) | 낭비 |

랜덤 레인은 라운드를 **리플레이 못 함.** 복구 수단은 사후적(저장된 크래시 ELF, sha1 이름, 로그된 값)뿐.
→ 진짜 퍼저가 되려면 **통합 시드 레이어**(mutator+field+value+target, CLI `--seed`, 시드를 상태 원장에 기록)가 필요. 그래야 크래시가 저장된 ELF가 아니라 **로그에서 재현**된다.

---

## 3. 버그 (검증 완료)

### 3-A. 최우선 — 시스템 전체를 오염시키는 신호 결함 3개 (전부 CONFIRMED)

| ID | 파일:라인 | 문제 | 수정 |
|---|---|---|---|
| **B03** | lfuzzer.py:47 | `"exit=0" not in status` → 모든 비영점 종료·TIMEOUT·ENOEXEC를 크래시로 저장 + ELF를 **직접 실행**(링커 안 거침). 크래시 코퍼스가 비-버그로 도배 | 신호사(음수 returncode)만 카운트; ELF를 링커 입력으로 |
| **B02** | drivers/run.sh:40 | `exit $ret`가 시그널사(139/134)를 평범한 종료코드로 전파 → AFL이 크래시를 정상종료로 오인(**전 크래시 은폐 가능**) | ret>128이면 `kill -$((ret-128)) $$` 재발생 |
| **B04** | autorun_v3.py:103 | `verify_repro`가 `ld.so --verify`(포맷체크만, 재배치·실행 안 함) → 진짜 크래시 옆에 verify=ok 표기, sites_summary 신뢰 불가 | 실제 재실행(ASAN 계측 로더)으로 교체 |

### 3-B. 크래시 오라클 오탐 (direct-exec + OTHER→crash)

| ID | 파일:라인 | 판정 | 문제 |
|---|---|---|---|
| B09 | interp_vaddr_v2.py:171 | CONFIRMED | `is_crash`가 `OTHER(*)` True → ld.so 거부(exit 127)·정상 비영점을 메모리크래시로 저장(interp_overflow도 동일) |
| B11 | fuzzer_overlap.py:63 | CONFIRMED | 동일한 `exit=0 not in` 술어, crashes_overlap/ 수동 재필터 필요 |
| B12 | autorun_v3.py:90 | CONFIRMED | 2초 타임아웃(rc124)을 크래시로 → 느린-정상 로드가 distinct-site 부풀림 |

### 3-C. 트리아지 정확도 (chmod 누락, 주소 오염, 라이브러리 경로)

| ID | 파일:라인 | 판정 | 문제 |
|---|---|---|---|
| B13 | auto_gdb_classify.py:62 | CONFIRMED | 크래시 ELF에 chmod +x 안 함 → gdb run이 EACCES → 전부 EARLY_NO_STACK 오분류(리포트 0화) |
| B14 | analyze_crashes.py:32 | CONFIRMED | `#0` 라인을 hex 주소 통째로 버킷키 → 같은 사이트가 싱글톤으로 쪼개져 unique 부풀림 |
| B05 | analyze_crashes.py:19 | CONFIRMED | timeout에 try/except 없음 → 행 하나가 배치 전체 중단, 결과파일 안 써짐 |
| B06 | attribute_lines.py:9 | PLAUSIBLE | `--library-path` 누락(rerun_debug_ldso는 넘김). 단 phdr/dynamic 단계 크래시엔 영향 없음 — "전면 신뢰불가"는 과장, 조건부 |

### 3-D. 뮤테이션 낭비/무효 (중복 생성, 매핑 안 닿는 프로브)

| ID | 파일:라인 | 판정 | 문제 |
|---|---|---|---|
| B01 | interp_overflow.py:126 | CONFIRMED | PT_INTERP를 EOF 페이로드로 재지향 + direct-exec → 매번 ENOENT/EXECVE_REJECT, ld.so strcmp 경로 절대 안 닿음(파일 통째 죽은 실험, vaddr_v2가 대체) |
| B07 | mutate_elf_v4.py:189 | CONFIRMED | keep-mode PHT 극단값을 repair_pht가 동일 바이트로 클램프 → --max 예산을 중복파일에 소모 |
| B08 | interp_overflow.py:256 | CONFIRMED | 그리드에 range(count)인데 payload는 결정론 → (N-1)/N이 바이트동일 중복실행 |
| B10 | interp_vaddr_v2.py:103 | **미검증** | Mode B가 매핑 안(내부)을 겨냥 → over-page-edge 프로브 실제로 안 됨 (안전분류기 차단으로 검증 못 함) |
| B22/B23 | mutate_elf_v4.py:213/311 | CONFIRMED | keep==violate 바이트동일(EHDR); _verneed_jobs가 --modes 무시 |

### 3-E. 저심각도 CONFIRMED (요약)

B16(exp_e5 `set -e`가 링크실패 시 VERDICT 안 뜸), B17(pgrep 15자 truncation → `cat /proc//maps` 죽은 라인), B18(autorun 미시드), B19(mutator_field PHDR_SIZE=56 하드코딩, e_phentsize 무시), B20(p_flags에 ±0x3000 델타 = 3비트 필드에 쓰레기), B21(`ec==139` 죽은 분기, SIGABRT/BUS 오분류), B28(set 슬라이스로 recency 안 지켜짐 → 중복 재저장), B29(run.sh `|| exit 0`가 드라이버 실패 은폐), B31(exploit_analyze_dtors 카운터가 error dict에서 KeyError).

### 3-F. 반증됨 (REFUTED) — 이것들은 버그 아님, 손대지 말 것

| ID | 판정 근거 |
|---|---|
| B15 | strace가 실패한 execve를 `execve(EACCES)`로 크게 찍음 → "빈 히스토그램" 전제 거짓(오히려 반대) |
| B25 | loc는 절대 `''`가 아님(파싱실패 기본값 "UNKNOWN") → `loc in k` 오탐 안 생김 |
| **B26** | **디렉토리에 478개 크래시파일뿐, 확장자 0개. 제안된 `.elf` 필터는 478개를 전부 0으로 날리는 파괴적 수정** |
| B30 | `pf`는 p_filesz 올바르게 읽음; v2o의 filesz 매핑이 정답(.bss는 파일오프셋 없음) |
| B24 | (PLAUSIBLE 하향) no-op은 p_align==0에서만, ==1은 아님 → 주장의 절반 |
| B27 | (PLAUSIBLE 하향) 메커니즘 맞으나 ('?','??') 버킷이 이미 구분됨 → 영향 낮음 |

---

## 4. 중복 지도 & 정리 권고

**폐기/죽은 코드(legacy/로):** mutator_field.py(field_v2가 완전 대체), interp_overflow.py(vaddr_v2 docstring이 은퇴 선언), analyze_crashes.py(triage_v3가 대체), lfuzzer.py(임포터 없는 죽은 모듈).

**95% 클론 → 파라미터화:** shuffle_gold=shuffle의 복사(--target {ld,gold}), driver_header/segment/dynamic → 하나로(--region).

**중복 프리미티브 → 공유 모듈 추출:** ELF64 PHT 파서가 8곳+ 재구현, PT_DYNAMIC 워크가 5곳 재구현, section-by-name 워크 중복.

**권고 우선순위:**
1. `elf64.py` 공유 모듈(PHT 파서, DYNAMIC 워크, v2o vaddr→offset, section-by-name) 추출 후 8곳 이관.
2. 죽은 4파일 legacy/로.
3. 클론 2쌍 파라미터화.
4. **크래시 오라클 하나로 통일**: "시그널사(SIGSEGV/ABRT/BUS) OR ASAN 비영점 OR 확증된 타임아웃", 나머지 술어 전부 삭제. **뮤테이트 ELF를 절대 direct-execve 하지 말 것 — 항상 타겟 도구 입력으로.**
5. 통합 `--seed` 레이어.
6. 신호결함 3개(B02/B03/B04) 먼저 — ROI 최고.

---

## 5. 자동화 자산 — 있는 것 vs 새로 지을 것

### 이미 있음(재사용 가능, 플래그된 수정 후)
- **생성:** mutate_elf_v4(가장 강함 — 필드테이블 스윕+repair+MANIFEST+chmod), dynamic_v3(VERNEED/AUDIT/STRTAB 메타 뮤테이터), autorun_v3.Elf.mutate(유일한 구조인식 랜덤 뮤테이터), exp_e*(자립 오프셋문서화 1필드 프리미티브 6종 → 디스패치테이블에 바로), AFL 드라이버(가장 건전한 뮤테이션 프론트엔드, 바이트 containment assert).
- **실행+diff:** exp_e2/run_exp.sh(가장 깔끔한 "한 입력 여러 도구 diff" 오라클: BFD ld-new vs gold ld-new, rc+stdout+stderr+산출물 캡처 후 diff+readelf 비교), exp_e3.link_case(재사용 per-cell 러너), interp_vaddr_v2/field_v2(mp.Pool imap_unordered 워커 스켈레톤 + ETXTBSY-safe tmp + 5s timeout).
- **트리아지+원장:** auto_gdb_classify.run_gdb_on_elf(frame0+rip+bt5, MP-safe, 자연스러운 트리아지 워커) + is_known 신규성 게이트(B25 먼저), rerun_debug_ldso.top(유일하게 올바른 디버그로더+library-path 호출), strace_classify(스택없는 폴백), minimal_repro 템플릿, auto_followup.sh(si_code/si_addr 패밀리 추출), autorun_v3 JSON 원장.

### 새로 지어야 함(전무)
1. **도구-러너 추상화** — `[tmp]`(direct-exec) → `[tool, tmp]`로 일반화. 현재 코드베이스는 ld/gold/readelf/strace/gdb만 닿음. **objdump·ghidra 싱크는 아예 없음**(ghidra=headless analyzeHeadless, objdump=파싱타겟 추가 필요).
2. **ASAN 레인** — ASAN 계측 ld/gold/readelf/objdump 빌드·실행하는 게 전무, ASAN stderr 시그니처로 키잉하는 오라클 없음. classify를 시그널/타임아웃 전용 → ASAN 리포트 파싱으로 확장, 크래시 정의를 "ASAN리포트 OR 시그널"로.
3. **통합 시드 랜덤 디스패처** — mutator+field+value+target 뽑고 시드 기록. 현재 생성은 결정론 하드코딩 아니면 미시드-리플레이불가, 중간 레이어 없음.
4. **코퍼스/시드 피더** — 모든 실험이 단일 입력 하드코딩(prac.elf/base.elf). 시드선택·커버리지피드백 루프 없음.
5. **단일 크래시 오라클 + 자동 수집+트리아지 배선** — 모순 오라클 3개를 하나로, 흩어진 생성/실행/트리아지 스테이지를 한 루프로.

### 권장 조립
```
공유 elf64.py
  → 시드 뮤테이션 디스패처 {v4.build_jobs, dynamic_v3 생성기, exp_e* 프리미티브, AFL 드라이버}
  → exp_e2/e3 스타일 멀티도구 러너를 N도구 × M입력으로 일반화 (objdump/ghidra + ASAN 빌드 포함)
  → 단일 시그널/ASAN 오라클
  → auto_gdb_classify + rerun_debug_ldso + strace 폴백 트리아지 싱크
  → autorun_v3 스타일 JSON 원장(시드기반 리플레이)
```
