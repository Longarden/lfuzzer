# 파이프라인 개선 — baseline vs SOTA 대조군 vs 실험군 (근거·인용 부착)

> 목적: 사용자가 실제로 한 파이프라인(baseline)을, **오늘자(2026-08-01) 웹리서치로 세운 SOTA 대조군**과 대조하고,
> baseline을 개선하는 실험군 여러 개를 정의·판정한다. 모든 SOTA 주장엔 출처(제목·연도·링크). 미확인은 그렇게 표기(날조 금지).
> 판정 축 = **유니크 확정 버그/CPU-hour**(주) + 커버리지(엔진건강) + 차등수율(보조). 커버리지는 지표가 아니라 AFL 엔진.

---

## 0. 연구적으로 중요한 발견 2개 (먼저)

1. **"ELFuzz"는 가짜 친구(false friend)다.** USENIX Security 2025의 ELFuzz = "Evolution through Large-language-models For fuzzing"(Chen, Dolan-Gavitt, Lin) — **LLM 기반 문법퍼저 합성**이고 평가 대상은 cvc5(SMT 솔버). **ELF 바이너리 포맷·ld.so와 무관.** (arXiv 2506.10323 / usenix.org/…/chen-chuyang / github.com/OSUSecLab/elfuzz) → 볼트의 `ELFuzz - USENIX.md`를 "ELF 로더 퍼징 계보"로 인용하면 안 됨.
2. **노벨티 레인 확인.** 2022–2026 top-venue(USENIX/NDSS/S&P/CCS/WOOT/FSE/ISSTA)에서 **ld.so 또는 gold/bfd '링커'를 구체적으로 퍼징한 피어리뷰 논문을 못 찾음(NOT-FOUND).** OSS-Fuzz binutils는 BFD-라이브러리 진입점(readelf/objdump/nm/objcopy…)만 퍼징하고 **`ld`/`gold` 링크타임 동작은 대상 아님**(oss-fuzz/projects/binutils 직접 확인). glibc+ASan+libFuzzer는 "가능하나 수작업 많음"으로 문서화(턴키 아님). → **gold-vs-bfd / ld.so 차등 로더·링커 퍼징은 상위 학회에서 사실상 미청구.** 단, 검색 부재 ≠ 부재 증명 — ACM DL/IEEE Xplore 수동 확인이 다음 단계.

---

## 1. Baseline (사용자가 실제로 한 것 — 탐색으로 확정)

- 타깃: **생 프로덕션 ld.so** `/lib64/ld-linux-x86-64.so.2`, 통짜 뮤테이트 ELF를 `@@`로. 하니스·계측 없음(블랙박스).
- 시드: python 구조인지 뮤테이터가 prac.elf의 PHT/PT_DYNAMIC/verneed/strtab 한 영역씩 변형 → SIGSEGV/timeout만 보존 → `rebuild_seeds.sh` → `in_elf_v2/`.
- 퍼저: **AFL++ QEMU 바이너리모드** `afl-fuzz -Q -i in_elf_v2 -o out_qemu_v2 -t 1000 -m none -- /lib64/ld-linux-x86-64.so.2 @@` (main+2 secondary). 커버리지=QEMU 엣지.
- "ASAN"=오해: `-fsanitize=address` 빌드 없음. 실체는 `rerun_debug_ldso.py`가 **debug+assert glibc ld.so**(~/glibc/build-dbg)로 재실행해 assert로 버그 표면화. 진짜 ASAN+libFuzzer 하니스는 문서에만, `harness/` 없음. → 탐지는 segfault·timeout·assert만.
- 차등(gold/bfd): **별개 오프라인 트랙** — region-fill 드라이버가 AFL-계측 binutils ld-new 구동, gcov 라인커버리지 diff. ld.so QEMU 루프와 미연결(대상도 다름: binutils vs glibc).
- 트리아지: 사후 수동(auto_followup·sprint1~3·afl_unique showmap 디둡). 자동 되먹임 없음(mutator→시드 단방향).

### 약점 3
- **W1** QEMU 생-ld.so = 느림 + 메모리오염 눈뜬장님(안 죽는 힙오버플로 안 보임; 가짜 ASAN).
- **W2** AFL이 통짜 바이트뒤집기 → 대부분 ELF 매직/헤더검사에서 즉시 거부(too-invalid) → 얕은 도달.
- **W3** 차등·커버리지측정·재시드 전부 사후·수동·루프 밖 → 최강 신호(divergence)가 늦게, 손으로 발견되고 탐색을 못 이끔.

---

## 2. SOTA 대조군 (오늘자 웹리서치 · 인용 부착) — 이길 기준

| 컴포넌트 | SOTA 선택 | 출처(신뢰도) |
|---|---|---|
| 타깃 계측 | **소스모드**(afl-clang-fast/LTO, 충돌없는 엣지) + **CMPLOG/RedQueen**(매직/오프셋 비교 자동돌파). QEMU는 소스없을 때만. ld.so·gold·bfd는 소스빌드 가능 → 소스계측 우세. | AFL++ Fioraldi et al., **WOOT'20** usenix.org/system/files/woot20-paper-fioraldi.pdf (高) · CMPLOG 문서 github.com/AFLplusplus…/README.cmplog.md (高) |
| 오라클(탐지) | **libFuzzer+ASan 하니스**를 파싱 진입점(`_dl_map_object_from_fd`, `elf_get_dynamic_info`, verneed/versym)에서. 안 죽는 메모리버그 잡음. | LLVM libFuzzer docs llvm.org/docs/LibFuzzer.html (高) · glibc+ASan은 "수작업 많음" (中, absence-of-evidence) |
| 입력 모델 | **FormatFuzzer식 바이너리템플릿** 생성/변형(ELF 구조) + **AFLSmart식 청크인지** 변형(DT_ 태그 배열). 매직/헤더 게이트 통과 보장. | FormatFuzzer Dutra/Gopinath/Zeller **ACM TOSEM 33(2), 2024** DOI 10.1145/3628157 (高) · AFLSmart Pham et al. **IEEE TSE 2019** arXiv:1811.09447 (高) |
| 오라클(차등) | **Nezha δ-diversity 차등 오라클**: 같은 ELF를 {ld.so, gold, bfd}에 넣고 **행동 비대칭 최대화** 입력에 가점(accept/reject·심볼해석·relocation·crash/clean). | NEZHA Petsios et al. **IEEE S&P 2017** wcventure.github.io/FuzzingPaper/Paper/SP17_NEZHA.pdf (高) |
| 스케줄 | AFL++ power schedule + **MOpt** 변형스케줄, **afl-cmin** 코퍼스 최소화, 가능하면 **persistent mode**. | AFL++ features.md (高) · MOpt Lyu et al. USENIX'19 (中, 원논문 미재확인) · AFLFast Böhme CCS'16 (中) |
| 트리아지 | **CASR**(심각도+ASan/UBSan 리포트+`casr-cluster` 스택해시 디둡), GDB `exploitable` 교차, `afl-tmin` 최소화. **교차구현(gold≠bfd)엔 원시 스택해시 무의미** → 구현별 CASR 점수 + Nezha δ-diversity를 교차디둡 신호로. | CASR github.com/ispras/casr (高) · exploitable CERT/SEI (高) · CrashWalk github.com/bnagy/crashwalk (高) · GPTrace(LLM임베딩 디둡) arXiv:2512.01609 (高) |

**핵심 함의(합성, 단일출처 아님):** 스택해시 디둡은 *같은 코드베이스 안* 가정 → gold vs bfd(다른 코드베이스)엔 무의미. 구현별 CASR + δ-diversity로 교차디둡해야 함.

### 미확인/못 찾음(명시)
AFLSmart++ 학회(SBFT'23, 저자 PDF만) · Semantic Crash Bucketing 학회/연도(DOI 접두사 추정) · HTTP Garden 발표처(arXiv만) · MOpt 원논문 · glibc의 OSS-Fuzz 등록 여부 · **ld.so/gold/bfd 전용 top-venue 퍼징 논문(적극 검색, NOT-FOUND).**

---

## 3. 실험군 5개 = 대조군의 "위상 분해"이지 경쟁자가 아님

심판 핵심: **어떤 단일 변이도 대조군(13항목 조합)을 못 이긴다. 5개는 대조군을 단계로 쪼갠 것.** 그래서 결정은 "무엇"이 아니라 **빌드 순서**(유니크확정버그/CPU-hour ROI 기준).

| 변이 | 공격 약점 | = 대조군 항목 | 점수/판정 | 한줄 |
|---|---|---|---|---|
| **V1 진짜계측 타깃** | W1 | 1+2+6 (LTO소스+ASan+persistent) | 4 · DOMINATED(정직한 코어) | in-process persistent+진짜 ASAN: exec/s ~100–1000x + 안 죽는 메모리버그 가시화 |
| **V2 구조인지 입력** | W2 | 3+4+5 (grammar+커스텀뮤+CMPLOG) | 3 · DOMINATED | validity gradient: 게이트는 수리, 심층필드 불일치는 살림("파싱될만큼 유효, 깰만큼 무효") |
| **V3 차등 in-loop** | W3(+W1) | 7+8 (Nezha δ + N-version) | 3 · DOMINATED(최고 구현청사진) | 불일치를 가상엣지로 주입 → divergence가 탐색을 조종, 안 죽는 파서혼동 버그 |
| **V4 앙상블+환류** | W3 | 7+9+10+12 (앙상블sync+cmin+스케줄) | 3 · MOSTLY DOMINATED | 유일 알짜=자가급식 back-edge 데몬+이종 코퍼스 sync. QEMU-only 프레이밍은 버릴 것 |
| **V5 근거기반 트리아지** | W3(+W1) | 13(확장) | **4 · ADDS(유일하게 대조군 초과)** | CASR 권위 디둡 + in-loop tri-oracle 자동확정 + **MCP/LLM은 자문만(판정 불가)** |

### 추천 빌드 순서 (싸고 ROI 높은 것부터)
**V5 → V1 → V2 → V3 → V4(글루로만)**

1. **V5 먼저** — 빌드비용 ~0(기존 auto_followup/sprint/rerun_debug_ldso 감쌈). **지표 정의 자체를 결정론화**: CASR 스택해시가 비트맵 10–100x 과대유니크를 진짜 근본원인 버킷으로 접고, tri-oracle이 사람 없이 자동확정. **이게 있어야 이후 변이 이득을 정직히 측정 가능.** "이번 주 하나만? → V5."
2. **V1** — 최대 발견 승수(100–1000x exec/s + 진짜 ASAN 오라클). 나머지가 계측할 토대. "baseline 위 하나만? → V1."
3. **V2** — 구조인지 뮤테이터+validity gradient+CMPLOG를 **V1의 소스+ASan 타깃 위에**(V2 자체 QEMU 드롭인 말고) 얹어 게이트통과 뮤턴트가 심층 DT_/verneed 도달.
4. **V3** — Nezha 차등을 **병렬 트랙**(코퍼스 공유)으로. 안 죽는 버그류를 여나 처리량 음수 → 빠른 크래시경로 포화 후에 값어치.
5. **V4는 글루로만** — 통짜 빌드 금지(QEMU-only ld.so라 ASan 오라클 스킵=W1 후퇴). 알짜 2개(이종 코퍼스 sync + 자가급식 cmin/tmin back-edge 데몬)만 채택해 V1+V2+V3를 한 루프로 묶음.

---

## 4. V5가 사용자 미결질문(MCP 트리아지)에 주는 답

- **MCP/LLM은 자문(advisory)만. 판정(adjudicate) 절대 안 함.** 권위=CASR(유니크 집합·심각도 read-only). 규칙: **모든 LLM 주장은 도구결과(CASR 리포트·bt·필드diff·gcov)를 인용해야 하고, 인용 없으면 폐기.** 지표 숫자는 LLM을 절대 안 읽음 → 재현가능·결정론.
- LLM이 실제로 더하는 값: 스택해시가 **잘못 병합한 버킷을 분할**(같은 top frame, 다른 근본원인 → 진짜 유니크 회수) + 논문용 자연어 재현/교차오라클 가설. SOTA 대비(afl-showmap·CASR·exploitable·crashwalk·GPTrace)에서 **결정론 작업은 도구가, 의미론적 분할·서술만 LLM**이 얹는 자리.

---

## 5. 그래서 결정할 것 (다음 /deep-interview)
- 빌드 순서를 추천대로(V5→V1→…) 갈지, 아니면 다른 우선순위(예: 노벨티 위해 V3 차등을 앞당김)로 갈지.
- V1 하니스의 진입점 선택(어느 ld.so 파싱 함수부터) + precondition fixture 전략(phantom bug 방지).
- V5의 tri-oracle 구성(stock + debug-assert + gold/bfd)과 MCP 서버 도구 어댑터 범위.
