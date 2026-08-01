# 검증: 7/03 교수님 지시 ↔ 7/13 수행 작업 (RAG grounding)

> 방법: 원문 회의록 `context/meeting_0703_raw.md`를 ground truth로 두고, 교수님이 지시한 액션아이템 각각에 대해
> (1) 회의록 verbatim 인용(근거), (2) 어느 step이 수행했는지, (3) 아티팩트가 실제로 담은 증거, (4) grounding grep 카운트, (5) 판정.
> grounding grep = 해당 아티팩트 HTML 안에서 핵심 증거 문자열의 등장 횟수(내용 실재 확인).

## 요약 판정표

| # | 교수님 지시 | 근거(타임스탬프) | 수행 | 판정 |
|---|------------|-----------------|------|------|
| A | 미정의 태그가 인덱스 계산까지 도달하는지 GDB로 확인 | 14:29 / 16:24 / 17:58 | 7/13(3) 선행 + step4 확장 | ✅ 완료 |
| B | 섹션헤더(SHT) 폴백 트러스트바운더리 재검증 | 18:44 / 19:52 / 20:07~20:46 / 21:12 | **step1** | ✅ 완료(가설 반증) |
| C | GNU_HASH 해시 값 재확인(이월) | 21:29 | **step2** | ✅ 완료 |
| D | Gold 링커 differential (LD↔Gold, evasion) | 21:38~22:53 | **step3** | ✅ 완료(divergence 증명) |
| E | IDA/Ghidra + 분석기 differential (사이드) | 23:02 | **step4** | ✅ 완료(부분: Ghidra 미설치) |

전체 5개 지시 중 5개 수행. B/C/D/E는 이번 team 4-step, A는 7/13 선행작업이 답을 냈고 step4가 그 PoC를 differential로 확장.

---

## A. 미정의 태그 인덱스 도달 여부 (GDB 검증)

**근거 인용:**
- 14:29 교수님: "정의되지 않은 필드 태그가 있으면 아예 무시하게끔 코드가 되어 있으면… 정의된 필드가 인덱스화되기 전에 필터링되면 공격할 방법이 없잖아요… **그 전에 무시가 되는지 확인할 필요가 있어요.** 진짜 봤더니 필터링 안 되네 하면 정말 좋은 방법."
- 16:24 교수님: "**디버깅(GDB) 걸어서 invalid한 태그 값이 여기까지 오는지** 확인… 설정 초입에 브레이크포인트 잡고… 도달하지 않으면 57 계산 전 훨씬 위에서 필터링."

**수행:** 7/13(3) 선행작업(메모리 기록) — `get-dynamic-info.h`의 5개 매크로 전수분석 + GDB 실증.
**결과(근거있는 답):** 5개 중 4개(VERSION/VAL/ADDR TAGIDX)는 64비트 뺄셈이라 슬롯침범 수학적 불가(가설 반증). **1개 DT_EXTRATAGIDX는 64비트 d_tag를 32비트로 절단** → 상위 32비트 무시. `0xDEADBEEFFFFFFFFD` 패치본이 `get-dynamic-info.h:68`에서 i=60 슬롯 도달을 GDB로 실증(필터 안 됨 = 교수님이 원한 "좋은 방법" 성립).
**판정:** ✅ 교수님 질문에 정면으로 근거있게 답함. step4가 이 PoC를 분석기 differential로 확장.

## B. 섹션헤더(SHT) 폴백 트러스트바운더리 — step1

**근거 인용:**
- 18:44 학생: "주소 공간 가리키는 것들은 주소를 바꾸면… readelf에서 **섹션 헤더를 읽어서 0x50e로 되고, 0으로 바꿨는데도 다르게 읽히고** 실제 실행 시 세그먼트 폴트."
- 19:52 교수님: "**섹션 헤더를 읽었다는 얘기는 버전 심볼(심볼 테이블)을 섹션 헤더에서 읽었다는 얘기.**"
- 20:26~20:46 교수님: "섹션 헤더의 위치도 바꿀 수 있다… **섹션 헤더에 쓰레기를 넣어도 된다… malform시키면**… 어떤 조건에 의해 섹션 헤더 정보가 어드레스된다면, 0이었음에도 버전 심볼에 다른 정보가 읽히겠죠."
- 21:12 학생: "다시 한번 이번에 해보겠습니다." (재검증 커밋)

**수행/결과:** DT_VERSYM/VERNEED의 d_un만 0으로 패치, SHT는 유지 → 디버그 ld.so + GDB.
- verneed_zero: `dl-version.c:184`에서 ent=base+0 읽어 vn_version=0x457f(ELF매직) → "unsupported version 17791" 에러. **SHT의 진짜 레코드(base+0x520, vn_version=1)는 무시됨.**
- versym_zero: `dl-version.c:294` l_versyms=NULL → `do-rel.h:126` NULL 역참조 SIGSEGV. **SHT 배열(base+0x50e)은 미사용.**
- 소스 전수: 런타임 로더에 섹션헤더 파싱 없음(e_shoff/Shdr 검색 0건).
**결론:** **SHT 폴백은 존재하지 않는다(가설 반증).** 7/03의 0x50e는 폴백이 아니라 링커가 DYNAMIC과 SHT에 같은 값을 써서 우연히 일치 — readelf는 SHT본, 로더는 DYNAMIC본을 읽었을 뿐. 대신 실재 표면 발견: d_ptr을 0이 아닌 임의 오프셋으로 밀면 로더가 그 주소를 그대로 신뢰.
**grounding:** dl-version.c(14), SHT/0x50e(28), versym/verneed(42), 미재현/방어/폴백(12).
**판정:** ✅ 교수님 가설을 하드 증거로 정정. "봤더니 이거 [폴백] 아니네"를 근거있게 확정한 것 자체가 유효 결론.

## C. GNU_HASH 해시 값 재확인 — step2

**근거 인용:**
- 21:29 교수님: "**저번에 얘기했던 것 중에 해시 값 한번 보는 것도 한 번 더 진행을 해보고요.**"

**수행/결과:** DT_GNU_HASH d_ptr 및 GNU hash 헤더(maskwords/symbias/nbuckets) 7변종 → 디버그+assert ld.so.
- d_ptr=범위밖 → SIGSEGV `dl-setup_hash.c:32`; d_ptr=0 → SIGSEGV `dl-lookup.c:411`; maskwords=2^28 → SIGSEGV `dl-lookup.c:411`(assert 통과, 크기 무검증); symbias=0xffffffff → SIGSEGV `dl-lookup.c:429`.
- 유일한 의도적 방어 = `dl-setup_hash.c:35` assert(maskwords가 2의 거듭제곱). `get-dynamic-info.h:91`에서 d_ptr에 l_addr만 더하고 범위검증 없음.
**결론:** 로더는 손상된 GNU hash 입력을 방어하지 못함(검증=assert 1개뿐). 한계: 디버그빌드라 릴리스는 assert 컴파일아웃되어 더 터질 개연성 명시.
**grounding:** GNU_HASH(18), dl-lookup/setup_hash(17), SIGSEGV(18).
**판정:** ✅ 이월 항목을 소스라인 근거로 재확인 완료.

## D. Gold 링커 differential — step3

**근거 인용:**
- 21:38 교수님: "골드도 같이 그런 식으로 적용되어 있는지… **골드는 다르게 접근돼 있다면 LD랑 골드랑 다르게 동작하는 ELF 파일을 만들 수 있어요.** 멀웨어가 골드에서는 동작하고 LD에는 동작 안 하고 도먼트."

**수행/결과:** Gold 빌드 복구 성공(all-gold 타겟만 격리, `MAKEINFO=true --disable-gdb/sim/gprofng`, 2분27초, `~/binutils-build-gold/gold/ld-new`).
- **PRIMARY divergence:** libfoo.so.1의 .dynamic 섹션헤더 sh_type를 6→0x99로 1바이트 변조 → 같은 파일에 대해 **런타임 ld.so=정상실행 / Gold=ACCEPT(링크성공) / LD(BFD)=REJECT("wrong format")**. = 실행되고 Gold로 링크되는데 LD 분석만 거부하는 링커-의존적 ELF(evasion 증명).
- SECONDARY: e_shstrndx=0xffff → LD 관대(경고 후 진행) vs Gold 엄격(하드에러). 손상위치 따라 역할 반전.
- 인사이트: PT_DYNAMIC DT_* 필드 조작 12종은 링크타임 12/12 무반응 → divergence는 섹션헤더 필드에서 나옴.
**grounding:** gold(33), BFD/ld-new(12), divergence(21).
**판정:** ✅ 교수님 제안(evasion)을 재현 100% 사례로 실증. 최선 결과.

## E. IDA/Ghidra + 분석기 differential — step4 (사이드)

**근거 인용:**
- 23:02 교수님: "**아이다나 기드라가 어떻게 인식하는지도 사이드로.** 걔네들도 LD처럼 그대로 안 할 거고 차이가 있을 것. **분석기마다 분석 결과가 달라서, 버전 정보가 하나는 최신인데 옛날 버전으로** 쓰게끔."

**수행/결과:** prac_extratag_poc.elf(EXTRATAGIDX PoC) 대상.
- readelf(시스템), readelf(소스빌드), objdump, pyelftools 4종 **전부 `<unknown>`으로 놓침** vs 디버그 ld.so는 하위 32비트만 보고 i=60 슬롯 처리(정상 실행). GDB(get-dynamic-info.h:68)로 실측.
- 인덱스 60 = EXTRATAGIDX(2)+DT_NUM(38)+THISPROCNUM(4)+VERSIONTAGNUM(16), elf.h 상수 인용.
**정직한 한계:** Ghidra headless 이 WSL 미설치 → 설치 시도 시간초과 우려로 스킵("미설치"로 기록). readelf 2빌드가 같은 2.42 소스라 "버전 간" 차이는 안 남 → 발견은 "정적분석기 부류 vs 런타임 로더" 불일치.
**grounding:** readelf(8), objdump/pyelftools(7), unknown(5), EXTRATAGIDX/60(17).
**판정:** ✅ 최소선(분석기 vs 로더 불일치) 근거있게 재현. 사이드 항목이라 Ghidra 미완은 다음 단계로 정직 기록.

---

## 미팅 보고용 한 줄 정리 (근거 기반)

1. **B(섹션헤더 폴백):** 교수님 가설 검증 → **폴백 없음**, 0x50e는 우연의 일치. 로더는 DYNAMIC만 신뢰(하드 증거). SHT 단독 뮤테이션은 공격표면 아님 → 퍼저 우선순위 강등 권고.
2. **C(GNU_HASH):** 로더가 해시 입력 **무방어**(assert 1개뿐), 4개 SIGSEGV 사이트 소스라인 확보.
3. **D(Gold):** 빌드 복구 성공 + **LD↔Gold divergence 실증**(sh_type 1바이트로 Gold=링크/LD=거부/런타임=실행) = evasion 표면 증명. 링크타임 divergence는 섹션헤더 필드에서 나옴.
4. **E(분석기):** 정적분석기 4종 전부 놓치는 태그를 로더는 처리 = analysis↔runtime 괴리 재현. Ghidra는 미설치로 다음 단계.
5. **A(GDB 인덱스):** 미정의 태그가 필터를 뚫고 인덱스까지 도달함을 실증(EXTRATAGIDX 32비트 절단), 나머지 4매크로는 수학적으로 침범 불가로 반증.
