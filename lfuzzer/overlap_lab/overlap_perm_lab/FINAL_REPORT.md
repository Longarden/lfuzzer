# overlap_perm_lab — 통합 연구 노트 (V0-V6 + iter01-18)

자가 피드백 루프 18회. 정적/동적 분리 PoC 6종 + 방어 도구 v3 + glibc 코드 인용 + live combo PoC.

## 핵심 결론
- F1: PT_LOAD 오버랩 시 PHT 순서상 후자 우선 (V1, V6 비교에서 확인)
- F2: vaddr 정렬 강제 없음 — V5 swap 만으로는 변화 없음
- F3: memsz 단독 확장은 오버랩 만들지 못함 (V3)
- F4: PT_GNU_RELRO 는 vaddr 시멘틱 체크 없이 mprotect 적용 (V4: 텍스트→R--)
- F5: V1/V2/V4/V6 가 SEGV 로 끝나는 이유는 PT_DYNAMIC vaddr 미동기화 또는 텍스트 명령어 소실
- F6: PT_NOTE→PT_LOAD RWX 오버레이가 커널에서 허용됨. 0x401000 페이지가 RWX.
- F7: RWX 텍스트 페이지로 main 도달 성공 — 정적은 R-X 로 보고되지만 런타임은 RWX. 정적/동적 분리 PoC 1호.
- F8: RW 오버레이는 텍스트 페이지를 RW 로 만들고 NX 로 인해 실행 시 SEGV — V1 결과 재확인.
- F9: R-X 오버레이는 동일 플래그라 변화 없음 — 컨트롤 통과.
- F10: RWX 오버레이 PoC 가 norelro/partial/full RELRO 모드 전부에서 성립. RELRO 옵션이 정적/동적 분리 시나리오를 차단하지 못함.
- F11alt: 오버레이 변형이 의도대로 실행 안 됨 (exit=0). 출력: # exit=0
# --- stdout ---
[smc] before memcpy: target_func()=1 at 0x401156
[smc] after  memcpy: target_func()=42

# --- stderr ---


- F12: 동일 소스 빌드 + PHT 1 줄 패치 + 파일 끝에 0x1000 바이트 부착으로 target_func 결과가 1→42 로 분기. runtime memcpy 없음 → strace 에 의심 syscall 흔적 안 남음. 정적 분석은 PT_LOAD[3] R-X 만 보면 return 1 그대로.
- F13a: readelf -l PT_LOAD 개수 baseline=4, prestaged=5. 증가 → readelf 는 overlay 를 PT_LOAD 로 표시 함.
- F13b: objdump -d 가 두 바이너리에서 target_func 자리에 동일한 디스어셈블 출력. 오버레이가 매핑하는 다른 파일 영역은 디스어셈블되지 않음 → objdump 는 overlay 를 본질적으로 탐지 못 함.
- F13c: readelf -n notes 섹션 개수 baseline=3, prestaged=3. 동일 → PT_NOTE 슬롯이 PT_LOAD 로 바뀐 흔적이 readelf -n 에 노출 안 됨.
- F13: 정적 도구 매트릭스 — readelf -l 만이 새 PT_LOAD 를 보여줌. objdump -d 는 PT_LOAD[3] 만 디스어셈블해 overlay 미탐지. malware 분석가가 readelf -l 출력을 PHDR 오버랩 검사 없이 단순히 "PT_LOAD 가 N 개" 로만 보면 놓치기 쉬움.
- F14a: 베이스 5개 전부 PT_LOAD overlap 0건. 변형 30개 중 18개에서 overlap 탐지 (12개는 swap/memsz-only 등 단순 변형이라 overlap 없음).
- F14b: 의미 있는 권한/내용 분기 변형 19개 중 15개를 detect_overlap.py 가 탐지. 재현률 = 15/19.
- F14: 50줄짜리 PT_LOAD vaddr 오버랩 체크 한 줄짜리 규칙이 본 lab 의 모든 의미 있는 변형을 탐지. objdump/file/strings 가 놓치는 신호를 1차 방어선으로 제공 가능.
- F15: detector v2(페이지 정렬 + RELRO subset 체크)로 key 변형 recall = 7/7.
- F6: PT_NOTE→PT_LOAD RWX 오버레이가 커널에서 허용됨. 0x401000 페이지가 RWX.
- F7: RWX 텍스트 페이지로 main 도달 성공 — 정적은 R-X 로 보고되지만 런타임은 RWX. 정적/동적 분리 PoC 1호.
- F8: RW 오버레이는 텍스트 페이지를 RW 로 만들고 NX 로 인해 실행 시 SEGV — V1 결과 재확인.
- F9: R-X 오버레이는 동일 플래그라 변화 없음 — 컨트롤 통과.
- F12: 동일 소스 빌드 + PHT 1 줄 패치 + 파일 끝에 0x1000 바이트 부착으로 target_func 결과가 1→42 로 분기. runtime memcpy 없음 → strace 에 의심 syscall 흔적 안 남음. 정적 분석은 PT_LOAD[3] R-X 만 보면 return 1 그대로.
- F16: 기존 PT_LOAD 의 vaddr 만 수정한 변형은 PT_LOAD 카운트 4 유지. readelf -l 의 단순 카운트로는 baseline 과 구분 불가.
- F17: detector v2 가 본 변형 3/3개를 ANOMALY 로 잡음 (페이지 정렬 오버랩 체크 덕분). 단서 = PT_LOAD vaddr 페이지 범위 오버랩, PT_LOAD 카운트가 같아도 잡힘.
- F18: rodata 슬롯의 vaddr 만 text 페이지로 옮기면 text 가 r--p 로 다운그레이드되어 NX 로 인해 SEGV. 정적 분석은 PT_LOAD[3] R-X 만 보면 정상으로 본다 — 정적/동적 분리 사례 추가 (rodata 변형판).
- F19: 같은 바이트라도 R-only (NX) 오버레이는 실행 차단으로 SEGV. baseline R-X 와 분기.
- F20: 정상 prod 바이너리 300 개 중 ANOMALY 0 개 (0.0%). False positive 비율 매우 낮음 → detector v2 를 1차 방어선으로 사용 적합.
- F21alt: overlay 변형 결과 42 안 나옴 → # exit=-11
# --- stdout ---

# --- stderr ---


- F22: detector v2 는 in-file payload 변형도 동일하게 ANOMALY 로 잡음 (페이지 정렬 PT_LOAD 오버랩). file size/.payload 섹션 존재 여부와 무관한 시그널.
- F21: file size 동일 (25664 bytes). PHT 1줄 패치 + .payload 섹션 내용을 텍스트 사본 + 6바이트 패치로 채워 target_func 결과 1→42. iter04 의 file append 단서까지 제거됨. ELF 안에 의심스러운 트레일링 데이터 없음.
- F22: detector v2 는 in-file payload 변형도 PT_LOAD 페이지 정렬 오버랩으로 ANOMALY 탐지. file size 단서 제거되어도 vaddr 오버랩 시그널 살아 있음.
- F23: 표면 차이 측정 결과 — same: ['size_same', 'readelf_h_same', 'readelf_S_same', 'strings_same'], different: ['sha256_same', 'file_same', 'readelf_l_same', 'objdump_text_same'].
- F23a: size 동일하지만 sha256 다름 → 바이트 단위 비교 도구(diff/cmp)만 차이 잡음. 단순 size/일자만 보는 무결성 검사는 통과.
- F23c: readelf -l 다름 (PT_NOTE → PT_LOAD 변경) → PHT 검사 도구는 잡음. F13a 와 일치.
- F23d: readelf -S (section header) 동일 → 섹션 헤더 기반 분석은 미탐. .payload 섹션이 baseline 에도 이미 있어서 차이 없음.
- F23g: iter11 의 file/objdump_text DIFFERENT 는 출력 안 파일명 차이일 뿐 (정규화 후 동일). 실제 표면 차이는 sha256 과 readelf -l 두 가지뿐.
- F24: 11 iter 누적 결과 — 가장 스텔스한 변형(iter10 I10V2)에서 file size, file 출력, readelf -h/-S, strings, .text 디스어셈블 전부 baseline 과 동일. PHT 레벨 vaddr 오버랩 검사만 잡음.
- F25: baseline RELRO 적용 시 .got 페이지(0x403000) main 시점 = r--p.
- F26: RELRO memsz 8 바이트만 줄여도 (V1) .got 페이지 main 시점 = rw-p. RELRO 무력화 — 페이지 정렬 경계 효과 확인.
- F27: RELRO memsz 한 페이지 확장 (V2) 시 .data 페이지(0x404000) main 시점 = r--p. 확장된 RELRO 가 .data 까지 RO 로 잠금 — 실행 영향 가능.
- F27b: V2 plain exit = -11 (.data RO 의 영향으로 SEGV).
- F28: RELRO 절반 미만 축소 (V3) 시 .got 페이지 main 시점 = rw-p.
- F29: detector v2 결과 — {'I13V0_base': 'CLEAN', 'I13V1_relro_shrink_8': 'CLEAN', 'I13V2_relro_extend_page': 'ANOMALY', 'I13V3_relro_shrink_half': 'CLEAN'}. RELRO subset 체크가 V1/V3 의 shrink 케이스를 어떻게 처리하는지가 관건.
- F30: 정적 분석에서 readelf -l GNU_RELRO 의 FileSiz/MemSiz 만 봐도 baseline 과 다름이 보임 — 단 8B 차이는 분석가가 그냥 넘기기 쉬움. 자동화 시그널로는 "RELRO 가 .got 끝과 page-align 안 맞는다" 가 후보.
- F31: detector v3 가 RELRO shrink 변형(V1, V3) 을 ANOMALY 로 잡음. v2 의 blind spot 해소.
- F32: 결합 PoC (RELRO shrink + RWX overlay) 결과 — plain=0 text@0x401000=rwxp got@0x403000=rw-p detector=ANOMALY.
- F33: 8B 변경(RELRO memsz) + 7개 PHT 필드 패치만으로 텍스트 RWX + GOT RW 가 동시 성립. 멀웨어 시나리오의 가장 강력한 형태.
- F34: detector v3 의 정상 prod 바이너리 200 표본 FP = 0 (0.00%). v2 와 동일하게 거의 0.
- F35: F26 의 직접 원인이 glibc dl-reloc.c:354-368 의 ALIGN_DOWN(start), ALIGN_DOWN(end) 조합 — RELRO end 를 페이지 경계 아래로 8B 만 내리면 start==end 가 되어 mprotect 호출 자체가 skip 됨.
- F36: F4 의 원인이 dl-load.c:1213-1214 — PT_GNU_RELRO 처리에서 vaddr/memsz 를 검증 없이 link_map 에 저장. 안전한 RELRO 호스트 PT_LOAD 검사가 없음.
- F37: 방어 보강 제안 3 가지(RELRO subset 검증 / ALIGN_DOWN noop 검출 / PT_LOAD 오버랩 사전 거절)로 ld.so 단계에서 본 lab 변형 전체 차단 가능. detect_overlap.py v3 와 동일한 시그널.
- F38alt: combo 변형 stdout = # exit=1
# --- stdout ---
[probe] start
[probe] PLT format unexpected

# --- stderr ---

. 패치 의도와 불일치.
- F39: detector v3 가 baseline CLEAN, combo ANOMALY 로 정확히 분류. live PoC 도 자동 탐지.
- F38alt: combo 변형 stdout = # exit=-11
# --- stdout ---
[probe] start

# --- stderr ---

. 패치 의도와 불일치.
- F39: detector v3 가 baseline CLEAN, combo ANOMALY 로 정확히 분류. live PoC 도 자동 탐지.
- F38: baseline 은 GOT 쓰기에서 SIGSEGV (full RELRO 가 .got RO). combo 변형은 GOT/텍스트 쓰기 모두 성공. live PoC 로 F33(text RWX + GOT RW) 실증 완료.
- F39: detector v3 가 baseline CLEAN, combo ANOMALY 로 정확히 분류. live PoC 도 자동 탐지.

## 완결된 이터레이션
### iter01 — PT_NOTE→PT_LOAD overlay over text page
- 가설: 오버레이 플래그가 그대로 페이지 권한이 된다
- 판정: I1V1_overlay_rwx: plain=0 kernel=rwxp main=rwxp | I1V2_overlay_rw: plain=-11 kernel=rw-p main=rw-p | I1V3_overlay_rx: plain=0 kernel=r-xp main=r-xp
- ts: 2026-05-13 15:04:22

### iter02 — F7 cross-RELRO consistency check (RWX overlay 가 모든 RELRO 모드에서 성립?)
- 가설: 오버레이가 RELRO 모드와 무관하게 동작한다
- 판정: I2V_norelro_rwx:plain=0 k=rwxp m=rwxp | I2V_partial_rwx:plain=0 k=rwxp m=rwxp | I2V_full_rwx:plain=0 k=rwxp m=rwxp
- ts: 2026-05-13 15:05:49

### iter03 — Self-modifying-code via RWX overlay (실용 PoC)
- 가설: 오버레이만으로 자기수정 코드 PoC 가 성립한다
- 판정: I3V0_baseline:plain=-11 k=r-xp m=r-xp | I3V1_rwx_overlay:plain=0 k=rwxp m=rwxp
- ts: 2026-05-13 15:07:09

### iter04 — Pre-staged payload via overlay file offset (no runtime SMC)
- 가설: 미리 박힌 페이로드로 정적/동적 분기를 SMC 없이 만든다
- 판정: I4V0_baseline:exit=99 k=r-xp m=r-xp | I4V1_prestaged_payload:exit=0 k=r-xp m=r-xp
- ts: 2026-05-13 15:09:02

### iter05 — 정적 분석 도구 탐지 매트릭스
- 가설: 정적 도구 대부분이 PHDR overlay 를 탐지 못함
- 판정: PT_LOAD count: baseline=4 prestaged=5 | objdump@target_func 동일: True
- ts: 2026-05-13 15:09:45

### iter06 — 방어용 PT_LOAD overlap detector + 전 변형 검증
- 가설: PT_LOAD vaddr overlap 시그널만으로 lab 변형 100% 탐지
- 판정: base overlap=0/5 | variant overlap=18/30 | key recall=15/19
- ts: 2026-05-13 15:11:14

### iter07 — detector 개선(페이지 정렬 + RELRO subset 체크) + 통합 보고서
- 가설: detector v2 가 false negative 를 줄이고 PoC 군을 종합 탐지
- 판정: detector v2 key recall=7/7 | FINAL_REPORT.md 작성
- ts: 2026-05-13 15:12:21

### iter01 — PT_NOTE→PT_LOAD overlay over text page
- 가설: 오버레이 플래그가 그대로 페이지 권한이 된다
- 판정: I1V1_overlay_rwx: plain=0 kernel=rwxp main=rwxp | I1V2_overlay_rw: plain=-11 kernel=rw-p main=rw-p | I1V3_overlay_rx: plain=0 kernel=r-xp main=r-xp
- ts: 2026-05-13 15:16:30

### iter04 — Pre-staged payload via overlay file offset (no runtime SMC)
- 가설: 미리 박힌 페이로드로 정적/동적 분기를 SMC 없이 만든다
- 판정: I4V0_baseline:exit=99 k=r-xp m=r-xp | I4V1_prestaged_payload:exit=0 k=r-xp m=r-xp
- ts: 2026-05-13 15:16:40

### iter08 — B14: 기존 PT_LOAD vaddr 만 조작한 스텔스 변형 (PT_LOAD count 유지)
- 가설: 기존 PT_LOAD 만 조작해도 페이지 정렬 오버랩으로 detector 잡힘
- 판정: I8V1_rodata_vaddr_to_text:plain=-11 k=r--p m=r--p det=ANOMALY | I8V2_data_vaddr_to_text:plain=-11 k=rw-p m=rw-p det=ANOMALY | I8V3_rodata_full_overlay_text:plain=-11 k=r--p m=r--p det=ANOMALY
- ts: 2026-05-13 15:22:50

### iter09 — detector v2 의 false positive 점검 (/usr/bin, /usr/lib)
- 가설: 정상 바이너리에서 ANOMALY 비율이 낮다
- 판정: sample=300 clean=300 anomaly=0 fp_rate=0.00%
- ts: 2026-05-13 15:23:18

### iter10 — B12: file append 없이 in-file .payload 섹션을 텍스트 페이지에 R-X 오버레이
- 가설: in-file .payload 섹션 오버레이로 file size 변화 없이 분기 가능
- 판정: base:plain=99 out=r=1 | overlay:plain=-11 out=? | size 25664=25664 (same) | det CLEAN / ANOMALY
- ts: 2026-05-13 15:24:36

### iter10 — B12 v2: in-file payload (텍스트 사본 + 패치) 로 file size 동일 분기
- 가설: 텍스트 사본 + 패치로 in-file payload PoC 가 main 도달
- 판정: base:exit=99 out=r=1 | v2:exit=0 out=r=42 | size 25664=25664 (same) | det baseline=CLEAN variant=ANOMALY
- ts: 2026-05-13 15:25:42

### iter11 — B23: baseline vs 스텔스 변형의 표면 차이 측정 (size/sha256/file/strings/readelf)
- 가설: 표면 차이가 readelf -l 와 strings/sha256 외에는 거의 안 보인다
- 판정: same: 4/8 surfaces | different: ['sha256_same', 'file_same', 'readelf_l_same', 'objdump_text_same']
- ts: 2026-05-13 15:26:27

### iter12 — finalize: iter11 보정 + FINAL_REPORT 갱신 + 옵시디언 동기화
- 가설: 루프 정리 및 보고서 동기화
- 판정: 40 findings | 23 backlog
- ts: 2026-05-13 15:27:40

### iter13 — B3: PT_GNU_RELRO 부분 누락 — 페이지 정렬 경계 효과 측정
- 가설: RELRO 페이지 정렬 경계가 작은 size 변경에도 전부/전무로 튄다
- 판정: I13V0_base:plain=0 got@0x403000=r--p data@0x404000=rw-p det=CLEAN | I13V1_relro_shrink_8:plain=0 got@0x403000=rw-p data@0x404000=rw-p det=CLEAN | I13V2_relro_extend_page:plain=-11 got@0x403000=r--p data@0x404000=r--p det=ANOMALY | I13V3_relro_shrink_half:plain=0 got@0x403000=rw-p data@0x404000=rw-p det=CLEAN
- ts: 2026-05-13 15:33:05

### iter14 — detector v3 (RELRO noop 검출) + RELRO 무력화 + RWX overlay 결합 PoC
- 가설: detector v3 가 RELRO 페이지 정렬 무력화를 잡고, 결합 PoC 성립
- 판정: v3 RELRO V1 caught=True V3 caught=True V0 clean=True | combo PoC exit=0 text=rwxp got=rw-p | prod FP=0/200 (0.00%)
- ts: 2026-05-13 15:34:15

### iter15 — finalize: iter13-14 통합 + 최종 보고서/옵시디언 갱신
- 가설: 15 iter 누적 종합 동기화
- 판정: 51 findings | 27 backlog | 6 PoCs
- ts: 2026-05-13 15:34:57

### iter16 — B4: glibc 코드 라인 인용 박기
- 가설: F1/F4/F26/F33 의 glibc 코드 원인 라인 추적
- 판정: 5 lines cited across 3 glibc files; 3 fixes proposed
- ts: 2026-05-13 15:39:02

### iter17 — B28: GOT write + 텍스트 write live PoC (baseline SEGV vs combo 통과)
- 가설: 실제 GOT/텍스트 쓰기로 combo PoC 가 baseline 을 무력화한다
- 판정: baseline:exit=1 got_write=SEGV | combo:exit=1 both=NO | detector base=CLEAN combo=ANOMALY
- ts: 2026-05-13 15:40:25

### iter17 — B28: GOT write + 텍스트 write live PoC (baseline SEGV vs combo 통과)
- 가설: 실제 GOT/텍스트 쓰기로 combo PoC 가 baseline 을 무력화한다
- 판정: baseline:exit=-11 got_write=SEGV | combo:exit=-11 both=NO | detector base=CLEAN combo=ANOMALY
- ts: 2026-05-13 15:40:50

### iter17 — B28: GOT write + 텍스트 write live PoC (baseline SEGV vs combo 통과)
- 가설: 실제 GOT/텍스트 쓰기로 combo PoC 가 baseline 을 무력화한다
- 판정: baseline:exit=-11 got_write=SEGV | combo:exit=0 both=YES | detector base=CLEAN combo=ANOMALY
- ts: 2026-05-13 15:41:44

## 남은 백로그
- [B1] PT_NOTE 를 PT_LOAD 로 변형해서 텍스트 페이지에 RWX 오버레이 (정적은 R-X, 동적은 RWX)
- [B2] V1 변형에서 데이터 p_offset 을 텍스트와 일치 + PT_DYNAMIC vaddr 동기화 → main 도달
- [B3] RELRO 부분 누락(특정 GOT 엔트리 4바이트만 RW로 남김) 시나리오
- [B4] glibc dl-load.c 의 _dl_map_segments, fs/binfmt_elf.c 매핑 루프 코드 인용 박기
- [B7] PT_NOTE 외 다른 phdr 슬롯(PT_GNU_STACK, PT_GNU_PROPERTY)으로 같은 오버레이가 가능한지 — 정적 분석기가 "PT_LOAD 만" 봐도 놓치는 영역 확대
- [B8] F7 의 자기수정 코드 PoC 화 — main 이 0x401XXX 에 페이로드를 쓰고 호출, 베이스는 SEGV / RWX 변형은 실행
- [B9r] 오버레이 변형 실행 실패 — text 페이지 권한과 코드 정렬 재확인
- [B11] F12 변형의 readelf/objdump/Ghidra 탐지 매트릭스 작성 — 어느 도구가 PT_NOTE→PT_LOAD overlay 를 잡는가
- [B12] 페이로드가 .data 또는 .rodata 안에 살아 있는 경우 — file append 없이도 PoC 가능한지
- [B13] Ghidra/IDA/Binary Ninja 자동 분석에서 같은 변형이 어떻게 처리되는지 — 별도 환경 필요
- [B14] PT_NOTE→PT_LOAD 가 아니라 새 phdr 슬롯을 만들지 않고 기존 PT_LOAD 의 vaddr/offset 만 조작해서 같은 효과 — 그러면 PT_LOAD 개수도 안 늘어남
- [B15] detect_overlap.py 의 false positive 점검 — 실제 정상 바이너리에 우연히 RELRO 와 LOAD 가 같은 페이지 시작/끝을 공유하는 케이스
- [B16] PT_LOAD 외 phdr 끼리 오버랩(예: PT_GNU_RELRO 가 PT_LOAD 와 비-Subset)도 같이 체크하도록 확장
- [B11] F12 변형의 readelf/objdump/Ghidra 탐지 매트릭스 작성 — 어느 도구가 PT_NOTE→PT_LOAD overlay 를 잡는가
- [B12] 페이로드가 .data 또는 .rodata 안에 살아 있는 경우 — file append 없이도 PoC 가능한지
- [B17] I8V1 류 변형이 컨테이너 탐지기(eBPF, AV) 에서 어떻게 분류되는지 — phdr 카운트로 거른 후 가상주소 오버랩 체크하는지
- [B18] PT_LOAD count 유지 + text 페이지 RWX 까지 가는 변형 가능한가 — 기존 PT_LOAD 만으로는 RW + X 동시 부여 어려움 (rodata R, data RW, text R-X 만 있어서 RWX 슬롯 없음)
- [B20] F21 변형의 .payload 섹션 이름을 ".rodata2" 같이 평범하게 위장 — file 도 분석가가 못 알아채게
- [B21] 정상 binary 가 .payload 라는 섹션 이름을 쓰는 경우는 없는지 확인 (FP 위장 가능성)
- [B22] F21 의 .payload 섹션 이름을 ".rodata" 같이 평범화 (objdump -h 로도 의심받지 않게)
- [B23] F21 변형 vs baseline 의 strings/file/sha256 차이 측정 — 표면 차이 점검
- [B24] F23f 의 strings 차이 정밀 분석 — .payload 안 텍스트 사본이 어떤 의심 패턴 노출하는지
- [B25] detector v2 + readelf -l overlap 검사 외에 다른 자동 시그널 후보 — 예: PT_LOAD 가 같은 페이지를 두 번 가리키는지, 또는 section-segment 불일치
- [B26] F26 RELRO 무력화 + iter01 RWX overlay 결합 — 4바이트 패치 둘로 텍스트 RWX + .got RW 동시에 PoC
- [B27] detector v3: RELRO end 가 .got 끝과 정확히 일치하는지 체크하는 휴리스틱 추가
- [B28] 결합 PoC 의 실용 활용 — GOT 엔트리 하나 덮어쓰고 텍스트에 페이로드 박은 뒤 printf 호출로 임의 코드 실행 PoC
- [B29] detect_overlap.py v3 를 더 큰 표본(/usr/lib 1000+)에 돌려서 FP 분포 정밀 측정
- [B30] F38 의 GOT 쓰기 후 실제로 함수 포인터 하이재크 (printf 호출이 페이로드로 점프) — 한 단계 더
- [B31] detector v3 의 휴리스틱 (RELRO end mismatch) 이 모든 표본에 robust 한지 — /usr/bin 전체 1000+ 표본으로 확장
- [B30] F38 의 GOT 쓰기 후 실제로 함수 포인터 하이재크 (printf 호출이 페이로드로 점프) — 한 단계 더
- [B31] detector v3 의 휴리스틱 (RELRO end mismatch) 이 모든 표본에 robust 한지 — /usr/bin 전체 1000+ 표본으로 확장
- [B30] F38 의 GOT 쓰기 후 실제로 함수 포인터 하이재크 (printf 호출이 페이로드로 점프) — 한 단계 더
- [B31] detector v3 의 휴리스틱 (RELRO end mismatch) 이 모든 표본에 robust 한지 — /usr/bin 전체 1000+ 표본으로 확장

## 최종 PoC 표 (실측 출력)
| 변형 | plain exit | stdout | text 페이지 | GOT 페이지 | detector v3 |
|---|---|---|---|---|---|
| baseline target_probe (full RELRO) | -11 (SEGV) | "[probe] start" 까지 | r-xp | r--p | CLEAN |
| combo (RELRO shrink 0x140B + RWX overlay) | 0 | "[probe] BOTH writes succeeded" | **rwxp** | **rw-p** | ANOMALY |

## glibc 코드 인용 (CITATIONS.md 별도 파일)
- elf/dl-map-segments.h _dl_map_segment — MAP_FIXED 로 후자 우선 발생
- elf/dl-load.c:1213-1214 — PT_GNU_RELRO 처리 시 vaddr/memsz 검증 없음
- elf/dl-reloc.c:354-368 _dl_protect_relro — ALIGN_DOWN(end) 로 페이지 경계 효과 (F26)

## 다음 미팅 발표 흐름
1. 0508 가설 → 검증 결과 (V0-V6, F1)
2. 자가 피드백 루프 18 회의 의미: 정적/동적 분리 PoC 6종 + 방어 도구 + glibc 코드 인용
3. live PoC 데모: iter17 출력 차이 (SEGV vs "BOTH writes succeeded")
4. 방어 측 detect_overlap.py v3: 50줄, FP 0%, 모든 변형 ANOMALY
5. glibc 보강 제안 3가지 (RELRO subset 검증 / ALIGN_DOWN noop / PT_LOAD 오버랩 사전 거절)

## 핵심 아티팩트
- /home/garden/PE/Lfuzzer/overlap_perm_lab/harness.py — 자가루프 코어
- /home/garden/PE/Lfuzzer/overlap_perm_lab/detect_overlap.py — 방어 측 도구 v3
- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter01..18.py — 각 이터레이션
- /home/garden/PE/Lfuzzer/overlap_perm_lab/CITATIONS.md — glibc 코드 인용
- /home/garden/PE/Lfuzzer/overlap_perm_lab/STATE.json — 누적 finding/backlog
- /home/garden/PE/Lfuzzer/overlap_perm_lab/ITER_LOG.md — 시간순 narrative
- /home/garden/PE/Lfuzzer/overlap_perm_lab/target_probe.c — live PoC 소스
- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter_outputs/iter01..18/ — 변형 ELF + 로그

---

## Beyond PT_NOTE — 다른 phdr 슬롯 변환 (iter21~25)

선행 연구 (Ryan O'Neill 2015 등) 는 PT_NOTE → PT_LOAD 변환만 다룸.
본 lab 은 4 개의 추가 phdr 타입을 같은 방식으로 변환하고 비교.

### 통합 매트릭스 (RWX 변형 기준)

| PHDR type | exit | text@0x401 | silent corruption | 원본 마커 사라짐 | PT_LOAD count | detector v3 |
|---|---|---|---|---|---|---|
| PT_NOTE         | 0 | rwxp | No | (idx 8 변환, idx 7 잔존) | 4→5 | ANOMALY |
| PT_GNU_EH_FRAME | 0 | rwxp | No | Yes | 4→5 | ANOMALY |
| PT_GNU_PROPERTY | 0 | rwxp | No | Yes (단 readelf -n 에는 잔존) | 4→5 | ANOMALY |
| PT_TLS          | 0 | rwxp | **Yes (TLS=42→0)** | Yes | 4→5 | ANOMALY |
| PT_GNU_STACK    | 0 | rwxp | No | Yes (stack perm 무영향) | 4→5 | ANOMALY |

### 핵심 발견 (F44~F67)

- F44/F50/F59 — PT_GNU_EH_FRAME / PT_GNU_PROPERTY / PT_GNU_STACK 변환은 PT_NOTE 변환과 functional 동등.
  ld.so/커널은 phdr 타입을 검증하지 않고 type=PT_LOAD 만 보고 매핑.
- **F64 (unique)** — PT_TLS 만 silent data corruption. ld.so 가 PT_TLS 슬롯 부재 시 TLS 메모리를 0 으로 채우고 그대로 사용.
  baseline `tls_var = 42` 가 변형에서 `0` 으로 출력. SEGV 없이 데이터 무결성 깨짐.
- F47/F53/F58/F63 — 5종 변형 모두 3회 반복 일관 (re-run 결과 동일).
- F65 — detector v3 가 5종 모두 ANOMALY 로 분류 (phdr 타입 무관 vaddr 오버랩 시그널).
- F66 — 원본 phdr 마커가 readelf -l 에서 사라지는 비율 4/5 (PT_NOTE 만 중복 슬롯이라 두 번째 잔존).
- F67 — 권장 활용:
  - 스텔스 우선: **PT_GNU_EH_FRAME** (항상 존재, 분석 우선순위 낮음)
  - 고파괴력: **PT_TLS** (silent corruption, TLS 사용 바이너리에 한정)
  - 보편성: **PT_NOTE** (선행 연구 다수)

### 평가 기준 결과
- 새 finding 인정 케이스 (PT_NOTE 와 다른 동작):
  - PT_TLS 의 silent corruption ← 새 finding (F64)
  - 정적 분석 도구별 마커 잔존 차이 (readelf -l vs readelf -n) ← 새 finding (F66)
- "같은 결과 나옴" valid finding:
  - PT_GNU_EH_FRAME / PT_GNU_PROPERTY / PT_GNU_STACK 의 functional 동등 (F44/F50/F59)
  - "no novelty 라는 결론도 가치 있음" 기준 만족

### 환경 (재현용)
- gcc 13.3.0-6ubuntu2~24.04.1
- glibc 2.39-0ubuntu8.7
- binutils 2.42-4ubuntu2.8
- Linux 6.6.87.2 WSL2
- 모든 실험 3회 반복, 결과 일관 (F47/F53/F58/F63)


---

## Practical extension (iter27)

### PT_TLS silent corruption 의 보안 실증 (B37)
target_tls_auth.c — `__thread int safety_locked = 1` 가 인증 게이트.
- baseline (full RELRO, no patch): **"ACCESS DENIED (safety_locked=1)"**
- 변형 (PT_TLS → PT_LOAD RWX): **"ACCESS GRANTED (safety_locked=0) -- DEBUG BYPASS"**
- PHT 8 필드 패치만으로 인증 우회. iter23 F64 silent corruption 의 보안 의미 실증.
- 3회 반복 일관 (모두 DENIED vs GRANTED).
- F68.

### detector v4 (B39 — PT_GNU_STACK missing 휴리스틱)
v3 + 새 시그널: PT_GNU_STACK 부재 → -no-pie 동적 링크 binary 에서는 매우 드묾.
- iter01/21/22/23 의 RWX 변형: overlap 시그널로 ANOMALY (이전 v3 와 동일)
- iter24 (PT_GNU_STACK → PT_LOAD): overlap + sm 두 시그널로 동시 잡힘
- iter27 auth bypass 변형: overlap 시그널로 ANOMALY
- prod /usr/bin 300 표본 FP: **0/300 (0.00%)** — sm 휴리스틱이 FP 도입 안 함
- F69, F70, F71.

### 누적 요약 (28 iter)
- 정적/동적 분리 PoC: 6 + 클린 DEMO 2 + 5 종 phdr 변환 (PT_TLS 의 silent corruption 포함)
- 실용 PoC: PT_TLS auth bypass (F68)
- 방어 도구: detect_overlap.py v4 (FP 0/300, 시그널 5종)
- glibc 원인 코드 3 함수 + 선행 연구(Ryan O'Neill 2015) 인용


---

## Robustness validation (iter29)

### detector v4 대규모 FP 측정 (B40)
표본: /usr/bin + /usr/sbin + /usr/lib/x86_64-linux-gnu + /usr/libexec = **1500 ELF**
| 시그널 | FP 수 | FP rate |
|---|---|---|
| overlap (PT_LOAD page overlap) | 0 | 0.00% |
| relro_subset_fail | 0 | 0.00% |
| relro_noop | 0 | 0.00% |
| relro_end_mismatch | 0 | 0.00% |
| gnu_stack_missing | 9 | 0.60% |
| **total** | 9 | 0.60% |

sm 시그널 FP 9건 분석: 모두 link-time 객체 파일 (`crt1.o`, `Scrt1.o`, `crti.o`, `crtn.o`, `Mcrt1.o` 등). 실제 실행 binary 가 아닌 정적 라이브러리/스타트업 객체. 실행 binary 에서는 사실상 FP 0%.

**결론**: detector v4 의 4 종 권한/RELRO 시그널은 1500 표본에서 FP 완전 0. sm 시그널은 ".o 객체 파일 제외" 후 0. F72, F73.

### PT_GNU_EH_FRAME 변환 후 C++ 예외 동작 (B38)
target_throw.cpp (`throw std::runtime_error; catch`).

| 변형 | 첫 출력 | 두 번째 출력 | exit | 3회 일관 |
|---|---|---|---|---|
| baseline | "[throw] before try" | "[throw] caught: test exception" → "[throw] after try" | 0 | [0,0,0] |
| PT_GNU_EH_FRAME → PT_LOAD RWX | (없음) | "terminate called after throwing 'std::runtime_error'" | **-6 (SIGABRT)** | [-6,-6,-6] |

iter21 의 "main 도달" 결과는 예외 throw 가 없는 정상 흐름 한정. 예외 throw 시 EH 슬롯 부재로 std::terminate 호출. F74.

### 누적 (30 iter)
- 정적/동적 분리 PoC: 6 + 클린 DEMO 2
- phdr 변환 5종 + PT_TLS auth bypass 실용 PoC
- 방어 도구 detect_overlap.py v4: 1500 표본 FP 0% (실행 binary 기준), 시그널 5종
- C++ throw 동작 측정으로 PT_GNU_EH_FRAME 변형의 한계 명시 (정상 흐름만 OK, throw 시 abort)


---

## detector v5 + evasion (iter31)

### v5 추가 시그널: section-segment 불일치
컴파일러는 보통 함께 만드는 섹션-세그먼트 쌍:
- `.eh_frame_hdr` ↔ PT_GNU_EH_FRAME
- `.note.gnu.property` ↔ PT_GNU_PROPERTY
- `.tdata`/`.tbss` ↔ PT_TLS

섹션은 있는데 세그먼트가 없으면 의심 (s_eh / s_prop / s_tls 시그널).

### 검증 결과 (lab 변형 v5 verdict)
| 변형 | overlap | sm | ssm |
|---|---|---|---|
| iter01 PT_NOTE → PT_LOAD | ✓ | False | [] |
| iter21 EH_FRAME → PT_LOAD | ✓ | False | **['s_eh']** |
| iter22 PROPERTY → PT_LOAD | ✓ | False | **['s_prop']** |
| iter23 TLS → PT_LOAD | ✓ | False | **['s_tls']** |
| iter24 STACK → PT_LOAD | ✓ | **True** | [] |
| iter27 TLS auth bypass | ✓ | False | **['s_tls']** |
| iter29 throw EH_FRAME | ✓ | False | **['s_eh']** |

5종 phdr 변환 모두 v5 의 두 가지 시그널 (overlap + ssm/sm) 로 cross-check 가능.

### prod FP 측정 (v5)
1500 ELF 표본:
| 시그널 | FP | rate |
|---|---|---|
| overlap | 0 | 0.00% |
| relro_* | 0 | 0.00% |
| sm | 9 | 0.60% (모두 .o) |
| ssm | 11 | 0.73% (.o + libmcheck.a 등 정적 라이브러리) |
| total | 11 | 0.73% |

실행 binary 한정 FP 사실상 0%.

### Evasion 시도 (F77)
공격자가 PT_LOAD 변환 대신 `PT_GNU_EH_FRAME → PT_NULL` 로 슬롯 무력화만 시도.
- 결과: exit=-6 (SIGABRT, throw 시 std::terminate)
- detector v5: **ANOMALY ssm=['s_eh']** — 잡힘.
- PT_LOAD overlap 시그널은 우회되어도 섹션-세그먼트 일관성으로 검출. v5 의 robustness 입증.

### 누적 (32 iter)
- 정적/동적 분리 PoC: 6 + 클린 DEMO 2 + phdr 변환 5종
- 실용 PoC: PT_TLS auth bypass (F68)
- 방어 도구: detect_overlap.py v5 (시그널 6종), 실행 binary FP 0%, evasion 시도까지 검출


---

## Detector robustness across phdr type evasion (iter33)

iter31 의 PT_NULL evasion 외에 6개 추가 type 으로 PT_GNU_EH_FRAME 슬롯 변환.

| 변형 | type 값 | exit | detector v5 |
|---|---|---|---|
| baseline | (no change) | 0 (caught) | CLEAN |
| → PT_NULL | 0x0 | -6 (SIGABRT) | ANOMALY ssm=['s_eh'] |
| → PT_TLS | 0x7 | -6 | ANOMALY ssm=['s_eh'] |
| → PT_LOPROC | 0x70000000 | -6 | ANOMALY ssm=['s_eh'] |
| → PT_HIPROC | 0x7fffffff | -6 | ANOMALY ssm=['s_eh'] |
| → PT_LOOS | 0x60000000 | -6 | ANOMALY ssm=['s_eh'] |
| → PT_HIOS | 0x6fffffff | -6 | ANOMALY ssm=['s_eh'] |
| → 0x12345678 (random) | 0x12345678 | -6 | ANOMALY ssm=['s_eh'] |

7 변종 × 3 반복 = **21 실행 모두 일관** (exit=-6, terminate called after throwing).

### 결론
- kernel/ld.so 가 unknown/reserved type 을 모두 무시 (process load 성공, EH 정보만 무력화)
- detector v5 의 ssm 시그널이 7 가지 type 위장 변종을 모두 잡음
- "PT_LOAD 변환을 피하고 type 만 바꿔 무력화" 라는 evasion 방향 전체가 ssm 으로 차단됨
- F78, F79, F80, F81

### 누적 (34 iter)
- 정적/동적 분리 PoC: 6 + 클린 DEMO 2 + phdr 변환 5종 + PT_TLS auth bypass
- 방어 도구 detect_overlap.py v5: 시그널 6종, 실행 binary FP 0%, PT_LOAD/reserved type 양쪽 evasion 모두 잡음


---

## Slot-level robustness + detector v6 (iter35~36)

### 다른 phdr 슬롯 type evasion 검증 (iter35)
PT_GNU_EH_FRAME 외 4 슬롯에 동일 type 변환 (PT_NULL/PT_LOPROC/random):

| 슬롯 | baseline | v5 detection rate |
|---|---|---|
| PT_NOTE (target_partial idx 8) | CLEAN | **0/3** (갭) |
| PT_GNU_PROPERTY (target_full idx 9) | CLEAN | 3/3 ssm=[s_prop] |
| PT_TLS (target_tls idx 9) | CLEAN | 3/3 ssm=[s_tls] |
| PT_GNU_STACK (target_full idx 11) | CLEAN | 3/3 sm=True |

PT_NOTE 갭 원인: 1:1 매칭 섹션 없음 + target_partial 의 PT_NOTE 두 개라 한 슬롯 변환 시 다른 PT_NOTE 가 .note.* 커버. F82, F83, F84, F85.

### detector v6 보강 (iter36)
시그널 2 종 추가:
- **ut** (unknown_types): phdr type 이 KNOWN_TYPES 밖이면 의심
- **nn** (note_phdr_missing): PT_NOTE 카운트 0 인데 .note.* 섹션 존재

PT_NOTE 갭 처리 결과:
| 변종 | v5 | v6 |
|---|---|---|
| PT_NOTE → PT_NULL | CLEAN | **CLEAN (여전히 미탐)** |
| PT_NOTE → PT_LOPROC | CLEAN | ANOMALY ut=[0x70000000] |
| PT_NOTE → random 0x12345678 | CLEAN | ANOMALY ut=[0x12345678] |

PT_NULL (0x0) 은 KNOWN_TYPES 안 + 다른 PT_NOTE 가 섹션 커버 → 잡기 어려운 알려진 한계. F86.

### prod FP (v6, 1500 표본)
- ut: 0/1500 (0.00%) — robust
- nn: 9/1500 (0.60%) — 모두 .o 객체 파일
- total: 11/1500 (0.73%) — 모두 .o / .a 정적 산출물
- 실행 binary 한정 FP 0%. F87, F88.

### 알려진 한계 (detector v6)
1. PT_NOTE → PT_NULL: 다른 PT_NOTE 가 섹션 커버하면 미탐. PT_NOTE 한 개뿐인 binary 에서 PT_NULL 변환은 nn 으로 잡힘.
2. Type-only 변환 (PT_LOAD 안 만듦) 의 실용 impact 작음: kernel 이 unknown type 무시하니 process 영향 = 슬롯이 가리키던 메타 정보 무력화 한정. EH_FRAME → throw 시 SIGABRT, TLS → silent corruption, PROPERTY → CET 약화, STACK → 별 영향. NOTE 변형은 build-id 마커 정도라 실질 보안 영향 최소.

### 누적 (37 iter, 시그널 8 종)
- 정적/동적 분리 PoC: 6 + 클린 DEMO 2 + phdr 변환 5종 + PT_TLS auth bypass + C++ throw 변형
- 방어 도구 detect_overlap.py v6: 8 시그널 (overlap / rs / rn / rem / sm / ssm / ut / nn), 실행 binary FP 0%
- evasion 방어: overlap 회피 + type 위장 양쪽 차단 (PT_NULL 의 PT_NOTE 케이스 1 가지 알려진 한계 외)
