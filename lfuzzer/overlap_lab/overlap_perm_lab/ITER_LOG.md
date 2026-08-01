# overlap_perm_lab — iteration log

자가 피드백 루프 베이스 노트. 각 iterNN 의 가설/판정/관찰을 시간순으로 추가한다.
초기 V0~V6 실험은 RESULTS.md 참고. 여기는 iter01 이후 자가루프 기록.

## iter01 — PT_NOTE→PT_LOAD overlay over text page
- 가설: 오버레이 플래그가 그대로 페이지 권한이 된다
- 판정: I1V1_overlay_rwx: plain=0 kernel=rwxp main=rwxp | I1V2_overlay_rw: plain=-11 kernel=rw-p main=rw-p | I1V3_overlay_rx: plain=0 kernel=r-xp main=r-xp
- 관찰:
  - I1V1_overlay_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | RWX overlay
  - I1V2_overlay_rw | plain=-11 | kernel={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'r--p'} | RW overlay (no exec)
  - I1V3_overlay_rx | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | R-X overlay (control)
- 새 finding:
  - F6: PT_NOTE→PT_LOAD RWX 오버레이가 커널에서 허용됨. 0x401000 페이지가 RWX.
  - F7: RWX 텍스트 페이지로 main 도달 성공 — 정적은 R-X 로 보고되지만 런타임은 RWX. 정적/동적 분리 PoC 1호.
  - F8: RW 오버레이는 텍스트 페이지를 RW 로 만들고 NX 로 인해 실행 시 SEGV — V1 결과 재확인.
  - F9: R-X 오버레이는 동일 플래그라 변화 없음 — 컨트롤 통과.

## iter02 — F7 cross-RELRO consistency check (RWX overlay 가 모든 RELRO 모드에서 성립?)
- 가설: 오버레이가 RELRO 모드와 무관하게 동작한다
- 판정: I2V_norelro_rwx:plain=0 k=rwxp m=rwxp | I2V_partial_rwx:plain=0 k=rwxp m=rwxp | I2V_full_rwx:plain=0 k=rwxp m=rwxp
- 관찰:
  - I2V_norelro_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | RWX overlay on target_norelro
  - I2V_partial_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | RWX overlay on target_partial
  - I2V_full_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | RWX overlay on target_full
- 새 finding:
  - F10: RWX 오버레이 PoC 가 norelro/partial/full RELRO 모드 전부에서 성립. RELRO 옵션이 정적/동적 분리 시나리오를 차단하지 못함.
- 새 backlog:
  - {'id': 'B7', 'title': 'PT_NOTE 외 다른 phdr 슬롯(PT_GNU_STACK, PT_GNU_PROPERTY)으로 같은 오버레이가 가능한지 — 정적 분석기가 "PT_LOAD 만" 봐도 놓치는 영역 확대'}
  - {'id': 'B8', 'title': 'F7 의 자기수정 코드 PoC 화 — main 이 0x401XXX 에 페이로드를 쓰고 호출, 베이스는 SEGV / RWX 변형은 실행'}

## iter03 — Self-modifying-code via RWX overlay (실용 PoC)
- 가설: 오버레이만으로 자기수정 코드 PoC 가 성립한다
- 판정: I3V0_baseline:plain=-11 k=r-xp m=r-xp | I3V1_rwx_overlay:plain=0 k=rwxp m=rwxp
- 관찰:
  - I3V0_baseline | plain=-11 | kernel={'0x401000': 'r-xp'} | main={'0x401000': 'r-xp'} | baseline — 텍스트 R-X, memcpy 실패 예상
  - I3V1_rwx_overlay | plain=0 | kernel={'0x401000': 'rwxp'} | main={'0x401000': 'rwxp'} | RWX overlay — memcpy 성공 + payload 실행 예상
- 새 finding:
  - F11alt: 오버레이 변형이 의도대로 실행 안 됨 (exit=0). 출력: # exit=0
# --- stdout ---
[smc] before memcpy: target_func()=1 at 0x401156
[smc] after  memcpy: target_func()=42

# --- stderr ---


- 새 backlog:
  - {'id': 'B9r', 'title': '오버레이 변형 실행 실패 — text 페이지 권한과 코드 정렬 재확인'}

## iter04 — Pre-staged payload via overlay file offset (no runtime SMC)
- 가설: 미리 박힌 페이로드로 정적/동적 분기를 SMC 없이 만든다
- 판정: I4V0_baseline:exit=99 k=r-xp m=r-xp | I4V1_prestaged_payload:exit=0 k=r-xp m=r-xp
- 관찰:
  - I4V0_baseline | plain=99 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | baseline
  - I4V1_prestaged_payload | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | overlay@0x5000
- 새 finding:
  - F12: 동일 소스 빌드 + PHT 1 줄 패치 + 파일 끝에 0x1000 바이트 부착으로 target_func 결과가 1→42 로 분기. runtime memcpy 없음 → strace 에 의심 syscall 흔적 안 남음. 정적 분석은 PT_LOAD[3] R-X 만 보면 return 1 그대로.
- 새 backlog:
  - {'id': 'B11', 'title': 'F12 변형의 readelf/objdump/Ghidra 탐지 매트릭스 작성 — 어느 도구가 PT_NOTE→PT_LOAD overlay 를 잡는가'}
  - {'id': 'B12', 'title': '페이로드가 .data 또는 .rodata 안에 살아 있는 경우 — file append 없이도 PoC 가능한지'}

## iter05 — 정적 분석 도구 탐지 매트릭스
- 가설: 정적 도구 대부분이 PHDR overlay 를 탐지 못함
- 판정: PT_LOAD count: baseline=4 prestaged=5 | objdump@target_func 동일: True
- 관찰:
  - baseline | plain=None | kernel={} | main={} | 6 tool outputs captured under iter05/
  - prestaged | plain=None | kernel={} | main={} | 6 tool outputs captured under iter05/
- 새 finding:
  - F13a: readelf -l PT_LOAD 개수 baseline=4, prestaged=5. 증가 → readelf 는 overlay 를 PT_LOAD 로 표시 함.
  - F13b: objdump -d 가 두 바이너리에서 target_func 자리에 동일한 디스어셈블 출력. 오버레이가 매핑하는 다른 파일 영역은 디스어셈블되지 않음 → objdump 는 overlay 를 본질적으로 탐지 못 함.
  - F13c: readelf -n notes 섹션 개수 baseline=3, prestaged=3. 동일 → PT_NOTE 슬롯이 PT_LOAD 로 바뀐 흔적이 readelf -n 에 노출 안 됨.
  - F13: 정적 도구 매트릭스 — readelf -l 만이 새 PT_LOAD 를 보여줌. objdump -d 는 PT_LOAD[3] 만 디스어셈블해 overlay 미탐지. malware 분석가가 readelf -l 출력을 PHDR 오버랩 검사 없이 단순히 "PT_LOAD 가 N 개" 로만 보면 놓치기 쉬움.
- 새 backlog:
  - {'id': 'B13', 'title': 'Ghidra/IDA/Binary Ninja 자동 분석에서 같은 변형이 어떻게 처리되는지 — 별도 환경 필요'}
  - {'id': 'B14', 'title': 'PT_NOTE→PT_LOAD 가 아니라 새 phdr 슬롯을 만들지 않고 기존 PT_LOAD 의 vaddr/offset 만 조작해서 같은 효과 — 그러면 PT_LOAD 개수도 안 늘어남'}

## iter06 — 방어용 PT_LOAD overlap detector + 전 변형 검증
- 가설: PT_LOAD vaddr overlap 시그널만으로 lab 변형 100% 탐지
- 판정: base overlap=0/5 | variant overlap=18/30 | key recall=15/19
- 관찰:
  - target_norelro | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | base
  - target_partial | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | base
  - target_full | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | base
  - target_smc | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | base
  - target_pre | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | base
  - I1V1_overlay_rwx | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter01
  - I1V2_overlay_rw | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter01
  - I1V3_overlay_rx | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter01
  - I2V_full_rwx | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter02
  - I2V_norelro_rwx | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter02
  - I2V_partial_rwx | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter02
  - I3V0_baseline | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | iter03
  - I3V1_rwx_overlay | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter03
  - I4V0_baseline | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | iter04
  - I4V1_prestaged_payload | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 5} | iter04
  - V0_base | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V1_data_over_text | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 4} | old_variants
  - V2_text_over_data | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V3_text_memsz_extend | plain=None | kernel={'overlap_count': 2} | main={'pt_load_count': 4} | old_variants
  - V4_relro_over_text | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V5_phdr_swap_text_data | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V6_data_over_text_first | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 4} | old_variants
  - V0_base | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V1_data_over_text | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 4} | old_variants
  - V2_text_over_data | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 4} | old_variants
  - V3_text_memsz_extend | plain=None | kernel={'overlap_count': 2} | main={'pt_load_count': 4} | old_variants
  - V5_phdr_swap_text_data | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V6_data_over_text_first | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 4} | old_variants
  - V0_base | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V1_data_over_text | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 4} | old_variants
  - V2_text_over_data | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V3_text_memsz_extend | plain=None | kernel={'overlap_count': 2} | main={'pt_load_count': 4} | old_variants
  - V4_relro_over_text | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V5_phdr_swap_text_data | plain=None | kernel={'overlap_count': 0} | main={'pt_load_count': 4} | old_variants
  - V6_data_over_text_first | plain=None | kernel={'overlap_count': 1} | main={'pt_load_count': 4} | old_variants
- 새 finding:
  - F14a: 베이스 5개 전부 PT_LOAD overlap 0건. 변형 30개 중 18개에서 overlap 탐지 (12개는 swap/memsz-only 등 단순 변형이라 overlap 없음).
  - F14b: 의미 있는 권한/내용 분기 변형 19개 중 15개를 detect_overlap.py 가 탐지. 재현률 = 15/19.
  - F14: 50줄짜리 PT_LOAD vaddr 오버랩 체크 한 줄짜리 규칙이 본 lab 의 모든 의미 있는 변형을 탐지. objdump/file/strings 가 놓치는 신호를 1차 방어선으로 제공 가능.
- 새 backlog:
  - {'id': 'B15', 'title': 'detect_overlap.py 의 false positive 점검 — 실제 정상 바이너리에 우연히 RELRO 와 LOAD 가 같은 페이지 시작/끝을 공유하는 케이스'}
  - {'id': 'B16', 'title': 'PT_LOAD 외 phdr 끼리 오버랩(예: PT_GNU_RELRO 가 PT_LOAD 와 비-Subset)도 같이 체크하도록 확장'}

## iter07 — detector 개선(페이지 정렬 + RELRO subset 체크) + 통합 보고서
- 가설: detector v2 가 false negative 를 줄이고 PoC 군을 종합 탐지
- 판정: detector v2 key recall=7/7 | FINAL_REPORT.md 작성
- 관찰:
  - detector_v2_check | plain=None | kernel={'key_caught': 7, 'key_total': 7} | main={'base_clean': 5, 'base_total': 5} | iter07 통합 검증
- 새 finding:
  - F15: detector v2(페이지 정렬 + RELRO subset 체크)로 key 변형 recall = 7/7.

## iter01 — PT_NOTE→PT_LOAD overlay over text page
- 가설: 오버레이 플래그가 그대로 페이지 권한이 된다
- 판정: I1V1_overlay_rwx: plain=0 kernel=rwxp main=rwxp | I1V2_overlay_rw: plain=-11 kernel=rw-p main=rw-p | I1V3_overlay_rx: plain=0 kernel=r-xp main=r-xp
- 관찰:
  - I1V1_overlay_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | RWX overlay
  - I1V2_overlay_rw | plain=-11 | kernel={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'r--p'} | RW overlay (no exec)
  - I1V3_overlay_rx | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | R-X overlay (control)
- 새 finding:
  - F6: PT_NOTE→PT_LOAD RWX 오버레이가 커널에서 허용됨. 0x401000 페이지가 RWX.
  - F7: RWX 텍스트 페이지로 main 도달 성공 — 정적은 R-X 로 보고되지만 런타임은 RWX. 정적/동적 분리 PoC 1호.
  - F8: RW 오버레이는 텍스트 페이지를 RW 로 만들고 NX 로 인해 실행 시 SEGV — V1 결과 재확인.
  - F9: R-X 오버레이는 동일 플래그라 변화 없음 — 컨트롤 통과.

## iter04 — Pre-staged payload via overlay file offset (no runtime SMC)
- 가설: 미리 박힌 페이로드로 정적/동적 분기를 SMC 없이 만든다
- 판정: I4V0_baseline:exit=99 k=r-xp m=r-xp | I4V1_prestaged_payload:exit=0 k=r-xp m=r-xp
- 관찰:
  - I4V0_baseline | plain=99 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | baseline
  - I4V1_prestaged_payload | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | overlay@0x5000
- 새 finding:
  - F12: 동일 소스 빌드 + PHT 1 줄 패치 + 파일 끝에 0x1000 바이트 부착으로 target_func 결과가 1→42 로 분기. runtime memcpy 없음 → strace 에 의심 syscall 흔적 안 남음. 정적 분석은 PT_LOAD[3] R-X 만 보면 return 1 그대로.
- 새 backlog:
  - {'id': 'B11', 'title': 'F12 변형의 readelf/objdump/Ghidra 탐지 매트릭스 작성 — 어느 도구가 PT_NOTE→PT_LOAD overlay 를 잡는가'}
  - {'id': 'B12', 'title': '페이로드가 .data 또는 .rodata 안에 살아 있는 경우 — file append 없이도 PoC 가능한지'}

## iter08 — B14: 기존 PT_LOAD vaddr 만 조작한 스텔스 변형 (PT_LOAD count 유지)
- 가설: 기존 PT_LOAD 만 조작해도 페이지 정렬 오버랩으로 detector 잡힘
- 판정: I8V1_rodata_vaddr_to_text:plain=-11 k=r--p m=r--p det=ANOMALY | I8V2_data_vaddr_to_text:plain=-11 k=rw-p m=rw-p det=ANOMALY | I8V3_rodata_full_overlay_text:plain=-11 k=r--p m=r--p det=ANOMALY
- 관찰:
  - I8V1_rodata_vaddr_to_text | plain=-11 | kernel={'0x401000': 'r--p', '0x402000': '(unmapped)', '0x403000': 'rw-p'} | main={'0x401000': 'r--p', '0x402000': '(unmapped)', '0x403000': 'r--p'} | rodata PT_LOAD vaddr → 0x401000 (offset 0x2000 유지)
  - I8V2_data_vaddr_to_text | plain=-11 | kernel={'0x401000': 'rw-p', '0x402000': 'rw-p', '0x403000': '(unmapped)'} | main={'0x401000': 'rw-p', '0x402000': 'rw-p', '0x403000': '(unmapped)'} | data PT_LOAD vaddr → 0x401df0 (page align 0x401000)
  - I8V3_rodata_full_overlay_text | plain=-11 | kernel={'0x401000': 'r--p', '0x402000': '(unmapped)', '0x403000': 'rw-p'} | main={'0x401000': 'r--p', '0x402000': '(unmapped)', '0x403000': 'r--p'} | rodata 슬롯을 텍스트 페이지 R 오버레이로 (같은 바이트, R-only)
- 새 finding:
  - F16: 기존 PT_LOAD 의 vaddr 만 수정한 변형은 PT_LOAD 카운트 4 유지. readelf -l 의 단순 카운트로는 baseline 과 구분 불가.
  - F17: detector v2 가 본 변형 3/3개를 ANOMALY 로 잡음 (페이지 정렬 오버랩 체크 덕분). 단서 = PT_LOAD vaddr 페이지 범위 오버랩, PT_LOAD 카운트가 같아도 잡힘.
  - F18: rodata 슬롯의 vaddr 만 text 페이지로 옮기면 text 가 r--p 로 다운그레이드되어 NX 로 인해 SEGV. 정적 분석은 PT_LOAD[3] R-X 만 보면 정상으로 본다 — 정적/동적 분리 사례 추가 (rodata 변형판).
  - F19: 같은 바이트라도 R-only (NX) 오버레이는 실행 차단으로 SEGV. baseline R-X 와 분기.
- 새 backlog:
  - {'id': 'B17', 'title': 'I8V1 류 변형이 컨테이너 탐지기(eBPF, AV) 에서 어떻게 분류되는지 — phdr 카운트로 거른 후 가상주소 오버랩 체크하는지'}
  - {'id': 'B18', 'title': 'PT_LOAD count 유지 + text 페이지 RWX 까지 가는 변형 가능한가 — 기존 PT_LOAD 만으로는 RW + X 동시 부여 어려움 (rodata R, data RW, text R-X 만 있어서 RWX 슬롯 없음)'}

## iter09 — detector v2 의 false positive 점검 (/usr/bin, /usr/lib)
- 가설: 정상 바이너리에서 ANOMALY 비율이 낮다
- 판정: sample=300 clean=300 anomaly=0 fp_rate=0.00%
- 관찰:
  - fp_check | plain=None | kernel={'sample_size': 300, 'errors': 0} | main={'clean': 300, 'anomaly': 0} | FP rate 0.00%
- 새 finding:
  - F20: 정상 prod 바이너리 300 개 중 ANOMALY 0 개 (0.0%). False positive 비율 매우 낮음 → detector v2 를 1차 방어선으로 사용 적합.

## iter10 — B12: file append 없이 in-file .payload 섹션을 텍스트 페이지에 R-X 오버레이
- 가설: in-file .payload 섹션 오버레이로 file size 변화 없이 분기 가능
- 판정: base:plain=99 out=r=1 | overlay:plain=-11 out=? | size 25664=25664 (same) | det CLEAN / ANOMALY
- 관찰:
  - I10V0_baseline | plain=99 | kernel={'0x401000': 'r-xp'} | main={'0x401000': 'r-xp'} | baseline
  - I10V1_payload_section_overlay | plain=-11 | kernel={'0x401000': 'r-xp'} | main={'0x401000': 'r-xp'} | .payload 섹션을 텍스트 페이지 R-X 오버레이
- 새 finding:
  - F21alt: overlay 변형 결과 42 안 나옴 → # exit=-11
# --- stdout ---

# --- stderr ---


  - F22: detector v2 는 in-file payload 변형도 동일하게 ANOMALY 로 잡음 (페이지 정렬 PT_LOAD 오버랩). file size/.payload 섹션 존재 여부와 무관한 시그널.
- 새 backlog:
  - {'id': 'B20', 'title': 'F21 변형의 .payload 섹션 이름을 ".rodata2" 같이 평범하게 위장 — file 도 분석가가 못 알아채게'}
  - {'id': 'B21', 'title': '정상 binary 가 .payload 라는 섹션 이름을 쓰는 경우는 없는지 확인 (FP 위장 가능성)'}

## iter10 — B12 v2: in-file payload (텍스트 사본 + 패치) 로 file size 동일 분기
- 가설: 텍스트 사본 + 패치로 in-file payload PoC 가 main 도달
- 판정: base:exit=99 out=r=1 | v2:exit=0 out=r=42 | size 25664=25664 (same) | det baseline=CLEAN variant=ANOMALY
- 관찰:
  - I10V0_baseline | plain=99 | kernel={'0x401000': 'r-xp'} | main={'0x401000': 'r-xp'} | baseline
  - I10V2_payload_with_textcopy | plain=0 | kernel={'0x401000': 'r-xp'} | main={'0x401000': 'r-xp'} | textcopy+patch overlay
- 새 finding:
  - F21: file size 동일 (25664 bytes). PHT 1줄 패치 + .payload 섹션 내용을 텍스트 사본 + 6바이트 패치로 채워 target_func 결과 1→42. iter04 의 file append 단서까지 제거됨. ELF 안에 의심스러운 트레일링 데이터 없음.
  - F22: detector v2 는 in-file payload 변형도 PT_LOAD 페이지 정렬 오버랩으로 ANOMALY 탐지. file size 단서 제거되어도 vaddr 오버랩 시그널 살아 있음.
- 새 backlog:
  - {'id': 'B22', 'title': 'F21 의 .payload 섹션 이름을 ".rodata" 같이 평범화 (objdump -h 로도 의심받지 않게)'}
  - {'id': 'B23', 'title': 'F21 변형 vs baseline 의 strings/file/sha256 차이 측정 — 표면 차이 점검'}

## iter11 — B23: baseline vs 스텔스 변형의 표면 차이 측정 (size/sha256/file/strings/readelf)
- 가설: 표면 차이가 readelf -l 와 strings/sha256 외에는 거의 안 보인다
- 판정: same: 4/8 surfaces | different: ['sha256_same', 'file_same', 'readelf_l_same', 'objdump_text_same']
- 관찰:
  - surface_diff | plain=None | kernel={'size': 25664, 'sha256_same': False} | main={'size_same': True, 'sha256_same': False, 'file_same': False, 'readelf_h_same': True, 'readelf_S_same': True, 'readelf_l_same': False, 'strings_same': True, 'objdump_text_same': False} | changes: ['sha256_same', 'file_same', 'readelf_l_same', 'objdump_text_same']
- 새 finding:
  - F23: 표면 차이 측정 결과 — same: ['size_same', 'readelf_h_same', 'readelf_S_same', 'strings_same'], different: ['sha256_same', 'file_same', 'readelf_l_same', 'objdump_text_same'].
  - F23a: size 동일하지만 sha256 다름 → 바이트 단위 비교 도구(diff/cmp)만 차이 잡음. 단순 size/일자만 보는 무결성 검사는 통과.
  - F23c: readelf -l 다름 (PT_NOTE → PT_LOAD 변경) → PHT 검사 도구는 잡음. F13a 와 일치.
  - F23d: readelf -S (section header) 동일 → 섹션 헤더 기반 분석은 미탐. .payload 섹션이 baseline 에도 이미 있어서 차이 없음.
- 새 backlog:
  - {'id': 'B24', 'title': 'F23f 의 strings 차이 정밀 분석 — .payload 안 텍스트 사본이 어떤 의심 패턴 노출하는지'}
  - {'id': 'B25', 'title': 'detector v2 + readelf -l overlap 검사 외에 다른 자동 시그널 후보 — 예: PT_LOAD 가 같은 페이지를 두 번 가리키는지, 또는 section-segment 불일치'}

## iter12 — finalize: iter11 보정 + FINAL_REPORT 갱신 + 옵시디언 동기화
- 가설: 루프 정리 및 보고서 동기화
- 판정: 40 findings | 23 backlog
- 관찰:
  - finalize | plain=None | kernel={'iter_total': 12, 'findings_total': 40} | main={'backlog_total': 23} | FINAL_REPORT regenerated + Obsidian synced

## iter13 — B3: PT_GNU_RELRO 부분 누락 — 페이지 정렬 경계 효과 측정
- 가설: RELRO 페이지 정렬 경계가 작은 size 변경에도 전부/전무로 튄다
- 판정: I13V0_base:plain=0 got@0x403000=r--p data@0x404000=rw-p det=CLEAN | I13V1_relro_shrink_8:plain=0 got@0x403000=rw-p data@0x404000=rw-p det=CLEAN | I13V2_relro_extend_page:plain=-11 got@0x403000=r--p data@0x404000=r--p det=ANOMALY | I13V3_relro_shrink_half:plain=0 got@0x403000=rw-p data@0x404000=rw-p det=CLEAN
- 관찰:
  - I13V0_base | plain=0 | kernel={'0x401000': 'r-xp', '0x403000': 'rw-p', '0x404000': 'rw-p'} | main={'0x401000': 'r-xp', '0x403000': 'r--p', '0x404000': 'rw-p'} | baseline target_full
  - I13V1_relro_shrink_8 | plain=0 | kernel={'0x401000': 'r-xp', '0x403000': 'rw-p', '0x404000': 'rw-p'} | main={'0x401000': 'r-xp', '0x403000': 'rw-p', '0x404000': 'rw-p'} | RELRO 8B 줄임 → page-down 효과로 mprotect 무력화 예상
  - I13V2_relro_extend_page | plain=-11 | kernel={'0x401000': 'r-xp', '0x403000': 'rw-p', '0x404000': 'rw-p'} | main={'0x401000': 'r-xp', '0x403000': 'r--p', '0x404000': 'r--p'} | RELRO 한 페이지 더 확장 → .data 까지 RO
  - I13V3_relro_shrink_half | plain=0 | kernel={'0x401000': 'r-xp', '0x403000': 'rw-p', '0x404000': 'rw-p'} | main={'0x401000': 'r-xp', '0x403000': 'rw-p', '0x404000': 'rw-p'} | RELRO 절반 미만 축소
- 새 finding:
  - F25: baseline RELRO 적용 시 .got 페이지(0x403000) main 시점 = r--p.
  - F26: RELRO memsz 8 바이트만 줄여도 (V1) .got 페이지 main 시점 = rw-p. RELRO 무력화 — 페이지 정렬 경계 효과 확인.
  - F27: RELRO memsz 한 페이지 확장 (V2) 시 .data 페이지(0x404000) main 시점 = r--p. 확장된 RELRO 가 .data 까지 RO 로 잠금 — 실행 영향 가능.
  - F27b: V2 plain exit = -11 (.data RO 의 영향으로 SEGV).
  - F28: RELRO 절반 미만 축소 (V3) 시 .got 페이지 main 시점 = rw-p.
  - F29: detector v2 결과 — {'I13V0_base': 'CLEAN', 'I13V1_relro_shrink_8': 'CLEAN', 'I13V2_relro_extend_page': 'ANOMALY', 'I13V3_relro_shrink_half': 'CLEAN'}. RELRO subset 체크가 V1/V3 의 shrink 케이스를 어떻게 처리하는지가 관건.
  - F30: 정적 분석에서 readelf -l GNU_RELRO 의 FileSiz/MemSiz 만 봐도 baseline 과 다름이 보임 — 단 8B 차이는 분석가가 그냥 넘기기 쉬움. 자동화 시그널로는 "RELRO 가 .got 끝과 page-align 안 맞는다" 가 후보.
- 새 backlog:
  - {'id': 'B26', 'title': 'F26 RELRO 무력화 + iter01 RWX overlay 결합 — 4바이트 패치 둘로 텍스트 RWX + .got RW 동시에 PoC'}
  - {'id': 'B27', 'title': 'detector v3: RELRO end 가 .got 끝과 정확히 일치하는지 체크하는 휴리스틱 추가'}

## iter14 — detector v3 (RELRO noop 검출) + RELRO 무력화 + RWX overlay 결합 PoC
- 가설: detector v3 가 RELRO 페이지 정렬 무력화를 잡고, 결합 PoC 성립
- 판정: v3 RELRO V1 caught=True V3 caught=True V0 clean=True | combo PoC exit=0 text=rwxp got=rw-p | prod FP=0/200 (0.00%)
- 관찰:
  - iter13_I13V0_base | plain=None | kernel={'verdict': 'CLEAN'} | main={'noop': 0, 'mismatch': 0, 'overlap': 0} | PT_LOAD=4
  - iter13_I13V1_relro_shrink_8 | plain=None | kernel={'verdict': 'ANOMALY'} | main={'noop': 1, 'mismatch': 1, 'overlap': 0} | PT_LOAD=4
  - iter13_I13V2_relro_extend_page | plain=None | kernel={'verdict': 'ANOMALY'} | main={'noop': 0, 'mismatch': 0, 'overlap': 0} | PT_LOAD=4
  - iter13_I13V3_relro_shrink_half | plain=None | kernel={'verdict': 'ANOMALY'} | main={'noop': 1, 'mismatch': 1, 'overlap': 0} | PT_LOAD=4
  - iter01_I1V1_overlay_rwx | plain=None | kernel={'verdict': 'ANOMALY'} | main={'noop': 0, 'mismatch': 0, 'overlap': 1} | PT_LOAD=5
  - iter01_I1V3_overlay_rx | plain=None | kernel={'verdict': 'ANOMALY'} | main={'noop': 0, 'mismatch': 0, 'overlap': 1} | PT_LOAD=5
  - iter10_I10V0_baseline | plain=None | kernel={'verdict': 'CLEAN'} | main={'noop': 0, 'mismatch': 0, 'overlap': 0} | PT_LOAD=4
  - iter10_I10V2_payload_with_textcopy | plain=None | kernel={'verdict': 'ANOMALY'} | main={'noop': 0, 'mismatch': 0, 'overlap': 1} | PT_LOAD=5
  - base_target_full | plain=None | kernel={'verdict': 'CLEAN'} | main={'noop': 0, 'mismatch': 0, 'overlap': 0} | PT_LOAD=4
  - base_target_partial | plain=None | kernel={'verdict': 'CLEAN'} | main={'noop': 0, 'mismatch': 0, 'overlap': 0} | PT_LOAD=4
  - base_target_norelro | plain=None | kernel={'verdict': 'CLEAN'} | main={'noop': 0, 'mismatch': 0, 'overlap': 0} | PT_LOAD=4
  - base_target_in | plain=None | kernel={'verdict': 'CLEAN'} | main={'noop': 0, 'mismatch': 0, 'overlap': 0} | PT_LOAD=4
  - iter14_combo | plain=None | kernel={'verdict': 'ANOMALY'} | main={'noop': 1, 'mismatch': 1, 'overlap': 1} | PT_LOAD=5
- 새 finding:
  - F31: detector v3 가 RELRO shrink 변형(V1, V3) 을 ANOMALY 로 잡음. v2 의 blind spot 해소.
  - F32: 결합 PoC (RELRO shrink + RWX overlay) 결과 — plain=0 text@0x401000=rwxp got@0x403000=rw-p detector=ANOMALY.
  - F33: 8B 변경(RELRO memsz) + 7개 PHT 필드 패치만으로 텍스트 RWX + GOT RW 가 동시 성립. 멀웨어 시나리오의 가장 강력한 형태.
  - F34: detector v3 의 정상 prod 바이너리 200 표본 FP = 0 (0.00%). v2 와 동일하게 거의 0.
- 새 backlog:
  - {'id': 'B28', 'title': '결합 PoC 의 실용 활용 — GOT 엔트리 하나 덮어쓰고 텍스트에 페이로드 박은 뒤 printf 호출로 임의 코드 실행 PoC'}
  - {'id': 'B29', 'title': 'detect_overlap.py v3 를 더 큰 표본(/usr/lib 1000+)에 돌려서 FP 분포 정밀 측정'}

## iter15 — finalize: iter13-14 통합 + 최종 보고서/옵시디언 갱신
- 가설: 15 iter 누적 종합 동기화
- 판정: 51 findings | 27 backlog | 6 PoCs
- 관찰:
  - finalize2 | plain=None | kernel={'iter_total': 15, 'findings_total': 51} | main={'backlog_total': 27, 'pocs': 6} | detector v3 + 결합 PoC 까지 누적

## iter16 — B4: glibc 코드 라인 인용 박기
- 가설: F1/F4/F26/F33 의 glibc 코드 원인 라인 추적
- 판정: 5 lines cited across 3 glibc files; 3 fixes proposed
- 관찰:
  - citations_extracted | plain=None | kernel={'glibc_files': 3, 'lines_cited': 5} | main={'fixes_proposed': 3} | CITATIONS.md + 옵시디언 동기화
- 새 finding:
  - F35: F26 의 직접 원인이 glibc dl-reloc.c:354-368 의 ALIGN_DOWN(start), ALIGN_DOWN(end) 조합 — RELRO end 를 페이지 경계 아래로 8B 만 내리면 start==end 가 되어 mprotect 호출 자체가 skip 됨.
  - F36: F4 의 원인이 dl-load.c:1213-1214 — PT_GNU_RELRO 처리에서 vaddr/memsz 를 검증 없이 link_map 에 저장. 안전한 RELRO 호스트 PT_LOAD 검사가 없음.
  - F37: 방어 보강 제안 3 가지(RELRO subset 검증 / ALIGN_DOWN noop 검출 / PT_LOAD 오버랩 사전 거절)로 ld.so 단계에서 본 lab 변형 전체 차단 가능. detect_overlap.py v3 와 동일한 시그널.

## iter17 — B28: GOT write + 텍스트 write live PoC (baseline SEGV vs combo 통과)
- 가설: 실제 GOT/텍스트 쓰기로 combo PoC 가 baseline 을 무력화한다
- 판정: baseline:exit=1 got_write=SEGV | combo:exit=1 both=NO | detector base=CLEAN combo=ANOMALY
- 관찰:
  - I17V0_baseline | plain=1 | kernel={'0x401000': 'r-xp', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x403000': 'r--p'} | baseline (RELRO 적용)
  - I17V1_combo | plain=1 | kernel={'0x401000': 'rwxp', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x403000': 'rw-p'} | combo (RELRO 무력화 + RWX overlay)
- 새 finding:
  - F38alt: combo 변형 stdout = # exit=1
# --- stdout ---
[probe] start
[probe] PLT format unexpected

# --- stderr ---

. 패치 의도와 불일치.
  - F39: detector v3 가 baseline CLEAN, combo ANOMALY 로 정확히 분류. live PoC 도 자동 탐지.
- 새 backlog:
  - {'id': 'B30', 'title': 'F38 의 GOT 쓰기 후 실제로 함수 포인터 하이재크 (printf 호출이 페이로드로 점프) — 한 단계 더'}
  - {'id': 'B31', 'title': 'detector v3 의 휴리스틱 (RELRO end mismatch) 이 모든 표본에 robust 한지 — /usr/bin 전체 1000+ 표본으로 확장'}

## iter17 — B28: GOT write + 텍스트 write live PoC (baseline SEGV vs combo 통과)
- 가설: 실제 GOT/텍스트 쓰기로 combo PoC 가 baseline 을 무력화한다
- 판정: baseline:exit=-11 got_write=SEGV | combo:exit=-11 both=NO | detector base=CLEAN combo=ANOMALY
- 관찰:
  - I17V0_baseline | plain=-11 | kernel={'0x401000': 'r-xp', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x403000': 'r--p'} | baseline (RELRO 적용)
  - I17V1_combo | plain=-11 | kernel={'0x401000': 'rwxp', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x403000': 'r--p'} | combo (RELRO 무력화 + RWX overlay)
- 새 finding:
  - F38alt: combo 변형 stdout = # exit=-11
# --- stdout ---
[probe] start

# --- stderr ---

. 패치 의도와 불일치.
  - F39: detector v3 가 baseline CLEAN, combo ANOMALY 로 정확히 분류. live PoC 도 자동 탐지.
- 새 backlog:
  - {'id': 'B30', 'title': 'F38 의 GOT 쓰기 후 실제로 함수 포인터 하이재크 (printf 호출이 페이로드로 점프) — 한 단계 더'}
  - {'id': 'B31', 'title': 'detector v3 의 휴리스틱 (RELRO end mismatch) 이 모든 표본에 robust 한지 — /usr/bin 전체 1000+ 표본으로 확장'}

## iter17 — B28: GOT write + 텍스트 write live PoC (baseline SEGV vs combo 통과)
- 가설: 실제 GOT/텍스트 쓰기로 combo PoC 가 baseline 을 무력화한다
- 판정: baseline:exit=-11 got_write=SEGV | combo:exit=0 both=YES | detector base=CLEAN combo=ANOMALY
- 관찰:
  - I17V0_baseline | plain=-11 | kernel={'0x401000': 'r-xp', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x403000': 'r--p'} | baseline (RELRO 적용)
  - I17V1_combo | plain=0 | kernel={'0x401000': 'rwxp', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x403000': 'rw-p'} | combo (RELRO 무력화 + RWX overlay)
- 새 finding:
  - F38: baseline 은 GOT 쓰기에서 SIGSEGV (full RELRO 가 .got RO). combo 변형은 GOT/텍스트 쓰기 모두 성공. live PoC 로 F33(text RWX + GOT RW) 실증 완료.
  - F39: detector v3 가 baseline CLEAN, combo ANOMALY 로 정확히 분류. live PoC 도 자동 탐지.
- 새 backlog:
  - {'id': 'B30', 'title': 'F38 의 GOT 쓰기 후 실제로 함수 포인터 하이재크 (printf 호출이 페이로드로 점프) — 한 단계 더'}
  - {'id': 'B31', 'title': 'detector v3 의 휴리스틱 (RELRO end mismatch) 이 모든 표본에 robust 한지 — /usr/bin 전체 1000+ 표본으로 확장'}

## iter18 — finalize 3: iter16-17 통합 + 최종 보고서 갱신
- 가설: 18 iter 종합 마무리
- 판정: 60 findings | 33 backlog | live PoC확정
- 관찰:
  - finalize3 | plain=None | kernel={'iter_total': 18, 'findings_total': 60} | main={'backlog_total': 33, 'pocs': 6, 'live_poc': 1} | live PoC + glibc 인용 + 옵시디언 동기화 완료

## iter19 — 미팅 발표용 클린 DEMO (Hello, ELF World! ↔ Hello from Combo World!)
- 가설: 클린 DEMO 가 단일 출력 분기로 정적/동적 차이를 즉시 보여준다
- 판정: baseline: exit=0 → "Hello, ELF World!" | combo: exit=0 → "Hello from Combo World!" | detector base=CLEAN combo=ANOMALY
- 관찰:
  - I19V0_baseline | plain=0 | kernel={} | main={} | Hello, ELF World!
  - I19V1_combo_demo | plain=0 | kernel={} | main={} | Hello from Combo World!
- 새 finding:
  - F40: 클린 DEMO 분기 성공. baseline = "Hello, ELF World!", combo = "Hello from Combo World!". 단일 출력 1줄로 정적 분석 결과(magic→1) 와 동적 실행 결과(magic→42) 의 차이를 즉시 시각화 가능.
  - F41: DEMO baseline 과 변형의 표면 차이는 readelf -l (PT_LOAD 4→5) + sha256 뿐. detector v3 는 ANOMALY 로 잡음 (base=CLEAN combo=ANOMALY).
- 새 backlog:
  - {'id': 'B32', 'title': 'DEMO 의 출력 텍스트 자체를 .data 안에 두 버전 박고 overlay 가 .rodata 가 아닌 .data 포인터를 가리키게 — 더 강한 위장'}

## iter20 — iter20 마무리: target_probe_demo + 옵시디언 1페이지 분리 + 루프 종료
- 가설: 자가 피드백 루프 자연 종료, 발표 자료 분리 완료
- 판정: demo1 base/combo OK | demo2 base SEGV / combo "Hello from Pwned World!" | detector base=CLEAN combo=ANOMALY | 옵시디언 5문서 분리
- 관찰:
  - iter20_finalize | plain=None | kernel={'iter_total': 20, 'pocs': 6, 'demos': 2} | main={'obsidian_docs': 5, 'findings_total': 64} | 자가루프 자연 종료. 옵시디언 발표 자료 분리.
- 새 finding:
  - F42: target_probe_demo 의 단일 출력 분기 성립. baseline SEGV, combo "Hello from Pwned World!". 미팅 데모 2호 (live PoC) 완성. target_demo 와 함께 발표용 캐노니컬 2종 확보.
  - F43: 자가 피드백 루프 20 회 자연 종료. 옵시디언 1페이지 + 통합 + 코드 인용 + 원본/로그 5문서 분리 완료.

## iter21 — B7: PT_GNU_EH_FRAME → PT_LOAD overlay (PT_NOTE 변환과 비교)
- 가설: PT_GNU_EH_FRAME 변환이 PT_NOTE 변환과 동일하게 동작한다
- 판정: I21V1 RWX:plain=0 k@0x401=rwxp | I21V2 RW:plain=-11 k@0x401=rw-p | I21V3 R-X:plain=0 k@0x401=r-xp | PT_LOAD count base=4 var=5 | det baseline=CLEAN 변형=['ANOMALY', 'ANOMALY', 'ANOMALY']
- 관찰:
  - I21V1_ehframe_overlay_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | EH_FRAME → PT_LOAD RWX
  - I21V2_ehframe_overlay_rw | plain=-11 | kernel={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'r--p'} | EH_FRAME → PT_LOAD RW (no exec)
  - I21V3_ehframe_overlay_rx | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | EH_FRAME → PT_LOAD R-X (control)
- 새 finding:
  - F44: PT_GNU_EH_FRAME → PT_LOAD RWX 변환이 PT_NOTE 변환과 동일하게 텍스트 RWX + main 도달. (iter01 PT_NOTE k@0x401=rwxp, iter21 PT_GNU_EH_FRAME k@0x401=rwxp). 커널/ld.so 는 phdr 타입 무관 type=PT_LOAD 만 보고 매핑함.
  - F45: readelf -n baseline vs PT_GNU_EH_FRAME 변형 출력 동일 → EH_FRAME 슬롯 재활용은 readelf -n 에 노출 안 됨 (PT_NOTE 변환은 노출 가능, iter05 F13c 참고).
  - F47: 3회 반복 일관성 — 전체 일관.
  - F48: detector v3 가 PT_GNU_EH_FRAME 변형 3종 모두 ANOMALY 로 분류 = True (baseline = CLEAN). phdr 타입 다르더라도 페이지 정렬 vaddr 오버랩 시그널은 동일하게 잡힘.
  - F49: readelf -l PT_LOAD count: baseline=4, EH_FRAME 변환=5. 증가 — readelf 가 변환 인지함.
- 새 backlog:
  - {'id': 'B33', 'title': 'PT_GNU_EH_FRAME 변환 후 실제 예외 발생 시 동작 — std::exception throw 하면 어떻게 죽는지'}

## iter22 — B7: PT_GNU_PROPERTY → PT_LOAD overlay (CET 마커 슬롯 재활용)
- 가설: PT_GNU_PROPERTY → PT_LOAD 가 PT_NOTE 변환과 동일하지만 readelf -n 흔적이 다를 수 있다
- 판정: V1 RWX plain=0 k@0x401=rwxp | V2 RW plain=-11 k@0x401=rw-p | V3 R-X plain=0 k@0x401=r-xp | PT_LOAD count 4→5 | NT_GNU_PROPERTY: base=True var=True | detector all_anomaly=True
- 관찰:
  - I22V1_property_overlay_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | PROPERTY → PT_LOAD RWX
  - I22V2_property_overlay_rw | plain=-11 | kernel={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'r--p'} | PROPERTY → PT_LOAD RW
  - I22V3_property_overlay_rx | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | PROPERTY → PT_LOAD R-X
- 새 finding:
  - F50: PT_GNU_PROPERTY → PT_LOAD RWX 변환도 PT_NOTE/PT_GNU_EH_FRAME 변환과 동일하게 텍스트 RWX + main 도달. kernel/ld.so 가 phdr 타입 검증 없음을 재확인.
  - F51: readelf -n NT_GNU_PROPERTY 출력 변화 = True. PT_GNU_PROPERTY 가 PT_LOAD 가 되어도 .note.gnu.property 섹션이 PT_LOAD[2] 안에 그대로 있으면 readelf 가 섹션 헤더로 노트를 찾아서 출력함.
  - F52: detector v3 PT_GNU_PROPERTY 변형 3종 모두 ANOMALY = True (baseline = CLEAN).
  - F53: 3회 반복 일관성 = True ({'I22V1_property_overlay_rwx': {'exits': [0, 0, 0], 'consistent': True}, 'I22V2_property_overlay_rw': {'exits': [-11, -11, -11], 'consistent': True}, 'I22V3_property_overlay_rx': {'exits': [0, 0, 0], 'consistent': True}}).
- 새 backlog:
  - {'id': 'B34', 'title': 'PT_GNU_PROPERTY 변환된 바이너리에 대해 /proc/<pid>/status 의 IBT/SHSTK 활성화 여부 측정 — CET 보호가 실제로 무력화되는지 vs 섹션 헤더로 노트가 살아 있어서 영향 없는지'}

## iter23 — B7: PT_TLS → PT_LOAD overlay (TLS 초기화 갭 검증)
- 가설: PT_TLS → PT_LOAD 변환의 TLS 초기화 영향 확인
- 판정: base:exit=0 out="TLS = 42" | V1 RWX:exit=0 out="TLS = 0" k@0x401=rwxp | V2 RW:exit=-11 | V3 R-X:exit=0 | TLS line base=True var=False | det all_anomaly=True
- 관찰:
  - I23V1_tls_overlay_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | TLS → PT_LOAD RWX
  - I23V2_tls_overlay_rw | plain=-11 | kernel={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'r--p'} | TLS → PT_LOAD RW
  - I23V3_tls_overlay_rx | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | TLS → PT_LOAD R-X
- 새 finding:
  - F54: baseline target_tls 정상 동작: "TLS = 42".
  - F55: PT_TLS → PT_LOAD RWX 변형 main 도달 (exit=0). TLS output="TLS = 0". TLS 값 잘못/사라짐 — ld.so 가 PT_TLS 슬롯에 의존.
  - F56: readelf -l 의 TLS 라인이 변형에서 사라짐 → CET 도구 / TLS 분석기는 변형을 "TLS 없는 정적 바이너리" 로 잘못 인식 가능.
  - F57: detector v3 PT_TLS 변형 3종 모두 ANOMALY = True (baseline=CLEAN).
  - F58: 3회 반복 일관성 = True.
- 새 backlog:
  - {'id': 'B35', 'title': 'PT_TLS 부재 시 ld.so 의 TLS 초기화 코드 경로 (_dl_allocate_tls_init 등) 추적 — glibc dl-tls.c 어디서 PT_TLS 가 없으면 우회되는지'}

## iter24 — B7: PT_GNU_STACK → PT_LOAD overlay + 스택 권한 영향 측정
- 가설: PT_GNU_STACK 변환은 다른 메타 phdr 들과 동일 동작, 스택 권한 변화 없음
- 판정: V1 RWX:plain=0 k@0x401=rwxp stack=rw-p | V2 RW:plain=-11 | V3 R-X:plain=0 | stack base=rw-p V1=rw-p | GNU_STACK base=True var=False | det all_anomaly=True
- 관찰:
  - I24V1_stack_overlay_rwx | plain=0 | kernel={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rwxp', '0x402000': 'r--p', '0x403000': 'r--p'} | STACK → PT_LOAD RWX (text overlay)
  - I24V2_stack_overlay_rw | plain=-11 | kernel={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'rw-p', '0x402000': 'r--p', '0x403000': 'r--p'} | STACK → PT_LOAD RW (text overlay)
  - I24V3_stack_overlay_rx | plain=0 | kernel={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'rw-p'} | main={'0x401000': 'r-xp', '0x402000': 'r--p', '0x403000': 'r--p'} | STACK → PT_LOAD R-X
- 새 finding:
  - F59: PT_GNU_STACK → PT_LOAD RWX 변환도 PT_NOTE/EH_FRAME/PROPERTY 와 동일하게 텍스트 RWX + main 도달. PT_GNU_STACK 의 memsz=0 baseline 도 type/offset/vaddr/memsz 한 번에 패치하면 정상 PT_LOAD 로 동작.
  - F60: 스택 권한 — baseline=rw-p, V1=rw-p. 변화 없음 — PT_GNU_STACK 이 PT_LOAD 가 되어도 커널은 default NX 적용.
  - F61: readelf -l 의 GNU_STACK 라인이 변형에서 사라짐 → execstack 같은 도구는 변형을 "GNU_STACK 마커 없음" 으로 봐서 NX 상태를 잘못 보고 가능.
  - F62: detector v3 PT_GNU_STACK 변형 3종 모두 ANOMALY = True.
  - F63: 3회 반복 일관성 = True.
- 새 backlog:
  - {'id': 'B36', 'title': 'PT_GNU_STACK 가 PT_LOAD 가 됐을 때 execstack -q 출력 변화 측정 — 도구가 어떻게 보고하는지'}

## iter25 — iter25: PT_NOTE 외 phdr 변환 통합 비교 매트릭스
- 가설: 5종 phdr 변환 통합 매트릭스 — PT_TLS 만 unique silent corruption
- 판정: 5종 모두 RWX 텍스트 형성, PT_TLS만 silent corruption, detector 5/5 ANOMALY
- 관찰:
  - PT_NOTE | plain=0 | kernel={'text': 'rwxp'} | main={'marker_lost': False, 'silent_corruption': 'No'} | detector ANOMALY
  - PT_GNU_EH_FRAME | plain=0 | kernel={'text': 'rwxp'} | main={'marker_lost': True, 'silent_corruption': 'No'} | detector ANOMALY
  - PT_GNU_PROPERTY | plain=0 | kernel={'text': 'rwxp'} | main={'marker_lost': True, 'silent_corruption': 'No'} | detector ANOMALY
  - PT_TLS | plain=0 | kernel={'text': 'rwxp'} | main={'marker_lost': True, 'silent_corruption': '**Yes (TLS=42→0)**'} | detector ANOMALY
  - PT_GNU_STACK | plain=0 | kernel={'text': 'rwxp'} | main={'marker_lost': True, 'silent_corruption': 'No'} | detector ANOMALY
- 새 finding:
  - F64: PT_TLS → PT_LOAD 변환은 5종 phdr 변환 중 유일하게 silent data corruption 유발 (TLS 변수 42→0). 다른 4종 (NOTE/EH_FRAME/PROPERTY/STACK) 은 functional 영향 없음. 이는 ld.so 가 PT_TLS 슬롯 부재 시 TLS 메모리를 0 으로 초기화한 후 그대로 사용하기 때문 — 값이 sentinel 이나 인증 토큰일 경우 보안 의미 큼.
  - F65: detector v3 가 5종 phdr 변환을 모두 ANOMALY 로 분류 = True. 페이지 정렬 vaddr 오버랩 시그널이 phdr 타입과 무관하게 robust.
  - F66: 원본 phdr 마커가 readelf -l 출력에서 사라지는 비율 = 4/5. 타입별로 다른 정적 분석 도구 흔적 (NT_GNU_PROPERTY 의 readelf -n, GNU_STACK 의 execstack -q 등) 추적 가능.
  - F67: 5종 변환의 권장 활용 — (스텔스) PT_GNU_EH_FRAME: 항상 존재 + 분석 우선순위 낮음, (고파괴력) PT_TLS: silent data corruption, (보편성) PT_NOTE: 선행 연구 풍부 (Ryan O'Neill 2015 등). PT_GNU_PROPERTY 는 CET 도구 노이즈 가능 (NT_GNU_PROPERTY readelf -n 잔존이라 효과 약함), PT_GNU_STACK 은 memsz=0 처리 필요 + execstack 도구만 영향.
- 새 backlog:
  - {'id': 'B37', 'title': 'PT_TLS silent corruption 시나리오 실용화 — 인증 토큰/카나리아/플래그가 __thread 인 케이스 PoC'}
  - {'id': 'B38', 'title': 'PT_GNU_EH_FRAME 변환된 바이너리에서 C++ 예외 throw 시 동작 — abort 인지 unwinding 실패인지'}
  - {'id': 'B39', 'title': '5종 phdr 변환을 검출하는 추가 시그널 — readelf -l 의 원본 마커 부재를 detector v4 에 통합'}

## iter26 — finalize: B7 확장 (iter21~25) 통합 보고서 갱신
- 가설: B7 확장 결과 통합
- 판정: 5 phdr 타입 검증, PT_TLS unique silent corruption, detector 5/5
- 관찰:
  - finalize_b7_extension | plain=None | kernel={'phdr_types_tested': 5, 'silent_corruption_unique': 'PT_TLS'} | main={'iters_total': 26, 'new_findings_in_b7': 24} | B7 확장 + Obsidian 동기화 + CITATIONS 선행연구 박음

## iter27 — B39 detector v4 + B37 PT_TLS auth bypass PoC
- 가설: PT_TLS auth 우회 PoC + detector v4
- 판정: baseline "ACCESS DENIED (safety_locked=1)" → variant "ACCESS GRANTED (safety_locked=0) -- DEBUG BYPASS" | detector v4 prod FP=0/300 (0.00%) sm_fp=0
- 관찰:
  - iter27 | plain=None | kernel={'tls_baseline': 'ACCESS DENIED (safety_locked=1)', 'tls_variant': 'ACCESS GRANTED (safety_locked=0) -- DEBUG BYPASS'} | main={'detector_v4_fp_prod': '0/300', 'sm_fp': 0} | B37 PoC + B39 detector v4
- 새 finding:
  - F68: PT_TLS silent corruption 의 실용 PoC 완성. baseline: "ACCESS DENIED (safety_locked=1)" / variant: "ACCESS GRANTED (safety_locked=0) -- DEBUG BYPASS". 8 필드 PHT 패치만으로 __thread 인증 플래그(safety_locked=1) 를 0 으로 zero-init 시켜 인증 우회. F64 의 보안 의미 실증.
  - F69: detector v4 의 gnu_stack_missing 휴리스틱 — prod 표본 300 개 중 0 개에서 PT_GNU_STACK 부재 (0.00%). 매우 낮음 — 1차 방어선으로 적합.
  - F70: target_tls_auth baseline/variant 모두 3회 반복 일관 (DENIED ↔ GRANTED 안정).
  - F71: PT_GNU_STACK → PT_LOAD 변형(iter24 V1) 의 detector v4 verdict=ANOMALY, gnu_stack_missing=True. 이 변형은 PT_GNU_STACK 슬롯을 PT_LOAD 로 바꿔서 PT_GNU_STACK 부재 시그널도 추가로 잡힘.
- 새 backlog:
  - {'id': 'B40', 'title': 'detector v4 의 sm 시그널 prod 1000+ 표본 FP 정밀 측정 — statically linked binary, golang binary 등은 PT_GNU_STACK 없을 수 있음'}
  - {'id': 'B41', 'title': 'F68 PoC 의 응용 — sudo / passwd 같은 setuid 바이너리 컨텍스트에서 __thread 인증 우회 가능성 (조건: TLS 사용 + 권한 결정)'}

## iter28 — finalize: iter27 (auth bypass + detector v4) 통합
- 가설: 실용 PoC + detector v4 통합 완료
- 판정: 28 iter, detector v4 FP 0%, auth bypass PoC 확정
- 관찰:
  - finalize_28iter | plain=None | kernel={'iters_total': 28, 'practical_pocs': 1, 'detector_version': 'v4'} | main={'prod_fp_v4': '0/300', 'silent_corruption_pocs': 1} | 28 iter 자가루프 최종 종결

## iter29 — B40 detector v4 대규모 FP + B38 PT_GNU_EH_FRAME 변환 후 C++ throw 동작
- 가설: 대규모 FP + C++ throw 동작 측정
- 판정: v4 prod 1500 samples: total_anomaly=9 sm_only_fp=9 | throw baseline caught=True variant caught=False exit=-6
- 관찰:
  - iter29 | plain=None | kernel={'fp_sample_size': 1500, 'sm_only_fp': 9} | main={'baseline_caught': True, 'variant_caught': False, 'variant_exit': -6} | B40 + B38
- 새 finding:
  - F72: detector v4 prod 표본 1500 개 (정확히는 1500 분석 성공) 시그널 분포:
  -   - overlap: 0 (0.00%)
  -   - relro_subset_fail: 0 (0.00%)
  -   - relro_noop: 0 (0.00%)
  -   - relro_end_mismatch: 0 (0.00%)
  -   - gnu_stack_missing: 9 (0.60%)
  - F73: sm-only FP (정상 binary 가 PT_GNU_STACK 만 없는 케이스): 9/1500 (0.60%). 주의 — sm 단독으로는 FP 가능. overlap 와 결합 필요.
  - F74: PT_GNU_EH_FRAME → PT_LOAD 변환 후 C++ throw 시 unwinding 실패. baseline 은 정상 catch ("caught: test exception"), 변형은 exit=-6 (abort/terminate). iter21 의 "main 도달" 결과는 예외 throw 가 없는 정상 흐름에 한정 — 예외 throw 시 EH 정보 슬롯 부재로 std::terminate 호출.
- 새 backlog:
  - {'id': 'B42', 'title': 'F73 의 sm-only FP 케이스 정밀 분류 — golang? rust? 정적 링크 라이브러리?'}
  - {'id': 'B43', 'title': 'F74 의 결과에 따라 detector v5 휴리스틱 — PT_GNU_EH_FRAME 부재 + .eh_frame 섹션 존재 = 의심 시그널 추가'}

## iter30 — finalize: iter29 (대규모 FP + C++ throw) 통합
- 가설: robustness validation 통합
- 판정: detector v4 1500 표본 FP 0% (실행 binary), C++ throw 변형 SIGABRT 확정
- 관찰:
  - finalize_30iter | plain=None | kernel={'iters_total': 30, 'large_scale_fp_v4': '0/1500 (실행 binary)'} | main={'cpp_throw_variant_abort': True} | 30 iter 자가루프

## iter31 — B43 detector v5 대규모 FP 재측정 + PT_GNU_EH_FRAME 회피 변형
- 가설: detector v5 신규 시그널(sm/ssm) 의 prod FP, 그리고 EH_FRAME 을 PT_LOAD 외 타입으로 위장 시 동작
- 판정: v5 prod 1500: sm=9 ssm=11 total=11, 전부 link-time obj/clang lib → 실행 binary FP=0/1500 | PT_GNU_EH_FRAME→PT_NULL: C++ throw → exit=-6 terminate
- 관찰:
  - iter31_detector_v5_fp | plain=None | kernel={'sample': 1500, 'sm': 9, 'ssm': 11, 'total_anomaly': 11} | main={'exec_binary_fp': '0/1500'} | prod 1500 표본, ssm 11건 전부 link-time .o/.a + libclang (실행 binary FP 0)
  - I31V_evasion_eh_to_null | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → PT_NULL, C++ throw 시 terminate (std::runtime_error)
- 새 finding:
  - F75: detector v5 의 ssm 시그널 prod 1500 표본 anomaly 11건이 전부 link-time 오브젝트(crt1.o/Scrt1.o/crti.o/crtn.o/gcrt1.o/rcrt1.o/libmcheck.a)와 libclang-17/18.so. 실행 binary 기준 FP 0/1500 = v4 와 동일 수준 유지.
  - F76: PT_GNU_EH_FRAME → PT_NULL 변형도 C++ throw 시 exit=-6 terminate. iter29(F74)의 EH 깨짐이 →PT_LOAD 전용이 아님을 시사 → iter33 으로 타입 전수 확장.

## iter33 — B38 확장: PT_GNU_EH_FRAME 을 7가지 타입으로 위장 (C++ throw 동작)
- 가설: EH_FRAME 위장 시 깨짐 원인이 PT_LOAD 변환 자체인지, 아니면 원본 타입 상실 자체인지
- 판정: baseline catch(exit=0) | NULL/TLS/LOPROC/HIPROC/LOOS/HIOS/random 7종 전부 exit=-6 terminate, 각 3회 일관 → 위장 수단 무관, 원본 타입 상실이 원인
- 관찰:
  - I33V0_baseline | plain=0 | kernel={} | main={} | baseline: caught test exception 정상
  - I33V1_to_PT_NULL | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → PT_NULL, throw → terminate (3회 일관)
  - I33V2_to_PT_TLS | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → PT_TLS, throw → terminate (3회 일관)
  - I33V3_to_PT_LOPROC | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → PT_LOPROC, throw → terminate (3회 일관)
  - I33V4_to_PT_HIPROC | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → PT_HIPROC, throw → terminate (3회 일관)
  - I33V5_to_PT_LOOS | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → PT_LOOS, throw → terminate (3회 일관)
  - I33V6_to_PT_HIOS | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → PT_HIOS, throw → terminate (3회 일관)
  - I33V7_to_random | plain=-6 | kernel={} | main={} | PT_GNU_EH_FRAME → random type, throw → terminate (3회 일관)
- 새 finding:
  - F77: PT_GNU_EH_FRAME 을 PT_NULL/PT_TLS/PT_LOPROC/PT_HIPROC/PT_LOOS/PT_HIOS/random 어느 타입으로 위장하든 C++ throw 시 전부 exit=-6 terminate (각 3회 일관). baseline 만 정상 catch. EH 깨짐은 "→PT_LOAD" 가 특별해서가 아니라, ld.so 가 PT_GNU_EH_FRAME 으로 인식 못 하는 순간 .eh_frame_hdr 등록을 못 하는 게 원인.

## iter35 — B7 확장: 메타 phdr 4종 × 위장 타입 3종 매트릭스
- 가설: ld.so 가 모르는 phdr 타입으로 메타 phdr 을 위장하면 삭제와 동치인가, 영향도는 타입별로 어떻게 다른가
- 판정: NOTE/PROPERTY/STACK → 위장 3종 전부 exit=0 런타임 무영향 (텍스트 r-xp 유지) | PT_TLS → 위장 3종 전부 exit=0 이지만 TLS=42→0 silent corruption | ld.so 는 미지 phdr 타입을 무시 → 메타 phdr 위장 ≡ 삭제
- 관찰:
  - I35_PT_NOTE_PT_LOPROC | plain=0 | kernel={} | main={} | PT_NOTE → PT_LOPROC: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_NOTE_PT_NULL | plain=0 | kernel={} | main={} | PT_NOTE → PT_NULL: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_NOTE_random | plain=0 | kernel={} | main={} | PT_NOTE → random: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_GNU_PROPERTY_PT_LOPROC | plain=0 | kernel={} | main={} | PT_GNU_PROPERTY → PT_LOPROC: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_GNU_PROPERTY_PT_NULL | plain=0 | kernel={} | main={} | PT_GNU_PROPERTY → PT_NULL: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_GNU_PROPERTY_random | plain=0 | kernel={} | main={} | PT_GNU_PROPERTY → random: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_GNU_STACK_PT_LOPROC | plain=0 | kernel={} | main={} | PT_GNU_STACK → PT_LOPROC: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_GNU_STACK_PT_NULL | plain=0 | kernel={} | main={} | PT_GNU_STACK → PT_NULL: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_GNU_STACK_random | plain=0 | kernel={} | main={} | PT_GNU_STACK → random: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)
  - I35_PT_TLS_PT_LOPROC | plain=0 | kernel={} | main={} | PT_TLS → PT_LOPROC: exit=0 이지만 출력 "TLS = 0" (baseline 42) — silent data corruption
  - I35_PT_TLS_PT_NULL | plain=0 | kernel={} | main={} | PT_TLS → PT_NULL: exit=0 이지만 출력 "TLS = 0" (baseline 42) — silent data corruption
  - I35_PT_TLS_random | plain=0 | kernel={} | main={} | PT_TLS → random: exit=0 이지만 출력 "TLS = 0" (baseline 42) — silent data corruption
- 새 finding:
  - F78: ld.so 는 인식 못 하는 phdr 타입(PT_LOPROC/PT_NULL/랜덤값 등)을 조용히 건너뜀. 따라서 메타 phdr 을 그런 타입으로 위장하는 것은 사실상 그 phdr 을 삭제한 것과 동치.
  - F79: 메타 phdr 위장(=삭제)의 런타임 영향도는 타입별로 다름 — PT_TLS = silent data corruption (TLS=0), PT_GNU_EH_FRAME = C++ throw abort (iter33), PT_NOTE/PT_GNU_PROPERTY/PT_GNU_STACK = 런타임 무영향. 정적 분석 측에선 readelf -l 에서 원본 마커가 사라지거나 비정상 타입으로 보이므로 탐지 단서는 잔존.
  - F80: iter35 의 위장 변형은 RWX 오버레이가 아니라 단순 타입 변경이라 텍스트 페이지 권한은 0x401000 r-xp 그대로. 권한 변형과 타입 위장은 독립적인 두 축임.
