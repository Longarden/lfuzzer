"""
iter12 — finalize: iter11 보정 + FINAL_REPORT 재생성 + Obsidian 동기화.

iter11 의 file/objdump DIFFERENT 는 출력에 파일명이 들어가서 생긴 cosmetic artifact 였음.
파일명 정규화 후 다시 비교하면 실제 표면 차이는 sha256 과 readelf -l 둘 뿐.
"""
import harness, subprocess, shutil
from pathlib import Path

N = 12
TITLE = 'finalize: iter11 보정 + FINAL_REPORT 갱신 + 옵시디언 동기화'

state = harness.load_state()
state['findings'].append('F23g: iter11 의 file/objdump_text DIFFERENT 는 출력 안 파일명 차이일 뿐 (정규화 후 동일). 실제 표면 차이는 sha256 과 readelf -l 두 가지뿐.')
state['findings'].append('F24: 11 iter 누적 결과 — 가장 스텔스한 변형(iter10 I10V2)에서 file size, file 출력, readelf -h/-S, strings, .text 디스어셈블 전부 baseline 과 동일. PHT 레벨 vaddr 오버랩 검사만 잡음.')
harness.save_state(state)

# FINAL_REPORT 재생성 (iter07 의 로직 + 11 iter 반영)
state = harness.load_state()
rep = []
rep.append('# overlap_perm_lab — 통합 연구 노트 (V0-V6 + iter01-12)\n')
rep.append('자가 피드백 루프 12회. 0508 미팅 액션 A 확장. 정적/동적 분리 PoC 5종 + 방어 도구 v2 + 표면 분석 완료.\n')

rep.append('## 핵심 결론')
for f in state['findings']:
    rep.append(f'- {f}')
rep.append('')

rep.append('## 완결된 이터레이션')
for ci in state['completed_iterations']:
    rep.append(f'### iter{ci["iter"]:02d} — {ci["title"]}')
    rep.append(f'- 가설: {ci["hypothesis"]}')
    rep.append(f'- 판정: {ci["verdict"]}')
    rep.append(f'- ts: {ci.get("ts","")}')
    rep.append('')

rep.append('## 남은 백로그')
for b in state['backlog']:
    rep.append(f'- [{b["id"]}] {b["title"]}')
rep.append('')

rep.append('## 핵심 아티팩트')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/harness.py — 자가루프 코어')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/detect_overlap.py — 방어 측 도구 v2')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter01..12.py — 각 단계 spec/분석')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/STATE.json — 누적 finding/backlog')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/ITER_LOG.md — 시간순 narrative')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter_outputs/iter01..12/ — 변형 ELF + 로그')
rep.append('')

rep.append('## 정적/동적 분리 PoC 5종')
rep.append('1. RWX 오버레이 (iter01/02): PT_NOTE→PT_LOAD RWX 로 텍스트 페이지가 RWX. RELRO 모드 무관.')
rep.append('2. SMC PoC (iter03): 동일 소스, PHT 패치만으로 baseline=SEGV vs 변형 "result=42".')
rep.append('3. Pre-staged + file append (iter04): runtime memcpy 없이 file 끝 부착으로 1→42. strace 깨끗.')
rep.append('4. Existing-slot stealth (iter08): 기존 PT_LOAD vaddr 만 수정해서 PT_LOAD 카운트 유지. SEGV 분기.')
rep.append('5. In-file payload (iter10): file size 동일, sha256 만 다름. .payload 섹션 안 텍스트 사본+패치로 분기.')
rep.append('')

rep.append('## 방어 도구 detect_overlap.py')
rep.append('- v2 시그널: PT_LOAD 페이지 정렬 vaddr 오버랩 + PT_GNU_RELRO subset 위반')
rep.append('- key 변형 recall (lab 내): 7/7')
rep.append('- false positive (정상 prod 바이너리 300 표본): 0/300 = **0%**')
rep.append('- 50줄 단일 파일, 외부 의존성 없음')
rep.append('')

rep.append('## 0508 미팅 가설 vs 실측')
rep.append('| 가설 | 결과 |')
rep.append('|---|---|')
rep.append('| 후자 우선 | 확정 (F1) |')
rep.append('| 최소 권한 우선 | 기각 |')
rep.append('| 순서 무관/다른 규칙 | 기각 |')
rep.append('| 텍스트 RW 코드 인젝션 | 확정 + 실행까지 (F11/F12) |')

report_path = harness.ROOT / 'FINAL_REPORT.md'
report_path.write_text('\n'.join(rep))
print(f'  regenerated: {report_path}')

# Obsidian 동기화
obs_dir = Path('/mnt/c/Users/dmsak/Documents/Obsidian Vault/ELF 연구/0508 액션 A — 세그먼트 오버랩 자가루프')
shutil.copy(harness.ROOT / 'FINAL_REPORT.md', obs_dir / 'FINAL_REPORT 원본.md')
shutil.copy(harness.ROOT / 'ITER_LOG.md', obs_dir / 'ITER_LOG.md')
print(f'  obsidian sync: {obs_dir}')

# 통합 보고서 (Obsidian 친화판) 갱신 — iter08~12 섹션 추가
obs_main = obs_dir / '0508 액션 A — 통합 보고서.md'
existing = obs_main.read_text()
addendum = '''

---

## 자가루프 후반 (iter08 ~ iter12)

### iter08 — B14: PT_LOAD 카운트 유지 스텔스
PT_NOTE→PT_LOAD 대신 기존 PT_LOAD 의 vaddr 만 조작. PT_LOAD 카운트 4 유지.

| variant | plain | k@0x401 | m@0x401 | detector |
|---|---|---|---|---|
| I8V1_rodata_vaddr_to_text | SEGV | r--p | r--p | ANOMALY |
| I8V2_data_vaddr_to_text | SEGV | rw-p | rw-p | ANOMALY |
| I8V3_rodata_full_overlay_text | SEGV | r--p | r--p | ANOMALY |

- F16: 카운트 유지 가능 (4건 모두 4)
- F17: detector v2 가 모두 잡음 (페이지 정렬 vaddr 오버랩)

### iter09 — B15: false positive 측정
/usr/bin + /usr/lib/x86_64-linux-gnu 표본 300개에 detector v2 실행.

- F20: anomaly 0건 / 300. **FP rate = 0%**. 1차 방어선으로 적합.

### iter10 — B12: file size 변화 없는 in-file payload
target_in.c 에 `.payload` 섹션을 미리 박아 빌드. patch script 가 .payload 안에 텍스트 사본 + target_func 자리 6바이트 페이로드 채움. PT_NOTE[8] → PT_LOAD R-X 오버레이.

- baseline: exit=99, "result = 1", size 25664
- 변형: exit=0, "result = 42", size 25664 (동일)
- F21: file size 동일 + result 분기. iter04 의 file append 단서 제거.
- F22: detector v2 는 여전히 잡음 (vaddr 오버랩 시그널이 size 무관).

### iter11 — B23: 표면 차이 측정
baseline (target_in) vs 가장 스텔스한 변형 (iter10 I10V2) 비교.

| 도구 | 같음/다름 |
|---|---|
| size | same |
| sha256 | DIFFERENT |
| file | same (파일명 정규화 후) |
| readelf -h | same |
| readelf -S | same |
| readelf -l | **DIFFERENT** (PT_NOTE → PT_LOAD) |
| strings | same |
| objdump -d -j .text | same |

- F23: 실질 차이는 sha256 과 readelf -l 두 가지뿐. malware 분석가가 PHT 오버랩 검사 안 하면 못 잡는다.

### iter12 — finalize
iter11 보정 + FINAL_REPORT 재생성 + 옵시디언 동기화.

---

## 결론 (12 iter 누적)
1. 정적/동적 분리 PoC 5종 확보: RWX overlay, SMC, file-append pre-staged, existing-slot stealth, in-file payload.
2. 방어 측 detect_overlap.py: 50줄, lab key 변형 7/7, FP 0/300.
3. 0508 가설(후자 우선) 코드 레벨 검증 완료.
4. 다음 미팅 발표 흐름: 가설→검증→PoC 5종 데모→탐지 매트릭스→방어 도구.
'''

# 이미 addendum 이 있는지 확인 (재실행 시 중복 방지)
if '## 자가루프 후반' not in existing:
    obs_main.write_text(existing + addendum)
    print(f'  obsidian addendum: {obs_main}')

obs = [{
    'name': 'finalize',
    'plain_exit': None,
    'kernel_perm': {'iter_total': 12, 'findings_total': len(state['findings'])},
    'main_perm':   {'backlog_total': len(state['backlog'])},
    'note': 'FINAL_REPORT regenerated + Obsidian synced'
}]

harness.commit_iteration(N, TITLE, '루프 정리 및 보고서 동기화', obs,
                         f'{len(state["findings"])} findings | {len(state["backlog"])} backlog',
                         new_findings=[], new_backlog=[])

print('iter12 complete')
print(f'  findings total: {len(state["findings"])}')
print(f'  backlog total: {len(state["backlog"])}')
print(f'  completed iterations: {len(state["completed_iterations"])+1}')
