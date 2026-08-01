"""
iter15 — finalize 2: iter13-14 추가 반영 + FINAL_REPORT/옵시디언 동기화.
"""
import harness, shutil
from pathlib import Path

N = 15
TITLE = 'finalize: iter13-14 통합 + 최종 보고서/옵시디언 갱신'

state = harness.load_state()
rep = []
rep.append('# overlap_perm_lab — 통합 연구 노트 (V0-V6 + iter01-15)\n')
rep.append('자가 피드백 루프 15회. 정적/동적 분리 PoC 6종 + 방어 도구 v3.\n')

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

rep.append('## 정적/동적 분리 PoC 6종')
rep.append('1. RWX 오버레이 (iter01/02) — PT_NOTE→PT_LOAD RWX 로 텍스트 RWX')
rep.append('2. SMC (iter03) — 동일 소스 + PHT 패치로 SEGV ↔ "result=42" 분기')
rep.append('3. File-append pre-staged (iter04) — file 끝 부착 + PHT 1줄')
rep.append('4. Existing-slot stealth (iter08) — 기존 PT_LOAD vaddr 만 수정, PT_LOAD 카운트 유지')
rep.append('5. In-file payload (iter10) — file size 동일, .payload 섹션 내 텍스트 사본 + 6B 패치')
rep.append('6. **RELRO 무력화 + RWX 오버레이 결합 (iter14)** — 8B RELRO memsz 변경 + 7개 PHT 필드로 텍스트 RWX + GOT RW 동시 + 정상 실행')
rep.append('')

rep.append('## 방어 도구 detect_overlap.py v3')
rep.append('- 검사: (1) PT_LOAD 페이지 정렬 vaddr 오버랩, (2) RELRO subset 위반, (3) RELRO ALIGN_DOWN noop, (4) RELRO end-host mismatch')
rep.append('- RELRO shrink 변형: v2 가 못 잡던 케이스를 v3 가 ANOMALY 로 분류')
rep.append('- 결합 PoC 도 v3 가 ANOMALY')
rep.append('- 정상 prod 바이너리 표본 FP: 0/200 (0%)')
rep.append('')

rep.append('## 0508 미팅 가설 vs 실측')
rep.append('| 가설 | 결과 |')
rep.append('|---|---|')
rep.append('| 후자 우선 | 확정 (F1) |')
rep.append('| 최소 권한 우선 | 기각 |')
rep.append('| 텍스트 RW 코드 인젝션 | 확정 + 실행까지 (F11/F12) |')
rep.append('| RELRO 부분 누락(1.5 보류) | 8B shrink 로 .got 페이지 전체 RW (F26) |')
rep.append('| 결합 시 멀웨어 시나리오 | 텍스트 RWX + GOT RW 동시 가능 (F33) |')

report_path = harness.ROOT / 'FINAL_REPORT.md'
report_path.write_text('\n'.join(rep))
print(f'  regenerated: {report_path}')

obs_dir = Path('/mnt/c/Users/dmsak/Documents/Obsidian Vault/ELF 연구/0508 액션 A — 세그먼트 오버랩 자가루프')
shutil.copy(harness.ROOT / 'FINAL_REPORT.md', obs_dir / 'FINAL_REPORT 원본.md')
shutil.copy(harness.ROOT / 'ITER_LOG.md', obs_dir / 'ITER_LOG.md')
print(f'  obsidian sync: {obs_dir}')

# 옵시디언 주 보고서에 iter13-14 섹션 추가 (중복 방지)
obs_main = obs_dir / '0508 액션 A — 통합 보고서.md'
existing = obs_main.read_text()
addendum = '''

---

## 자가루프 13~15

### iter13 — B3: RELRO 부분 누락 (페이지 정렬 효과)
target_full 의 PT_GNU_RELRO memsz 조작.

| variant | plain | got@0x403 | data@0x404 | detector v2 |
|---|---|---|---|---|
| V0 baseline | ok | r--p | rw-p | CLEAN |
| V1 RELRO shrink 8B | ok | **rw-p** | rw-p | CLEAN (놓침) |
| V2 RELRO extend 1page | SEGV | r--p | **r--p** | ANOMALY |
| V3 RELRO shrink half | ok | **rw-p** | rw-p | CLEAN (놓침) |

- F26: 8B RELRO memsz 감소만으로 .got 페이지 전체 RW (glibc 의 ALIGN_DOWN(end) 효과).
- F29: detector v2 의 blind spot — subset 체크만으론 못 잡음.
- F30: 0508 미팅 1.5 보류 아이디어가 페이지 단위 경계 효과로 더 강력함 확인.

### iter14 — detector v3 + 결합 PoC (B26)
detector v3 휴리스틱 추가: RELRO ALIGN_DOWN noop 검출 + host PT_LOAD end mismatch.

- v3 가 RELRO shrink V1/V3 모두 ANOMALY 분류 ✓
- V0 baseline 은 여전히 CLEAN ✓
- /usr/bin 200 표본 FP = 0 (0%)

결합 PoC (8B + 7필드 패치):
- text@0x401000 = **rwxp** (RWX 오버레이로 텍스트 쓰기/실행 가능)
- got@0x403000 = **rw-p** (RELRO 무력화로 GOT 오염 가능)
- 정상 exit=0, 프로세스 정상 실행
- detector v3 ANOMALY

F33: 8 바이트 + 7 필드 만으로 멀웨어가 원하는 두 조건(코드 변조 + GOT 하이재킹)이 동시에 성립. 정적 분석은 정상 RELRO + 정상 PT_LOAD 로 봄.

### iter15 — finalize 2
FINAL_REPORT 재생성 + 옵시디언 동기화.
'''

if '## 자가루프 13~15' not in existing:
    obs_main.write_text(existing + addendum)
    print(f'  obsidian addendum: {obs_main}')

obs = [{
    'name': 'finalize2',
    'plain_exit': None,
    'kernel_perm': {'iter_total': 15, 'findings_total': len(state['findings'])},
    'main_perm':   {'backlog_total': len(state['backlog']), 'pocs': 6},
    'note': 'detector v3 + 결합 PoC 까지 누적'
}]

harness.commit_iteration(N, TITLE, '15 iter 누적 종합 동기화', obs,
                         f'{len(state["findings"])} findings | {len(state["backlog"])} backlog | 6 PoCs',
                         new_findings=[], new_backlog=[])

print('iter15 complete')
