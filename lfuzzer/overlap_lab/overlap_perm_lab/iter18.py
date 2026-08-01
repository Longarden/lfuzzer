"""
iter18 — finalize 3: iter16-17 통합 + FINAL_REPORT/옵시디언 갱신.
"""
import harness, shutil
from pathlib import Path

N = 18
TITLE = 'finalize 3: iter16-17 통합 + 최종 보고서 갱신'

state = harness.load_state()
rep = []
rep.append('# overlap_perm_lab — 통합 연구 노트 (V0-V6 + iter01-18)\n')
rep.append('자가 피드백 루프 18회. 정적/동적 분리 PoC 6종 + 방어 도구 v3 + glibc 코드 인용 + live combo PoC.\n')

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

rep.append('## 최종 PoC 표 (실측 출력)')
rep.append('| 변형 | plain exit | stdout | text 페이지 | GOT 페이지 | detector v3 |')
rep.append('|---|---|---|---|---|---|')
rep.append('| baseline target_probe (full RELRO) | -11 (SEGV) | "[probe] start" 까지 | r-xp | r--p | CLEAN |')
rep.append('| combo (RELRO shrink 0x140B + RWX overlay) | 0 | "[probe] BOTH writes succeeded" | **rwxp** | **rw-p** | ANOMALY |')
rep.append('')

rep.append('## glibc 코드 인용 (CITATIONS.md 별도 파일)')
rep.append('- elf/dl-map-segments.h _dl_map_segment — MAP_FIXED 로 후자 우선 발생')
rep.append('- elf/dl-load.c:1213-1214 — PT_GNU_RELRO 처리 시 vaddr/memsz 검증 없음')
rep.append('- elf/dl-reloc.c:354-368 _dl_protect_relro — ALIGN_DOWN(end) 로 페이지 경계 효과 (F26)')
rep.append('')

rep.append('## 다음 미팅 발표 흐름')
rep.append('1. 0508 가설 → 검증 결과 (V0-V6, F1)')
rep.append('2. 자가 피드백 루프 18 회의 의미: 정적/동적 분리 PoC 6종 + 방어 도구 + glibc 코드 인용')
rep.append('3. live PoC 데모: iter17 출력 차이 (SEGV vs "BOTH writes succeeded")')
rep.append('4. 방어 측 detect_overlap.py v3: 50줄, FP 0%, 모든 변형 ANOMALY')
rep.append('5. glibc 보강 제안 3가지 (RELRO subset 검증 / ALIGN_DOWN noop / PT_LOAD 오버랩 사전 거절)')
rep.append('')

rep.append('## 핵심 아티팩트')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/harness.py — 자가루프 코어')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/detect_overlap.py — 방어 측 도구 v3')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter01..18.py — 각 이터레이션')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/CITATIONS.md — glibc 코드 인용')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/STATE.json — 누적 finding/backlog')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/ITER_LOG.md — 시간순 narrative')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/target_probe.c — live PoC 소스')
rep.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter_outputs/iter01..18/ — 변형 ELF + 로그')

report_path = harness.ROOT / 'FINAL_REPORT.md'
report_path.write_text('\n'.join(rep))

obs_dir = Path('/mnt/c/Users/dmsak/Documents/Obsidian Vault/ELF 연구/0508 액션 A — 세그먼트 오버랩 자가루프')
shutil.copy(harness.ROOT / 'FINAL_REPORT.md', obs_dir / 'FINAL_REPORT 원본.md')
shutil.copy(harness.ROOT / 'ITER_LOG.md', obs_dir / 'ITER_LOG.md')
shutil.copy(harness.ROOT / 'CITATIONS.md', obs_dir / 'glibc 코드 인용.md')

# 옵시디언 주 보고서에 iter16-18 추가
obs_main = obs_dir / '0508 액션 A — 통합 보고서.md'
existing = obs_main.read_text()
add = '''

---

## 자가루프 16~18

### iter16 — B4: glibc 코드 라인 인용
- elf/dl-map-segments.h `_dl_map_segment`: MAP_COPY|MAP_FILE [+ MAP_FIXED] → F1(후자 우선) 원인.
- elf/dl-load.c:1213-1214 PT_GNU_RELRO 처리: vaddr/memsz 무검증 저장 → F4 원인.
- elf/dl-reloc.c:354-368 `_dl_protect_relro`: ALIGN_DOWN(start), ALIGN_DOWN(end) → F26 원인.
- 별도 파일 [[glibc 코드 인용]].

### iter17 — B28: live GOT + 텍스트 write PoC
target_probe (-no-pie -z relro -z now) + combo 패치(RELRO msz 0x100 + PT_NOTE→PT_LOAD RWX).

| 변형 | plain | text@0x401 | got@0x403 | stdout |
|---|---|---|---|---|
| baseline | SEGV | r-xp | r--p | "[probe] start" 에서 멈춤 |
| combo | exit 0 | **rwxp** | **rw-p** | "[probe] BOTH writes succeeded" |

- F38: live PoC 가 baseline 대비 GOT/텍스트 쓰기 둘 다 성공. 멀웨어 시나리오 실측 완성.
- F39: detector v3 가 baseline CLEAN / combo ANOMALY 로 정확 분류.

### iter18 — finalize 3
FINAL_REPORT/옵시디언 동기화. 18 iter 누적 종합.

---

## 18 iter 자가루프 최종 정리

- 정적/동적 분리 PoC 6종 + live PoC 실측 출력 완성
- 방어 도구 detect_overlap.py v3 (50줄, FP 0/200)
- glibc 코드 원인 3개 함수 인용
- 보강 제안 3가지 (subset 검증 / ALIGN_DOWN noop / PT_LOAD 오버랩 사전 거절)
'''
if '## 자가루프 16~18' not in existing:
    obs_main.write_text(existing + add)

obs = [{
    'name': 'finalize3',
    'plain_exit': None,
    'kernel_perm': {'iter_total': 18, 'findings_total': len(state['findings'])},
    'main_perm':   {'backlog_total': len(state['backlog']), 'pocs': 6, 'live_poc': 1},
    'note': 'live PoC + glibc 인용 + 옵시디언 동기화 완료'
}]
harness.commit_iteration(N, TITLE, '18 iter 종합 마무리', obs,
                         f'{len(state["findings"])} findings | {len(state["backlog"])} backlog | live PoC확정',
                         new_findings=[], new_backlog=[])

print('iter18 complete')
print(f'  findings: {len(state["findings"])}')
print(f'  backlog: {len(state["backlog"])}')
print(f'  iters: 18')
