"""
iter28 — finalize: iter27 결과 반영 + 모든 옵시디언 문서 갱신.
"""
import harness, shutil
from pathlib import Path

N = 28
TITLE = 'finalize: iter27 (auth bypass + detector v4) 통합'

state = harness.load_state()

# FINAL_REPORT.md 에 iter27 섹션 추가
fr = harness.ROOT / 'FINAL_REPORT.md'
fr_text = fr.read_text()
new = '''

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
'''
if 'Practical extension (iter27)' not in fr_text:
    fr.write_text(fr_text + new)

# 옵시디언 동기화
obs_dir = Path('/mnt/c/Users/dmsak/Documents/Obsidian Vault/ELF 연구/0508 액션 A — 세그먼트 오버랩 자가루프')
shutil.copy(fr, obs_dir / 'FINAL_REPORT 원본.md')
shutil.copy(harness.ROOT / 'ITER_LOG.md', obs_dir / 'ITER_LOG.md')
shutil.copy(harness.ROOT / 'CITATIONS.md', obs_dir / 'glibc 코드 인용.md')

# 통합 보고서 addendum
obs_main = obs_dir / '0508 액션 A — 통합 보고서.md'
ex = obs_main.read_text()
add = '''

---

## 자가루프 27~28: 실용 PoC + detector v4

### iter27 — B37 PT_TLS auth bypass + B39 detector v4
**B37 PoC** (target_tls_auth):
- baseline: "ACCESS DENIED (safety_locked=1)" exit=0
- 변형: "ACCESS GRANTED (safety_locked=0) -- DEBUG BYPASS" exit=1
- F68 — iter23 silent corruption (F64) 의 보안 의미 실증

**B39 detector v4**:
- 시그널 추가: PT_GNU_STACK missing (sm)
- iter24 (PT_GNU_STACK → PT_LOAD) 가 overlap + sm 두 시그널로 동시 잡힘
- prod /usr/bin 300 표본 FP=0 (0%)
- F69, F70, F71

### iter28 — finalize
FINAL_REPORT / 통합 보고서 / 1페이지 요약 / CITATIONS 동기화. 28 iter 종결.
'''
if '## 자가루프 27~28' not in ex:
    obs_main.write_text(ex + add)

# 1페이지 요약 추가
op = obs_dir / '0508 액션 A — 1페이지 요약.md'
op_text = op.read_text()
op_add = '''

---

## 실용 PoC (iter27 추가)

| 데모 | baseline | 변형 | 의미 |
|---|---|---|---|
| target_tls_auth | "ACCESS DENIED" | "ACCESS GRANTED -- DEBUG BYPASS" | PT_TLS silent corruption 으로 __thread 인증 우회 |

방어 도구 detect_overlap.py v4:
- 시그널 5종: PT_LOAD 페이지 오버랩 / RELRO subset 위반 / RELRO ALIGN_DOWN noop / RELRO end mismatch / PT_GNU_STACK missing
- prod /usr/bin 300 표본 FP **0/300 (0%)**
- 28 iter 자가루프 모든 의미 있는 변형 잡음
'''
if '실용 PoC (iter27 추가)' not in op_text:
    op.write_text(op_text + op_add)

obs = [{
    'name': 'finalize_28iter',
    'plain_exit': None,
    'kernel_perm': {'iters_total': 28, 'practical_pocs': 1, 'detector_version': 'v4'},
    'main_perm':   {'prod_fp_v4': '0/300', 'silent_corruption_pocs': 1},
    'note': '28 iter 자가루프 최종 종결',
}]

harness.commit_iteration(N, TITLE, '실용 PoC + detector v4 통합 완료', obs,
                         '28 iter, detector v4 FP 0%, auth bypass PoC 확정',
                         new_findings=[], new_backlog=[])

print('iter28 complete — 28 iter 자가루프 종결')
print(f'  옵시디언 문서 위치:')
print(f'    {obs_dir}')
print(f'    파일들:')
import os
for f in sorted(os.listdir(obs_dir)):
    print(f'      - {f}')
