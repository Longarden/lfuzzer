"""
iter26 — finalize: iter21~25 통합 + FINAL_REPORT 갱신 + 옵시디언 동기화.
"""
import harness, shutil
from pathlib import Path

N = 26
TITLE = 'finalize: B7 확장 (iter21~25) 통합 보고서 갱신'

state = harness.load_state()

# FINAL_REPORT.md 에 새 섹션 추가
fr = harness.ROOT / 'FINAL_REPORT.md'
fr_text = fr.read_text()

new_section = '''

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
'''

if 'Beyond PT_NOTE' not in fr_text:
    fr.write_text(fr_text + new_section)
    print(f'  FINAL_REPORT.md updated with Beyond PT_NOTE section')

# 옵시디언 동기화
obs_dir = Path('/mnt/c/Users/dmsak/Documents/Obsidian Vault/ELF 연구/0508 액션 A — 세그먼트 오버랩 자가루프')
shutil.copy(fr, obs_dir / 'FINAL_REPORT 원본.md')
shutil.copy(harness.ROOT / 'ITER_LOG.md', obs_dir / 'ITER_LOG.md')
shutil.copy(harness.ROOT / 'CITATIONS.md', obs_dir / 'glibc 코드 인용.md')
shutil.copy(harness.OUT_ROOT / 'iter25' / 'MATRIX.md', obs_dir / 'PHDR 변환 매트릭스 (iter25).md')

# 옵시디언 통합 보고서에 새 섹션 추가
obs_main = obs_dir / '0508 액션 A — 통합 보고서.md'
existing = obs_main.read_text()
add = '''

---

## 자가루프 21~26: Beyond PT_NOTE

PT_NOTE 외 다른 phdr 슬롯도 같은 PT_LOAD 변환이 가능한지 검증.

별도 매트릭스 문서: [[PHDR 변환 매트릭스 (iter25)]]

### iter21 — PT_GNU_EH_FRAME → PT_LOAD
PT_NOTE 변환과 functional 등가. 3회 일관. F44~F49.

### iter22 — PT_GNU_PROPERTY → PT_LOAD
동일 등가. 단 readelf -n 의 NT_GNU_PROPERTY 마커는 섹션 헤더로 잔존. F50~F53.

### iter23 — PT_TLS → PT_LOAD (가장 흥미로운 결과)
- baseline: `TLS = 42`
- 변형 RWX: exit=0, main 도달, 그러나 출력 **`TLS = 0`** (silent corruption)
- ld.so 가 PT_TLS 슬롯 부재 시 zero-init TLS 그대로 사용
- SEGV 없이 데이터 무결성 깨짐. 보안 의미 큼.
- F54~F58, F64.

### iter24 — PT_GNU_STACK → PT_LOAD
동일 등가. 스택 권한은 baseline rw-p → 변형 rw-p 동일. F59~F63.

### iter25 — 5종 통합 매트릭스
PT_NOTE / PT_GNU_EH_FRAME / PT_GNU_PROPERTY / PT_TLS / PT_GNU_STACK 비교. F64~F67.

### iter26 — finalize
보고서/옵시디언/CITATIONS 동기화. 26 iter 종결.

---

## 26 iter 자가루프 최종

- 정적/동적 분리 PoC 6종 + 클린 DEMO 2종 + B7 확장 5종 변환 + live PoC + 방어 도구 v3 + glibc 코드 인용
- 새 발견 강조: **PT_TLS silent corruption (F64)** — 본 lab 자체 발견, 선행 연구 없음
- 다음 작업 (backlog): B37 (PT_TLS PoC 실용화), B38 (EH_FRAME 변환의 예외 throw), B39 (detector v4: 원본 마커 부재 시그널)
'''
if '## 자가루프 21~26' not in existing:
    obs_main.write_text(existing + add)
    print(f'  obsidian addendum: {obs_main}')

# 1페이지 요약 갱신
one_pager = obs_dir / '0508 액션 A — 1페이지 요약.md'
op_text = one_pager.read_text()
op_add = '''

---

## Beyond PT_NOTE 추가 결과 (iter21~25)

PT_NOTE 외 4 개 phdr 타입 변환 검증.

| 타입 | 결과 | 비고 |
|---|---|---|
| PT_GNU_EH_FRAME | RWX 텍스트 + main 도달 | 가장 스텔스 (항상 존재) |
| PT_GNU_PROPERTY | 동일 | readelf -n 마커 잔존 |
| **PT_TLS** | **TLS=42→0 silent corruption** | **본 lab 자체 발견** |
| PT_GNU_STACK | 동일, 스택 권한 무영향 | execstack -q 만 흔적 |

별도 매트릭스: [[PHDR 변환 매트릭스 (iter25)]]
'''
if 'Beyond PT_NOTE 추가 결과' not in op_text:
    one_pager.write_text(op_text + op_add)
    print(f'  1페이지 요약 updated')

obs = [{
    'name': 'finalize_b7_extension',
    'plain_exit': None,
    'kernel_perm': {'phdr_types_tested': 5, 'silent_corruption_unique': 'PT_TLS'},
    'main_perm':   {'iters_total': 26, 'new_findings_in_b7': 24},
    'note': 'B7 확장 + Obsidian 동기화 + CITATIONS 선행연구 박음'
}]

harness.commit_iteration(N, TITLE, 'B7 확장 결과 통합', obs,
                         f'5 phdr 타입 검증, PT_TLS unique silent corruption, detector 5/5',
                         new_findings=[], new_backlog=[])

print(f'\niter26 complete — 26 iter 자가루프 종결')
print(f'  Obsidian docs (6): 1페이지 요약, 통합 보고서, FINAL_REPORT 원본, ITER_LOG, glibc 코드 인용, PHDR 변환 매트릭스')
