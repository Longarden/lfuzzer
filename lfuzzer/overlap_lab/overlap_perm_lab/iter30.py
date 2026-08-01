"""
iter30 — finalize: iter29 결과 통합 + 옵시디언 동기화.
"""
import harness, shutil
from pathlib import Path

N = 30
TITLE = 'finalize: iter29 (대규모 FP + C++ throw) 통합'

state = harness.load_state()

# FINAL_REPORT
fr = harness.ROOT / 'FINAL_REPORT.md'
fr_text = fr.read_text()
new = '''

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
'''
if 'Robustness validation (iter29)' not in fr_text:
    fr.write_text(fr_text + new)

# 옵시디언 동기화
obs_dir = Path('/mnt/c/Users/dmsak/Documents/Obsidian Vault/ELF 연구/0508 액션 A — 세그먼트 오버랩 자가루프')
shutil.copy(fr, obs_dir / 'FINAL_REPORT 원본.md')
shutil.copy(harness.ROOT / 'ITER_LOG.md', obs_dir / 'ITER_LOG.md')

# 1페이지 요약 추가
op = obs_dir / '0508 액션 A — 1페이지 요약.md'
op_add = '''

---

## Robustness validation (iter29)

**detector v4 대규모 FP**: 1500 ELF 표본에서 권한/RELRO 시그널 4종 **0건**, sm 시그널 9건(모두 .o 객체 파일). 실행 binary 에선 사실상 0%.

**PT_GNU_EH_FRAME 변환의 한계** (C++ throw 동작): 정상 흐름은 OK 지만 예외 throw 시 `terminate called after throwing 'std::runtime_error'` → SIGABRT. EH 슬롯 부재로 unwinding 실패.
'''
op_text = op.read_text()
if 'Robustness validation (iter29)' not in op_text:
    op.write_text(op_text + op_add)

# 통합 보고서 addendum
obs_main = obs_dir / '0508 액션 A — 통합 보고서.md'
ex = obs_main.read_text()
add = '''

---

## 자가루프 29~30: robustness

### iter29 — B40 detector v4 대규모 FP + B38 C++ throw
**B40**: /usr/bin + /usr/sbin + /usr/lib + /usr/libexec 1500 ELF 표본.
- overlap/rs/rn/rem FP = 0 (모든 권한/RELRO 시그널 prod 에서 0건)
- sm FP = 9 (0.60%), 모두 .o link-time 객체 파일 (crt1.o, Scrt1.o, crti.o, crtn.o, Mcrt1.o ...)
- 실행 binary 기준 FP = 0%
- F72, F73

**B38**: target_throw.cpp (C++ try/catch).
- baseline: "caught: test exception" 정상 exit=0
- PT_GNU_EH_FRAME → PT_LOAD 변형: "terminate called after throwing 'std::runtime_error'" SIGABRT (-6), 3회 일관
- iter21 의 "main 도달" 결과는 정상 흐름 한정 — throw 시 unwinding 실패로 abort
- F74

### iter30 — finalize
FINAL_REPORT / 1페이지 요약 / ITER_LOG 동기화. 30 iter 종결.
'''
if '## 자가루프 29~30' not in ex:
    obs_main.write_text(ex + add)

obs = [{
    'name': 'finalize_30iter',
    'plain_exit': None,
    'kernel_perm': {'iters_total': 30, 'large_scale_fp_v4': '0/1500 (실행 binary)'},
    'main_perm':   {'cpp_throw_variant_abort': True},
    'note': '30 iter 자가루프'
}]
harness.commit_iteration(N, TITLE, 'robustness validation 통합', obs,
                         f'detector v4 1500 표본 FP 0% (실행 binary), C++ throw 변형 SIGABRT 확정',
                         new_findings=[], new_backlog=[])

print('iter30 complete — 30 iter 자가루프')
