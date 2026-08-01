"""
iter29 — B40 (detector v4 대규모 FP) + B38 (PT_GNU_EH_FRAME 변환 후 C++ throw 동작).

Part 1 (B40): /usr/bin + /usr/lib/x86_64-linux-gnu + /usr/libexec 통합 표본으로
시그널별 (overlap / rs / rn / rem / sm) FP 분포 측정.
가설: sm 시그널이 golang / 정적 링크 binary 에서 FP 가능성 가장 큼.

Part 2 (B38): target_throw (C++ throw/catch) 의 PT_GNU_EH_FRAME → PT_LOAD 변형.
- baseline: throw → catch → "caught: test exception" 출력
- 변형: EH 정보 슬롯 잃음 → throw 시 unwinding 실패 → abort or terminate
- iter21 결과 (main 도달) 와 별개로 예외 throw 시 동작 차이 측정
"""
import harness, subprocess, shutil, json
from pathlib import Path
from elftools.elf.elffile import ELFFile

N = 29
TITLE = 'B40 detector v4 대규모 FP + B38 PT_GNU_EH_FRAME 변환 후 C++ throw 동작'

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

# ==================== Part 1: B40 대규모 FP ====================
print('=== Part 1: detector v4 대규모 FP 측정 ===')

dirs = ['/usr/bin', '/usr/sbin', '/usr/lib/x86_64-linux-gnu', '/usr/libexec']
samples = []
for d in dirs:
    p = Path(d)
    if not p.exists(): continue
    for f in p.rglob('*'):
        if f.is_file() and not f.is_symlink():
            try:
                if f.read_bytes()[:4] == b'\x7fELF':
                    samples.append(f)
            except (PermissionError, OSError):
                pass
        if len(samples) >= 1500: break
    if len(samples) >= 1500: break

print(f'  표본 수: {len(samples)}')

# 각 시그널별 카운트
sig_counts = {'overlap':0, 'relro_subset_fail':0, 'relro_noop':0, 'relro_end_mismatch':0, 'gnu_stack_missing':0}
anomaly_list = []
errors = 0
for f in samples:
    try:
        r = detect_overlap.analyze(str(f))
        if r['overlap_count'] > 0: sig_counts['overlap'] += 1
        if r['relro_subset_fail'] > 0: sig_counts['relro_subset_fail'] += 1
        if r['relro_noop'] > 0: sig_counts['relro_noop'] += 1
        if r['relro_end_mismatch'] > 0: sig_counts['relro_end_mismatch'] += 1
        if r['gnu_stack_missing']: sig_counts['gnu_stack_missing'] += 1
        if r['verdict'] != 'CLEAN':
            anomaly_list.append({'path': str(f), 'signals': {k: v for k, v in r.items() if k != 'path'}})
    except Exception:
        errors += 1

total_anomaly = len(anomaly_list)
print(f'  errors: {errors}')
print(f'  signal-by-signal counts:')
for sig, c in sig_counts.items():
    rate = c / max(1, len(samples)) * 100
    print(f'    {sig:25s}: {c:5d} ({rate:.2f}%)')
print(f'  total anomaly (any signal): {total_anomaly} ({total_anomaly/max(1,len(samples))*100:.2f}%)')

(iter_dir / 'fp_v4_report.json').write_text(json.dumps({
    'sample_size': len(samples), 'errors': errors,
    'signal_counts': sig_counts, 'total_anomaly': total_anomaly,
    'anomaly_paths': [a['path'] for a in anomaly_list[:50]]   # 상위 50개만
}, indent=2, ensure_ascii=False))

# sm 시그널 only 발생 케이스 분석
sm_only = [a for a in anomaly_list if a['signals']['gnu_stack_missing']
                                       and not any([a['signals']['overlap_count'],
                                                    a['signals']['relro_subset_fail'],
                                                    a['signals']['relro_noop'],
                                                    a['signals']['relro_end_mismatch']])]
print(f'  sm-only anomaly (정상 binary 가 PT_GNU_STACK 만 없는 케이스): {len(sm_only)}')
if sm_only:
    print(f'    예시 (상위 5개):')
    for a in sm_only[:5]:
        print(f'      {a["path"]}')

# ==================== Part 2: B38 C++ throw ====================
print('\n=== Part 2: PT_GNU_EH_FRAME 변환 후 C++ throw 동작 ===')

# target_throw PHT inspect
with open(harness.ROOT / 'target_throw', 'rb') as f:
    e = ELFFile(f)
    eh_idx = None; text_size = None
    for i, s in enumerate(e.iter_segments()):
        if s['p_type'] == 'PT_GNU_EH_FRAME': eh_idx = i
        if s['p_type'] == 'PT_LOAD' and s['p_flags'] == 5: text_size = s['p_filesz']
print(f'  target_throw: EH_FRAME idx={eh_idx}, text size={text_size:#x}')

# baseline
base_path = iter_dir / 'I29V0_throw_baseline'
shutil.copy(harness.ROOT / 'target_throw', base_path); base_path.chmod(0o755)
harness.run_plain(base_path, iter_dir / 'I29V0_throw_baseline.plain.log')

# 변형: PT_GNU_EH_FRAME → PT_LOAD RWX over text
var_path = iter_dir / 'I29V1_throw_ehframe_overlay'
data = (harness.ROOT / 'target_throw').read_bytes()
patches = [
    {'phdr_idx': eh_idx, 'field': 'type',   'value': 1},
    {'phdr_idx': eh_idx, 'field': 'flags',  'value': 0x7},
    {'phdr_idx': eh_idx, 'field': 'offset', 'value': 0x1000},
    {'phdr_idx': eh_idx, 'field': 'vaddr',  'value': 0x401000},
    {'phdr_idx': eh_idx, 'field': 'paddr',  'value': 0x401000},
    {'phdr_idx': eh_idx, 'field': 'filesz', 'value': text_size},
    {'phdr_idx': eh_idx, 'field': 'memsz',  'value': text_size},
    {'phdr_idx': eh_idx, 'field': 'align',  'value': 0x1000},
]
patched = harness.apply_patches(data, patches)
var_path.write_bytes(patched); var_path.chmod(0o755)
harness.run_plain(var_path, iter_dir / 'I29V1_throw_ehframe_overlay.plain.log')

def run3(path, prefix):
    outs = []
    for trial in range(3):
        p = iter_dir / f'{prefix}.plain.run{trial+1}.log'
        harness.run_plain(path, p)
        outs.append((harness.exit_code(p), p.read_text()))
    return outs

base_runs = run3(base_path, 'I29V0_throw_baseline')
var_runs = run3(var_path, 'I29V1_throw_ehframe_overlay')

def extract_throw_lines(stdout):
    return [L.strip() for L in stdout.splitlines() if '[throw]' in L or 'terminate' in L.lower() or 'aborted' in L.lower()]

base_out = base_runs[0][1]
var_out = var_runs[0][1]
print(f'  baseline output:')
for L in extract_throw_lines(base_out): print(f'    {L}')
print(f'  variant output:')
for L in extract_throw_lines(var_out): print(f'    {L}')
print(f'  baseline exit: {[e for e,_ in base_runs]}')
print(f'  variant exit: {[e for e,_ in var_runs]}')

# stderr (terminate 메시지가 거기에 나옴)
print(f'  baseline stderr last:')
for L in base_out.splitlines()[-5:]: print(f'    {L}')
print(f'  variant stderr last:')
for L in var_out.splitlines()[-5:]: print(f'    {L}')

# Findings
findings = []
backlog = []

# Part 1
findings.append(f'F72: detector v4 prod 표본 {len(samples)} 개 (정확히는 {len(samples) - errors} 분석 성공) 시그널 분포:')
for sig, c in sig_counts.items():
    findings.append(f'  - {sig}: {c} ({c/max(1,len(samples))*100:.2f}%)')
findings.append(f'F73: sm-only FP (정상 binary 가 PT_GNU_STACK 만 없는 케이스): {len(sm_only)}/{len(samples)} ({len(sm_only)/max(1,len(samples))*100:.2f}%). '
                f'{"낮음 — sm 휴리스틱이 robust" if len(sm_only) < 5 else "주의 — sm 단독으로는 FP 가능. overlap 와 결합 필요."}')

# Part 2
base_caught = any('caught:' in L for L in extract_throw_lines(base_out))
var_caught = any('caught:' in L for L in extract_throw_lines(var_out))
base_aborted = any('terminate' in L.lower() or 'aborted' in L.lower() for L in var_out.splitlines())
var_aborted = any('terminate' in L.lower() or 'aborted' in L.lower() for L in var_out.splitlines())

if base_caught and not var_caught and (var_aborted or var_runs[0][0] not in (0, None)):
    findings.append(f'F74: PT_GNU_EH_FRAME → PT_LOAD 변환 후 C++ throw 시 unwinding 실패. '
                    f'baseline 은 정상 catch ("caught: test exception"), 변형은 exit={var_runs[0][0]} '
                    f'(abort/terminate). iter21 의 "main 도달" 결과는 예외 throw 가 없는 정상 흐름에 한정 — '
                    f'예외 throw 시 EH 정보 슬롯 부재로 std::terminate 호출.')
elif base_caught and var_caught:
    findings.append(f'F74: 변형도 정상 catch — PT_GNU_EH_FRAME 슬롯이 PT_LOAD 가 되어도 .eh_frame_hdr 섹션이 '
                    f'PT_LOAD[4] 안에 그대로 남아서 unwinding 가능. PT_NOTE 변환의 readelf -n 잔존과 유사 패턴.')
else:
    findings.append(f'F74: 결과 분석 필요 — baseline caught={base_caught} variant caught={var_caught} variant exit={var_runs[0][0]}')

backlog.append({'id':'B42','title':'F73 의 sm-only FP 케이스 정밀 분류 — golang? rust? 정적 링크 라이브러리?'})
backlog.append({'id':'B43','title':'F74 의 결과에 따라 detector v5 휴리스틱 — '
                'PT_GNU_EH_FRAME 부재 + .eh_frame 섹션 존재 = 의심 시그널 추가'})

obs = [{
    'name': 'iter29',
    'plain_exit': None,
    'kernel_perm': {'fp_sample_size': len(samples), 'sm_only_fp': len(sm_only)},
    'main_perm':   {'baseline_caught': base_caught, 'variant_caught': var_caught, 'variant_exit': var_runs[0][0]},
    'note': f'B40 + B38',
}]

verdict = (f'v4 prod {len(samples)} samples: total_anomaly={total_anomaly} sm_only_fp={len(sm_only)} | '
           f'throw baseline caught={base_caught} variant caught={var_caught} exit={var_runs[0][0]}')

harness.commit_iteration(N, TITLE, '대규모 FP + C++ throw 동작 측정', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print(f'\niter29 complete')
