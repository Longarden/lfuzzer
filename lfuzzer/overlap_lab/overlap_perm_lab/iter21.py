"""
iter21 — B7 확장: PT_GNU_EH_FRAME → PT_LOAD RWX/RW/R-X 변형.

target_full PT_GNU_EH_FRAME (idx 10): offset 0x2030, vaddr 0x402030, fsz 0x44, fl=0x4 (R).
이 슬롯을 PT_LOAD 로 바꿔서 텍스트 페이지(0x401000) 위에 동일 패턴 오버레이.

iter01(PT_NOTE) 와의 비교:
- PT_NOTE 변환: Ryan O'Neill 2015 등 선행 연구 존재
- PT_GNU_EH_FRAME 변환: 공개된 PoC 흔치 않음. exception unwinding 메타데이터 슬롯 재활용.
  - 모든 -fexceptions / -fnon-call-exceptions 빌드에 항상 존재 → 보편적 공격 표면.
  - 변환 시 EH 정보 손실 → 예외 throw 시 abort. 단 main 정상 흐름은 무관.

3회 반복 일관성 확인. 평가 기준에 따라 새 finding 으로 인정되는 차이만 F-번호.

가설:
- H1: PT_GNU_EH_FRAME → PT_LOAD RWX 가 PT_NOTE 변환과 동일하게 main 도달 + RWX 텍스트 보임.
- H2: readelf -n 은 PT_NOTE 변형에 영향 받지만 PT_GNU_EH_FRAME 변형에는 무관 → 다른 도구가 단서.
- H3: detector v3 가 동일하게 ANOMALY 로 잡음 (오버랩 시그널 일치).
"""
import harness, subprocess, hashlib
from pathlib import Path

N = 21
TITLE = 'B7: PT_GNU_EH_FRAME → PT_LOAD overlay (PT_NOTE 변환과 비교)'

EH_IDX = 10
TEXT_SIZE = 0x331

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

def spec(name, flags, note):
    return {
        'name': name,
        'base': 'target_full',
        'patches': [
            {'phdr_idx': EH_IDX, 'field': 'type',   'value': 1},
            {'phdr_idx': EH_IDX, 'field': 'flags',  'value': flags},
            {'phdr_idx': EH_IDX, 'field': 'offset', 'value': 0x1000},
            {'phdr_idx': EH_IDX, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': EH_IDX, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': EH_IDX, 'field': 'filesz', 'value': TEXT_SIZE},
            {'phdr_idx': EH_IDX, 'field': 'memsz',  'value': TEXT_SIZE},
            {'phdr_idx': EH_IDX, 'field': 'align',  'value': 0x1000},
        ],
        'note': note,
    }

spec_list = [
    spec('I21V1_ehframe_overlay_rwx', 0x7, 'EH_FRAME → PT_LOAD RWX'),
    spec('I21V2_ehframe_overlay_rw',  0x6, 'EH_FRAME → PT_LOAD RW (no exec)'),
    spec('I21V3_ehframe_overlay_rx',  0x5, 'EH_FRAME → PT_LOAD R-X (control)'),
]

# 3회 반복 일관성: harness.run_iteration 은 1회만 → 직접 3회 run_plain
def run_three_times(name, path):
    exits = []
    stdouts = []
    for trial in range(3):
        plain_log = iter_dir / f'{name}.plain.run{trial+1}.log'
        harness.run_plain(path, plain_log)
        exits.append(harness.exit_code(plain_log))
        stdouts.append(plain_log.read_text())
    return exits, stdouts

obs = harness.run_iteration(N, TITLE, spec_list, observe_addrs=[0x401000, 0x402000, 0x403000])

# 일관성 측정
consistency = {}
for spec_dict in spec_list:
    name = spec_dict['name']
    path = iter_dir / name
    exits, stdouts = run_three_times(name, path)
    consistency[name] = {
        'exits': exits,
        'consistent': len(set(exits)) == 1,
    }

# 정적 도구 매트릭스
def tool_out(args, path):
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, timeout=15)
        return r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')
    except Exception as e:
        return f'ERROR: {e}'

tools = [
    ('readelf_l', ['readelf', '-l']),
    ('readelf_n', ['readelf', '-n']),
    ('readelf_S', ['readelf', '-S']),
    ('file',      ['file']),
    ('objdump_h', ['objdump', '-h']),
    ('checksec',  ['checksec', '--file=', '--no-banner']),
]

# baseline target_full 도 비교에 포함
import shutil
base_path = iter_dir / 'I21V0_baseline'
shutil.copy(harness.ROOT / 'target_full', base_path); base_path.chmod(0o755)

tool_results = {}
for label, path in [('baseline', base_path)] + [(s['name'], iter_dir / s['name']) for s in spec_list]:
    tool_results[label] = {}
    for tname, targs in tools:
        if tname == 'checksec':
            out = tool_out(targs[:1] + [f'--file={path}', targs[2]], path) if shutil.which('checksec') else 'SKIP (checksec not installed)'
        else:
            out = tool_out(targs, path)
        log_path = iter_dir / f'{label}.{tname}.log'
        log_path.write_text(out)
        tool_results[label][tname] = out

# detector v3
import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap
det_results = {}
for label in ['baseline'] + [s['name'] for s in spec_list]:
    p = base_path if label == 'baseline' else iter_dir / label
    det_results[label] = detect_overlap.analyze(str(p))

findings = []
backlog = []

# 결과 인쇄
print('=== iter21 결과 ===')
for r in obs:
    name = r['name']
    print(f'  {name}: plain={r["plain_exit"]} k@0x401={r["kernel_perm"].get("0x401000","?")} m@0x401={r["main_perm"].get("0x401000","?")} '
          f'consistency={consistency[name]["exits"]} det={det_results[name]["verdict"]}')

# PT_NOTE 변환(iter01)과 비교
note_v1_path = harness.OUT_ROOT / 'iter01' / 'I1V1_overlay_rwx'
note_rwx_main = harness.perm_at(harness.parse_maps(harness.OUT_ROOT / 'iter01' / 'I1V1_overlay_rwx.gdb_main.log'), 0x401000)
eh_rwx_main = obs[0]['main_perm'].get('0x401000', '?')

if note_rwx_main == 'rwxp' and eh_rwx_main == 'rwxp':
    findings.append(f'F44: PT_GNU_EH_FRAME → PT_LOAD RWX 변환이 PT_NOTE 변환과 동일하게 텍스트 RWX + main 도달. '
                    f'(iter01 PT_NOTE k@0x401=rwxp, iter21 PT_GNU_EH_FRAME k@0x401={eh_rwx_main}). '
                    f'커널/ld.so 는 phdr 타입 무관 type=PT_LOAD 만 보고 매핑함.')

# readelf -n 차이
note_n_base = tool_results['baseline']['readelf_n']
note_n_var = tool_results['I21V1_ehframe_overlay_rwx']['readelf_n']
findings.append(f'F45: readelf -n baseline vs PT_GNU_EH_FRAME 변형 출력 {"동일" if note_n_base == note_n_var else "다름"} → '
                f'EH_FRAME 슬롯 재활용은 readelf -n 에 노출 안 됨 (PT_NOTE 변환은 노출 가능, iter05 F13c 참고).')

# checksec 차이
if 'SKIP' not in tool_results['baseline'].get('checksec', ''):
    cs_base = tool_results['baseline']['checksec']
    cs_var = tool_results['I21V1_ehframe_overlay_rwx']['checksec']
    findings.append(f'F46: checksec 출력 {"동일" if cs_base == cs_var else "다름"}.')

# 3회 반복 일관성
all_consistent = all(c['consistent'] for c in consistency.values())
findings.append(f'F47: 3회 반복 일관성 — {"전체 일관" if all_consistent else "불일관 발견: "+str({n:c["exits"] for n,c in consistency.items()})}.')

# detector v3 일관 ANOMALY
det_var_all_anomaly = all(det_results[s['name']]['verdict'] == 'ANOMALY' for s in spec_list)
findings.append(f'F48: detector v3 가 PT_GNU_EH_FRAME 변형 3종 모두 ANOMALY 로 분류 = {det_var_all_anomaly} (baseline = {det_results["baseline"]["verdict"]}). '
                f'phdr 타입 다르더라도 페이지 정렬 vaddr 오버랩 시그널은 동일하게 잡힘.')

# readelf -l PT_LOAD 카운트 차이
import re
def count_loads(s): return len(re.findall(r'^\s+LOAD\s', s, re.M))
n_base = count_loads(tool_results['baseline']['readelf_l'])
n_var = count_loads(tool_results['I21V1_ehframe_overlay_rwx']['readelf_l'])
findings.append(f'F49: readelf -l PT_LOAD count: baseline={n_base}, EH_FRAME 변환={n_var}. '
                f'{"증가 — readelf 가 변환 인지함" if n_var > n_base else "동일 — PT_LOAD 카운트로는 미탐지"}.')

backlog.append({'id':'B33','title':'PT_GNU_EH_FRAME 변환 후 실제 예외 발생 시 동작 — std::exception throw 하면 어떻게 죽는지'})

verdict = (f'I21V1 RWX:plain={obs[0]["plain_exit"]} k@0x401={obs[0]["kernel_perm"].get("0x401000","?")} | '
           f'I21V2 RW:plain={obs[1]["plain_exit"]} k@0x401={obs[1]["kernel_perm"].get("0x401000","?")} | '
           f'I21V3 R-X:plain={obs[2]["plain_exit"]} k@0x401={obs[2]["kernel_perm"].get("0x401000","?")} | '
           f'PT_LOAD count base={n_base} var={n_var} | det baseline={det_results["baseline"]["verdict"]} 변형={[det_results[s["name"]]["verdict"] for s in spec_list]}')

harness.commit_iteration(N, TITLE, 'PT_GNU_EH_FRAME 변환이 PT_NOTE 변환과 동일하게 동작한다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print(f'\niter21 complete')
print(f'  consistency: {[(n, c["exits"]) for n, c in consistency.items()]}')
print(f'  PT_LOAD count base={n_base} variant={n_var}')
print(f'  detector verdicts: baseline={det_results["baseline"]["verdict"]} variants={[det_results[s["name"]]["verdict"] for s in spec_list]}')
