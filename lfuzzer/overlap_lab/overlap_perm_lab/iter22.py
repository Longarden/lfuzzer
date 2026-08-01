"""
iter22 — B7 확장: PT_GNU_PROPERTY → PT_LOAD 변형.

target_full PT_GNU_PROPERTY (idx 9): offset 0x338, vaddr 0x400338, fsz 0x30 (NT_GNU_PROPERTY_TYPE_0
   = .note.gnu.property 가리킴 — CET/IBT 마커 포함 가능).
이 슬롯을 PT_LOAD 로 바꾸고 텍스트 페이지 RWX 오버레이.

가설 H1: PT_GNU_PROPERTY 변환 시 ld.so 의 CET/SHSTK 처리 (rtld 의 _dl_process_pt_gnu_property 같은
함수) 가 슬롯을 잃어 어떤 동작이 사라지거나 의심 흔적 남는지.

추가 관찰:
- readelf -n: PT_GNU_PROPERTY 슬롯이 사라지면 NT_GNU_PROPERTY 노트가 보고 안 될 수 있음.
- /proc/<pid>/auxv 의 AT_HWCAP 변화 가능성 (영향 미미).
"""
import harness, subprocess, shutil
from pathlib import Path

N = 22
TITLE = 'B7: PT_GNU_PROPERTY → PT_LOAD overlay (CET 마커 슬롯 재활용)'

PROP_IDX = 9
TEXT_SIZE = 0x331

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

def spec(name, flags, note):
    return {
        'name': name,
        'base': 'target_full',
        'patches': [
            {'phdr_idx': PROP_IDX, 'field': 'type',   'value': 1},
            {'phdr_idx': PROP_IDX, 'field': 'flags',  'value': flags},
            {'phdr_idx': PROP_IDX, 'field': 'offset', 'value': 0x1000},
            {'phdr_idx': PROP_IDX, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': PROP_IDX, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': PROP_IDX, 'field': 'filesz', 'value': TEXT_SIZE},
            {'phdr_idx': PROP_IDX, 'field': 'memsz',  'value': TEXT_SIZE},
            {'phdr_idx': PROP_IDX, 'field': 'align',  'value': 0x1000},
        ],
        'note': note,
    }

spec_list = [
    spec('I22V1_property_overlay_rwx', 0x7, 'PROPERTY → PT_LOAD RWX'),
    spec('I22V2_property_overlay_rw',  0x6, 'PROPERTY → PT_LOAD RW'),
    spec('I22V3_property_overlay_rx',  0x5, 'PROPERTY → PT_LOAD R-X'),
]

obs = harness.run_iteration(N, TITLE, spec_list, observe_addrs=[0x401000, 0x402000, 0x403000])

# 3회 반복
consistency = {}
for s in spec_list:
    name = s['name']; path = iter_dir / name
    exits = []
    for trial in range(3):
        plain_log = iter_dir / f'{name}.plain.run{trial+1}.log'
        harness.run_plain(path, plain_log)
        exits.append(harness.exit_code(plain_log))
    consistency[name] = {'exits': exits, 'consistent': len(set(exits)) == 1}

# 정적 도구 매트릭스
def tool_out(args, path):
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, timeout=15)
        return r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')
    except Exception as e:
        return f'ERROR: {e}'

base_path = iter_dir / 'I22V0_baseline'
shutil.copy(harness.ROOT / 'target_full', base_path); base_path.chmod(0o755)

tools = [
    ('readelf_l', ['readelf', '-l']),
    ('readelf_n', ['readelf', '-n']),
    ('readelf_S', ['readelf', '-S']),
    ('file',      ['file']),
    ('objdump_h', ['objdump', '-h']),
]

tool_results = {}
for label, p in [('baseline', base_path)] + [(s['name'], iter_dir / s['name']) for s in spec_list]:
    tool_results[label] = {}
    for tname, targs in tools:
        out = tool_out(targs, p)
        (iter_dir / f'{label}.{tname}.log').write_text(out)
        tool_results[label][tname] = out

# detector v3
import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap
det_results = {}
for label, p in [('baseline', base_path)] + [(s['name'], iter_dir / s['name']) for s in spec_list]:
    det_results[label] = detect_overlap.analyze(str(p))

# readelf -n 차이 — 핵심 관찰
import re
def find_property_note(s):
    return 'NT_GNU_PROPERTY' in s or '.note.gnu.property' in s or 'IBT' in s or 'SHSTK' in s or 'gnu.properties' in s

base_n = tool_results['baseline']['readelf_n']
var_n = tool_results['I22V1_property_overlay_rwx']['readelf_n']
base_has_property = find_property_note(base_n)
var_has_property  = find_property_note(var_n)

# PT_LOAD count
def count_loads(s): return len(re.findall(r'^\s+LOAD\s', s, re.M))
n_base = count_loads(tool_results['baseline']['readelf_l'])
n_var = count_loads(tool_results['I22V1_property_overlay_rwx']['readelf_l'])

findings = []
backlog = []

# 결과 인쇄
print('=== iter22 결과 ===')
for r in obs:
    name = r['name']
    print(f'  {name}: plain={r["plain_exit"]} k@0x401={r["kernel_perm"].get("0x401000","?")} m@0x401={r["main_perm"].get("0x401000","?")} '
          f'consistency={consistency[name]["exits"]} det={det_results[name]["verdict"]}')
print(f'  PT_LOAD count: baseline={n_base} variant={n_var}')
print(f'  readelf -n NT_GNU_PROPERTY: baseline={base_has_property} variant={var_has_property}')

# F-findings
v1 = obs[0]
if v1['plain_exit'] == 0 and v1['kernel_perm'].get('0x401000') == 'rwxp':
    findings.append(f'F50: PT_GNU_PROPERTY → PT_LOAD RWX 변환도 PT_NOTE/PT_GNU_EH_FRAME 변환과 동일하게 텍스트 RWX + main 도달. '
                    f'kernel/ld.so 가 phdr 타입 검증 없음을 재확인.')
else:
    findings.append(f'F50alt: PT_GNU_PROPERTY 변환 결과 plain={v1["plain_exit"]} k@0x401={v1["kernel_perm"].get("0x401000")}. '
                    f'PT_NOTE/EH_FRAME 와 달라짐.')

if base_has_property and not var_has_property:
    findings.append(f'F51: readelf -n 에서 NT_GNU_PROPERTY 마커가 변형에서 사라짐 → '
                    f'CET/IBT 분석 도구는 변형을 "보호 없음" 으로 잘못 인식할 가능성.')
elif base_has_property == var_has_property:
    findings.append(f'F51: readelf -n NT_GNU_PROPERTY 출력 변화 = {base_has_property == var_has_property}. '
                    f'PT_GNU_PROPERTY 가 PT_LOAD 가 되어도 .note.gnu.property 섹션이 PT_LOAD[2] 안에 그대로 있으면 '
                    f'readelf 가 섹션 헤더로 노트를 찾아서 출력함.')

all_anomaly = all(det_results[s['name']]['verdict'] == 'ANOMALY' for s in spec_list)
findings.append(f'F52: detector v3 PT_GNU_PROPERTY 변형 3종 모두 ANOMALY = {all_anomaly} (baseline = {det_results["baseline"]["verdict"]}).')

all_consistent = all(c['consistent'] for c in consistency.values())
findings.append(f'F53: 3회 반복 일관성 = {all_consistent} ({consistency}).')

backlog.append({'id':'B34','title':'PT_GNU_PROPERTY 변환된 바이너리에 대해 /proc/<pid>/status 의 IBT/SHSTK 활성화 여부 측정 — '
                'CET 보호가 실제로 무력화되는지 vs 섹션 헤더로 노트가 살아 있어서 영향 없는지'})

verdict = (f'V1 RWX plain={obs[0]["plain_exit"]} k@0x401={obs[0]["kernel_perm"].get("0x401000")} | '
           f'V2 RW plain={obs[1]["plain_exit"]} k@0x401={obs[1]["kernel_perm"].get("0x401000")} | '
           f'V3 R-X plain={obs[2]["plain_exit"]} k@0x401={obs[2]["kernel_perm"].get("0x401000")} | '
           f'PT_LOAD count {n_base}→{n_var} | NT_GNU_PROPERTY: base={base_has_property} var={var_has_property} | '
           f'detector all_anomaly={all_anomaly}')

harness.commit_iteration(N, TITLE, 'PT_GNU_PROPERTY → PT_LOAD 가 PT_NOTE 변환과 동일하지만 readelf -n 흔적이 다를 수 있다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print(f'\niter22 complete')
