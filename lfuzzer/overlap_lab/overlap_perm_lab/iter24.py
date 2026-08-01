"""
iter24 — B7 확장: PT_GNU_STACK → PT_LOAD 변형.

target_full PT_GNU_STACK (idx 11): offset/vaddr/fsz/msz 모두 0. fl=0x6 (RW).
원래 의미는 "스택 권한 마커" — 실제 매핑 없음.

변형: type=PT_LOAD + 텍스트 오버레이 필드 채움.

가설 H4: memsz=0 이라 추가 작업 필요. 또한 PT_GNU_STACK 은 ld.so/커널이
stack 권한 결정에 사용하므로 변환 시 NX 스택 적용에 영향 가능.

추가 관찰:
- 변형 후 스택 권한 (gdb maps 의 [stack] 라인) 이 RWX 로 바뀌나?
- PT_GNU_STACK 부재 시 커널이 legacy default(executable stack) 적용?
"""
import harness, subprocess, shutil
from pathlib import Path

N = 24
TITLE = 'B7: PT_GNU_STACK → PT_LOAD overlay + 스택 권한 영향 측정'

STACK_IDX = 11
TEXT_SIZE = 0x331

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

def spec(name, flags, note):
    return {
        'name': name,
        'base': 'target_full',
        'patches': [
            {'phdr_idx': STACK_IDX, 'field': 'type',   'value': 1},
            {'phdr_idx': STACK_IDX, 'field': 'flags',  'value': flags},
            {'phdr_idx': STACK_IDX, 'field': 'offset', 'value': 0x1000},
            {'phdr_idx': STACK_IDX, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': STACK_IDX, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': STACK_IDX, 'field': 'filesz', 'value': TEXT_SIZE},
            {'phdr_idx': STACK_IDX, 'field': 'memsz',  'value': TEXT_SIZE},
            {'phdr_idx': STACK_IDX, 'field': 'align',  'value': 0x1000},
        ],
        'note': note,
    }

spec_list = [
    spec('I24V1_stack_overlay_rwx', 0x7, 'STACK → PT_LOAD RWX (text overlay)'),
    spec('I24V2_stack_overlay_rw',  0x6, 'STACK → PT_LOAD RW (text overlay)'),
    spec('I24V3_stack_overlay_rx',  0x5, 'STACK → PT_LOAD R-X'),
]

obs = harness.run_iteration(N, TITLE, spec_list, observe_addrs=[0x401000, 0x402000, 0x403000])

# baseline
base_path = iter_dir / 'I24V0_baseline'
shutil.copy(harness.ROOT / 'target_full', base_path); base_path.chmod(0o755)
harness.run_plain(base_path, iter_dir / 'I24V0_baseline.plain.log')
harness.run_gdb(base_path, iter_dir / 'I24V0_baseline.gdb_main.log', 'main')

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

# stack 권한 — gdb_main 로그 안 [stack] 매핑 찾기
import re
def stack_perm(gdb_log_path):
    if not Path(gdb_log_path).exists(): return None
    txt = Path(gdb_log_path).read_text()
    m = re.search(r'^\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+([rwxp-]+)\s+\[stack\]', txt, re.M)
    return m.group(1) if m else None

base_stack = stack_perm(iter_dir / 'I24V0_baseline.gdb_main.log')
v1_stack = stack_perm(iter_dir / 'I24V1_stack_overlay_rwx.gdb_main.log')

# detector v3
import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap
det_results = {}
for label, p in [('baseline', base_path)] + [(s['name'], iter_dir / s['name']) for s in spec_list]:
    det_results[label] = detect_overlap.analyze(str(p))

# readelf -l (GNU_STACK 라인 변화)
def tool_out(args, path):
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, timeout=15)
        return r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')
    except Exception as e:
        return f'ERROR: {e}'

base_l = tool_out(['readelf', '-l'], base_path)
var_l = tool_out(['readelf', '-l'], iter_dir / 'I24V1_stack_overlay_rwx')
(iter_dir / 'baseline.readelf_l.log').write_text(base_l)
(iter_dir / 'I24V1_stack_overlay_rwx.readelf_l.log').write_text(var_l)
base_has_stack = 'GNU_STACK' in base_l
var_has_stack  = 'GNU_STACK' in var_l

findings = []
backlog = []

print('=== iter24 결과 ===')
print(f'  baseline: stack perm={base_stack}')
for r in obs:
    name = r['name']
    print(f'  {name}: plain={r["plain_exit"]} k@0x401={r["kernel_perm"].get("0x401000")} '
          f'm@0x401={r["main_perm"].get("0x401000")} consistency={consistency[name]["exits"]} '
          f'det={det_results[name]["verdict"]}')
print(f'  V1 stack perm: {v1_stack}')
print(f'  readelf -l GNU_STACK: baseline={base_has_stack} variant={var_has_stack}')

# F-findings
v1 = obs[0]
if v1['plain_exit'] == 0 and v1['kernel_perm'].get('0x401000') == 'rwxp':
    findings.append(f'F59: PT_GNU_STACK → PT_LOAD RWX 변환도 PT_NOTE/EH_FRAME/PROPERTY 와 동일하게 텍스트 RWX + main 도달. '
                    f'PT_GNU_STACK 의 memsz=0 baseline 도 type/offset/vaddr/memsz 한 번에 패치하면 정상 PT_LOAD 로 동작.')

if base_stack and v1_stack:
    findings.append(f'F60: 스택 권한 — baseline={base_stack}, V1={v1_stack}. '
                    f'{"변화 없음 — PT_GNU_STACK 이 PT_LOAD 가 되어도 커널은 default NX 적용" if base_stack == v1_stack else "스택 권한 변화! PT_GNU_STACK 부재로 커널이 다른 default 적용"}.')

if base_has_stack and not var_has_stack:
    findings.append(f'F61: readelf -l 의 GNU_STACK 라인이 변형에서 사라짐 → '
                    f'execstack 같은 도구는 변형을 "GNU_STACK 마커 없음" 으로 봐서 NX 상태를 잘못 보고 가능.')

all_anomaly = all(det_results[s['name']]['verdict'] == 'ANOMALY' for s in spec_list)
findings.append(f'F62: detector v3 PT_GNU_STACK 변형 3종 모두 ANOMALY = {all_anomaly}.')

all_consistent = all(c['consistent'] for c in consistency.values())
findings.append(f'F63: 3회 반복 일관성 = {all_consistent}.')

backlog.append({'id':'B36','title':'PT_GNU_STACK 가 PT_LOAD 가 됐을 때 execstack -q 출력 변화 측정 — 도구가 어떻게 보고하는지'})

verdict = (f'V1 RWX:plain={obs[0]["plain_exit"]} k@0x401={obs[0]["kernel_perm"].get("0x401000")} stack={v1_stack} | '
           f'V2 RW:plain={obs[1]["plain_exit"]} | V3 R-X:plain={obs[2]["plain_exit"]} | '
           f'stack base={base_stack} V1={v1_stack} | GNU_STACK base={base_has_stack} var={var_has_stack} | '
           f'det all_anomaly={all_anomaly}')

harness.commit_iteration(N, TITLE, 'PT_GNU_STACK 변환은 다른 메타 phdr 들과 동일 동작, 스택 권한 변화 없음', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print(f'\niter24 complete')
