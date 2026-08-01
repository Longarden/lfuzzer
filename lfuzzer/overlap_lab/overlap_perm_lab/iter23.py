"""
iter23 — B7 확장: PT_TLS → PT_LOAD 변형.

target_tls 의 PT_TLS (idx 9): offset 0x2dcc, vaddr 0x403dcc, fsz 0x4, fl=R.
.tdata 섹션(__thread int tls_var = 42) 를 가리킴.

가설 H3: PT_TLS 슬롯이 PT_LOAD 로 바뀌면 ld.so 가 TLS 초기화를 못 해서
__thread 변수 접근이 잘못된 값이거나 SEGV.

target_tls 정상 동작: "TLS = 42\\n" 출력.
변형 후: TLS 초기화 실패 → 출력 다르거나 죽음.

발견 후보:
- ld.so 가 PT_TLS 부재 시 어떻게 처리하는지 (rtld _dl_setup_tls 우회)
- TLS 변수 접근이 garbage (이전 메모리 값) 또는 SEGV
"""
import harness, subprocess, shutil
from pathlib import Path

N = 23
TITLE = 'B7: PT_TLS → PT_LOAD overlay (TLS 초기화 갭 검증)'

TLS_IDX = 9   # target_tls
TEXT_SIZE = 0x16d  # target_tls .text PT_LOAD[3] fsz

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

def spec(name, flags, note):
    return {
        'name': name,
        'base': 'target_tls',
        'patches': [
            {'phdr_idx': TLS_IDX, 'field': 'type',   'value': 1},
            {'phdr_idx': TLS_IDX, 'field': 'flags',  'value': flags},
            {'phdr_idx': TLS_IDX, 'field': 'offset', 'value': 0x1000},
            {'phdr_idx': TLS_IDX, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': TLS_IDX, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': TLS_IDX, 'field': 'filesz', 'value': TEXT_SIZE},
            {'phdr_idx': TLS_IDX, 'field': 'memsz',  'value': TEXT_SIZE},
            {'phdr_idx': TLS_IDX, 'field': 'align',  'value': 0x1000},
        ],
        'note': note,
    }

spec_list = [
    spec('I23V1_tls_overlay_rwx', 0x7, 'TLS → PT_LOAD RWX'),
    spec('I23V2_tls_overlay_rw',  0x6, 'TLS → PT_LOAD RW'),
    spec('I23V3_tls_overlay_rx',  0x5, 'TLS → PT_LOAD R-X'),
]

obs = harness.run_iteration(N, TITLE, spec_list, observe_addrs=[0x401000, 0x402000, 0x403000])

# baseline
base_path = iter_dir / 'I23V0_baseline'
shutil.copy(harness.ROOT / 'target_tls', base_path); base_path.chmod(0o755)
harness.run_plain(base_path, iter_dir / 'I23V0_baseline.plain.log')

# 3회 반복
consistency = {}
for s in spec_list + [{'name': 'I23V0_baseline'}]:
    name = s['name']
    path = base_path if 'V0' in name else iter_dir / name
    exits = []; outs = []
    for trial in range(3):
        plain_log = iter_dir / f'{name}.plain.run{trial+1}.log'
        harness.run_plain(path, plain_log)
        exits.append(harness.exit_code(plain_log))
        outs.append(plain_log.read_text())
    consistency[name] = {'exits': exits, 'outs': outs, 'consistent': len(set(exits)) == 1}

def extract_tls_output(stdout):
    for L in stdout.splitlines():
        if 'TLS =' in L: return L.strip()
    return None

# baseline 첫 run 출력
base_out = consistency['I23V0_baseline']['outs'][0]
base_tls = extract_tls_output(base_out)

# detector v3
import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap
det_results = {}
for label, p in [('baseline', base_path)] + [(s['name'], iter_dir / s['name']) for s in spec_list]:
    det_results[label] = detect_overlap.analyze(str(p))

# 정적 도구
def tool_out(args, path):
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, timeout=15)
        return r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')
    except Exception as e:
        return f'ERROR: {e}'

import re
base_l = tool_out(['readelf', '-l'], base_path)
var_l = tool_out(['readelf', '-l'], iter_dir / 'I23V1_tls_overlay_rwx')
(iter_dir / 'baseline.readelf_l.log').write_text(base_l)
(iter_dir / 'I23V1_tls_overlay_rwx.readelf_l.log').write_text(var_l)

# TLS 라인 존재 여부
base_has_tls = 'TLS ' in base_l
var_has_tls  = 'TLS ' in var_l

findings = []
backlog = []

print('=== iter23 결과 ===')
print(f'  baseline: exit={consistency["I23V0_baseline"]["exits"]} output="{base_tls}"')
for r in obs:
    name = r['name']
    out_first = consistency[name]['outs'][0]
    tls_line = extract_tls_output(out_first)
    print(f'  {name}: plain={r["plain_exit"]} k@0x401={r["kernel_perm"].get("0x401000")} '
          f'm@0x401={r["main_perm"].get("0x401000")} consistency={consistency[name]["exits"]} '
          f'tls_line="{tls_line}" det={det_results[name]["verdict"]}')

print(f'  readelf -l TLS line: baseline={base_has_tls} variant={var_has_tls}')

# Findings
if base_tls == 'TLS = 42':
    findings.append(f'F54: baseline target_tls 정상 동작: "{base_tls}".')

v1 = obs[0]
v1_out = consistency['I23V1_tls_overlay_rwx']['outs'][0]
v1_tls = extract_tls_output(v1_out)
if v1['plain_exit'] == 0:
    findings.append(f'F55: PT_TLS → PT_LOAD RWX 변형 main 도달 (exit=0). TLS output="{v1_tls}". '
                    f'{"정상 TLS 값 보임 — ld.so 가 PT_TLS 슬롯 부재에도 TLS 처리함" if v1_tls == "TLS = 42" else "TLS 값 잘못/사라짐 — ld.so 가 PT_TLS 슬롯에 의존" if v1_tls else "TLS 출력 없음 — 다른 위치에서 처리 변경"}.')
elif v1['plain_exit'] == -11:
    findings.append(f'F55: PT_TLS → PT_LOAD RWX 변형 SEGV. TLS 초기화 실패 가능 — H3 부분 부합.')
else:
    findings.append(f'F55: PT_TLS → PT_LOAD RWX 변형 exit={v1["plain_exit"]} 예상 외. 정밀 분석 필요.')

if base_has_tls and not var_has_tls:
    findings.append(f'F56: readelf -l 의 TLS 라인이 변형에서 사라짐 → '
                    f'CET 도구 / TLS 분석기는 변형을 "TLS 없는 정적 바이너리" 로 잘못 인식 가능.')

all_anomaly = all(det_results[s['name']]['verdict'] == 'ANOMALY' for s in spec_list)
findings.append(f'F57: detector v3 PT_TLS 변형 3종 모두 ANOMALY = {all_anomaly} (baseline={det_results["baseline"]["verdict"]}).')

all_consistent = all(c['consistent'] for c in consistency.values())
findings.append(f'F58: 3회 반복 일관성 = {all_consistent}.')

backlog.append({'id':'B35','title':'PT_TLS 부재 시 ld.so 의 TLS 초기화 코드 경로 (_dl_allocate_tls_init 등) 추적 — '
                'glibc dl-tls.c 어디서 PT_TLS 가 없으면 우회되는지'})

verdict = (f'base:exit={consistency["I23V0_baseline"]["exits"][0]} out="{base_tls}" | '
           f'V1 RWX:exit={obs[0]["plain_exit"]} out="{v1_tls}" k@0x401={obs[0]["kernel_perm"].get("0x401000")} | '
           f'V2 RW:exit={obs[1]["plain_exit"]} | V3 R-X:exit={obs[2]["plain_exit"]} | '
           f'TLS line base={base_has_tls} var={var_has_tls} | det all_anomaly={all_anomaly}')

harness.commit_iteration(N, TITLE, 'PT_TLS → PT_LOAD 변환의 TLS 초기화 영향 확인', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print(f'\niter23 complete')
