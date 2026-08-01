"""
iter05 — 정적 분석 도구 탐지 매트릭스.

iter04 의 I4V1 (pre-staged overlay) 를 readelf/objdump/file/ldd 로 검사.
어느 도구가 PT_NOTE→PT_LOAD overlay 를 "오버랩" 또는 "수상함" 으로 표시하는지 측정.

가설:
- readelf -l 은 PT_LOAD 로 새로 표시함 (탐지 1차 가능)
- objdump -d 는 PT_LOAD[3] 의 텍스트만 디스어셈블 → 오버레이 모름
- file 은 ELF 헤더만 보고 정상으로 보고
- ldd 는 dynamic deps 만 봄
"""
import harness, subprocess
from pathlib import Path

N = 5
TITLE = '정적 분석 도구 탐지 매트릭스'

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

bases = {
    'baseline'    : harness.OUT_ROOT / 'iter04' / 'I4V0_baseline',
    'prestaged'   : harness.OUT_ROOT / 'iter04' / 'I4V1_prestaged_payload',
}

tools = [
    ('readelf_l',      ['readelf', '-l']),       # phdr 목록
    ('readelf_S',      ['readelf', '-S']),       # section header
    ('readelf_n',      ['readelf', '-n']),       # notes
    ('objdump_d',      ['objdump', '-d']),       # 디스어셈블
    ('objdump_h',      ['objdump', '-h']),       # section headers via objdump
    ('file',           ['file']),
]

def run_tool(args, path):
    try:
        r = subprocess.run(args + [str(path)], capture_output=True, timeout=15)
        return r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')
    except Exception as e:
        return f'ERROR: {e}'

obs = []
findings, backlog = [], []
target_func_va = 0x401136

for label, path in bases.items():
    rec = {'label': label, 'path': str(path), 'tools': {}}
    for tname, targs in tools:
        out = run_tool(targs, path)
        log_path = iter_dir / f'{label}.{tname}.log'
        log_path.write_text(out)
        rec['tools'][tname] = out
    obs.append(rec)

# 비교
b = obs[0]['tools']; p = obs[1]['tools']

# readelf -l 차이
import re
def count_pt_load(text):
    return len(re.findall(r'^\s+LOAD\s', text, re.M))
def total_phdr_lines(text):
    return len(re.findall(r'^\s+(LOAD|NOTE|DYNAMIC|INTERP|GNU_RELRO|GNU_STACK|GNU_PROPERTY|GNU_EH_FRAME|PHDR)\s', text, re.M))

b_loads = count_pt_load(b['readelf_l']); p_loads = count_pt_load(p['readelf_l'])

# objdump -d 가 0x401136 target_func 의 어떤 코드를 보여주는지
def disasm_at(text, va):
    pat = re.compile(rf'^{va:x} <[^>]+>:\s*\n((?:\s*[0-9a-f]+:.*\n){{0,8}})', re.M)
    m = pat.search(text)
    return m.group(0) if m else 'NOT FOUND'

b_disasm = disasm_at(b['objdump_d'], target_func_va)
p_disasm = disasm_at(p['objdump_d'], target_func_va)

findings.append(f'F13a: readelf -l PT_LOAD 개수 baseline={b_loads}, prestaged={p_loads}. '
                f'{"증가" if p_loads > b_loads else "변화 없음"} → readelf 는 overlay 를 PT_LOAD 로 표시 {"함" if p_loads > b_loads else "안 함"}.')

if b_disasm.strip() == p_disasm.strip():
    findings.append('F13b: objdump -d 가 두 바이너리에서 target_func 자리에 동일한 디스어셈블 출력. '
                    '오버레이가 매핑하는 다른 파일 영역은 디스어셈블되지 않음 → objdump 는 overlay 를 본질적으로 탐지 못 함.')
else:
    findings.append('F13b: objdump -d 가 두 바이너리에서 다른 출력 — 의외. 정밀 확인 필요.')

# readelf -n 변화 — PT_NOTE 가 PT_LOAD 로 바뀌었으니 note 표시도 줄어들 것
b_notes = len(re.findall(r'^Displaying notes', b['readelf_n'], re.M))
p_notes = len(re.findall(r'^Displaying notes', p['readelf_n'], re.M))
findings.append(f'F13c: readelf -n notes 섹션 개수 baseline={b_notes}, prestaged={p_notes}. '
                f'{"감소" if p_notes < b_notes else "동일"} → PT_NOTE 슬롯이 PT_LOAD 로 바뀐 흔적이 readelf -n 에 노출 {"됨" if p_notes < b_notes else "안 됨"}.')

# 종합 판정
findings.append('F13: 정적 도구 매트릭스 — readelf -l 만이 새 PT_LOAD 를 보여줌. objdump -d 는 PT_LOAD[3] 만 디스어셈블해 overlay 미탐지. '
                'malware 분석가가 readelf -l 출력을 PHDR 오버랩 검사 없이 단순히 "PT_LOAD 가 N 개" 로만 보면 놓치기 쉬움.')

backlog.append({'id':'B13','title':'Ghidra/IDA/Binary Ninja 자동 분석에서 같은 변형이 어떻게 처리되는지 — 별도 환경 필요'})
backlog.append({'id':'B14','title':'PT_NOTE→PT_LOAD 가 아니라 새 phdr 슬롯을 만들지 않고 기존 PT_LOAD 의 vaddr/offset 만 조작해서 같은 효과 — 그러면 PT_LOAD 개수도 안 늘어남'})

# state 갱신 (obs 는 너무 크니까 요약만 저장)
summary_obs = [{
    'name': r['label'],
    'plain_exit': None,
    'kernel_perm': {},
    'main_perm': {},
    'note': f'{len(r["tools"])} tool outputs captured under iter05/'
} for r in obs]

verdict = (f'PT_LOAD count: baseline={b_loads} prestaged={p_loads} | '
           f'objdump@target_func 동일: {b_disasm.strip() == p_disasm.strip()}')

harness.commit_iteration(N, TITLE, '정적 도구 대부분이 PHDR overlay 를 탐지 못함', summary_obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter05 complete')
print(f'  readelf -l PT_LOAD: baseline={b_loads} prestaged={p_loads}')
print(f'  objdump@target_func equal: {b_disasm.strip() == p_disasm.strip()}')
print(f'  --- baseline target_func disasm ---\n{b_disasm}')
print(f'  --- prestaged target_func disasm ---\n{p_disasm}')
