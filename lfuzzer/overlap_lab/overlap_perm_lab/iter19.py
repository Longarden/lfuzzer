"""
iter19 — 미팅 발표용 클린 DEMO.

target_demo: 단일 출력 분기.
- baseline: magic() returns 1 → "Hello, ELF World!"
- combo 변형: 파일 끝에 텍스트 사본(magic 자리에 mov $42; ret 패치) 부착 + PT_NOTE[8] → PT_LOAD R-X overlay
- 결과: "Hello from Combo World!"

baseline 과 변형의 차이는 readelf -l 의 PT_LOAD 한 줄과 sha256 두 가지뿐.
"""
import harness, shutil, struct
from pathlib import Path

N = 19
TITLE = '미팅 발표용 클린 DEMO (Hello, ELF World! ↔ Hello from Combo World!)'

TARGET = harness.ROOT / 'target_demo'
PAGE = 0x1000
TEXT_OFF = 0x1000
MAGIC_INTRA = 0x401136 - 0x401000  # 0x136
PAYLOAD = b'\xb8\x2a\x00\x00\x00\xc3'  # mov $42; ret

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

base_path = iter_dir / 'I19V0_baseline'
shutil.copy(TARGET, base_path); base_path.chmod(0o755)

# 변형: file 끝에 텍스트 사본 부착 + PT_NOTE[8] PT_LOAD overlay
data = bytearray(TARGET.read_bytes())
text_copy = bytearray(data[TEXT_OFF:TEXT_OFF + PAGE])
text_copy[MAGIC_INTRA:MAGIC_INTRA + len(PAYLOAD)] = PAYLOAD
new_off = (len(data) + PAGE - 1) & ~(PAGE - 1)
data += b'\x00' * (new_off - len(data))
data += text_copy

patches = [
    {'phdr_idx': 8, 'field': 'type',   'value': 1},
    {'phdr_idx': 8, 'field': 'flags',  'value': 0x5},   # R-X
    {'phdr_idx': 8, 'field': 'offset', 'value': new_off},
    {'phdr_idx': 8, 'field': 'vaddr',  'value': 0x401000},
    {'phdr_idx': 8, 'field': 'paddr',  'value': 0x401000},
    {'phdr_idx': 8, 'field': 'filesz', 'value': PAGE},
    {'phdr_idx': 8, 'field': 'memsz',  'value': PAGE},
    {'phdr_idx': 8, 'field': 'align',  'value': PAGE},
]
patched = harness.apply_patches(bytes(data), patches)
variant_path = iter_dir / 'I19V1_combo_demo'
variant_path.write_bytes(patched); variant_path.chmod(0o755)

# 실행
def run_and_record(name, path):
    plain_log = iter_dir / f'{name}.plain.log'
    harness.run_plain(path, plain_log)
    return {
        'name': name,
        'exit': harness.exit_code(plain_log),
        'stdout': plain_log.read_text(),
    }

base_r = run_and_record('I19V0_baseline', base_path)
var_r  = run_and_record('I19V1_combo_demo', variant_path)

# detector v3
import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap
det_b = detect_overlap.analyze(str(base_path))
det_v = detect_overlap.analyze(str(variant_path))

# 출력에서 핵심 메시지만 추출
def extract_line(stdout):
    for L in stdout.splitlines():
        if 'Hello' in L: return L.strip()
    return '(no Hello line)'

base_msg = extract_line(base_r['stdout'])
var_msg  = extract_line(var_r['stdout'])

findings = []
backlog = []

if base_msg == 'Hello, ELF World!' and var_msg == 'Hello from Combo World!':
    findings.append(f'F40: 클린 DEMO 분기 성공. baseline = "{base_msg}", combo = "{var_msg}". '
                    f'단일 출력 1줄로 정적 분석 결과(magic→1) 와 동적 실행 결과(magic→42) 의 차이를 즉시 시각화 가능.')
else:
    findings.append(f'F40alt: 분기 출력 — baseline = "{base_msg}", combo = "{var_msg}".')

findings.append(f'F41: DEMO baseline 과 변형의 표면 차이는 readelf -l (PT_LOAD 4→5) + sha256 뿐. '
                f'detector v3 는 ANOMALY 로 잡음 (base={det_b["verdict"]} combo={det_v["verdict"]}).')

backlog.append({'id':'B32','title':'DEMO 의 출력 텍스트 자체를 .data 안에 두 버전 박고 overlay 가 .rodata 가 아닌 .data 포인터를 가리키게 — 더 강한 위장'})

obs = [
    {'name': base_r['name'], 'plain_exit': base_r['exit'], 'kernel_perm': {}, 'main_perm': {}, 'note': base_msg},
    {'name': var_r['name'],  'plain_exit': var_r['exit'],  'kernel_perm': {}, 'main_perm': {}, 'note': var_msg},
]

verdict = (f'baseline: exit={base_r["exit"]} → "{base_msg}" | '
           f'combo: exit={var_r["exit"]} → "{var_msg}" | '
           f'detector base={det_b["verdict"]} combo={det_v["verdict"]}')

harness.commit_iteration(N, TITLE, '클린 DEMO 가 단일 출력 분기로 정적/동적 차이를 즉시 보여준다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter19 complete')
print(f'  baseline → "{base_msg}"')
print(f'  combo    → "{var_msg}"')
print(f'  detector base={det_b["verdict"]} combo={det_v["verdict"]}')
print(f'  baseline path: {base_path}')
print(f'  combo path   : {variant_path}')
