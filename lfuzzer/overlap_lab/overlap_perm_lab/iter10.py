"""
iter10 — B12: file size 변화 없이 in-file payload 로 분기 (v2).

학습: 단순히 .payload 섹션을 텍스트 위에 덮으면 _start 까지 NULL 로 덮여 SEGV.
해결: build 후 .payload 섹션을 텍스트 원본 사본으로 채우고 target_func 자리만 mov $42; ret
로 덮는다. file size 동일, 단 .payload 내용은 build 시점 0 → patch 후 텍스트 사본.
즉 file 안에 "위장된 텍스트 복제본 + target_func 패치" 가 미리 들어가 있는 형태.

가설:
- 변형 1 (단순 overlay): _start 자리 NULL → SEGV. (iter10 v1 에서 이미 확인)
- 변형 2 (사본 + 패치): _start/main 자리에 원본 텍스트 바이트 + target_func 자리에 페이로드.
  → main 도달, target_func = 42, exit=0. file size 동일.
"""
import harness, shutil, struct
from pathlib import Path

N = 10
TITLE = 'B12 v2: in-file payload (텍스트 사본 + 패치) 로 file size 동일 분기'

TARGET = harness.ROOT / 'target_in'
TEXT_FILE_OFF = 0x1000   # PT_LOAD[3] offset
TEXT_VADDR    = 0x401000
PAYLOAD_FILE_OFF = 0x3000  # .payload section file offset
TARGET_FUNC_INTRA = 0x401136 - TEXT_VADDR  # 0x136
PAYLOAD_BYTES = b'\xb8\x2a\x00\x00\x00\xc3'  # mov $42; ret

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

# baseline
base_path = iter_dir / 'I10V0_baseline'
shutil.copy(TARGET, base_path); base_path.chmod(0o755)

# 변형 2: payload 섹션 안을 텍스트 사본 + target_func 위치 패치로 채움 + PT_NOTE[8] overlay
def build_v2(out_path):
    data = bytearray(Path(TARGET).read_bytes())
    # .payload (0x3000-0x4000) 안에 텍스트 사본 (0x1000-0x2000) 복사
    data[PAYLOAD_FILE_OFF:PAYLOAD_FILE_OFF + 0x1000] = data[TEXT_FILE_OFF:TEXT_FILE_OFF + 0x1000]
    # target_func 자리에 페이로드
    patch_off = PAYLOAD_FILE_OFF + TARGET_FUNC_INTRA
    data[patch_off:patch_off + len(PAYLOAD_BYTES)] = PAYLOAD_BYTES
    # PT_NOTE[8] → PT_LOAD R-X overlay
    patches = [
        {'phdr_idx': 8, 'field': 'type',   'value': 1},
        {'phdr_idx': 8, 'field': 'flags',  'value': 0x5},
        {'phdr_idx': 8, 'field': 'offset', 'value': PAYLOAD_FILE_OFF},
        {'phdr_idx': 8, 'field': 'vaddr',  'value': TEXT_VADDR},
        {'phdr_idx': 8, 'field': 'paddr',  'value': TEXT_VADDR},
        {'phdr_idx': 8, 'field': 'filesz', 'value': 0x1000},
        {'phdr_idx': 8, 'field': 'memsz',  'value': 0x1000},
        {'phdr_idx': 8, 'field': 'align',  'value': 0x1000},
    ]
    patched = harness.apply_patches(bytes(data), patches)
    Path(out_path).write_bytes(patched)
    import os; os.chmod(out_path, 0o755)

variant_path = iter_dir / 'I10V2_payload_with_textcopy'
build_v2(variant_path)

obs = []
for name, path in [('I10V0_baseline', base_path), ('I10V2_payload_with_textcopy', variant_path)]:
    plain_log = iter_dir / f'{name}.plain.log'
    gdb_k     = iter_dir / f'{name}.gdb_kernel.log'
    gdb_m     = iter_dir / f'{name}.gdb_main.log'
    harness.run_plain(path, plain_log)
    harness.run_gdb(path, gdb_k, 'kernel')
    harness.run_gdb(path, gdb_m, 'main')
    k = harness.parse_maps(gdb_k); m = harness.parse_maps(gdb_m)
    obs.append({
        'name': name,
        'note': 'baseline' if 'V0' in name else 'textcopy+patch overlay',
        'plain_exit': harness.exit_code(plain_log),
        'kernel_perm': {'0x401000': harness.perm_at(k, 0x401000)},
        'main_perm':   {'0x401000': harness.perm_at(m, 0x401000)},
        'stdout': plain_log.read_text()[:400],
    })

base_size = TARGET.stat().st_size
var_size = variant_path.stat().st_size

import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

det_b = detect_overlap.analyze(str(base_path))
det_v = detect_overlap.analyze(str(variant_path))

ok_base = 'result = 1' in obs[0]['stdout']
ok_var  = 'result = 42' in obs[1]['stdout']
same_size = base_size == var_size

findings = []
backlog = []

if ok_base and ok_var and same_size:
    findings.append(f'F21: file size 동일 ({base_size} bytes). PHT 1줄 패치 + .payload 섹션 내용을 텍스트 사본 + 6바이트 패치로 채워 target_func 결과 1→42. '
                    f'iter04 의 file append 단서까지 제거됨. ELF 안에 의심스러운 트레일링 데이터 없음.')
    backlog.append({'id':'B22','title':'F21 의 .payload 섹션 이름을 ".rodata" 같이 평범화 (objdump -h 로도 의심받지 않게)'})
    backlog.append({'id':'B23','title':'F21 변형 vs baseline 의 strings/file/sha256 차이 측정 — 표면 차이 점검'})
elif not ok_var:
    findings.append(f'F21alt: 변형 결과 42 안 나옴 → {obs[1]["stdout"][:200]}')
    backlog.append({'id':'B22r','title':'overlay 매핑 디스어셈블 재확인'})

if det_v['verdict'] == 'ANOMALY':
    findings.append('F22: detector v2 는 in-file payload 변형도 PT_LOAD 페이지 정렬 오버랩으로 ANOMALY 탐지. '
                    'file size 단서 제거되어도 vaddr 오버랩 시그널 살아 있음.')

verdict = (f'base:exit={obs[0]["plain_exit"]} out={"r=1" if ok_base else "?"} | '
           f'v2:exit={obs[1]["plain_exit"]} out={"r=42" if ok_var else "?"} | '
           f'size {base_size}={var_size} ({"same" if same_size else "DIFF"}) | '
           f'det baseline={det_b["verdict"]} variant={det_v["verdict"]}')

harness.commit_iteration(N, TITLE, '텍스트 사본 + 패치로 in-file payload PoC 가 main 도달', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter10 complete')
for r in obs:
    print(f'  {r["name"]}: exit={r["plain_exit"]} stdout={r["stdout"].replace(chr(10)," | ")[:200]}')
print(f'  file size base={base_size} var={var_size} ({"same" if same_size else "DIFF"})')
print(f'  detector: base={det_b["verdict"]} var={det_v["verdict"]}')
