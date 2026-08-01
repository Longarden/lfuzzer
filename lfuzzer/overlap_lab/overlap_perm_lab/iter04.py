"""
iter04 — 미리 박힌 페이로드 (pre-staged) PoC.
runtime memcpy 없이, PHT 오버레이가 다른 파일 영역을 텍스트 페이지에 매핑.

target_pre: 정적 디스어셈블 시 target_func() { return 1; }.
- baseline: target_func 호출 결과 1.
- 오버레이 변형: 파일 끝에 modified text page 부착 (target_func 자리에 "mov $42; ret" 박힘)
                + PT_NOTE[8] → PT_LOAD R-X with offset=NEW_OFF, vaddr=0x401000.
  런타임 target_func 호출은 42 반환.

가설:
- 정적 분석은 PT_LOAD[3] R-X 의 텍스트만 디스어셈블하므로 "return 1" 으로 본다.
- 런타임은 PHT 순서상 마지막 PT_LOAD 가 0x401000 페이지를 덮어서 결과 분기.
- 무작위 메모리 쓰기 없음 → strace/syscall 추적도 깨끗.
"""
import harness, struct
from pathlib import Path

N = 4
TITLE = 'Pre-staged payload via overlay file offset (no runtime SMC)'

TARGET = harness.ROOT / 'target_pre'
PAGE = 0x1000
TEXT_OFF = 0x1000
TEXT_SIZE = 0x191
TARGET_FUNC_INTRA = 0x401136 - 0x401000   # 0x136
PAYLOAD = b'\xb8\x2a\x00\x00\x00\xc3'      # mov $42, %eax; ret

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

def build_overlay_variant(out_path):
    data = bytearray(Path(TARGET).read_bytes())
    # 원본 text page 0x1000..0x2000 의 0x1000 바이트 (text + 패딩) 복사
    modified = bytearray(data[TEXT_OFF:TEXT_OFF + PAGE])
    modified[TARGET_FUNC_INTRA:TARGET_FUNC_INTRA + len(PAYLOAD)] = PAYLOAD
    # 파일 끝을 page 정렬 → NEW_OFF 부터 modified 부착
    new_off = (len(data) + PAGE - 1) & ~(PAGE - 1)
    data += b'\x00' * (new_off - len(data))
    data += modified
    # PT_NOTE[8] → PT_LOAD R-X, offset=new_off, vaddr=0x401000, filesz=memsz=0x1000
    e_phoff, _ = harness.load_phdr_table(data)
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
    Path(out_path).write_bytes(patched)
    import os; os.chmod(out_path, 0o755)
    return new_off

# baseline 은 그냥 그대로 복사
import shutil
base_path = iter_dir / 'I4V0_baseline'
shutil.copy(TARGET, base_path); base_path.chmod(0o755)

variant_path = iter_dir / 'I4V1_prestaged_payload'
new_off = build_overlay_variant(variant_path)
print(f'  new_off (overlay file offset) = {new_off:#x}')

# harness 의 run_iteration 은 spec 기반이지만 여기서는 직접 실행
spec_list_dummy = []  # 빈 spec
obs = []
for name, path in [('I4V0_baseline', base_path), ('I4V1_prestaged_payload', variant_path)]:
    plain_log = iter_dir / f'{name}.plain.log'
    gdb_k     = iter_dir / f'{name}.gdb_kernel.log'
    gdb_m     = iter_dir / f'{name}.gdb_main.log'
    harness.run_plain(path, plain_log)
    harness.run_gdb(path, gdb_k, 'kernel')
    harness.run_gdb(path, gdb_m, 'main')
    k = harness.parse_maps(gdb_k); m = harness.parse_maps(gdb_m)
    record = {
        'name': name,
        'note': 'baseline' if 'V0' in name else f'overlay@{new_off:#x}',
        'plain_exit': harness.exit_code(plain_log),
        'kernel_perm': {f'{a:#x}': harness.perm_at(k, a) for a in [0x401000, 0x402000, 0x403000]},
        'main_perm':   {f'{a:#x}': harness.perm_at(m, a) for a in [0x401000, 0x402000, 0x403000]},
        'stdout': plain_log.read_text()[:400],
    }
    obs.append(record)

base_out  = obs[0]['stdout']; ov_out = obs[1]['stdout']
findings, backlog = [], []
base_ret_1   = 'result = 1' in base_out
ov_ret_42    = 'result = 42' in ov_out
if base_ret_1 and ov_ret_42:
    findings.append('F12: 동일 소스 빌드 + PHT 1 줄 패치 + 파일 끝에 0x1000 바이트 부착으로 target_func 결과가 1→42 로 분기. '
                    'runtime memcpy 없음 → strace 에 의심 syscall 흔적 안 남음. 정적 분석은 PT_LOAD[3] R-X 만 보면 return 1 그대로.')
    backlog.append({'id':'B11','title':'F12 변형의 readelf/objdump/Ghidra 탐지 매트릭스 작성 — 어느 도구가 PT_NOTE→PT_LOAD overlay 를 잡는가'})
    backlog.append({'id':'B12','title':'페이로드가 .data 또는 .rodata 안에 살아 있는 경우 — file append 없이도 PoC 가능한지'})
elif not base_ret_1:
    findings.append(f'F12alt: baseline 출력 비정상 → {base_out[:200]}')
elif not ov_ret_42:
    findings.append(f'F12alt: 오버레이 변형 결과 42 안 나옴 → {ov_out[:200]}')
    backlog.append({'id':'B11r','title':'overlay 가 매핑되는지 gdb_main 0x401136 의 디스어셈블로 직접 확인'})

verdict = ' | '.join(f'{r["name"]}:exit={r["plain_exit"]} k={r["kernel_perm"]["0x401000"]} m={r["main_perm"]["0x401000"]}' for r in obs)
harness.commit_iteration(N, TITLE, '미리 박힌 페이로드로 정적/동적 분기를 SMC 없이 만든다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)
print('iter04 complete')
for r in obs:
    print(r['name'], 'exit=', r['plain_exit'])
    print('  stdout:', r['stdout'].replace('\n',' | ')[:250])
