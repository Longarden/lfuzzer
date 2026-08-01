"""
iter17 — B28: 진짜 GOT write + 텍스트 write 시연.

target_probe (full RELRO 빌드) baseline 대비 combo 변형(RELRO shrink 8B + RWX overlay) 에서
GOT 와 텍스트 쓰기 둘 다 통과하는 것을 출력으로 확인.

target_probe 정보:
- PT_LOAD[3] text: vaddr 0x401000, fsz 0x2a5
- PT_GNU_RELRO at idx 12: vaddr 0x403dc0, msz 0x240 (end=0x404000 page 정렬)
- PT_NOTE[8] 슬롯 재활용 가능
"""
import harness, shutil
from pathlib import Path

N = 17
TITLE = 'B28: GOT write + 텍스트 write live PoC (baseline SEGV vs combo 통과)'

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

TEXT_SIZE = 0x2a5

# baseline
base_path = iter_dir / 'I17V0_baseline'
shutil.copy(harness.ROOT / 'target_probe', base_path); base_path.chmod(0o755)

# combo 변형
combo_path = iter_dir / 'I17V1_combo_relro_shrink_plus_rwx_overlay'
patches = [
    # RELRO shrink: target_probe 의 RELRO 는 vaddr=0x403dd0, msz=0x240, end=0x404010.
    # mprotect 무력화를 위해 end < 0x404000 필요 → msz < 0x230. 안전하게 0x100.
    # ALIGN_DOWN(0x403dd0 + 0x100) = ALIGN_DOWN(0x403ed0) = 0x403000 == ALIGN_DOWN(start) → mprotect skip.
    {'phdr_idx': 12, 'field': 'memsz',  'value': 0x100},
    {'phdr_idx': 12, 'field': 'filesz', 'value': 0x100},
    # PT_NOTE[8] → PT_LOAD RWX over text page
    {'phdr_idx': 8, 'field': 'type',   'value': 1},
    {'phdr_idx': 8, 'field': 'flags',  'value': 0x7},
    {'phdr_idx': 8, 'field': 'offset', 'value': 0x1000},
    {'phdr_idx': 8, 'field': 'vaddr',  'value': 0x401000},
    {'phdr_idx': 8, 'field': 'paddr',  'value': 0x401000},
    {'phdr_idx': 8, 'field': 'filesz', 'value': TEXT_SIZE},
    {'phdr_idx': 8, 'field': 'memsz',  'value': TEXT_SIZE},
    {'phdr_idx': 8, 'field': 'align',  'value': 0x1000},
]
data = (harness.ROOT / 'target_probe').read_bytes()
patched = harness.apply_patches(data, patches)
combo_path.write_bytes(patched); combo_path.chmod(0o755)

# 실행
obs = []
for name, path in [('I17V0_baseline', base_path), ('I17V1_combo', combo_path)]:
    plain_log = iter_dir / f'{name}.plain.log'
    gdb_k     = iter_dir / f'{name}.gdb_kernel.log'
    gdb_m     = iter_dir / f'{name}.gdb_main.log'
    harness.run_plain(path, plain_log)
    harness.run_gdb(path, gdb_k, 'kernel')
    harness.run_gdb(path, gdb_m, 'main')
    k = harness.parse_maps(gdb_k); m = harness.parse_maps(gdb_m)
    obs.append({
        'name': name,
        'note': 'baseline (RELRO 적용)' if 'V0' in name else 'combo (RELRO 무력화 + RWX overlay)',
        'plain_exit': harness.exit_code(plain_log),
        'kernel_perm': {'0x401000': harness.perm_at(k, 0x401000), '0x403000': harness.perm_at(k, 0x403000)},
        'main_perm':   {'0x401000': harness.perm_at(m, 0x401000), '0x403000': harness.perm_at(m, 0x403000)},
        'stdout': plain_log.read_text()[:400],
    })

# detector v3
import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap
det_b = detect_overlap.analyze(str(base_path))
det_c = detect_overlap.analyze(str(combo_path))

findings = []
backlog = []

base_out = obs[0]['stdout']
combo_out = obs[1]['stdout']

base_got_write_succ = 'GOT write OK' in base_out
combo_got_write_succ = 'GOT write OK' in combo_out
combo_text_write_succ = 'text write OK' in combo_out
combo_both = 'BOTH writes succeeded' in combo_out

if not base_got_write_succ and combo_both:
    findings.append('F38: baseline 은 GOT 쓰기에서 SIGSEGV (full RELRO 가 .got RO). combo 변형은 GOT/텍스트 쓰기 모두 성공. '
                    'live PoC 로 F33(text RWX + GOT RW) 실증 완료.')
elif base_got_write_succ:
    findings.append(f'F38alt: baseline 도 GOT 쓰기 성공 — full RELRO 가 의도대로 안 걸린 듯. stdout={base_out[:200]}')
elif not combo_both:
    findings.append(f'F38alt: combo 변형 stdout = {combo_out[:200]}. 패치 의도와 불일치.')

if det_c['verdict'] == 'ANOMALY' and det_b['verdict'] == 'CLEAN':
    findings.append('F39: detector v3 가 baseline CLEAN, combo ANOMALY 로 정확히 분류. live PoC 도 자동 탐지.')

backlog.append({'id':'B30','title':'F38 의 GOT 쓰기 후 실제로 함수 포인터 하이재크 (printf 호출이 페이로드로 점프) — 한 단계 더'})
backlog.append({'id':'B31','title':'detector v3 의 휴리스틱 (RELRO end mismatch) 이 모든 표본에 robust 한지 — /usr/bin 전체 1000+ 표본으로 확장'})

verdict = (f'baseline:exit={obs[0]["plain_exit"]} got_write={"OK" if base_got_write_succ else "SEGV"} | '
           f'combo:exit={obs[1]["plain_exit"]} both={"YES" if combo_both else "NO"} | '
           f'detector base={det_b["verdict"]} combo={det_c["verdict"]}')

harness.commit_iteration(N, TITLE, '실제 GOT/텍스트 쓰기로 combo PoC 가 baseline 을 무력화한다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter17 complete')
print(f'  baseline stdout: {base_out.replace(chr(10)," | ")[:200]}')
print(f'  combo    stdout: {combo_out.replace(chr(10)," | ")[:200]}')
print(f'  detector: base={det_b["verdict"]} combo={det_c["verdict"]}')
