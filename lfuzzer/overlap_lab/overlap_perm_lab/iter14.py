"""
iter14 — detector v3 (RELRO end 페이지 정렬 휴리스틱) + B26 결합 PoC.

iter13 F26: RELRO memsz 8B 줄이면 ALIGN_DOWN 효과로 mprotect 무력화 → .got 페이지 RW.
iter13 F29: detector v2 는 이 케이스를 CLEAN 으로 분류 (subset 검사만 함). Blind spot.

detector v3:
1. v2 의 PT_LOAD 페이지 정렬 오버랩 + RELRO subset 체크
2. + RELRO 가 자체적으로 ALIGN_DOWN 적용 후 길이가 0 이 되는 케이스 (= mprotect 가 noop)
3. + RELRO end 가 호스트 PT_LOAD end 와 페이지 정렬에서 안 맞는 케이스 (의심 휴리스틱)

결합 PoC (B26):
- target_full 에 RELRO 8B shrink + PT_NOTE → PT_LOAD RWX overlay 동시 적용
- 텍스트 RWX + .got RW. 동적 링커가 GOT 오염 + 코드 변조 둘 다 가능한 상태.
"""
import harness
from pathlib import Path

N = 14
TITLE = 'detector v3 (RELRO noop 검출) + RELRO 무력화 + RWX overlay 결합 PoC'

# detector v3 본문 — v2 위에 추가 휴리스틱
DETECTOR_V3 = r'''#!/usr/bin/env python3
"""detect_overlap.py v3 — ELF PT_LOAD/PT_GNU_RELRO 이상 탐지.

검사 1 (v1): PT_LOAD 페이지 정렬 vaddr 오버랩.
검사 2 (v2): PT_GNU_RELRO 가 PT_LOAD 의 subset 이 아닌 경우.
검사 3 (v3): PT_GNU_RELRO 의 ALIGN_DOWN(end) <= ALIGN_DOWN(start) 인 noop mprotect 케이스.
검사 4 (v3): PT_GNU_RELRO end 가 host PT_LOAD end 와 page-align 에서 어긋난 경우.

usage: detect_overlap.py <elf>...
exit: 0 = CLEAN, 1 = anomaly
"""
import sys, struct

PHDR_SIZE = 56
PAGE = 0x1000
PT_LOAD      = 1
PT_GNU_RELRO = 0x6474e552

def phdrs(data):
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    out = []
    for i in range(e_phnum):
        b = e_phoff + i * PHDR_SIZE
        out.append({
            'idx': i,
            'type':   struct.unpack_from('<I', data, b)[0],
            'flags':  struct.unpack_from('<I', data, b+4)[0],
            'offset': struct.unpack_from('<Q', data, b+8)[0],
            'vaddr':  struct.unpack_from('<Q', data, b+16)[0],
            'memsz':  struct.unpack_from('<Q', data, b+40)[0],
        })
    return out

def page_range(p):
    s = p['vaddr'] & ~(PAGE-1)
    e = (p['vaddr'] + p['memsz'] + PAGE-1) & ~(PAGE-1)
    return s, e

def overlap_load(phs):
    loads = [p for p in phs if p['type'] == PT_LOAD]
    out = []
    for i in range(len(loads)):
        a_s, a_e = page_range(loads[i])
        for j in range(i+1, len(loads)):
            b_s, b_e = page_range(loads[j])
            if a_s < b_e and b_s < a_e:
                out.append((loads[i], loads[j]))
    return out

def relro_subset_fail(phs):
    rel = [p for p in phs if p['type'] == PT_GNU_RELRO]
    loads = [p for p in phs if p['type'] == PT_LOAD]
    flagged = []
    for r in rel:
        rs = r['vaddr']; re_ = r['vaddr'] + r['memsz']
        in_load = any(L['vaddr'] <= rs and re_ <= L['vaddr']+L['memsz'] for L in loads)
        if not in_load:
            flagged.append(r)
    return flagged

def relro_noop(phs):
    """mprotect 가 ALIGN_DOWN(start)..ALIGN_DOWN(end) 이라서 길이 <= 0 인 케이스."""
    flagged = []
    for r in [p for p in phs if p['type'] == PT_GNU_RELRO]:
        start = r['vaddr']; end = r['vaddr'] + r['memsz']
        align_start = start & ~(PAGE-1)
        align_end   = end & ~(PAGE-1)
        if align_end <= align_start:
            flagged.append(r)
    return flagged

def relro_end_mismatch(phs):
    """RELRO end 가 host PT_LOAD end 의 page 정렬과 안 맞으면 의심.
    (정상 빌드 산출물은 RELRO end == host PT_LOAD end (페이지 정렬) 거나 RELRO end 가 page 경계.)"""
    flagged = []
    loads = [p for p in phs if p['type'] == PT_LOAD]
    for r in [p for p in phs if p['type'] == PT_GNU_RELRO]:
        re_ = r['vaddr'] + r['memsz']
        align_re = re_ & ~(PAGE-1)
        rs = r['vaddr']
        host = next((L for L in loads if L['vaddr'] <= rs and rs < L['vaddr']+L['memsz']), None)
        if host is None:
            continue
        host_end = host['vaddr'] + host['memsz']
        # 정상: RELRO end 가 page 경계에 있거나, host PT_LOAD end 와 일치
        re_on_page = (re_ & (PAGE-1)) == 0
        re_eq_host_end = re_ == host_end
        if not (re_on_page or re_eq_host_end):
            flagged.append((r, host))
    return flagged

def analyze(path):
    data = open(path, 'rb').read()
    P = phdrs(data)
    ov  = overlap_load(P)
    rs  = relro_subset_fail(P)
    rn  = relro_noop(P)
    rem = relro_end_mismatch(P)
    anomaly = bool(ov or rs or rn or rem)
    return {
        'path': path,
        'pt_load_count': sum(1 for p in P if p['type'] == PT_LOAD),
        'overlap_count': len(ov),
        'overlap_pairs': [(a['idx'], b['idx']) for a, b in ov],
        'relro_subset_fail': len(rs),
        'relro_noop': len(rn),
        'relro_end_mismatch': len(rem),
        'verdict': 'ANOMALY' if anomaly else 'CLEAN',
    }

if __name__ == '__main__':
    paths = sys.argv[1:]
    if not paths:
        print('usage: detect_overlap.py <elf>...'); sys.exit(2)
    bad = 0
    for p in paths:
        try:
            r = analyze(p)
            print(f'{r["verdict"]:8s} {p}  PT_LOAD={r["pt_load_count"]} ov={r["overlap_count"]} '
                  f'rs={r["relro_subset_fail"]} rn={r["relro_noop"]} rem={r["relro_end_mismatch"]}')
            if r['verdict'] != 'CLEAN': bad += 1
        except Exception as e:
            print(f'ERROR    {p}  {e}')
    sys.exit(1 if bad else 0)
'''

(harness.ROOT / 'detect_overlap.py').write_text(DETECTOR_V3)
(harness.ROOT / 'detect_overlap.py').chmod(0o755)

import importlib, sys
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules:
    importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

# iter13 의 RELRO 변형들 + iter01/04/10 의 overlay 변형들 + 새 결합 PoC 에 대해 v3 검증
test_targets = []

# iter13 RELRO 변형
for v in ['I13V0_base','I13V1_relro_shrink_8','I13V2_relro_extend_page','I13V3_relro_shrink_half']:
    p = harness.OUT_ROOT / 'iter13' / v
    if p.exists(): test_targets.append(('iter13_'+v, p))

# iter01 RWX overlay
for v in ['I1V1_overlay_rwx','I1V3_overlay_rx']:
    p = harness.OUT_ROOT / 'iter01' / v
    if p.exists(): test_targets.append(('iter01_'+v, p))

# iter10 in-file
for v in ['I10V0_baseline','I10V2_payload_with_textcopy']:
    p = harness.OUT_ROOT / 'iter10' / v
    if p.exists(): test_targets.append(('iter10_'+v, p))

# base
for b in ['target_full','target_partial','target_norelro','target_in']:
    p = harness.ROOT / b
    if p.exists(): test_targets.append(('base_'+b, p))

# 새 결합 PoC 생성: target_full 에 RELRO shrink + RWX overlay
iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

combo_path = iter_dir / 'I14V1_relro_shrink_plus_rwx_overlay'
patches = [
    {'phdr_idx': 12, 'field': 'memsz',  'value': 0x258},   # RELRO shrink
    {'phdr_idx': 12, 'field': 'filesz', 'value': 0x258},
    # PT_NOTE[8] → PT_LOAD RWX over text
    {'phdr_idx': 8, 'field': 'type',   'value': 1},
    {'phdr_idx': 8, 'field': 'flags',  'value': 0x7},
    {'phdr_idx': 8, 'field': 'offset', 'value': 0x1000},
    {'phdr_idx': 8, 'field': 'vaddr',  'value': 0x401000},
    {'phdr_idx': 8, 'field': 'paddr',  'value': 0x401000},
    {'phdr_idx': 8, 'field': 'filesz', 'value': 0x331},
    {'phdr_idx': 8, 'field': 'memsz',  'value': 0x331},
    {'phdr_idx': 8, 'field': 'align',  'value': 0x1000},
]
data = (harness.ROOT / 'target_full').read_bytes()
patched = harness.apply_patches(data, patches)
combo_path.write_bytes(patched); combo_path.chmod(0o755)

# 실행
harness.run_plain(combo_path, iter_dir / f'I14V1_relro_shrink_plus_rwx_overlay.plain.log')
harness.run_gdb(combo_path, iter_dir / f'I14V1_relro_shrink_plus_rwx_overlay.gdb_main.log', 'main')
m_maps = harness.parse_maps(iter_dir / f'I14V1_relro_shrink_plus_rwx_overlay.gdb_main.log')
combo_text_perm = harness.perm_at(m_maps, 0x401000)
combo_got_perm  = harness.perm_at(m_maps, 0x403000)
combo_exit = harness.exit_code(iter_dir / f'I14V1_relro_shrink_plus_rwx_overlay.plain.log')

test_targets.append(('iter14_combo', combo_path))

# detector v3 실행
results = {}
for tag, path in test_targets:
    r = detect_overlap.analyze(str(path))
    results[tag] = r

# 정상 prod 바이너리에서 FP 재측정 (v3 가 새 휴리스틱 추가했으니 FP rate 다시)
prod_samples = []
for p in Path('/usr/bin').glob('*'):
    if p.is_file() and not p.is_symlink():
        try:
            if p.read_bytes()[:4] == b'\x7fELF':
                prod_samples.append(p)
        except: pass
    if len(prod_samples) >= 200: break

prod_results = []
for p in prod_samples:
    try:
        prod_results.append(detect_overlap.analyze(str(p)))
    except: pass

fp = sum(1 for r in prod_results if r['verdict'] != 'CLEAN')

findings = []
backlog = []

# RELRO 변형 잡는지
v1_caught = results['iter13_I13V1_relro_shrink_8']['verdict'] == 'ANOMALY'
v3_caught = results['iter13_I13V3_relro_shrink_half']['verdict'] == 'ANOMALY'
v0_clean  = results['iter13_I13V0_base']['verdict'] == 'CLEAN'

if v1_caught and v3_caught and v0_clean:
    findings.append('F31: detector v3 가 RELRO shrink 변형(V1, V3) 을 ANOMALY 로 잡음. v2 의 blind spot 해소.')
else:
    findings.append(f'F31alt: v3 결과 — V0 clean={v0_clean}, V1 caught={v1_caught}, V3 caught={v3_caught}. 휴리스틱 조정 필요.')

# 결합 PoC: 텍스트 RWX + .got RW 동시?
findings.append(f'F32: 결합 PoC (RELRO shrink + RWX overlay) 결과 — plain={combo_exit} text@0x401000={combo_text_perm} got@0x403000={combo_got_perm} detector={results["iter14_combo"]["verdict"]}.')
if combo_text_perm == 'rwxp' and combo_got_perm == 'rw-p' and combo_exit == 0:
    findings.append('F33: 8B 변경(RELRO memsz) + 7개 PHT 필드 패치만으로 텍스트 RWX + GOT RW 가 동시 성립. 멀웨어 시나리오의 가장 강력한 형태.')

# FP 재측정
fp_rate = fp / max(1, len(prod_results)) * 100
findings.append(f'F34: detector v3 의 정상 prod 바이너리 {len(prod_results)} 표본 FP = {fp} ({fp_rate:.2f}%). '
                f'{"v2 와 동일하게 거의 0" if fp_rate < 1 else "v3 의 새 휴리스틱이 FP 도입 " + str(fp_rate)+"%"}.')

backlog.append({'id':'B28','title':'결합 PoC 의 실용 활용 — GOT 엔트리 하나 덮어쓰고 텍스트에 페이로드 박은 뒤 printf 호출로 임의 코드 실행 PoC'})
backlog.append({'id':'B29','title':'detect_overlap.py v3 를 더 큰 표본(/usr/lib 1000+)에 돌려서 FP 분포 정밀 측정'})

obs = [{
    'name': tag,
    'plain_exit': None,
    'kernel_perm': {'verdict': r['verdict']},
    'main_perm':   {'noop': r['relro_noop'], 'mismatch': r['relro_end_mismatch'], 'overlap': r['overlap_count']},
    'note': f'PT_LOAD={r["pt_load_count"]}',
} for tag, r in results.items()]

verdict = (f'v3 RELRO V1 caught={v1_caught} V3 caught={v3_caught} V0 clean={v0_clean} | '
           f'combo PoC exit={combo_exit} text={combo_text_perm} got={combo_got_perm} | '
           f'prod FP={fp}/{len(prod_results)} ({fp_rate:.2f}%)')

harness.commit_iteration(N, TITLE, 'detector v3 가 RELRO 페이지 정렬 무력화를 잡고, 결합 PoC 성립', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter14 complete')
print(f'  detector v3 RELRO shrink V1 caught: {v1_caught}')
print(f'  detector v3 RELRO shrink V3 caught: {v3_caught}')
print(f'  baseline V0 clean: {v0_clean}')
print(f'  combo PoC: exit={combo_exit} text=0x401000 {combo_text_perm} got=0x403000 {combo_got_perm}')
print(f'  prod FP: {fp}/{len(prod_results)} ({fp_rate:.2f}%)')
