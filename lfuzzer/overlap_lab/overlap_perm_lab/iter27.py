"""
iter27 — B39 detector v4 + B37 PT_TLS 실용 PoC.

Part 1 (B39): detector v4 추가 시그널 — phdr 변환 시 원본 마커가 readelf -l 에서 사라짐.
- baseline 에 있던 PT_NOTE/PT_GNU_EH_FRAME/PT_GNU_PROPERTY/PT_TLS/PT_GNU_STACK 중 하나가 사라지면 의심.
- 단 binary 가 원래 그 마커를 안 가질 수도 있어서 "보통 같이 있는 PT_GNU_STACK 이 사라짐" 같은 패턴 기반.
- 휴리스틱: PT_GNU_STACK 없는 동적 링크 -no-pie binary 는 매우 드묾 → 부재 시 의심.

Part 2 (B37): target_tls_auth 의 PT_TLS 변형으로 safety_locked 우회.
- baseline: "ACCESS DENIED (safety_locked=1)" exit=0
- 변형 PT_TLS → PT_LOAD: "ACCESS GRANTED (safety_locked=0) -- DEBUG BYPASS" exit=1
- 8 바이트 (?) PHT 패치만으로 인증 우회.
"""
import harness, subprocess, shutil
from pathlib import Path
from elftools.elf.elffile import ELFFile

N = 27
TITLE = 'B39 detector v4 + B37 PT_TLS auth bypass PoC'

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

# ==================== Part 2 (B37) — PT_TLS auth bypass ====================
print('=== Part 2: PT_TLS auth bypass PoC ===')

# 먼저 target_tls_auth 의 PT_TLS idx 찾기
with open(harness.ROOT / 'target_tls_auth', 'rb') as f:
    e = ELFFile(f)
    tls_idx = None; text_size = None
    for i, s in enumerate(e.iter_segments()):
        if s['p_type'] == 'PT_TLS': tls_idx = i
        if s['p_type'] == 'PT_LOAD' and s['p_flags'] == 5: text_size = s['p_filesz']
print(f'  target_tls_auth: TLS idx={tls_idx}, text size={text_size:#x}')

# baseline
base_path = iter_dir / 'I27V0_baseline_tls_auth'
shutil.copy(harness.ROOT / 'target_tls_auth', base_path); base_path.chmod(0o755)
harness.run_plain(base_path, iter_dir / 'I27V0_baseline_tls_auth.plain.log')

# PT_TLS → PT_LOAD RWX (다른 필드도 같이 패치)
combo_path = iter_dir / 'I27V1_tls_to_load_auth_bypass'
patches = [
    {'phdr_idx': tls_idx, 'field': 'type',   'value': 1},
    {'phdr_idx': tls_idx, 'field': 'flags',  'value': 0x7},
    {'phdr_idx': tls_idx, 'field': 'offset', 'value': 0x1000},
    {'phdr_idx': tls_idx, 'field': 'vaddr',  'value': 0x401000},
    {'phdr_idx': tls_idx, 'field': 'paddr',  'value': 0x401000},
    {'phdr_idx': tls_idx, 'field': 'filesz', 'value': text_size},
    {'phdr_idx': tls_idx, 'field': 'memsz',  'value': text_size},
    {'phdr_idx': tls_idx, 'field': 'align',  'value': 0x1000},
]
data = (harness.ROOT / 'target_tls_auth').read_bytes()
patched = harness.apply_patches(data, patches)
combo_path.write_bytes(patched); combo_path.chmod(0o755)
harness.run_plain(combo_path, iter_dir / 'I27V1_tls_to_load_auth_bypass.plain.log')

# 3회 반복
def run3(path, log_prefix):
    outs = []
    for trial in range(3):
        plain_log = iter_dir / f'{log_prefix}.plain.run{trial+1}.log'
        harness.run_plain(path, plain_log)
        outs.append(plain_log.read_text())
    return outs

base_outs = run3(base_path, 'I27V0_baseline_tls_auth')
combo_outs = run3(combo_path, 'I27V1_tls_to_load_auth_bypass')

def extract_access(stdout):
    for L in stdout.splitlines():
        if 'ACCESS' in L: return L.strip()
    return '(no ACCESS line)'

base_msg = extract_access(base_outs[0])
combo_msg = extract_access(combo_outs[0])
print(f'  baseline: "{base_msg}"')
print(f'  variant : "{combo_msg}"')

# 일관성
base_consistent = len(set(extract_access(o) for o in base_outs)) == 1
combo_consistent = len(set(extract_access(o) for o in combo_outs)) == 1

# ==================== Part 1 (B39) — detector v4 ====================
print('\n=== Part 1: detector v4 (원본 phdr 마커 부재 시그널) ===')

DETECTOR_V4 = r'''#!/usr/bin/env python3
"""detect_overlap.py v4 — ELF PHT 이상 탐지 (v3 + 원본 마커 휴리스틱).

검사 1 (v1): PT_LOAD 페이지 정렬 vaddr 오버랩.
검사 2 (v2): PT_GNU_RELRO 가 PT_LOAD subset 위반.
검사 3 (v3): PT_GNU_RELRO ALIGN_DOWN(end) <= ALIGN_DOWN(start) → noop mprotect.
검사 4 (v3): PT_GNU_RELRO end 와 host PT_LOAD end 의 page-align mismatch.
검사 5 (v4): PT_GNU_STACK 부재 (-no-pie 동적 링크 binary 에서는 매우 드묾).
"""
import sys, struct

PHDR_SIZE = 56
PAGE = 0x1000
PT_LOAD       = 1
PT_DYNAMIC    = 2
PT_GNU_RELRO  = 0x6474e552
PT_GNU_STACK  = 0x6474e551

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
        if not in_load: flagged.append(r)
    return flagged

def relro_noop(phs):
    flagged = []
    for r in [p for p in phs if p['type'] == PT_GNU_RELRO]:
        start = r['vaddr']; end = r['vaddr'] + r['memsz']
        align_start = start & ~(PAGE-1); align_end = end & ~(PAGE-1)
        if align_end <= align_start: flagged.append(r)
    return flagged

def relro_end_mismatch(phs):
    flagged = []
    loads = [p for p in phs if p['type'] == PT_LOAD]
    for r in [p for p in phs if p['type'] == PT_GNU_RELRO]:
        re_ = r['vaddr'] + r['memsz']; rs = r['vaddr']
        host = next((L for L in loads if L['vaddr'] <= rs and rs < L['vaddr']+L['memsz']), None)
        if host is None: continue
        host_end = host['vaddr'] + host['memsz']
        re_on_page = (re_ & (PAGE-1)) == 0
        re_eq_host_end = re_ == host_end
        if not (re_on_page or re_eq_host_end): flagged.append((r, host))
    return flagged

def gnu_stack_missing(phs):
    """PT_GNU_STACK 부재 — 정상 binary 에는 보통 있음."""
    has = any(p['type'] == PT_GNU_STACK for p in phs)
    return not has

def analyze(path):
    data = open(path, 'rb').read()
    P = phdrs(data)
    ov = overlap_load(P)
    rs = relro_subset_fail(P)
    rn = relro_noop(P)
    rem = relro_end_mismatch(P)
    sm = gnu_stack_missing(P)
    anomaly = bool(ov or rs or rn or rem or sm)
    return {
        'path': path,
        'pt_load_count': sum(1 for p in P if p['type'] == PT_LOAD),
        'overlap_count': len(ov),
        'overlap_pairs': [(a['idx'], b['idx']) for a, b in ov],
        'relro_subset_fail': len(rs),
        'relro_noop': len(rn),
        'relro_end_mismatch': len(rem),
        'gnu_stack_missing': sm,
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
                  f'rs={r["relro_subset_fail"]} rn={r["relro_noop"]} rem={r["relro_end_mismatch"]} sm={r["gnu_stack_missing"]}')
            if r['verdict'] != 'CLEAN': bad += 1
        except Exception as e:
            print(f'ERROR    {p}  {e}')
    sys.exit(1 if bad else 0)
'''
(harness.ROOT / 'detect_overlap.py').write_text(DETECTOR_V4)
(harness.ROOT / 'detect_overlap.py').chmod(0o755)

import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

# v4 검증: iter21~25 의 RWX 변형들 + 정상 prod 표본
test_targets = []
for it_var in [('iter01','I1V1_overlay_rwx'),
               ('iter21','I21V1_ehframe_overlay_rwx'),
               ('iter22','I22V1_property_overlay_rwx'),
               ('iter23','I23V1_tls_overlay_rwx'),
               ('iter24','I24V1_stack_overlay_rwx')]:
    p = harness.OUT_ROOT / it_var[0] / it_var[1]
    if p.exists(): test_targets.append((it_var[1], p))

# 본 PoC 도
test_targets.append(('I27V1_tls_to_load_auth_bypass', combo_path))
test_targets.append(('I27V0_baseline_tls_auth', base_path))

# baseline 추가
for b in ['target_full','target_partial','target_tls','target_tls_auth']:
    p = harness.ROOT / b
    if p.exists(): test_targets.append((b, p))

results = {}
for name, p in test_targets:
    r = detect_overlap.analyze(str(p))
    results[name] = r

# 정상 prod 바이너리 FP 측정
prod_results = []
for p in Path('/usr/bin').iterdir():
    if p.is_file() and not p.is_symlink():
        try:
            if p.read_bytes()[:4] == b'\x7fELF':
                prod_results.append(detect_overlap.analyze(str(p)))
        except: pass
    if len(prod_results) >= 300: break
fp_v4 = sum(1 for r in prod_results if r['verdict'] != 'CLEAN')
fp_v4_sm = sum(1 for r in prod_results if r['gnu_stack_missing'])

# 출력
print('\n  detector v4 verdicts:')
for name, r in results.items():
    print(f'    {r["verdict"]:8s} {name:45s} sm={r["gnu_stack_missing"]} '
          f'overlap={r["overlap_count"]} rn={r["relro_noop"]}')

print(f'\n  prod {len(prod_results)} samples: anomaly={fp_v4} ({fp_v4/max(1,len(prod_results))*100:.2f}%)')
print(f'    그 중 gnu_stack_missing={fp_v4_sm} (정상에서도 누락된 binary 가 일부 있을 수 있음 — sm 휴리스틱 FP 측정)')

findings = []
backlog = []

# F-findings
if 'GRANTED' in combo_msg and 'DENIED' in base_msg:
    findings.append(f'F68: PT_TLS silent corruption 의 실용 PoC 완성. '
                    f'baseline: "{base_msg}" / variant: "{combo_msg}". '
                    f'8 필드 PHT 패치만으로 __thread 인증 플래그(safety_locked=1) 를 0 으로 zero-init 시켜 인증 우회. '
                    f'F64 의 보안 의미 실증.')

findings.append(f'F69: detector v4 의 gnu_stack_missing 휴리스틱 — prod 표본 {len(prod_results)} 개 중 {fp_v4_sm} 개에서 PT_GNU_STACK 부재 ({fp_v4_sm/max(1,len(prod_results))*100:.2f}%). '
                f'{"매우 낮음 — 1차 방어선으로 적합" if fp_v4_sm < 5 else "FP rate 높음 — 다른 휴리스틱과 결합 필요"}.')

if base_consistent and combo_consistent:
    findings.append(f'F70: target_tls_auth baseline/variant 모두 3회 반복 일관 (DENIED ↔ GRANTED 안정).')

# detector v4 가 PT_GNU_STACK 변형(iter24) 을 추가 시그널로 잡는지 확인
i24_v = results.get('I24V1_stack_overlay_rwx', {})
if i24_v:
    findings.append(f'F71: PT_GNU_STACK → PT_LOAD 변형(iter24 V1) 의 detector v4 verdict={i24_v["verdict"]}, '
                    f'gnu_stack_missing={i24_v["gnu_stack_missing"]}. '
                    f'이 변형은 PT_GNU_STACK 슬롯을 PT_LOAD 로 바꿔서 PT_GNU_STACK 부재 시그널도 추가로 잡힘.')

backlog.append({'id':'B40','title':'detector v4 의 sm 시그널 prod 1000+ 표본 FP 정밀 측정 — '
                'statically linked binary, golang binary 등은 PT_GNU_STACK 없을 수 있음'})
backlog.append({'id':'B41','title':'F68 PoC 의 응용 — sudo / passwd 같은 setuid 바이너리 컨텍스트에서 __thread 인증 우회 가능성 (조건: TLS 사용 + 권한 결정)'})

obs = [{
    'name': 'iter27',
    'plain_exit': None,
    'kernel_perm': {'tls_baseline': base_msg, 'tls_variant': combo_msg},
    'main_perm':   {'detector_v4_fp_prod': f'{fp_v4}/{len(prod_results)}', 'sm_fp': fp_v4_sm},
    'note': 'B37 PoC + B39 detector v4',
}]

verdict = (f'baseline "{base_msg}" → variant "{combo_msg}" | '
           f'detector v4 prod FP={fp_v4}/{len(prod_results)} ({fp_v4/max(1,len(prod_results))*100:.2f}%) sm_fp={fp_v4_sm}')

harness.commit_iteration(N, TITLE, 'PT_TLS auth 우회 PoC + detector v4', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print(f'\niter27 complete')
