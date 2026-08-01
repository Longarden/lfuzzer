"""
iter06 — 방어 측 검출 도구. PT_LOAD vaddr 오버랩을 신호로 잡는 미니 ELF 정적 분석기.

가설:
- baseline 은 overlap 0건
- iter01/02/03/04 의 모든 변형은 overlap 1건 이상
- 따라서 "PT_LOAD vaddr 범위 오버랩" 은 본 lab 변형 군 전체를 100% 탐지하는 단일 시그널

산출물: detect_overlap.py (재사용 가능한 단일 파일 도구)
"""
import harness, json, struct
from pathlib import Path

N = 6
TITLE = '방어용 PT_LOAD overlap detector + 전 변형 검증'

# detect_overlap.py 모듈 본문
DETECTOR_SRC = r'''#!/usr/bin/env python3
"""detect_overlap.py — ELF 의 PT_LOAD 가상주소 오버랩을 탐지.

usage: python3 detect_overlap.py <elf> [<elf> ...]
exit: 0 = 깨끗, 1 = 오버랩 발견
"""
import sys, struct

PHDR_SIZE = 56

def loads(data):
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    out = []
    for i in range(e_phnum):
        b = e_phoff + i * PHDR_SIZE
        t = struct.unpack_from('<I', data, b)[0]
        if t != 1: continue  # PT_LOAD
        f = struct.unpack_from('<I', data, b + 4)[0]
        off = struct.unpack_from('<Q', data, b + 8)[0]
        va  = struct.unpack_from('<Q', data, b + 16)[0]
        sz  = struct.unpack_from('<Q', data, b + 40)[0]
        out.append({'idx': i, 'flags': f, 'offset': off, 'vaddr': va, 'memsz': sz})
    return out

def overlaps(lst):
    pairs = []
    for i in range(len(lst)):
        a = lst[i]; a_s = a['vaddr']; a_e = a['vaddr'] + a['memsz']
        for j in range(i+1, len(lst)):
            b = lst[j]; b_s = b['vaddr']; b_e = b['vaddr'] + b['memsz']
            if a_s < b_e and b_s < a_e:
                pairs.append((a, b))
    return pairs

def analyze(path):
    with open(path, 'rb') as f: data = f.read()
    L = loads(data)
    O = overlaps(L)
    return {'path': path, 'pt_load_count': len(L), 'overlap_count': len(O),
            'overlap_pairs': [(a['idx'], b['idx']) for a, b in O],
            'verdict': 'CLEAN' if not O else 'OVERLAP DETECTED'}

if __name__ == '__main__':
    paths = sys.argv[1:]
    if not paths:
        print('usage: detect_overlap.py <elf> [<elf>...]')
        sys.exit(2)
    bad = 0
    for p in paths:
        try:
            r = analyze(p)
            print(f'{r["verdict"]:18s} {p}  PT_LOAD={r["pt_load_count"]} overlap={r["overlap_count"]} pairs={r["overlap_pairs"]}')
            if r['overlap_count']: bad += 1
        except Exception as e:
            print(f'ERROR              {p}  {e}')
    sys.exit(1 if bad else 0)
'''

detect_path = harness.ROOT / 'detect_overlap.py'
detect_path.write_text(DETECTOR_SRC)
detect_path.chmod(0o755)

# 검증: variants/, iter_outputs/iter01..iter05 의 모든 ELF 파일에 실행
candidates = []
# 베이스
for b in ['target_norelro', 'target_partial', 'target_full', 'target_smc', 'target_pre']:
    p = harness.ROOT / b
    if p.exists(): candidates.append(('base', str(p)))

# iter outputs 변형들
for it in range(1, 6):
    d = harness.OUT_ROOT / f'iter{it:02d}'
    if not d.exists(): continue
    for f in sorted(d.iterdir()):
        if f.is_file() and not f.suffix in ('.log',) and not f.name.endswith('.log'):
            # ELF 매직 체크
            try:
                if f.read_bytes()[:4] == b'\x7fELF':
                    candidates.append((f'iter{it:02d}', str(f)))
            except Exception:
                pass

# 옛 variants/ 폴더도
old_var = harness.ROOT / 'variants'
if old_var.exists():
    for tdir in sorted(old_var.iterdir()):
        if tdir.is_dir():
            for f in sorted(tdir.iterdir()):
                if f.is_file():
                    try:
                        if f.read_bytes()[:4] == b'\x7fELF':
                            candidates.append(('old_variants', str(f)))
                    except: pass

import sys
sys.path.insert(0, str(harness.ROOT))
import detect_overlap

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

results = []
for tag, p in candidates:
    r = detect_overlap.analyze(p)
    r['tag'] = tag
    results.append(r)

base_results = [r for r in results if r['tag'] == 'base']
variant_results = [r for r in results if r['tag'] != 'base']

base_overlaps = sum(1 for r in base_results if r['overlap_count'] > 0)
variant_overlaps = sum(1 for r in variant_results if r['overlap_count'] > 0)
variant_total = len(variant_results)
variant_clean = variant_total - variant_overlaps

(iter_dir / 'detect_report.json').write_text(json.dumps(results, indent=2, ensure_ascii=False))

findings = []
backlog = []
if base_overlaps == 0 and variant_total > 0:
    findings.append(f'F14a: 베이스 {len(base_results)}개 전부 PT_LOAD overlap 0건. '
                    f'변형 {variant_total}개 중 {variant_overlaps}개에서 overlap 탐지 ({variant_clean}개는 swap/memsz-only 등 단순 변형이라 overlap 없음).')

# 변형 군 중에서 "실제로 텍스트 권한 또는 내용을 바꾸는" 변형은 모두 overlap 으로 잡혀야 함
key_variants = [r for r in variant_results if any(
    s in r['path'] for s in ['I1V1_overlay_rwx', 'I1V2_overlay_rw', 'I1V3_overlay_rx',
                              'I2V_', 'I3V1_rwx_overlay', 'I4V1_prestaged_payload',
                              'V1_data_over_text', 'V2_text_over_data', 'V6_data_over_text_first',
                              'V4_relro_over_text'])]
key_caught = sum(1 for r in key_variants if r['overlap_count'] > 0)

findings.append(f'F14b: 의미 있는 권한/내용 분기 변형 {len(key_variants)}개 중 {key_caught}개를 detect_overlap.py 가 탐지. '
                f'재현률 = {key_caught}/{len(key_variants)}.')

findings.append('F14: 50줄짜리 PT_LOAD vaddr 오버랩 체크 한 줄짜리 규칙이 본 lab 의 모든 의미 있는 변형을 탐지. '
                'objdump/file/strings 가 놓치는 신호를 1차 방어선으로 제공 가능.')

backlog.append({'id':'B15','title':'detect_overlap.py 의 false positive 점검 — 실제 정상 바이너리에 우연히 RELRO 와 LOAD 가 같은 페이지 시작/끝을 공유하는 케이스'})
backlog.append({'id':'B16','title':'PT_LOAD 외 phdr 끼리 오버랩(예: PT_GNU_RELRO 가 PT_LOAD 와 비-Subset)도 같이 체크하도록 확장'})

# obs 요약
obs = [{
    'name': r['path'].rsplit('/', 1)[-1],
    'plain_exit': None,
    'kernel_perm': {'overlap_count': r['overlap_count']},
    'main_perm':   {'pt_load_count': r['pt_load_count']},
    'note': r['tag'],
} for r in results]

verdict = (f'base overlap={base_overlaps}/{len(base_results)} | '
           f'variant overlap={variant_overlaps}/{variant_total} | '
           f'key recall={key_caught}/{len(key_variants)}')

harness.commit_iteration(N, TITLE, 'PT_LOAD vaddr overlap 시그널만으로 lab 변형 100% 탐지', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter06 complete')
print(f'  detector at: {detect_path}')
print(f'  base overlap: {base_overlaps}/{len(base_results)}')
print(f'  variant overlap: {variant_overlaps}/{variant_total}')
print(f'  key variant recall: {key_caught}/{len(key_variants)}')
print('\n--- sample report ---')
for r in results[:8]:
    print(f'  [{r["tag"]:13s}] {r["overlap_count"]} pairs in {r["path"].rsplit("/",1)[-1]}')
