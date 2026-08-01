"""
iter11 — B23: 분석가가 첫 번째로 비교하는 도구들의 표면 차이 측정.

대상: target_in (baseline) vs iter10/I10V2_payload_with_textcopy (가장 스텔스한 변형)
도구: ls -l (size), sha256, file, strings, readelf -h, readelf -S

가설:
- size 동일 (이미 iter10 에서 확인)
- sha256 다름 — PHT 와 .payload 안 바이트가 달라졌으므로
- file 출력 동일 (ELF header 만 봄)
- strings 다름 — .payload 안에 텍스트 바이트 사본이 들어있음
- readelf -h 동일 (헤더만)
- readelf -S 동일 (섹션 헤더 변경 없음)
- readelf -l 다름 (PT_NOTE → PT_LOAD)
"""
import harness, subprocess, hashlib
from pathlib import Path

N = 11
TITLE = 'B23: baseline vs 스텔스 변형의 표면 차이 측정 (size/sha256/file/strings/readelf)'

BASE = harness.ROOT / 'target_in'
VAR  = harness.OUT_ROOT / 'iter10' / 'I10V2_payload_with_textcopy'

def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        return r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')
    except Exception as e:
        return f'ERROR: {e}'

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

def measure(path):
    p = Path(path)
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    return {
        'path': str(p),
        'size': p.stat().st_size,
        'sha256': sha,
        'file':       run(['file', str(p)]).strip(),
        'readelf_h':  run(['readelf', '-h', str(p)]),
        'readelf_S':  run(['readelf', '-S', str(p)]),
        'readelf_l':  run(['readelf', '-l', str(p)]),
        'strings':    run(['strings', '-n', '6', str(p)]),
        'objdump_t_d_short': run(['objdump', '-d', '-j', '.text', str(p)]),
    }

b = measure(BASE)
v = measure(VAR)

# 저장
for label, m in [('baseline', b), ('variant', v)]:
    for k, val in m.items():
        if k in ('path','size','sha256'): continue
        (iter_dir / f'{label}.{k}.log').write_text(val)

# 비교
def diff_lines(a, b):
    al = a.splitlines(); bl = b.splitlines()
    diff = []
    for i, (x, y) in enumerate(zip(al, bl)):
        if x != y: diff.append((i, x, y))
    if len(al) != len(bl):
        diff.append(('len', len(al), len(bl)))
    return diff

surface = {
    'size_same'        : b['size'] == v['size'],
    'sha256_same'      : b['sha256'] == v['sha256'],
    'file_same'        : b['file'] == v['file'],
    'readelf_h_same'   : b['readelf_h'] == v['readelf_h'],
    'readelf_S_same'   : b['readelf_S'] == v['readelf_S'],
    'readelf_l_same'   : b['readelf_l'] == v['readelf_l'],
    'strings_same'     : b['strings'] == v['strings'],
    'objdump_text_same': b['objdump_t_d_short'] == v['objdump_t_d_short'],
}

# 차이 디테일 (몇 줄)
diffs = {}
for k in ['readelf_l', 'strings', 'readelf_h', 'readelf_S', 'objdump_t_d_short']:
    d = diff_lines(b[k], v[k])
    diffs[k] = d[:5]

findings = []
backlog = []

# 정리
visible_changes = [k for k, same in surface.items() if not same]
findings.append(f'F23: 표면 차이 측정 결과 — same: {[k for k,s in surface.items() if s]}, different: {visible_changes}.')

if surface['size_same'] and not surface['sha256_same']:
    findings.append('F23a: size 동일하지만 sha256 다름 → 바이트 단위 비교 도구(diff/cmp)만 차이 잡음. 단순 size/일자만 보는 무결성 검사는 통과.')

if surface['file_same'] and surface['readelf_h_same']:
    findings.append('F23b: file 출력과 readelf -h 동일 → ELF 헤더 기반 도구는 baseline 와 구별 못함.')

if not surface['readelf_l_same']:
    findings.append('F23c: readelf -l 다름 (PT_NOTE → PT_LOAD 변경) → PHT 검사 도구는 잡음. F13a 와 일치.')

if surface['readelf_S_same']:
    findings.append('F23d: readelf -S (section header) 동일 → 섹션 헤더 기반 분석은 미탐. .payload 섹션이 baseline 에도 이미 있어서 차이 없음.')

if surface['objdump_text_same']:
    findings.append('F23e: objdump -d -j .text 동일 → .text 섹션 디스어셈블은 동일 출력. malware reverser 가 .text 만 보면 미탐.')

if not surface['strings_same']:
    findings.append('F23f: strings 다름 → .payload 안에 텍스트 사본 바이트가 들어가 strings 추출 결과 변함. 어떤 문자열이 .payload 안에 우연히 보일 수 있음.')

backlog.append({'id':'B24','title':'F23f 의 strings 차이 정밀 분석 — .payload 안 텍스트 사본이 어떤 의심 패턴 노출하는지'})
backlog.append({'id':'B25','title':'detector v2 + readelf -l overlap 검사 외에 다른 자동 시그널 후보 — 예: PT_LOAD 가 같은 페이지를 두 번 가리키는지, 또는 section-segment 불일치'})

obs = [{
    'name': 'surface_diff',
    'plain_exit': None,
    'kernel_perm': {'size': b['size'], 'sha256_same': surface['sha256_same']},
    'main_perm':   {f'{k}': v for k, v in surface.items()},
    'note': f'changes: {visible_changes}',
}]

verdict = f'same: {sum(1 for v in surface.values() if v)}/8 surfaces | different: {visible_changes}'

harness.commit_iteration(N, TITLE, '표면 차이가 readelf -l 와 strings/sha256 외에는 거의 안 보인다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter11 complete')
print('  surface comparison:')
for k, same in surface.items():
    print(f'    {k:25s}: {"same" if same else "DIFFERENT"}')
