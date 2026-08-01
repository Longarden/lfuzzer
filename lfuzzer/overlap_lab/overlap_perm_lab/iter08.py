"""
iter08 — B14: 기존 PT_LOAD 만 조작해서 phdr 카운트를 안 늘리는 스텔스 변형.

iter01~04 의 변형들은 PT_NOTE→PT_LOAD 로 만들어서 readelf -l 의 PT_LOAD 카운트가
4→5 로 증가했다 (F13a). 분석가가 "이상한 PT_LOAD 가 하나 더 있네" 만 봐도 잡힐 수 있는 단서.

여기선 PT_NOTE/PT_GNU_STACK 같은 슬롯을 건드리지 않고, **기존 PT_LOAD 의 필드만 수정**해서
텍스트 페이지에 오버랩을 만든다. 결과: PT_LOAD 카운트 유지(=4) → 도구 단서 한 단계 약화.

가설:
- I8V1 (rodata→text): PT_LOAD[4] (rodata R) 의 vaddr 만 0x402000 → 0x401000. PHT 순서상 text 보다 뒤 → R 권한이 text 위를 덮음.
  → text 페이지가 r--p, NX 로 SEGV. PT_LOAD count 동일.
- I8V2 (data→text): PT_LOAD[5] (data RW) 의 vaddr 만 0x403df8 → 0x401df8. text 페이지가 rw-p.
  → 단 PT_DYNAMIC vaddr 도 데이터 안에 있어서 정상 동작은 깨짐. plain 결과 SEGV 예상.
- I8V3 (rodata→text + offset 같이): I8V1 + p_offset 도 0x2000 → 0x1000 으로 동기화 → 같은 텍스트 바이트를 R 권한으로 매핑. 텍스트 페이지가 r--p 인데 바이트는 원본 텍스트 그대로 → NX 라서 SEGV.
"""
import harness
from pathlib import Path

N = 8
TITLE = 'B14: 기존 PT_LOAD vaddr 만 조작한 스텔스 변형 (PT_LOAD count 유지)'

# target_partial PT_LOAD indices: [2]=R metadata, [3]=R-X text, [4]=R rodata, [5]=RW data
spec_list = [
    {
        'name': 'I8V1_rodata_vaddr_to_text',
        'base': 'target_partial',
        'patches': [
            {'phdr_idx': 4, 'field': 'vaddr', 'value': 0x401000},
            {'phdr_idx': 4, 'field': 'paddr', 'value': 0x401000},
        ],
        'note': 'rodata PT_LOAD vaddr → 0x401000 (offset 0x2000 유지)',
    },
    {
        'name': 'I8V2_data_vaddr_to_text',
        'base': 'target_partial',
        'patches': [
            {'phdr_idx': 5, 'field': 'vaddr', 'value': 0x401df0},
            {'phdr_idx': 5, 'field': 'paddr', 'value': 0x401df0},
        ],
        'note': 'data PT_LOAD vaddr → 0x401df0 (page align 0x401000)',
    },
    {
        'name': 'I8V3_rodata_full_overlay_text',
        'base': 'target_partial',
        'patches': [
            {'phdr_idx': 4, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': 4, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': 4, 'field': 'offset', 'value': 0x1000},   # 같은 텍스트 바이트
        ],
        'note': 'rodata 슬롯을 텍스트 페이지 R 오버레이로 (같은 바이트, R-only)',
    },
]

obs = harness.run_iteration(N, TITLE, spec_list)

# detector v2 결과
import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules:
    importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
det_results = {}
for spec in spec_list:
    path = iter_dir / spec['name']
    r = detect_overlap.analyze(str(path))
    det_results[spec['name']] = r
    print(f'  detector: {r["verdict"]:8s} {spec["name"]} PT_LOAD={r["pt_load_count"]} overlap={r["overlap_count"]} pairs={r["overlap_pairs"]}')

findings = []
backlog = []

# PT_LOAD count 유지 여부 (baseline 4)
counts = [r['pt_load_count'] for r in det_results.values()]
if all(c == 4 for c in counts):
    findings.append('F16: 기존 PT_LOAD 의 vaddr 만 수정한 변형은 PT_LOAD 카운트 4 유지. readelf -l 의 단순 카운트로는 baseline 과 구분 불가.')
else:
    findings.append(f'F16alt: PT_LOAD 카운트가 {counts} — 기대값 4 와 다름.')

# detector v2 가 잡는지
caught = sum(1 for r in det_results.values() if r['verdict'] == 'ANOMALY')
findings.append(f'F17: detector v2 가 본 변형 {caught}/{len(det_results)}개를 ANOMALY 로 잡음 (페이지 정렬 오버랩 체크 덕분). '
                f'단서 = PT_LOAD vaddr 페이지 범위 오버랩, PT_LOAD 카운트가 같아도 잡힘.')

# I8V1 결과 (rodata→text R 오버레이) — text 페이지 r--p 로 NX SEGV 예상
v1 = obs[0]
if v1['plain_exit'] == -11 and v1['main_perm'].get('0x401000', '') == 'r--p':
    findings.append('F18: rodata 슬롯의 vaddr 만 text 페이지로 옮기면 text 가 r--p 로 다운그레이드되어 NX 로 인해 SEGV. '
                    '정적 분석은 PT_LOAD[3] R-X 만 보면 정상으로 본다 — 정적/동적 분리 사례 추가 (rodata 변형판).')

# I8V3 결과 (같은 바이트, R-only) — main 도달 가능성?
v3 = obs[2]
if v3['plain_exit'] == 0 and v3['main_perm'].get('0x401000','') == 'r--p':
    findings.append('F19: rodata 슬롯이 텍스트와 동일 offset+R로 오버레이되면 text 가 r--p (NX) 인데도 main 도달... 가능성 낮음. 정밀 분석 필요.')
elif v3['plain_exit'] == -11 and v3['main_perm'].get('0x401000','') == 'r--p':
    findings.append('F19: 같은 바이트라도 R-only (NX) 오버레이는 실행 차단으로 SEGV. baseline R-X 와 분기.')

backlog.append({'id':'B17','title':'I8V1 류 변형이 컨테이너 탐지기(eBPF, AV) 에서 어떻게 분류되는지 — phdr 카운트로 거른 후 가상주소 오버랩 체크하는지'})
backlog.append({'id':'B18','title':'PT_LOAD count 유지 + text 페이지 RWX 까지 가는 변형 가능한가 — 기존 PT_LOAD 만으로는 RW + X 동시 부여 어려움 (rodata R, data RW, text R-X 만 있어서 RWX 슬롯 없음)'})

verdict = ' | '.join(
    f'{r["name"]}:plain={r["plain_exit"]} k={r["kernel_perm"]["0x401000"]} m={r["main_perm"]["0x401000"]} det={det_results[r["name"]]["verdict"]}'
    for r in obs
)

harness.commit_iteration(N, TITLE, '기존 PT_LOAD 만 조작해도 페이지 정렬 오버랩으로 detector 잡힘', obs, verdict,
                         new_findings=findings, new_backlog=backlog)
print('iter08 complete')
for r in obs:
    print(f'  {r["name"]}: plain={r["plain_exit"]} k={r["kernel_perm"]["0x401000"]} m={r["main_perm"]["0x401000"]}')
