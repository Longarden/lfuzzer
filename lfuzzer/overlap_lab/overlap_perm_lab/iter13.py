"""
iter13 — B3: RELRO 부분 누락 변형. 0508 미팅 1.5 보류 아이디어 검증.

PT_GNU_RELRO memsz/vaddr 를 미세 조정해서 ld.so 의 mprotect 호출이
- 적용 안 되거나 (shrink): GOT/init_array 가 런타임에 RW
- 너무 넓게 적용되거나 (extend): .data 까지 RO 로 잠김

glibc _dl_protect_relro 는 start/end 를 page ALIGN_DOWN 하므로 작은 변경이
페이지 경계에서 전부/전무로 갈 수 있음. 그 페이지 단위 경계 효과 측정.

대상: target_full (full RELRO). RELRO 0x403da0-0x404000 (msz=0x260), .got at 0x403fa8-0x404000.

가설:
- V1 (msz 0x260 → 0x258, 8B 줄임): end 0x404000 → 0x403ff8, page-down 0x404000 → 0x403000.
  mprotect 범위 0x403000-0x403000 = 0 bytes → RELRO 사실상 무력화. .got 페이지가 런타임 RW.
- V2 (msz 0x260 → 0x1260, 0x1000B 늘림): end → 0x405000. mprotect 추가 페이지(0x404000-0x405000) 까지 RO.
  .data 도 잠겨서 데이터 쓰기 시 SEGV 가능.
- V3 (msz 0x260 → 0x100, 절반 미만): end → 0x403ea0, page-down 0x403000. mprotect 0 bytes → RELRO 무력화.
"""
import harness
from pathlib import Path

N = 13
TITLE = 'B3: PT_GNU_RELRO 부분 누락 — 페이지 정렬 경계 효과 측정'

# target_full PT_GNU_RELRO 는 PHT idx 12
RELRO_IDX = 12
ORIG_MEMSZ = 0x260
ORIG_FILESZ = 0x260

spec_list = [
    {
        'name': 'I13V0_base',
        'base': 'target_full',
        'patches': [],
        'note': 'baseline target_full',
    },
    {
        'name': 'I13V1_relro_shrink_8',
        'base': 'target_full',
        'patches': [
            {'phdr_idx': RELRO_IDX, 'field': 'memsz',  'value': ORIG_MEMSZ - 8},
            {'phdr_idx': RELRO_IDX, 'field': 'filesz', 'value': ORIG_FILESZ - 8},
        ],
        'note': 'RELRO 8B 줄임 → page-down 효과로 mprotect 무력화 예상',
    },
    {
        'name': 'I13V2_relro_extend_page',
        'base': 'target_full',
        'patches': [
            {'phdr_idx': RELRO_IDX, 'field': 'memsz',  'value': ORIG_MEMSZ + 0x1000},
            {'phdr_idx': RELRO_IDX, 'field': 'filesz', 'value': ORIG_FILESZ + 0x1000},
        ],
        'note': 'RELRO 한 페이지 더 확장 → .data 까지 RO',
    },
    {
        'name': 'I13V3_relro_shrink_half',
        'base': 'target_full',
        'patches': [
            {'phdr_idx': RELRO_IDX, 'field': 'memsz',  'value': 0x100},
            {'phdr_idx': RELRO_IDX, 'field': 'filesz', 'value': 0x100},
        ],
        'note': 'RELRO 절반 미만 축소',
    },
]

# observe addresses: 텍스트(0x401000), .got 가 있는 페이지(0x403000), .data 가 있는 페이지(0x404000)
obs = harness.run_iteration(N, TITLE, spec_list, observe_addrs=[0x401000, 0x403000, 0x404000])

import sys, importlib
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules: importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
det_results = {}
for spec in spec_list:
    path = iter_dir / spec['name']
    r = detect_overlap.analyze(str(path))
    det_results[spec['name']] = r

findings = []
backlog = []

# baseline: .got 페이지(0x403000) main 시점 r--p, .data 페이지(0x404000) rw-p
base = obs[0]
v1 = obs[1]; v2 = obs[2]; v3 = obs[3]

# V1: shrink 8 → got page 가 RW 로 남는가?
v1_got_main = v1['main_perm'].get('0x403000', '?')
v1_data_main = v1['main_perm'].get('0x404000', '?')
findings.append(f'F25: baseline RELRO 적용 시 .got 페이지(0x403000) main 시점 = {base["main_perm"].get("0x403000","?")}.')
findings.append(f'F26: RELRO memsz 8 바이트만 줄여도 (V1) .got 페이지 main 시점 = {v1_got_main}. '
                f'{"RELRO 무력화 — 페이지 정렬 경계 효과 확인" if v1_got_main == "rw-p" else "여전히 RO — 페이지 경계 효과 가설 미성립"}.')

# V2: extend → data page RO?
v2_data_main = v2['main_perm'].get('0x404000', '?')
findings.append(f'F27: RELRO memsz 한 페이지 확장 (V2) 시 .data 페이지(0x404000) main 시점 = {v2_data_main}. '
                f'{"확장된 RELRO 가 .data 까지 RO 로 잠금 — 실행 영향 가능" if v2_data_main == "r--p" else "extend 가 효과 없음"}.')

# V2: plain exit — .data RO 면 데이터 쓰기 시 SEGV 가능
findings.append(f'F27b: V2 plain exit = {v2["plain_exit"]} ({".data RO 의 영향으로 SEGV" if v2["plain_exit"] == -11 else "정상 실행"}).')

# V3 결과
v3_got_main = v3['main_perm'].get('0x403000', '?')
findings.append(f'F28: RELRO 절반 미만 축소 (V3) 시 .got 페이지 main 시점 = {v3_got_main}.')

# detector v2 가 RELRO subset 위반을 잡는지
det_summary = {n: r['verdict'] for n, r in det_results.items()}
findings.append(f'F29: detector v2 결과 — {det_summary}. '
                f'RELRO subset 체크가 V1/V3 의 shrink 케이스를 어떻게 처리하는지가 관건.')

# 분석가가 readelf -l 로 RELRO size 만 봐도 단서를 얻을 수 있는지
findings.append('F30: 정적 분석에서 readelf -l GNU_RELRO 의 FileSiz/MemSiz 만 봐도 baseline 과 다름이 보임 — '
                '단 8B 차이는 분석가가 그냥 넘기기 쉬움. 자동화 시그널로는 "RELRO 가 .got 끝과 page-align 안 맞는다" 가 후보.')

backlog.append({'id':'B26','title':'F26 RELRO 무력화 + iter01 RWX overlay 결합 — 4바이트 패치 둘로 텍스트 RWX + .got RW 동시에 PoC'})
backlog.append({'id':'B27','title':'detector v3: RELRO end 가 .got 끝과 정확히 일치하는지 체크하는 휴리스틱 추가'})

verdict = ' | '.join(
    f'{r["name"]}:plain={r["plain_exit"]} got@0x403000={r["main_perm"].get("0x403000","?")} '
    f'data@0x404000={r["main_perm"].get("0x404000","?")} det={det_summary[r["name"]]}'
    for r in obs
)

harness.commit_iteration(N, TITLE, 'RELRO 페이지 정렬 경계가 작은 size 변경에도 전부/전무로 튄다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)

print('iter13 complete')
for r in obs:
    print(f'  {r["name"]}: plain={r["plain_exit"]} '
          f'got@0x403000={r["main_perm"].get("0x403000","?")} '
          f'data@0x404000={r["main_perm"].get("0x404000","?")} '
          f'det={det_summary[r["name"]]}')
