"""
iter02 — F7 (RWX 오버레이로 main 도달) 가 RELRO 모드 별로 견고한지 확인.

target_partial 에서만 검증됐던 결과를 target_norelro / target_full 에 동일 변형을 적용해
일관되게 RWX 가 살아남는지 본다. 만약 full RELRO 에서 ld.so 가 RWX 텍스트를 R-X 로
재마스킹한다면 PoC 가 partial 한정으로 약해진다.

베이스 별 PT_NOTE[8] 위치 확인:
- target_norelro: PT_NOTE 인덱스 자동 탐색 필요
- target_partial: idx=8 (검증됨)
- target_full   : idx=8 (검증됨)
"""
import harness, struct
from pathlib import Path

def find_pt_note_idx(path):
    data = Path(path).read_bytes()
    e_phoff, e_phnum = harness.load_phdr_table(data)
    for i in range(e_phnum):
        t = struct.unpack_from('<I', data, e_phoff + i * harness.PHDR_SIZE)[0]
        if t == 4:  # PT_NOTE
            return i
    return None

N = 2
TITLE = 'F7 cross-RELRO consistency check (RWX overlay 가 모든 RELRO 모드에서 성립?)'

bases = ['target_norelro', 'target_partial', 'target_full']
spec_list = []
for b in bases:
    idx = find_pt_note_idx(harness.ROOT / b)
    if idx is None:
        print(f'  (skip) {b}: PT_NOTE 없음')
        continue
    print(f'  {b}: PT_NOTE idx={idx}')
    spec_list.append({
        'name': f'I2V_{b.replace("target_","")}_rwx',
        'base': b,
        'patches': [
            {'phdr_idx': idx, 'field': 'type',   'value': 1},
            {'phdr_idx': idx, 'field': 'flags',  'value': 0x7},
            {'phdr_idx': idx, 'field': 'offset', 'value': 0x1000},
            {'phdr_idx': idx, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': idx, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': idx, 'field': 'filesz', 'value': 0x331},
            {'phdr_idx': idx, 'field': 'memsz',  'value': 0x331},
            {'phdr_idx': idx, 'field': 'align',  'value': 0x1000},
        ],
        'note': f'RWX overlay on {b}',
    })

obs = harness.run_iteration(N, TITLE, spec_list)

findings = []
backlog = []
all_ok = True
for r in obs:
    if r['plain_exit'] != 0 or r['main_perm']['0x401000'] != 'rwxp':
        all_ok = False

if all_ok:
    findings.append('F10: RWX 오버레이 PoC 가 norelro/partial/full RELRO 모드 전부에서 성립. RELRO 옵션이 정적/동적 분리 시나리오를 차단하지 못함.')
    backlog.append({'id':'B7','title':'PT_NOTE 외 다른 phdr 슬롯(PT_GNU_STACK, PT_GNU_PROPERTY)으로 같은 오버레이가 가능한지 — 정적 분석기가 "PT_LOAD 만" 봐도 놓치는 영역 확대'})
    backlog.append({'id':'B8','title':'F7 의 자기수정 코드 PoC 화 — main 이 0x401XXX 에 페이로드를 쓰고 호출, 베이스는 SEGV / RWX 변형은 실행'})
else:
    findings.append('F10alt: RELRO 모드 별로 결과가 다름 — full RELRO 가 일부 마스킹 가능성. gdb_main 로그 정밀 분석 필요.')
    backlog.append({'id':'B7r','title':'RELRO 모드별 분화 원인 분석 — _dl_protect_relro 와 PT_LOAD 매핑 순서 상호작용'})

verdict = ' | '.join(f'{r["name"]}:plain={r["plain_exit"]} k={r["kernel_perm"]["0x401000"]} m={r["main_perm"]["0x401000"]}' for r in obs)
harness.commit_iteration(N, TITLE, '오버레이가 RELRO 모드와 무관하게 동작한다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)
print('iter02 complete')
for r in obs:
    print(r)
