"""
iter01 — PT_NOTE → PT_LOAD 변형으로 텍스트 페이지 위에 오버레이.

가설:
- I1V1 (RWX 오버레이): 텍스트 페이지가 RWX 로 끝나고 main 이 도달한다.
  플래그 0x7 가 ld.so/커널에서 허용되는지, W^X 가 차단하는지 1차 관측.
- I1V2 (RW 오버레이): 텍스트 페이지가 RW 로 끝나며 실행 불가 → SIGSEGV.
  V1 의 정적 R-X / 동적 RW 결론을 재확인 (단, 오리지널 데이터 PT_LOAD 는 손대지 않음).
- I1V3 (R-X 오버레이): 오버레이 플래그가 같으면 정적/동적 일치, main 도달.
  컨트롤 비교군.
"""
import harness

N = 1
TITLE = 'PT_NOTE→PT_LOAD overlay over text page'

# target_partial PT_NOTE [idx=8]: offset=0x368, vaddr=0x400368, fsz=0x44, flags=R, align=0x4
# 이 엔트리를 PT_LOAD 로 바꾸고 vaddr/offset 을 텍스트와 동일하게.

def make_spec(name, flags, note):
    return {
        'name': name,
        'patches': [
            {'phdr_idx': 8, 'field': 'type',   'value': 1},          # PT_LOAD
            {'phdr_idx': 8, 'field': 'flags',  'value': flags},
            {'phdr_idx': 8, 'field': 'offset', 'value': 0x1000},
            {'phdr_idx': 8, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': 8, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': 8, 'field': 'filesz', 'value': 0x331},
            {'phdr_idx': 8, 'field': 'memsz',  'value': 0x331},
            {'phdr_idx': 8, 'field': 'align',  'value': 0x1000},
        ],
        'note': note,
    }

spec_list = [
    make_spec('I1V1_overlay_rwx', 0x7, 'RWX overlay'),
    make_spec('I1V2_overlay_rw',  0x6, 'RW overlay (no exec)'),
    make_spec('I1V3_overlay_rx',  0x5, 'R-X overlay (control)'),
]

obs = harness.run_iteration(N, TITLE, spec_list)

# 판정
verdict_parts = []
findings = []
backlog = []
for r in obs:
    name = r['name']; pl = r['plain_exit']
    kp = r['kernel_perm']['0x401000']; mp = r['main_perm']['0x401000']
    verdict_parts.append(f'{name}: plain={pl} kernel={kp} main={mp}')

# 명시적 가설 vs 관찰 비교
v1 = obs[0]
if v1['kernel_perm']['0x401000'] == 'rwxp':
    findings.append('F6: PT_NOTE→PT_LOAD RWX 오버레이가 커널에서 허용됨. 0x401000 페이지가 RWX.')
    if v1['plain_exit'] == 0:
        findings.append('F7: RWX 텍스트 페이지로 main 도달 성공 — 정적은 R-X 로 보고되지만 런타임은 RWX. 정적/동적 분리 PoC 1호.')
    else:
        backlog.append({'id':'B5','title':'RWX 케이스 SEGV 원인 분석 (ld.so 단계 어디서 죽는지 gdb_main 로그 정밀 파싱)'})
else:
    findings.append(f'F6alt: RWX 플래그 적용 결과 {v1["kernel_perm"]["0x401000"]} — W^X 또는 ld.so가 마스킹 가능성. gdb_kernel/main 로그 정밀 분석 필요.')

v2 = obs[1]
if v2['kernel_perm']['0x401000'] == 'rw-p' and v2['plain_exit'] != 0:
    findings.append('F8: RW 오버레이는 텍스트 페이지를 RW 로 만들고 NX 로 인해 실행 시 SEGV — V1 결과 재확인.')

v3 = obs[2]
if v3['plain_exit'] == 0 and v3['kernel_perm']['0x401000'] == 'r-xp':
    findings.append('F9: R-X 오버레이는 동일 플래그라 변화 없음 — 컨트롤 통과.')
else:
    backlog.append({'id':'B6','title':f'R-X 컨트롤이 정상이 아님 (exit={v3["plain_exit"]} k={v3["kernel_perm"]["0x401000"]}). PT_NOTE→PT_LOAD 변형 자체에 부수효과 의심.'})

verdict = ' | '.join(verdict_parts)
harness.commit_iteration(N, TITLE, '오버레이 플래그가 그대로 페이지 권한이 된다', obs, verdict,
                         new_backlog=backlog, new_findings=findings)

print('iter01 complete')
for r in obs:
    print(r)
