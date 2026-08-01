"""
iter03 — 자기수정 코드 PoC. F7/F10 의 실용적 가치 검증.

target_smc: main 이 target_func 자리에 페이로드를 memcpy 한 뒤 target_func() 호출.
- baseline: 텍스트가 R-X → memcpy 시 SIGSEGV.
- RWX 오버레이: 텍스트가 RWX → memcpy 성공, payload(eax=42; ret) 실행 → result=42.

가설: 동일 소스 빌드에서 PHT 한 줄만 패치해도 정적 분석으로는 동일해 보이지만
런타임 거동이 SEGV vs 정상 실행으로 갈린다. 정적/동적 분리 케이스의 실용성 입증.

PT_NOTE[8] (offset 0x368, .note.gnu.build-id) 슬롯을 재활용해서 RWX 오버레이 추가.
"""
import harness
from pathlib import Path

N = 3
TITLE = 'Self-modifying-code via RWX overlay (실용 PoC)'

# target_smc 의 텍스트 size 0x219, offset 0x1000, vaddr 0x401000
TEXT_SIZE = 0x219

spec_list = [
    {
        'name': 'I3V0_baseline',
        'base': 'target_smc',
        'patches': [],   # 변형 없음
        'note': 'baseline — 텍스트 R-X, memcpy 실패 예상',
    },
    {
        'name': 'I3V1_rwx_overlay',
        'base': 'target_smc',
        'patches': [
            {'phdr_idx': 8, 'field': 'type',   'value': 1},
            {'phdr_idx': 8, 'field': 'flags',  'value': 0x7},
            {'phdr_idx': 8, 'field': 'offset', 'value': 0x1000},
            {'phdr_idx': 8, 'field': 'vaddr',  'value': 0x401000},
            {'phdr_idx': 8, 'field': 'paddr',  'value': 0x401000},
            {'phdr_idx': 8, 'field': 'filesz', 'value': TEXT_SIZE},
            {'phdr_idx': 8, 'field': 'memsz',  'value': TEXT_SIZE},
            {'phdr_idx': 8, 'field': 'align',  'value': 0x1000},
        ],
        'note': 'RWX overlay — memcpy 성공 + payload 실행 예상',
    },
]

obs = harness.run_iteration(N, TITLE, spec_list, observe_addrs=[0x401000])

# stdout 도 같이 모아서 보기
iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
for r in obs:
    plain = (iter_dir / f'{r["name"]}.plain.log').read_text()
    r['stdout_preview'] = plain[:400]

findings = []
backlog = []

base_obs = obs[0]; overlay_obs = obs[1]
base_ok = base_obs['plain_exit'] == -11
overlay_ok = overlay_obs['plain_exit'] == 0 and 'result = 42' in (iter_dir / f'{overlay_obs["name"]}.plain.log').read_text()

if base_ok and overlay_ok:
    findings.append('F11: 베이스 = SEGV(memcpy on R-X), RWX 오버레이 변형 = 정상 실행 + "result = 42" 출력. '
                    'PHT 한 줄 패치(PT_NOTE→PT_LOAD)만으로 자기수정 코드가 가능해짐. '
                    '정적 분석은 두 바이너리를 동일 의미로 볼 수 있지만 런타임은 SEGV vs 성공.')
    backlog.append({'id':'B9','title':'F11 의 페이로드 위치를 .data 안에 미리 박아두고 main 진입 즉시 호출 — memcpy 없이도 결과 분기'})
    backlog.append({'id':'B10','title':'static analyzer(readelf/objdump/Ghidra) 가 PT_NOTE→PT_LOAD overlay 를 탐지하는지 도구별 매트릭스'})
elif not base_ok:
    findings.append(f'F11alt: 베이스도 SEGV 안 남 (exit={base_obs["plain_exit"]}). text 가 이미 RW 가 아닌데 memcpy 성공? 빌드 옵션/페이지 권한 재확인 필요.')
    backlog.append({'id':'B9r','title':f'베이스 SEGV 부재 원인 — gdb 로 memcpy 단계 추적'})
elif not overlay_ok:
    findings.append(f'F11alt: 오버레이 변형이 의도대로 실행 안 됨 (exit={overlay_obs["plain_exit"]}). 출력: {overlay_obs.get("stdout_preview","")[:200]}')
    backlog.append({'id':'B9r','title':'오버레이 변형 실행 실패 — text 페이지 권한과 코드 정렬 재확인'})

verdict = ' | '.join(f'{r["name"]}:plain={r["plain_exit"]} k={r["kernel_perm"]["0x401000"]} m={r["main_perm"]["0x401000"]}' for r in obs)
harness.commit_iteration(N, TITLE, '오버레이만으로 자기수정 코드 PoC 가 성립한다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)
print('iter03 complete')
for r in obs:
    print(r['name'], 'exit=', r['plain_exit'], 'k=', r['kernel_perm'], 'm=', r['main_perm'])
    print('  stdout preview:', r['stdout_preview'].replace('\n',' | ')[:300])
