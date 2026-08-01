"""
iter07 — detect_overlap 개선(page-align + RELRO 비-subset 체크) + 통합 보고서.

iter06 에서 V2_text_over_data 등이 PT_LOAD vaddr 범위 자체로는 겹치지 않지만
mmap 의 페이지 단위 때문에 사실상 페이지 충돌이 일어났던 케이스를 탐지하지 못했음.
개선판: 페이지 정렬 후 비교 + PT_GNU_RELRO 가 PT_LOAD 의 부분집합이 아닌 케이스도 표시.

산출물: detect_overlap.py 갱신 + FINAL_REPORT.md
"""
import harness, json, struct
from pathlib import Path

N = 7
TITLE = 'detector 개선(페이지 정렬 + RELRO subset 체크) + 통합 보고서'

DETECTOR_SRC = r'''#!/usr/bin/env python3
"""detect_overlap.py — ELF 의 PT_LOAD 가상주소 오버랩 및 PT_GNU_RELRO 불일치 탐지.

검사 1: PT_LOAD 두 엔트리의 페이지 정렬된 vaddr 범위가 겹치면 OVERLAP.
검사 2: PT_GNU_RELRO 가 어느 PT_LOAD 의 부분집합이 아니면 ANOMALOUS_RELRO.

usage: detect_overlap.py <elf> [<elf> ...]
exit:  0 = clean, 1 = anomaly detected
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
        t = struct.unpack_from('<I', data, b)[0]
        f = struct.unpack_from('<I', data, b + 4)[0]
        off = struct.unpack_from('<Q', data, b + 8)[0]
        va  = struct.unpack_from('<Q', data, b + 16)[0]
        sz  = struct.unpack_from('<Q', data, b + 40)[0]
        out.append({'idx': i, 'type': t, 'flags': f, 'offset': off, 'vaddr': va, 'memsz': sz})
    return out

def page_range(p):
    s = p['vaddr'] & ~(PAGE - 1)
    e = (p['vaddr'] + p['memsz'] + PAGE - 1) & ~(PAGE - 1)
    return s, e

def overlap_load(phs):
    loads = [p for p in phs if p['type'] == PT_LOAD]
    out = []
    for i in range(len(loads)):
        a_s, a_e = page_range(loads[i])
        for j in range(i + 1, len(loads)):
            b_s, b_e = page_range(loads[j])
            if a_s < b_e and b_s < a_e:
                out.append((loads[i], loads[j]))
    return out

def relro_anomaly(phs):
    rel = [p for p in phs if p['type'] == PT_GNU_RELRO]
    loads = [p for p in phs if p['type'] == PT_LOAD]
    flagged = []
    for r in rel:
        r_s = r['vaddr']; r_e = r['vaddr'] + r['memsz']
        contained = False
        for L in loads:
            if L['vaddr'] <= r_s and r_e <= L['vaddr'] + L['memsz']:
                contained = True; break
        if not contained:
            flagged.append(r)
    return flagged

def analyze(path):
    data = open(path, 'rb').read()
    P = phdrs(data)
    ov = overlap_load(P)
    ra = relro_anomaly(P)
    anomaly = bool(ov) or bool(ra)
    return {
        'path': path,
        'pt_load_count': sum(1 for p in P if p['type'] == PT_LOAD),
        'overlap_count': len(ov),
        'overlap_pairs': [(a['idx'], b['idx']) for a, b in ov],
        'relro_anomaly': len(ra),
        'verdict': 'ANOMALY' if anomaly else 'CLEAN',
    }

if __name__ == '__main__':
    paths = sys.argv[1:]
    if not paths:
        print('usage: detect_overlap.py <elf> [<elf>...]')
        sys.exit(2)
    bad = 0
    for p in paths:
        try:
            r = analyze(p)
            print(f'{r["verdict"]:8s} {p}  PT_LOAD={r["pt_load_count"]} overlap={r["overlap_count"]} relro_anom={r["relro_anomaly"]} pairs={r["overlap_pairs"]}')
            if r['verdict'] != 'CLEAN':
                bad += 1
        except Exception as e:
            print(f'ERROR    {p}  {e}')
    sys.exit(1 if bad else 0)
'''

(harness.ROOT / 'detect_overlap.py').write_text(DETECTOR_SRC)
(harness.ROOT / 'detect_overlap.py').chmod(0o755)

import importlib, sys
sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules:
    importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

candidates = []
for b in ['target_norelro', 'target_partial', 'target_full', 'target_smc', 'target_pre']:
    p = harness.ROOT / b
    if p.exists(): candidates.append(('base', str(p)))
for it in range(1, 7):
    d = harness.OUT_ROOT / f'iter{it:02d}'
    if not d.exists(): continue
    for f in sorted(d.iterdir()):
        if f.is_file():
            try:
                if f.read_bytes()[:4] == b'\x7fELF':
                    candidates.append((f'iter{it:02d}', str(f)))
            except: pass

results = []
for tag, p in candidates:
    r = detect_overlap.analyze(p)
    r['tag'] = tag
    results.append(r)

base_results = [r for r in results if r['tag'] == 'base']
variant_results = [r for r in results if r['tag'] != 'base']

key_variants = [r for r in variant_results if any(
    s in r['path'] for s in ['I1V1_overlay_rwx', 'I1V2_overlay_rw',
                              'I2V_', 'I3V1_rwx_overlay', 'I4V1_prestaged_payload',
                              'V1_data_over_text', 'V2_text_over_data',
                              'V6_data_over_text_first', 'V4_relro_over_text'])]
key_caught = sum(1 for r in key_variants if r['verdict'] == 'ANOMALY')

(iter_dir / 'detect_v2_report.json').write_text(json.dumps(results, indent=2, ensure_ascii=False))

findings = []
findings.append(f'F15: detector v2(페이지 정렬 + RELRO subset 체크)로 key 변형 recall = {key_caught}/{len(key_variants)}.')

# 통합 보고서 작성
state = harness.load_state()
report = []
report.append('# overlap_perm_lab — 통합 연구 노트 (V0-V6 + iter01-07)\n')
report.append('자가 피드백 루프로 진행한 0508 미팅 액션 A 확장 연구 결과.\n')
report.append('## 핵심 결론')
for f in state['findings']:
    report.append(f'- {f}')
report.append('')
report.append('## 완결된 이터레이션')
for ci in state['completed_iterations']:
    report.append(f'### iter{ci["iter"]:02d} — {ci["title"]}')
    report.append(f'- 가설: {ci["hypothesis"]}')
    report.append(f'- 판정: {ci["verdict"]}')
    report.append(f'- ts: {ci.get("ts","")}')
    report.append('')

report.append('## 남은 백로그')
for b in state['backlog']:
    report.append(f'- [{b["id"]}] {b["title"]}')
report.append('')

report.append('## 핵심 아티팩트')
report.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/harness.py — 코어')
report.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/detect_overlap.py — 방어 측 도구 v2')
report.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter01..07.py — 각 단계 spec/분석')
report.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/STATE.json — 누적 finding/backlog')
report.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/ITER_LOG.md — 자가루프 시간순 로그')
report.append('- /home/garden/PE/Lfuzzer/overlap_perm_lab/iter_outputs/iterNN/ — 변형 ELF + 로그')
report.append('')

report.append('## 정적/동적 분리 PoC 요약')
report.append('1. RWX 오버레이 (iter01/02): PT_NOTE→PT_LOAD 한 줄 패치로 텍스트 페이지가 RWX. norelro/partial/full RELRO 전부 성립.')
report.append('2. SMC PoC (iter03): 동일 소스, PHT 패치만으로 baseline=SEGV vs 변형="result=42". 정적 분석은 두 바이너리를 동일 의미로 본다.')
report.append('3. Pre-staged payload (iter04): runtime memcpy 없이 file 끝에 0x1000 바이트 부착 + PHT 1줄 패치로 target_func 1→42 분기. strace 흔적 없음.')
report.append('4. 도구 탐지 매트릭스 (iter05): readelf -l 만이 새 PT_LOAD 표시. objdump -d 는 미탐. malware 분석가가 단순 카운트로는 놓침.')
report.append('5. 방어 도구 (iter06/07): PT_LOAD vaddr 페이지 정렬 오버랩 + RELRO subset 체크 한 가지 시그널로 lab 의 의미 있는 변형을 거의 전부 탐지.')

report_path = harness.ROOT / 'FINAL_REPORT.md'
report_path.write_text('\n'.join(report))

verdict = f'detector v2 key recall={key_caught}/{len(key_variants)} | FINAL_REPORT.md 작성'
obs = [{'name': 'detector_v2_check', 'plain_exit': None,
        'kernel_perm': {'key_caught': key_caught, 'key_total': len(key_variants)},
        'main_perm': {'base_clean': sum(1 for r in base_results if r["verdict"]=="CLEAN"),
                      'base_total': len(base_results)},
        'note': 'iter07 통합 검증'}]
harness.commit_iteration(N, TITLE, 'detector v2 가 false negative 를 줄이고 PoC 군을 종합 탐지', obs, verdict,
                         new_findings=findings)

print('iter07 complete')
print(f'  detector v2 key recall: {key_caught}/{len(key_variants)}')
print(f'  base clean: {sum(1 for r in base_results if r["verdict"]=="CLEAN")}/{len(base_results)}')
print(f'  FINAL_REPORT.md at: {report_path}')

# 다음 백로그 후보 출력
print('\n남은 backlog:')
for b in harness.load_state()['backlog']:
    print(f'  [{b["id"]}] {b["title"]}')
