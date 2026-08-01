"""
iter09 — B15: detect_overlap.py 의 false positive 점검.

정상 prod 바이너리(/usr/bin/*, /usr/lib/x86_64-linux-gnu/*.so) 에 detector v2 를 돌려
ANOMALY 가 어느 정도 발생하는지 측정. False positive 비율이 높으면 1차 방어선으로 못 씀.

가설:
- ELF 스펙이 PT_LOAD 오버랩을 명시적으로 금지하진 않지만, 정상 빌드 툴체인 산출물에서는
  거의 안 나타난다. PT_GNU_RELRO 도 PT_LOAD subset 으로 항상 떨어진다.
  따라서 FP 비율은 0% 또는 매우 낮을 것.
"""
import harness, subprocess, sys, importlib
from pathlib import Path

N = 9
TITLE = 'detector v2 의 false positive 점검 (/usr/bin, /usr/lib)'

sys.path.insert(0, str(harness.ROOT))
if 'detect_overlap' in sys.modules:
    importlib.reload(sys.modules['detect_overlap'])
import detect_overlap

# 표본 수집
targets = []
# /usr/bin 의 ELF
for p in Path('/usr/bin').glob('*'):
    if p.is_file() and not p.is_symlink():
        try:
            if p.read_bytes()[:4] == b'\x7fELF':
                targets.append(p)
        except (PermissionError, OSError):
            pass
    if len(targets) >= 200: break

# /usr/lib/x86_64-linux-gnu 의 ELF (subset)
LIB = Path('/usr/lib/x86_64-linux-gnu')
if LIB.exists():
    cnt = 0
    for p in LIB.glob('*.so*'):
        if p.is_file() and not p.is_symlink():
            try:
                if p.read_bytes()[:4] == b'\x7fELF':
                    targets.append(p); cnt += 1
            except: pass
        if cnt >= 100: break

print(f'표본 {len(targets)} 개')

iter_dir = harness.OUT_ROOT / f'iter{N:02d}'
iter_dir.mkdir(parents=True, exist_ok=True)

results = []
errors = 0
for p in targets:
    try:
        r = detect_overlap.analyze(str(p))
        results.append(r)
    except Exception as e:
        errors += 1

clean = [r for r in results if r['verdict'] == 'CLEAN']
anomaly = [r for r in results if r['verdict'] != 'CLEAN']

print(f'  clean: {len(clean)}/{len(results)}')
print(f'  anomaly: {len(anomaly)}')
print(f'  errors: {errors}')

if anomaly:
    print('\n  의심 케이스 (FP 후보):')
    for r in anomaly[:15]:
        print(f'    {r["verdict"]}: {r["path"]} overlap={r["overlap_count"]} relro_anom={r["relro_anomaly"]} pairs={r["overlap_pairs"]}')

import json
(iter_dir / 'fp_report.json').write_text(json.dumps(results, indent=2, ensure_ascii=False))

findings = []
backlog = []

fp_rate = len(anomaly) / max(1, len(results)) * 100
findings.append(f'F20: 정상 prod 바이너리 {len(results)} 개 중 ANOMALY {len(anomaly)} 개 ({fp_rate:.1f}%). '
                f'False positive 비율 {"매우 낮음" if fp_rate < 1 else "보통" if fp_rate < 5 else "높음"} → '
                f'detector v2 를 1차 방어선으로 사용 {"적합" if fp_rate < 5 else "추가 휴리스틱 필요"}.')

if anomaly:
    causes = {}
    for r in anomaly:
        key = ('overlap' if r['overlap_count'] else '') + ('+relro' if r['relro_anomaly'] else '')
        causes[key] = causes.get(key, 0) + 1
    findings.append(f'F20b: FP 원인 분류 — {causes}')
    backlog.append({'id':'B19','title':f'FP {len(anomaly)} 건 정밀 분석 — RELRO 가 PT_LOAD 의 끝과 정렬 차이로 subset 위배 보이는 정상 케이스가 있는지'})

obs = [{
    'name': 'fp_check',
    'plain_exit': None,
    'kernel_perm': {'sample_size': len(results), 'errors': errors},
    'main_perm':   {'clean': len(clean), 'anomaly': len(anomaly)},
    'note': f'FP rate {fp_rate:.2f}%',
}]

verdict = f'sample={len(results)} clean={len(clean)} anomaly={len(anomaly)} fp_rate={fp_rate:.2f}%'

harness.commit_iteration(N, TITLE, '정상 바이너리에서 ANOMALY 비율이 낮다', obs, verdict,
                         new_findings=findings, new_backlog=backlog)
print('iter09 complete')
