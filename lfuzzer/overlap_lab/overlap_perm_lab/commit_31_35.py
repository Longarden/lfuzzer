"""
commit_31_35.py — iter31/33/35 의 iter_outputs 결과를 STATE.json + ITER_LOG.md 에
정식 반영 (루프가 출력만 남기고 commit 안 한 미정리분).
harness.commit_iteration 을 그대로 사용해 기존 포맷과 일관되게 기록.
"""
import harness

# ---------------- iter31 ----------------
obs31 = [
    {
        'name': 'iter31_detector_v5_fp',
        'note': 'prod 1500 표본, ssm 11건 전부 link-time .o/.a + libclang (실행 binary FP 0)',
        'plain_exit': None,
        'kernel_perm': {'sample': 1500, 'sm': 9, 'ssm': 11, 'total_anomaly': 11},
        'main_perm': {'exec_binary_fp': '0/1500'},
    },
    {
        'name': 'I31V_evasion_eh_to_null',
        'note': 'PT_GNU_EH_FRAME → PT_NULL, C++ throw 시 terminate (std::runtime_error)',
        'plain_exit': -6,
        'kernel_perm': {},
        'main_perm': {},
    },
]
harness.commit_iteration(
    31,
    'B43 detector v5 대규모 FP 재측정 + PT_GNU_EH_FRAME 회피 변형',
    'detector v5 신규 시그널(sm/ssm) 의 prod FP, 그리고 EH_FRAME 을 PT_LOAD 외 타입으로 위장 시 동작',
    obs31,
    'v5 prod 1500: sm=9 ssm=11 total=11, 전부 link-time obj/clang lib → 실행 binary FP=0/1500 | '
    'PT_GNU_EH_FRAME→PT_NULL: C++ throw → exit=-6 terminate',
    new_findings=[
        'F75: detector v5 의 ssm 시그널 prod 1500 표본 anomaly 11건이 전부 link-time 오브젝트'
        '(crt1.o/Scrt1.o/crti.o/crtn.o/gcrt1.o/rcrt1.o/libmcheck.a)와 libclang-17/18.so. '
        '실행 binary 기준 FP 0/1500 = v4 와 동일 수준 유지.',
        'F76: PT_GNU_EH_FRAME → PT_NULL 변형도 C++ throw 시 exit=-6 terminate. iter29(F74)의 '
        'EH 깨짐이 →PT_LOAD 전용이 아님을 시사 → iter33 으로 타입 전수 확장.',
    ],
)

# ---------------- iter33 ----------------
_i33 = [
    ('I33V0_baseline', 0, 'baseline: caught test exception 정상'),
    ('I33V1_to_PT_NULL', -6, 'PT_GNU_EH_FRAME → PT_NULL, throw → terminate (3회 일관)'),
    ('I33V2_to_PT_TLS', -6, 'PT_GNU_EH_FRAME → PT_TLS, throw → terminate (3회 일관)'),
    ('I33V3_to_PT_LOPROC', -6, 'PT_GNU_EH_FRAME → PT_LOPROC, throw → terminate (3회 일관)'),
    ('I33V4_to_PT_HIPROC', -6, 'PT_GNU_EH_FRAME → PT_HIPROC, throw → terminate (3회 일관)'),
    ('I33V5_to_PT_LOOS', -6, 'PT_GNU_EH_FRAME → PT_LOOS, throw → terminate (3회 일관)'),
    ('I33V6_to_PT_HIOS', -6, 'PT_GNU_EH_FRAME → PT_HIOS, throw → terminate (3회 일관)'),
    ('I33V7_to_random', -6, 'PT_GNU_EH_FRAME → random type, throw → terminate (3회 일관)'),
]
obs33 = [{'name': n, 'note': note, 'plain_exit': e, 'kernel_perm': {}, 'main_perm': {}}
         for n, e, note in _i33]
harness.commit_iteration(
    33,
    'B38 확장: PT_GNU_EH_FRAME 을 7가지 타입으로 위장 (C++ throw 동작)',
    'EH_FRAME 위장 시 깨짐 원인이 PT_LOAD 변환 자체인지, 아니면 원본 타입 상실 자체인지',
    obs33,
    'baseline catch(exit=0) | NULL/TLS/LOPROC/HIPROC/LOOS/HIOS/random 7종 전부 exit=-6 terminate, '
    '각 3회 일관 → 위장 수단 무관, 원본 타입 상실이 원인',
    new_findings=[
        'F77: PT_GNU_EH_FRAME 을 PT_NULL/PT_TLS/PT_LOPROC/PT_HIPROC/PT_LOOS/PT_HIOS/random 어느 '
        '타입으로 위장하든 C++ throw 시 전부 exit=-6 terminate (각 3회 일관). baseline 만 정상 catch. '
        'EH 깨짐은 "→PT_LOAD" 가 특별해서가 아니라, ld.so 가 PT_GNU_EH_FRAME 으로 인식 못 하는 순간 '
        '.eh_frame_hdr 등록을 못 하는 게 원인.',
    ],
)

# ---------------- iter35 ----------------
_meta = ['PT_NOTE', 'PT_GNU_PROPERTY', 'PT_GNU_STACK', 'PT_TLS']
_disg = ['PT_LOPROC', 'PT_NULL', 'random']
obs35 = []
for m in _meta:
    for d in _disg:
        name = f'I35_{m}_{d}'
        if m == 'PT_TLS':
            note = f'{m} → {d}: exit=0 이지만 출력 "TLS = 0" (baseline 42) — silent data corruption'
        else:
            note = f'{m} → {d}: exit=0, ctor+main 도달 정상, 텍스트 0x401000 r-xp 유지 (런타임 무영향)'
        obs35.append({'name': name, 'note': note, 'plain_exit': 0,
                       'kernel_perm': {}, 'main_perm': {}})
harness.commit_iteration(
    35,
    'B7 확장: 메타 phdr 4종 × 위장 타입 3종 매트릭스',
    'ld.so 가 모르는 phdr 타입으로 메타 phdr 을 위장하면 삭제와 동치인가, 영향도는 타입별로 어떻게 다른가',
    obs35,
    'NOTE/PROPERTY/STACK → 위장 3종 전부 exit=0 런타임 무영향 (텍스트 r-xp 유지) | '
    'PT_TLS → 위장 3종 전부 exit=0 이지만 TLS=42→0 silent corruption | '
    'ld.so 는 미지 phdr 타입을 무시 → 메타 phdr 위장 ≡ 삭제',
    new_findings=[
        'F78: ld.so 는 인식 못 하는 phdr 타입(PT_LOPROC/PT_NULL/랜덤값 등)을 조용히 건너뜀. '
        '따라서 메타 phdr 을 그런 타입으로 위장하는 것은 사실상 그 phdr 을 삭제한 것과 동치.',
        'F79: 메타 phdr 위장(=삭제)의 런타임 영향도는 타입별로 다름 — PT_TLS = silent data '
        'corruption (TLS=0), PT_GNU_EH_FRAME = C++ throw abort (iter33), '
        'PT_NOTE/PT_GNU_PROPERTY/PT_GNU_STACK = 런타임 무영향. 정적 분석 측에선 readelf -l 에서 '
        '원본 마커가 사라지거나 비정상 타입으로 보이므로 탐지 단서는 잔존.',
        'F80: iter35 의 위장 변형은 RWX 오버레이가 아니라 단순 타입 변경이라 텍스트 페이지 권한은 '
        '0x401000 r-xp 그대로. 권한 변형과 타입 위장은 독립적인 두 축임.',
    ],
)

print('committed iter31, iter33, iter35')
import json
s = json.loads(open('STATE.json').read())
print('iteration =', s['iteration'])
print('findings  =', len(s['findings']))
print('completed =', [c['iter'] for c in s['completed_iterations']][-6:])
