# 표 1. 제안 프레임워크와 기존 기법의 성능 대조 (실측)

실험일 2026-08-28 · 시간예산 arm당 1h(짧은-비교 tier; 논문 헤드라인 full-scale 48h) ·
계측 링커 SUT: GNU ld(bfd, afl-clang-fast) / gold(afl-clang-fast) ·
트리아지: CASR(casr-gdb) 백트레이스 클러스터링, 버킷=고유 결함 후보 ·
뮤테이터 고정(structure_aware 4축 ADD/SUB/SUBST/SCRAMBLE), 피드백 유무만 대조.

## (a) 크래시·결함 다양성 — SUT: gold (crash-yielding)

| 기법 | Exec 수 | 원시 크래시 | 고유 버킷(CASR) | 커버리지(edges) |
|------|--------:|-----------:|---------------:|---------------:|
| **제안** (4축 + afl 커버리지 피드백) | 542,144 | 64 † | **16** | 10,475 |
| no-feedback (동일 뮤테이터, 피드백 OFF) | 480,500 | 18,582 ‡ | 4 | – |
| Melkor (규칙기반 베이스라인) | – | 778 | 3 | – |

† afl 의 saved_crashes = **커버리지-고유** 크래시만 저장(새 엣지 없으면 폐기).
‡ no-feedback = **내용-고유** 크래시 전부 저장 → 원시 수는 크나 버킷은 적음.
→ 원시 크래시 수는 arm 간 직접 비교 불가. **공정 지표 = CASR 고유 버킷**.
버킷은 각 arm 40개 샘플 트리아지(고유 버킷의 하한 추정).

## (b) 조기기각률·커버리지 — SUT: bfd (robust)

| 기법 | 조기기각률 † | 심층도달률 | 커버리지(bitmap) | 원시 크래시 |
|------|-----------:|----------:|----------------:|-----------:|
| **제안** (4축 + 리페어 ON) | **24.3%** | 75.7% | 10.88% | 0 ‡ |
| Naïve bitflip (리페어 OFF) | 36.0% | 64.0% | – | – |
| Melkor (규칙기반) | – | – | – | 12 → 2 버킷 |

† controlled 측정, N=300 각, 계측 bfd ld. 리페어(canonicalize)가 조기기각을
36.0%→24.3% 로 낮춰 심층 파싱 도달률을 64%→76% 로 끌어올림(논문 §서론 주장).
‡ bfd 는 견고한 링커(parser_diff 51,762 뮤턴트서 readelf/objdump/bfd 0-crash) →
.so 변조로 1h 내 크래시 미발생. 크래시 관측은 gold 표(a) 참조.

## 핵심 해석 (논문 §4.2 재현)

1. **커버리지 피드백 효과 (제안 vs no-feedback)**: 뮤테이터를 고정하고 피드백만
   껐을 때, no-feedback 은 크래시를 18,582건 쏟아내지만 **CASR 버킷은 4개** —
   커버리지 안내가 없어 같은 얕은 결함을 반복 타격. 제안은 크래시 64건으로 적지만
   **버킷 16개** — 커버리지가 새 경로의 크래시만 큐에 남겨 결함 다양성을 4배로.
   → "원시 크래시 수가 아니라 커버리지 피드백이 고유 결함 발굴을 좌우"함을 실증.

2. **제안 vs Melkor**: 제안 16버킷 vs Melkor 3버킷. 구조보존 4축(엔트리 추가·삭제·
   재배치를 포함)과 피드백이 규칙기반 단일필드 변조보다 다양한 심층 결함 도달.

3. **리페어 효과(③)**: 조기기각 36%→24% 하락으로 파서 심층 경로 진입률 상승.

## 재현 명령
```
# 계측 빌드(존재): ~/binutils-build-afl-bfd-clean/ld/ld-new,
#                  ~/binutils-src/binutils-2.42-afl-gold/gold/ld-new
python3 -m lfuzzer.coverage.gen_afl_dict lfuzzer/coverage/elf.dict
BUDGET=3600 KIND=gold LD=~/binutils-src/binutils-2.42-afl-gold/gold/ld-new \
    RUN=/tmp/lfuzz_gold bash lfuzzer/coverage/run_campaign.sh
# 조기기각: python3 -m lfuzzer.coverage.measure_early_reject --ld <ld> --main-o main.o --inputs <mut_dir>
```

## 한계 (정직)
- **시드 교란**: 제안·no-feedback 은 libv.so(라이브러리) 변조, Melkor 는 prac.elf
  (실행파일) 변조 — Melkor 크래시 차이는 부분적으로 시드 종류 기인.
- 버킷은 40개 샘플 트리아지(전수 아님) → 고유 버킷 하한 추정. 전수 트리아지 시 증가 가능.
- 1h 짧은-비교 tier. full-scale(48h, 다중 trial) 은 후속.
- bfd 커버리지 % 는 절대값(gold 는 116MB C++ 바이너리라 bitmap% 작음; edges 절대수 유효).
