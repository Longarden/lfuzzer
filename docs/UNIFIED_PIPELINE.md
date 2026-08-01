# 통합 파이프라인 설계 — collect-once → dual oracle

> 목적: 오늘 **따로 실행**되는 두 흐름 — A(크래시 사냥)와 B(차등 관찰) — 을,
> 뮤턴트당 실행을 **한 번만** 하고 그 관측을 두 오라클이 나눠 먹는 하나의 파이프라인으로 합친다.
> 이 문서는 설계(도식·오라클·티어)만 정의한다. `autorun_v3`의 실제 코드 개조는 다음 패스.

---

## 1. 왜 합치나 (오늘의 낭비)

| | Flow A (크래시) | Flow B (차등) |
|---|---|---|
| 실행 주체 | `autorun_v3` 대량 루프 | `exp_*.py` 특정 파일 |
| ld.so 실행 | 한다 | (또 ) 한다 |
| 신호 | 크래시(rc<0/timeout) | 도구 간 불일치 |
| 분석기 | **안 씀** | readelf/objdump/Ghidra |

두 흐름은 **"ld.so로 실행한다"** 노드만 공유하는데, 오늘은 그 실행을 **각자 따로** 한다.
→ 통합의 핵심: **실행(=관측 수집)을 1회로 묶고**, 크래시 오라클과 divergence 오라클이 그 결과를 공유한다.
실행비용 절반 + 두 신호 동시. 이것이 표준 **"collect-once, feed many oracles"**(N-version differential) 설계다.

---

## 2. 관측벡터 (뮤턴트 1개당 한 번 수집)

```
mutant ──▶ 다음 소비자에 물려 결과를 한 레코드로 수집:

  observation = {
    ld_so   : { rc, signal },                    # 뮤턴트를 로더로 직접 실행
    gold    : { link_rc, run_rc, run_signal },   # gold 링크 → 산출물 실행
    bfd     : { link_rc, run_rc, run_signal },   # bfd  링크 → 산출물 실행
    readelf : digest,   # -d/-S → {DT 태그셋, 심볼수, 섹션수} 정규화 다이제스트
    objdump : digest,   # -T    → 동일 정규화
  }
```

- **싼 것(핫루프)**: ld.so 실행, gold/bfd 링크+실행(수십 ms), readelf/objdump 파싱(ms).
- **입력 모드 적응**:
  - *link 모드* (linkable 입력=object/.so): gold·bfd 포크가 살아 있음 → gold≠bfd 관측 가능.
  - *direct 모드* (최종 실행파일 뮤턴트): 링크 스킵, ld.so 직접 실행 + 분석기만 → 로더≠분석기는 여전히 관측.

---

## 3. 두 오라클 (같은 벡터를 공유)

```
              ┌──────────── 관측벡터 1개 ────────────┐
              │  ld.so · gold · bfd · readelf · objdump │
              └───────────────┬───────────┬───────────┘
              작업1 (크래시)  │           │  작업2 (divergence, 병렬)
                              ▼           ▼
   gold-run/bfd-run 에서 크래시?     벡터 내 불일치?
     rc<0 or timeout                  ├ gold ≠ bfd   (링크 수용/거부, 또는 런타임 rc/sig)
        │                             ├ 로더 ≠ 분석기 (readelf는 파싱 OK인데 ld.so 실패 등)
        ▼                             └ 분석기 ≠ 분석기 (readelf vs objdump 다이제스트 차이)
   crashes/ 저장                          │
   gdb `bt` 트리아지                       ▼
   key = "SIGNAL:frame" 분류         divergence/ 저장 + 타입 랭크
```

### 작업1 — 크래시 (양쪽 링커 다)
`gold`·`bfd` 실행결과 각각에서 `rc<0`(시그널) 또는 `rc==124`(timeout)면 크래시.
→ `crashes/`에 (뮤테이션 seed와 함께) 저장 → `gdb --batch -ex run -ex "bt 4"`로 시그널+프레임 추출 →
`key = "SIGSEGV:frame명"`으로 디둡/분류. (오늘 `autorun_v3`의 트리아지를 **gold·bfd 양쪽**에 적용.)

### 작업2 — divergence (병렬, 크래시 아님)
같은 벡터에서 다음을 발화·저장하고 타입으로 랭크:

| 순위 | divergence 타입 | 정의 |
|---|---|---|
| 1 | **crash** | 위 작업1 (가장 강한 신호) |
| 2 | **gold ≠ bfd (런타임)** | 둘 다 링크 성공했는데 실행 rc/sig가 갈림 ← reframe 핵심 |
| 3 | **gold ≠ bfd (링크타임)** | 한쪽은 링크, 다른쪽은 거부 |
| 4 | **로더 ≠ 분석기** | readelf/objdump는 정상 파싱인데 ld.so는 실패/다르게 로드 (evasion) |
| 5 | **분석기 ≠ 분석기** | readelf 다이제스트 ≠ objdump 다이제스트 |

---

## 4. 2티어 — Ghidra는 왜 핫루프에 못 넣나

Ghidra 헤드리스는 **시작만 30~60초**. 수백만 뮤턴트마다 못 돌린다.
→ **티어1(핫루프)**: ld.so·gold·bfd·readelf·objdump (전부 싸다).
→ **티어2(살아남은 것만)**: 작업1/작업2가 "흥미로움"으로 저장한 소수에만 Ghidra(`ghidra_scripts/DumpDynamic.java`) + `gdb` 심층 + 사람.

이게 오늘 A/B가 원시적으로 하던 것의 정리된 형태다: 싼 오라클을 대량 루프에, 비싼 분석을 생존자에만.

---

## 5. 기존 파일 매핑 (구현 시)

| 통합 단계 | 재사용할 오늘의 코드 |
|---|---|
| 뮤테이트 | `lfuzzer/mutators/*` |
| 관측 수집(실행) | `orchestrator/lfuzzer.py`(`run_elf`) + `differential/exp_goldbfd_diff/common.py`(`link_with`, gold/bfd) |
| 링커 경로 | `lfuzzer/config.py` (BFD/GOLD) |
| 작업1 트리아지 | `analysis/auto_gdb_classify.py`, `orchestrator/autorun_v3.py`(gdb_site) |
| 작업2 divergence | `differential/exp_goldbfd_diff/`(exp_d*·exp_r*), `parser_diff/` |
| 티어2 | `differential/ghidra_scripts/DumpDynamic.java` |
| 기록 | `logger/logger.py` (뮤테이션·발화 규칙·오프셋) |

**구현 시 새로 필요한 것**: `orchestrator/unified_runner.py` — 관측벡터를 수집하고 두 오라클을 호출하는 얇은 상위 루프.
오늘 코드의 대부분은 이미 존재; 통합은 "실행 1회 수집 + 오라클 분기"를 얹는 재배선이다.

---

## 6. 현재 → 통합 한 줄

- **현재**: A와 B가 실행을 **각자** 한다 (ld.so 두 번, 분석기는 B에서만).
- **통합**: 실행을 **한 번** 수집 → 크래시 오라클 + divergence 오라클이 공유. Ghidra만 티어2.
