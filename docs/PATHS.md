# Lfuzzer 경로 설정 (`lfuzzer/config.py`)

**한 줄 요약 →** 모든 하드코딩 경로는 `lfuzzer/config.py` 한 곳으로 모았다. 해석 우선순위는 **환경변수 → 알려진 빌드 경로 → 시스템 폴백** 이며, 이는 기존 `exp_goldbfd_diff/common.py` 가 BFD/GOLD 에 쓰던 `next((p for p in [...] if exists), None)` 규칙을 그대로 일반화한 것이다. **레거시 스크립트는 아직 경로를 각자 하드코딩**하고 있고, 이 모듈이 그 마이그레이션 목표(single source of truth)다.

---

## 해석 우선순위

```
(1) 환경변수 오버라이드   LFUZZER_*        ← 있으면 무조건 채택(존재 안 해도, 경고만)
        ↓ 없으면
(2) 알려진 빌드 경로       ~/binutils-build-*, ~/ghidra_*, /lib64/... ← 첫 존재 경로
        ↓ 없으면
(3) 시스템 폴백           /usr/bin/ld, /usr/bin/ld.gold, PATH 조회 …  ← 첫 존재 경로
```

환경변수 값은 **명시적 의도**로 간주해 존재 검사에 실패해도 채택하고 `print_config()` 가 경고만 낸다. 오타를 조용히 시스템 바이너리로 폴백해 엉뚱한 결과를 내는 사고를 막기 위함이다.

---

## 경로 테이블

| 이름 | 환경변수 (override) | 알려진 빌드 경로 (default) | 시스템 폴백 (fallback) | 필수 | 없으면 깨지는 것 |
|------|--------------------|---------------------------|------------------------|:----:|------------------|
| **BFD** | `LFUZZER_BFD` | `~/binutils-build-afl-bfd-clean/ld/ld-new` | `/usr/bin/ld` → `/usr/bin/ld.bfd` → PATH `ld.bfd`/`ld` | 예 | gold-vs-BFD differential(`exp_goldbfd_diff/*`, `exp_d*`/`exp_r*`)의 BFD 링크 단계 전체 |
| **GOLD** | `LFUZZER_GOLD` | `~/binutils-build-gold/gold/ld-new` | `/usr/bin/ld.gold` → `/usr/bin/gold` → PATH `ld.gold`/`gold` | 예 | differential 의 GOLD 링커 측 실행. 없으면 대질 자체가 불가 |
| **GHIDRA** | `LFUZZER_GHIDRA` | `~/ghidra_12.1.2_PUBLIC` | `/opt/ghidra` → `/usr/local/ghidra` | 아니오 | Ghidra 분석기 차등(`DumpDynamic.java` headless). **Java 21 필요**. 없으면 Ghidra 레인만 스킵, 링커/로더 실험은 정상 |
| **LOADER** | `LFUZZER_LOADER` | `/lib64/ld-linux-x86-64.so.2` | `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` | 예 | ld.so 런타임 로더 실험(직접 `./ld-linux ... prog` 실행, dl-load 재현). 배포판마다 위치가 달라 폴백이 중요 |
| **REPO_ROOT** | `LFUZZER_REPO_ROOT` | `config.py` 기준 패키지 부모(`<repo>/lfuzzer/` 의 부모) | `~/PE/Lfuzzer`(레거시) → `cwd` | 예 | `seeds/`, `templates/`, `out*/` 경로 계산의 기준점. 항상 문자열을 반환하므로 `None` 은 안 됨 |

---

## API

```python
from lfuzzer import config

config.BFD        # str | None  — BFD(ld) 링커 절대경로
config.GOLD       # str | None  — gold 링커 절대경로
config.GHIDRA     # str | None  — Ghidra 설치 루트
config.LOADER     # str | None  — ld.so 로더
config.REPO_ROOT  # str         — 리포 루트(항상 값 존재)

config.which("ld.gold")   # shutil.which 래퍼: PATH 에서 실행파일 조회
config.print_config()     # 해석 결과 출력 + 누락된 '필수' 경로 개수 반환(0=정상)
```

### 진단 실행

```bash
python -m lfuzzer.config
```

필수 경로가 하나라도 없으면 종료코드 1(누락 개수>0), 모두 있으면 0. CI 게이트로 그대로 쓸 수 있다.

출력 예:

```
========================================================================
 Lfuzzer 경로 설정 (config.py)
========================================================================
  [OK     ] BFD        (필수)
            value    = /home/garden/binutils-build-afl-bfd-clean/ld/ld-new
            source   = auto   (override: LFUZZER_BFD)
  [MISSING] GOLD       (필수)
            value    = <해석 실패>
            source   = auto   (override: LFUZZER_GOLD)
            !! 경로 없음 → 깨지는 것: gold-vs-BFD differential 의 GOLD 링커 측 실행
  ...
```

---

## 마이그레이션 노트

- **현 상태:** `exp_goldbfd_diff/common.py` 를 비롯한 레거시 스크립트가 여전히 경로를 자체 하드코딩한다. 이 `config.py` 는 그것들이 옮겨올 **목표**다.
- **옮기는 법:** 스크립트 상단의 `BFD = next((...))` / `GOLD = next((...))` 블록을 삭제하고
  ```python
  from lfuzzer.config import BFD, GOLD, GHIDRA, LOADER, REPO_ROOT
  ```
  로 교체한다. 동작 동일(환경변수 한 단이 앞에 추가될 뿐).
- **왜 env 우선인가:** 같은 코드를 다른 머신/컨테이너/CI 에서 돌릴 때 경로만 환경변수로 바꿔 끼우면 되도록. 하드코딩 경로 수정 없이 이식 가능.
- **stdlib 전용:** `os`, `shutil`, `pathlib` 만 쓴다(외부 의존성 없음). 임포트 부작용 없음.
