# 재현 가이드 (coverage-guided ELF 퍼징)

이 문서 하나로 제3자가 처음부터 재현할 수 있게 정리. Linux/WSL2(Ubuntu 22.04/24.04) 기준.
**바이너리를 받지 말고 소스에서 직접 빌드**할 것 — 계측·디버그정보가 각자 환경에 맞아야
afl 커버리지·CASR 심볼 백트레이스가 정상 동작한다.

## 0. 받아야 할 것 (공유자 → 재현자)
1. **코드**: 이 repo, 브랜치 `feat/coverage-guided-upgrade` (PR #3). private면 collaborator 초대.
2. **소스 아카이브**: `binutils_2.42.orig.tar.xz`, `glibc_2.39.orig.tar.xz` (또는 재현자가 `apt source`로 직접 받기 — 아래).
3. 이 REPRODUCE.md.

## 1. 툴체인 설치 (검증된 버전)
```bash
# AFL++ (afl-fuzz 4.09c, afl-clang-fast), clang 17
sudo apt install -y afl++ clang gcc g++ gdb bison flex texinfo build-essential
#   ↳ 확인: afl-fuzz (v4.09c+), afl-clang-fast --version (clang 17), gcc, gold(ld.gold)
# CASR (casr-gdb 2.13.1) — 크래시 버킷팅
cargo install casr        # 또는 배포 바이너리. 확인: casr-gdb --version
# (선택) Melkor 베이스라인
git clone https://github.com/IOActive/Melkor_ELF_Fuzzer && (cd Melkor_ELF_Fuzzer && make)
```

## 2. 계측 링커(SUT) 빌드 — afl-clang-fast + -g
검증된 버전: GNU Binutils 2.42. 소스는 아카이브 풀거나 `apt source binutils`.
```bash
tar xf binutils_2.42.orig.tar.xz            # → binutils-2.42/
# --- (A) bfd ld (계측) ---
mkdir build-afl-bfd && cd build-afl-bfd
CC=afl-clang-fast CFLAGS='-O2 -g -Wno-error' \
  ../binutils-2.42/configure --disable-gold --disable-shared \
      --disable-werror --disable-multilib --disable-nls
make -j$(nproc)          # → ld/ld-new   (with debug_info, not stripped)
cd ..
# --- (B) gold (계측; C++ 라 CXX 도 afl) ---
mkdir build-afl-gold && cd build-afl-gold
CC=afl-clang-fast CXX=afl-clang-fast++ CFLAGS='-O2 -g -Wno-error' CXXFLAGS='-O2 -g -Wno-error' \
  ../binutils-2.42/configure --enable-gold=default --disable-shared \
      --disable-werror --disable-multilib --disable-nls
make -j$(nproc)          # → gold/ld-new
cd ..
# 확인: 디버그정보 있어야 CASR 백트레이스에 심볼이 뜬다
file build-afl-bfd/ld/ld-new        # ... with debug_info, not stripped
readelf -S build-afl-bfd/ld/ld-new | grep debug_info   # .debug_info 존재
```
> **왜 -g 인가**: 없으면 gdb/CASR 백트레이스가 `#0 0x.. in ??` 뿐 → (signal,frame)
> 버킷팅 무의미. -g 라야 `_bfd_elf_slurp_version_tables` 같은 심볼로 분류된다.

## 3. 시드 + main.o
```bash
cd $REPO/lfuzzer/differential/exp_e4_verneed
gcc -shared -fPIC -Wl,--version-script=libv.map -o /tmp/seed/libv.so libv.c   # 버전정보 있는 .so
printf 'extern int foo(); int _start(){return foo();}\n' > /tmp/seed/main.c
gcc -c -fPIC -nostdlib -o /tmp/seed/main.o /tmp/seed/main.c
```

## 4. AFL dictionary (numbers.py 위험값)
```bash
cd $REPO
python3 -m lfuzzer.coverage.gen_afl_dict lfuzzer/coverage/elf.dict
```

## 5. 캠페인 실행 (제안 vs no-feedback vs Melkor)
```bash
export PYTHONPATH=$REPO
# ⚠ WSL2 주의: /tmp 는 tmpfs → distro 셧다운 시 소실. 영속 경로(~/lfuzz_run) 사용.
RUN=~/lfuzz_run; mkdir -p $RUN/seeds; cp /tmp/seed/{libv.so,main.o} $RUN/; cp /tmp/seed/libv.so $RUN/seeds/
BUDGET=3600 KIND=gold RUN=$RUN \
  LD=$PWD/build-afl-gold/gold/ld-new \
  SEED_SO=$RUN/libv.so MAIN_O=$RUN/main.o MELKOR_SEED=<유효.elf> \
  bash lfuzzer/coverage/run_campaign.sh
# → $RUN/camp/REPORT.md (CASR 고유버킷 표). bfd 는 KIND=bfd, LD=build-afl-bfd/ld/ld-new
```
개별 실행:
- 제안(피드백 ON): `lfuzzer/coverage/run_afl.sh gold`  (env LD_GOLD 로 경로 지정)
- no-feedback(blind 대조): `python3 -m lfuzzer.coverage.run_nofeedback --target gold --ld <gold> --main-o main.o --seeds seeds --seconds 3600`
- 조기기각률: `python3 -m lfuzzer.coverage.measure_early_reject --ld <ld> --main-o main.o --inputs <mut_dir>`

## 6. gold 크래시 CASR 분류 (단독)
```python
from lfuzzer.triage.gold_casr import LinkerCasrDedup
dd = LinkerCasrDedup(linker="build-afl-gold/gold/ld-new", main_o="main.o", kind="gold")
print(dd.bucket("crash.so").bucket_key)   # 예: gold:casr:SourceAvNearNull:685f0ab1
```

## 7. 환경 (참고 — 우리 실측 기준)
| 항목 | 값 |
|------|----|
| WSL | 2.6.3.0 (WSL2) / kernel 6.6.87.2-1 |
| OS | Ubuntu 24.04.1 LTS |
| binutils(ld/gold) | 2.42 / gold 1.16 |
| glibc(ld.so) | 2.39 |
| AFL++ | 4.09c | 
| clang(afl-clang-fast) | 17.0.6 |
| casr-gdb | 2.13.1 |

## 8. 기대 결과 (우리 1h 실측, gold SUT)
| 기법 | 원시 크래시 | CASR 고유버킷(40샘플) |
|------|-----------:|---------------------:|
| 제안(4축+afl 피드백) | 67 | 16 |
| no-feedback(동일뮤테이터 blind) | 19,765 | 4 |
| Melkor(규칙기반) | 810 | 3 |
> 원시 크래시 수는 arm 간 직접 비교 불가(afl=커버리지고유 저장, blind=내용고유 전부).
> 공정 지표 = CASR 고유버킷. 상세 lfuzzer/coverage/TABLE1_RESULTS.md.
