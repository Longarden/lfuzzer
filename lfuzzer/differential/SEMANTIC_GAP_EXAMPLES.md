# Semantic Gap 실측 예시 모음 (로더 vs 분석기 / 링커 vs 링커)

> **목표 저장 위치**: `lfuzzer/differential/SEMANTIC_GAP_EXAMPLES.md` (이 파일을 그 경로로 옮기면 됨. 백그라운드 isolation 가드 때문에 우선 바탕화면에 산출)
>
> 목적: 논문 §4.2(링커 차등)·§4.3(해석 사각지대) 작성용으로, **저장된 실측 데이터에 근거한** 재현 가능한 예시만 정리한다. 지어낸 예시 없음. 각 예시는 파일 경로·재현 명령·관찰 포인트를 포함.
>
> **범위 결정(2026-08-27 확정)**: SUT = **GNU ld(bfd) + gold** 두 링커. semantic gap 축 = **런타임 로더(ld.so) vs 정적 분석기**.
>
> **정직성 플래그**: binutils `readelf`는 51,762개 뮤턴트 스윕에서 **크래시·행 0건, 완전 견고**(`parser_diff/SUMMARY.txt:4`). 따라서 readelf는 semantic gap의 "무력화되는 분석기"로 쓸 수 없다. 논문 sh_info=0xFFFFFFFF DoS도 readelf가 아니라 **llvm-objdump**가 터진 것이다.

---

## 요약 표

| # | 예시 | 축 | 논문 섹션 | 저장 데이터 |
|---|------|-----|-----------|-------------|
| ① | llvm-objdump DoS (무한루프) vs ld.so 정상 | **로더 vs 분석기** | §4.3 해석 사각지대 | `parser_diff/` (33건 rc137) |
| ② | bfd fail-fast vs gold fail-slow (verneed) | 링커 vs 링커 | §4.2 링커 차등 | `exp_e4_verneed/FULL_TRANSCRIPT.txt` (트랜스크립트 저장됨) |
| ③ | Ghidra 64→32bit 값 절단 vs readelf | 분석기 값오류 | §4.3 보조 | `exp_goldbfd_diff/exp_r7_ghidra_dtag.py` |

> 사용자 요청 예시는 ②③. ①은 "로더 vs 분석기" 프레이밍에 **정확히 맞는** 예시라 함께 수록(§4.3 본체). 셋 다 SUT 범위(ld+gold)와의 관계를 각 항목에 명시한다.

---

## ① 로더 vs 분석기 — llvm-objdump DoS vs ld.so 정상  (§4.3 본체)

**한 줄**: PT_DYNAMIC의 `p_filesz`/`p_offset`를 조작한 ELF를 **정적 분석기 llvm-objdump 18.1.3**에 넣으면 무한루프(행)로 서비스 거부되지만, 동일 파일이 **런타임 로더 ld.so**에서는 정상 처리된다 → 정적 분석 우회.

- 관찰 데이터: `parser_diff/SUMMARY.txt:4-10` — 5개 파서(readelf/objdump/nm/pyelftools/llvm-objdump) × 51,762 뮤턴트.
  - readelf/objdump/nm: **0 크래시 (완전 견고)**
  - llvm-objdump 18.1.3: **33건 HANG (무한루프 DoS)**, 전부 DYNAMIC `p_filesz`/`p_offset` (+`e_phnum=0xffff`, 거대 `.symtab sh_size`)
- 행 유발 입력 33건 목록: `parser_diff/crashers/ALL_33_paths.txt` (rc=137, 전부 `seg6_p_filesz`/`seg6_p_offset`)
- 저장된 크래셔 아티팩트: `parser_diff/crashers/rv_verneed_maxinfo` (390KB PIE, `.gnu.version_r sh_info=0xFFFFFFFF` — 이것도 **llvm-objdump** DoS 입력이지 readelf 실패 아님)

**재현 (Linux/WSL)**:
```bash
cd lfuzzer/differential/parser_diff
# 저장된 행 유발 입력 하나 선택
IN=$(head -1 crashers/ALL_33_paths.txt)
# 분석기: 무한루프 → timeout으로 감지 (rc 124/137)
timeout 10 llvm-objdump-18 -d "$IN"; echo "objdump rc=$?"   # HANG
# 로더: 정상 (또는 즉시 정상 거부, DoS 아님)
timeout 10 /lib64/ld-linux-x86-64.so.2 --verify "$IN"; echo "ldso rc=$?"
readelf -a "$IN" >/dev/null; echo "readelf rc=$?"           # 0, 견고
```
**관찰 포인트**: objdump는 timeout(행), ld.so/readelf는 정상 종료 → 동일 메타데이터를 정적 도구만 무력화.

> **SUT 범위 주의**: llvm-objdump는 확정 SUT(ld+gold) 밖이다. 이 예시를 §4.3에 넣으려면 "정적 분석기 대표 사례"로 별도 위치시키고, 메인 실험(ld+gold)과 구분해 서술할 것.

---

## ② 링커 vs 링커 — bfd fail-fast vs gold fail-slow (verneed vna_next)  (§4.2)

**한 줄**: `.gnu.version_r`의 `vna_next`(Verneed→Vernaux 연결리스트 "다음 엔트리까지 오프셋")를 `0 → 0x7ffffff0`으로 조작하면, **bfd와 gold 둘 다 거부**하지만 **거부 시점이 다르다** — bfd는 깨진 라이브러리에서 즉시 중단, gold는 거부하고도 뒤따르는 유효 입력을 계속 처리한다. 종료코드(1/1)·시간(0.00s) 동일해서 **`--trace-symbol` 출력으로만 갈린다.**

- 저장 트랜스크립트: `exp_e4_verneed/FULL_TRANSCRIPT.txt`
  - 정적 뷰(견고): `:18-22` readelf `-V`가 클린 lib의 Verneed 정상 출력 (`Cnt:1 … GLIBC_2.2.5`)
  - 뮤테이션: `:28-29` `vna_next @ 파일오프셋 0x4c4: 0 → 2147483632 (0x7ffffff0)`
  - **bfd (fail-fast)** `:51-56`:
    ```
    ld-new: ./libv_corrupt.so: .gnu.version_r invalid entry
    ld-new: ./libv_corrupt.so: error adding symbols: bad value   (BFD_EXIT=1, 출력파일 없음)
    ```
  - **gold (fail-slow)** `:59-63`:
    ```
    ld-new: error: ./libv_corrupt.so: verneed vna_next field out of range: 2147483632   (GOLD_EXIT=1)
    ```
  - **차등 프로브** `:74-84`: 링크순서 `main2.o libv_corrupt.so(BROKEN) libw.so(FINE)` + `--trace-symbol=bar`
    - bfd: 깨진 obj 전에서 중단 → `./libw.so: definition of bar` **안 찍음** (`:75-78`)
    - gold: 깨진 verneed 거부하고도 뒤 라이브러리 계속 → `./libw.so: definition of bar` **찍음** (`:83`)
  - 프로브 근거 주석: `run_experiment.sh:145-159`
- 필요 링커: `~/binutils-build-afl-bfd-clean/ld/ld-new` (bfd), `~/binutils-build-gold/gold/ld-new` (gold) — `run_experiment.sh:30-31`

**재현 (Linux/WSL)**:
```bash
cd lfuzzer/differential/exp_e4_verneed
bash run_experiment.sh          # 6단계 end-to-end 자동
# --- 또는 핵심 단계 수동 ---
gcc -shared -fPIC -Wl,--version-script=libv.map -o libv.so libv.c
readelf -V libv.so                                        # 정적 뷰: 견고, Verneed 정상
python3 corrupt_verneed.py libv.so libv_corrupt.so        # vna_next 0 -> 0x7ffffff0
# 단일 조작 입력 — 두 링커의 서로 다른 메시지 관찰
~/binutils-build-afl-bfd-clean/ld/ld-new -shared -o /dev/null main.o  -L. -lv_corrupt   # "invalid entry / bad value"
~/binutils-build-gold/gold/ld-new        -shared -o /dev/null main.o  -L. -lv_corrupt   # "vna_next field out of range: 2147483632"
# THE 프로브 — 이것만이 갭을 드러냄
~/binutils-build-afl-bfd-clean/ld/ld-new -shared -o /dev/null main2.o -L. -lv_corrupt -lw --trace-symbol=bar  # libw 줄 없음(fail-fast)
~/binutils-build-gold/gold/ld-new        -shared -o /dev/null main2.o -L. -lv_corrupt -lw --trace-symbol=bar  # "./libw.so: definition of bar" 찍힘(fail-slow)
```
**관찰 포인트**: 종료코드·시간이 같아도 `--trace-symbol=bar` 출력 유무로 소비 범위 차이(입력 그래프를 어디까지 읽고 거부하는가)가 드러난다. readelf는 같은 테이블을 문제없이 파싱 → 링커만 갈림.

---

## ③ 분석기 값 절단 — Ghidra 64→32bit truncation vs readelf  (§4.3 보조)

**한 줄**: 64bit `d_tag = 0xDEADBEEFFFFFFFFD`를 **Ghidra**는 `0xfffffffd`로 절단해 표시하고, **readelf**는 `<unknown>`으로 표시한다 → 같은 필드를 정적 분석기가 서로 다른 값으로 해석.

- 스크립트: `exp_goldbfd_diff/exp_r7_ghidra_dtag.py`
- 명령 메뉴: `exp_goldbfd_diff/RUN_ALL_COMMANDS.md:49-51`
- 관련: `exp_r8_ghidra_symcount` — `nchain` 위조 파일에서 Ghidra 동적심볼 43개 vs readelf 7개 (`pipeline_runs/SUMMARY.md:33`)

**재현 (Linux/WSL, Ghidra headless 필요)**:
```bash
cd lfuzzer/differential/exp_goldbfd_diff
python3 exp_r7_ghidra_dtag.py     # d_tag 0xDEADBEEFFFFFFFFD 주입 ELF 생성 + 두 분석기 비교
# 관찰: readelf -d 는 <unknown> (0xDEADBEEFFFFFFFFD 전체), Ghidra 는 0xfffffffd (하위 32bit)
readelf -d <생성된.elf> | grep -i unknown
```
**관찰 포인트**: 값 절단 방향의 semantic gap(정적 도구 간 불일치). §4.3에서 "정적 도구도 필드 해석이 갈린다"의 보조 실증.

---

## 부록: 다른 저장된 링커 차등 (bfd rc / gold rc, `pipeline_runs/SUMMARY.md`, 2026-07-22 측정)

| Exp | 필드 | bfd | gold | 비고 |
|-----|------|-----|------|------|
| d03 | PIE / ET_DYN | 1 | 0 | 갈림 ✓ (`:7`) |
| d06 | malformed verdef | 0 | 1 | bfd fail-fast (`:10`) |
| d11 | `e_shstrndx` OOB | 0 | 1 | 갈림 ✓ (`:15`) |
| d13 | verdef `vd_version` | 0 | 1 | bfd 무검사/gold 게이트 (`:17`) |
| d15 | verdef `vd_cnt=0` | 0 | 1 | gold만 거부(엄격성 역전) (`:19`) |
| d22 | DT_RUNPATH | 0 | 1 | 갈림 ✓ (`:25`) |
| d24 | DT_RPATH | 0 | 1 | 갈림 ✓ (`:27`) |

런타임 차등(gdb 실측): **PT_GNU_PROPERTY 로더경로 4:1** — bfd는 PT_GNU_PROPERTY 세그먼트 방출, gold는 안 함 → 디버그 ld.so에서 `_dl_process_pt_gnu_property`(dl-load.c:868) 히트가 bfd 4회 vs gold 1회. 근거 `archive/gold_bfd_output_diff/ldso_traces/FINDING_01_pt_gnu_property.md:1-19`. 보안 함의: gold 링크 산출물은 CET/shadow-stack 협상을 조용히 건너뜀.

---

## 열린 작업 (별도 /deep-dive로 확정 예정)

- **gold도 CASR 분류** — 현재 CASR는 ld.so 로더 경로만 버킷팅(`triage/casr_dedup.py:121`), gold/bfd는 rc-diff 보조증거로만 사용(`triage/tri_oracle.py:12-14`). "gold도 CASR로 분류" = casr를 gold 실행에도 겨누는 **신규 작업**.
- **표1 비교측정** — 커버리지 입도·시간예산·버킷정의(CASR threshold 0.3)·조기기각 정의는 비교측정 전용 /deep-dive에서 확정.
