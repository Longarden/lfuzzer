# 경험적 gold↔bfd 출력 델타 (track B 그라운드트루스) — libfoo 샘플

샘플: `sources/foo.c` (전역변수 + __thread TLS + 2함수) → `-fPIC -shared`, `-fuse-ld=bfd|gold`.
출력 크기: **libfoo_bfd.so=15776B vs libfoo_gold.so=7776B** (gold 절반). DYNAMIC 태그 수 bfd 25 / gold 27.

## S1 DYNAMIC — 태그 집합 델타
- gold에만: **DT_VERDEF, DT_VERDEFNUM** (gold이 베이스 버전정의를 방출, bfd은 안 함)
- → ld.so 함의: gold 출력은 `dl-version.c` verdef 처리 경로 진입, bfd 출력은 안 함. **런타임 차등 후보 #2.**

## S2 PHT — 세그먼트 순서/집합 델타 (★최강)
- bfd:  LOAD×4, DYNAMIC, NOTE×2, TLS, **GNU_PROPERTY**, GNU_EH_FRAME, GNU_STACK, GNU_RELRO
- gold: **PHDR**, LOAD×2, DYNAMIC, NOTE×2, GNU_EH_FRAME, GNU_STACK, TLS, GNU_RELRO
- 델타:
  1. **PT_GNU_PROPERTY: bfd 방출 / gold 미방출** → ld.so `_dl_process_pt_gnu_property`(dl-load.c) 실행 갈림. **런타임 차등 후보 #1(최강).**
  2. **LOAD 개수 4(bfd) vs 2(gold)** → 런타임 mmap/mprotect 횟수·매핑 경계 차이(관측가능 부작용).
  3. **PT_PHDR: gold의 .so엔 있음 / bfd .so엔 없음** → PHDR 세그먼트 자체 유무.
  4. TLS 세그먼트 순서 위치 다름.

## S3 SHT — 섹션 델타 (분석기전용 예상)
- bfd에만: `.plt.got`, `.plt.sec`
- gold에만: `.gnu.version_d`(=DT_VERDEF 대응), `.note.gnu.*`, `.tm_clone_table`
- 섹션 수 bfd 32 / gold 33.
- 가설: SHT 차이는 런타임 ld.so 무관(분석기 readelf/objdump만 봄). `.gnu.version_d`만 DT_VERDEF와 묶여 런타임 의미有 — 검증 필요.

## 다음(통합): 6 survey가 이 델타들의 "왜(소스 file:line)"를 채우면 SUMMARY로 병합.
## ld.so 실험 1순위: PT_GNU_PROPERTY(#1) → main_bfd vs main_gold를 debug ld.so로 돌려 _dl_process_pt_gnu_property 진입 여부 gdb 실측.
