# SUMMARY — gold vs bfd 출력 차등 → 동적 링커(ld.so) 반응 (3면 전수)

## 한 줄 결론
**같은 소스를 gold/bfd로 링크한 두 정상(valid) 출력인데, 링커에 따라 ld.so가 실제로 다른 코드경로를 밟는다.**
가장 강한 실측 증거: `_dl_process_pt_gnu_property` 호출 **bfd 4회 : gold 1회**. 3면 민감도 = DYNAMIC·PHT(런타임 영향) > SHT(분석기 전용).

## 방법
6 survey(3면 S1 DYNAMIC/S2 PHT/S3 SHT × 2링커, scientist sonnet 병렬) 소스 전수 + readelf 교차검증 + debug ld.so(glibc2.39) gdb 실측.
샘플: `sources/foo.c`(전역변수+__thread TLS+2함수) → `-fPIC -shared`, `-fuse-ld=bfd|gold`. 출력크기 bfd 15776B / gold 7776B.

## 3면 Differential Map
### S1 · DYNAMIC (ld.so가 elf_get_dynamic_info로 직접 소비 = 1순위)
| 항목 | bfd | gold | ld.so 영향 | 근거 |
|---|---|---|---|---|
| 태그 set | (기본) | **+DT_VERDEF/VERDEFNUM** | ○ gold만 dl-version.c 버전정의 처리 | S1gold layout.cc:5066-5069 / readelf |
| 태그 순서 | NEEDED→INIT→…RELACOUNT(끝) | PLTGOT/RELA→…RELACOUNT(8번째) | △ 대부분 중립(l_info 태그 디먹스), 단 DT_NEEDED 순서는 로드순서 영향 | 양 덤프 |
| INIT/FINI_ARRAY 순 | INIT_ARRAY 먼저 | FINI_ARRAY 먼저 | △ 중립(디먹스) | 덤프 |
| DT_RELR | -z pack-relative-relocs로 가능 | **미지원**(2.42, grep 0건) | ○ 켜면 ld.so RELR 재배치 경로 vs 불가 | S1gold(부재확인) |
결론: DYNAMIC은 **순서차=분석기 관점 / VERDEF·NEEDED·RELR=런타임 관점**으로 갈림.

### S2 · PHT (ld.so가 매핑/하드닝에 사용 = 최다 런타임 차등)
| 항목 | bfd | gold | ld.so 영향 | 근거 |
|---|---|---|---|---|
| **PT_GNU_PROPERTY** | **방출**(전용 세그먼트) | **미방출**(PT_GNU_PROPERTY 코드 자체 없음) | ●● `_dl_process_pt_gnu_property` 실행 여부 = CET/shadow-stack 하드닝 협상 | S2bfd elf.c:5669-5685 / S2gold(부재) |
| PT_LOAD 개수 | 4 | 2 | ○ 매핑(mmap/mprotect) 경계·횟수 | 양 phdr 덤프 |
| PT_PHDR(.so) | 없음(.interp 없어서) | 생성 | ○ AT_PHDR 경로 | S2 양측 |
| 세그먼트 순서 규칙 | 생성(코드실행) 순 | PT_ type값 오름차순 | △ 대부분 중립 | S2bfd elf.c:5990/6107, S2gold segment_precedes:3733 |
| PT_GNU_RELRO align/flags | align=1 | "RW/4"(bfd 소스가 gold과 다름을 주석 명시) | ○ RELRO 보호범위/정렬 | S2bfd elf.c:6833-6836 |
결론: **S2가 런타임 차등의 본진.** PT_GNU_PROPERTY가 헤드라인.

### S3 · SHT (ld.so가 런타임에 안 읽음 = 분석기 전용/evasion 축)
| 항목 | bfd | gold | ld.so 영향 | 근거 |
|---|---|---|---|---|
| 섹션 set | +.plt.sec/.plt.got | +.gnu.version_d/.tm_clone_table/**.note.gnu.gold-version**(자가식별) | ✗ 없음 | S3 양측 |
| 섹션 순서 | 리스트 순(ldlang) | 세그먼트→ORDER_* 2단 | ✗ 없음 | S3gold output.cc:320 |
| sh_link/sh_info 연결 | .plt→.got.plt 등 | 동등 메커니즘 | ✗ 없음 | S3 양측 |
결론: **양 survey 독립적으로 "ld.so는 AT_PHDR/PT_DYNAMIC만 읽고 SHT/e_shoff 안 봄" 확정** → SHT 차이는 전부 **분석기(readelf/objdump/ghidra) 전용 = evasion 축**(교수님 7/03 프레이밍의 정확한 자리).

## 검증된 FINDING
- **#1 PT_GNU_PROPERTY 4:1 (실측 확정, ldso_traces/FINDING_01):** gdb per-객체 트레이스 — bfd출력은 main·libfoo·libc(4회), gold출력은 libc뿐(1회). 두 프로그램 출력·exit(12) 동일. 보안: gold-링크는 CET/shadow-stack 하드닝 협상을 로더에 못 알림. 소스원인 S2에서 확증.
- **#2 DT_VERDEF (구조 확정):** gold만 베이스 버전정의 방출 → ld.so `dl-version.c _dl_check_map_versions` 소비 경로가 gold출력엔 존재. (후속: gdb 실측 예정.)

## 3면 민감도 스펙트럼 (핵심 스토리 = 논문 뼈대)
```
DYNAMIC (직접소비)  ●●●  VERDEF·NEEDED·RELR·FLAGS → 로더 반응
PHT     (매핑/하드닝) ●●  PT_GNU_PROPERTY·LOAD수·RELRO → 로더 반응 (본진)
SHT     (미사용)     ✗   전부 분석기 전용 → evasion 축
```
"퍼저가 뮤테이트하는 3면"이 곧 "로더가 얼마나 신경쓰나"의 스펙트럼 = 어디를 건드리면 런타임 차등이고 어디가 evasion인지의 지도.

## 정직한 한계
- 샘플 1개(libfoo). feature 매트릭스(TLS 심화·IFUNC·버전스크립트·-z pack-relative-relocs·PIE 실행파일) 확장 필요.
- **S1bfd 워커 미복귀** → bfd DYNAMIC은 readelf 덤프 + elflink.c로 대체 확인함(태그 set/순서 확정).
- gold 2.42 기준. #1의 "gold이 PT_GNU_PROPERTY를 원래 안 만드는가(기본)"인지 플래그/버전 이슈인지 미확정.
- 소스트리(gold/layout.cc:5325 등)에 **이전 Claude 세션이 주입한 한국어 학습주석** 존재(S1gold 보고) — upstream binutils 아님. 기술 findings는 전부 실제 코드라인 기준. 그 주석 내용은 인용 주의.
