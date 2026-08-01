# FINDING #1 — PT_GNU_PROPERTY: 링커별 런타임 하드닝 경로 차등 (실측 확정)

## 한 줄
같은 소스(foo.c/main.c)를 bfd/gold로 링크한 두 **정상** 출력을, 같은 debug ld.so(glibc 2.39)로
실행하니 `_dl_process_pt_gnu_property` 호출이 **bfd 4회 vs gold 1회**로 갈림. 프로그램 결과는 동일.

## 구조적 근거 (readelf, track B)
- PT_GNU_PROPERTY 세그먼트: main_bfd=1, libfoo_bfd.so=1 / main_gold=0, libfoo_gold.so=0
- 즉 **bfd은 PT_GNU_PROPERTY 방출, gold은 미방출.**

## 런타임 실측 (gdb + ~/glibc/build-dbg/elf/ld.so, ldso_traces/prop.gdb)
`_dl_process_pt_gnu_property`(dl-load.c:868) 브레이크포인트에 `l->l_name` 로깅:
```
BFD :  name=[]            fd=3   (main_bfd)
       name=[]            fd=-1  (main_bfd, 2nd pass)
       name=[./libfoo_bfd.so] fd=3
       name=[libc.so.6]   fd=3
GOLD:  name=[libc.so.6]   fd=3   (그게 전부)
```
두 프로그램 다 "hello from foo" 출력 + exit 12(=2+3+7) 동일.

## 오라클 정밀화 교훈 (스펙 반영됨)
프로세스 레벨 "브레이크포인트 히트 여부"로는 못 가림 — **libc가 항상 PT_GNU_PROPERTY를 가져서
둘 다 최소 1회 히트.** 반드시 **per-객체(l->l_name)** 로 봐야 링커가 만든 객체의 차이가 드러남.

## 의미 / 보안 각
`_dl_process_pt_gnu_property`는 GNU_PROPERTY_X86_FEATURE_1(CET IBT / shadow stack) 등 하드닝을
로더에 알리는 경로. gold 출력엔 이 프로퍼티가 없어 로더가 해당 객체에 대해 하드닝 협상을 안 함
→ **링커 선택이 런타임 보안 속성을 조용히 바꾼다**는 정직한 differential.

## 남은 검증 (정직)
- gold 2.42의 이 동작이 (a) 기본값인지 (b) `-z` 플래그/버전으로 바뀌는지 확인 (bfd은 기본 방출).
- 실제로 CET 강제가 꺼지는지(커널/하드웨어 CET 있는 환경에서) 행동 재현.
- main의 fd=-1 2차 호출 의미 추적(초기 매핑 vs 재배치 단계).
