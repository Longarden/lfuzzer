# Gold vs BFD + readelf/Ghidra differential 실험 (교수님 1번 과제)

소스 대질(아티팩트 D01~D24, R1~R9)에서 예측한 "링커/분석기별로 다르게 동작하는 ELF"를
**직접 돌려 확인**한다. 방법: 소스로 예측 → 실험으로 확인(블랙박스 단독은 차이를 놓친다).
전 27개 실험, 전부 `./exp_xxx.py` 로 바로 실행 가능(shebang + 실행권한 부여됨).

## 직접 실행
```
cd ~/PE/Lfuzzer/exp_goldbfd_diff
./exp_d03_pie.py            # 개별 (또는 python3 exp_d03_pie.py)
bash run_all.sh            # 4개 핵심만 일괄
```
결과 판독: 각 출력의 **`>>> DIVERGED <<<`** 와 **`BFD rc / GOLD rc`** 줄, 맨 끝 **`결론:`** 줄.

의존: gcc readelf objdump valgrind patchelf python3-pyelftools radare2
링커: BFD=`~/binutils-build-afl-bfd-clean/ld/ld-new` · GOLD=`~/binutils-build-gold/gold/ld-new`
Ghidra(R7/R8): `~/ghidra_12.1.2_PUBLIC` (설치됨, sudo 불필요 — 다운로드+압축해제만, Java 21 사용)

## gold vs bfd 링크타임 (입력 .so 소비 차이) — 17개
| 실행 | 차이 | 예측 (BFD vs GOLD) | 상태 |
|---|---|---|---|
| `./exp_d03_pie.py` | D03 PIE 입력 | BFD 거부 / GOLD 수락 | ✅실측 적중 |
| `./exp_d22_runpath.py` | D22 입력 RUNPATH | BFD 성공 / GOLD 실패 | ~부분(사유 혼입) |
| `./exp_d02_dynstr_nonul.py` | D02 끝-NUL 없는 .dynstr | GOLD over-read | ✗미재현 |
| `./exp_d19_justsymbols.py` | D19 --just-symbols on DSO | (반증) | ✗둘 다 거부(REFUTED) |
| `./exp_d01_strip_sht.py` | D01 섹션헤더 제거 | BFD 심볼재구성 / GOLD 0 | CONFIRMED |
| `./exp_d04_audit.py` | D04 DT_AUDIT | BFD 읽음 / GOLD 무시 | CONFIRMED |
| `./exp_d05_verneed_edge.py` | D05 버전 끝-근처 | GOLD over-read | PLAUSIBLE |
| `./exp_d06_malformed_verdef.py` | D06 손상 verdef | GOLD fail-slow / BFD fail-fast | CONFIRMED |
| `./exp_d07_dt_hash_nchain.py` | D07 DT_HASH nchain | BFD 신뢰 / GOLD 무관 | CONFIRMED |
| `./exp_d08_gnuhash_maskwords.py` | D08 GNU_HASH maskwords | BFD 무검증 / GOLD 무관 | CONFIRMED |
| `./exp_d10_shnum_zero.py` | D10 e_shnum=0 sh_size | BFD 거부 / GOLD 신뢰 | CONFIRMED |
| `./exp_d11_shstrndx_oob.py` | D11 e_shstrndx 범위밖 | BFD 검사 / GOLD 역참조 | CONFIRMED |
| `./exp_d12_symname_oob.py` | D12 심볼이름 오프셋 | GOLD over-read | PLAUSIBLE |
| `./exp_d13_vd_version.py` | D13 vd_version 오류 | GOLD 거부 / BFD 무검증 | CONFIRMED |
| `./exp_d14_vd_ndx_zero.py` | D14 vd_ndx=0 | GOLD 수락 / BFD 거부 | CONFIRMED |
| `./exp_d15_vd_cnt_zero.py` | D15 vd_cnt=0 | GOLD 거부 / BFD 관대 | CONFIRMED |
| `./exp_d16_next_zero.py` | D16 next=0 체인 | GOLD 재읽기 / BFD break | PLAUSIBLE |
| `./exp_d17_et_core.py` | D17 ET_CORE | GOLD hard-error / BFD wrong-format | CONFIRMED |
| `./exp_d20_dt_syment.py` | D20 DT_SYMENT | BFD 거부 / GOLD 무시 | CONFIRMED |
| `./exp_d21_strindex_zero.py` | D21 strindex=0 | GOLD 역참조 / BFD "" | PLAUSIBLE |
| `./exp_d23_etrel_no_sht.py` | D23 ET_REL e_shoff=0 | GOLD 수락 / BFD 거부 | CONFIRMED |
| `./exp_d24_rpath.py` | D24 입력 RPATH | BFD 읽음 / GOLD 무시 | CONFIRMED |
| `./exp_d09_osabi.py` | D09 EI_OSABI 이질 | BFD 벡터 거부 / GOLD 수락 | CONFIRMED |

## readelf / Ghidra DISPLAY 축 — 관측/Ghidra
| 실행 | 차이 | 볼 것 |
|---|---|---|
| `./exp_display_all.py` | R1~R4,R9 | readelf -d(SHT) vs -D(PT_DYNAMIC) vs objdump vs r2 나란히 |
| `./exp_r1_decoy_dynamic.py` | R1 | SHT .dynamic decoy → readelf -d 가 PT_DYNAMIC과 갈리나 |
| `./exp_r5_phdr_vs_sht.py` | R5 | sh_addr 어긋냄 → readelf -S vs r2(로더뷰) 주소 갈림 |
| `./exp_r6_ehdr_unknown_enum.py` | R6 | e_machine 미지값 → readelf 표시 vs objdump 거부 |
| `./exp_r7_ghidra_dtag.py` | R7 | **✅라이브 실증**: 0xDEADBEEFFFFFFFFD → Ghidra 0xfffffffd(절단), readelf `<unknown>` |
| `./exp_r8_ghidra_symcount.py` | R8 | Ghidra dynsym 수(nchain 근원) vs readelf(sh_size) 비교 |

Ghidra 스크립트: `ghidra_scripts/DumpDynamic.java` (Java GhidraScript — Ghidra 12는 Jython 폐기).

## 재검증 상태 (2026-07-22, 34에이전트 적대적)
33주장 중 **31 유지**: 26 CONFIRMED · 5 PLAUSIBLE(D05·D12·D16·D21·R9) · **2 REFUTED**(삭제 대상):
D18(gold도 e_shentsize 검사) · D19(gold도 --just-symbols DSO 거부 — 실험도 확인).

## 정직한 한계
- 링크타임만 — 런타임 로더(ld.so) 다리는 별개. · binutils-2.42 한 버전. · Ghidra 12.1.2.
- D02/D05/D12 over-read류는 "링커가 입력의 SONAME/버전을 실제 읽는 경로"에 닿아야 재현.
- R7만 라이브 실증 완료(Ghidra). 나머지 D0x/Rx 는 작성됨 — 직접 `./` 로 돌려 결론 줄 확인.
