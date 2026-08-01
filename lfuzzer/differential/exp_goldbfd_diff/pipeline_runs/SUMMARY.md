# 전 실험 파이프라인 실측 (2026-07-22 15:21)

| 실험 | BFD rc | GOLD rc | DIVERGED | 결론 |
|---|---|---|---|---|
| exp_d01_strip_sht | 1 | 1 | - | 안 갈림 — 재확인 필요 |
| exp_d02_dynstr_nonul | 1 | 0 | Y | over-read 미관찰 — valgrind 설치/SONAME 배치·읽� |
| exp_d03_pie | 1 | 0 | Y | 예측대로 갈림 ✓ |
| exp_d04_audit | 0 | 0 | - | 링크타임 안 갈림 — LD_DEBUG/strace 로더 관찰로 |
| exp_d05_verneed_edge | 1 | 0 | Y | 재확인 필요(verneed 소비 경로 미도달 — docstri |
| exp_d06_malformed_verdef | 0 | 1 | Y | 예측대로 갈림 ✓ (bfd fail-fast vs gold fail-slow) |
| exp_d07_dt_hash_nchain | 1 | 1 | - | 안 갈림 — 재확인 필요 |
| exp_d08_gnuhash_maskwords | 1 | 1 | - | 안 갈림 — 스트립/폴백 경로 재확인 필요 |
| exp_d09_osabi | 0 | 0 | - | 안 갈림 — 재확인 필요(빌드 링커 OSABI 완화 � |
| exp_d10_shnum_zero | 1 | 1 | - | 안 갈림 — sh_size 값/경로 재확인 필요 |
| exp_d11_shstrndx_oob | 0 | 1 | Y | 예측대로 갈림 ✓ |
| exp_d12_symname_oob | 1 | 1 | - | GOLD OOB 미검출 — new_stname 값/심볼 선택/valgrind |
| exp_d13_vd_version | 0 | 1 | Y | 예측대로 갈림 ✓ (bfd 무검사 / gold 게이트) |
| exp_d14_vd_ndx_zero | 0 | 0 | - | 안 갈림 — 재확인 필요 |
| exp_d15_vd_cnt_zero | 0 | 1 | Y | 예측대로 갈림 ✓ (GOLD 만 거부 → 반전된 엄� |
| exp_d16_next_zero | 1 | 1 | - | 안 갈림 — 링커가 verdef 체인을 소비 안 하거� |
| exp_d17_et_core | 1 | 1 | - | 안 갈림 — 재확인 필요 |
| exp_d19_justsymbols | 1 | 1 | - | 안 갈림 — 재확인 필요 |
| exp_d20_dt_syment | 1 | 1 | - | 안 갈림 — 재확인 필요 |
| exp_d21_strindex_zero | 0 | 0 | - | 안 갈림 — 재확인 필요(소스라인/오염전제 � |
| exp_d22_runpath | 0 | 1 | Y | 예측대로 갈림 ✓ |
| exp_d23_etrel_no_sht | 1 | 1 | - | 안 갈림 — stderr 문구로 재확인 필요 |
| exp_d24_rpath | 0 | 1 | Y | 예측대로 갈림 ✓ |
| exp_display_all | ? | ? | - | 두 파일의 -d(SHT) vs objdump -T/r2 idj(PT_DYNAMIC) 태� |
| exp_r1_decoy_dynamic | 1 | 1 | - | 안 갈림 — readelf 가 섹션헤더 대신 세그먼트� |
| exp_r5_phdr_vs_sht | 0 | 0 | - | 판정 불가 — readelf=0000000000002040 r2=(r2 미설치) |
| exp_r6_ehdr_unknown_enum | 0 | 0 | - | 재확인 필요(readelf_shows=True, objdump_rejects=False,  |
| exp_r7_ghidra_dtag | ? | ? | - | GHIDRA_TRUNCATION 실증 ✓ |
| exp_r8_ghidra_symcount | ? | ? | - | 갈림 — Ghidra 43 vs readelf 7 (nchain 위조 파일이� |

개별 로그: pipeline_runs/<실험>.log — 재현시 그 로그의 크래프팅/명령 참조
