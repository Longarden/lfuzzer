# 6 survey 통합 (3면 × 2링커) — 소스 전수 + readelf 교차검증

> 5개는 scientist(sonnet) 병렬 반환, S1-bfd는 워커 미복귀로 readelf 덤프+elflink.c 대체분석.
> 각 원본 근거 file:line은 아래 요약에, 전문은 세션 로그. 핵심만 응축.

## S1-gold · DYNAMIC (gold 방출)
- 전 DT_ 태그: PLTGOT/PLTRELSZ/JMPREL/PLTREL/RELA/RELASZ/RELAENT/RELACOUNT/SYMTAB/SYMENT/STRTAB/STRSZ/GNU_HASH/NEEDED×2/INIT/FINI/FINI_ARRAY/FINI_ARRAYSZ/INIT_ARRAY/INIT_ARRAYSZ/VERSYM/VERDEF/VERDEFNUM/VERNEED/VERNEEDNUM/NULL (27).
- 순서 = `Output_data_dynamic` push_back 호출순(정렬 없음). Finalize 호출순서 지배: target->finalize_sections(layout.cc:2997)→create_dynamic_symtab(3019)→finish_dynamic_section(3035)→create_version_sections(3043).
- 조건부 태그 근거: SONAME layout.cc:5289, RPATH/RUNPATH 5337-5365, FLAGS 5417-5444, FLAGS_1 5446-5476, VERDEF 5066-5069, NULL(+spare) output.cc:1878-1886.
- **DT_RELR 미지원**(코드 grep 0건) = bfd 갭 후보.
- ⚠ layout.cc:5325-5335에 upstream 아닌 한국어 주입주석 발견(이전 세션). 코드로직엔 무관.

## S1-bfd · DYNAMIC (bfd 방출) — S1bfd 워커 복귀분(실물)
- 전 DT_ 태그(실측 25): NEEDED×2/INIT/FINI/INIT_ARRAY/INIT_ARRAYSZ/FINI_ARRAY/FINI_ARRAYSZ/GNU_HASH/STRTAB/SYMTAB/STRSZ/SYMENT/PLTGOT/PLTRELSZ/PLTREL/JMPREL/RELA/RELASZ/RELAENT/VERNEED/VERNEEDNUM/VERSYM/RELACOUNT/NULL.
- 방출 순서 지배: `bfd_elf_size_dynamic_sections`(elflink.c) → SONAME(6763)→SYMBOLIC/RPATH/FILTER/AUDIT(7345-7410)→INIT/FINI/*_ARRAY(7440-7498)→HASH/GNU_HASH/STRTAB/SYMTAB/STRSZ/SYMENT/GNU_FLAGS_1(7512-7524)→백엔드훅(x86)→`_bfd_elf_add_dynamic_tags`(15551): DEBUG/PLTGOT/PLT*/JMPREL/RELA/TEXTREL→VERDEF/FLAGS/FLAGS_1/VERNEED(7545-7577)→`bfd_elf_size_dynsym_hash_dynstr`: VERSYM(7694)→DT_NULL×(spare+1)(7952).
- gold 대비 핵심:
  - **VERDEF/VERDEFNUM 없음**(cverdefs=0), 순서 상이(NEEDED 먼저, INIT_ARRAY→FINI_ARRAY, VERSYM 맨끝).
  - **DT_RELR/RELRSZ/RELRENT 실제 지원**(elflink.c:13318-13339, `-z pack-relative-relocs`) — gold 2.42 미지원과 대조 = 능력 갭 확정.
  - **DT_GNU_FLAGS_1**(info->gnu_flags_1, GNU_PROPERTY 관련) 방출 경로 존재(7522).
  - **DT_X86_64_PLT**(elfxx-x86.c:2690, CET/IBT 마킹) — 조건부, 샘플엔 비활성.
- ★ bfd 특이설계: **스페어 DT_NULL 재활용** — 사이징때 spare_dynamic_tags개(기본5) DT_NULL 예약 후, `bfd_elf_final_link`(13301-13339)에서 RELCOUNT/RELACOUNT→RELR triple로 in-place 덮어씀(append 아님). RELACOUNT가 "맨끝"에 오는 이유. RELR triple은 여유슬롯 3개 부족하면 통째 스킵(13320 경계=견고성 후보). gold은 정확히 필요한 만큼만 만드는 방식(대조).
- (정직) 실측 DT_NULL 1개뿐 → 코퍼스 링크가 `-z spare-dynamic-tags` 비기본값 사용 추정(커맨드라인 미확인).

## S2-gold · PHT
- PT: PHDR(강제최우선)/INTERP(2번째)/LOAD(RO먼저W나중X먼저)/DYNAMIC/NOTE(align다르면분열)/GNU_EH_FRAME/GNU_STACK(align16하드코딩)/TLS(RELRO직전)/GNU_RELRO(최후미). 순서=`segment_precedes`(layout.cc:3733)=type값 오름차순.
- **PT_GNU_PROPERTY 전용세그먼트 안 만듦**(elfcpp::PT_GNU_PROPERTY 리터럴 0건) → .note.gnu.property는 PT_NOTE로 흡수.
- TLS flags PF_R 강제(output.cc:4085). GNU_STACK align=16 하드코딩.

## S2-bfd · PHT
- PT 생성: PHDR/INTERP(.interp시 elf.c:5278)/LOAD×N(분할휴리스틱 elf.c:5379)/DYNAMIC/NOTE(그룹핑)/TLS(PF_R강제 5605)/GNU_MBIND/**GNU_PROPERTY(elf.c:5669-5685 전용 생성)**/GNU_EH_FRAME/GNU_SFRAME/GNU_STACK(align=stack_align 16)/GNU_RELRO(align=1 고정 6839).
- 디스크순=생성순(m->idx, elf.c:5990/6107), elf_sort_segments는 오프셋계산용 워킹순만.
- ★ **PT_GNU_PROPERTY 방출**(gold 미방출과 대조 = FINDING #1 소스원인).
- **PT_GNU_RELRO: bfd align=1, 주석(elf.c:6833-6836)에 "gold은 RW/4 생성"이라 명시** = 링커별 RELRO 정책차.
- .note.gnu.property가 PT_NOTE+PT_GNU_PROPERTY 이중커버.

## S3-gold · SHT
- 32섹션. 필드방출 `Output_section::write_header`(output.cc:3646-3686). 순서=세그먼트→ORDER_* enum 2단(output.cc:320).
- gold 특이: **.note.gnu.gold-version 자가식별 NOTE**(layout.cc:3328) non-alloc, .tm_clone_table, SHF_INFO_LINK 자동파생(output.cc:3654).
- 결론: 전부 **분석기 전용**(ld.so는 SHT 안 읽음). XINDEX(PN_XNUM)만 이론적 커널 관련.

## S3-bfd · SHT
- 31섹션. `elf_fake_sections`(elf.c:3707) 1차값, `assign_section_numbers`(elf.c:4200) 순번/링크확정.
- sh_link규칙: REL/RELA→.dynsym+.plt리다이렉트(`_bfd_elf_plt_get_reloc_section` elf.c:4147), DYNSYM/DYNAMIC→.dynstr, HASH/versym→.dynsym.
- e_shnum≥SHN_LORESERVE면 하드에러(elf.c:4305) → XINDEX 회피코드는 ld경로 도달불가.
- 결론(핵심): **glibc ld.so는 AT_PHDR/PT_DYNAMIC의 DT_*(가상주소 직접지정)만 읽고 e_shoff/SHT를 안 연다** → gold/bfd SHT 차이 전부 **분석기(readelf/objdump/ghidra) 전용, 로더 보안모델 무관**. 가설 확정.
