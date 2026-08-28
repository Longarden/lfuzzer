# ELF64 유효시드 다양성 카탈로그 (전략1 seed_builder 레시피 근거)

핵심: 3축(DT_태그 / PT_세그먼트 / SHT_섹션)은 **컨테이너 타입**을 갈린다.
진짜 고가치 다양성 = 로더/링커가 그 컨테이너를 통해 역참조하는 **내부 구조**
(버전체인·리로케이션 인코딩·해시테이블·property노트·TLS모델). 이게 미탐색 파서 표면.

## 우선순위 추가 축 (distinct 코드경로 순)
```
1. 심볼 버저닝 체인(verdef/verneed)  ── 최대 미탐색 로더 서브시스템 dl-version.c
2. 리로케이션 인코딩(RELA/REL/RELR + 타입 스윕) ── 타입별 분기, RELR=별도 디코더
3. 해시테이블(sysv vs gnu)           ── do_lookup_x 두 독립 워커
4. TLS 모델(GD/LD/IE/LE)             ── 모델별 별도 reloc + dl-tls.c 할당
5. GNU property 노트(CET)            ── dl-prop.c, 링커 AND-merge
6. IFUNC/IRELATIVE + COPY reloc      ── resolver 호출·교차객체 복사 경로
7. 확장넘버링(PN_XNUM/SHN_XINDEX)    ── 스펙 escape hatch, 엣지밀도 높음
8. init/fini 순서(배열+우선순위)     ── _dl_init 호출순서 로직
9. RPATH vs RUNPATH(new/old dtags)   ── dl-load.c 두 검색경로
10. 세그먼트 레이아웃(separate-code·page-size) ── PT_LOAD 개수/권한 파생
```

## 생성명령 (정공법, 표준 GNU 툴체인)
| 축 | 생성 방법 | 스윕 값 |
|----|----------|--------|
| 버저닝 verdef/verneed | `--version-script=v.map`(`V1{global:foo;}; V2{...}V1;`) + asm `.symver foo,foo@@V2`(default)/`foo@V1`(hidden) | verdef만/verneed만, base유무, 1vsN 의존, 체인 부모버전, @@vs@ |
| RELA/REL/RELR | RELA=x86-64 기본; RELR=`-Wl,-z,pack-relative-relocs`(glibc≥2.36); `-z combreloc` on/off | RELA만, RELR+RELA, .rela.plt vs .rela.dyn |
| reloc 타입 | PLT호출→JUMP_SLOT, extern data→GLOB_DAT, `-fpic` GOT→GOTPCREL, static local→RELATIVE | JUMP_SLOT/GLOB_DAT/RELATIVE/64/PC32/GOTPCREL/TLS류 |
| IFUNC | `__attribute__((ifunc("resolver")))` | exe vs .so, local vs export, 다중 |
| COPY reloc | non-PIE서 .so의 export 데이터 참조: `gcc -no-pie main.c -L. -lfoo` | 유무, 다중, 대형객체 |
| TEXTREL | `-shared -fno-PIC` + abs reloc / `-z text`(거부) | DT_TEXTREL vs DF_TEXTREL |
| GNU property(CET) | `-fcf-protection=full/branch/return/none` | IBT/SHSTK, 다중 property |
| 해시 | `-Wl,--hash-style=sysv/gnu/both` | sysv만/gnu만/both, 대량심볼(bloom 스트레스) |
| TLS 모델 | `__attribute__((tls_model("global-dynamic/local-dynamic/initial-exec/local-exec")))` on `__thread` | 4모델×(exe/.so), .tdata vs .tbss, 정렬 |
| init/fini | `__attribute__((constructor(101)/destructor))`; `-Wl,-init,fn,-fini,fn` | 레거시 vs 배열, PREINIT(exe전용), 우선순위 |
| 심볼 STT_/STB_/STV_ | FUNC/OBJECT/`__thread`(TLS)/ifunc(GNU_IFUNC); `weak`/`-fgnu-unique`; `visibility(hidden/protected)` | 타입·바인딩·가시성 조합 |
| sh_info local/global | static함수 vs export 개수 변화 | sh_info=1(all global)~high(many local) |
| 객체타입/PIE | `-no-pie`(ET_EXEC)/`-pie`(ET_DYN)/`-shared`/`-r`(ET_REL) | 4종, PIE±INTERP |
| PT_INTERP | `-Wl,--dynamic-linker=<path>`; `patchelf --set-interpreter` | 표준/대체/musl/장경로/무INTERP |
| OS/ABI | IFUNC/unique/property가 GNU(3) 강제; 아니면 SYSV(0) | SYSV/GNU/FreeBSD |
| RPATH vs RUNPATH | `-rpath,X,--enable-new-dtags`(RUNPATH)/`--disable-new-dtags`(RPATH); `patchelf` | RPATH만/RUNPATH만/both, `$ORIGIN`, 다중 |
| DT_AUDIT/DEPAUDIT | `-Wl,--audit,lib.so` / `--depaudit` | AUDIT/DEPAUDIT/both/다중 |
| NEEDED/SONAME | `--no-as-needed -lfoo`; `-soname,libx.so.1`; `patchelf --add-needed` | 0/1/다중, soname±버전, 순환, self |
| DF_/DF_1_ | `-z now/origin/nodelete/nodlopen/global/initfirst/interpose` | BIND_NOW/NODELETE/NOOPEN/ORIGIN/... 비트마스크 |
| BIND_NOW vs lazy | `-z now` vs `-z lazy` | now/lazy ± RELRO |
| RELRO | `-z relro`(부분)/`-z now`(full)/`-z norelro` | full/부분/none |
| execstack | `-z execstack`/`-z noexecstack` | RWX/RW/부재 |
| build-id 노트 | `-Wl,--build-id=sha1/md5/uuid/0x<hex>/none` | sha1(20B)/md5(16B)/none/커스텀 |
| 커스텀 노트 | `as .section .note.foo,"a",@note` + `.long` name/desc/type | ABI-tag, vendor 노트, 다중, 정렬 |
| SHF_COMPRESSED | `-Wl,--compress-debug-sections=zlib/zstd/none`; `objcopy` | zlib/zstd/uncompressed, 레거시 .zdebug |
| SHT_GROUP(COMDAT) | C++ inline/template 다중TU; `as .section .text.foo,"axG",@progbits,grp,comdat` | 단일/다중 그룹, 멤버수 |
| SHF_MERGE/STRINGS | 문자열리터럴→.rodata.str(MS); `-fmerge-constants`; `as ...,"aMS",@progbits,1` | MERGE만/+STRINGS, entsize 1/2/4/8 |
| 섹션 플래그 | `.text`(AX)/`.data`(WA)/`.rodata`(A)/`.bss`(WA NOBITS); `as .section n,"awx"` | AX/WA/A/WAX/NOBITS/TLS |
| 정렬/페이지 | `-z max-page-size=0x200000/0x1000`, `-z common-page-size=` | 4K/16K/2M, p_align 변화 |
| 세그먼트 레이아웃 | `-z separate-code`/`-z noseparate-code`; `-N`(OMAGIC) | 2-LOAD vs 3~4-LOAD 분리 |
| -Bsymbolic | `-Bsymbolic`/`-Bsymbolic-functions` | none/전체/함수만, DF_SYMBOLIC |
| eh_frame | `--eh-frame-hdr`(기본) vs `-fno-asynchronous-unwind-tables`; C++ 예외 | eh_frame_hdr 유무 |
| 확장넘버링 | PN_XNUM(>65535 phdr), SHN_XINDEX(>65280 섹션 via 대량 `-ffunction-sections`) | e_phnum=0xffff, e_shnum=0 escape |
| 교차아키(별도 패밀리) | `aarch64-linux-gnu-gcc`, `riscv64-linux-gnu-gcc`(툴체인 있으면) | e_machine/e_flags/reloc 우주 |

## 주의
- DF_*/DT_RPATH/PT_GNU_*/SHT_GNU_ver* 등은 "타입"은 기존 3축에 속하나, **그것이 가리키는 내부 구조**(버전체인·노트·해시)가 새 파서 표면 → 태그와 내부구조를 함께 생성할 것.
- PN_XNUM/SHN_XINDEX·교차아키는 엣지헤비/툴체인 필요 → 별도 스코프.
