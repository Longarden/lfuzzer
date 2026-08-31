# Lfuzzer 메타데이터 확장 통합 스펙 (논문 "전체 메타데이터" ↔ 코드 정합)

작성: 2026-08-28 · 근거: 소스 실측(deep-dive trace) · 상태: 구현 착수

## 0. 왜 이 문서

deep-dive trace로 확정된 격차: **논문은 "ELF헤더+섹션헤더+프로그램헤더+뒤쪽 메타데이터 전부"를
뮤테이션한다고 주장하나, 실제 코드는 프로그램헤더(PHT)+.dynamic까지만 구현**돼 있다.
아래는 논문 주장을 실제로 구현하기 위한 drop-in 통합 스펙. 결정: **전체 스윕**.

## 1. 실제 구현 현황 (소스 실측)

```
클래스            구현?   근거
─────────────────────────────────────────────────────────────────────
PHT p_* (8필드)   ✅     mutators/mutator_field_v2.py  PH_FIELDS(45-53), range(e_phnum)
.dynamic DT_       ✅     mutators/mutator_dynamic_v3.py  (DT_VERNEED/AUDIT/STRTAB/STRSZ)
ELF헤더 e_*       ⚠️게이트 mutators/structure_aware.py  magic/class/machine/phnum "복구"만
섹션헤더 sh_*     ❌     코드에 sh_ 쓰기 0. structure_aware 341-347행 전부 [ ] TODO
심볼/문자열       ❌     구조적 타깃 없음
노트             ❌     구조적 타깃 없음
재배치 rela       ❌     구조적 타깃 없음
verneed/versym   ⚠️부분  dynamic_v3의 DT_VERNEED 경유만
```

## 2. 재사용 프리미티브 인벤토리 (core/elf64.py — 실측)

**이미 있음(그대로 재사용):**
- `u16/u32/u64(b,o)` 리더 — elf64.py:59-66
- `read_phdrs(data)` — PHT 전체 dict 리스트(+entry_offset) — elf64.py:69
- `iter_dynamic(data)` — Elf64_Dyn 순회 (i,tag,val,off) — elf64.py:103
- `vaddr_to_offset(data,vaddr)` — v2o(FILESZ-bounded) — elf64.py:135
- **`section_by_name(data,name)` — SHT 완전 파싱!** e_shoff@0x28/e_shentsize@0x3A/e_shnum@0x3C/
  e_shstrndx@0x3E, shstrtab 해석, Shdr dict 반환(sh_offset/size/link/info/entsize/entry_offset) — elf64.py:158
- Shdr 필드 오프셋 전부 문서화 — elf64.py:36-46

**신규 작성 필요(elf64.py에 추가 권장):**
- `iter_sections(data)` — section_by_name 루프를 전 섹션 yield로 (약 10줄, 자명)
- `p16/p32/p64` 라이터 — 기존 뮤테이터는 각자 struct.pack_into 사용 중; 공통화 권장
- Elf64_Sym / Elf64_Nhdr / Elf64_Rela / Elf64_Verneed 파서 (아래 오프셋)

## 3. 신규 뮤테이터별 계획 (템플릿 = mutator_field_v2.py)

공통 패턴(mutator_field_v2 미러): `XXX_FIELDS = {name:(off,size,fmt)}` 테이블 →
대상 엔트리 순회 → 각 필드에 mode A(단일)/B(콤보) 뮤테이션 → is_crash → CRASH_DIR 출력.
멀티프로세싱 워커(_init_worker/worker/pool)도 그대로 복제.

### 3.1 SHT — `mutators/mutator_section_v1.py`  [1순위, 프리미티브 有]
```
대상: section_by_name/iter_sections로 얻은 각 Shdr의 entry_offset 기준
SH_FIELDS = {
  "sh_name":(0x00,4,"<I"), "sh_type":(0x04,4,"<I"), "sh_flags":(0x08,8,"<Q"),
  "sh_addr":(0x10,8,"<Q"), "sh_offset":(0x18,8,"<Q"), "sh_size":(0x20,8,"<Q"),
  "sh_link":(0x28,4,"<I"), "sh_info":(0x2C,4,"<I"),
  "sh_addralign":(0x30,8,"<Q"), "sh_entsize":(0x38,8,"<Q") }
크래시 유발 값: sh_entsize=0(나눗셈), sh_offset+sh_size>파일, sh_link=엉뚱인덱스, sh_size=거대
타깃: readelf/objdump (ld.so는 SHT 거의 안 봄)
```

### 3.2 심볼/문자열 — `mutators/mutator_symtab_v1.py`
```
섹션: section_by_name(".symtab"|".dynsym") → sh_offset/sh_size/sh_entsize로 Elf64_Sym 순회
Elf64_Sym(24B): st_name(0x00,u32) st_info(0x04,u8) st_other(0x05,u8)
                st_shndx(0x06,u16) st_value(0x08,u64) st_size(0x10,u64)
크래시: st_name>strtab크기(.strtab/.dynstr sh_link), st_shndx>e_shnum
타깃: readelf -s, objdump -t
```

### 3.3 노트 — `mutators/mutator_note_v1.py`
```
섹션: section_by_name(".note.*") 또는 PT_NOTE 세그먼트
Elf64_Nhdr(12B): n_namesz(0x00,u32) n_descsz(0x04,u32) n_type(0x08,u32) +name(4정렬)+desc
크래시: n_namesz/n_descsz 거대 → note 순회 파일밖 OOB
타깃: readelf -n
```

### 3.4 재배치 — `mutators/mutator_reloc_v1.py`
```
섹션: section_by_name(".rela.*") → Elf64_Rela 순회
Elf64_Rela(24B): r_offset(0x00,u64) r_info(0x08,u64) r_addend(0x10,i64)
크래시(정적파서): sh_entsize≠24, r_info 심볼인덱스 폭주
크래시(로더): r_offset 오염 → elf_machine_rela 쓰기주소 오염 (기존 RB05/12/18 계열과 연결)
타깃: readelf -r, objdump -R, ld.so
```

### 3.5 verneed/versym — `mutator_dynamic_v3` 확장 or `mutators/mutator_verneed_v1.py`
```
DT_VERNEED(val)=verneed 시작 vaddr → v2o
Elf64_Verneed(16B): vn_version(0,u16) vn_cnt(2,u16) vn_file(4,u32) vn_aux(8,u32) vn_next(0xC,u32)
Elf64_Vernaux(16B): vna_hash(0,u32) vna_flags(4,u16) vna_other(6,u16) vna_name(8,u32) vna_next(0xC,u32)
.gnu.version(versym): u16 배열
크래시: vn_cnt/vn_next 체인 폭주(CVE-2023-1972 계열), versym idx>verneed
타깃: readelf -V, ld.so(_dl_check_map_versions — 기존 b39 버킷 함수와 연결)
```

## 4. 러너/타깃 확장 (orchestrator/harness)

```
현재: execve로 시스템 ld.so 실행(로더 크래시). readelf/objdump 타깃 없음.
추가: runner에 target=readelf|objdump|ldso 스위치.
  - readelf:  timeout N readelf -a <mut> ; 크래시=exit>128(139/134), 행=124
  - objdump:  timeout N objdump -x <mut> ; 동일
  - ASAN 빌드(~/binutils-build-afl-bfd-clean 또는 asan변형) 사용 시 heap-OOB read도 SIGABRT로 검출
크래시 판정 공통: verdict_of(rc) = 124→HANG, >128→CRASH(sig=rc-128), else nonzero/ok
```

## 5. structure_aware TODO 마감 (341-347행 [ ] → 구현)

```
[ ] DT_STRSZ vs 실제 strtab 끝 정합    → _repair_semantic_fields에 추가
[ ] DT_RELASZ / DT_RELAENT 배수 정합
[ ] sh_link / sh_info 유효 인덱스       → section_by_name로 e_shnum 얻어 클램프
[ ] versym idx ≤ verneed 카운트
전부 "선택복구(낮은 p_repair)" 대상 = 모순을 대체로 살려둬 파서 안쪽 무검증 순회를 때림.
```

## 6. 빌드 순서 & 리스크

```
순서(안전순, 프리미티브 유무 기준):
  1) core/elf64.py에 iter_sections + p16/p32/p64 + Sym/Nhdr/Rela/Verneed 파서 추가
  2) mutator_section_v1.py (SHT — 프리미티브 완비, 최저위험)  ← 착수
  3) runner에 readelf/objdump 타깃 추가 (없으면 SHT 크래시 관측 불가)
  4) mutator_symtab_v1 → mutator_note_v1 → mutator_reloc_v1 → verneed
  5) structure_aware TODO 마감
  6) 통합 스모크: 각 뮤테이터 → readelf/objdump/ld.so 재현 카운트

리스크:
  · WSL 현재 프로세스생성 오류(getpwuid) → Python 실행/테스트 불가.
    코드는 작성 가능하나 "검증 완료"는 WSL 복구 후. 미검증 코드는 그렇게 명시(가짜완성 금지).
  · 이 세션 안전분류기가 멀티에이전트(Workflow/Agent) 팬아웃을 차단 → 병렬구현 불가, 직렬로.
  · SHT/심볼/노트 뮤테이션은 ld.so 크래시 증가에 기여 안 함(로더가 안 읽음).
    반드시 readelf/objdump 타깃과 함께여야 성과. (funnel 법칙)
```

## 7. 파일별 작업 목록 (구현자용)

```
[C] core/elf64.py            +iter_sections, +p16/p32/p64, +iter_syms/iter_notes/iter_relas/iter_verneed
[N] mutators/mutator_section_v1.py   SH_FIELDS 미러 + 워커풀 + CRASH_DIR
[N] mutators/mutator_symtab_v1.py    ST_FIELDS + .symtab/.dynsym 순회
[N] mutators/mutator_note_v1.py      NOTE_FIELDS + .note 순회
[N] mutators/mutator_reloc_v1.py     RELA_FIELDS + .rela 순회
[N] mutators/mutator_verneed_v1.py   VN/VNA_FIELDS + versym  (or dynamic_v3 확장)
[E] orchestrator/harness runner      target 스위치(readelf/objdump/ldso) + verdict_of
[E] mutators/structure_aware.py      _repair_semantic_fields의 [ ] 4항목 구현
[N]=신규 [E]=편집 [C]=코어확장
```
