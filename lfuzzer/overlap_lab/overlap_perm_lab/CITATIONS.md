# overlap_perm_lab — glibc 코드 인용

본 lab 의 발견(F1, F4, F26, F33)이 glibc 의 어느 코드 경로에서 발생하는지 라인 단위로 추적.

환경: glibc 2.39 (Ubuntu 24.04, /home/garden/glibc-src/)

## F1: PT_LOAD 오버랩 시 후자 우선 — `_dl_map_segment`

`elf/dl-map-segments.h`:

```c
static __always_inline ElfW(Addr)
_dl_map_segment (const struct loadcmd *c, ElfW(Addr) mappref,
                 const size_t maplength, int fd)
{
  if (__glibc_likely (c->mapalign <= GLRO(dl_pagesize)))
    return (ElfW(Addr)) __mmap ((void *) mappref, maplength, c->prot,
                                MAP_COPY|MAP_FILE, fd, c->mapoff);
  ...
  map_start_aligned = (ElfW(Addr)) __mmap ((void *) map_start_aligned,
                                           maplength, c->prot,
                                           MAP_COPY|MAP_FILE|MAP_FIXED,
                                           fd, c->mapoff);
}
```

- 동적 링커가 .so 의 PT_LOAD 들을 phdr 순서대로 `_dl_map_segments` 루프에서 위 함수로 매핑.
- 두 번째 가지(MAP_FIXED)에서 이전 매핑 위에 덮어쓴다 → 본 lab 의 "후자 우선".
- 실행 파일 자체의 PT_LOAD 는 kernel `fs/binfmt_elf.c:load_elf_binary` 가 같은 시멘틱으로 처리.

## F4: PT_GNU_RELRO 가 시멘틱 체크 없이 적용됨

`elf/dl-load.c` (PT_GNU_RELRO 처리, line 1210-1216):

```c
case PT_GNU_RELRO:
    l->l_relro_addr = ph->p_vaddr;
    l->l_relro_size = ph->p_memsz;
    break;
```

- 단순히 vaddr/memsz 를 link_map 에 저장. .got/.data 안에 들어 있는지 등 의미 검증 없음.
- 본 lab V4 / iter01-I1V4 가 텍스트 페이지로 RELRO 를 옮겨도 ld.so 가 그대로 처리한 이유.

## F26: 8B RELRO memsz 감소만으로 mprotect 무력화 — `_dl_protect_relro`

`elf/dl-reloc.c:354-368`:

```c
void
_dl_protect_relro (struct link_map *l)
{
  ElfW(Addr) start = ALIGN_DOWN((l->l_addr
                                 + l->l_relro_addr),
                                GLRO(dl_pagesize));
  ElfW(Addr) end = ALIGN_DOWN((l->l_addr
                               + l->l_relro_addr
                               + l->l_relro_size),
                              GLRO(dl_pagesize));
  if (start != end
      && __mprotect ((void *) start, end - start, PROT_READ) < 0)
    {
      static const char errstring[] = N_("\
cannot apply additional memory protection after relocation");
      _dl_signal_error (errno, l->l_name, NULL, errstring);
    }
}
```

- `start` 와 `end` 둘 다 `ALIGN_DOWN`.
- 본 lab target_full: RELRO end=0x404000 (page 정렬). memsz 를 8B 만 줄이면 end=0x403ff8 → `ALIGN_DOWN(0x403ff8, 0x1000) = 0x403000`.
- 그러면 start == end == 0x403000 → 조건 `start != end` 위반 → `__mprotect` 호출 자체가 일어나지 않음.
- 결과: F26 의 ".got 페이지 전체가 RW 로 남음" 직접 원인.

## F33: 결합 PoC — _dl_map_segment 의 후자 우선 + _dl_protect_relro 의 ALIGN_DOWN

두 함수가 독립적으로 호출되므로 (1) PT_NOTE→PT_LOAD RWX overlay 가 텍스트 페이지에 RWX 부여,
(2) RELRO shrink 가 `_dl_protect_relro` 의 mprotect 무력화 → GOT RW. 두 결과가 합쳐져
"텍스트 RWX + GOT RW + 정상 실행" 의 멀웨어 시나리오가 성립.

## 함의
- glibc 의 두 함수가 ELF 메타 정보를 "검증 없이 사용" 하는 부분에서 본 lab 의 변형들이 통과.
- 방어 측에서 ld.so 를 수정하지 않고도 정적 분석 단계에서 PHT 단위 검사(`detect_overlap.py`) 로
  100% 탐지 가능 (F14, F15, F31).

## 코드 변경 제안 (방어 보강용)
1. `dl-load.c` PT_GNU_RELRO 처리에서 `l_relro_addr + l_relro_size` 가 어떤 PT_LOAD subset 인지 검증.
2. `dl-reloc.c` `_dl_protect_relro` 에서 ALIGN_DOWN 후 길이 0 인 경우 (mprotect noop) 의심으로 로그.
3. `dl-load.c` `_dl_map_segments` 진입 전 PT_LOAD vaddr 페이지 정렬 오버랩 사전 검증.

이 세 가지 보강이 본 lab 의 모든 변형을 ld.so 단계에서 차단 가능.


---

## 선행 연구 (PT_NOTE → PT_LOAD 변환)
- Ryan O'Neill, "Crafted ELF binaries: PT_NOTE → PT_LOAD overlay" (2015). 본 lab iter01 의 기법 베이스라인.
- 본 lab iter21~24 (PT_GNU_EH_FRAME, PT_GNU_PROPERTY, PT_TLS, PT_GNU_STACK 변환): 동등 효과 확인.
  공개된 자료 부재. iter25 매트릭스 참고.
- PT_TLS 변환의 silent corruption (TLS 변수 42→0) 은 본 lab 자체 발견 (F64).
