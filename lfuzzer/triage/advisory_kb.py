#!/usr/bin/env python3
"""
advisory_kb.py — ③ 자문 백엔드(me-as-backend)의 '지식'.

ld.so crash-site(함수) -> 5단 서술의 근거 재료:
  where              : 그 함수가 무슨 일을 하는 지점인가
  missing_validation : glibc 로더가 무엇을 검증하지 않아 이 크래시가 났나
  impact             : 그래서 어떻게 될 수 있나(익스플로잇 성격 포함)
  spec_ptr           : 근거 포인터(gABI 조항 / glibc 소스 / 이 연구 실측 노트)

이 표는 '판정'이 아니라 '해설'이다. 실제 evidence(CASR severity, tri_oracle rc,
파일명 필드)와 code가 join 해서 서술을 만들고, 이 표에 없는 site 는 자문이 DROP 된다
(mcp_advisor 의 인용 규칙). = 근거 없는 해설은 나가지 않는다.
"""
from __future__ import annotations
from typing import Dict, Optional

# ld.so 함수 -> 서술 재료
SITE_KB: Dict[str, dict] = {
    "__GI_mprotect": {
        "where": "RELRO(GOT 읽기전용) 보호를 거는 mprotect 시스템콜 경로",
        "missing_validation": "PT_GNU_RELRO의 p_memsz/p_vaddr를 파일크기·페이지정렬 대비 검증 없이 신뢰",
        "impact": "RELRO 범위 붕괴 → GOT가 쓰기가능으로 남거나(memsz-shrink, B1) mprotect에서 크래시. 보호우회/제어흐름 후보",
        "spec_ptr": "elf/dl-reloc.c _dl_protect_relro (RELRO PoC B1과 동일 필드)",
    },
    "_dl_call_fini": {
        "where": "프로그램 종료 시 fini(소멸자) 함수포인터를 호출하는 지점",
        "missing_validation": "DT_FINI_ARRAY의 포인터가 매핑된 유효 코드영역을 가리키는지 미검증",
        "impact": "함수포인터가 오염된 값을 가리키면 잘못된 주소로 호출/쓰기 → 제어흐름 탈취 1차 프리미티브",
        "spec_ptr": "glibc elf/dl-fini.c / gABI .fini_array",
    },
    "_dl_fini": {
        "where": "런타임 종료 정리(fini) 경로",
        "missing_validation": "링크맵/소멸자 목록의 포인터 유효성 미검증",
        "impact": "손상된 링크맵 참조 → 잘못된 호출/역참조. 제어흐름/DoS",
        "spec_ptr": "glibc elf/dl-fini.c",
    },
    "call_init": {
        "where": "초기화(init) 함수포인터 배열을 호출하는 지점",
        "missing_validation": "DT_INIT_ARRAY 포인터의 유효성/범위 미검증",
        "impact": "init 함수포인터를 오염된 주소로 호출 → 제어흐름 탈취(CallAv)",
        "spec_ptr": "glibc elf/dl-init.c",
    },
    "elf_machine_rela": {
        "where": "재배치(relocation) 항목을 적용해 타깃 주소에 값을 write 하는 지점",
        "missing_validation": "r_offset(쓸 위치)이 로드된 세그먼트 내부인지 미검증",
        "impact": "파일이 정한 임의 주소에 write(DestAv) → 임의쓰기 프리미티브, 익스플로잇 가능",
        "spec_ptr": "gABI Relocation / sysdeps/x86_64 dl-machine.h",
    },
    "elf_machine_rela_relative": {
        "where": "R_X86_64_RELATIVE 상대재배치를 적용(write)하는 지점",
        "missing_validation": "r_offset 범위 미검증(상대재배치도 동일)",
        "impact": "임의주소 write(DestAv) → 익스플로잇 가능",
        "spec_ptr": "sysdeps/x86_64 dl-machine.h elf_machine_rela_relative",
    },
    "_dl_relocate_object": {
        "where": "오브젝트 전체의 재배치 테이블을 순회 적용하는 지점",
        "missing_validation": "재배치 테이블 크기/각 항목 오프셋 범위 미검증",
        "impact": "write-AV/임의쓰기 또는 크래시",
        "spec_ptr": "glibc elf/dl-reloc.c",
    },
    "elf_dynamic_do_Rela": {
        "where": "동적 재배치(Rela) 루프를 처리하는 지점",
        "missing_validation": "relnum=sh_size/entsize 및 각 항목 범위 미검증",
        "impact": "write-AV 또는 과다 루프(DoS)",
        "spec_ptr": "glibc elf/do-rel.h",
    },
    "elf_get_dynamic_info": {
        "where": ".dynamic 세그먼트의 DT_* 태그 정보를 수집하는 지점",
        "missing_validation": "DYNAMIC 세그먼트 주소·DT_* d_ptr/d_val 범위 미검증",
        "impact": "나쁜 주소에서 read(SourceAv) → 대개 정보노출/DoS(익스플로잇성 낮음)",
        "spec_ptr": "glibc elf/get-dynamic-info.h (0729 signed d_tag 실측)",
    },
    "audit_list_add_dynamic_tag": {
        "where": "LA_ audit용 DT 태그 목록에 태그를 추가하는 지점",
        "missing_validation": "d_tag(Elf64_Sxword) 범위(음수/거대값)를 unsigned 캐스트 없이 인덱싱",
        "impact": "OOB read/write 후보(태그 라우팅 오류)",
        "spec_ptr": "elf/rtld.c:225 (0729 signed d_tag 실측)",
    },
    "_dl_check_map_versions": {
        "where": "심볼 버전(verneed/versym) 요구를 검증하는 지점",
        "missing_validation": "version 인덱스·verneed 오프셋의 범위 미검증",
        "impact": "OOB read → DoS (정적 파서 llvm-objdump VERNEED 선례와 동류)",
        "spec_ptr": "glibc elf/dl-version.c (0714 VERNEED)",
    },
    "_dl_lookup_symbol_x": {
        "where": "심볼 조회(이름→주소)를 수행하는 지점",
        "missing_validation": "symtab 인덱스·strtab 종단/범위 미검증",
        "impact": "OOB read → 정보노출/DoS",
        "spec_ptr": "glibc elf/dl-lookup.c",
    },
    "do_lookup_x": {
        "where": "심볼 해시 버킷을 훑어 이름을 매칭하는 지점",
        "missing_validation": "해시 체인 인덱스·symtab 범위 미검증",
        "impact": "OOB read",
        "spec_ptr": "glibc elf/dl-lookup.c do_lookup_x",
    },
    "resolve_map": {
        "where": "심볼이 정의된 링크맵을 결정하는 지점",
        "missing_validation": "손상된 링크맵/스코프 참조 미검증",
        "impact": "OOB read/잘못된 역참조",
        "spec_ptr": "glibc elf/dl-lookup.c",
    },
    "_dl_setup_hash": {
        "where": "심볼 해시테이블(nbucket/nchain)을 준비하는 지점",
        "missing_validation": "해시테이블 크기 필드가 파일 내부인지 미검증",
        "impact": "OOB read",
        "spec_ptr": "glibc elf/dl-lookup.c hash setup",
    },
    "_dl_map_object_from_fd": {
        "where": "오브젝트를 fd에서 메모리에 매핑하며 헤더를 파싱하는 지점",
        "missing_validation": "e_phoff/p_offset/p_filesz 범위를 파일크기 대비 미검증",
        "impact": "OOB read 또는 잘못된 매핑",
        "spec_ptr": "glibc elf/dl-load.c",
    },
    "_dl_map_object_deps": {
        "where": "의존성(DT_NEEDED)을 해석해 로드 목록을 만드는 지점",
        "missing_validation": "DT_NEEDED d_val(strtab 오프셋)이 DT_STRSZ 미만인지 미검증",
        "impact": "OOB read (0714d 재현 케이스와 동류)",
        "spec_ptr": "0714d reproduced (llvm-objdump), glibc elf/dl-deps.c",
    },
    "_dl_tlsdesc_return": {
        "where": "TLS 디스크립터를 반환하는 경로",
        "missing_validation": "TLS 모듈 인덱스/오프셋 범위 미검증",
        "impact": "OOB(TLS 영역) read/write",
        "spec_ptr": "sysdeps tls / dl-tlsdesc",
    },
    "__libc_start_call_main": {
        "where": "런타임 진입 직전 main을 호출하는 경로",
        "missing_validation": "진입점/보조벡터(auxv) 손상 미검증",
        "impact": "제어흐름/크래시",
        "spec_ptr": "glibc csu/libc-start.c",
    },
    "__libc_start_main_impl": {
        "where": "프로그램 시작 구현부",
        "missing_validation": "초기 상태/포인터 손상 미검증",
        "impact": "제어흐름(CallAv)",
        "spec_ptr": "glibc csu/libc-start.c",
    },
    "_rtld_global": {
        "where": "런타임 링커 전역 구조(_rtld_global)에 접근하는 지점",
        "missing_validation": "손상된 전역/링크맵 참조 미검증",
        "impact": "제어흐름/크래시",
        "spec_ptr": "glibc elf/rtld.c",
    },
}

# 세그먼트 필드 -> 한 줄 해설(파일명 field_segN_p_XXX 에서 필드 추출)
FIELD_HINT: Dict[str, str] = {
    "p_memsz": "세그먼트 크기 → RELRO/재배치/매핑 범위에 직결(축소 시 보호 붕괴)",
    "p_vaddr": "세그먼트 가상주소 → 매핑 위치/정렬 가정 위반",
    "p_flags": "세그먼트 권한(R/W/X) → RWX 무장/보호 우회",
    "p_offset": "파일 오프셋 → 파일 밖 매핑 유도(OOB)",
    "p_filesz": "파일상 크기 → filesz>memsz 등 매핑 불일치",
    "p_paddr": "물리주소(로더는 대개 무시)",
    "p_align": "정렬값 → 정렬 가정 위반/주소 계산 붕괴",
    "p_type": "세그먼트 종류 → 로더 해석 변경(PT_GNU_RELRO/PT_TLS 등)",
}


def lookup_site(func: Optional[str]) -> Optional[dict]:
    """crash-site 함수명 -> KB 항목. 정확일치 우선, 없으면 접두 substring."""
    if not func:
        return None
    if func in SITE_KB:
        return SITE_KB[func]
    for k, v in SITE_KB.items():
        if func.startswith(k) or k in func:
            return v
    return None


def lookup_field(field: Optional[str]) -> Optional[str]:
    if not field:
        return None
    for k, v in FIELD_HINT.items():
        if k in field:
            return v
    return None
