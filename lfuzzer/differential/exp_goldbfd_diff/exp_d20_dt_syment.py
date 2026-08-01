#!/usr/bin/env python3
"""
exp_d20_dt_syment.py — D20: DT_SYMENT(동적 심볼 엔트리 크기) 값 위조.

소스 근거:
  bfd   elf.c/elflink.c 폴백 — 섹션헤더가 없을 때 링커는 PT_DYNAMIC 만으로
        동적 심볼테이블을 잡는데, 이때 DT_SYMENT(=Elf64_Sym 한 개 크기)를
        기대치 bed->s->sizeof_sym(64bit=24)과 대조한다. 불일치 시 bfd_error
        (malformed/invalid entry size 계열)로 거부/경고한다.
  gold  dynobj.cc Sized_dynobj::read_dynsym_section — DT_SYMENT 를 신뢰하지 않고
        elfcpp 고정 sym_size(64bit=24)로 스트라이드를 계산한다. 위조된 DT_SYMENT
        는 그냥 무시하고 통과한다.
예측: 섹션헤더 없는 상태 + 틀린 DT_SYMENT →
      BFD  = DT_SYMENT 검증 실패 → 거부/경고
      GOLD = 고정 sym_size 로 파싱 → 무시하고 수락(관대)

크래프팅(정밀 수술 — 초반 포맷검사 통과가 핵심):
  1) common.make_base_lib 로 완전 정상 .so 빌드(early format check 통과 보장).
  2) SHT 가 살아있는 동안 common.dyn_entries 로 DT_SYMENT(tag 11) 파일오프셋 확보
     (섹션헤더를 지운 뒤엔 .dynamic 을 찾을 수 없으므로 순서가 중요).
  3) common.strip_section_headers 로 e_shoff/e_shnum/e_shstrndx 만 0 →
     '섹션헤더 없는' 유효 ELF. 링커의 PT_DYNAMIC 폴백 경로 강제.
  4) DT_SYMENT 엔트리의 val 필드(Elf64_Dyn: tag@off, val@off+8)만 patch_bytes 로
     틀린 값으로 덮어씀. 그 외 바이트는 전부 유효 → 초반검사 통과 후
     심볼엔트리크기 검증 경로에 정확히 도달.

직접 실행:  ./exp_d20_dt_syment.py      (사용자가 ! 로 직접)

결과 판독: diff_report 가 rc/stderr 로 갈림 판정.
  BFD 만 non-zero 또는 "entry size"/"malformed"류 메시지면 예측 적중.
"""
import os, struct, tempfile, common

DT_SYMENT = 11          # .dynamic 태그: Elf64_Sym 한 개의 바이트 크기
GOOD_SYMENT = 24        # 정상값 sizeof(Elf64_Sym) = 24 (0x18)
BAD_SYMENT = 0x30       # 위조값 48 — 크기 검증을 걸어 BFD 를 자극


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d20_")

    # 1) 정상 .so — 이후 이 파일만 수술한다.
    so = common.make_base_lib(wd, name="libd20")

    # 2) SHT 가 살아있을 때 DT_SYMENT 의 파일오프셋을 확보(스트립 후엔 못 찾음).
    ents = common.dyn_entries(so)
    hit = next(((i, tag, val, off) for (i, tag, val, off) in ents
                if tag == DT_SYMENT), None)
    if hit is None:
        print("DT_SYMENT(11) 엔트리 없음 — 이 툴체인의 .dynamic 미포함. 중단.")
        return
    i, tag, val, off = hit
    print(f".dynamic DT_SYMENT 발견: idx={i} val={val}(0x{val:x}) off=0x{off:x}")

    # 3) 섹션헤더 제거 → 링커가 PT_DYNAMIC 폴백으로 심볼테이블을 해석하게 강제.
    common.strip_section_headers(so)
    print("strip_section_headers 적용: e_shoff/e_shnum/e_shstrndx = 0")

    # 4) DT_SYMENT 엔트리의 val 필드(off+8)만 위조. 나머지는 전부 유효 유지.
    common.patch_bytes(so, off + 8, struct.pack("<Q", BAD_SYMENT))
    print(f"patch_bytes: DT_SYMENT val {GOOD_SYMENT} → {BAD_SYMENT}"
          f" (off+8 = 0x{off + 8:x})")

    # 5) 이 위조 .so 를 소비하는 프로그램을 각 링커로 링크(-pie/-r 동시금지 준수).
    csrc = common.make_consumer(wd, so, name="main")
    args = ["-o", os.path.join(wd, "out"), csrc, so,
            "-Wl,-rpath," + wd]
    bfd = common.link_with(common.BFD, args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report(
        "D20 DT_SYMENT-forged", bfd, gold,
        extra=(f"위조: DT_SYMENT {GOOD_SYMENT}→{BAD_SYMENT} (SHT 제거 상태)\n"
               "예측: BFD=심볼엔트리크기 검증 실패 거부 / GOLD=무시하고 수락"))
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")


if __name__ == "__main__":
    main()
