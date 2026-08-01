#!/usr/bin/env python3
"""
exp_d09_osabi.py — D09: EI_OSABI(e_ident[7])를 이질값으로 패치한 .so 를 링크 입력으로.

소스 근거:
  bfd  elfcode.h:634   elf_object_p(): OSABI 불일치면 specialized target 벡터가
                       bfd_check_format 에서 wrong_format 로 거부(elf64-x86-64 등은
                       ELFOSABI_NONE/ELFOSABI_GNU 만 매칭). → ld 가 "file not recognized".
  gold target-select.cc:105  Target_selector::recognize(): machine + size(64) +
                       big_endian 3개만 비교. e_ident[EI_OSABI] 는 아예 안 봄 → 수락.
예측:
  같은 .so 의 EI_OSABI 를 ELFOSABI_FREEBSD(9) 로 1바이트 패치한 뒤 링크 입력으로 주면
    BFD  = 거부(rc≠0, "file not recognized" / "not recognized: file format not recognized")
    GOLD = 수락(OSABI 무시 → 정상 링크 rc 0, 혹은 다른 무관한 사유)

크래프팅:
  1) common.make_base_lib 로 정상 libfoo.so 생성(ELFOSABI_NONE=0).
  2) 그 파일의 오프셋 7(e_ident[EI_OSABI]) 바이트를 9(FreeBSD)로 덮어씀.
     - EI_OSABI 는 e_ident 배열의 인덱스 7, 파일 절대 오프셋도 7 로 고정(ELF 헤더 맨 앞).
     - 이 1바이트만 바꾸면 program/section 헤더는 그대로라 "구조적으로는 여전히 정상",
       다만 target 벡터 매칭에서만 갈린다(best-effort: 다른 필드 안 건드림).

직접 실행:
  ./exp_d09_osabi.py            (또는  python3 exp_d09_osabi.py)  — 사용자가 ! 로 직접

결과 판독:
  diff_report 의 두 줄을 본다.
    BFD  rc=1  stderr=... "file format not recognized" / "not recognized"  → 예측대로 거부
    GOLD rc=0  (또는 OSABI 와 무관한 사유)                                → 예측대로 수락
  추가로 readelf -h 발췌의 "OS/ABI:" 가 UNIX - FreeBSD 로 바뀌었는지로 패치 성공 확인.
  마지막 '결론:' 줄이 최종 판정.
"""
import os, tempfile, common

EI_OSABI = 7           # e_ident[7] = OS/ABI 바이트 (파일 오프셋도 7 로 고정)
ELFOSABI_FREEBSD = 9   # 이질값: FreeBSD ABI

def patch_osabi(path, value=ELFOSABI_FREEBSD):
    """path 의 EI_OSABI(오프셋 7) 1바이트를 value 로 덮어쓴다 (in-place)."""
    with open(path, "r+b") as f:
        f.seek(0)
        magic = f.read(4)
        assert magic == b"\x7fELF", f"not an ELF file: {magic!r}"
        f.seek(EI_OSABI)
        old = f.read(1)
        f.seek(EI_OSABI)
        f.write(bytes([value]))
    return old[0]

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d09_")

    # 1) 정상 .so 하나 만든다 (ELFOSABI_NONE=0 상태)
    so = common.make_base_lib(wd, name="libfoo")

    # 2) EI_OSABI 를 FreeBSD(9) 로 1바이트 패치
    old = patch_osabi(so, ELFOSABI_FREEBSD)
    print(f"patched EI_OSABI: {old} (NONE) -> {ELFOSABI_FREEBSD} (FreeBSD)  @offset {EI_OSABI}")

    # (확인) readelf 가 OS/ABI 를 FreeBSD 로 읽는지 — 패치 성공 검증
    _, ro, _ = common.run(["readelf", "-h", so])
    for line in ro.splitlines():
        if "OS/ABI" in line or "ABI Version" in line:
            print("   ", line.strip())

    # 3) 패치한 .so 를 소비하는 프로그램을 두 링커로 각각 링크
    #    (라이브러리를 입력으로 직접 넘겨 target 벡터 매칭을 강제)
    consumer = common.make_consumer(wd, so)
    out = os.path.join(wd, "app")
    args = [consumer, so, "-o", out]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report("D09 EI_OSABI=FreeBSD(9)", bfd, gold,
        extra="예측: BFD=거부(file format not recognized) / GOLD=수락(OSABI 무시)")
    print("\n결론:", "예측대로 갈림 ✓ (BFD OSABI 거부 vs GOLD OSABI 무시)"
          if diverged else "안 갈림 — 재확인 필요(빌드 링커 OSABI 완화 여부 점검)")

if __name__ == "__main__":
    main()
