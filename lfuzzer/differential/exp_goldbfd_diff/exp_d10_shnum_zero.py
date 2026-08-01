#!/usr/bin/env python3
"""
exp_d10_shnum_zero.py — D10: e_shnum=0(확장 규약) + section[0].sh_size 거대값.

소스 근거:
  ELF64 확장 규약: e_shnum==0 이고 e_shoff!=0 이면 "진짜 섹션 개수"는
    section header[0].sh_size 에 들어있다(원래 e_shnum 이 16비트라 65535 초과 시 사용).
  gold  elfcpp_file.h  Elf_file::initialize_shnum()
        → e_shnum==0 이면 섹션[0].sh_size 를 실제 개수로 읽어 shnum_ 에 그대로 신뢰 저장.
  bfd   elfcode.h:elf_object_p() 의 shnum 처리 구간
        → 동일하게 섹션[0].sh_size 를 읽되, 파일 크기/섹션헤더 배열 범위와 대조해
          말이 안 되면 bfd_error(wrong_format 등)로 거부한다.
  핵심 대비: BFD = 범위검증 후 거부 / GOLD = 무검증 신뢰 → 거대 섹션수 그대로 사용.

예측:
  e_shnum=0 으로 두고 shdr[0].sh_size 를 파일 크기 대비 불가능한 거대값으로 심으면
    BFD  → 섹션 개수가 파일 범위를 넘으므로 "wrong format / too many sections"
           류로 거부(rc != 0).
    GOLD → 거대값을 섹션 개수로 신뢰 → 거대 배열 순회/할당 시도로 엉뚱한 에러 또는
           크래시. BFD 와 rc/stderr 가 갈림.
  → rc / stderr 가 갈리면 D10 예측 성립.

크래프팅(외과적 패치, 초반 포맷검사 통과가 핵심):
  1) common.make_base_lib 로 "완전 정상" libfoo.so 빌드(플래그 충돌 없음).
  2) 패치 전 EHDR 에서 e_shoff(0x28,8B) 를 읽어 section header[0] 위치 확보.
  3) common.patch_bytes 로 e_shnum(0x3C,2B) = 0            → 확장규약 트리거.
  4) common.patch_bytes 로 shdr[0].sh_size(e_shoff+0x20,8B) = 0x00FFFFFF  → 거대 섹션수.
  나머지 바이트는 전부 유효 → e_ident/e_type/머신 등 초반 검사는 통과, 오직 섹션 개수만 함정.
  (이전 실패 원인: -pie 와 -r 동시 사용으로 플래그 충돌 → 여기선 순수 -L./-lfoo 로만 소비.)

직접 실행:  ./exp_d10_shnum_zero.py     (또는 python3 exp_d10_shnum_zero.py; 사용자가 ! 로)

결과 판독:
  diff_report 가 DIVERGED 이면 두 링커의 확장 섹션개수 신뢰 정책 차이 확인.
  BFD 거부(rc!=0) + GOLD 상이 rc → 예측대로.
"""
import os, struct, tempfile, common

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d10_")

    # 1) 정상 공유 라이브러리 빌드(플래그 충돌 없이). 이후 이 파일만 외과적으로 패치.
    so = common.make_base_lib(wd, name="libfoo")

    # 2) 패치 전 EHDR 에서 e_shoff 를 읽어 shdr[0] 위치 확보(패치 후엔 못 믿으니 지금 읽는다).
    raw = open(so, "rb").read()
    assert raw[:4] == b"\x7fELF" and raw[4] == 2 and raw[5] == 1, "ELF64 LE 전용"
    e_shoff  = struct.unpack_from("<Q", raw, 0x28)[0]   # ELF64 e_shoff @0x28
    e_shnum0 = struct.unpack_from("<H", raw, 0x3C)[0]   # 원래 섹션 개수(로그용)
    assert e_shoff != 0, "e_shoff==0 이면 확장규약이 발동 안 함"
    sh0_size_off = e_shoff + 0x20                        # ELF64 shdr 내 sh_size 오프셋 =0x20
    print(f"패치 전: e_shoff={e_shoff:#x}  e_shnum={e_shnum0}  shdr[0].sh_size@={sh0_size_off:#x}")

    # 3) e_shnum = 0 → "확장 섹션 개수" 규약 발동(개수를 shdr[0].sh_size 에서 읽게 강제).
    common.patch_bytes(so, 0x3C, struct.pack("<H", 0))

    # 4) shdr[0].sh_size = 거대값 → 실제 섹션 개수를 터무니없이 크게 위장.
    BIG = 0x00FFFFFF
    common.patch_bytes(so, sh0_size_off, struct.pack("<Q", BIG))
    print(f"패치 후: e_shnum=0, shdr[0].sh_size={BIG:#x} (={BIG} 섹션 주장)")

    # (참고) readelf 가 이 파일을 뭐라 보는지 — 도구별 견해도 남긴다.
    _, ro, rerr = common.run(["readelf", "-h", so])
    for line in ro.splitlines():
        if "section header" in line.lower() or "Number of section" in line:
            print("   readelf:", line.strip())
    if rerr.strip():
        print("   readelf stderr:", rerr.strip().replace("\n", " ⏎ ")[:160])

    # 5) 이 .so 를 consumer 가 gcc -L. -lfoo 로 소비(플래그 충돌 없음: -r/-pie 미사용).
    cons = common.make_consumer(wd, so, name="main")
    out  = os.path.join(wd, "consumer")
    args = ["-L.", "-lfoo", cons, "-o", out]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report(
        "D10 e_shnum=0 + shdr[0].sh_size 거대", bfd, gold,
        extra="예측: BFD=범위검증 거부(wrong format/too many sections) / GOLD=개수 신뢰→상이 rc")
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — sh_size 값/경로 재확인 필요")

if __name__ == "__main__":
    main()
