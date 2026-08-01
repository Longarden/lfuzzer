#!/usr/bin/env python3
"""
exp_d13_vd_version.py — D13: verdef 의 vd_version 을 VER_DEF_CURRENT 가 아닌 값으로.

(1) 소스 근거
  gold  dynobj.cc:577  Verdef 를 읽을 때 vd_version 을 검사:
        if (verdef->vd_version != elfcpp::VER_DEF_CURRENT)  → 에러 처리
        (gold 는 "unexpected verdef version" 류로 오브젝트를 거부/경고).
  bfd   elf.c 의 _bfd_elf_slurp_version_tables 계열 verdef 파싱 경로에는
        vd_version 이 VER_DEF_CURRENT(=1) 인지 확인하는 분기가 없다(무검사).
        vd_version 필드를 읽어 구조체에 담기만 하고 값 자체로는 거르지 않는다.
  → 같은 필드를 gold 는 게이트로 쓰고 bfd 는 흘려보낸다.

(2) 예측 (BFD vs GOLD)
  BFD  : vd_version 이 1 이 아니어도 무검사 → 심볼 버전 테이블 정상 파싱, 링크 성공(rc 0).
  GOLD : vd_version != VER_DEF_CURRENT 감지 → 오브젝트 거부(비영 rc) 또는 명시 에러.
  즉 >>> DIVERGED <<< 예상.

(3) 크래프팅 (how the input is made)
  a. 버전 스크립트(V1 { global: foo; };)로 .gnu.version_d(=verdef) 를 가진 DSO 를 gcc 로 빌드.
  b. pyelftools 로 .gnu.version_d 섹션의 파일 오프셋을 찾는다.
  c. 그 섹션의 첫 Elf_Verdef 엔트리 선두 2바이트(vd_version, Half)를
     엔디안에 맞춰 1(VER_DEF_CURRENT) → 2(비정상) 로 바이트 패치.
     verdef 는 vd_next 로 연결된 리스트지만, 소비 측 파서는 각 엔트리의 vd_version 을
     본다. 최소·명확하게 첫 엔트리만 오염시켜 divergence 를 노출.
  d. 오염된 DSO 를 두 링커에 입력으로 링크(소비자 main 이 foo() 를 참조 → 심볼 버전 해석 유발).

(4) 실행법
  python3 exp_d13_vd_version.py     (사용자가 ! 로 직접)

주의: bfd/gold 버전에 따라 verdef 소비 시점이 다를 수 있다. divergence 가 안 보이면
  - readelf -V 로 패치가 실제로 vd_version=2 로 박혔는지(패치 검증) 확인,
  - GOLD stderr 에 'version' 관련 메시지가 뜨는지 확인할 것.
"""
import os, struct, tempfile, common
from elftools.elf.elffile import ELFFile

VER_DEF_CURRENT = 1
BAD_VERSION = 2  # VER_DEF_CURRENT 아님 → gold 게이트 트리거 목적


def patch_vd_version(sopath):
    """.gnu.version_d 첫 Verdef 의 vd_version(선두 Half) 을 BAD_VERSION 으로 바이트 패치."""
    with open(sopath, "rb") as f:
        elf = ELFFile(f)
        endian = "<" if elf.little_endian else ">"
        sec = elf.get_section_by_name(".gnu.version_d")
        if sec is None:
            return None, "no .gnu.version_d (verdef) section — 버전 스크립트 반영 안 됨"
        off = sec["sh_offset"]  # 섹션 파일 오프셋 = 첫 Elf_Verdef 시작
    # vd_version 은 Elf_Verdef 의 첫 필드(Half, 2바이트)
    with open(sopath, "r+b") as f:
        f.seek(off)
        (cur,) = struct.unpack(endian + "H", f.read(2))
        f.seek(off)
        f.write(struct.pack(endian + "H", BAD_VERSION))
    return (off, cur), None


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d13_")

    # 1) 버전 스크립트로 verdef 를 가진 DSO 빌드
    csrc = os.path.join(wd, "foo.c")
    open(csrc, "w").write("int foo(void){ return 42; }\n")
    vscript = os.path.join(wd, "ver.map")
    open(vscript, "w").write("V1 { global: foo; local: *; };\n")
    so = os.path.join(wd, "libfoo.so")
    rc, o, e = common.run(
        ["gcc", "-shared", "-fPIC", "-Wl,-soname,libfoo.so.1",
         f"-Wl,--version-script,{vscript}", "-o", so, csrc], cwd=wd)
    assert rc == 0, f"verdef DSO build failed: {e}"

    # (확인) 패치 전 verdef
    _, ro, _ = common.run(["readelf", "-V", so])
    print("readelf -V (패치 전, 발췌):")
    for line in ro.splitlines():
        if "version def" in line.lower() or "Rev:" in line or "Name:" in line:
            print("   ", line.strip())

    # 2) vd_version 패치
    info, err = patch_vd_version(so)
    if err:
        print("크래프팅 실패:", err)
        print("\n결론: verdef 미생성 — 재확인 필요")
        return
    off, cur = info
    print(f"\n패치: .gnu.version_d off=0x{off:x}  vd_version {cur} → {BAD_VERSION}")

    # (확인) 패치 후 readelf 가 vd_version 을 어떻게 보는지
    _, ro2, re2 = common.run(["readelf", "-V", so])
    print("readelf -V (패치 후, 발췌):")
    for line in (ro2 + re2).splitlines():
        if "Rev:" in line or "version" in line.lower() or "Unknown" in line:
            print("   ", line.strip())

    # 3) 소비자: foo() 를 참조해 심볼 버전 해석을 유발
    main_c = common.make_consumer(wd, so)
    args = [main_c, so, "-o", os.path.join(wd, "app")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report("D13 verdef vd_version != VER_DEF_CURRENT", bfd, gold,
        extra=f"vd_version={BAD_VERSION} (VER_DEF_CURRENT=1)  예측: BFD 수락 / GOLD 거부")
    print("\n결론:", "예측대로 갈림 ✓ (bfd 무검사 / gold 게이트)"
          if diverged else "안 갈림 — readelf -V 로 패치 반영·gold 소비시점 재확인 필요")


if __name__ == "__main__":
    main()
