#!/usr/bin/env python3
"""
exp_d06_malformed_verdef.py — D06: 손상된 verdef(vd_version 오류) 처리 차이.

소스 근거:
  gold dynobj.cc:577   Verdef_iterator 순회 중 vd_version 검사 실패해도
                       "부분 맵(partial map)"으로 계속 → 남은 심볼 버전 해석 시도
  gold dynobj.cc:664   버전 정의를 name index 로 매핑, 손상돼도 오브젝트 전체를 드롭하지 않음
                       → gold = fail-slow (심볼 계속 해석)
  bfd  elf.c:9459      _bfd_elf_slurp_version_tables 에서 vd_version != 1 이면
                       bfd_set_error(bfd_error_bad_value) 후 실패 리턴
                       → bfd = fail-fast (버전 테이블 슬럽 실패 → 오브젝트 드롭/에러)
예측:
  BFD  = vd_version 검증 실패 → bad value / 링크 에러(fail-fast, 오브젝트 드롭)
  GOLD = 손상 무시하고 부분맵으로 심볼 해석 계속 → 링크 성공하거나 다른 사유로 진행(fail-slow)
  즉 링크 성공여부 + 심볼 해석 결과가 갈리는 것을 관찰.

크래프팅:
  1) common.make_base_lib 로 버전 스크립트를 준 정상 versioned DSO(libfoo.so) 빌드.
     (VERDEF 섹션이 생기도록 -Wl,--version-script 사용)
  2) pyelftools 로 .gnu.version_d(SHT_GNU_verdef) 섹션을 찾아, 첫 Verdef 항목의
     vd_version 필드(각 항목 맨 앞 2바이트, LE uint16)를 1 → 0xFF 로 바이트 패치.
     (Elfstructs 로 sh_offset + vd_offset 계산해 정확한 파일 오프셋에 write)
  3) 이 손상된 DSO 를 소비하는 main 을 두 링커로 각각 링크해 결과 비교.

실행:  python3 exp_d06_malformed_verdef.py      (사용자가 ! 로)

의존: pyelftools. 크래프팅이 verdef 섹션을 못 찾으면 best-effort 로 스킵 표시.
"""
import os, struct, tempfile, common
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section


# ── SHT_GNU_verdef = 0x6ffffffd. verdef 엔트리 맨 앞 필드가 vd_version(uint16) ──
SHT_GNU_verdef = 0x6ffffffd


def patch_vd_version(sopath, bad=0xFF):
    """
    .gnu.version_d(verdef) 섹션의 첫 Verdef 엔트리 vd_version 을 bad 로 바이트 패치.
    반환: (patched_bool, info_str). 섹션이 없으면 (False, 사유).
    """
    with open(sopath, "rb") as f:
        elf = ELFFile(f)
        vsec = None
        for sec in elf.iter_sections():
            # 이름(.gnu.version_d) 또는 타입(SHT_GNU_verdef) 둘 중 하나로 식별
            if sec.name == ".gnu.version_d" or sec["sh_type"] == SHT_GNU_verdef:
                vsec = sec
                break
        if vsec is None:
            return False, "verdef(.gnu.version_d) 섹션 없음 — 버전 스크립트 미적용?"
        sh_offset = vsec["sh_offset"]
        endian = "<" if elf.little_endian else ">"

    # 첫 Verdef 엔트리 시작 = sh_offset. vd_version 은 그 맨 앞 2바이트.
    with open(sopath, "r+b") as f:
        f.seek(sh_offset)
        orig = struct.unpack(endian + "H", f.read(2))[0]
        f.seek(sh_offset)
        f.write(struct.pack(endian + "H", bad))
    return True, f"verdef@0x{sh_offset:x}: vd_version {orig} → 0x{bad:x}"


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d06_")

    # 1) versioned DSO 빌드 — VERDEF 가 생기도록 version-script 사용.
    ver = os.path.join(wd, "foo.ver")
    open(ver, "w").write("V1 { global: foo; local: *; };\n")
    src = os.path.join(wd, "libfoo.c")
    open(src, "w").write("int foo(void){ return 42; }\n")
    so = os.path.join(wd, "libfoo.so")
    rc, o, e = common.run(
        ["gcc", "-shared", "-fPIC", "-Wl,--version-script," + ver,
         "-Wl,-soname,libfoo.so.1", "-o", so, src], cwd=wd)
    assert rc == 0, f"versioned DSO build failed: {e}"

    # (확인) verdef 섹션과 버전 정의가 진짜 있는지
    _, ro, _ = common.run(["readelf", "-V", so])
    print("readelf -V libfoo.so (발췌):")
    for line in ro.splitlines():
        if "version_d" in line or "Rev:" in line or "Name:" in line or "Flags:" in line:
            print("   ", line.strip())

    # 2) vd_version 손상 패치
    patched, info = patch_vd_version(so, bad=0xFF)
    print("\n크래프팅:", info)
    if not patched:
        # best-effort: 못 만들면 스크립트는 남기되 관찰 불가 표시.
        # 확인할 점: 이 환경 gcc/ld 가 verdef 를 생성하는지(readelf -V 로 검증),
        #            안 되면 -Wl,--default-symver 등으로 강제 필요.
        print("\n결론: verdef 미생성으로 크래프팅 실패 — 관찰 불가(위 사유 확인 요망)")
        return

    # (확인) 패치 후 readelf 가 손상을 보고하는지
    prc, pro, pre = common.run(["readelf", "-V", so])
    print("패치 후 readelf -V rc=%d (경고 발췌):" % prc)
    for line in (pro + pre).splitlines():
        if "version" in line.lower() or "Rev:" in line or "warning" in line.lower():
            print("   ", line.strip())

    # 3) 손상 DSO 를 소비하는 main 을 두 링커로 링크
    con = common.make_consumer(wd, so, name="main")
    args = [con, so, "-o", os.path.join(wd, "app")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report(
        "D06 malformed-verdef(vd_version)", bfd, gold,
        extra=("예측: BFD=fail-fast(bad value/verdef 슬럽 실패로 오브젝트 드롭) / "
               "GOLD=fail-slow(부분맵으로 심볼 계속 해석)\n"
               "관찰축: 링크 rc + foo 심볼 해석 성공여부(stderr 의 undefined/bad value)"))

    print("\n결론:", "예측대로 갈림 ✓ (bfd fail-fast vs gold fail-slow)"
          if diverged else "안 갈림 — 두 링커 모두 같은 처리(재확인 필요)")


if __name__ == "__main__":
    main()
