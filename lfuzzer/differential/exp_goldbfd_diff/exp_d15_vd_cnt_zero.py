#!/usr/bin/env python3
"""
exp_d15_vd_cnt_zero.py — D15: verdef 항목의 vd_cnt(=버전 이름 개수) 를 0 으로.

소스 근거:
  gold  dynobj.cc:592   verdef 파싱 루프에서 vd_cnt < 1 이면 곧바로 에러
                        ("version definition ... has no name") — 최소 1개 이름 강제.
  bfd   elf.c:9723      _bfd_elf_slurp_version_tables 근처, vd_cnt 를 반복 상한으로만
                        사용 → 0 이면 이름 루프를 그냥 0회 돌고 조용히 계속(관대).
예측(반전된 엄격도):
  대부분 필드에서 BFD 가 더 관대한데, 이 케이스는 GOLD 가 더 엄격.
    BFD  → vd_cnt=0 을 삼키고 링크 계속(rc 0 또는 무관한 사유).
    GOLD → "no name" 류로 거부(rc != 0).
크래프팅:
  pyelftools 로 라이브러리의 .gnu.version_d(SHT_GNU_verdef) 섹션을 찾고,
  첫 Verdef 엔트리의 vd_cnt 필드(엔트리 오프셋 +16, Elf_Half=2바이트, LE)를
  0 으로 in-place 패치한다. vd_cnt 만 건드리고 vd_aux/vd_next 는 그대로 두는
  최소·정확 뮤테이션(이름 문자열 자체는 남겨둠 → 순수하게 "개수"만 거짓말).
직접 실행:
  python3 exp_d15_vd_cnt_zero.py       (사용자가 ! 로 직접)
결과 판독:
  diff_report 의 두 줄을 본다.
    BFD  rc=0    (또는 vd_cnt 무관한 에러)  → 관대
    GOLD rc!=0   stderr 에 name/version 관련 거부 메시지  → 엄격
  두 줄의 rc 가 갈리면 "예측대로 갈림". GOLD 만 거부하면 반전된 엄격도 확인.
"""
import os, struct, tempfile, common

# .gnu.version_d 를 실제로 만들려면 버전 스크립트로 심볼 버전을 부여해야 한다.
VERSCRIPT = "V1 { global: foo; local: *; };\n"

# Verdef(Elf64_Verdef) 필드 레이아웃 — vd_cnt 오프셋을 정확히 잡기 위한 상수.
#   vd_version(H,0) vd_flags(H,2) vd_ndx(H,4) vd_cnt(H,6) vd_hash(I,8)
#   vd_aux(I,12) vd_next(I,16)
VD_CNT_OFF = 6   # 엔트리 시작 기준 vd_cnt 바이트 오프셋


def find_verdef_first_entry_offset(path):
    """pyelftools 로 .gnu.version_d 섹션의 (파일오프셋, 첫엔트리내부오프셋) 반환."""
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            # SHT_GNU_verdef == 0x6ffffffd
            if sec["sh_type"] == "SHT_GNU_verdef" or sec.name == ".gnu.version_d":
                return sec["sh_offset"]   # 첫 Verdef 엔트리가 섹션 선두에 위치
    return None


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d15_")

    # 1) 심볼 버전(V1)을 가진 정상 공유 라이브러리 빌드 → verdef 섹션 생성 강제
    src = os.path.join(wd, "libfoo.c")
    open(src, "w").write("int foo(void){ return 42; }\n")
    vsc = os.path.join(wd, "ver.map")
    open(vsc, "w").write(VERSCRIPT)
    lib = os.path.join(wd, "libfoo.so")
    rc, o, e = common.run(["gcc", "-shared", "-fPIC",
                           f"-Wl,--version-script,{vsc}",
                           "-Wl,-soname,libfoo.so.1",
                           "-o", lib, src], cwd=wd)
    assert rc == 0, f"base lib build failed: {e}"

    # (확인) verdef 가 실제로 들어갔는지
    _, ro, _ = common.run(["readelf", "-V", lib])
    print("readelf -V libfoo.so (version definition 발췌):")
    for line in ro.splitlines():
        if "version_d" in line or "Rev:" in line or "Name:" in line or "Flags:" in line:
            print("   ", line.strip())

    # 2) 첫 Verdef 엔트리의 vd_cnt 를 0 으로 in-place 패치 (best-effort: 첫 엔트리만)
    off = find_verdef_first_entry_offset(lib)
    assert off is not None, "no .gnu.version_d section — 버전 스크립트 링크 확인 필요"
    with open(lib, "r+b") as f:
        f.seek(off + VD_CNT_OFF)
        old = struct.unpack("<H", f.read(2))[0]
        f.seek(off + VD_CNT_OFF)
        f.write(struct.pack("<H", 0))     # vd_cnt = 0
    print(f"patched vd_cnt: {old} -> 0  (offset 0x{off + VD_CNT_OFF:x})")

    # 3) 이 뮤테이트된 라이브러리를 소비하는 프로그램을 두 링커로 링크
    csrc = common.make_consumer(wd, lib, name="main")
    args = ["-nostdlib", csrc, lib, "-o", os.path.join(wd, "out")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report("D15 verdef vd_cnt=0", bfd, gold,
        extra="예측(반전): BFD=관대 수락 / GOLD=엄격 거부(no name)")

    print("\n결론:", "예측대로 갈림 ✓ (GOLD 만 거부 → 반전된 엄격도)"
          if diverged else "안 갈림 — 재확인 필요")


if __name__ == "__main__":
    main()
