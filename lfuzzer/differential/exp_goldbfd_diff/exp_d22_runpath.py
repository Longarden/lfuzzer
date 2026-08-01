#!/usr/bin/env python3
"""
exp_d22_runpath.py — D22: 입력 .so 의 DT_RUNPATH 를 링크타임에 소비하는가.

소스 근거:
  bfd  elflink.c:4526-4551  입력 .so 의 DT_RUNPATH 를 읽어 rpath-link 탐색에 사용(RPATH 오버라이드)
  gold dynobj.cc:332,339    DT_RUNPATH case 없음(default:break) → 입력의 RUNPATH 무시
예측: libA 가 자기 DT_RUNPATH 에만 libC 경로를 갖고 있을 때,
      BFD 는 그 RUNPATH 를 암묵적 rpath-link 로 써서 libC 를 찾고,
      GOLD 는 RUNPATH 를 안 읽어 "cannot find libC" 로 실패.
주의(e1 교훈): 기본 플래그론 둘 다 실패할 수 있음 → --copy-dt-needed-entries 필요.
      이 실험은 그 플래그를 켜고 비교한다.

의존: patchelf (sudo apt-get install patchelf). 없으면 pyelftools 주입 경로로 바꿔야 함.
실행:  python3 exp_d22_runpath.py
"""
import os, tempfile, common

def main():
    common.banner()
    if not common.shutil.which("patchelf"):
        print("patchelf 필요: sudo apt-get install -y patchelf  (설치 후 재실행)")
        return
    wd = tempfile.mkdtemp(prefix="exp_d22_")
    libdir = os.path.join(wd, "hidden"); os.makedirs(libdir)
    # libC: 진짜 구현, "숨은" 디렉토리에만 둔다
    libc = common.make_base_lib(libdir, name="libC", soname="libC.so",
                                src="int bar(void){return 7;}\n")
    # libA: libC 를 NEEDED 로 갖고, libC 경로는 자기 DT_RUNPATH 에만 박는다
    a_src = os.path.join(wd, "libA.c"); open(a_src, "w").write(
        "extern int bar(void);\nint foo(void){return bar();}\n")
    libA = os.path.join(wd, "libA.so")
    rc, o, e = common.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libA.so",
                           "-o", libA, a_src, "-L"+libdir, "-lC",
                           f"-Wl,-rpath-link,{libdir}"], cwd=wd)
    assert rc == 0, f"libA build failed: {e}"
    common.run(["patchelf", "--set-rpath", libdir, libA])   # DT_RUNPATH := hidden
    # (확인) libA 가 DT_RUNPATH=hidden, DT_NEEDED=libC.so 인지
    _, ro, _ = common.run(["readelf", "-d", libA])
    print("libA readelf -d (발췌):")
    for l in ro.splitlines():
        if "RUNPATH" in l or "NEEDED" in l: print("   ", l.strip())
    # 이제 libA 를 -L/-rpath-link 없이 링크 → libC 는 libA 의 RUNPATH 로만 찾아야 함
    cons = common.make_consumer(wd, libA)
    args = [cons, "-L"+wd, "-lA", "-Wl,--copy-dt-needed-entries",
            "-o", os.path.join(wd, "main_out")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report("D22 input DT_RUNPATH consumption", bfd, gold,
        extra="예측: BFD=libA의 RUNPATH로 libC 찾아 성공 / GOLD=RUNPATH 무시→'cannot find libC' 실패")
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")

if __name__ == "__main__":
    main()
