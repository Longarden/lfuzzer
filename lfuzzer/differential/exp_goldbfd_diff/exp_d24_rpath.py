#!/usr/bin/env python3
"""
exp_d24_rpath.py — D24: 입력 .so 의 DT_RPATH(구식, RUNPATH 아님)를 링크타임에 소비하는가.

소스 근거:
  bfd  elflink.c:4526-4551  입력 .so 의 DT_RPATH/DT_RUNPATH 를 읽어 rpath-link 탐색에 사용.
                            (D22 는 DT_RUNPATH 로 이 경로를 탔고, 여기선 구식 DT_RPATH 태그로 같은 경로를 탄다)
  gold dynobj.cc:332,339    dynamic tag switch 에 DT_RPATH 케이스 없음(default:break) → 입력의 RPATH 무시.
예측: libA 가 자기 DT_RPATH 에만 libC 경로를 갖고 있을 때,
      BFD 는 그 RPATH 를 암묵적 rpath-link 로 써서 libC 를 찾아 성공,
      GOLD 는 RPATH 를 안 읽어 "cannot find libC" 로 실패.
주의(e1 교훈): 기본 플래그론 둘 다 실패 → --copy-dt-needed-entries 로 NEEDED 재귀를 켠다.
      또한 consumer 는 libC 경로(-L hidden) 없이 링크해야 "RPATH 로만 찾는지"가 검증된다.

크래프팅(방어적, 외과적):
  1) libC 를 "숨은" 디렉토리(hidden/)에만 정상 빌드 → 기본 탐색경로·-L 어디에도 노출 안 함.
  2) libA 를 정상 빌드(libC 를 NEEDED 로) 후,
     patchelf --force-rpath --set-rpath <hidden> 로 DT_RUNPATH 가 아닌 구식 DT_RPATH 로 강제.
     (--force-rpath 없으면 patchelf 는 최신 DT_RUNPATH 를 심는다 → 그건 D22)
  파일 구조 자체는 완전 유효 → 두 링커 모두 초반 포맷검사는 통과, 갈림은 RPATH 해석에서만 발생.

의존: patchelf (sudo apt-get install patchelf).
직접 실행:  ./exp_d24_rpath.py     또는   python3 exp_d24_rpath.py    (사용자가 ! 로)
결과 판독: BFD rc=0(성공) / GOLD rc!=0 & stderr 에 libC 못 찾음 → >>> DIVERGED <<< 이면 예측 적중.
"""
import os, tempfile, common

def main():
    common.banner()
    if not common.shutil.which("patchelf"):
        print("patchelf 필요: sudo apt-get install -y patchelf  (설치 후 재실행)")
        return
    wd = tempfile.mkdtemp(prefix="exp_d24_")
    libdir = os.path.join(wd, "hidden"); os.makedirs(libdir)
    # libC: 진짜 구현, "숨은" 디렉토리에만 둔다 (기본 탐색경로/-L 어디에도 노출 안 함)
    common.make_base_lib(libdir, name="libC", soname="libC.so",
                         src="int bar(void){return 7;}\n")
    # libA: libC 를 NEEDED 로 갖고, 빌드 시엔 rpath-link 로만 libC 를 찾게 한다
    a_src = os.path.join(wd, "libA.c"); open(a_src, "w").write(
        "extern int bar(void);\nint foo(void){return bar();}\n")
    libA = os.path.join(wd, "libA.so")
    rc, o, e = common.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libA.so",
                           "-o", libA, a_src, "-L"+libdir, "-lC",
                           f"-Wl,-rpath-link,{libdir}"], cwd=wd)
    assert rc == 0, f"libA build failed: {e}"
    # 핵심: --force-rpath 로 DT_RUNPATH 가 아니라 구식 DT_RPATH 를 hidden/ 으로 심는다
    common.run(["patchelf", "--force-rpath", "--set-rpath", libdir, libA])
    # (확인) libA 가 RPATH=hidden(RUNPATH 아님), NEEDED=libC.so 인지
    _, ro, _ = common.run(["readelf", "-d", libA])
    print("libA readelf -d (발췌):")
    for l in ro.splitlines():
        if "RPATH" in l or "RUNPATH" in l or "NEEDED" in l:
            print("   ", l.strip())

    # consumer 를 -L(hidden) / -rpath-link 없이 링크 → libC 는 오직 libA 의 DT_RPATH 로만 찾아야 함
    cons = common.make_consumer(wd, libA)
    args = [cons, "-L"+wd, "-lA", "-Wl,--copy-dt-needed-entries",
            "-o", os.path.join(wd, "main_out")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report("D24 input DT_RPATH consumption", bfd, gold,
        extra="예측: BFD=libA의 RPATH로 libC 찾아 성공 / GOLD=RPATH 무시→'cannot find libC' 실패")
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")

if __name__ == "__main__":
    main()
