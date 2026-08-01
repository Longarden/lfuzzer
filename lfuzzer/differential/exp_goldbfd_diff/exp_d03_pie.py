#!/usr/bin/env python3
"""
exp_d03_pie.py — D03: PIE 실행파일을 링크 "입력"으로 줬을 때.

소스 근거:
  bfd  elflink.c:4582-4583  DT_FLAGS_1 읽어 is_pie 세팅  →  ld/ldelf.c:1320 fatal 거부
  gold dynobj.cc:332,339    DT_FLAGS_1 안 읽음(default:break), e_type만 봄 → ET_DYN이면 수락
예측: 같은 PIE 파일 → BFD는 fatal("cannot use executable file as input"), GOLD는 평범한 DSO로 수락.

실행:  python3 exp_d03_pie.py      (사용자가 ! 로)
"""
import os, tempfile, common

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d03_")
    # 1) PIE 실행파일 하나 만든다 (ET_DYN + DF_1_PIE)
    src = os.path.join(wd, "p.c"); open(src, "w").write("int main(void){return 0;}\n")
    pie = os.path.join(wd, "prog_pie")
    rc, o, e = common.run(["gcc", "-fPIE", "-pie", "-o", pie, src], cwd=wd)
    assert rc == 0, f"PIE build failed: {e}"
    # (확인) 진짜 ET_DYN + DF_1_PIE 인지
    _, ro, _ = common.run(["readelf", "-hd", pie])
    print("readelf -hd prog_pie (발췌):")
    for line in ro.splitlines():
        if "Type:" in line or "FLAGS_1" in line or "PIE" in line:
            print("   ", line.strip())

    # 2) 이 PIE 를 -shared 링크의 입력 오브젝트로 넣는다
    args = ["-shared", "-nostdlib", pie, "-o", os.path.join(wd, "out.so")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report("D03 PIE-as-input", bfd, gold,
        extra="예측: BFD=fatal 거부 / GOLD=수락(rc 0 또는 다른 사유)")
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")

if __name__ == "__main__":
    main()
