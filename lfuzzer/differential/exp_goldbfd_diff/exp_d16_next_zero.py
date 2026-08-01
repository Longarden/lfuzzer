#!/usr/bin/env python3
"""
exp_d16_next_zero.py — D16: verdef/verneed 체인의 vd_next/vn_next 를 0 으로 하되 count>1.

소스 근거:
  gold  dynobj.cc:621   verdef 순회 루프가 vd_next 만으로 다음 레코드를 찾는다.
                        next==0 특례가 없어 pd = pd + vd_next 가 제자리(+0)면 같은
                        레코드를 count 만큼 재읽기 → 무한/재읽기 루프 위험.
  bfd   elf.c:9589      _bfd_elf_slurp_version_tables: extverdef 를 훑을 때
                        vd_next==0 이면 명시적으로 break 하여 체인을 종료.
예측(BFD vs GOLD):
  같은 DSO(vd_next=0, cnt=sh_info>1) 를 링크 입력으로 줬을 때
    BFD  → vd_next=0 에서 break, 조용히 수락(rc 0) 하거나 정상 버전 진단만.
    GOLD → next==0 특례 없어 같은 레코드를 반복 처리(중복 버전 경고/에러/멈칫) →
           rc 또는 stderr 가 BFD 와 갈린다.

크래프팅:
  1) 두 개의 심볼 버전(V1, V2)을 가진 정상 DSO 를 version-script 로 빌드.
     → .gnu.version_d 안에 Verdef 레코드가 2+개(base 포함) 생기고 vd_cnt>1 상황 확보.
  2) pyelftools 로 .gnu.version_d 섹션을 파싱, 각 Verdef 의 vd_next(레코드 오프셋
     +16 위치의 4바이트 LE)를 0 으로 in-place 패치. vd_cnt 는 건드리지 않는다(=count 유지).
     (best-effort: 오프셋은 elftools 가 준 레코드 시작 + Elf_Verdef.vd_next 필드 오프셋을 사용)
  3) 패치한 DSO 를 두 링커에 입력으로 넣어 소비 프로그램을 링크.

직접 실행:  ./exp_d16_next_zero.py      (또는 python3 exp_d16_next_zero.py, 사용자가 ! 로)

결과 판독(무슨 줄을 보나):
  diff_report 의 두 줄 — BFD rc/stderr vs GOLD rc/stderr.
    · BFD  가 rc 0(또는 짧은 버전 진단)인데 GOLD 가 rc!=0 / "duplicate"/"version" stderr →
      예측대로 갈림(GOLD 의 next==0 재읽기 노출).
    · 둘 다 조용하면 링커 소비 경로가 verdef 체인을 안 걷는 것 — readelf 재읽기(아래)로 보강.
  맨 끝 "결론:" 줄에 갈림 여부 요약.
"""
import os, struct, tempfile, common

# .gnu.version_d 의 Elf_Verdef 는 (vd_version H, vd_flags H, vd_ndx H, vd_cnt H,
#  vd_hash I, vd_aux I, vd_next I) = 20바이트. vd_next 는 레코드 시작 +16 오프셋.
VERDEF_NEXT_OFF = 16


def patch_verdef_next_zero(sopath):
    """
    pyelftools 로 .gnu.version_d 를 찾아 각 Verdef 레코드의 vd_next 를 0 으로 패치.
    반환: (패치한 레코드 수, 원래 vd_cnt 값 리스트). vd_cnt(count)는 손대지 않는다.
    best-effort: 섹션 파일 오프셋 + iter_versions() 가 준 논리 순서로 레코드 위치를 잰다.
    """
    from elftools.elf.elffile import ELFFile
    from elftools.elf.gnuversions import GNUVerDefSection

    with open(sopath, "rb") as f:
        elf = ELFFile(f)
        sec = None
        for s in elf.iter_sections():
            if isinstance(s, GNUVerDefSection):
                sec = s
                break
        if sec is None:
            return 0, []
        sh_off = sec["sh_offset"]
        # 각 Verdef 레코드의 섹션 내 상대 오프셋을 vd_aux/vd_next 를 따라 직접 계산한다.
        # (elftools 가 레코드 파일오프셋을 직접 안 주므로 체인을 손으로 걷는다.)
        raw = sec.data()
        counts = []
        offsets = []  # 패치할 vd_next 필드의 섹션 상대 오프셋
        cur = 0
        # sh_info 는 Verdef 레코드 개수. 이걸 신뢰해 그만큼만 걷는다(=count 유지 확인용).
        n = sec["sh_info"] if sec["sh_info"] else 1
        for _ in range(n):
            if cur + 20 > len(raw):
                break
            vd_cnt = struct.unpack_from("<H", raw, cur + 6)[0]
            vd_next = struct.unpack_from("<I", raw, cur + VERDEF_NEXT_OFF)[0]
            counts.append(vd_cnt)
            offsets.append(cur + VERDEF_NEXT_OFF)
            if vd_next == 0:
                break
            cur += vd_next

    # 파일에 in-place 로 vd_next=0 기록 (vd_cnt 는 그대로 → count>1 유지).
    with open(sopath, "r+b") as f:
        for rel in offsets:
            f.seek(sh_off + rel)
            f.write(struct.pack("<I", 0))
    return len(offsets), counts


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d16_")

    # 1) 두 심볼 버전을 가진 정상 DSO 빌드 → Verdef 레코드 2+개 확보.
    src = os.path.join(wd, "vsym.c")
    open(src, "w").write(
        'int foo_v1(void){return 1;}\n'
        'int foo_v2(void){return 2;}\n'
        '__asm__(".symver foo_v1, foo@V1");\n'
        '__asm__(".symver foo_v2, foo@@V2");\n'
    )
    vscript = os.path.join(wd, "ver.map")
    open(vscript, "w").write("V1 { global: foo; };\nV2 { global: foo; } V1;\n")
    so = os.path.join(wd, "libvsym.so")
    rc, o, e = common.run(
        ["gcc", "-shared", "-fPIC", "-Wl,-soname,libvsym.so.1",
         f"-Wl,--version-script,{vscript}", "-o", so, src], cwd=wd)
    assert rc == 0, f"versioned DSO build failed: {e}"

    # (확인) 패치 전 verdef 체인
    _, ro0, _ = common.run(["readelf", "-V", so])
    print("readelf -V (패치 전, .gnu.version_d 발췌):")
    for line in ro0.splitlines():
        if "version_d" in line or "Rev:" in line or "Name:" in line or "Parent" in line:
            print("   ", line.strip())

    # 2) vd_next 를 전부 0 으로 패치(count=vd_cnt 는 유지).
    try:
        npatched, counts = patch_verdef_next_zero(so)
    except ImportError:
        print("pyelftools 없음 → 크래프팅 불가. `pip install pyelftools` 후 재실행.")
        return
    print(f"\n패치: vd_next=0 으로 만든 Verdef 레코드 {npatched}개, vd_cnt(원본)={counts}")
    if npatched < 2:
        print("주의: Verdef 레코드가 2개 미만 — count>1 조건이 약함(best-effort).")

    # (확인) 패치 후 readelf 재파싱 — readelf 자체가 next==0 을 어떻게 다루나도 신호.
    rrc, ro1, re1 = common.run(["readelf", "-V", so])
    print("readelf -V (패치 후) rc=%d, stderr=%s" % (rrc, (re1 or '').strip()[:120]))

    # 3) 이 패치 DSO 를 링크 입력으로 소비하는 프로그램 링크.
    csrc = os.path.join(wd, "main.c")
    open(csrc, "w").write("extern int foo(void);\nint main(void){return foo();}\n")
    obj = os.path.join(wd, "main.o")
    rc, o, e = common.run(["gcc", "-c", "-o", obj, csrc], cwd=wd)
    assert rc == 0, f"consumer compile failed: {e}"

    args = [obj, so, "-o", os.path.join(wd, "out"),
            f"-Wl,-rpath,{wd}"]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report(
        "D16 verdef vd_next=0 (count>1)", bfd, gold,
        extra="예측: BFD=next0 break 로 조용/정상 / GOLD=next0 특례없어 재읽기(중복 version 경고/에러)")

    print("\n결론:", "예측대로 갈림 ✓ (GOLD next==0 재읽기 노출)"
          if diverged else "안 갈림 — 링커가 verdef 체인을 소비 안 하거나 둘 다 견고. readelf 재읽기 결과로 보강 판단")


if __name__ == "__main__":
    main()
