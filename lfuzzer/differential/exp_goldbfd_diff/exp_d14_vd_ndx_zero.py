#!/usr/bin/env python3
"""
exp_d14_vd_ndx_zero.py — D14: verdef 레코드의 vd_ndx 를 0 으로 뭉갠다.

소스 근거:
  gold  dynobj.cc:584     Verdef_info 읽기 루프. vd_ndx 를 그대로 version index 로
                          받아 저장만 하고, 0 이라도 별도 거부/검증 없음 → 수락.
  bfd   elf.c:9718        _bfd_elf_slurp_version_tables 계열. verdef/verneed 의
                          index 가 0 이면 불법(0 = local, 1 = base 예약)으로 보고
                          "unable to read/parse version" 계열로 거부.
예측(BFD vs GOLD):
  BFD  → vd_ndx==0 인 verdef 를 불법 index 로 판정하여 거부(rc!=0, 에러 메시지).
  GOLD → 그대로 수락(rc 0), 뭉갠 index 를 저장.
크래프팅:
  1) --version-script 로 VER_1{...}; 심볼 버저닝을 넣어 .gnu.version_d(verdef) 있는 .so 빌드.
  2) pyelftools 로 .so 를 열어 SHT_GNU_verdef 섹션을 찾고, 각 Verdef 엔트리의
     vd_ndx(오프셋 +4, Elf64_Half, LE) 를 0 으로 덮어쓴다. base(index 1) 를 포함해
     모든 verdef ndx 를 0 으로 만들면 BFD 의 index==0 거부 경로를 확실히 친다.
     (best-effort: 오프셋은 Elf64_Verdef 레이아웃 vd_version(2)+vd_flags(2)+vd_ndx(2)
      로 계산. 32비트일 경우 동일 필드 순서/크기라 그대로 동작.)
  3) 뮤테이트한 .so 를 소비자(main)에서 -l 로 링크시켜 두 링커 반응을 비교.
직접 실행:
  python3 exp_d14_vd_ndx_zero.py       (사용자가 ! 로 직접)
결과 판독:
  diff_report 의 BFD stderr 에 "version"/"index"/"unable to read" 류 에러가 뜨고
  rc!=0 이면 예측대로. GOLD 는 rc 0(또는 무관한 사유) 이어야 갈림 확정.
  맨 끝 "결론:" 줄에서 예측대로 갈렸는지 최종 판정.
"""
import os, struct, tempfile, common

# .gnu.version_d 섹션 타입 (SHT_GNU_verdef)
SHT_GNU_verdef = 0x6ffffffd


def patch_all_vd_ndx_zero(so_path):
    """
    pyelftools 로 verdef 섹션을 순회하며 각 Verdef 레코드의 vd_ndx 를 0 으로 패치.
    반환: 패치한 레코드 수. verdef 없으면 0.
    Elf64_Verdef: vd_version(H) vd_flags(H) vd_ndx(H) vd_cnt(H) vd_hash(I)
                  vd_aux(I) vd_next(I)  → vd_ndx 는 레코드 시작 +4 바이트.
    """
    from elftools.elf.elffile import ELFFile

    with open(so_path, "rb") as f:
        data = bytearray(f.read())

    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        endian = "<" if elf.little_endian else ">"
        verdef_sh_off = None
        verdef_sh_size = None
        for sec in elf.iter_sections():
            if sec["sh_type"] == SHT_GNU_verdef:
                verdef_sh_off = sec["sh_offset"]
                verdef_sh_size = sec["sh_size"]
                break

    if verdef_sh_off is None:
        return 0

    # verdef 레코드 체인을 vd_next 를 따라가며 각 vd_ndx(+4) 를 0 으로.
    patched = 0
    off = verdef_sh_off
    end = verdef_sh_off + verdef_sh_size
    seen = set()
    while off < end and off not in seen:
        seen.add(off)
        # vd_ndx 는 레코드 +4 위치의 Elf*_Half(2바이트)
        struct.pack_into(endian + "H", data, off + 4, 0)
        patched += 1
        # vd_next 는 Elf64/32 공통으로 레코드 +16 위치의 4바이트 (상대 오프셋)
        (vd_next,) = struct.unpack_from(endian + "I", data, off + 16)
        if vd_next == 0:
            break
        off += vd_next

    with open(so_path, "wb") as f:
        f.write(data)
    return patched


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d14_")

    # 1) 버전 스크립트로 verdef 를 가진 정상 .so 빌드
    src = os.path.join(wd, "libver.c")
    open(src, "w").write("int foo(void){ return 42; }\n")
    vscript = os.path.join(wd, "ver.map")
    open(vscript, "w").write("VER_1 { global: foo; local: *; };\n")
    so = os.path.join(wd, "libver.so")
    rc, o, e = common.run(
        ["gcc", "-shared", "-fPIC", "-Wl,-soname,libver.so.1",
         f"-Wl,--version-script,{vscript}", "-o", so, src], cwd=wd)
    assert rc == 0, f"versioned lib build failed: {e}"

    # (확인) verdef 가 실제로 박혔는지 + 패치 전 ndx
    _, ro, _ = common.run(["readelf", "-V", so])
    print("readelf -V libver.so (패치 전, 발췌):")
    for line in ro.splitlines():
        if "Verdef" in line or "Rev:" in line or "Name:" in line:
            print("   ", line.strip())

    # 2) 모든 verdef 레코드의 vd_ndx 를 0 으로 뭉갠다
    n = patch_all_vd_ndx_zero(so)
    print(f"\npatched vd_ndx=0 records: {n}")
    _, ro2, _ = common.run(["readelf", "-V", so])
    print("readelf -V libver.so (패치 후, 발췌):")
    for line in ro2.splitlines():
        if "Verdef" in line or "Rev:" in line or "Name:" in line:
            print("   ", line.strip())

    # 3) 이 뮤테이트한 .so 를 두 링커로 각각 링크시킨다
    consumer = common.make_consumer(wd, so, name="main")
    args = [consumer, "-L", wd, "-l:libver.so", "-o", os.path.join(wd, "out")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report(
        "D14 verdef vd_ndx=0", bfd, gold,
        extra="예측: BFD=index 0 불법 거부(rc!=0) / GOLD=수락(rc 0)")

    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")


if __name__ == "__main__":
    main()
