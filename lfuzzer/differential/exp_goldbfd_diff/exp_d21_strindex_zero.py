#!/usr/bin/env python3
"""
exp_d21_strindex_zero.py — D21: DT_SONAME(그리고 DT_NEEDED) 값을 0 으로 강제.

소스 근거:
  gold  dynobj.cc:314   sd->soname = this->get_dynamic_string(dyn.val)  형태로
                        d_val(strindex)을 특례 없이 strtab+strindex 역참조 → strindex==0 이면 strtab[0](첫 바이트)부터 읽음.
  bfd   elf.c:314       _bfd_elf_string_from_elf_section 계열에서 strindex==0 을
                        즉시 "" 로 처리(빈 문자열 특례) → strtab 역참조 없음.
예측(BFD vs GOLD):
  정상 ELF 는 strtab[0]==0(NUL) 이라 GOLD 이 strtab+0 을 읽어도 결과는 "" → 둘 다 "".
  따라서 "정상" strtab 이면 차이가 미미(rc/stderr 동일)할 수 있음.
  → 그 경우, strtab[0] 을 NUL 이 아닌 실제 문자로 오염시켜 GOLD 만 쓰레기 SONAME 을 읽게
    만들어 재확인한다. 이때 예측: GOLD 은 strtab[0..]까지 이어붙인 이상한 soname 을 채택
    (경고/거부 가능), BFD 은 여전히 "" 로 처리 → 갈림.

크래프팅(pyelftools, best-effort):
  1) 정상 libfoo.so 빌드(soname=libfoo.so.1).
  2) .dynamic 에서 DT_SONAME 엔트리를 찾아 d_val 을 0 으로 패치(strindex==0).
  3) 1차 링크 diff. 안 갈리면(정상 strtab[0]=NUL 이라) 2차:
     .dynstr 섹션의 첫 바이트(원래 NUL)를 'Z' 로 덮어 strtab[0]!=0 으로 만들고 재링크.

직접 실행:
  python3 ./exp_d21_strindex_zero.py     (사용자가 ! 로 직접)

결과 판독(무슨 줄을 보나):
  - diff_report 의 ">>> DIVERGED <<<" 여부.
  - GOLD stderr 에 이상한 soname/needed 관련 경고나 rc!=0 이 뜨는지.
  - 2차(오염 strtab)에서 GOLD 만 'Z...' 를 soname 으로 물었는지(BFD 은 "").
  - 맨 끝 "결론:" 줄.
"""
import os, tempfile, struct, common

# pyelftools 는 읽기용. 쓰기 패치는 raw 바이트로 직접 한다(elftools 는 write 미지원).
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection


def _find_soname_dval_offset(path):
    """
    .dynamic 안에서 DT_SONAME 엔트리의 (파일오프셋, 원래 d_val, is64, endian, 원래 soname 문자열)
    을 찾아 반환. d_tag(8B)+d_val(8B) 레이아웃에서 d_val 필드 오프셋을 계산한다.
    """
    with open(path, "rb") as f:
        elf = ELFFile(f)
        is64 = elf.elfclass == 64
        little = elf.little_endian
        dyn = elf.get_section_by_name(".dynamic")
        assert isinstance(dyn, DynamicSection), ".dynamic 없음"
        entsize = dyn["sh_entsize"] or (16 if is64 else 8)
        base = dyn["sh_offset"]
        # DT_SONAME 태그 값 = 14
        DT_SONAME = 14
        cur_soname = None
        for i, tag in enumerate(dyn.iter_tags()):
            if tag.entry.d_tag == "DT_SONAME":
                cur_soname = getattr(tag, "soname", None)
                ent_off = base + i * entsize
                dval_off = ent_off + (8 if is64 else 4)  # d_tag 다음이 d_val
                orig = tag.entry.d_val
                return dval_off, orig, is64, little, cur_soname
    return None


def _dynstr_first_byte_offset(path):
    """.dynstr 섹션의 파일오프셋(첫 바이트) 반환. strtab[0] 오염용."""
    with open(path, "rb") as f:
        elf = ELFFile(f)
        s = elf.get_section_by_name(".dynstr")
        assert s is not None, ".dynstr 없음"
        return s["sh_offset"]


def _patch_bytes(path, offset, raw):
    """path 의 offset 위치에 raw 바이트를 덮어쓴다(in-place)."""
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(raw)


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d21_")

    # 1) 정상 공유 라이브러리(soname=libfoo.so.1) + 소비자 소스
    lib = common.make_base_lib(wd, name="libfoo", soname="libfoo.so.1")
    cons = common.make_consumer(wd, lib, name="main")

    # DT_SONAME d_val 위치/원값 파악
    info = _find_soname_dval_offset(lib)
    assert info is not None, "DT_SONAME 엔트리를 못 찾음"
    dval_off, orig_val, is64, little, cur_soname = info
    print(f"DT_SONAME 원래 strindex(d_val)={orig_val}  soname={cur_soname!r}  "
          f"(class={'64' if is64 else '32'}, {'LE' if little else 'BE'})")

    # 2) d_val 을 0 으로 패치(strindex==0). 폭은 64/32 에 맞춰 기록.
    endc = "<" if little else ">"
    if is64:
        raw = struct.pack(endc + "Q", 0)
    else:
        raw = struct.pack(endc + "I", 0)
    _patch_bytes(lib, dval_off, raw)
    print(f"→ 패치: DT_SONAME d_val @0x{dval_off:x} 을 0 으로(strindex==0)")

    # (확인) readelf 가 soname 을 어떻게 보는지
    _, ro, _ = common.run(["readelf", "-d", lib])
    for ln in ro.splitlines():
        if "SONAME" in ln or "Library soname" in ln:
            print("   readelf -d:", ln.strip())

    # 3) 1차 링크 diff — 이 lib 를 소비자와 함께 링크(-l 대신 직접 경로).
    args = ["-o", os.path.join(wd, "main1"), cons, lib]
    bfd1  = common.link_with(common.BFD,  args, wd)
    gold1 = common.link_with(common.GOLD, args, wd)
    d1 = common.diff_report("D21 strindex==0 (정상 strtab[0]=NUL)", bfd1, gold1,
        extra="예측: strtab[0]=NUL 이라 GOLD 도 ''→ 차이 미미할 수 있음(그러면 2차로)")

    if d1:
        print("\n결론: 1차에서 이미 갈림 ✓ (strindex==0 특례 유무 차이 확정)")
        return

    # 4) 2차(재확인): .dynstr[0](원래 NUL)을 'Z' 로 오염 → GOLD 은 strtab+0 에서 'Z..' 를
    #    읽어 쓰레기 soname 채택, BFD 은 strindex==0 특례로 여전히 "".
    ds0 = _dynstr_first_byte_offset(lib)
    _patch_bytes(lib, ds0, b"Z")   # NUL → 'Z'
    print(f"\n→ 2차 오염: .dynstr[0] @0x{ds0:x} 을 NUL→'Z' (strtab[0]!=0)")
    _, ro2, _ = common.run(["readelf", "-d", lib])
    for ln in ro2.splitlines():
        if "SONAME" in ln or "Library soname" in ln:
            print("   readelf -d(오염후):", ln.strip())

    args2 = ["-o", os.path.join(wd, "main2"), cons, lib]
    bfd2  = common.link_with(common.BFD,  args2, wd)
    gold2 = common.link_with(common.GOLD, args2, wd)
    d2 = common.diff_report("D21 strindex==0 (오염 strtab[0]='Z')", bfd2, gold2,
        extra="예측: GOLD='Z..' 쓰레기 soname / BFD='' → 갈림(경고·rc·DT_NEEDED 값)")

    # 최종 산출물의 DT_NEEDED 를 각각 확인(soname 이 needed 로 기록되므로)
    for tag, out in [("BFD", os.path.join(wd, "main2")),
                     ("GOLD", os.path.join(wd, "main2"))]:
        if os.path.exists(out):
            _, no, _ = common.run(["readelf", "-d", out])
            need = [l.strip() for l in no.splitlines() if "NEEDED" in l]
            print(f"   {out} NEEDED: {need}")
            break  # 두 링크가 같은 -o 를 덮어쓰므로 마지막(GOLD) 것만 의미

    print("\n결론:",
          "예측대로 갈림 ✓ (BFD strindex==0 특례 vs GOLD 특례 없음)"
          if (d1 or d2) else "안 갈림 — 재확인 필요(소스라인/오염전제 점검)")


if __name__ == "__main__":
    main()
