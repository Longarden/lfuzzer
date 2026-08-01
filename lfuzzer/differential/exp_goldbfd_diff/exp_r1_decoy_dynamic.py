#!/usr/bin/env python3
"""
exp_r1_decoy_dynamic.py — R1: .dynamic 섹션헤더 sh_offset 를 decoy 배열로 돌리기.

(1) 소스 근거:
  readelf.c:6767  process_dynamic_section() 안에서 readelf 는 "섹션 헤더" 경로로
                  .dynamic 을 찾을 때 그 섹션의 sh_offset/sh_size 를 그대로 신뢰해
                  거기서 Elf_Dyn 배열을 읽는다 (dynamic_addr = section->sh_offset).
                  즉 readelf -d 는 PT_DYNAMIC(세그먼트)이 아니라 SHT 항목을 본다.
  대조: 실제 런타임 로더(ld.so)는 섹션 헤더를 아예 로드하지 않고 PT_DYNAMIC
        프로그램 헤더의 p_offset/p_vaddr 만 본다. → 두 뷰를 갈라놓을 수 있다.

(2) 예측 (BFD vs GOLD 링커 산출물 둘 다):
  링크 자체는 두 링커 모두 정상(rc 0) — 우리는 링크 "후"의 산출물을 패치한다.
  패치 후:
    readelf -d  (섹션 뷰)  → decoy 배열을 읽음 → 맨 앞에 심은 DT_NULL 때문에
                             "contains 1 entries" 로 조기 종료(사실상 빈 동적 정보).
    readelf -l  (세그먼트 뷰) / PT_DYNAMIC → 원본 오프셋 그대로 → 진짜 DT_NEEDED 등 다 보임.
  ∴ 같은 파일에서 "섹션 뷰(readelf -d)" 와 "세그먼트 뷰(로더)" 가 갈린다.
  BFD/GOLD 산출물 모두에서 동일하게 재현되어야 한다(readelf 파싱 규칙은 링커 무관).

(3) 크래프팅:
  - 두 링커로 각각 정상 DSO(out.so) 를 링크한다.
  - pyelftools 로 .dynamic 섹션(sh_offset/sh_size)과 그 섹션헤더 엔트리 위치,
    그리고 PT_DYNAMIC 세그먼트(p_offset) 를 읽어둔다.
  - decoy = [DT_NULL] + (원본 .dynamic 바이트 전체) 를 파일 끝(8바이트 정렬)에 append.
  - .dynamic 섹션헤더의 sh_offset 만 decoy 오프셋으로, sh_size 는 decoy 길이로 바이트 패치.
    PT_DYNAMIC 프로그램헤더는 절대 건드리지 않음 → 로더 뷰 불변.
  ※ pyelftools 는 read-only 이므로 실제 패치는 struct 로 원바이트 오버라이트(64bit Elf64_Shdr:
    sh_offset @+24, sh_size @+32; Elf64_Dyn 엔트리 = 16바이트).

(4) 실행법:
  python3 exp_r1_decoy_dynamic.py      (사용자가 ! 로 직접)
"""
import os, tempfile, struct, common
from elftools.elf.elffile import ELFFile


def _dynamic_geometry(path):
    """(.dynamic 섹션 sh_offset, sh_size, 섹션헤더엔트리 파일오프셋, PT_DYNAMIC p_offset, is64) 반환."""
    with open(path, "rb") as f:
        elf = ELFFile(f)
        is64 = elf.elfclass == 64
        e_shoff = elf["e_shoff"]
        e_shentsize = elf["e_shentsize"]
        sec_off = sec_size = sec_hdr_pos = None
        for i in range(elf.num_sections()):
            s = elf.get_section(i)
            if s.name == ".dynamic":
                sec_off = s["sh_offset"]
                sec_size = s["sh_size"]
                sec_hdr_pos = e_shoff + i * e_shentsize
                break
        pt_dyn_off = None
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_DYNAMIC":
                pt_dyn_off = seg["p_offset"]
                break
    assert sec_off is not None, ".dynamic 섹션 없음"
    return sec_off, sec_size, sec_hdr_pos, pt_dyn_off, is64


def craft_decoy(path):
    """path 를 in-place 패치: .dynamic 섹션헤더 sh_offset 를 [DT_NULL]+원본 decoy 로 돌림."""
    sec_off, sec_size, sec_hdr_pos, pt_dyn_off, is64 = _dynamic_geometry(path)
    assert is64, "이 실험은 ELF64 가정(gcc 기본). 32bit 면 오프셋 상수 조정 필요."
    with open(path, "r+b") as f:
        blob = f.read()
        real_dyn = blob[sec_off:sec_off + sec_size]
        # decoy = 맨 앞 DT_NULL(tag=0, val=0) 한 칸 + 원본 전체 → readelf -d 는 즉시 종료
        decoy = struct.pack("<qQ", 0, 0) + real_dyn
        # 파일 끝 8바이트 정렬 위치에 append
        f.seek(0, os.SEEK_END)
        end = f.tell()
        pad = (-end) % 8
        f.write(b"\x00" * pad)
        decoy_off = end + pad
        f.write(decoy)
        # 섹션헤더 엔트리 패치: Elf64_Shdr 에서 sh_offset @+24, sh_size @+32 (각 8바이트 LE)
        f.seek(sec_hdr_pos + 24)
        f.write(struct.pack("<Q", decoy_off))
        f.seek(sec_hdr_pos + 32)
        f.write(struct.pack("<Q", len(decoy)))
    return {"real_off": sec_off, "decoy_off": decoy_off,
            "pt_dyn_off": pt_dyn_off, "real_size": sec_size}


def _readelf_d_count(path):
    """readelf -d 출력에서 엔트리 요약 라인만 뽑기."""
    _, o, _ = common.run(["readelf", "-d", path])
    lines = [ln.strip() for ln in o.splitlines()
             if "Dynamic section" in ln or "NEEDED" in ln or "SONAME" in ln]
    return o, lines


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_r1_")
    # 여러 DT_NEEDED 가 생기도록 base lib 를 소비하는 DSO 를 만든다(원본 .dynamic 이 풍부해야 대비가 뚜렷).
    base = common.make_base_lib(wd, name="libfoo", soname="libfoo.so.1")
    csrc = os.path.join(wd, "user.c")
    open(csrc, "w").write(
        "extern int foo(void);\n"
        "int bar(void){ return foo() + 1; }\n")

    results = {}
    for tag, linker in (("BFD", common.BFD), ("GOLD", common.GOLD)):
        out = os.path.join(wd, f"out_{tag}.so")
        # base lib 를 링크 입력으로 넣어 DT_NEEDED(libfoo.so.1) 가 실제 .dynamic 에 들어가게
        args = ["-shared", "-fPIC", "-o", out, csrc,
                f"-L{wd}", "-l:libfoo.so.1", f"-Wl,-rpath,{wd}"]
        res = common.link_with(linker, args, wd)
        info = None
        if res[0] == 0 and os.path.exists(out):
            info = craft_decoy(out)
        results[tag] = (res, out, info)

    # 링커 산출물 두 개를 diff_report 로(링크 rc/stderr 비교)
    bfd_res = results["BFD"][0]
    gold_res = results["GOLD"][0]

    # 섹션뷰(readelf -d) vs 세그먼트뷰(PT_DYNAMIC) 실증: BFD 산출물 기준으로 상세 출력
    extra_lines = []
    decoy_ok = False
    for tag in ("BFD", "GOLD"):
        _, out, info = results[tag]
        if info is None:
            extra_lines.append(f"{tag}: 링크 실패 → 패치 스킵")
            continue
        full_d, d_lines = _readelf_d_count(out)
        # PT_DYNAMIC 원본 오프셋에서 진짜 DT_NEEDED 개수(참조용): readelf -d 는 이제 decoy 를 보므로
        # 원본을 직접 세어 대비한다.
        with open(out, "rb") as f:
            blob = f.read()
        real = blob[info["real_off"]:info["real_off"] + info["real_size"]]
        n_real = sum(1 for i in range(0, len(real), 16)
                     if struct.unpack_from("<q", real, i)[0] != 0)  # non-NULL 태그 수
        first_tag = struct.unpack_from("<q", blob, info["decoy_off"])[0]
        # decoy 첫 태그가 DT_NULL(0) 이고, readelf -d 가 DT_NEEDED 를 못 보면 divergence 성립
        d_needed_shown = any("NEEDED" in ln for ln in d_lines)
        this_ok = (first_tag == 0) and (not d_needed_shown) and (n_real > 0)
        decoy_ok = decoy_ok or this_ok
        extra_lines.append(
            f"{tag}: decoy_off={info['decoy_off']} first_tag={first_tag}(0=DT_NULL) "
            f"| readelf -d 가 본 NEEDED/SONAME 라인수={len(d_lines)} "
            f"| PT_DYNAMIC(real) non-NULL 엔트리={n_real} "
            f"| pt_dyn_off={info['pt_dyn_off']} real_off={info['real_off']}")
        if d_lines:
            extra_lines.append("   readelf -d(섹션뷰) 요약: " + " ; ".join(d_lines))

    common.diff_report("R1 decoy .dynamic (sh_offset→decoy, PT_DYNAMIC 불변)",
                       bfd_res, gold_res, extra="\n".join(extra_lines))

    print("\n결론:",
          "섹션뷰(readelf -d)가 PT_DYNAMIC 진짜 동적정보와 갈림 — decoy 성공 ✓"
          if decoy_ok else
          "안 갈림 — readelf 가 섹션헤더 대신 세그먼트를 봤거나 패치 실패, 재확인 필요")
    print("검증법: readelf -d out_BFD.so (decoy=거의 빈 출력) vs "
          "readelf -l out_BFD.so 의 DYNAMIC 세그먼트 오프셋(원본) 비교. "
          "readelf --use-dynamic 는 세그먼트 경로라 진짜가 보여야 함.")


if __name__ == "__main__":
    main()
