#!/usr/bin/env python3
"""
exp_r5_phdr_vs_sht.py — R5: 섹션 sh_addr 를 그 섹션을 덮는 PT_LOAD 와 어긋나게 패치.

소스 근거(관측 기반 divergence, 파서/도구 view 차이):
  readelf -S : elfcomm/readelf.c 의 process_section_headers → SHT(section header table)의
               sh_addr 값을 그대로 주소로 출력한다. 섹션 관점(section view).
  objdump    : binutils/objdump.c dump_section_header → 마찬가지로 SHT sh_addr 사용.
  radare2 iS : r2 의 iS(=sections)는 "로더가 실제로 매핑하는" PT_LOAD 세그먼트 기준
               (libr/bin/format/elf/elf.c 의 Elf_(r_bin_elf_get_maps)/get_sections_from_phdr)
               으로 주소를 재계산 → 세그먼트 관점(segment/loader view).
  => 같은 .so 안에서 특정 섹션의 sh_addr 만 PT_LOAD 커버리지와 어긋나게 만들면,
     readelf/objdump(SHT view) 와 r2 iS(PT_LOAD view) 가 같은 섹션/심볼에 대해
     서로 다른 주소를 보고한다. 정적 도구 간 "주소 진실"이 갈리는 지점.

예측(BFD vs GOLD 링커 산출물이 아니라, 같은 손상 .so 를 두 도구가 어떻게 읽나):
  - readelf -S : 패치된 sh_addr (원래 vaddr + 0x1000) 를 그대로 표시  → +0x1000 어긋난 값.
  - r2 iS      : PT_LOAD 세그먼트로부터 재유도 → 원래(정상) vaddr 를 표시하거나
                 섹션을 세그먼트에 매핑 못해 vaddr=0/누락으로 처리.
  - 두 뷰의 .text 주소가 불일치하면 R5 divergence 재현.

크래프팅:
  pyelftools 로 정상 .so 를 읽어 .text(없으면 첫 SHF_ALLOC+PROGBITS) 의 SHT 엔트리를
  파일에서 찾아 sh_addr 필드만 +0x1000 in-place 패치. PT_LOAD phdr 는 건드리지 않는다
  → 섹션은 여전히 원래 세그먼트에 물리적으로 존재하지만 SHT 는 거짓 주소를 주장.
  (best-effort: sh_offset 은 그대로 두어 파일 오프셋↔주소 관계만 깨뜨림. 링크/로드 유효성은
   목표가 아님 — 정적 도구 view 갈림이 목표.)

직접 실행:
  python3 exp_r5_phdr_vs_sht.py        (사용자가 ! 로 직접)

결과 판독(무슨 줄을 보나):
  - "readelf -S .text" 줄의 Addr 컬럼 vs "r2 iS .text" 줄의 vaddr/paddr.
  - 두 주소가 0x1000 만큼(혹은 그 이상) 다르면 => R5 재현: SHT view != PT_LOAD view.
  - 맨 끝 "결론:" 줄에서 갈림 여부 확정.
"""
import os, struct, tempfile, common

def _pick_section(elf, want=".text"):
    """대상 섹션 인덱스 선택: .text 우선, 없으면 첫 SHF_ALLOC+PROGBITS 섹션."""
    from elftools.elf.constants import SH_FLAGS
    idx_named = None
    idx_fallback = None
    for i in range(elf.num_sections()):
        s = elf.get_section(i)
        if s.name == want:
            idx_named = i
        if (idx_fallback is None and s['sh_type'] == 'SHT_PROGBITS'
                and (s['sh_flags'] & SH_FLAGS.SHF_ALLOC)):
            idx_fallback = i
    return idx_named if idx_named is not None else idx_fallback

def _patch_sh_addr(path, sec_index, delta):
    """
    SHT 엔트리 sec_index 의 sh_addr 필드만 +delta 로 in-place 패치(ELF64 LE 가정).
    반환: (old_addr, new_addr). Elf64_Shdr 레이아웃:
      name(4) type(4) flags(8) addr(8) offset(8) ...  → sh_addr 는 엔트리 시작+16.
    (best-effort: 32비트/BE 는 이 실험 범위 밖, ELF64 LE 만 지원.)
    """
    with open(path, "rb") as f:
        data = bytearray(f.read())
    assert data[:4] == b"\x7fELF", "not an ELF"
    assert data[4] == 2, "ELF64 만 지원(EI_CLASS != 2)"
    e_shoff   = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsz = struct.unpack_from("<H", data, 0x3A)[0]
    ent = e_shoff + sec_index * e_shentsz
    addr_off = ent + 16                      # sh_addr 필드 위치
    old_addr = struct.unpack_from("<Q", data, addr_off)[0]
    new_addr = old_addr + delta
    struct.pack_into("<Q", data, addr_off, new_addr)
    with open(path, "wb") as f:
        f.write(data)
    return old_addr, new_addr

def _readelf_addr(path, secname):
    """readelf -S 출력에서 secname 섹션의 Addr(16진) 문자열 추출."""
    _, o, _ = common.run(["readelf", "-SW", path])
    for line in o.splitlines():
        # 예: "  [11] .text  PROGBITS  0000000000001060 001060 ..."
        if secname in line and "PROGBITS" in line:
            parts = line.replace("[", " ").replace("]", " ").split()
            for p in parts:
                if len(p) >= 8 and all(c in "0123456789abcdefABCDEF" for c in p):
                    return p
    return None

def _r2_addr(path, secname):
    """r2 iSj(JSON) 에서 secname 섹션의 vaddr 를 뽑는다. r2 없으면 None."""
    import json
    if not (common.run(["which", "r2"])[0] == 0):
        return "(r2 미설치)"
    _, o, _ = common.run(["r2", "-q", "-c", "iSj", "-e", "scr.color=0", path])
    try:
        # iSj 출력은 [ {..} ] 배열(때로 앞뒤 잡음) — 첫 '[' 부터 파싱.
        s = o[o.index("["):]
        arr = json.loads(s)
        for sec in arr:
            if sec.get("name", "").endswith(secname.lstrip(".")) or sec.get("name") == secname:
                return hex(sec.get("vaddr", 0))
    except Exception as e:
        return f"(r2 파싱실패:{e})"
    return None

def main():
    common.banner()
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        print("pyelftools 필요: pip install pyelftools"); return

    wd = tempfile.mkdtemp(prefix="exp_r5_")
    # 1) 정상 .so 하나 만든다(공용 헬퍼) — 이게 손상 대상.
    so = common.make_base_lib(wd, name="libr5")

    # 2) 대상 섹션(.text) 선택 + sh_addr 를 +0x1000 어긋나게 패치.
    with open(so, "rb") as f:
        elf = ELFFile(f)
        sec_idx = _pick_section(elf, ".text")
        sec_name = elf.get_section(sec_idx).name
    assert sec_idx is not None, "패치할 SHF_ALLOC PROGBITS 섹션을 못 찾음"
    DELTA = 0x1000
    old_addr, new_addr = _patch_sh_addr(so, sec_idx, DELTA)
    print(f"패치: 섹션 '{sec_name}' (idx {sec_idx})  sh_addr "
          f"0x{old_addr:x} -> 0x{new_addr:x}  (+0x{DELTA:x})")
    print(f"  PT_LOAD phdr 는 그대로 → 로더 view 는 여전히 0x{old_addr:x} 근처 기대\n")

    # 3) 두 도구의 주소 view 비교.
    re_addr = _readelf_addr(so, sec_name)   # SHT view
    r2_addr = _r2_addr(so, sec_name)        # PT_LOAD view
    print(f"  readelf -S  {sec_name} Addr = {re_addr}    (SHT sh_addr view)")
    print(f"  r2 iS       {sec_name} vaddr= {r2_addr}    (PT_LOAD loader view)")

    # 4) diff_report 형식 재사용(도구 stdout 을 stderr 슬롯에 실어 나란히 표시).
    _, re_out, _ = common.run(["readelf", "-SW", so])
    _, objd_out, _ = common.run(["objdump", "-h", so])
    bfd_like  = (0, "", f"readelf {sec_name} Addr={re_addr}")
    gold_like = (0, "", f"r2 iS   {sec_name} vaddr={r2_addr}")
    common.diff_report("R5 SHT-view vs PT_LOAD-view", bfd_like, gold_like,
        extra=f"objdump -h {sec_name} 주소도 readelf 와 같은 SHT view 여야 함")

    # 5) 판정: 두 주소가 파싱되고 서로 다르면 divergence.
    def _to_int(x):
        try: return int(x, 16)
        except Exception: return None
    a, b = _to_int(re_addr), _to_int(r2_addr)
    if a is not None and b is not None and a != b:
        verdict = f"예측대로 갈림 ✓  (readelf 0x{a:x} != r2 0x{b:x}, Δ=0x{abs(a-b):x})"
    elif a is not None and b is not None:
        verdict = f"안 갈림 — 두 도구 주소 동일(0x{a:x}). r2 가 SHT 를 신뢰했을 수 있음"
    else:
        verdict = f"판정 불가 — readelf={re_addr} r2={r2_addr} (도구/파싱 확인 필요)"
    print("\n결론:", verdict)

if __name__ == "__main__":
    main()
