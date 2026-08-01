#!/usr/bin/env python3
"""
exp_d17_et_core.py — D17: e_type=ET_CORE 로 패치한 오브젝트를 링크 "입력"으로.

소스 근거:
  gold  target.cc:99   Target::do_make_elf_object 계열에서 e_type 스위치.
        ET_REL/ET_DYN/ET_EXEC 외의 값(ET_CORE 포함)은 곧장 hard error:
        "unsupported ELF file type <n>" → 링크 즉시 중단(다른 시도 없음).
  bfd   elfcode.h:586  elf_object_p(): e_type 를 EXEC/DYN/REL/CORE 로만 분류하고
        ET_CORE 는 이 target vector 에서 유효 오브젝트로 매칭시키지 않는다.
        → BFD 는 이 벡터를 "wrong format" 으로 물리고 다른 backend vector 를
        차례로 재시도(bfd_check_format_matches 루프) → 최종적으로
        "file not recognized / file format not recognized" 류로 귀결.
예측:
  같은 ET_CORE 오브젝트 → GOLD 는 e_type 기반 hard error("unsupported ELF file type")
  로 즉사, BFD 는 wrong-format 판정 후 다른 벡터를 시도하다 "file format not
  recognized"(또는 유사) 로 거부. 둘 다 실패지만 실패 경로/메시지가 갈린다.

크래프팅:
  정상 .o 를 gcc -c 로 만든 뒤, ELF 헤더의 e_type(오프셋 16, 2바이트 LE)을
  ET_REL(1) → ET_CORE(4) 로 바이트 패치. e_type 오프셋은 ELF32/ELF64 공통 16.
  (pyelftools 로 e_ident/EI_CLASS 만 확인하고, 실제 패치는 최소 바이트 write)

실행:  python3 exp_d17_et_core.py      (사용자가 ! 로)
"""
import os, struct, tempfile, common

ET_CORE = 4
E_TYPE_OFF = 16  # e_ident(16바이트) 직후, ELF32/64 공통

def patch_e_type(path, new_type):
    """ELF 헤더 e_type(오프셋16, 2바이트)를 new_type 으로 덮어씀. EI_DATA 로 endian 결정."""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    assert data[:4] == b"\x7fELF", "not an ELF"
    ei_data = data[5]                      # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    old = struct.unpack_from(endian + "H", data, E_TYPE_OFF)[0]
    struct.pack_into(endian + "H", data, E_TYPE_OFF, new_type)
    with open(path, "wb") as f:
        f.write(data)
    return old

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d17_")
    # 1) 정상 오브젝트(.o) 하나 만든다 (ET_REL)
    src = os.path.join(wd, "u.c")
    open(src, "w").write("int helper(void){ return 7; }\n")
    obj = os.path.join(wd, "u.o")
    rc, o, e = common.run(["gcc", "-c", "-fPIC", "-o", obj, src], cwd=wd)
    assert rc == 0, f"obj build failed: {e}"

    # 2) e_type 을 ET_CORE(4) 로 패치
    old = patch_e_type(obj, ET_CORE)
    print(f"patched e_type: {old} (ET_REL) -> {ET_CORE} (ET_CORE)")
    _, ro, _ = common.run(["readelf", "-h", obj])
    for line in ro.splitlines():
        if "Type:" in line:
            print("   readelf:", line.strip())

    # 3) 이 ET_CORE 오브젝트를 링크 입력으로 (실행파일 만들기 시도)
    outp = os.path.join(wd, "out")
    args = ["-nostdlib", "-e", "helper", obj, "-o", outp]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report("D17 ET_CORE-as-input", bfd, gold,
        extra="예측: GOLD=hard error 'unsupported ELF file type' / "
              "BFD=wrong-format 재시도 후 'file format not recognized'")
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")

if __name__ == "__main__":
    main()
