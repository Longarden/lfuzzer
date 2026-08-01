#!/usr/bin/env python3
"""
exp_d04_audit.py — D04: .so 의 .dynamic 에 DT_AUDIT(0x6ffffefb) 주입.

소스 근거:
  bfd  elflink.c:4577  case DT_AUDIT: elf_dt_audit(abfd)=info.name (dynstr 오프셋 읽어 저장)
                        → BFD 는 입력 DSO 의 DT_AUDIT 를 인식하고 audit 라이브러리 이름을 취함.
  gold dynobj.cc:339   sweep_dynamic 의 switch 에 DT_AUDIT case 없음(default:break)
                        → GOLD 는 이 태그를 완전히 무시하고 그냥 넘어감.
예측:
  같은 입력 DSO(.dynamic 에 DT_AUDIT 삽입) →
    BFD  = DT_AUDIT 를 파싱(elf_dt_audit 세팅), 링크는 성공하되 태그를 소비/전파할 수 있음.
    GOLD = 태그 무시, 아무 반응 없이 링크.
  링크타임 관찰이 약하면(둘 다 rc 0) LD_DEBUG=all / strace 로 로더 audit 훅 흔적을 보강.

크래프팅:
  pyelftools 로 .so 를 읽어 .dynamic 섹션의 파일 오프셋과 엔트리 크기를 구하고,
  첫 DT_NULL(=0) 슬롯을 찾아 그 자리에 (d_tag=0x6ffffefb, d_val=기존 .dynstr 내
  임의 문자열 오프셋) 을 바이트 패치로 덮어쓴다. DT_NULL 은 배열 종결자라
  그 앞 엔트리들 뒤에 하나 이상 존재(보통 패딩으로 여러 개) → 첫 슬롯만 바꾸면
  뒤에 남은 DT_NULL 이 계속 종결자 역할을 하므로 배열이 깨지지 않는다.
  d_val 은 .dynstr 안의 유효 오프셋(SONAME 문자열 오프셋 재사용)으로 넣어
  BFD 가 elf_dt_audit 로 읽을 때 유효 문자열을 가리키게 한다.

실행:  python3 exp_d04_audit.py      (사용자가 ! 로)
"""
import os, struct, tempfile, common

DT_AUDIT = 0x6ffffefb
DT_NULL  = 0x0
DT_SONAME = 0xE  # 14, d_val 재사용용 문자열 오프셋 소스

def craft_audit_so(src_so, dst_so):
    """
    src_so 를 복사한 dst_so 의 .dynamic 첫 DT_NULL 슬롯을
    (DT_AUDIT, <dynstr offset>) 로 바이트 패치. (오프셋, d_val) 반환.
    """
    from elftools.elf.elffile import ELFFile

    with open(src_so, "rb") as f:
        data = bytearray(f.read())

    # .dynamic 섹션 위치/엔트리 크기 + .dynstr 내 SONAME 오프셋을 pyelftools 로 확보
    with open(src_so, "rb") as f:
        elf = ELFFile(f)
        is64 = elf.elfclass == 64
        little = elf.little_endian
        dyn = elf.get_section_by_name(".dynamic")
        assert dyn is not None, ".dynamic 없음"
        sh_off = dyn["sh_offset"]
        ent = dyn["sh_entsize"] or (16 if is64 else 8)
        # d_val 로 재사용할 유효 dynstr 오프셋: SONAME 태그의 d_ptr(=문자열 오프셋)
        soname_val = None
        for tag in dyn.iter_tags():
            if tag.entry.d_tag == "DT_SONAME":
                soname_val = tag.entry.d_val  # dynstr 내 오프셋
                break
        if soname_val is None:
            soname_val = 1  # 폴백: dynstr[1] (dynstr[0]은 항상 '\0')

    endian = "<" if little else ">"
    fmt = endian + ("QQ" if is64 else "II")  # d_tag, d_val

    # .dynamic 배열을 훑어 첫 DT_NULL 엔트리 파일 오프셋을 찾는다
    n = 0
    null_off = None
    while True:
        off = sh_off + n * ent
        if off + ent > len(data):
            break
        d_tag, d_val = struct.unpack_from(fmt, data, off)
        if d_tag == DT_NULL:
            null_off = off
            break
        n += 1
    assert null_off is not None, "DT_NULL 슬롯을 못 찾음(.dynamic 종결자 없음)"

    # 첫 DT_NULL 슬롯을 DT_AUDIT 로 덮어쓴다 (뒤 슬롯이 종결자 유지)
    struct.pack_into(fmt, data, null_off, DT_AUDIT, soname_val)
    with open(dst_so, "wb") as f:
        f.write(data)
    return null_off, soname_val

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d04_")

    # 1) 정상 공유 라이브러리 하나
    base = common.make_base_lib(wd, name="libfoo", soname="libfoo.so.1")

    # 2) .dynamic 첫 DT_NULL → DT_AUDIT 주입한 변종 DSO
    audit_so = os.path.join(wd, "libfoo_audit.so")
    try:
        off, val = craft_audit_so(base, audit_so)
        print(f"[craft] DT_AUDIT 주입: .dynamic off=0x{off:x}, "
              f"d_val=dynstr[0x{val:x}] (SONAME 오프셋 재사용)")
    except Exception as ex:
        # best-effort: 크래프팅 실패 시에도 스크립트는 남기되 무엇을 볼지 명시
        print(f"[craft][WARN] DT_AUDIT 주입 실패: {ex}")
        print("  → 확인할 것: pyelftools 설치 여부, .so 에 .dynamic/DT_NULL/DT_SONAME 존재 여부.")
        print("  → 폴백: readelf -d libfoo.so 로 종결 DT_NULL 슬롯 파일오프셋을 수동 계산해 패치.")
        return

    # (확인) BFD readelf 로 DT_AUDIT 가 실제로 보이는지
    _, ro, _ = common.run(["readelf", "-d", audit_so])
    print("readelf -d libfoo_audit.so (발췌):")
    for line in ro.splitlines():
        if "AUDIT" in line or "0x6ffffefb" in line or "NULL" in line:
            print("   ", line.strip())

    # 3) 이 변종 DSO 를 링크 입력으로 소비 (main → foo() 호출)
    csrc = common.make_consumer(wd, audit_so, name="main")
    out  = os.path.join(wd, "prog")
    args = [csrc, audit_so, "-o", out, f"-Wl,-rpath,{wd}"]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report("D04 DT_AUDIT-injection", bfd, gold,
        extra=("예측: BFD=DT_AUDIT 파싱(elf_dt_audit 세팅, 무해히 링크) / "
               "GOLD=태그 무시\n"
               "링크타임 신호 약하면 아래 로더 보강 참고."))

    # 4) 링크타임이 조용하면 로더(ld.so) audit 훅으로 보강 관찰
    #    - BFD 로 링크된 prog 실행 시 LD_DEBUG 로 audit 흔적 유무 확인
    if os.path.exists(out):
        env = dict(os.environ, LD_DEBUG="all", LD_LIBRARY_PATH=wd)
        rc, o, e = common.run([out], env=env)
        hits = [ln for ln in (e or "").splitlines()
                if "audit" in ln.lower() or "la_" in ln]
        print("  [LD_DEBUG=all 보강] audit 관련 라인:",
              (hits[:3] if hits else "없음(로더 audit 훅 미발동)"))
    else:
        print("  [보강] 실행파일 미생성 — 링크 단계 stderr 로만 판정.")

    print("\n결론:",
          "예측대로 갈림 ✓ (BFD DT_AUDIT 인식 vs GOLD 무시)" if diverged
          else "링크타임 안 갈림 — LD_DEBUG/strace 로더 관찰로 재확인 필요")

if __name__ == "__main__":
    main()
