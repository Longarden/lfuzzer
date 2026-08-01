#!/usr/bin/env python3
"""
exp_d02_dynstr_nonul.py — D02: .dynstr 마지막 NUL 종단자 제거 → GOLD SONAME strlen over-read.
출력: ./out_bfd, ./out_gold (실행파일 ELF, 현재 디렉토리)
"""
import os, tempfile, subprocess, common
from elftools.elf.elffile import ELFFile

CWD = os.path.dirname(os.path.abspath(__file__))


def dynstr_last_byte_off(so_path):
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        s = elf.get_section_by_name(".dynstr")
        assert s is not None, ".dynstr 섹션 없음"
        off, size = s["sh_offset"], s["sh_size"]
    return off + size - 1, off, size


def dump_dynstr(so_path):
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        ds = elf.get_section_by_name(".dynstr")
        raw = ds.data()
    strings = raw.split(b"\x00")
    print(f"[.dynstr 문자열 순서] {strings}")
    last = [s for s in strings if s]
    if last:
        print(f"  → 실질적 마지막 문자열: {last[-1]}")
        if b"libfoo" in last[-1]:
            print("  → SONAME이 마지막 위치 ✓ — over-read 경로 유효")
        else:
            print("  → SONAME이 마지막이 아님 ✗ — over-read 경로 미도달 가능성 있음")


def valgrind_on(linker_path, args, workdir):
    if not common.shutil.which("valgrind"):
        return None
    cmd = ["valgrind",
           "--error-exitcode=99",
           "--track-origins=yes",
           "--pages-as-heap=yes",
           "--malloc-fill=0xff",
           "--redzone-size=32",
           linker_path] + args
    return common.run(cmd, cwd=workdir)


def summarize_valgrind(res):
    if res is None:
        return "(valgrind 미설치)"
    rc, o, e = res
    keep = [ln.strip() for ln in (e or "").splitlines()
            if any(k in ln.lower() for k in
                   ("invalid read", "invalid write", "strlen",
                    "soname", "read_dynamic", "bytes after a block"))]
    return (" ⏎ ".join(keep[:12]) if keep else "(경계밖 접근 신호 없음)") + f"  [rc={rc}]"


def main():
    common.banner()
    if not common.shutil.which("valgrind"):
        print("주의: valgrind 미설치 → over-read 계측 불가. sudo apt-get install -y valgrind")

    wd = tempfile.mkdtemp(prefix="exp_d02_")

    # 1) foo 구현체 .so 빌드
    so = common.make_base_lib(wd, name="libfoo", soname="libfoo.so.1")

    # 2) .dynstr 마지막 NUL → 0x41 패치
    last_off, ds_off, ds_size = dynstr_last_byte_off(so)
    orig = open(so, "rb").read()[last_off]
    assert orig == 0, f".dynstr 끝이 NUL 이 아님(0x{orig:02x}) — 대상 부적합"
    common.patch_bytes(so, last_off, b"\x41")
    print(f"[craft] .dynstr @0x{ds_off:x} size={ds_size}  "
          f"마지막바이트 @0x{last_off:x}: 0x00 → 0x41 (NUL 종단자 제거)")

    # 3) .dynstr 문자열 순서 확인
    dump_dynstr(so)

    # 4) main.c 컴파일 → main.o
    main_c = os.path.join(wd, "main.c")
    main_o = os.path.join(wd, "main.o")
    with open(main_c, "w") as f:
        f.write('#include <stdio.h>\nextern void foo(void);\nint main(){foo();return 0;}\n')
    subprocess.run(["gcc", "-c", "-o", main_o, main_c], check=True)

    # 5) 출력 경로: 현재 디렉토리 (실행파일 ELF)
    out_bfd  = os.path.join(CWD, "out_bfd")
    out_gold = os.path.join(CWD, "out_gold")

    dynlinker = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
    args_bfd  = ["-o", out_bfd,  main_o, so, "-lc", f"--dynamic-linker={dynlinker}"]
    args_gold = ["-o", out_gold, main_o, so, f"--dynamic-linker={dynlinker}"]


    # 6) valgrind 계측
    bfd_vg  = valgrind_on(common.BFD,  args_bfd,  wd)
    gold_vg = valgrind_on(common.GOLD, args_gold, wd)

    # 7) rc/stderr 대조
    bfd  = common.run([common.BFD]  + args_bfd,  cwd=wd)
    gold = common.run([common.GOLD] + args_gold, cwd=wd)

    bfd_rc,  _, bfd_err  = bfd
    gold_rc, _, gold_err = gold

    # 8) 생성 결과 출력
    print("\n[출력 파일]")

    if bfd_rc == 0 and os.path.exists(out_bfd):
        print(f"  BFD  → {out_bfd}  (생성 성공)")
        subprocess.run([out_bfd])
    else:
        print(f"  BFD  → out_bfd 생성 실패 (rc={bfd_rc})")
        if bfd_err:
            print(f"         사유: {bfd_err.strip()}")

    if gold_rc == 0 and os.path.exists(out_gold):
        print(f"  GOLD → {out_gold}  (생성 성공)")
        subprocess.run([out_gold])
    else:
        print(f"  GOLD → out_gold 생성 실패 (rc={gold_rc})")
        if gold_err:
            print(f"         사유: {gold_err.strip()}")

    # 9) diff 리포트
    common.diff_report(
        "D02 dynstr-no-NUL (SONAME over-read)", bfd, gold,
        extra=("valgrind(BFD)  : " + summarize_valgrind(bfd_vg) + "\n"
               "valgrind(GOLD) : " + summarize_valgrind(gold_vg)))

    # 10) 결론
    gold_overread = (gold_vg is not None
                     and ("invalid read" in (gold_vg[2] or "").lower()
                          or gold_vg[0] == 99))
    print("\n결론:",
          "GOLD 에서 .dynstr 경계밖 Invalid read 관찰 ✓ (예측대로 SONAME over-read)"
          if gold_overread else
          "over-read 미관찰 — valgrind 설치/SONAME 배치·읽기경로 재확인 필요")


if __name__ == "__main__":
    main()
