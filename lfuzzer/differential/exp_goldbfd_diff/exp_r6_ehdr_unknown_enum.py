#!/usr/bin/env python3
"""
exp_r6_ehdr_unknown_enum.py — R6: e_machine 을 미지 열거값(0x9999)으로 패치.

소스 근거(관측 기반):
  readelf -h   : binutils/readelf.c get_machine_name() 는 미등록 EM_* 값을 만나면
                 "<unknown>: 0xNNNN" 문자열로 표시하고 헤더 덤프를 그대로 계속한다.
                 (관측 대상 줄:  readelf -h 출력의 "Machine:" 라인)
  objdump -f   : BFD elf_object_p (bfd/elfcode.h) → elf_backend 매칭 단계에서
                 알 수 없는 e_machine 은 어떤 target 백엔드와도 안 붙어
                 "file format not recognized" 로 거부한다.
                 (관측 대상 줄:  objdump -f 출력의 에러 라인)
예측(BFD vs GOLD 계열 = readelf 관용 vs objdump/BFD 엄격):
  같은 파일 하나에 두 도구를 돌린다.
    readelf -h  → rc 0, "Machine:  <unknown>: 0x9999" 표시하고 계속       (표시)
    objdump -f  → rc≠0, "file format not recognized" 거부                (거부)
  이 실험의 대조축은 gold/bfd 링커가 아니라 "표시형 파서 vs 포맷판정 파서" 다.
  (common.diff_report 의 두 슬롯에 readelf 결과와 objdump 결과를 넣어 재사용한다.)

크래프팅:
  정상 .o(또는 .so) 를 만든 뒤 ELF 헤더의 e_machine 필드(1워드=2바이트)만
  0x9999 로 덮어쓴다. e_machine 오프셋:
    e_ident(16) + e_type(2) = 18 (0x12), 리틀엔디언 2바이트.
  나머지 헤더/섹션은 손대지 않으므로 크래프팅은 최소이며 구조적으로 CORRECT.

직접 실행:
  ./exp_r6_ehdr_unknown_enum.py      (사용자가 ! 로 직접)
  또는  python3 exp_r6_ehdr_unknown_enum.py

결과 판독(무슨 줄을 보나):
  1) readelf -h 출력의  "Machine:" 줄  → "<unknown>: 0x9999" 여야 관용(표시).
  2) objdump -f 출력/에러 → "file format not recognized" 여야 엄격(거부).
  3) 결론 줄: 표시 vs 거부로 갈리면 예측대로 ✓.
"""
import os, struct, tempfile, common

# ELF64/32 공통: e_machine 은 e_ident(16) + e_type(2) 뒤 → 오프셋 0x12, 2바이트 LE
E_MACHINE_OFF = 0x12
UNKNOWN_EM = 0x9999


def patch_e_machine(path, value=UNKNOWN_EM):
    """대상 ELF 의 e_machine 워드만 value 로 덮어쓴다(1워드 패치, best-effort:
    엔디언은 e_ident[EI_DATA]=ELFDATA2LSB 인 x86-64 기준 리틀엔디언 고정)."""
    with open(path, "r+b") as f:
        f.seek(0)
        assert f.read(4) == b"\x7fELF", "not an ELF"
        f.seek(5)
        ei_data = f.read(1)[0]           # 1=LE, 2=BE
        endian = "<" if ei_data == 1 else ">"
        f.seek(E_MACHINE_OFF)
        old = struct.unpack(endian + "H", f.read(2))[0]
        f.seek(E_MACHINE_OFF)
        f.write(struct.pack(endian + "H", value))
        return old


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_r6_")

    # 1) 정상 오브젝트 하나 컴파일 (.o 로 충분: objdump -f 가 포맷 판정만 하면 됨)
    src = os.path.join(wd, "t.c")
    open(src, "w").write("int x = 42;\n")
    obj = os.path.join(wd, "t.o")
    rc, o, e = common.run(["gcc", "-c", "-o", obj, src], cwd=wd)
    assert rc == 0, f"compile failed: {e}"

    # 2) e_machine 을 미지값 0x9999 로 1워드 패치
    old = patch_e_machine(obj, UNKNOWN_EM)
    print(f"e_machine 패치: 0x{old:04x} → 0x{UNKNOWN_EM:04x}  (offset 0x{E_MACHINE_OFF:x})")

    # 3) 같은 파일에 두 도구를 돌린다: 표시형(readelf) vs 포맷판정형(objdump)
    readelf_res = common.run(["readelf", "-h", obj])   # (rc, out, err)
    objdump_res = common.run(["objdump", "-f", obj])

    # readelf "Machine:" 줄, objdump 에러 줄 발췌
    rmach = next((l.strip() for l in readelf_res[1].splitlines() if "Machine:" in l), "(Machine 줄 없음)")
    ojerr = (objdump_res[2] or objdump_res[1]).strip().splitlines()
    ojerr = ojerr[0] if ojerr else "(출력 없음)"

    print("\nreadelf -h  Machine 줄 :", rmach)
    print("objdump -f  에러/출력   :", ojerr)

    # diff_report 재사용: 슬롯1=readelf, 슬롯2=objdump 로 넣어 rc/stderr 대조
    diverged = common.diff_report(
        "R6 e_machine=0x9999 (표시 vs 거부)",
        readelf_res, objdump_res,
        extra=("슬롯 해석:  BFD 칸=readelf -h (표시형)  /  GOLD 칸=objdump -f (포맷판정형)\n"
               "예측: readelf rc0 '<unknown>: 0x9999' / objdump rc≠0 'file format not recognized'"))

    # 판독: readelf 는 unknown 표시하며 rc0, objdump 는 거부(rc≠0)
    readelf_shows = ("unknown" in rmach.lower()) or (str(UNKNOWN_EM) in rmach) or ("9999" in rmach.lower())
    objdump_rejects = (objdump_res[0] != 0) and ("not recognized" in ojerr.lower() or "recognized" in ojerr.lower())

    verdict = readelf_shows and objdump_rejects
    print("\n결론:",
          "예측대로 갈림 ✓ — readelf는 <unknown> 표시·계속, objdump/BFD는 포맷 거부"
          if verdict else
          f"재확인 필요(readelf_shows={readelf_shows}, objdump_rejects={objdump_rejects}, diverged={diverged})")


if __name__ == "__main__":
    main()
