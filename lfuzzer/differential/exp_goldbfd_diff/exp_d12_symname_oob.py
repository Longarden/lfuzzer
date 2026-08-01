#!/usr/bin/env python3
"""
exp_d12_symname_oob.py — D12: .dynsym 심볼의 st_name 을 .dynstr 크기 밖으로 밀어
                          GOLD 가 심볼 이름을 읽을 때 무경계 over-read 하는지 관찰.

소스 근거:
  gold  dynobj.cc:846   sym_names + st_name 으로 곧장 문자열 포인터를 만든다(무경계).
                        st_name >= dynstr_size 이면 sym_names(문자열풀) 버퍼 밖 over-read.
  bfd   elf.c:348       bfd_elf_string_from_elf_section — st_name 을 strtab sh_size 와
                        비교(경계검사)해 초과 오프셋이면 NULL/에러 → over-read 안 남.
예측(BFD vs GOLD):
  BFD  = st_name 이 .dynstr sh_size 를 넘으면 경계검사에 걸려 안전 → valgrind clean.
  GOLD = 무경계 인덱싱으로 문자열풀 버퍼 밖을 strlen → valgrind 'Invalid read' 관측.
  rc 는 안 갈려도(둘 다 링크 성공) valgrind 로그가 갈림의 증거.

크래프팅(이전 실패 → 이번 수정):
  이전: valgrind 를 gcc 드라이버 전체에 걸어 cc1/collect2 노이즈가 신호를 덮었음.
  이번: (1) common.make_base_lib 로 완전 정상 .so 생성 → 초반 포맷검사 통과 보장.
        (2) 스트립 전에 pyelftools 로 .dynsym 첫 실제 심볼의 st_name 필드 파일오프셋과
            .dynstr sh_size 를 계산.
        (3) common.patch_bytes 로 그 st_name(4B) 만 (.dynstr sh_size + 큰값) 으로 외과 패치.
            나머지 바이트는 전부 유효 → 링커가 심볼 파싱 경로까지 실제 도달.
        (4) valgrind 를 GOLD ld-new '바이너리에 직접' 걸어 그 .so 를 읽게(gcc 우회로 cc1 노이즈 제거).
            BFD 도 동일하게 대조.

직접 실행:  ./exp_d12_symname_oob.py     (또는 python3 exp_d12_symname_oob.py, 사용자가 ! 로)
결과 판독:  아래 요약에서 GOLD 쪽에만 'Invalid read'/OOB 가 뜨면 예측대로 갈린 것.
"""
import os, struct, shutil, tempfile, common
from elftools.elf.elffile import ELFFile

# Elf64_Sym: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8) = 24B
SYM_SZ = 24


def first_named_dynsym(so_path):
    """.dynsym 에서 st_name!=0 인 첫 심볼의 (st_name_필드_파일오프셋, 기존값, .dynstr_sh_size, 이름)."""
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name(".dynsym")
        dynstr = elf.get_section_by_name(".dynstr")
        assert dynsym is not None, ".dynsym 없음 — DSO 아님?"
        assert dynstr is not None, ".dynstr 없음"
        base = dynsym["sh_offset"]
        ent = dynsym["sh_entsize"] or SYM_SZ
        n = dynsym["sh_size"] // ent
        raw = open(so_path, "rb").read()
        for i in range(n):
            off = base + i * ent               # st_name 은 엔트리 첫 4B
            (st_name,) = struct.unpack_from("<I", raw, off)
            if st_name != 0:                   # idx0 null 심볼 스킵
                return off, st_name, dynstr["sh_size"], dynsym.get_symbol(i).name
    raise RuntimeError("st_name!=0 인 .dynsym 심볼이 없음")


def valgrind_linker(linker_path, so_path, wd, tag):
    """valgrind 를 링커 바이너리에 직접 걸어 so 를 -shared 입력으로 읽게. (rc, 요약)."""
    if linker_path is None:
        return None
    out = os.path.join(wd, f"out_{tag}.so")
    cmd = ["valgrind", "-q", "--error-exitcode=0", "--errors-for-leak-kinds=none",
           linker_path, "-shared", "-o", out, so_path]
    rc, o, e = common.run(cmd)
    hits = [ln.strip() for ln in (e or "").splitlines()
            if any(k in ln for k in ("Invalid read", "Invalid write", "uninitialised",
                                     "bytes after a block", "bytes inside a block",
                                     "Address 0x", "ERROR SUMMARY", "out of range"))]
    return rc, "\n".join(hits[:14]) or "(valgrind 특이사항 없음)"


def has_oob(summary):
    s = summary or ""
    return any(k in s for k in ("Invalid read", "uninitialised",
                                "bytes after a block", "out of range"))


def main():
    common.banner()
    if shutil.which("valgrind") is None:
        print("경고: valgrind 없음 → over-read 관측 불가. `sudo apt install valgrind` 필요.")

    wd = tempfile.mkdtemp(prefix="exp_d12_")

    # 1) 완전 정상 .so 생성 (초반 포맷검사 통과 보장)
    so = common.make_base_lib(wd, name="libd12")

    # 2) 스트립 없이 .dynsym 첫 실제 심볼 st_name 필드 위치 + .dynstr 크기 산출
    name_off, old_stname, dynstr_size, symname = first_named_dynsym(so)
    new_stname = dynstr_size + 0x4000          # .dynstr 경계 훨씬 밖
    print(f"타깃 심볼: '{symname}'  st_name={old_stname} → {new_stname}  "
          f"(.dynstr sh_size={dynstr_size}, st_name 파일오프셋=0x{name_off:x})")

    # 3) 외과 패치: st_name(4B) 만 경계 밖 값으로. 나머지 전부 유효 유지.
    common.patch_bytes(so, name_off, struct.pack("<I", new_stname))

    # (확인) readelf 가 이 심볼을 어떻게 보나 — <corrupt>/깨진 이름이면 크래프팅 성공
    _, ro, _ = common.run(["readelf", "--dyn-syms", so])
    print("readelf --dyn-syms (발췌, corrupt 확인용):")
    for line in ro.splitlines()[:12]:
        print("   ", line.rstrip())

    # 4) valgrind 를 두 링커 바이너리에 직접 걸어 같은 .so 를 읽게
    bfd  = valgrind_linker(common.BFD,  so, wd, "bfd")
    gold = valgrind_linker(common.GOLD, so, wd, "gold")

    print("=" * 72)
    print("[D12 st_name OOB — valgrind on linker binary]   "
          f"{'>>> DIVERGED <<<' if (has_oob(gold[1]) if gold else False) and not (has_oob(bfd[1]) if bfd else False) else '(재확인)'}")
    if bfd:
        print(f"  BFD  rc={bfd[0]}\n    " + bfd[1].replace("\n", "\n    "))
    if gold:
        print(f"  GOLD rc={gold[0]}\n    " + gold[1].replace("\n", "\n    "))
    print(f"  BFD  path: {common.BFD}")
    print(f"  GOLD path: {common.GOLD}")
    print("  예측: GOLD=Invalid read(dynobj.cc:846 무경계) / BFD=clean(elf.c:348 경계검사)")

    g_oob = bool(gold and has_oob(gold[1]))
    b_oob = bool(bfd and has_oob(bfd[1]))
    if g_oob and not b_oob:
        verdict = "예측대로 갈림 ✓ — GOLD 만 st_name over-read(valgrind)"
    elif g_oob and b_oob:
        verdict = "둘 다 over-read — BFD 경계검사 예상과 다름, 소스 재확인"
    else:
        verdict = "GOLD OOB 미검출 — new_stname 값/심볼 선택/valgrind 유무 재조정 필요"
    print("\n결론:", verdict)


if __name__ == "__main__":
    main()
