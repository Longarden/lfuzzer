#!/usr/bin/env python3
"""
common.py — Gold vs BFD(ld) 링커 differential 실험 공용 엔진.

목적(방어적 연구): 같은 입력 ELF를 두 링커에 먹였을 때 동작이 어떻게 갈리는지
소스 대질(STRUCTURE_AUDIT/PLAN 아티팩트 D01~D24)에서 예측한 차이를 실제로 확인한다.
실행은 사용자가 `!` 로 직접 돌린다(이 세션의 분업). Claude는 설계/해석.

두 링커 바이너리(이미 빌드돼 있음, WSL):
  BFD  = ~/binutils-build-afl-bfd-clean/ld/ld-new
  GOLD = ~/binutils-build-gold/gold/ld-new
없으면 시스템 /usr/bin/ld, /usr/bin/ld.gold 로 폴백.
"""
import os, subprocess, shutil, tempfile, textwrap

HOME = os.path.expanduser("~")
BFD  = next((p for p in [
    f"{HOME}/binutils-build-afl-bfd-clean/ld/ld-new",
    "/usr/bin/ld", "/usr/bin/ld.bfd"] if os.path.exists(p)), None)
GOLD = next((p for p in [
    f"{HOME}/binutils-build-gold/gold/ld-new",
    "/usr/bin/ld.gold", "/usr/bin/gold"] if os.path.exists(p)), None)

def run(cmd, **kw):
    """명령 실행 → (rc, stdout, stderr). 타임아웃 30s."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kw)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except Exception as e:
        return -1, "", f"ERROR:{e}"

def link_with(linker_path, args, workdir):
    """
    gcc 를 드라이버로 쓰되 -B<dir> 트릭으로 특정 ld 바이너리를 강제.
    linker_path 를 <dir>/ld 심링크로 걸고 gcc -B<dir> 로 그 ld 를 쓰게 한다
    (exp_e3/e5 에서 쓰던 방식). args 는 gcc 뒤에 붙는 링크 인자.
    반환: (rc, stdout, stderr)
    """
    bindir = os.path.join(workdir, "ldwrap_" + os.path.basename(linker_path))
    os.makedirs(bindir, exist_ok=True)
    link = os.path.join(bindir, "ld")
    if os.path.lexists(link):
        os.remove(link)
    os.symlink(os.path.abspath(linker_path), link)
    return run(["gcc", f"-B{bindir}"] + args, cwd=workdir)

def make_base_lib(workdir, name="libfoo", soname=None, src=None):
    """정상 공유 라이브러리 하나 빌드 → 경로 반환. 이후 실험이 이걸 뮤테이트."""
    soname = soname or f"{name}.so.1"
    src = src or f'int foo(void){{ return 42; }}\n'
    c = os.path.join(workdir, f"{name}.c")
    so = os.path.join(workdir, f"{name}.so")
    open(c, "w").write(src)
    rc, o, e = run(["gcc", "-shared", "-fPIC", f"-Wl,-soname,{soname}",
                    "-o", so, c], cwd=workdir)
    assert rc == 0, f"base lib build failed: {e}"
    return so

def make_consumer(workdir, libpath, name="main"):
    """libpath 의 foo() 를 호출하는 프로그램 소스만 만들어 경로 반환(링크는 실험이)."""
    c = os.path.join(workdir, f"{name}.c")
    open(c, "w").write('extern int foo(void);\nint main(void){return foo();}\n')
    return c

def diff_report(title, bfd_res, gold_res, extra=""):
    """두 링커 결과를 나란히 출력 + 갈리는지 판정."""
    (brc, bo, be), (grc, go, ge) = bfd_res, gold_res
    def short(s): return (s or "").strip().replace("\n", " ⏎ ")[:200]
    diverged = (brc != grc) or (bool(be.strip()) != bool(ge.strip()))
    print("=" * 72)
    print(f"[{title}]   {'>>> DIVERGED <<<' if diverged else '(같음)'}")
    print(f"  BFD  rc={brc:<4} stderr={short(be)}")
    print(f"  GOLD rc={grc:<4} stderr={short(ge)}")
    if extra:
        print("  " + extra.replace("\n", "\n  "))
    print(f"  BFD  path: {BFD}")
    print(f"  GOLD path: {GOLD}")
    return diverged

def banner():
    print(textwrap.dedent(f"""
    ───────────────────────────────────────────────────────────
     Gold vs BFD differential 실험
       BFD  = {BFD}
       GOLD = {GOLD}
    ───────────────────────────────────────────────────────────
    """))

import struct as _struct

def patch_bytes(path, offset, data):
    """path 의 offset 위치에 data(bytes) 를 덮어쓴다 (정밀 바이트패치)."""
    b = bytearray(open(path, "rb").read())
    b[offset:offset + len(data)] = data
    open(path, "wb").write(bytes(b))

def strip_section_headers(path):
    """EHDR 의 e_shoff/e_shnum/e_shstrndx 를 0 으로 → '섹션헤더 없는' 유효 ELF.
    링커의 PT_DYNAMIC 폴백 경로(D01/D07/D08/D20)를 강제. ELF64 오프셋:
    e_shoff@0x28(8B) · e_shnum@0x3C(2B) · e_shstrndx@0x3E(2B)."""
    patch_bytes(path, 0x28, _struct.pack("<Q", 0))
    patch_bytes(path, 0x3C, _struct.pack("<H", 0))
    patch_bytes(path, 0x3E, _struct.pack("<H", 0))

def dyn_entries(so_path):
    """.dynamic 섹션의 (index, tag, val, file_offset) 리스트. pyelftools 사용."""
    from elftools.elf.elffile import ELFFile
    out = []
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        d = elf.get_section_by_name(".dynamic")
        if d is None:
            return out
        base = d["sh_offset"]; ent = 16  # Elf64_Dyn
        raw = open(so_path, "rb").read()
        for i in range(d["sh_size"] // ent):
            off = base + i * ent
            tag, val = _struct.unpack_from("<qQ", raw, off)
            out.append((i, tag, val, off))
    return out

def inject_dyn_tag(so_path, new_tag, new_val):
    """.dynamic 의 첫 DT_NULL(tag 0) 슬롯을 (new_tag,new_val) 로 덮어쓴다.
    정상 파일 구조 유지 → 초반 포맷검사 통과 후 해당 태그 경로 도달(D04/D24 등)."""
    for i, tag, val, off in dyn_entries(so_path):
        if tag == 0:  # DT_NULL
            patch_bytes(so_path, off, _struct.pack("<qQ", new_tag, new_val))
            return off
    raise RuntimeError("빈 DT_NULL 슬롯 없음 — --version-script 등으로 여유 슬롯 확보 필요")

if __name__ == "__main__":
    banner()
    print("this is a library module; run exp_d0X_*.py")
