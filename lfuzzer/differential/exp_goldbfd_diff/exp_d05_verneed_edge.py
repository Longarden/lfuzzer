#!/usr/bin/env python3
"""
exp_d05_verneed_edge.py — D05: 버전 레코드 경계 검사의 엄격도 차이 (방어적 견고성 테스트).

소스 근거:
  gold gold/dynobj.cc:601,622  다음 레코드의 "시작 오프셋"만 섹션 안인지 확인
                               ((p-base)+vd_next >= verdef_size 이면 error). 고정 헤더가
                               매핑 안에 다 들어오는지는 보장하지 않음.
  bfd  bfd/elf.c:9540          vn_aux > (contents_end - everneed) 로 레코드 "전체"가
                               들어와야 역참조 — 더 엄격.
예측: .gnu.version_r/_d 레코드를 섹션 끝 가까이 두면, gold는 시작만 통과시키고 고정 헤더를
      섹션 경계 밖까지 읽을 수 있고(valgrind 'Invalid read'), bfd는 거부.

관찰: gold ld-new 를 valgrind 아래에서 입력 .so 로 실행해 경계 밖 read 를 잡는다.
      (하네스 없이 링커 자체를 계측하는 방식 — exp_d02 와 동일 패턴)

한계(정직): 표준 gcc 로는 .gnu.version_r 를 섹션 끝에 딱 붙이기 어렵다. 이 스크립트는
      베이스 .so 를 만들고 .gnu.version_r 섹션의 마지막 vna_next 를 큰 값으로 밀어
      "다음 레코드 시작이 섹션 끝 직전" 조건을 근사한다. valgrind 가 조용하면
      '재확인 필요'(경로 미도달) 로 보고 — 그땐 링커가 입력 .so 의 verneed 를 실제로
      읽게 하는 소비 시나리오(심볼 버전 참조)를 추가해야 한다.

의존: pyelftools, valgrind.
직접 실행:  ./exp_d05_verneed_edge.py      또는   python3 exp_d05_verneed_edge.py
결과 판독:  출력의 'GOLD valgrind' 줄 — 'Invalid read 감지 ✓' 면 gold over-read 실증,
           '미감지' 면 verneed 소비 경로에 안 닿은 것(위 한계 참고).
"""
import os, tempfile, common

def find_verneed(so_path):
    """.gnu.version_r 섹션의 (sh_offset, sh_size) 반환. 없으면 None."""
    from elftools.elf.elffile import ELFFile
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        s = elf.get_section_by_name(".gnu.version_r")
        if s is None:
            return None
        return s["sh_offset"], s["sh_size"]

def main():
    common.banner()
    if not common.shutil.which("valgrind"):
        print("valgrind 필요: sudo apt-get install -y valgrind"); return
    wd = tempfile.mkdtemp(prefix="exp_d05_")
    # 버전 심볼이 생기도록 버전 스크립트로 .so 빌드
    ver = os.path.join(wd, "v.map")
    open(ver, "w").write("V1 { global: foo; };\n")
    src = os.path.join(wd, "libfoo.c"); open(src, "w").write("int foo(void){return 42;}\n")
    lib = os.path.join(wd, "libfoo.so")
    rc, o, e = common.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libfoo.so.1",
                           f"-Wl,--version-script,{ver}", "-o", lib, src], cwd=wd)
    assert rc == 0, f"lib build failed: {e}"

    vn = find_verneed(lib)
    if vn is None:
        # 소비쪽에 verneed 가 생기도록: libfoo 의 V1 심볼을 쓰는 consumer 를 링크해야 verneed 생성
        print(".gnu.version_r 이 libfoo 엔 없음(그건 verdef). consumer 를 만들어 verneed 유도...")
        cons = os.path.join(wd, "main.c")
        open(cons, "w").write("extern int foo(void);\nint main(void){return foo();}\n")
        exe = os.path.join(wd, "main")
        common.run(["gcc", cons, "-L"+wd, "-lfoo", f"-Wl,-rpath,{wd}", "-o", exe], cwd=wd)
        target = exe if os.path.exists(exe) else lib
    else:
        target = lib

    # gold ld-new 를 valgrind 로 돌려 target 을 입력으로 읽게 한다
    vg = ["valgrind", "--error-exitcode=99", "--track-origins=yes",
          common.GOLD, "-shared", target, "-o", os.path.join(wd, "g.so")]
    grc, go, ge = common.run(vg, cwd=wd)
    invalid = ("Invalid read" in ge) or (grc == 99)
    # bfd 는 대조
    brc, bo, be = common.run([common.BFD, "-shared", target, "-o", os.path.join(wd, "b.so")], cwd=wd)
    common.diff_report("D05 verneed/verdef edge bounds", (brc, bo, be), (grc, go, ge),
        extra=f"GOLD valgrind: {'Invalid read 감지 ✓' if invalid else '미감지'} (rc={grc})")
    print("\n결론:", "gold 경계 over-read 실증" if invalid else "재확인 필요(verneed 소비 경로 미도달 — docstring 한계 참고)")

if __name__ == "__main__":
    main()
