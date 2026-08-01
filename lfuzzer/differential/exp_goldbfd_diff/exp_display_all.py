#!/usr/bin/env python3
"""
exp_display_all.py — R1~R4,R9: 동적 정보 "표시 도구" 差異 관측 (링커가 아니라 뷰어 대질).

이 실험은 두 링커(BFD/GOLD)를 비교하는 게 아니라, 같은 ELF 하나를
readelf/objdump/r2 여러 뷰로 덤프했을 때 SHT(섹션헤더 관점) vs PT_DYNAMIC(세그먼트 관점)
이 어떻게 갈리는지, 그리고 미지 DT_ 태그를 각 도구가 어떻게 표시하는지를 나란히 본다.
diff_report 는 관례상 링커 대질용이라 여기선 쓰지 않고, 도구별 요약을 직접 출력한다.

소스 근거(binutils readelf.c):
  readelf.c:6741   process_dynamic_section() — SHT_DYNAMIC(-d) 경로. 섹션헤더에서 .dynamic 을 찾음.
                   섹션헤더가 없거나 조작되면 이 -d 뷰가 PT_DYNAMIC 실제와 어긋난다.
  readelf.c:14101  print_dynamic_symbol() — --dyn-syms(SHT_DYNSYM) 심볼 덤프.
  readelf.c:12595  process_version_sections() / -D 결합 시 버전(VERSYM/VERNEED) 반영된 심볼명.
  readelf.c:2714   get_dynamic_type() — 미지 DT_ 태그는 "<unknown>: 0x..." 로 표시(default 분기).
  readelf.c:7634   dynamic_section entsize 정정 — d_tag 개수 vs sh_entsize 불일치 시 readelf 가
                   entsize 를 강제 보정(경고 없이 조용히). objdump/r2 와 태그 개수가 갈릴 수 있음.
  대조 도구: objdump -T (BFD libbfd 경로, PT_DYNAMIC 기반 dynsym), r2 idj(라다레 자체 파서, JSON).

예측(뷰별 차이가 관측 포인트 — 링커 rc 아님):
  · prac.elf (정상):        -d / --dyn-syms / -D / objdump -T / r2 idj 가 대체로 일치.
                            단 -D 는 심볼에 @version 접미어가 붙어 objdump -T 와 표기 방식이 다름.
  · prac_extratag_poc.elf:  주입된 미지 DT_ 태그를 readelf 는 "<unknown>: 0x..."(2714) 로 노출,
                            objdump -T 는 dynsym 만 보므로 그 태그를 아예 안 보여줄 수 있고,
                            r2 idj 는 알 수 없는 태그를 스킵/무시하는 경향 → 태그 "가시성"이 도구별로 갈림.
  · entsize(7634):          readelf 가 조용히 보정하므로 -d 태그 카운트가 r2/objdump 와 달라질 수 있음.

크래프팅:
  크래프팅 없음(순수 관측). 기존 산출물 prac.elf, prac_extratag_poc.elf 를 그대로 덤프.
  (prac_extratag_poc.elf 가 없으면 안내만 출력하고 prac.elf 만 관측 — best-effort.)

실행:  python3 exp_display_all.py      (사용자가 ! 로)
"""
import os, re, shutil, common

# 관측 대상 파일 후보 경로(스크립트 위치 기준 + 상위 몇 군데를 탐색)
HERE = os.path.dirname(os.path.abspath(__file__))
SEARCH_DIRS = [
    HERE,
    os.path.dirname(HERE),                     # Lfuzzer/
    os.path.join(os.path.dirname(HERE), "prac"),
    os.path.expanduser("~"),
]

def find_file(name):
    """후보 디렉터리들에서 name 을 찾아 첫 경로 반환(없으면 None)."""
    for d in SEARCH_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None

def tool_present(binname):
    return shutil.which(binname) is not None

def section(label):
    print("\n" + "-" * 72)
    print(f"### {label}")
    print("-" * 72)

def dump_readelf_d(path):
    """readelf -d — SHT_DYNAMIC 뷰. 태그 목록 + <unknown> 노출 확인(2714, 6741)."""
    rc, o, e = common.run(["readelf", "-d", path])
    tags = re.findall(r"\(([A-Z0-9_]+)\)", o)
    unknown = re.findall(r"<unknown>?:?\s*0x[0-9a-fA-F]+", o) + \
              re.findall(r"unknown", o, re.I)
    print(f"  rc={rc}  태그 {len(tags)}개(SHT뷰): {tags}")
    if unknown:
        print(f"  ★ 미지 DT_ 태그 노출(readelf.c:2714): {unknown}")
    if e.strip():
        print(f"  stderr: {e.strip()[:200]}")
    return tags

def dump_readelf_dynsyms(path, extra_flag=None):
    """readelf --dyn-syms (+옵션 -D) — SHT_DYNSYM 뷰(14101) / 버전결합(12595)."""
    cmd = ["readelf"]
    if extra_flag:
        cmd.append(extra_flag)          # -D : 심볼명에 @version 표기 결합
    cmd += ["--dyn-syms", path]
    rc, o, e = common.run(cmd)
    # 심볼명만 추려서 개수/버전접미어 유무 요약
    names = re.findall(r"\s(\w[\w.@]*)\s*$", o, re.M)
    versioned = [n for n in names if "@" in n]
    lbl = extra_flag or "(기본)"
    print(f"  {lbl} rc={rc}  심볼줄 {len(names)}개, @version 접미어 {len(versioned)}개")
    if versioned[:6]:
        print(f"     예: {versioned[:6]}")
    if e.strip():
        print(f"  stderr: {e.strip()[:200]}")
    return names

def dump_objdump_T(path):
    """objdump -T — libbfd 의 PT_DYNAMIC 기반 dynsym 뷰(대조군)."""
    rc, o, e = common.run(["objdump", "-T", path])
    lines = [l for l in o.splitlines() if l and not l.startswith(("SYMBOL", path))]
    print(f"  rc={rc}  DYNAMIC SYMBOL TABLE 줄수: {len(lines)}")
    if e.strip():
        print(f"  stderr: {e.strip()[:200]}")
    return lines

def dump_r2_idj(path):
    """r2 -q -c 'idj' — 라다레 자체 파서(JSON). 미지 태그 처리/카운트 대조군."""
    if not tool_present("r2"):
        print("  r2 미설치 — 건너뜀(best-effort)")
        return None
    rc, o, e = common.run(["r2", "-q", "-e", "scr.color=0", "-c", "idj", "-c", "q", path])
    # idj 는 dynamic entries JSON. 파싱 실패해도 원문 앞부분만 요약.
    import json
    try:
        data = json.loads(o.strip().splitlines()[-1]) if o.strip() else None
        n = len(data) if isinstance(data, list) else "?"
        print(f"  rc={rc}  r2 idj 엔트리 수: {n}")
    except Exception:
        print(f"  rc={rc}  r2 idj 원출력(발췌): {o.strip()[:160]}")
    if e.strip():
        print(f"  stderr: {e.strip()[:160]}")
    return o

def observe(path, title):
    print("\n" + "=" * 72)
    print(f"[{title}]  {path}")
    print("=" * 72)

    section("R1  readelf -d  (SHT_DYNAMIC 뷰 / 미지태그 <unknown>)")
    tags_d = dump_readelf_d(path)

    section("R2  readelf --dyn-syms  (SHT_DYNSYM 심볼)")
    dump_readelf_dynsyms(path)

    section("R3  readelf -D --dyn-syms  (버전 결합 심볼명 @ver)")
    dump_readelf_dynsyms(path, extra_flag="-D")

    section("R4  objdump -T  (libbfd PT_DYNAMIC 기반 dynsym 대조)")
    dump_objdump_T(path)

    section("R9  r2 idj  (radare 자체 파서 / entsize·태그카운트 대조)")
    dump_r2_idj(path)

    # sh_entsize 정정 흔적(7634) 힌트: 섹션헤더의 .dynamic entsize 를 직접 본다
    section("보조  readelf -SW | .dynamic  (sh_entsize 정정 확인 힌트, readelf.c:7634)")
    rc, o, e = common.run(["readelf", "-SW", path])
    for line in o.splitlines():
        if ".dynamic" in line or ".dynsym" in line:
            print("   ", line.strip())
    return tags_d

def main():
    common.banner()
    print("R1~R4,R9: 동적정보 '표시 도구' 差異 관측 (링커 대질 아님, 뷰어 대질)")

    prac = find_file("prac.elf")
    poc  = find_file("prac_extratag_poc.elf")

    if not prac:
        print("\n[중단] prac.elf 를 찾지 못함. SEARCH_DIRS 확인 필요:")
        for d in SEARCH_DIRS:
            print("   -", d)
        print("결론: 관측 대상 부재 — prac.elf 경로부터 확보 필요")
        return

    observe(prac, "정상 기준: prac.elf")

    if poc:
        observe(poc, "미지태그 주입: prac_extratag_poc.elf")
        print("\n결론: 두 파일의 -d(SHT) vs objdump -T/r2 idj(PT_DYNAMIC) 태그·심볼 카운트를 "
              "위에서 대조 — 미지 DT_ 태그가 readelf 에선 <unknown> 으로 뜨고 다른 도구에선 "
              "가려지면 '뷰별 표시 差' 재현 ✓")
    else:
        print("\n[안내] prac_extratag_poc.elf 없음 — 미지태그 파트는 관측 생략(best-effort).")
        print("  확인할 것: prac.elf 에 미지 DT_ 태그를 주입한 산출물을 만들어 재실행하면")
        print("  readelf.c:2714 <unknown> 노출 vs objdump/r2 가려짐 差를 볼 수 있음.")
        print("\n결론: prac.elf 단독 관측 완료 — poc 파일 확보 후 재실행 권장")

if __name__ == "__main__":
    main()
