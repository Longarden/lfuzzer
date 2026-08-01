#!/usr/bin/env python3
"""
exp_r7_ghidra_dtag.py — R7: Ghidra가 64비트 d_tag를 32비트로 절단하는지 실증.

소스 근거:
  Ghidra ElfDynamic 생성자: this.d_tag = (int) reader.readNextLong()  → 상위 32비트 폐기.
  readelf / ld.so 는 64비트 전체 폭 사용.
당신 연구와의 연결: glibc 로더의 EXTRATAGIDX 32비트 절단(0xDEADBEEFFFFFFFFD)과 정확히 같은 결함의
  Ghidra판. "분석기는 모르는데 로더는 아는"이 Ghidra 쪽에서도 성립.

예측: prac_extratag_poc.elf 의 태그 0xDEADBEEFFFFFFFFD →
  · Ghidra:  DT tag=0xfffffffd  (상위 0xDEADBEEF 버림)   ← 절단 실증
  · readelf: <unknown>: fffffffd  (미지 태그로 표시)
  · ld.so:   하위 32비트 슬롯 처리(정상 실행)

의존: Ghidra headless(~/ghidra_*_PUBLIC), Java 21, DumpDynamic.java(ghidra_scripts/).
직접 실행:  ./exp_r7_ghidra_dtag.py      (첫 실행은 JVM/분석으로 1~2분)
결과 판독:  맨 끝 결론 줄 — "GHIDRA_TRUNCATION 실증 ✓" 이면 절단 확인.
"""
import os, subprocess, glob, re, tempfile, shutil

HOME = os.path.expanduser("~")

def ghidra_dir():
    ds = sorted(glob.glob(os.path.join(HOME, "ghidra_*_PUBLIC")))
    return ds[-1] if ds else None

def run_ghidra_dump(elf, script_dir):
    gh = ghidra_dir()
    assert gh, "Ghidra 미설치 (~/ghidra_*_PUBLIC 없음)"
    proj = tempfile.mkdtemp(prefix="ghproj_")
    try:
        cmd = [os.path.join(gh, "support", "analyzeHeadless"), proj, "p",
               "-import", elf, "-scriptPath", script_dir,
               "-postScript", "DumpDynamic.java", "-deleteProject"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=320)
        return r.stdout + r.stderr
    finally:
        shutil.rmtree(proj, ignore_errors=True)

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    sd = os.path.join(here, "ghidra_scripts")
    elf = os.path.expanduser("~/PE/Lfuzzer/prac_extratag_poc.elf")
    if not os.path.exists(elf):
        print("prac_extratag_poc.elf 없음 — craft_extratag_poc.py 로 먼저 생성 필요"); return
    print("=== Ghidra 파싱 (analyzeHeadless + DumpDynamic.java) — 1~2분 ===")
    out = run_ghidra_dump(elf, sd)
    tags = re.findall(r"DT tag=0x([0-9a-fA-F]+)", out)
    print("Ghidra dynamic 태그:", " ".join(tags) if tags else "(없음 — 로그 확인)")
    trunc = any(t.lower() == "fffffffd" for t in tags)

    print("\n=== readelf -d (대조) ===")
    r = subprocess.run(["readelf", "-d", elf], capture_output=True, text=True)
    for l in r.stdout.splitlines():
        s = l.lower()
        if "unknown" in s or "fffffffd" in s or "deadbeef" in s:
            print("  ", l.strip())

    print("\n" + "=" * 60)
    if trunc:
        print("결론: GHIDRA_TRUNCATION 실증 ✓")
        print("  0xDEADBEEFFFFFFFFD  →  Ghidra: 0xfffffffd (상위 0xDEADBEEF 버림)")
        print("  = 당신 EXTRATAGIDX 로더 결함의 Ghidra판. readelf는 <unknown>으로 표시.")
    else:
        print("결론: 재확인 필요 — Ghidra 출력에 0xfffffffd 태그 미검출")
        print("  (DumpDynamic.java 컴파일/실행 로그를 직접 확인:")
        print("   ", os.path.join(ghidra_dir() or '~', "support", "analyzeHeadless"), ")")

if __name__ == "__main__":
    main()
