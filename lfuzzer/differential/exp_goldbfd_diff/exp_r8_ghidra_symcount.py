#!/usr/bin/env python3
"""
exp_r8_ghidra_symcount.py — R8: Ghidra의 동적 심볼 개수 근원 vs readelf.
소스근거: Ghidra는 DT_HASH nchain / GNU_HASH buckets 로 .dynsym 개수를 도출(공격자 제어 가능),
  readelf 기본은 .dynsym 섹션 sh_size 로 센다.
예측: 위조 nchain 이면 Ghidra 심볼수 != readelf 심볼수.
직접 실행: ./exp_r8_ghidra_symcount.py
결과판독: Ghidra SYMCOUNT 와 readelf --dyn-syms 개수를 비교. 정상 파일이면 같고,
  nchain 위조(exp_d07)한 파일에 돌리면 갈릴 수 있음.
"""
import os, subprocess, glob, re, tempfile, shutil, sys
HOME=os.path.expanduser("~")
def gh(): d=sorted(glob.glob(HOME+"/ghidra_*_PUBLIC")); return d[-1] if d else None
def dump(elf, sd):
    proj=tempfile.mkdtemp(prefix="ghproj_")
    try:
        r=subprocess.run([gh()+"/support/analyzeHeadless",proj,"p","-import",elf,
            "-scriptPath",sd,"-postScript","DumpDynamic.java","-deleteProject"],
            capture_output=True,text=True,timeout=320)
        return r.stdout+r.stderr
    finally: shutil.rmtree(proj,ignore_errors=True)
def main():
    here=os.path.dirname(os.path.abspath(__file__)); sd=os.path.join(here,"ghidra_scripts")
    elf=sys.argv[1] if len(sys.argv)>1 else os.path.expanduser("~/PE/Lfuzzer/prac.elf")
    print("=== Ghidra 심볼수 (analyzeHeadless) — 1~2분 ===")
    out=dump(elf,sd); m=re.search(r"GHIDRA_SYMCOUNT total=(\d+)",out)
    gcount=int(m.group(1)) if m else None
    r=subprocess.run(["readelf","--dyn-syms",elf],capture_output=True,text=True)
    rcount=sum(1 for l in r.stdout.splitlines() if re.match(r"\s*\d+:",l))
    print(f"  Ghidra dynsym 수 : {gcount}")
    print(f"  readelf --dyn-syms: {rcount}")
    print("\n결론:", "일치(정상)" if gcount==rcount else f"갈림 — Ghidra {gcount} vs readelf {rcount} (nchain 위조 파일이면 R8 실증)")
if __name__=="__main__": main()
