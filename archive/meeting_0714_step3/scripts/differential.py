#!/usr/bin/env python3
"""
step3 differential mutator/harness.
libfoo.so.1의 DYNAMIC 섹션(Elf64_Dyn 배열)을 필드 단위로 조작해 뮤턴트를 만들고,
동일 뮤턴트를 LD(BFD)와 Gold에 각각 입력(-shared 링크)해 처리 결과를 대조한다.

Elf64_Dyn = { int64 d_tag; uint64 d_val }  (16 bytes, little-endian x86-64)
목적: LD와 Gold가 같은 조작 ELF를 다르게 처리하는 divergence(한쪽 성공/한쪽 실패 등) 포착.
"""
import os, struct, subprocess, sys, shutil

BASE   = "/home/garden/PE/Lfuzzer/meeting_0714_step3/diff"
OUTDIR = "/home/garden/PE/Lfuzzer/meeting_0714_step3/mutants"
LD   = os.path.expanduser("~/binutils-build-afl-bfd-clean/ld/ld-new")
GOLD = os.path.expanduser("~/binutils-build-gold/gold/ld-new")
SRC  = os.path.join(BASE, "libfoo.so.1")
MAIN = os.path.join(BASE, "main.o")

# DT tag 상수
DT = {"NULL":0,"NEEDED":1,"PLTRELSZ":2,"PLTGOT":3,"HASH":4,"STRTAB":5,"SYMTAB":6,
      "RELA":7,"RELASZ":8,"RELAENT":9,"STRSZ":10,"SYMENT":11,"INIT":12,"FINI":13,
      "SONAME":14,"GNU_HASH":0x6ffffef5,"RELACOUNT":0x6ffffff9}

def read_elf():
    with open(SRC,"rb") as f: return bytearray(f.read())

def find_dynamic(buf):
    # e_shoff@0x28(8), e_shentsize@0x3a(2), e_shnum@0x3c(2), e_shstrndx not needed;
    # SHT_DYNAMIC=6. section header: sh_type@off+4(4), sh_offset@off+24(8), sh_size@off+32(8), sh_entsize@off+56(8)
    e_shoff  = struct.unpack_from("<Q", buf, 0x28)[0]
    e_shentsz= struct.unpack_from("<H", buf, 0x3a)[0]
    e_shnum  = struct.unpack_from("<H", buf, 0x3c)[0]
    for i in range(e_shnum):
        sh = e_shoff + i*e_shentsz
        sh_type = struct.unpack_from("<I", buf, sh+4)[0]
        if sh_type == 6:  # SHT_DYNAMIC
            off  = struct.unpack_from("<Q", buf, sh+24)[0]
            size = struct.unpack_from("<Q", buf, sh+32)[0]
            ent  = struct.unpack_from("<Q", buf, sh+56)[0] or 16
            return off, size, ent
    raise RuntimeError("no SHT_DYNAMIC")

def entries(buf, off, size, ent):
    out=[]
    for k in range(size//ent):
        a = off + k*ent
        tag,val = struct.unpack_from("<qQ", buf, a)
        out.append((k,a,tag,val))
    return out

def set_tag(buf,a,tag): struct.pack_into("<q", buf, a, tag)
def set_val(buf,a,val): struct.pack_into("<Q", buf, a, val)

def make_mutants():
    os.makedirs(OUTDIR, exist_ok=True)
    off,size,ent = find_dynamic(read_elf())
    ents = entries(read_elf(), off, size, ent)
    by_tag = {t:(k,a,t,v) for (k,a,t,v) in ents}
    muts = []

    def emit(name, fn):
        buf = read_elf(); fn(buf, off, size, ent)
        p = os.path.join(OUTDIR, name)
        with open(p,"wb") as f: f.write(buf)
        muts.append((name, p))

    # M1: STRSZ를 거대값으로 (문자열 테이블 경계 파괴)
    a = by_tag[DT["STRSZ"]][1]
    emit("m01_strsz_huge.so",   lambda b,o,s,e: set_val(b, a, 0xffffffff))
    # M2: STRTAB 포인터를 파일 밖으로
    a2 = by_tag[DT["STRTAB"]][1]
    emit("m02_strtab_oob.so",   lambda b,o,s,e: set_val(b, a2, 0xdeadbeef))
    # M3: SONAME 문자열 오프셋을 STRSZ 밖으로 (112 -> 9999)
    a3 = by_tag[DT["SONAME"]][1]
    emit("m03_soname_oob.so",   lambda b,o,s,e: set_val(b, a3, 9999))
    # M4: SYMENT(심볼 엔트리 크기)를 24->0 (0 나눗셈/무한 유발 가능)
    a4 = by_tag[DT["SYMENT"]][1]
    emit("m04_syment_zero.so",  lambda b,o,s,e: set_val(b, a4, 0))
    # M5: SYMENT을 24->48 (엔트리 크기 왜곡)
    emit("m05_syment_48.so",    lambda b,o,s,e: set_val(b, a4, 48))
    # M6: SYMTAB 포인터를 파일 밖으로
    a6 = by_tag[DT["SYMTAB"]][1]
    emit("m06_symtab_oob.so",   lambda b,o,s,e: set_val(b, a6, 0xdeadbeef))
    # M7: GNU_HASH 포인터 손상
    a7 = by_tag[DT["GNU_HASH"]][1]
    emit("m07_gnuhash_oob.so",  lambda b,o,s,e: set_val(b, a7, 0xdeadbeef))
    # M8: 첫 엔트리 tag를 미지의 예약값으로
    a8 = ents[0][1]
    emit("m08_unknown_tag.so",  lambda b,o,s,e: set_tag(b, a8, 0x6fffff00))
    # M9: DT_NULL 종결자를 제거(마지막 엔트리를 NEEDED로 바꿔 배열이 끝나지 않게)
    last = ents[-1][1]
    def m9(b,o,s,e):
        set_tag(b, last, 1)         # NEEDED
        set_val(b, last, 9999)      # OOB 문자열
    emit("m09_no_null_term.so", m9)
    # M10: SONAME tag를 RPATH(0xf)로 바꿔 의미 재해석
    def m10(b,o,s,e): set_tag(b, a3, 15)  # DT_RPATH
    emit("m10_soname_to_rpath.so", m10)
    # M11: RELAENT(0x18->0) 재배치 엔트리 크기 0
    if DT["RELAENT"] in by_tag:
        a11 = by_tag[DT["RELAENT"]][1]
        emit("m11_relaent_zero.so", lambda b,o,s,e: set_val(b, a11, 0))
    # M12: STRSZ=0 (빈 문자열 테이블)
    emit("m12_strsz_zero.so",   lambda b,o,s,e: set_val(b, a, 0))
    return muts

def run(linker, mutant):
    out = mutant + (".ld.out" if linker==LD else ".gold.out")
    try:
        p = subprocess.run([linker,"-shared","-o",out, MAIN, mutant],
                           capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stderr.strip() or p.stdout.strip())
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT(20s)"

def classify(rc, err):
    if rc==124: return "HANG"
    if rc==0:   return "OK"
    if rc<0 or rc>=128: return f"CRASH(sig{rc-128 if rc>=128 else -rc})"
    return "ERROR"

def main():
    muts = make_mutants()
    print(f"{'MUTANT':28} | {'LD':<8} {'GOLD':<8} | DIVERGE?")
    print("-"*78)
    rows=[]
    diverge=[]
    for name,path in muts:
        lrc,lerr = run(LD,path)
        grc,gerr = run(GOLD,path)
        lc,gc = classify(lrc,lerr), classify(grc,gerr)
        d = "*** YES ***" if lc!=gc else ""
        if lc!=gc: diverge.append((name,lc,gc,lerr,gerr))
        print(f"{name:28} | {lc:<8} {gc:<8} | {d}")
        rows.append((name,lc,gc,lerr,gerr,lrc,grc))
    print("\n=== DIVERGENCE DETAIL ===")
    for name,lc,gc,lerr,gerr in diverge:
        print(f"\n### {name}: LD={lc}  GOLD={gc}")
        print(f"  LD  stderr: {lerr[:300]}")
        print(f"  GOLD stderr: {gerr[:300]}")
    if not diverge:
        print("(no class-level divergence; check stderr text diffs below)")
    # 상세 stderr 저장
    import json
    with open("/home/garden/PE/Lfuzzer/meeting_0714_step3/logs/03_differential.json","w") as f:
        json.dump([{"mutant":r[0],"ld_class":r[1],"gold_class":r[2],
                    "ld_stderr":r[3],"gold_stderr":r[4],"ld_rc":r[5],"gold_rc":r[6]} for r in rows],
                   f, indent=2, ensure_ascii=False)
    print(f"\n[+] {len(muts)} mutants, {len(diverge)} class-divergences. JSON saved.")

if __name__=="__main__":
    main()
