import struct, subprocess, os, sys, resource
BASE="/tmp/dyntest"; SRC=os.path.join(BASE,"victim")
OUT=os.path.join(BASE,"shtmut"); os.makedirs(OUT,exist_ok=True)
b0=open(SRC,"rb").read()
e_shoff=struct.unpack_from("<Q",b0,0x28)[0]
e_shentsize=struct.unpack_from("<H",b0,0x3a)[0]
e_shnum=struct.unpack_from("<H",b0,0x3c)[0]
print(f"victim: e_shoff={e_shoff:#x} e_shnum={e_shnum} e_shentsize={e_shentsize}")
HUGE=0x2625a6b7037c6736
mutants=[]
def emit(tag,field,patch):
    b=bytearray(b0); patch(b)
    fp=os.path.join(OUT,f"{tag}_{field}.elf"); open(fp,"wb").write(b); os.chmod(fp,0o755)
    mutants.append((tag,field,fp))
# ELF 헤더 뮤테이션
emit("EHDR","e_shoff_HUGE", lambda b: struct.pack_into("<Q",b,0x28,HUGE))
emit("EHDR","e_shnum_FFFF", lambda b: struct.pack_into("<H",b,0x3c,0xffff))
emit("EHDR","e_shentsize_HUGE", lambda b: struct.pack_into("<H",b,0x3a,0xffff))
emit("EHDR","e_shstrndx_FFFF", lambda b: struct.pack_into("<H",b,0x3e,0xffff))
emit("EHDR","e_phnum_FFFF", lambda b: struct.pack_into("<H",b,0x38,0xffff))
# 섹션 헤더 뮤테이션 (Elf64_Shdr: sh_offset@24, sh_size@32, sh_link@40, sh_info@44, sh_entsize@56)
for i in range(e_shnum):
    o=e_shoff+i*e_shentsize
    emit(f"SEC{i:02d}","sh_size_HUGE", lambda b,o=o: struct.pack_into("<Q",b,o+32,HUGE))
    emit(f"SEC{i:02d}","sh_offset_HUGE", lambda b,o=o: struct.pack_into("<Q",b,o+24,HUGE))
    emit(f"SEC{i:02d}","sh_entsize_1_size_HUGE", lambda b,o=o: (struct.pack_into("<Q",b,o+56,1),struct.pack_into("<Q",b,o+32,HUGE)))
print(f"생성 뮤턴트: {len(mutants)} (EHDR 5 + 섹션 {e_shnum}x3)")

def limit(): resource.setrlimit(resource.RLIMIT_AS,(3*1024**3,3*1024**3))
def run(cmd,f):
    try:
        r=subprocess.run(cmd+[f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=6,preexec_fn=limit)
        return r.returncode
    except subprocess.TimeoutExpired: return "HANG"
    except Exception: return "ERR"
PYET=[sys.executable,"-c",
 "import sys;from elftools.elf.elffile import ELFFile\n"
 "e=ELFFile(open(sys.argv[1],\"rb\"))\n"
 "[x for x in e.iter_sections()];[y for y in e.iter_segments()]\n"
 "import contextlib\n"
 "[list(s.iter_symbols()) for s in e.iter_sections() if hasattr(s,\"iter_symbols\")]\n"]
def run_py(f):
    try:
        r=subprocess.run(PYET+[f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=6,preexec_fn=limit)
        return r.returncode
    except subprocess.TimeoutExpired: return "HANG"
    except Exception: return "ERR"

hdr=f"{'mutant':16}{'field':24} readelf objdmp llvm   pyelf"
print(hdr); print("-"*len(hdr)); bad=[]
for tag,field,fp in mutants:
    re_=run(["readelf","-a"],fp); od=run(["objdump","-x"],fp)
    lv=run(["llvm-objdump","-x"],fp); py=run_py(fp)
    row=f"{tag:16}{field:24} {str(re_):6} {str(od):6} {str(lv):6} {str(py):6}"
    if any(v=="HANG" or v=="ERR" or (isinstance(v,int) and (v>=128 or v==124)) for v in (re_,od,lv,py)):
        bad.append(row)
    print(row)
print(f"\n=== 이상반응 {len(bad)}개 ===")
for r in bad: print(r)
