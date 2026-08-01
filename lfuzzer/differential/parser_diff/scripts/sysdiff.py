import struct, subprocess, os, sys
BASE="/tmp/dyntest"; SRC=os.path.join(BASE,"victim")
OUT=os.path.join(BASE,"sysmut"); os.makedirs(OUT,exist_ok=True)
b0=open(SRC,"rb").read()
phoff=struct.unpack_from("<Q",b0,0x20)[0]
phnum=struct.unpack_from("<H",b0,0x38)[0]
phes =struct.unpack_from("<H",b0,0x36)[0]
PT={1:"LOAD",2:"DYNAMIC",3:"INTERP",4:"NOTE",6:"PHDR",0x6474e551:"GNU_STACK",0x6474e552:"GNU_RELRO",0x6474e550:"GNU_EH_FRAME",0x6474e553:"GNU_PROPERTY",7:"TLS"}
FIELDS={"p_offset":8,"p_filesz":32,"p_memsz":40}
HUGE=0x2625a6b7037c6736
# 각 세그먼트 x 각 필드 -> HUGE 뮤턴트 생성
mutants=[]
for i in range(phnum):
    o=phoff+i*phes
    pt=struct.unpack_from("<I",b0,o)[0]
    name=PT.get(pt,f"T{pt:#x}")
    for fn,fo in FIELDS.items():
        b=bytearray(b0); struct.pack_into("<Q",b,o+fo,HUGE)
        fp=os.path.join(OUT,f"s{i:02d}_{name}_{fn}.elf")
        open(fp,"wb").write(b); os.chmod(fp,0o755)
        mutants.append((f"s{i:02d}_{name}",fn,fp))
print(f"생성 뮤턴트: {len(mutants)} (세그먼트 {phnum} x 필드 {len(FIELDS)})")

def run_cli(cmd,f):
    try:
        r=subprocess.run(cmd+[f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=6)
        return r.returncode
    except subprocess.TimeoutExpired: return "HANG"
PYET=[sys.executable,"-c",
 "import sys;from elftools.elf.elffile import ELFFile\n"
 "f=open(sys.argv[1],\"rb\");e=ELFFile(f)\n"
 "[list(s.iter_tags()) for s in e.iter_segments() if s[\"p_type\"]==\"PT_DYNAMIC\"]\n"
 "[x for x in e.iter_sections()]\n"]
def run_pyet(f):
    try:
        r=subprocess.run(PYET+[f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=6)
        return r.returncode
    except subprocess.TimeoutExpired: return "HANG"

hdr=f"{'mutant':28}{'field':10} readelf objdmp  nm    llvm   pyelf"
print(hdr); print("-"*len(hdr))
badrows=[]
for name,fn,fp in mutants:
    re_=run_cli(["readelf","-a"],fp); od=run_cli(["objdump","-x"],fp)
    nm=run_cli(["nm","-aD"],fp);      lv=run_cli(["llvm-objdump","-x"],fp)
    py=run_pyet(fp)
    row=f"{name:28}{fn:10} {str(re_):6} {str(od):6} {str(nm):5} {str(lv):6} {str(py):6}"
    interesting = any(v=="HANG" or (isinstance(v,int) and (v>=128 or v==124)) for v in (re_,od,nm,lv,py))
    if interesting: badrows.append(row)
    print(row)
print()
print(f"=== 이상반응 행 {len(badrows)}개 (HANG 또는 크래시) ===")
for r in badrows: print(r)
