#!/usr/bin/env python3
# mutator_dynamic_v3.py
# 도메인특화 ld.so 퍼저 v3 — DYNAMIC 섹션(DT_VERNEED/AUDIT/STRTAB) 인식 뮤테이션
#   + PHT 단일필드 변형(나머지 유지 = 깊이 도달). execve 러너로 시스템 ld.so 실행, 크래시 수집.
# 가설: PHT 순서가 아니라 DT_ 태그 그래프(특히 VERNEED 내부)가 새 버그 광맥.
import os, struct, subprocess, tempfile, time
from collections import Counter

BASE  = os.path.expanduser("~/PE/Lfuzzer/prac.elf")
OUTDIR= os.path.expanduser("~/PE/Lfuzzer/out_dynamic_v3")
LDSO  = "/lib64/ld-linux-x86-64.so.2"

PT_LOAD=1; PT_DYNAMIC=2
DT_NULL=0; DT_STRTAB=5; DT_STRSZ=10; DT_DEBUG=21; DT_AUDIT=28
DT_VERNEED=0x6ffffffe

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]
def p16(b,o,v): struct.pack_into("<H",b,o,v & 0xFFFF)
def p32(b,o,v): struct.pack_into("<I",b,o,v & 0xFFFFFFFF)
def p64(b,o,v): struct.pack_into("<Q",b,o,v & 0xFFFFFFFFFFFFFFFF)

class Elf:
    def __init__(self, data):
        self.d=bytearray(data)
        self.e_phoff=u64(self.d,0x20); self.e_phentsize=u16(self.d,0x36); self.e_phnum=u16(self.d,0x38)
        self.loads=[]; self.dyn_off=None
        for i in range(self.e_phnum):
            o=self.e_phoff+i*self.e_phentsize
            t=u32(self.d,o); poff=u64(self.d,o+8); pv=u64(self.d,o+0x10); pf=u64(self.d,o+0x20)
            if t==PT_LOAD: self.loads.append((pv,poff,pf))
            if t==PT_DYNAMIC: self.dyn_off=poff
    def v2o(self,vaddr):
        for (pv,po,pf) in self.loads:
            if pv<=vaddr<pv+pf: return po+(vaddr-pv)
        return None
    def dyn_entries(self):
        res=[]; o=self.dyn_off; i=0
        while o is not None and i<256:
            tag=u64(self.d,o); val=u64(self.d,o+8); res.append((i,tag,val,o))
            if tag==DT_NULL: break
            o+=16; i+=1
        return res
    def find_tag(self,want):
        for (i,tag,val,fo) in self.dyn_entries():
            if tag==want: return (val,fo)
        return (None,None)

def gen_verneed(base):
    out=[]; e=Elf(base)
    vn_vaddr,_=e.find_tag(DT_VERNEED); strsz,_=e.find_tag(DT_STRSZ)
    if vn_vaddr is None: return out
    vn_off=e.v2o(vn_vaddr)
    if vn_off is None: return out
    vn_aux=u32(base,vn_off+8); aux_off=vn_off+vn_aux
    big=[0xffffffff,(strsz or 0)+0x100000,0x41414141,0x7fffffff]
    for bv in big:  # vna_name OOB -> match_symbol/strlen (family2)
        d=bytearray(base); p32(d,aux_off+8,bv); out.append((f"vna_name_{bv:08x}",bytes(d)))
    for bv in big:  # vn_file OOB
        d=bytearray(base); p32(d,vn_off+4,bv); out.append((f"vn_file_{bv:08x}",bytes(d)))
    for nv in [0x0,0xffffffff,0x10,0xfffffff0]:  # vna_next -> loop/oob walk
        d=bytearray(base); p32(d,aux_off+12,nv); out.append((f"vna_next_{nv:08x}",bytes(d)))
    for nv in [0xffffffff,0x20,0xfffffff0]:  # vn_next
        d=bytearray(base); p32(d,vn_off+12,nv); out.append((f"vn_next_{nv:08x}",bytes(d)))
    for cv in [0xffff,0x7fff,0x100]:  # vn_cnt huge
        d=bytearray(base); p16(d,vn_off+2,cv); out.append((f"vn_cnt_{cv:04x}",bytes(d)))
    return out

def gen_audit(base):
    out=[]; e=Elf(base); strsz,_=e.find_tag(DT_STRSZ)
    dbg=None
    for (i,tag,val,fo) in e.dyn_entries():
        if tag==DT_DEBUG: dbg=fo; break
    if dbg is not None:  # DT_DEBUG -> DT_AUDIT 재활용 (family1 audit_list_add_dynamic_tag)
        for av in [(strsz or 0)+0x1000,0xffffffff,0x0]:
            d=bytearray(base); p64(d,dbg,DT_AUDIT); p64(d,dbg+8,av); out.append((f"dt_audit_{av:08x}",bytes(d)))
    sv0,strfo=e.find_tag(DT_STRTAB)
    if strfo is not None:
        for sv in [0x0,0xffffffff]:  # DT_STRTAB 포인터 깨기
            d=bytearray(base); p64(d,strfo+8,sv); out.append((f"dt_strtab_{sv:08x}",bytes(d)))
        if dbg is not None:  # audit + strtab null 콤보
            d=bytearray(base); p64(d,dbg,DT_AUDIT); p64(d,dbg+8,0x1000); p64(d,strfo+8,0x0)
            out.append(("dt_audit+strtab_null",bytes(d)))
    return out

def gen_phdr(base):
    out=[]; e=Elf(base); fsz=len(base)
    for i in range(e.e_phnum):
        o=e.e_phoff+i*e.e_phentsize; t=u32(base,o)
        if t not in (PT_LOAD,PT_DYNAMIC): continue
        for ov in [fsz+0x1000,0xffffffffffff,0x7fffffffffffffff]:
            d=bytearray(base); p64(d,o+8,ov); out.append((f"s{i}t{t}_p_offset_{ov:x}",bytes(d)))
        for fv in [0xffffffff,0x7fffffffffffffff]:
            d=bytearray(base); p64(d,o+0x20,fv); out.append((f"s{i}_p_filesz_{fv:x}",bytes(d)))
        d=bytearray(base); p64(d,o+0x28,0x7fffffffffffffff); out.append((f"s{i}_p_memsz_huge",bytes(d)))
        for av in [0x0,0x3,0x1001]:
            d=bytearray(base); p64(d,o+0x30,av); out.append((f"s{i}_p_align_{av:x}",bytes(d)))
    return out

def run_one(elf_bytes, timeout=3):
    with tempfile.NamedTemporaryFile(prefix="m_",suffix=".elf",delete=False,dir="/tmp") as f:
        f.write(elf_bytes); path=f.name
    os.chmod(path,0o755)
    try:
        r=subprocess.run([LDSO,path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout)
        rc=r.returncode
    except subprocess.TimeoutExpired: rc=124
    finally:
        try: os.unlink(path)
        except: pass
    return rc

def classify(rc):
    if rc==0: return "ok"
    if rc==124: return "timeout(DoS?)"
    if rc<0: return f"signal_{-rc}"
    if rc in (126,127): return "execve_fail"
    return f"exit_{rc}"

def main():
    os.makedirs(OUTDIR,exist_ok=True)
    base=open(BASE,"rb").read()
    print("base rc:",classify(run_one(base)))
    gens=[("verneed",gen_verneed),("audit",gen_audit),("phdr",gen_phdr)]
    tally=Counter(); crashes=[]; t0=time.time()
    for gname,gfn in gens:
        try: variants=gfn(base)
        except Exception as ex:
            print(f"[!] {gname} gen error: {ex}"); continue
        gc=Counter()
        for label,vb in variants:
            cls=classify(run_one(vb)); tally[cls]+=1; gc[cls]+=1
            if cls.startswith("signal") or cls.startswith("timeout"):
                fn=os.path.join(OUTDIR,f"{gname}__{label}__{cls.replace('(','').replace(')','').replace('?','')}.elf")
                open(fn,"wb").write(vb); crashes.append((gname,label,cls))
        print(f"[{gname}] {len(variants)} variants -> {dict(gc)}")
    print("=== TOTAL ===",dict(tally),f"({time.time()-t0:.1f}s)")
    print(f"=== {len(crashes)} crashes/timeouts saved to {OUTDIR} ===")
    for c in crashes: print("   CRASH:",c[0],c[1],c[2])

if __name__=="__main__":
    main()
