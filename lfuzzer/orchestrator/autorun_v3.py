#!/usr/bin/env python3
# autorun_v3.py — 자율 fuzz+triage 1 라운드. 상태를 autorun_state.json에 누적.
#   인자: budget_seconds (기본 1800). dynamic-aware 랜덤 뮤테이션 → ld.so 실행 → 크래시 저장
#   → gdb로 distinct 사이트 분류 → ld.so --verify로 비실행 재현 여부 기록 → 진행로그/요약 갱신.
import os,struct,subprocess,tempfile,time,random,hashlib,json,re,sys,argparse
import elf64
from elf64 import u16,u32,u64  # shared, behavior-exact ELF64 readers (dedup)
L=os.path.expanduser("~/PE/Lfuzzer")
BASE=os.path.join(L,"prac.elf"); OUT=os.path.join(L,"out_dynamic_v3")
STATE=os.path.join(L,"autorun_state.json"); PROG=os.path.join(L,"autorun_progress.log")
SUMM=os.path.join(L,"sites_summary.txt"); LDSO="/lib64/ld-linux-x86-64.so.2"
PT_LOAD=1;PT_DYNAMIC=2
DT_NULL=0;DT_STRTAB=5;DT_SYMTAB=6;DT_STRSZ=10;DT_DEBUG=21;DT_AUDIT=28;DT_RELA=7;DT_JMPREL=23
DT_VERNEED=0x6ffffffe;DT_VERSYM=0x6ffffff0
ITAGS=[DT_STRTAB,DT_SYMTAB,DT_AUDIT,DT_RELA,DT_JMPREL,DT_VERNEED,DT_VERSYM,0x1d,12,13,25,26,0x6fffffff]
# u16/u32/u64 read primitives are imported from elf64 (single source of truth).
def p16(b,o,v):struct.pack_into("<H",b,o,v&0xFFFF)
def p32(b,o,v):struct.pack_into("<I",b,o,v&0xFFFFFFFF)
def p64(b,o,v):struct.pack_into("<Q",b,o,v&0xFFFFFFFFFFFFFFFF)
class Elf:
    # PHT/DYNAMIC parsing delegated to the shared elf64 module (behavior-exact:
    # same little-endian offsets, filesz-bounded v2o, 256-entry DT_NULL walk).
    def __init__(s,data):
        s.d=bytearray(data)
        # raw header fields still needed directly by the phdr mutator (elf64 has
        # no writers, so the phdr category strides these to pick a write offset).
        s.e_phoff=u64(s.d,0x20);s.e_phentsize=u16(s.d,0x36);s.e_phnum=u16(s.d,0x38)
    def v2o(s,va):
        return elf64.vaddr_to_offset(s.d,va)
    def dyn(s):
        return list(elf64.iter_dynamic(s.d))
    def tag(s,w):
        for i,t,v,fo in s.dyn():
            if t==w:return v,fo
        return None,None
def rbig():return random.choice([0xffffffff,0x7fffffff,0x41414141,random.randint(0,0xffffffff),0xfffffff0,0x10,0x0,0x80000000])
def mutate(base,e):
    cat=random.choice(["verneed","verneed","dynrand","strtab","audit","phdr","reloc"]);d=bytearray(base)
    try:
        if cat=="verneed":
            vn,_=e.tag(DT_VERNEED)
            if vn is None:return None
            off=e.v2o(vn)
            if off is None:return None
            aux=off+u32(base,off+8)
            nm,pos,fn=random.choice([("vna_name",aux+8,p32),("vn_file",off+4,p32),("vna_next",aux+12,p32),("vn_next",off+12,p32),("vn_cnt",off+2,p16)])
            fn(d,pos,rbig());lab=f"verneed_{nm}"
        elif cat=="dynrand":
            ents=[x for x in e.dyn() if x[1]!=DT_NULL]
            if not ents:return None
            i,t,v,fo=random.choice(ents);p64(d,fo,random.choice(ITAGS));p64(d,fo+8,rbig());lab=f"dynrand_t{u64(d,fo):x}"
        elif cat=="strtab":
            v,fo=e.tag(DT_STRTAB)
            if fo is None:return None
            p64(d,fo+8,random.choice([0,rbig(),0xffffffffffff]));lab="strtab"
        elif cat=="audit":
            dbg=None
            for i,t,v,fo in e.dyn():
                if t==DT_DEBUG:dbg=fo;break
            if dbg is None:return None
            p64(d,dbg,DT_AUDIT);p64(d,dbg+8,rbig());lab="audit"
        elif cat=="reloc":
            done=False
            for w in [DT_JMPREL,DT_RELA]:
                v,fo=e.tag(w)
                if fo is not None:p64(d,fo+8,rbig());lab=f"reloc_{w}";done=True;break
            if not done:return None
        else:
            i=random.randrange(e.e_phnum);o=e.e_phoff+i*e.e_phentsize
            fld=random.choice([8,0x20,0x28,0x30,0x10]);p64(d,o+fld,rbig());lab=f"phdr_s{i}_f{fld:x}"
    except Exception:return None
    return lab,bytes(d)
def run_one(b,timeout=2):
    with tempfile.NamedTemporaryFile(prefix="ar_",suffix=".elf",delete=False,dir="/tmp") as f:
        f.write(b);path=f.name
    os.chmod(path,0o755)
    try:rc=subprocess.run([LDSO,path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout).returncode
    except subprocess.TimeoutExpired:rc=124
    finally:
        try:os.unlink(path)
        except:pass
    return rc
def is_crash(rc):return rc<0 or rc==124
def gdb_site(elf):
    try:
        out=subprocess.run(["gdb","--batch","-ex","run","-ex","bt 4","--args",LDSO,elf],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20,text=True).stdout
    except subprocess.TimeoutExpired:return("TIMEOUT","-")
    sig="?";m=re.search(r"received signal\s+(\w+)",out)
    if m:sig=m.group(1)
    fr="??"
    for ln in out.splitlines():
        m=re.match(r"#\d+\s+(?:0x[0-9a-f]+ in )?([A-Za-z_][\w.]*)\s*\(",ln.strip())
        if m and m.group(1)!="??":fr=m.group(1);break
    return sig,fr
def verify_repro(elf):
    try:rc=subprocess.run([LDSO,"--verify",elf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode
    except subprocess.TimeoutExpired:return "timeout"
    return f"SIG{-rc}" if rc<0 else "ok"
def load_state():
    if os.path.exists(STATE):
        try:return json.load(open(STATE))
        except:pass
    return {"start_ts":time.time(),"rounds":0,"runs":0,"crashes_saved":0,"sites":{},"verify":{},"seen_hashes":[]}
def main():
    ap=argparse.ArgumentParser(description="autorun_v3 fuzz+triage round")
    ap.add_argument("budget",nargs="?",type=int,default=1800,help="budget seconds (default 1800)")
    ap.add_argument("--seed",type=int,default=None,help="RNG seed for reproducible mutation; auto-generated & logged if omitted")
    args=ap.parse_args()
    budget=args.budget
    # B18: make the mutation RNG reproducible. Seed once at startup and record it
    # (in state + per crash) so a round replays from the log.
    seed=args.seed if args.seed is not None else random.randrange(1<<63)
    random.seed(seed)
    os.makedirs(OUT,exist_ok=True)
    base=open(BASE,"rb").read();e=Elf(base)
    st=load_state();st["rounds"]=st.get("rounds",0)+1;st["seed"]=seed
    # B28: keep seen hashes in an insertion-ordered dict (not a set) so the
    # recency slice below actually keeps the most-recent hashes.
    seen=dict.fromkeys(st.get("seen_hashes",[]));t0=time.time();runs=0;newc=0;new_files=[]
    mut_deadline=t0+budget*0.6
    while time.time()<mut_deadline:
        r=mutate(base,e)
        if not r:continue
        lab,vb=r;runs+=1;rc=run_one(vb)
        if is_crash(rc):
            h=hashlib.sha1(vb).hexdigest()[:12]
            if h in seen:continue
            seen[h]=None;cls="timeout" if rc==124 else f"sig{-rc}"
            fn=os.path.join(OUT,f"{lab}__{h}__{cls}.elf");open(fn,"wb").write(vb);new_files.append(fn);newc+=1
            # B18: record the seed alongside the crash so this exact round replays.
            json.dump({"seed":seed,"round":st["rounds"],"label":lab,"sha":h,"class":cls,"rc":rc},
                      open(fn+".meta.json","w"))
    triaged=0;MAXT=80
    for fn in new_files:
        if triaged>=MAXT or time.time()>t0+budget:break
        sig,fr=gdb_site(fn);key=f"{sig}:{fr}";triaged+=1
        s=st["sites"].setdefault(key,{"count":0,"example":os.path.basename(fn)});s["count"]+=1
        if key not in st["verify"]:st["verify"][key]=verify_repro(fn)
    st["runs"]=st.get("runs",0)+runs;st["crashes_saved"]=st.get("crashes_saved",0)+newc
    # B28: seen is now insertion-ordered, so this keeps the newest 60000 hashes.
    st["seen_hashes"]=list(seen)[-60000:];json.dump(st,open(STATE,"w"))
    elapsed=(time.time()-st["start_ts"])/3600.0;distinct=len(st["sites"]);ts=time.strftime("%Y-%m-%d %H:%M:%S")
    with open(PROG,"a") as f:
        f.write(f"[{ts}] round {st['rounds']} seed={seed} elapsed {elapsed:.2f}h | this: {runs} runs {newc} new {triaged} triaged | TOTAL runs={st['runs']} crashes={st['crashes_saved']} distinct={distinct}\n")
    with open(SUMM,"w") as f:
        f.write(f"updated {ts} | elapsed {elapsed:.2f}h | total runs {st['runs']} | total crashes {st['crashes_saved']} | distinct sites {distinct}\n\n")
        for k,v in sorted(st["sites"].items(),key=lambda x:-x[1]["count"]):
            f.write(f"  x{v['count']:<5} {k:42} verify={st['verify'].get(k,'?')}  e.g. {v['example']}\n")
    print(f"round {st['rounds']} done: {runs} runs {newc} new crashes, distinct {distinct}, elapsed {elapsed:.2f}h")
if __name__=="__main__":main()
