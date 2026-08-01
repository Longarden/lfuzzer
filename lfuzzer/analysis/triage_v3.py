#!/usr/bin/env python3
# triage_v3.py — out_dynamic_v3 크래시를 gdb로 (signal, 크래시함수)로 분류·dedup
import os, subprocess, re
from collections import Counter
OUT=os.path.expanduser("~/PE/Lfuzzer/out_dynamic_v3")
LDSO="/lib64/ld-linux-x86-64.so.2"

def top(elf):
    try:
        r=subprocess.run(["gdb","--batch","-ex","run","-ex","bt 6","--args",LDSO,elf],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20,text=True)
        out=r.stdout
    except subprocess.TimeoutExpired:
        return ("TIMEOUT","-")
    sig="?"
    m=re.search(r"received signal\s+(\w+)",out)
    if m: sig=m.group(1)
    frame="??"
    for line in out.splitlines():
        m=re.match(r"#\d+\s+(?:0x[0-9a-f]+ in )?([A-Za-z_][\w.]*)\s*\(",line.strip())
        if m and m.group(1)!="??":
            frame=m.group(1); break
    return (sig,frame)

buckets=Counter(); rows=[]
files=sorted(f for f in os.listdir(OUT) if f.endswith(".elf"))
for fn in files:
    sig,frame=top(os.path.join(OUT,fn)); buckets[(sig,frame)]+=1; rows.append((fn,sig,frame))
print("=== per-crash (signal, frame) ===")
for fn,sig,frame in rows: print(f"  {sig:10} {frame:34} {fn}")
print("=== distinct crash sites ===")
for (sig,frame),n in buckets.most_common(): print(f"  x{n:<3} {sig:10} {frame}")
print(f"=== {len(rows)} crashes -> {len(buckets)} distinct (signal,frame) buckets ===")
