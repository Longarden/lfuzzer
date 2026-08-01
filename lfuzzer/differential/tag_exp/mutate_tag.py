import struct, subprocess, os, shutil
D=os.path.expanduser("~/PE/Lfuzzer/tag_exp")
base=open(os.path.join(D,"hello"),"rb").read()

# .dynamic file offset from readelf
dynoff=0x2e08
# parse 16-byte Elf64_Dyn entries until DT_NULL, record (index, tag, off)
entries=[]
o=dynoff
while True:
    tag,val=struct.unpack_from("<qQ",base,o)
    entries.append((len(entries),tag,o,val))
    if tag==0: break
    o+=16
def find(tagv):
    for idx,tag,off,val in entries:
        if tag==tagv: return off,val
    raise SystemExit("tag %#x not found"%tagv)
debug_off,_=find(0x15)      # DEBUG - non-essential, safe to repurpose
strtab_off,strtab_val=find(0x5)  # STRTAB - essential

def make(name, off, new_tag, new_val=None):
    b=bytearray(base)
    struct.pack_into("<q",b,off,new_tag)
    if new_val is not None:
        struct.pack_into("<Q",b,off+8,new_val)
    p=os.path.join(D,name); open(p,"wb").write(b); os.chmod(p,0o755)
    return name

variants=[]
# --- 음수(signed) 태그: DEBUG 엔트리의 d_tag만 음수로 ---
variants.append(make("v_neg_msb",     debug_off, -0x8000000000000000))          # 0x8000..0000 INT64_MIN
variants.append(make("v_neg_ff",      debug_off, -1))                            # 0xFFFF..FFFF
variants.append(make("v_neg_min1",    debug_off, -0x7FFFFFFFFFFFFFFF))           # 0x8000..0001 (low=NEEDED=1)
# 음수인데 하위비트가 실제 STRTAB(5): 오배치(misroute) 가설 테스트 — STRTAB 자체를 음수화
variants.append(make("v_neg_strtab",  strtab_off, -0x7FFFFFFFFFFFFFFB, strtab_val)) # 0x8000..0005, 값은 진짜 STRTAB ptr 유지
# --- 경계태그 (l_info demux 엣지) ---
variants.append(make("v_loproc_lo",   debug_off, 0x70000000))                    # DT_LOPROC (signed 분기)
variants.append(make("v_loproc_hi",   debug_off, 0x7fffffff))                    # DT_HIPROC
variants.append(make("v_valrnglo",    debug_off, 0x6ffffd00))                    # DT_VALRNGLO
variants.append(make("v_addrrnglo",   debug_off, 0x6ffffe00))                    # DT_ADDRRNGLO
# --- 중복 태그 (last-wins 런타임): DEBUG(STRTAB 뒤 인덱스)을 가짜 STRTAB로 ---
variants.append(make("v_dup_strtab",  debug_off, 0x5, 0x400000))                 # 두번째 STRTAB, 가짜 ptr

print("baseline STRTAB ptr =", hex(strtab_val))
print("DEBUG entry off =", hex(debug_off), " STRTAB entry off =", hex(strtab_off))
print("variants:", ", ".join(variants))
