#!/usr/bin/env python3
"""detect_overlap.py v6 — v5 + unknown phdr type + missing PT_NOTE 시그널.

v5 시그널 + 추가:
  ut: phdr entry 중 KNOWN_TYPES 밖의 type 존재 (PT_LOPROC/PT_HIOS/임의값 등)
  nn: PT_NOTE 가 하나도 없음 (정상 -no-pie 실행 binary 는 거의 .note.gnu.build-id 보유)
"""
import sys, struct

PHDR_SIZE = 56
PAGE = 0x1000
PT_LOAD       = 1
PT_NOTE       = 4
PT_TLS        = 7
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK    = 0x6474e551
PT_GNU_RELRO    = 0x6474e552
PT_GNU_PROPERTY = 0x6474e553

KNOWN_TYPES = {0, 1, 2, 3, 4, 5, 6, 7,
               0x6474e550, 0x6474e551, 0x6474e552, 0x6474e553, 0x6474e554,
               0x6474e555}  # GNU_SFRAME 도 포함

def phdrs(data):
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    out = []
    for i in range(e_phnum):
        b = e_phoff + i * PHDR_SIZE
        out.append({'idx':i,
                    'type':struct.unpack_from('<I',data,b)[0],
                    'flags':struct.unpack_from('<I',data,b+4)[0],
                    'offset':struct.unpack_from('<Q',data,b+8)[0],
                    'vaddr':struct.unpack_from('<Q',data,b+16)[0],
                    'memsz':struct.unpack_from('<Q',data,b+40)[0]})
    return out

def section_names(data):
    e_shoff=struct.unpack_from('<Q',data,0x28)[0]
    e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
    e_shnum=struct.unpack_from('<H',data,0x3c)[0]
    e_shstrndx=struct.unpack_from('<H',data,0x3e)[0]
    if e_shnum==0 or e_shoff==0: return []
    shstr_sh=e_shoff+e_shstrndx*e_shentsize
    shstr_off=struct.unpack_from('<Q',data,shstr_sh+24)[0]
    shstr_size=struct.unpack_from('<Q',data,shstr_sh+32)[0]
    strtab=data[shstr_off:shstr_off+shstr_size]
    names=[]
    for i in range(e_shnum):
        sh=e_shoff+i*e_shentsize
        name_off=struct.unpack_from('<I',data,sh)[0]
        end=strtab.find(b'\x00',name_off)
        names.append(strtab[name_off:end].decode('utf-8',errors='replace'))
    return names

def page_range(p):
    s=p['vaddr']&~(PAGE-1); e=(p['vaddr']+p['memsz']+PAGE-1)&~(PAGE-1)
    return s,e

def overlap_load(phs):
    loads=[p for p in phs if p['type']==PT_LOAD]
    out=[]
    for i in range(len(loads)):
        a_s,a_e=page_range(loads[i])
        for j in range(i+1,len(loads)):
            b_s,b_e=page_range(loads[j])
            if a_s<b_e and b_s<a_e: out.append((loads[i],loads[j]))
    return out

def relro_subset_fail(phs):
    rel=[p for p in phs if p['type']==PT_GNU_RELRO]
    loads=[p for p in phs if p['type']==PT_LOAD]
    return [r for r in rel if not any(L['vaddr']<=r['vaddr'] and r['vaddr']+r['memsz']<=L['vaddr']+L['memsz'] for L in loads)]

def relro_noop(phs):
    out=[]
    for r in [p for p in phs if p['type']==PT_GNU_RELRO]:
        if (r['vaddr']+r['memsz'])&~(PAGE-1) <= r['vaddr']&~(PAGE-1): out.append(r)
    return out

def relro_end_mismatch(phs):
    out=[]
    loads=[p for p in phs if p['type']==PT_LOAD]
    for r in [p for p in phs if p['type']==PT_GNU_RELRO]:
        re_=r['vaddr']+r['memsz']
        host=next((L for L in loads if L['vaddr']<=r['vaddr']<L['vaddr']+L['memsz']),None)
        if host is None: continue
        if not ((re_&(PAGE-1))==0 or re_==host['vaddr']+host['memsz']): out.append((r,host))
    return out

def gnu_stack_missing(phs):
    return not any(p['type']==PT_GNU_STACK for p in phs)

def section_segment_mismatch(phs,secs):
    out=[]
    has_eh=any(p['type']==PT_GNU_EH_FRAME for p in phs)
    has_prop=any(p['type']==PT_GNU_PROPERTY for p in phs)
    has_tls=any(p['type']==PT_TLS for p in phs)
    if '.eh_frame_hdr' in secs and not has_eh: out.append('s_eh')
    if '.note.gnu.property' in secs and not has_prop: out.append('s_prop')
    if ('.tdata' in secs or '.tbss' in secs) and not has_tls: out.append('s_tls')
    return out

def unknown_types(phs):
    return [hex(p['type']) for p in phs if p['type'] not in KNOWN_TYPES]

def note_count_zero(phs, secs):
    """PT_NOTE 카운트 0 인데 .note.* 섹션 존재"""
    has_note_phdr = any(p['type']==PT_NOTE for p in phs)
    has_note_sec = any(s.startswith('.note') for s in secs)
    return has_note_sec and not has_note_phdr

def analyze(path):
    data=open(path,'rb').read()
    P=phdrs(data)
    try: secs=section_names(data)
    except: secs=[]
    ov=overlap_load(P); rs=relro_subset_fail(P); rn=relro_noop(P); rem=relro_end_mismatch(P)
    sm=gnu_stack_missing(P); ssm=section_segment_mismatch(P,secs)
    ut=unknown_types(P); nn=note_count_zero(P,secs)
    anomaly = bool(ov or rs or rn or rem or sm or ssm or ut or nn)
    return {
        'path': path, 'pt_load_count': sum(1 for p in P if p['type']==PT_LOAD),
        'overlap_count': len(ov), 'relro_subset_fail': len(rs),
        'relro_noop': len(rn), 'relro_end_mismatch': len(rem),
        'gnu_stack_missing': sm, 'section_segment_mismatch': ssm,
        'unknown_types': ut, 'note_phdr_missing': nn,
        'verdict': 'ANOMALY' if anomaly else 'CLEAN',
    }

if __name__ == '__main__':
    paths=sys.argv[1:]
    if not paths: print('usage: detect_overlap.py <elf>...'); sys.exit(2)
    bad=0
    for p in paths:
        try:
            r=analyze(p)
            print(f'{r["verdict"]:8s} {p}  ov={r["overlap_count"]} sm={r["gnu_stack_missing"]} '
                  f'ssm={r["section_segment_mismatch"]} ut={r["unknown_types"]} nn={r["note_phdr_missing"]}')
            if r['verdict'] != 'CLEAN': bad += 1
        except Exception as e: print(f'ERROR    {p}  {e}')
    sys.exit(1 if bad else 0)
