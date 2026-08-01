"""Re-inspect target_full PHT — slot indices for iter21~"""
from elftools.elf.elffile import ELFFile
import os
os.chdir('/home/garden/PE/Lfuzzer/overlap_perm_lab')
with open('target_full','rb') as f:
    e = ELFFile(f)
    for i,s in enumerate(e.iter_segments()):
        print(f'  [{i:2d}] {s["p_type"]:18s} off={s["p_offset"]:#08x} va={s["p_vaddr"]:#010x} fsz={s["p_filesz"]:#06x} msz={s["p_memsz"]:#06x} fl={s["p_flags"]:#x} align={s["p_align"]:#x}')
