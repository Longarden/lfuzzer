from elftools.elf.elffile import ELFFile
with open('/home/garden/PE/Lfuzzer/overlap_perm_lab/target_tls','rb') as f:
    e = ELFFile(f)
    for i,s in enumerate(e.iter_segments()):
        print(f'  [{i:2d}] {s["p_type"]:18s} off={s["p_offset"]:#08x} va={s["p_vaddr"]:#010x} fsz={s["p_filesz"]:#06x} msz={s["p_memsz"]:#06x} fl={s["p_flags"]:#x} align={s["p_align"]:#x}')
    print('Sections:')
    for sec in e.iter_sections():
        if sec.name in ('.text','.tbss','.tdata','.bss'):
            print(f'  {sec.name:12s} addr={sec["sh_addr"]:#010x} size={sec["sh_size"]:#x}')
