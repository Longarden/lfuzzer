#!/usr/bin/env python3
"""
corrupt_verneed.py

Locates the .gnu.version_r (Verneed) section inside a 64-bit little-endian
ELF shared object, finds the FIRST Vernaux entry belonging to the FIRST
Verneed entry, and overwrites that Vernaux's vna_next field with an
out-of-range huge value (0x7ffffff0).

vna_next is a linked-list 'offset to next Vernaux entry' field (relative
to the start of the current Vernaux entry). Setting it to a huge bogus
value means: 'if you keep walking the Vernaux chain past the first entry,
you will seek far outside the section / file'.

This script does NOT use pyelftools -- it parses the raw ELF64 structures
by hand with the struct module, so a student can see exactly which bytes
are being touched and why.

Usage:
    python3 corrupt_verneed.py libv.so libv_corrupt.so
"""
import struct
import sys
import shutil

ELF64_EHDR_FMT = '<16sHHIQQQIHHHHHH'
# e_ident(16s) e_type(H) e_machine(H) e_version(I) e_entry(Q) e_phoff(Q)
# e_shoff(Q) e_flags(I) e_ehsize(H) e_phentsize(H) e_phnum(H)
# e_shentsize(H) e_shnum(H) e_shstrndx(H)
ELF64_EHDR_SIZE = struct.calcsize(ELF64_EHDR_FMT)

ELF64_SHDR_FMT = '<IIQQQQIIQQ'
# sh_name(I) sh_type(I) sh_flags(Q) sh_addr(Q) sh_offset(Q) sh_size(Q)
# sh_link(I) sh_info(I) sh_addralign(Q) sh_entsize(Q)
ELF64_SHDR_SIZE = struct.calcsize(ELF64_SHDR_FMT)

VERNEED_FMT = '<HHIII'   # vn_version(H) vn_cnt(H) vn_file(I) vn_aux(I) vn_next(I)
VERNEED_SIZE = struct.calcsize(VERNEED_FMT)

VERNAUX_FMT = '<IHHII'   # vna_hash(I) vna_flags(H) vna_other(H) vna_name(I) vna_next(I)
VERNAUX_SIZE = struct.calcsize(VERNAUX_FMT)


def find_section_by_name(data, name):
    (e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack(ELF64_EHDR_FMT, data[:ELF64_EHDR_SIZE])

    assert e_ident[:4] == b'\x7fELF', 'not an ELF file'
    assert e_ident[4] == 2, 'expected ELFCLASS64'
    assert e_ident[5] == 1, 'expected little-endian'

    # Read all section headers.
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        shdrs.append(struct.unpack(ELF64_SHDR_FMT, data[off:off + ELF64_SHDR_SIZE]))

    # Section header string table gives us section names.
    shstrtab_off = shdrs[e_shstrndx][4]  # sh_offset of .shstrtab

    def sh_name(shdr):
        name_off = shstrtab_off + shdr[0]
        end = data.index(b'\x00', name_off)
        return data[name_off:end].decode()

    for shdr in shdrs:
        if sh_name(shdr) == name:
            sh_offset = shdr[4]
            sh_size = shdr[5]
            return sh_offset, sh_size

    return None


def corrupt_first_vernaux_next(path_in, path_out, bogus_value=0x7ffffff0):
    shutil.copyfile(path_in, path_out)

    with open(path_out, 'r+b') as f:
        data = f.read()

        result = find_section_by_name(data, '.gnu.version_r')
        if result is None:
            raise SystemExit('ERROR: .gnu.version_r section not found -- '
                              'the binary was not linked against a versioned symbol.')
        sh_offset, sh_size = result
        print(f'[*] .gnu.version_r found: sh_offset=0x{sh_offset:x} sh_size=0x{sh_size:x}')

        # First Verneed entry sits at the very start of the section.
        vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack(
            VERNEED_FMT, data[sh_offset:sh_offset + VERNEED_SIZE])
        print(f'[*] First Verneed entry: vn_version={vn_version} vn_cnt={vn_cnt} '
              f'vn_file(strtab off)={vn_file} vn_aux={vn_aux} vn_next={vn_next}')

        # vn_aux is a byte offset *relative to the start of this Verneed
        # entry* pointing to the first Vernaux entry in its aux chain.
        vernaux_offset = sh_offset + vn_aux
        vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack(
            VERNAUX_FMT, data[vernaux_offset:vernaux_offset + VERNAUX_SIZE])
        print(f'[*] First Vernaux entry @ file offset 0x{vernaux_offset:x}: '
              f'vna_hash=0x{vna_hash:x} vna_flags={vna_flags} vna_other={vna_other} '
              f'vna_name(strtab off)={vna_name} vna_next={vna_next} (ORIGINAL)')

        # vna_next is the last 4 bytes of the 16-byte Vernaux struct.
        vna_next_field_offset = vernaux_offset + 12
        assert struct.unpack('<I', data[vna_next_field_offset:vna_next_field_offset + 4])[0] == vna_next

        f.seek(vna_next_field_offset)
        f.write(struct.pack('<I', bogus_value))
        print(f'[*] Patched vna_next @ file offset 0x{vna_next_field_offset:x}: '
              f'{vna_next} -> {bogus_value} (0x{bogus_value:x})')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'usage: {sys.argv[0]} <in.so> <out_corrupt.so>')
        sys.exit(1)
    corrupt_first_vernaux_next(sys.argv[1], sys.argv[2])
