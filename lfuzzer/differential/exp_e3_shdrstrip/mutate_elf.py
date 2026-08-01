#!/usr/bin/env python3
"""
mutate_elf.py - ELF64 surgery helpers for exp_e3_shdrstrip.

Two independent mutations, each usable standalone:

  strip       : zero out e_shoff (8 bytes @ file offset 0x28) and
                e_shstrndx (2 bytes @ file offset 0x3E) in the ELF64 header.
                This makes the file look like it has NO section header table
                at all (shnum effectively 0 from the loader's point of view),
                which is what forces BFD's elfcode.h fallback path
                (_bfd_elf_get_dynamic_symbols) to engage instead of the
                normal section-header-based symbol table reader.

  patch-strsz : parse the ELF64 program header table, find the PT_DYNAMIC
                segment, scan its 16-byte Elf64_Dyn entries for d_tag==10
                (DT_STRSZ), and overwrite d_val with a caller-supplied value
                (bogus/tiny, e.g. 1, to make legitimate string-table offsets
                look "out of range").

Usage:
    python3 mutate_elf.py strip <in.so> <out.so>
    python3 mutate_elf.py patch-strsz <in.so> <out.so> <new_value>
    python3 mutate_elf.py dump-dynamic <in.so>        # debug helper
    python3 mutate_elf.py strip-full <in.so> <out.so> # BONUS/addendum, see below

BONUS note (added after first run of the experiment showed BFD rejecting
*every* section-header-stripped variant outright with "file format not
recognized", regardless of DT_STRSZ):

  `strip` (as specified in the experiment task) zeroes only e_shoff and
  e_shstrndx, per the task's literal recipe. Reading bfd/elfcode.h
  (elf_object_p) shows there is an EARLIER, stricter gate than the
  DT_STRSZ-sensitive fallback the task describes:

      if (i_ehdrp->e_shoff < sizeof (x_ehdr) && i_ehdrp->e_shnum != 0)
          goto got_wrong_format_error;

  Since `strip` leaves e_shnum (2 bytes @ file offset 0x3C) untouched at
  its original nonzero value, this guard rejects the file as an
  unrecognized format BEFORE bfd ever reaches the
  `e_shoff == 0 && e_shstrndx == 0` fallback block (which calls
  _bfd_elf_get_dynamic_symbols) that the task's hypothesis is actually
  about. `strip-full` additionally zeroes e_shnum, to test whether that
  is what's needed to actually reach the hypothesized fallback path.
  This is a diagnostic addendum, not a substitute for the as-specified
  `strip` -- both are run and reported separately.

All ELF64 little-endian struct layouts used here (offsets are byte offsets
within the respective struct, per the System V ABI / ELF64 spec):

  Elf64_Ehdr (64 bytes total):
    0x00 e_ident[16]
    0x10 e_type       (2)
    0x12 e_machine     (2)
    0x14 e_version     (4)
    0x18 e_entry       (8)
    0x20 e_phoff       (8)   <- program header table file offset
    0x28 e_shoff       (8)   <- section header table file offset  (ZEROED by strip)
    0x30 e_flags       (4)
    0x34 e_ehsize      (2)
    0x36 e_phentsize   (2)
    0x38 e_phnum       (2)
    0x3A e_shentsize   (2)
    0x3C e_shnum       (2)
    0x3E e_shstrndx    (2)   <- section name string table index (ZEROED by strip)

  Elf64_Phdr (56 bytes each):
    0x00 p_type   (4)
    0x04 p_flags  (4)
    0x08 p_offset (8)
    0x10 p_vaddr  (8)
    0x18 p_paddr  (8)
    0x20 p_filesz (8)
    0x28 p_memsz  (8)
    0x30 p_align  (8)

  Elf64_Dyn (16 bytes each):
    0x00 d_tag (8, signed)
    0x08 d_val / d_ptr (8, unsigned)

  PT_DYNAMIC = 2
  DT_NULL    = 0
  DT_STRSZ   = 10
"""
import shutil
import struct
import sys

EHDR_FMT_PARTIAL = None  # not used as a single struct; we index by offset directly

PT_DYNAMIC = 2
DT_NULL = 0
DT_STRSZ = 10


def read_ehdr_fields(data: bytes):
    """Pull out the handful of Ehdr fields we need, by fixed byte offset."""
    if data[0:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    ei_class = data[4]
    if ei_class != 2:
        raise ValueError("only ELF64 (EI_CLASS=2) is supported by this script")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    return {
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_phentsize": e_phentsize,
        "e_phnum": e_phnum,
        "e_shstrndx": e_shstrndx,
    }


def find_pt_dynamic(data: bytes):
    """Walk the program header table and return (p_offset, p_filesz) of PT_DYNAMIC."""
    hdr = read_ehdr_fields(data)
    for i in range(hdr["e_phnum"]):
        off = hdr["e_phoff"] + i * hdr["e_phentsize"]
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == PT_DYNAMIC:
            return p_offset, p_filesz
    raise RuntimeError("PT_DYNAMIC segment not found -- is this really a shared object?")


def cmd_strip(inpath: str, outpath: str):
    """Zero e_shoff and e_shstrndx so the file appears to have no section headers."""
    shutil.copy(inpath, outpath)
    with open(outpath, "r+b") as f:
        data = f.read()
        before = read_ehdr_fields(data)
        f.seek(0x28)
        f.write(b"\x00" * 8)   # e_shoff = 0
        f.seek(0x3E)
        f.write(b"\x00" * 2)   # e_shstrndx = 0
    with open(outpath, "rb") as f:
        after = read_ehdr_fields(f.read())
    print(f"[strip] {inpath} -> {outpath}")
    print(f"        e_shoff:     {before['e_shoff']:#x} -> {after['e_shoff']:#x}")
    print(f"        e_shstrndx:  {before['e_shstrndx']:#x} -> {after['e_shstrndx']:#x}")


def cmd_strip_full(inpath: str, outpath: str):
    """BONUS/addendum (not part of the as-specified recipe): zero e_shoff,
    e_shstrndx, AND e_shnum, so that BFD's earlier elf_object_p sanity gate
    (which independently checks e_shnum != 0) does not reject the file
    before reaching the e_shoff==0 && e_shstrndx==0 fallback path."""
    shutil.copy(inpath, outpath)
    with open(outpath, "r+b") as f:
        data = f.read()
        before_shnum = struct.unpack_from("<H", data, 0x3C)[0]
        f.seek(0x28)
        f.write(b"\x00" * 8)   # e_shoff = 0
        f.seek(0x3C)
        f.write(b"\x00" * 2)   # e_shnum = 0  (the extra field vs. plain `strip`)
        f.seek(0x3E)
        f.write(b"\x00" * 2)   # e_shstrndx = 0
    print(f"[strip-full] {inpath} -> {outpath}")
    print(f"        e_shoff -> 0x0, e_shstrndx -> 0x0, e_shnum: {before_shnum} -> 0")


def cmd_patch_strsz(inpath: str, outpath: str, new_val: int):
    """Overwrite DT_STRSZ's d_val inside PT_DYNAMIC with new_val."""
    shutil.copy(inpath, outpath)
    with open(outpath, "rb") as f:
        data = f.read()
    p_offset, p_filesz = find_pt_dynamic(data)
    n_entries = p_filesz // 16
    found_off = None
    old_val = None
    for i in range(n_entries):
        entry_off = p_offset + i * 16
        d_tag, d_val = struct.unpack_from("<qQ", data, entry_off)
        if d_tag == DT_STRSZ:
            found_off = entry_off
            old_val = d_val
            break
        if d_tag == DT_NULL:
            break  # end of dynamic array, DT_STRSZ genuinely absent
    if found_off is None:
        raise RuntimeError("DT_STRSZ (tag=10) not found in PT_DYNAMIC of " + inpath)
    with open(outpath, "r+b") as f:
        f.seek(found_off + 8)  # +8 to skip d_tag, land on d_val
        f.write(struct.pack("<Q", new_val))
    print(f"[patch-strsz] {inpath} -> {outpath}")
    print(f"        PT_DYNAMIC: p_offset={p_offset:#x} p_filesz={p_filesz:#x} ({n_entries} entries)")
    print(f"        DT_STRSZ entry @ file offset {found_off:#x}: d_val {old_val:#x} -> {new_val:#x}")


def cmd_dump_dynamic(inpath: str):
    """Debug helper: print all Elf64_Dyn entries in PT_DYNAMIC."""
    with open(inpath, "rb") as f:
        data = f.read()
    p_offset, p_filesz = find_pt_dynamic(data)
    n_entries = p_filesz // 16
    print(f"{inpath}: PT_DYNAMIC p_offset={p_offset:#x} p_filesz={p_filesz:#x} ({n_entries} entries)")
    for i in range(n_entries):
        entry_off = p_offset + i * 16
        d_tag, d_val = struct.unpack_from("<qQ", data, entry_off)
        print(f"  [{i:3d}] tag={d_tag:#06x} val={d_val:#x}")
        if d_tag == DT_NULL:
            break


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "strip" and len(argv) == 4:
        cmd_strip(argv[2], argv[3])
    elif cmd == "strip-full" and len(argv) == 4:
        cmd_strip_full(argv[2], argv[3])
    elif cmd == "patch-strsz" and len(argv) == 5:
        cmd_patch_strsz(argv[2], argv[3], int(argv[4], 0))
    elif cmd == "dump-dynamic" and len(argv) == 3:
        cmd_dump_dynamic(argv[2])
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
