#!/usr/bin/env python3
"""
mutate_dynamic.py -- Append a SECOND, conflicting DT_SONAME entry to an
ELF shared object's .dynamic array, to test whether BFD ld and gold's
dynamic linkers agree on "last DT_SONAME tag wins" semantics.

WHAT THIS SCRIPT ACTUALLY DOES (64-bit little-endian ELF only; that's
what `gcc -shared` produces on x86_64 Linux, which is our target here):

  1. Parse the ELF header to find the section header table.
  2. Locate the .dynamic and .dynstr sections by name.
  3. Confirm there is unused alignment padding immediately after the
     live bytes of .dynstr (i.e. between file_offset(.dynstr)+sh_size
     and the file offset of the next section). Sections are aligned,
     so this gap is typically a few zero bytes of padding inserted by
     the linker to satisfy the next section's alignment -- free space
     we can reuse without disturbing anything else in the file.
  4. Write a short NUL-terminated string into that padding gap. This
     becomes our second soname value.
  5. GROW the string table to legitimately cover the new string: bump
     both DT_STRSZ (in the .dynamic array) and the .dynstr section
     header's sh_size to include the new bytes.
     NOTE: an earlier version of this script skipped this step,
     reasoning that ELF loaders just read DT_STRTAB+offset as a raw C
     string without bounds-checking against DT_STRSZ. That is true for
     the runtime dynamic linker, but it is FALSE for BFD ld's own
     link-time ELF reader: BFD validates every string-table index it
     reads against the table's declared section size and rejects the
     whole file ('invalid string offset N >= N for section .dynstr')
     if any index -- including one it doesn't otherwise care about --
     falls outside it. So the string table must actually be grown, not
     just have data quietly appended past its declared end. Since our
     padding gap sits immediately before the next section, growing
     sh_size to fully cover the new string is safe and exact -- it
     fills the gap precisely with no overlap.
  6. Walk the Elf64_Dyn array pointed to by the .dynamic section and
     find the DT_RELACOUNT entry (tag 0x6ffffff9). This is a GNU
     extension hint used only by the *runtime* loader as a minor
     relocation-processing optimization; it plays no role in the
     static link-time processing of a dependency's soname, so
     repurposing it is safe for what we're testing here (we are not
     running the produced binaries, only linking against the mutated
     .so and inspecting what soname each linker recorded).
  7. Overwrite that entry's tag with DT_SONAME (0xe) and its value
     with the byte offset (within the string table) of the new string
     we just wrote. Because this entry sits near the END of the
     .dynamic array (right before the terminating DT_NULL), it is the
     LAST DT_SONAME entry in file order -- exactly what we need to
     test "last wins".

If step 3's padding gap turns out to be too small or non-zero (i.e.
the assumption doesn't hold for some other compiler/linker version),
the script aborts loudly rather than silently corrupting the file.
"""
import struct
import sys

DT_NULL = 0
DT_SONAME = 0xe
DT_STRSZ = 0xa
DT_RELACOUNT = 0x6ffffff9


def die(msg):
    print(f"[mutate_dynamic] FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def read_cstr(data, off):
    end = data.index(b"\x00", off)
    return data[off:end].decode(errors="replace")


def main():
    if len(sys.argv) != 4:
        die(f"usage: {sys.argv[0]} <in.so> <out.so> <new_soname_string>")
    in_path, out_path, new_soname = sys.argv[1], sys.argv[2], sys.argv[3]
    new_soname_bytes = new_soname.encode("ascii") + b"\x00"

    data = bytearray(open(in_path, "rb").read())

    # --- ELF64 header ---
    if data[0:4] != b"\x7fELF":
        die("not an ELF file")
    if data[4] != 2:
        die("only ELFCLASS64 supported by this script")
    if data[5] != 1:
        die("only little-endian supported by this script")

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]

    def read_shdr(i):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, \
            sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                "<IIQQQQIIQQ", data, off)
        return dict(name_off=sh_name, type=sh_type, flags=sh_flags,
                     addr=sh_addr, offset=sh_offset, size=sh_size,
                     link=sh_link, info=sh_info, addralign=sh_addralign,
                     entsize=sh_entsize, index=i, hdr_off=off)

    shdrs = [read_shdr(i) for i in range(e_shnum)]
    shstrtab = shdrs[e_shstrndx]

    def sh_name(sh):
        start = shstrtab["offset"] + sh["name_off"]
        end = data.index(b"\x00", start)
        return data[start:end].decode()

    named = {sh_name(sh): sh for sh in shdrs}
    if ".dynamic" not in named or ".dynstr" not in named:
        die("missing .dynamic or .dynstr section")

    dyn_sh = named[".dynamic"]
    dynstr_sh = named[".dynstr"]

    print(f"[mutate_dynamic] .dynamic: file_off=0x{dyn_sh['offset']:x} "
          f"size=0x{dyn_sh['size']:x} entsize=0x{dyn_sh['entsize']:x}")
    print(f"[mutate_dynamic] .dynstr : file_off=0x{dynstr_sh['offset']:x} "
          f"size=0x{dynstr_sh['size']:x}")

    # --- find the next section after .dynstr in FILE OFFSET order, to
    #     compute how much unused padding trails .dynstr's live bytes ---
    dynstr_end = dynstr_sh["offset"] + dynstr_sh["size"]
    later = [sh for sh in shdrs if sh["offset"] > dynstr_sh["offset"] and sh["type"] != 0]
    if not later:
        die("could not find a section after .dynstr to bound the padding gap")
    next_sh = min(later, key=lambda sh: sh["offset"])
    gap = next_sh["offset"] - dynstr_end
    print(f"[mutate_dynamic] next section after .dynstr is '{sh_name(next_sh)}' "
          f"at file_off=0x{next_sh['offset']:x} -> padding gap = {gap} bytes")

    if gap < len(new_soname_bytes):
        die(f"padding gap ({gap} bytes) is too small for new soname string "
            f"'{new_soname}' ({len(new_soname_bytes)} bytes incl. NUL). "
            f"Pick a shorter string.")

    existing_gap_bytes = bytes(data[dynstr_end:next_sh["offset"]])
    print(f"[mutate_dynamic] existing gap bytes: {existing_gap_bytes!r}")
    if any(b != 0 for b in existing_gap_bytes):
        die("padding gap is not all-zero; refusing to overwrite unknown data")

    # --- write the new string into the padding gap ---
    str_offset_in_table = dynstr_sh["size"]  # offset from start of string table
    write_at = dynstr_end
    data[write_at:write_at + len(new_soname_bytes)] = new_soname_bytes
    print(f"[mutate_dynamic] wrote {new_soname_bytes!r} at file_off=0x{write_at:x} "
          f"(dynstr-relative offset 0x{str_offset_in_table:x})")

    # --- grow .dynstr's declared size (section header) to legitimately
    #     cover the new string; BFD ld bounds-checks DT_SONAME/other
    #     string indices against this and rejects the file otherwise ---
    #  Elf64_Shdr layout: name(4) type(4) flags(8) addr(8) offset(8) size(8) ...
    #  -> sh_size field sits at byte offset 32 within the Shdr struct.
    new_dynstr_size = dynstr_sh["size"] + len(new_soname_bytes)
    struct.pack_into("<Q", data, dynstr_sh["hdr_off"] + 32, new_dynstr_size)
    print(f"[mutate_dynamic] grew .dynstr sh_size: 0x{dynstr_sh['size']:x} -> "
          f"0x{new_dynstr_size:x}")

    # --- walk .dynamic entries, find DT_RELACOUNT, and locate DT_STRSZ ---
    entsize = dyn_sh["entsize"] or 16
    n_entries = dyn_sh["size"] // entsize
    target_idx = None
    orig_soname_val = None
    strsz_idx = None
    orig_strsz = None
    for i in range(n_entries):
        off = dyn_sh["offset"] + i * entsize
        tag, val = struct.unpack_from("<qQ", data, off)
        if tag == DT_SONAME:
            orig_soname_val = val
        if tag == DT_RELACOUNT:
            target_idx = i
        if tag == DT_STRSZ:
            strsz_idx = i
            orig_strsz = val

    if target_idx is None:
        die("no DT_RELACOUNT entry found to repurpose -- this script's "
            "chosen 'safe to overwrite' slot doesn't exist in this binary; "
            "pick a different unused tag (see comments) and adjust the script")
    if orig_soname_val is None:
        die("no existing DT_SONAME entry found -- did you link with -soname?")
    if strsz_idx is None:
        die("no DT_STRSZ entry found -- cannot legitimately grow the string table")

    print(f"[mutate_dynamic] original DT_SONAME value = 0x{orig_soname_val:x} "
          f"-> {read_cstr(data, dynstr_sh['offset'] + orig_soname_val)!r}")

    strsz_off = dyn_sh["offset"] + strsz_idx * entsize
    struct.pack_into("<qQ", data, strsz_off, DT_STRSZ, new_dynstr_size)
    print(f"[mutate_dynamic] bumped DT_STRSZ entry #{strsz_idx}: "
          f"{orig_strsz} -> {new_dynstr_size}")

    print(f"[mutate_dynamic] repurposing .dynamic entry #{target_idx} "
          f"(was DT_RELACOUNT) as a SECOND, LAST-IN-FILE-ORDER DT_SONAME entry")
    off = dyn_sh["offset"] + target_idx * entsize
    struct.pack_into("<qQ", data, off, DT_SONAME, str_offset_in_table)

    open(out_path, "wb").write(data)
    print(f"[mutate_dynamic] wrote mutated file to {out_path}")


if __name__ == "__main__":
    main()
