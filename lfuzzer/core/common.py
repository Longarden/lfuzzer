"""
AFL 드라이버 3종 공통 헬퍼.
교수님 지시: 옵션은 박아두고, 특정 ELF 필드 자리만 AFL 값으로 채운다.
"""
import sys
from elftools.elf.elffile import ELFFile

MAGIC_KEEP = 16


def read_base(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def read_afl(path):
    with open(path, "rb") as f:
        data = f.read()
    return data if data else b"\x00"


def fill_region(rnd, length):
    if not rnd:
        return b"\x00" * length
    if len(rnd) >= length:
        return rnd[:length]
    times = (length // len(rnd)) + 1
    return (rnd * times)[:length]


def write_out(out_path, data):
    with open(out_path, "wb") as f:
        f.write(data)


def locate_header(base_path):
    with open(base_path, "rb") as f:
        elf = ELFFile(f)
        return 0, elf.header["e_ehsize"]


def locate_phdr(base_path):
    with open(base_path, "rb") as f:
        elf = ELFFile(f)
        h = elf.header
        return h["e_phoff"], h["e_phentsize"] * h["e_phnum"]


def locate_dynamic(base_path):
    with open(base_path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_DYNAMIC":
                return seg["p_offset"], seg["p_filesz"]
    raise RuntimeError("PT_DYNAMIC not found in base.elf")


def parse_args():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: python3 <driver>.py <afl_input> <out_path>\n")
        sys.exit(2)
    return sys.argv[1], sys.argv[2]
