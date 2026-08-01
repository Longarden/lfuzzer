#!/usr/bin/env python3
# pyelftools로 DYNAMIC 세그먼트를 파싱해서 DT_DEBUG(21) 태그가
# readelf/objdump와 마찬가지로 <unknown>으로 보이는지 확인
import sys
import elftools
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG

path = sys.argv[1] if len(sys.argv) > 1 else "prac_extratag_poc.elf"
with open(path, "rb") as f:
    elf = ELFFile(f)
    dyn = None
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_DYNAMIC":
            dyn = seg
            break
    print("=== pyelftools %s : %s ===" % (elftools.__version__, path))
    for tag in dyn.iter_tags():
        raw = tag.entry.d_tag
        print("  entry =", dict(tag.entry))
