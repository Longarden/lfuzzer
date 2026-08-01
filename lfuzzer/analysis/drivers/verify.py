"""드라이버가 정말 허용 영역만 건드렸는지 바이트 단위로 검증."""
import sys
from common import locate_header, locate_phdr, locate_dynamic

BASE = "base.elf"

KINDS = {
    "hdr": ("locate_header", 16),
    "seg": ("locate_phdr", 0),
    "dyn": ("locate_dynamic", 0),
}

LOCATORS = {
    "locate_header": locate_header,
    "locate_phdr": locate_phdr,
    "locate_dynamic": locate_dynamic,
}


def diff_ranges(a, b):
    n = min(len(a), len(b))
    ranges, i = [], 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            ranges.append((i, j))
            i = j
        else:
            i += 1
    if len(a) != len(b):
        ranges.append((n, max(len(a), len(b))))
    return ranges


def main():
    if len(sys.argv) != 3:
        print("usage: python3 verify.py <hdr|seg|dyn> <out.elf>")
        sys.exit(2)
    kind, out = sys.argv[1], sys.argv[2]

    with open(BASE, "rb") as f:
        a = f.read()
    with open(out, "rb") as f:
        b = f.read()

    loc_name, skip = KINDS[kind]
    start, length = LOCATORS[loc_name](BASE)
    allowed_lo = start + skip
    allowed_hi = start + length

    diffs = diff_ranges(a, b)
    print(f"allowed = [{allowed_lo}, {allowed_hi})")
    print(f"diffs   = {diffs}")

    bad = [(s, e) for (s, e) in diffs if s < allowed_lo or e > allowed_hi]
    if bad:
        print(f"FAIL: changes outside allowed region: {bad}")
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
