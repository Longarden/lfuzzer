"""Driver 3: PT_DYNAMIC 세그먼트 영역만 뮤테이션."""
from common import (
    read_base, read_afl, fill_region, write_out,
    locate_dynamic, parse_args,
)

BASE = "base.elf"


def main():
    afl_in, out_path = parse_args()

    base = read_base(BASE)
    rnd = read_afl(afl_in)

    start, length = locate_dynamic(BASE)
    payload = fill_region(rnd, length)
    base[start:start + length] = payload

    write_out(out_path, bytes(base))


if __name__ == "__main__":
    main()
