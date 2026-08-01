"""Driver 2: 프로그램 헤더 테이블(PHT) 영역만 뮤테이션. 우리 본업."""
from common import (
    read_base, read_afl, fill_region, write_out,
    locate_phdr, parse_args,
)

BASE = "base.elf"


def main():
    afl_in, out_path = parse_args()

    base = read_base(BASE)
    rnd = read_afl(afl_in)

    start, length = locate_phdr(BASE)
    payload = fill_region(rnd, length)
    base[start:start + length] = payload

    write_out(out_path, bytes(base))


if __name__ == "__main__":
    main()
