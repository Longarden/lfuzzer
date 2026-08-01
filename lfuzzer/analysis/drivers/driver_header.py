"""Driver 1: ELF 헤더 영역만 뮤테이션 (매직 16바이트 보존)."""
from common import (
    read_base, read_afl, fill_region, write_out,
    locate_header, parse_args, MAGIC_KEEP,
)

BASE = "base.elf"


def main():
    afl_in, out_path = parse_args()

    base = read_base(BASE)
    rnd = read_afl(afl_in)

    start, length = locate_header(BASE)
    mut_start = start + MAGIC_KEEP
    mut_len = length - MAGIC_KEEP
    if mut_len <= 0:
        write_out(out_path, bytes(base))
        return

    payload = fill_region(rnd, mut_len)
    base[mut_start:mut_start + mut_len] = payload

    write_out(out_path, bytes(base))


if __name__ == "__main__":
    main()
