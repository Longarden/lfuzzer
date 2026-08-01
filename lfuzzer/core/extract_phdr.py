"""
ELF 파일 모음에서 PHT 영역 바이트만 잘라 in/ 에 시드(.bin) 로 저장.
드라이버 2(driver_segment.py) 용 시드 생성기.
"""
import os
import sys
import glob
from elftools.elf.elffile import ELFFile


def extract_phdr_bytes(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        h = elf.header
        start = h["e_phoff"]
        length = h["e_phentsize"] * h["e_phnum"]
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(length)


def main():
    if len(sys.argv) < 3:
        print("usage: python3 extract_phdr.py <in_dir> <out_dir> [prefix]")
        sys.exit(2)
    in_dir = sys.argv[1]
    out_dir = sys.argv[2]
    prefix = sys.argv[3] if len(sys.argv) > 3 else "phdr"

    os.makedirs(out_dir, exist_ok=True)

    written, skipped = 0, 0
    candidates = []
    for pattern in ("*.elf", "*"):
        candidates.extend(glob.glob(os.path.join(in_dir, pattern)))
    candidates = sorted(set(candidates))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                head = f.read(4)
            if head != b"\x7fELF":
                continue
            payload = extract_phdr_bytes(path)
            if not payload:
                continue
            name = os.path.basename(path)
            out = os.path.join(out_dir, f"{prefix}_{written:04d}_{name}.bin")
            with open(out, "wb") as f:
                f.write(payload)
            written += 1
        except Exception as e:
            skipped += 1
            sys.stderr.write(f"skip {path}: {e}\n")

    print(f"wrote {written}, skipped {skipped}")


if __name__ == "__main__":
    main()
