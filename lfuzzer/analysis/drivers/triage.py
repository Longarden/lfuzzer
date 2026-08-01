"""
AFL crashes/ 의 입력들을 일괄 분류하는 트리아지 스크립트.

방식:
  1. 각 crash 입력을 driver 거쳐 ELF 로 변환
  2. 그 ELF 를 ld 에 넣어 GDB 자동 백트레이스
  3. (죽은 함수, 신호, 드라이버, 링커) 기준으로 버킷팅
  4. CSV + 카운트 표 출력

사용:
  python3 triage.py <crashes_dir> <driver_kind> <linker_kind> [out_csv]
예:
  python3 triage.py ~/PE/Lfuzzer/out/default/crashes seg bfd /tmp/triage.csv
"""
import csv
import os
import subprocess
import sys
import tempfile
from collections import Counter


LINKERS = {
    "bfd":  os.path.expanduser("~/binutils-build-afl-bfd-clean/ld/ld-new"),
    "gold": os.path.expanduser("~/binutils-build-afl-gold-clean/gold/ld-new"),
}

DRIVERS = {
    "hdr": os.path.expanduser("~/PE/Lfuzzer/drivers/driver_header.py"),
    "seg": os.path.expanduser("~/PE/Lfuzzer/drivers/driver_segment.py"),
    "dyn": os.path.expanduser("~/PE/Lfuzzer/drivers/driver_dynamic.py"),
}


def make_elf(driver_path, afl_input, out_elf):
    driver_dir = os.path.dirname(driver_path)
    return subprocess.run(
        ["python3", os.path.basename(driver_path), afl_input, out_elf],
        cwd=driver_dir,
        capture_output=True,
        timeout=10,
    ).returncode == 0


def run_under_gdb(linker_bin, elf_path):
    """ld + ELF 실행. 죽으면 GDB 백트레이스에서 (signal, top_frame) 추출."""
    cmd = [
        "gdb", "-batch", "-q",
        "-ex", "set pagination off",
        "-ex", f"run {elf_path} -o /tmp/triage_link_out",
        "-ex", "bt 1",
        "--args", linker_bin, elf_path, "-o", "/tmp/triage_link_out",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15, text=True)
        out = r.stdout + "\n" + r.stderr
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", "timeout")

    signal = "none"
    for line in out.splitlines():
        l = line.strip()
        if "received signal" in l:
            signal = l.split("received signal")[1].split(",")[0].strip()
            break
        if "Program terminated with signal" in l:
            signal = l.split("signal")[1].split(",")[0].strip()
            break

    top = "none"
    for line in out.splitlines():
        if line.startswith("#0"):
            parts = line.split(" in ", 1)
            if len(parts) == 2:
                top = parts[1].split(" (")[0].strip()
            else:
                top = line.split(None, 1)[1].strip()[:80]
            break

    return (signal, top)


def main():
    if len(sys.argv) < 4:
        print("usage: python3 triage.py <crashes_dir> <hdr|seg|dyn> <bfd|gold> [out_csv]")
        sys.exit(2)
    crashes_dir = sys.argv[1]
    drv_kind = sys.argv[2]
    ld_kind = sys.argv[3]
    out_csv = sys.argv[4] if len(sys.argv) > 4 else "/tmp/triage.csv"

    driver = DRIVERS[drv_kind]
    linker = LINKERS[ld_kind]

    rows = []
    buckets = Counter()
    files = sorted(
        f for f in os.listdir(crashes_dir)
        if os.path.isfile(os.path.join(crashes_dir, f))
        and not f.startswith("README")
    )
    print(f"triaging {len(files)} crashes from {crashes_dir}")

    for i, name in enumerate(files, 1):
        afl_in = os.path.join(crashes_dir, name)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tf:
            elf = tf.name
        try:
            if not make_elf(driver, afl_in, elf):
                buckets[("driver_fail", "driver_fail")] += 1
                rows.append((name, drv_kind, ld_kind, "driver_fail", "driver_fail"))
                continue
            sig, top = run_under_gdb(linker, elf)
            buckets[(sig, top)] += 1
            rows.append((name, drv_kind, ld_kind, sig, top))
        finally:
            try:
                os.unlink(elf)
            except OSError:
                pass
        if i % 20 == 0:
            print(f"  {i}/{len(files)}")

    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["crash_file", "driver", "linker", "signal", "top_frame"])
        w.writerows(rows)

    print(f"\nwrote {out_csv}\n")
    print("=== Top buckets (signal, top_frame): count ===")
    for (sig, top), n in buckets.most_common(20):
        print(f"  {n:5d}  {sig:20s}  {top}")


if __name__ == "__main__":
    main()
