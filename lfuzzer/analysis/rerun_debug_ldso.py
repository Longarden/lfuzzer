#!/usr/bin/env python3
# rerun 478 classified_crashes through the 6/23 debug+assert glibc build (build-dbg/elf/ld.so)
# instead of the production /lib64/ld-linux-x86-64.so.2, to surface hidden memory bugs
# (asserts / different signals) that the production build's raw SIGSEGV would mask.
import os, subprocess, re, json, time
from collections import Counter

CRASH_DIR = os.path.expanduser("~/PE/Lfuzzer/classified_crashes")
LDSO = os.path.expanduser("~/glibc/build-dbg/elf/ld.so")
LIBPATH = os.path.expanduser("~/glibc/build-dbg")
OUT_TXT = os.path.expanduser("~/PE/Lfuzzer/asan_debug_rerun_478.txt")
OUT_JSON = os.path.expanduser("~/PE/Lfuzzer/asan_debug_rerun_478.json")

def top(elf_path):
    try:
        r = subprocess.run(
            ["gdb", "--batch", "-ex", "run", "-ex", "bt 8", "--args",
             LDSO, "--library-path", LIBPATH, elf_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
        out = r.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", "-", "-")
    sig = "NONE"
    m = re.search(r"received signal\s+(\w+)", out)
    if m:
        sig = m.group(1)
    assertion = "-"
    m2 = re.search(r"Assertion `([^']+)' failed", out)
    if m2:
        assertion = m2.group(1)[:80]
    frame = "??"
    for line in out.splitlines():
        m3 = re.match(r"#\d+\s+(?:0x[0-9a-f]+ in )?([A-Za-z_][\w.]*)\s*\(", line.strip())
        if m3 and m3.group(1) != "??":
            frame = m3.group(1)
            break
    return (sig, frame, assertion)

files = sorted(os.listdir(CRASH_DIR))
total = len(files)
buckets = Counter()
rows = []
t0 = time.time()

with open(OUT_TXT, "w") as fh:
    fh.write(f"debug+assert ld.so rerun of {total} classified_crashes files\n")
    fh.write(f"LDSO={LDSO}\n\n")
    for i, fn in enumerate(files, 1):
        sig, frame, assertion = top(os.path.join(CRASH_DIR, fn))
        buckets[(sig, frame, assertion != "-")] += 1
        rows.append({"file": fn, "signal": sig, "frame": frame, "assertion": assertion})
        line = f"[{i}/{total}] {sig:10} {frame:34} assert={assertion!='-'}  {fn}\n"
        fh.write(line)
        fh.flush()
        if i % 25 == 0:
            elapsed = time.time() - t0
            print(f"{i}/{total} done, {elapsed:.0f}s elapsed", flush=True)

    fh.write("\n=== distinct (signal, frame, has_assert) buckets ===\n")
    for (sig, frame, has_assert), n in buckets.most_common():
        fh.write(f"  x{n:<3} {sig:10} {frame:34} assert={has_assert}\n")
    fh.write(f"\n=== {len(rows)} reruns -> {len(buckets)} distinct buckets, {sum(1 for r in rows if r['assertion']!='-')} with assertion messages ===\n")

with open(OUT_JSON, "w") as jf:
    json.dump(rows, jf, indent=1)

print("DONE", OUT_TXT, OUT_JSON)
