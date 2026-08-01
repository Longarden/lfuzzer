#!/usr/bin/env python3
"""
mutator_interp_vaddr_v2.py
===========================
0507 코드 분석 후 재설계 버전.

가설 (재정의): ld.so 는 PT_INTERP 의 p_filesz 를 안 본다 (rtld.c:1179 의
while(*cp != '\0') 가 NULL terminator 까지만 순회). 따라서 진짜 트리거는
p_filesz 부풀림이 아니라 p_vaddr 를 위험 위치로 변형하는 것이다.

전략: PT_INTERP 의 p_vaddr 한 필드만 변형. 다른 필드와 파일 데이터는 그대로.
- p_offset 은 원본 (0x318) — 커널은 여기서 valid interp path 읽고 통과
- p_vaddr 만 변형 — ld.so 만 잘못된 위치로 NULL 탐색하다 SIGSEGV

위험 위치 4 모드
  A unmapped : LOAD 범위 밖 (0x10000 등) — 즉시 페이지 폴트
  B page_edge: LOAD 매핑 끝 직전 (페이지 경계 - delta) — strlen 페이지 너머
  C null     : 0x0 직접 — l_addr=0 PIE 환경 NULL 접근
  D inside   : LOAD 안 NULL 없는 영역 (.text 중간 등)

기존 mutator_interp_overflow.py (페이로드 추가 + p_offset/p_vaddr 둘 다 옮김) 은
- 페이로드가 valid interp path 가 아니라서 커널 ENOENT 거부 (100% EXECVE_REJECT)
- 가설 자체 (p_filesz 부풀림 → strcmp 세그) 가 ld.so 코드 분석으로 무효
이 두 이유로 폐기하고 본 v2 로 대체.

self-contained. multiprocessing 8 워커.

사용법
    python3 mutator_interp_vaddr_v2.py --input prac.elf --workers 8
    python3 mutator_interp_vaddr_v2.py --mode A --count 50
    python3 mutator_interp_vaddr_v2.py --dry-run
"""

import argparse
import os
import re
import struct
import random
import subprocess
import time
import multiprocessing as mp
from pathlib import Path

import elf64  # shared behavior-exact ELF64 read primitives

PT_INTERP = 3
PT_LOAD = 1

# Only p_vaddr is mutated in-place; its Elf64_Phdr field offset (matches
# elf64.read_phdrs which reads p_vaddr at entry_offset + 0x10).
PH_P_VADDR_OFF = 0x10

PAGE_SIZE = 0x1000


def round_up(n: int, align: int) -> int:
    """Round n up to the next multiple of align (align is a power of two)."""
    return (n + align - 1) & ~(align - 1)

# 모드: A unmapped / B page_edge / C null / D inside
MODES = ["A", "B", "C", "D"]

OUT_DIR = Path("0507_interp_vaddr")
CRASH_DIR = OUT_DIR / "crashes"
LOG_FILE = OUT_DIR / "log_interp_vaddr.txt"

_W = {}


def parse_elf(data: bytes):
    # Migrated to the shared elf64 module. elf64.read_phdrs strides by
    # e_phentsize@0x36 over e_phnum@0x38 entries starting at e_phoff@0x20 and
    # reads p_flags@0x04, p_offset@0x08, p_vaddr@0x10, p_filesz@0x20,
    # p_memsz@0x28 — identical offsets/reads to the previous inline parse, so
    # the returned (interp_idx, e_phoff, e_phentsize, loads) is unchanged.
    e_phoff = elf64.u64(data, 0x20)
    e_phentsize = elf64.u16(data, 0x36)
    interp_idx = None
    loads = []
    for i, ph in enumerate(elf64.read_phdrs(data)):
        if ph["p_type"] == PT_INTERP:
            interp_idx = i
        elif ph["p_type"] == PT_LOAD:
            loads.append({"idx": i, "offset": ph["p_offset"], "vaddr": ph["p_vaddr"],
                          "filesz": ph["p_filesz"], "memsz": ph["p_memsz"],
                          "flags": ph["p_flags"]})
    if interp_idx is None:
        raise ValueError("PT_INTERP 엔트리 없음")
    return interp_idx, e_phoff, e_phentsize, loads


def pick_vaddr(mode: str, loads, rng) -> int:
    """위험 위치 후보 선정. 모드별 1 값 반환."""
    if mode == "A":
        # LOAD 범위 밖. 가장 큰 LOAD memsz 끝 너머 + random 오프셋
        max_end = max(L["vaddr"] + L["memsz"] for L in loads)
        return max_end + rng.randint(0x1000, 0x100000)
    elif mode == "B":
        # B10 (BEHAVIOR CHANGE — UNDER VERIFICATION): land JUST PAST the page
        # that ends the mapping so ld.so's strlen walks off the mapped region
        # (the over-page-edge probe). The old formula returned a vaddr INSIDE
        # the mapping, so the probe never fired.
        #   OLD (inside mapping): return end - delta   # end=vaddr+memsz, delta 1..16
        L = rng.choice(loads)
        end = L["vaddr"] + L["memsz"]
        page_end = round_up(end, PAGE_SIZE)
        delta = rng.choice([1, 2, 4, 8, 12, 16])
        return page_end + delta
    elif mode == "C":
        # 0x0 직접 또는 0x10 같은 매우 낮은 주소
        return rng.choice([0x0, 0x1, 0x8, 0x10, 0x100, 0x318])
    elif mode == "D":
        # LOAD 안 NULL 없을 가능성 높은 위치 (.text RX 영역 중간)
        rx_loads = [L for L in loads if (L["flags"] & 0x1)]  # PF_X
        if not rx_loads:
            return loads[0]["vaddr"] + rng.randint(0, loads[0]["memsz"])
        L = rng.choice(rx_loads)
        return L["vaddr"] + rng.randint(0, max(L["memsz"] - 1, 1))
    raise ValueError(f"unknown mode {mode}")


def mutate_vaddr_only(data: bytes, interp_idx: int, e_phoff: int,
                       e_phentsize: int, new_vaddr: int) -> bytes:
    """PT_INTERP 의 p_vaddr 한 필드만 변형. 다른 필드/데이터 그대로."""
    new_data = bytearray(data)
    ph_start = e_phoff + interp_idx * e_phentsize
    struct.pack_into("<Q", new_data, ph_start + PH_P_VADDR_OFF, new_vaddr)
    return bytes(new_data)


def run_elf_inline(elf_bytes: bytes, case_id: str, timeout: int = 5) -> dict:
    tmp_path = f"./mutated_iv_{os.getpid()}_{case_id}"
    try:
        with open(tmp_path, "wb") as f:
            f.write(elf_bytes)
        os.chmod(tmp_path, 0o755)
        try:
            r = subprocess.run([tmp_path], timeout=timeout,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            return {"exit_code": r.returncode,
                    "stderr": r.stderr[:200].decode(errors="replace").strip(),
                    "timed_out": False, "error": None}
        except subprocess.TimeoutExpired:
            return {"exit_code": None, "stderr": "", "timed_out": True, "error": None}
        except Exception as e:
            return {"exit_code": None, "stderr": "", "timed_out": False, "error": str(e)}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def classify(result: dict) -> str:
    if result["timed_out"]:
        return "TIMEOUT"
    if result["error"]:
        err = result["error"].lower()
        for p in ("exec format error", "errno 8", "no such file", "errno 2",
                  "permission denied", "errno 13", "input/output error", "errno 5"):
            if p in err:
                return "EXECVE_REJECT"
        return f"ERROR({result['error'][:30]})"
    ec = result["exit_code"]
    if ec == 0:
        return "OK"
    if ec == -11 or ec == 139:
        return "SIGSEGV"
    s = result["stderr"].lower()
    # B09: a sanitizer report is a genuine memory-safety crash even though the
    # process exits with a positive code (ASAN default exitcode=1).
    if "addresssanitizer" in s or "sanitizer" in s:
        return "ASAN"
    if "exec format error" in s or "no such file" in s:
        return "EXECVE_REJECT"
    return f"OTHER({ec})"


def is_crash(tag: str) -> bool:
    # B09 fix (CONFIRMED): only genuine memory-safety failures count as crashes.
    #   - SIGSEGV, or any signal death (negative returncode: SIGABRT -6,
    #     SIGBUS -7, ... surface as OTHER(-N))
    #   - ASAN sanitizer report (positive exit but real crash)
    #   - TIMEOUT (hang, kept as an interesting case)
    # A plain POSITIVE non-zero exit (e.g. ld.so "cannot map file" -> exit 127)
    # is NOT a crash. The old code saved every OTHER(...) as a crash, so benign
    # loader rejections were wrongly stored as memory-safety findings.
    if tag in ("SIGSEGV", "ASAN", "TIMEOUT"):
        return True
    if tag.startswith("OTHER("):
        m = re.match(r"OTHER\((-?\d+)\)$", tag)
        if m:
            return int(m.group(1)) < 0
    return False


def _init_worker(orig: bytes, interp_idx: int, e_phoff: int, e_phentsize: int,
                 loads: list, seed):
    _W["original"] = orig
    _W["interp_idx"] = interp_idx
    _W["e_phoff"] = e_phoff
    _W["e_phentsize"] = e_phentsize
    _W["loads"] = loads
    _W["seed"] = seed
    # Non-reproducible default: per-worker pid^time. When --seed is given the
    # per-worker rng is unused; each case derives a deterministic rng from
    # (seed, case_id) so results are reproducible regardless of scheduling.
    _W["rng"] = random.Random(os.getpid() ^ (int(time.time() * 1000) & 0xFFFFFFFF))


def _worker_run_case(task):
    case_id, mode = task
    if _W["seed"] is not None:
        # deterministic per-case rng -> reproducible even under imap_unordered
        rng = random.Random(f"{_W['seed']}:{case_id}")
    else:
        rng = _W["rng"]
    new_vaddr = pick_vaddr(mode, _W["loads"], rng)
    mutated = mutate_vaddr_only(_W["original"], _W["interp_idx"],
                                  _W["e_phoff"], _W["e_phentsize"], new_vaddr)
    result = run_elf_inline(mutated, case_id, timeout=5)
    tag = classify(result)
    return {
        "case_id": case_id, "mode": mode, "new_vaddr": new_vaddr,
        "tag": tag, "exit_code": result["exit_code"],
        "stderr": result["stderr"],
        "crash_data": mutated if is_crash(tag) else None,
    }


def _format_progress(done, total, start, counts):
    elapsed = time.time() - start
    rate = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / rate if rate > 0 else 0
    summary = " ".join(f"{k}={v}" for k, v in
                       sorted(counts.items(), key=lambda x: -x[1])[:5])
    return (f"[{time.strftime('%H:%M:%S')}] {done:>5,}/{total:,} "
            f"({100*done/total:5.1f}%) | elapsed {int(elapsed//60):02d}:{int(elapsed%60):02d} "
            f"| ETA {int(eta//60):02d}:{int(eta%60):02d} | rate {rate:5.1f}/s | {summary}")


def dry_run(input_path: str, seed=None):
    """모드별 1 케이스만 시연. 실패 원인 즉시 진단용."""
    data = Path(input_path).read_bytes()
    interp_idx, e_phoff, e_phentsize, loads = parse_elf(data)
    print(f"[+] {input_path}: PT_INTERP idx={interp_idx}, LOAD {len(loads)}개")
    print(f"[+] 원본 INTERP p_offset/p_vaddr 유지, p_vaddr 만 변형")
    rng = random.Random(42 if seed is None else seed)
    for mode in MODES:
        new_vaddr = pick_vaddr(mode, loads, rng)
        mutated = mutate_vaddr_only(data, interp_idx, e_phoff, e_phentsize, new_vaddr)
        r = run_elf_inline(mutated, f"dry_{mode}", timeout=3)
        tag = classify(r)
        print(f"  mode={mode}  p_vaddr=0x{new_vaddr:x}  → {tag}  "
              f"(exit={r['exit_code']}, stderr={r['stderr'][:60]!r})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="prac.elf")
    ap.add_argument("--mode", default="ALL", choices=MODES + ["ALL"])
    ap.add_argument("--count", type=int, default=200,
                    help="모드 당 케이스 수 (ALL이면 모드 4 × count)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--outdir", default="0507_interp_vaddr")
    ap.add_argument("--dry-run", action="store_true",
                    help="모드별 1 케이스 시연 (병렬 안 씀)")
    ap.add_argument("--seed", type=int, default=None,
                    help="재현 가능한 실행을 위한 시드. 미지정 시 워커별 pid^time.")
    args = ap.parse_args()

    if args.dry_run:
        dry_run(args.input, args.seed)
        return

    global OUT_DIR, CRASH_DIR, LOG_FILE
    OUT_DIR = Path(args.outdir)
    CRASH_DIR = OUT_DIR / "crashes"
    LOG_FILE = OUT_DIR / "log_interp_vaddr.txt"
    OUT_DIR.mkdir(exist_ok=True)
    CRASH_DIR.mkdir(exist_ok=True)

    data = Path(args.input).read_bytes()
    interp_idx, e_phoff, e_phentsize, loads = parse_elf(data)
    print(f"[+] {args.input}: PT_INTERP idx={interp_idx}, LOAD {len(loads)}개")
    for L in loads:
        print(f"    LOAD seg{L['idx']}: vaddr=0x{L['vaddr']:x} memsz=0x{L['memsz']:x} "
              f"flags={L['flags']:#x}")

    modes = MODES if args.mode == "ALL" else [args.mode]
    tasks = []
    for mode in modes:
        for i in range(args.count):
            tasks.append((f"{mode}_{i:04d}", mode))
    total = len(tasks)
    print(f"[+] 총 {total} 케이스 ({len(modes)} 모드 × {args.count}) / 워커 {args.workers}")
    if args.seed is not None:
        print(f"[+] seed={args.seed} (재현 가능; 케이스별 new_vaddr 는 results.csv 에 기록)")
    else:
        print("[+] seed=None (워커별 pid^time; 재현 불가)")

    counts = {}
    start = time.time()
    last_p = 0.0
    progress_file = OUT_DIR / "progress.txt"
    log_fh = LOG_FILE.open("a")
    log_fh.write(f"# run seed={args.seed}\n")
    csv_fh = (OUT_DIR / "results.csv").open("w")
    csv_fh.write("case_id,mode,new_vaddr,tag,exit_code\n")
    try:
        with mp.Pool(args.workers, initializer=_init_worker,
                     initargs=(data, interp_idx, e_phoff, e_phentsize, loads,
                               args.seed)) as pool:
            for i, r in enumerate(pool.imap_unordered(
                    _worker_run_case, tasks, chunksize=4), start=1):
                if r["crash_data"]:
                    (CRASH_DIR / f"{r['case_id']}.elf").write_bytes(r["crash_data"])
                log_fh.write(f"{r['case_id']} mode={r['mode']} "
                             f"vaddr=0x{r['new_vaddr']:x} → {r['tag']}\n")
                csv_fh.write(f"{r['case_id']},{r['mode']},0x{r['new_vaddr']:x},"
                             f"{r['tag']},{r['exit_code']}\n")
                counts[r["tag"]] = counts.get(r["tag"], 0) + 1
                now = time.time()
                if now - last_p > 2.0:
                    progress_file.write_text(_format_progress(i, total, start, counts) + "\n")
                    last_p = now
        progress_file.write_text(_format_progress(total, total, start, counts) + " [DONE]\n")
    finally:
        log_fh.close()
        csv_fh.close()

    # 모드별 분포
    by_mode = {}
    for L in (OUT_DIR / "results.csv").read_text().splitlines()[1:]:
        parts = L.split(",")
        if len(parts) < 4:
            continue
        m, t = parts[1], parts[3]
        by_mode.setdefault(m, {})[t] = by_mode.setdefault(m, {}).get(t, 0) + 1

    print("\n===== 모드별 분류 =====")
    for m in modes:
        d = by_mode.get(m, {})
        print(f"  mode {m}: " + "  ".join(f"{k}={v}" for k, v in
              sorted(d.items(), key=lambda x: -x[1])))

    print("\n===== 전체 =====")
    for tag, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {tag:25s} {n:5d}  ({100*n/total:.1f}%)")
    print(f"  총 {total}, 크래시 ELF 저장: {CRASH_DIR}")


if __name__ == "__main__":
    main()
