#!/usr/bin/env python3
"""
mutator_interp_overflow.py
===========================
INTERP 세그먼트(p_type=PT_INTERP=3)의 길이를 늘려서 ld.so의 strcmp 호출이
페이지 경계를 넘어 미맵핑 영역을 읽다가 SIGSEGV 나는지 검증한다.

기준 미팅: 2026-04-13 교수님 미팅 가설
   "INTERP 문자열을 길게 주면 strcmp에서 세그 폴트 날 것 같다"

전략
- 원본 INTERP 영역(prac.elf 기준 offset 0x318, 28 byte)에 길이 N의 문자열 박기.
- p_filesz, p_memsz 도 N으로 같이 키움. 안 그러면 잘림.
- 단, 파일 자체가 N만큼 커져야 하므로 ELF 끝에 N 바이트 추가하고 INTERP의
  p_offset 을 그쪽으로 옮기는 방식 사용 (원본 위치 유지하면 다른 섹션 침범).

NULL 위치 4종
  end   : "AAAA...A\0"       (마지막에만 NULL)
  none  : "AAAA...A"          (NULL 없음)
  middle: "AAA\0AAAA"         (절반 위치에 NULL)
  early : "AAAAAAAAAAAAAAA\0" + 나머지 데이터 (앞쪽 16바이트 끝에 NULL)

self-contained: mutator_field_v2.py와 동일 패턴.
multiprocessing 으로 8워커 병렬 실행.

사용법
    python3 mutator_interp_overflow.py --input prac.elf --workers 8
    python3 mutator_interp_overflow.py --count 50 --workers 8
"""

import argparse
import os
import struct
import random
import subprocess
import time
import multiprocessing as mp
from pathlib import Path


# ===== ELF 64-bit 상수 =====
PT_INTERP = 3
PT_LOAD = 1
PHDR_ENT_SIZE = 56  # ELF64 PHT 엔트리 크기

E_PHOFF_OFFSET = 0x20
E_PHNUM_OFFSET = 0x38
E_PHENTSIZE_OFFSET = 0x36

PH_P_TYPE_OFF = 0x00
PH_P_FLAGS_OFF = 0x04
PH_P_OFFSET_OFF = 0x08
PH_P_VADDR_OFF = 0x10
PH_P_PADDR_OFF = 0x18
PH_P_FILESZ_OFF = 0x20
PH_P_MEMSZ_OFF = 0x28
PH_P_ALIGN_OFF = 0x30


LENGTHS = [64, 128, 256, 512, 1024, 4096, 8192, 16384, 65536]
NULL_POSITIONS = ["end", "none", "middle", "early"]


OUT_DIR = Path("0504_interp_overflow")
CRASH_DIR = OUT_DIR / "crashes"
LOG_FILE = OUT_DIR / "log_interp.txt"

# 워커 글로벌
_W = {}


# ===== ELF 파싱/변형 =====
def find_interp_index(data: bytes) -> int:
    """PHT에서 PT_INTERP 엔트리의 인덱스 반환."""
    e_phoff = struct.unpack_from("<Q", data, E_PHOFF_OFFSET)[0]
    e_phnum = struct.unpack_from("<H", data, E_PHNUM_OFFSET)[0]
    e_phentsize = struct.unpack_from("<H", data, E_PHENTSIZE_OFFSET)[0]
    for i in range(e_phnum):
        ph_start = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, ph_start)[0]
        if p_type == PT_INTERP:
            return i, e_phoff, e_phentsize
    raise ValueError("PT_INTERP 엔트리 없음")


def make_payload(length: int, null_pos: str) -> bytes:
    """길이 N, NULL 위치 정책에 따른 INTERP 페이로드 생성."""
    # 기본 채움 문자: 'A' (0x41) — strcmp가 어디서 멈출지 결정하는 게 NULL 위치
    if null_pos == "end":
        if length < 1:
            return b"\x00"
        return b"A" * (length - 1) + b"\x00"
    elif null_pos == "none":
        return b"A" * length
    elif null_pos == "middle":
        if length < 2:
            return b"\x00"
        half = length // 2
        return b"A" * half + b"\x00" + b"B" * (length - half - 1)
    elif null_pos == "early":
        # 앞 16바이트 끝에 NULL, 나머지는 채움
        if length < 17:
            return b"A" * (length - 1) + b"\x00" if length >= 1 else b""
        return b"A" * 15 + b"\x00" + b"B" * (length - 16)
    else:
        raise ValueError(f"알 수 없는 null_pos: {null_pos}")


def mutate_interp(data: bytes, interp_idx: int, e_phoff: int, e_phentsize: int,
                  payload: bytes) -> bytes:
    """
    INTERP 페이로드를 파일 끝에 추가하고 PT_INTERP 엔트리의 offset/filesz/memsz/vaddr를 갱신.
    파일 자체가 N 바이트 더 커짐.
    """
    new_data = bytearray(data)
    new_offset = len(new_data)
    new_data += payload

    ph_start = e_phoff + interp_idx * e_phentsize

    # p_offset, p_vaddr, p_paddr, p_filesz, p_memsz 갱신
    # vaddr는 원본 INTERP의 vaddr 사용해도 되지만, 그 영역이 LOAD에 의해 매핑되어야 ld.so가 읽을 수 있음.
    # 가장 단순한 접근: vaddr = 새로운 페이로드 위치 그대로 (파일 끝 = 매핑 안 됨)
    # 하지만 ld.so는 INTERP의 p_vaddr+l_addr 위치에서 읽으니까, 매핑 안 된 영역이면 즉시 SIGSEGV.
    # → 우리가 노리는 게 정확히 이 동작 (페이지 경계 너머 읽기) 이므로 그대로 둠.
    struct.pack_into("<Q", new_data, ph_start + PH_P_OFFSET_OFF, new_offset)
    struct.pack_into("<Q", new_data, ph_start + PH_P_VADDR_OFF, new_offset)
    struct.pack_into("<Q", new_data, ph_start + PH_P_PADDR_OFF, new_offset)
    struct.pack_into("<Q", new_data, ph_start + PH_P_FILESZ_OFF, len(payload))
    struct.pack_into("<Q", new_data, ph_start + PH_P_MEMSZ_OFF, len(payload))

    return bytes(new_data)


# ===== ELF 실행 =====
def run_elf_inline(elf_bytes: bytes, case_id: str, timeout: int = 5) -> dict:
    """케이스마다 고유 임시 파일 사용. 실행 후 unlink."""
    tmp_path = f"./mutated_interp_{os.getpid()}_{case_id}"
    try:
        with open(tmp_path, "wb") as f:
            f.write(elf_bytes)
        os.chmod(tmp_path, 0o755)
        try:
            result = subprocess.run(
                [tmp_path], timeout=timeout,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            return {
                "exit_code": result.returncode,
                "stderr": result.stderr[:200].decode(errors="replace").strip(),
                "timed_out": False, "error": None,
            }
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
    stderr_low = result["stderr"].lower()
    if "exec format error" in stderr_low or "no such file" in stderr_low:
        return "EXECVE_REJECT"
    return f"OTHER({ec})"


def is_crash(tag: str) -> bool:
    return tag == "SIGSEGV" or tag == "TIMEOUT" or tag.startswith("OTHER")


# ===== 워커 =====
def _init_worker(original_bytes: bytes, interp_idx: int, e_phoff: int, e_phentsize: int):
    _W["original"] = original_bytes
    _W["interp_idx"] = interp_idx
    _W["e_phoff"] = e_phoff
    _W["e_phentsize"] = e_phentsize
    random.seed(os.getpid() ^ (int(time.time() * 1000) & 0xFFFFFFFF))


def _worker_run_case(task):
    case_id, length, null_pos = task
    payload = make_payload(length, null_pos)
    mutated = mutate_interp(_W["original"], _W["interp_idx"], _W["e_phoff"],
                            _W["e_phentsize"], payload)
    result = run_elf_inline(mutated, case_id, timeout=5)
    tag = classify(result)
    crash_data = mutated if is_crash(tag) else None
    return {
        "case_id": case_id,
        "length": length,
        "null_pos": null_pos,
        "tag": tag,
        "exit_code": result["exit_code"],
        "stderr": result["stderr"],
        "crash_data": crash_data,
    }


def _format_progress(done, total, start, counts):
    elapsed = time.time() - start
    rate = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / rate if rate > 0 else 0
    elapsed_s = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
    eta_s = f"{int(eta//60):02d}:{int(eta%60):02d}"
    pct = 100 * done / total if total else 0
    summary = " ".join(f"{k}={v}" for k, v in
                       sorted(counts.items(), key=lambda x: -x[1])[:5])
    return (f"[{time.strftime('%H:%M:%S')}] "
            f"{done:>6,}/{total:,} ({pct:5.1f}%) | "
            f"elapsed {elapsed_s} | ETA {eta_s} | rate {rate:5.1f}/s | "
            f"{summary}")


# ===== 메인 =====
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="prac.elf", help="원본 ELF")
    ap.add_argument("--count", type=int, default=10,
                    help="(길이, null_pos) 조합당 케이스 수")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--outdir", default="0504_interp_overflow")
    args = ap.parse_args()

    global OUT_DIR, CRASH_DIR, LOG_FILE
    OUT_DIR = Path(args.outdir)
    CRASH_DIR = OUT_DIR / "crashes"
    LOG_FILE = OUT_DIR / "log_interp.txt"
    OUT_DIR.mkdir(exist_ok=True)
    CRASH_DIR.mkdir(exist_ok=True)

    original = Path(args.input).read_bytes()
    interp_idx, e_phoff, e_phentsize = find_interp_index(original)
    print(f"[+] {args.input}: PT_INTERP @ index {interp_idx}, PHT 오프셋 0x{e_phoff:x}")

    # 모든 (length, null_pos, i) 조합 task 생성
    tasks = []
    for length in LENGTHS:
        for null_pos in NULL_POSITIONS:
            for i in range(args.count):
                case_id = f"L{length}_{null_pos}_{i:03d}"
                tasks.append((case_id, length, null_pos))

    total = len(tasks)
    print(f"[+] 총 {total} 케이스 ({len(LENGTHS)} 길이 × {len(NULL_POSITIONS)} NULL × {args.count}) / 워커 {args.workers}")

    results = []
    counts = {}
    start = time.time()
    last_p = 0.0
    progress_file = OUT_DIR / "progress.txt"

    log_fh = LOG_FILE.open("a")
    try:
        with mp.Pool(args.workers, initializer=_init_worker,
                     initargs=(original, interp_idx, e_phoff, e_phentsize)) as pool:
            for i, r in enumerate(pool.imap_unordered(
                    _worker_run_case, tasks, chunksize=4), start=1):
                if r["crash_data"]:
                    (CRASH_DIR / f"{r['case_id']}.elf").write_bytes(r["crash_data"])
                r["crash_data"] = None
                log_fh.write(f"{r['case_id']} → {r['tag']}\n")
                counts[r["tag"]] = counts.get(r["tag"], 0) + 1
                results.append({k: v for k, v in r.items() if k != "crash_data"})

                now = time.time()
                if now - last_p > 2.0:
                    progress_file.write_text(_format_progress(i, total, start, counts) + "\n")
                    last_p = now

        progress_file.write_text(_format_progress(total, total, start, counts) + " [DONE]\n")
    finally:
        log_fh.close()

    # 길이별 / NULL 위치별 분류 통계
    by_length = {}
    by_null = {}
    for r in results:
        L = r["length"]
        N = r["null_pos"]
        by_length.setdefault(L, {})[r["tag"]] = by_length.setdefault(L, {}).get(r["tag"], 0) + 1
        by_null.setdefault(N, {})[r["tag"]] = by_null.setdefault(N, {}).get(r["tag"], 0) + 1

    print("\n===== 길이별 분류 =====")
    print(f"{'길이':>6}  {'OK':>5} {'SIGSEGV':>8} {'EXECVE':>8} {'OTHER':>6} {'TIMEOUT':>8} {'ERROR':>6}")
    for L in LENGTHS:
        d = by_length.get(L, {})
        print(f"{L:>6}  "
              f"{d.get('OK', 0):>5} "
              f"{d.get('SIGSEGV', 0):>8} "
              f"{d.get('EXECVE_REJECT', 0):>8} "
              f"{sum(v for k, v in d.items() if k.startswith('OTHER')):>6} "
              f"{d.get('TIMEOUT', 0):>8} "
              f"{sum(v for k, v in d.items() if k.startswith('ERROR')):>6}")

    print("\n===== NULL 위치별 분류 =====")
    for N in NULL_POSITIONS:
        d = by_null.get(N, {})
        sigsegv = d.get("SIGSEGV", 0)
        ok = d.get("OK", 0)
        total_n = sum(d.values())
        print(f"  {N:>6}: SIGSEGV {sigsegv}/{total_n} ({100*sigsegv/total_n:.1f}%), OK {ok}")

    # 전체
    print("\n===== 전체 =====")
    for tag, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {tag:25s} {n:5d}  ({100*n/total:.1f}%)")
    print(f"  총 {total}, 크래시 ELF 저장: {CRASH_DIR}")


if __name__ == "__main__":
    main()
