#!/usr/bin/env python3
"""
strace_classify.py
===================
SIGSEGV 케이스(특히 GDB가 frame 정보 못 잡는 EARLY_NO_STACK)에 strace 떠서
마지막 syscall 패턴별로 클러스터링한다.

GDB는 backtrace 못 잡는 케이스도 strace는 syscall 흔적을 남기므로,
ld.so가 어떤 syscall에서 죽는지 (mmap? mprotect? read?) 추가로 분류 가능.

사용법:
    python3 strace_classify.py --crashes-dir 0504_field_shuffle/crashes \\
        --log-file 0504_field_shuffle/log_per_field.txt \\
        --filter-tag SIGSEGV --workers 8

출력:
    <crashes-dir>/../strace_cluster.txt — 마지막 syscall 별 빈도
    <crashes-dir>/../strace_per_case.csv — case_id, last_syscall
"""

import argparse
import os
import re
import subprocess
import multiprocessing as mp
from collections import Counter
from pathlib import Path


STRACE_TIMEOUT = 5
MAX_LAST_CALLS = 3  # 마지막 N개 syscall만 보고에 사용


def run_strace(elf_path: Path) -> dict:
    """elf_path에 strace 실행 → 마지막 syscalls 추출."""
    cmd = ["strace", "-f", "-e", "trace=all", str(elf_path)]
    try:
        out = subprocess.run(
            cmd,
            timeout=STRACE_TIMEOUT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        raw = out.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return {"path": str(elf_path), "last": "TIMEOUT", "tail": "", "err_syscall": "TIMEOUT"}
    except Exception as e:
        return {"path": str(elf_path), "last": f"ERROR({e!r})", "tail": "", "err_syscall": "ERROR"}

    # syscall 라인만 골라내기
    # 패턴: "syscall_name(args...) = retval" 또는 "syscall(...) = -1 ENOMEM (...)"
    # "+++ killed by SIGSEGV +++" 등 종료 시그널 줄도 잡음
    syscall_lines = []
    err_syscall = None
    last_real = None
    for line in raw.splitlines():
        # "exit_group(...)"이나 "+++ killed by SIGSEGV +++" 같은 종료 표지는 따로
        if line.startswith("+++") or line.startswith("---"):
            syscall_lines.append(line.strip())
            continue
        m = re.match(r"\s*(\w+)\s*\(.*?\)\s*=\s*(-?\d+|\?)", line)
        if m:
            name = m.group(1)
            ret = m.group(2)
            syscall_lines.append(f"{name}={ret}")
            last_real = name
            # -1 리턴 = 실패 syscall (에러 원인 후보)
            if ret == "-1":
                # 마지막 -1 syscall을 err_syscall로 기록
                em = re.search(r"=\s*-1\s+(\w+)", line)
                if em:
                    err_syscall = f"{name}({em.group(1)})"
                else:
                    err_syscall = f"{name}(-1)"

    last_n = syscall_lines[-MAX_LAST_CALLS:] if syscall_lines else []
    last = syscall_lines[-1] if syscall_lines else "NO_SYSCALLS"
    # 종료 직전 마지막 "성공한" syscall — 죽기 직전에 무엇을 했는가
    if last_real:
        last_real_short = last_real
    else:
        last_real_short = "NONE"

    return {
        "path": str(elf_path),
        "last": last,
        "last_real": last_real_short,
        "tail": " | ".join(last_n),
        "err_syscall": err_syscall or "no_err",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crashes-dir", required=True)
    ap.add_argument("--log-file", default=None,
                    help="log_per_field.txt — --filter-tag와 함께 사용")
    ap.add_argument("--filter-tag", default=None)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    crashes_dir = Path(args.crashes_dir)
    out_dir = Path(args.out) if args.out else crashes_dir.parent
    out_dir.mkdir(exist_ok=True)

    elfs = sorted(crashes_dir.glob("*.elf"))
    if args.filter_tag and args.log_file:
        log_path = Path(args.log_file)
        target_ids = set()
        with log_path.open() as f:
            for line in f:
                parts = line.strip().split("→")
                if len(parts) == 2 and parts[1].strip() == args.filter_tag:
                    target_ids.add(parts[0].strip())
        before = len(elfs)
        elfs = [e for e in elfs if e.stem in target_ids]
        print(f"[+] 태그 '{args.filter_tag}' 필터: {before} → {len(elfs)}")

    print(f"[+] strace 분석 ELF: {len(elfs)}개, 워커 {args.workers}개")

    with mp.Pool(args.workers) as pool:
        results = []
        for i, r in enumerate(pool.imap_unordered(run_strace, elfs, chunksize=10), start=1):
            results.append(r)
            if i % 1000 == 0 or i == len(elfs):
                print(f"  [{i}/{len(elfs)}]", flush=True)

    # 마지막 "real" syscall 별로 클러스터
    by_last_real = Counter(r["last_real"] for r in results)
    # err_syscall (마지막 -1 syscall) 별로 클러스터
    by_err = Counter(r["err_syscall"] for r in results)

    cluster_txt = out_dir / "strace_cluster.txt"
    per_case_csv = out_dir / "strace_per_case.csv"

    with cluster_txt.open("w") as f:
        f.write(f"# strace 자동 클러스터링 결과\n")
        f.write(f"# 분석 ELF: {len(elfs)}개\n\n")

        f.write(f"## 죽기 직전 마지막 'real' syscall 별 빈도\n\n")
        f.write(f"{'빈도':>7}  syscall\n")
        f.write("-" * 50 + "\n")
        for sc, cnt in by_last_real.most_common():
            f.write(f"{cnt:>7}  {sc}\n")

        f.write(f"\n## 마지막 실패(-1) syscall 별 빈도\n\n")
        f.write(f"{'빈도':>7}  syscall(errno)\n")
        f.write("-" * 70 + "\n")
        for sc, cnt in by_err.most_common(30):
            f.write(f"{cnt:>7}  {sc}\n")

        # 대표 케이스 (각 상위 syscall 별 1건)
        f.write(f"\n## 상위 패턴별 대표 케이스\n\n")
        seen = set()
        for r in results:
            k = r["last_real"]
            if k in seen or len(seen) >= 10:
                continue
            seen.add(k)
            f.write(f"\n### {k}\n")
            f.write(f"path: {r['path']}\n")
            f.write(f"last_3: {r['tail']}\n")
            f.write(f"err_syscall: {r['err_syscall']}\n")

    with per_case_csv.open("w") as f:
        f.write("case_id,last_real_syscall,err_syscall\n")
        for r in results:
            case_id = Path(r["path"]).stem
            f.write(f"{case_id},{r['last_real']},{r['err_syscall']}\n")

    print(f"\n[+] 완료. 마지막 syscall 종류: {len(by_last_real)}개")
    print(f"[+] 클러스터 보고서: {cluster_txt}")
    print(f"[+] per_case CSV: {per_case_csv}")


if __name__ == "__main__":
    main()
