#!/usr/bin/env python3
"""
auto_gdb_classify.py
=====================
크래시 ELF 디렉토리 안의 모든 ELF에 대해 batch GDB로 frame 0 위치를 추출하고
위치별로 클러스터링한다.

알려진 위치(0407 보고서 기준):
  - rtld.c:1673 (strcmp / INTERP 처리, l_addr=0+0x318)
  - rtld.c:1693 / get-dynamic-info.h:45 (elf_get_dynamic_info / DYNAMIC 처리)

위 두 위치는 "KNOWN"으로 분류, 그 외는 "NEW"로 분류해서 보고서에 첨부할 후보로 표시한다.

사용법:
    python3 auto_gdb_classify.py --crashes-dir 0504_field_shuffle/crashes
    python3 auto_gdb_classify.py --crashes-dir 0504_field_shuffle/crashes --sample 1000
    python3 auto_gdb_classify.py --crashes-dir 0504_field_shuffle/crashes --workers 4

출력:
  <crashes-dir>/../gdb_cluster.txt     — 위치별 빈도표
  <crashes-dir>/../new_locations/      — 신규 위치별 대표 ELF + 전체 GDB 출력

self-contained: gdb 가 시스템에 설치되어 있어야 함.
"""

import argparse
import os
import re
import random
import subprocess
import multiprocessing as mp
from collections import Counter, defaultdict
from pathlib import Path


# ===== 알려진 크래시 위치 (0407 보고서 기준) =====
KNOWN_LOCATIONS = {
    "rtld.c:1673": "INTERP/strcmp — l_addr=0+0x318 미맵핑 접근 (PHDR < INTERP 위반)",
    "rtld.c:1693": "DYNAMIC/elf_get_dynamic_info — l_ld 잘못 저장 (PHDR < DYNAMIC 위반)",
    "get-dynamic-info.h:45": "elf_get_dynamic_info 내부 frame 0 (rtld.c:1693 콜러)",
    "strcmp": "frame 0이 strcmp만 보이는 경우 (rtld.c:1673과 같은 케이스)",
}


# ===== GDB 한 ELF 실행 =====
GDB_TIMEOUT = 5  # 한 ELF 분석 최대 시간 (대부분 1~2초면 충분)


def run_gdb_on_elf(elf_path: Path) -> dict:
    """
    elf_path에 GDB batch 실행 → frame 0 위치 + 짧은 백트레이스 반환.
    return: {"path": str, "loc": str, "bt": str, "rip": str, "raw": str}
    """
    cmd = [
        "gdb", "-batch", "-nh", "-q",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "run",
        "-ex", "info registers rip",
        "-ex", "bt 5",
        "-ex", "quit",
        "--args", str(elf_path),
    ]
    try:
        out = subprocess.run(
            cmd,
            timeout=GDB_TIMEOUT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        raw = out.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return {"path": str(elf_path), "loc": "GDB_TIMEOUT", "bt": "", "rip": "", "raw": ""}
    except Exception as e:
        return {"path": str(elf_path), "loc": f"GDB_ERROR({e!r})", "bt": "", "rip": "", "raw": ""}

    # frame 0 추출
    # 0a) ld.so가 메타데이터 검증 실패로 graceful exit (SIGSEGV 아님, 0177 exit)
    ldso_err = re.search(
        r"error while loading shared libraries:\s+\S+:\s+(.+?)(?:\n|$)", raw)
    if ldso_err:
        msg = ldso_err.group(1).strip()
        # 너무 길면 자르기, 숫자/주소 뺀 일반화 형태로 분류
        msg_short = re.sub(r"\b0x[0-9a-fA-F]+\b", "0x?", msg)
        msg_short = re.sub(r"\b\d{2,}\b", "?", msg_short)
        loc = f"LDSO_ERR: {msg_short[:60]}"
    # 0b) 너무 일찍 죽어서 stack이 없는 경우
    elif "During startup program terminated" in raw and "No stack" in raw:
        loc = "EARLY_NO_STACK"
    # 1) "#0  0x0 in ?? ()" 같은 NULL 점프
    elif re.search(r"^#0\s+0x0+\s+in\s+\?\?\s*\(\)", raw, re.MULTILINE):
        loc = "NULL_DEREF (??)"
    else:
        loc = "UNKNOWN"
        # 패턴 1: "#0  func () at file.c:NNN"
        # 패턴 2: "#0  0x... in func () at file.c:NNN"
        # 패턴 3: "#0  0x... in func () from /lib/..."  (디버깅 심볼 없음)
        m = re.search(r"^#0\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(.+?)\s+\(.*?\)(?:\s+at\s+(\S+))?", raw, re.MULTILINE)
        if m:
            func = m.group(1).strip()
            file_line = m.group(2)
            if file_line:
                # "rtld.c:1673" 같은 base name만 추출
                file_short = file_line.rsplit("/", 1)[-1]
                loc = f"{file_short}"
            else:
                # 라이브러리만 보이는 경우 (디버그 심볼 없음)
                loc = func

    # bt 5 추출
    bt = ""
    bt_m = re.findall(r"^#\d+\s+.*$", raw, re.MULTILINE)
    if bt_m:
        bt = "\n".join(bt_m[:5])

    # rip 추출
    rip = ""
    rip_m = re.search(r"rip\s+(0x[0-9a-fA-F]+)", raw)
    if rip_m:
        rip = rip_m.group(1)

    return {"path": str(elf_path), "loc": loc, "bt": bt, "rip": rip, "raw": raw}


# ===== 메인 =====
def is_known(loc: str) -> bool:
    """frame 0 위치가 알려진 위치인지."""
    if loc in KNOWN_LOCATIONS:
        return True
    # 부분 매칭 — "rtld.c:1673" 식으로 시작하면 known
    for k in KNOWN_LOCATIONS:
        if k in loc or loc in k:
            return True
    # strcmp가 등장하면 strcmp 케이스 = rtld.c:1673
    if "strcmp" in loc.lower():
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crashes-dir", required=True, help="크래시 ELF 모인 디렉토리")
    ap.add_argument("--sample", type=int, default=0, help="N개 무작위 샘플만 (0=전수)")
    ap.add_argument("--workers", type=int, default=4, help="GDB 병렬 워커 수")
    ap.add_argument("--out", default=None, help="결과 디렉토리 (기본 = crashes-dir 의 부모)")
    ap.add_argument("--log-file", default=None,
                    help="log_per_field.txt 경로 — 지정 시 --filter-tag로 태그 필터")
    ap.add_argument("--filter-tag", default=None,
                    help="이 태그를 가진 case_id만 분석 (예: SIGSEGV)")
    args = ap.parse_args()

    crashes_dir = Path(args.crashes_dir)
    if not crashes_dir.is_dir():
        raise SystemExit(f"디렉토리 없음: {crashes_dir}")

    out_dir = Path(args.out) if args.out else crashes_dir.parent
    out_dir.mkdir(exist_ok=True)
    new_loc_dir = out_dir / "new_locations"
    new_loc_dir.mkdir(exist_ok=True)

    elfs = sorted(crashes_dir.glob("*.elf"))

    # 태그 필터 — log_per_field.txt 에서 해당 태그 case_id만 통과
    if args.filter_tag and args.log_file:
        log_path = Path(args.log_file)
        if not log_path.is_file():
            raise SystemExit(f"log 파일 없음: {log_path}")
        target_ids = set()
        with log_path.open() as f:
            for line in f:
                # "A_seg0_p_type_0001 → SIGSEGV" 형식
                parts = line.strip().split("→")
                if len(parts) == 2 and parts[1].strip() == args.filter_tag:
                    target_ids.add(parts[0].strip())
        before = len(elfs)
        elfs = [e for e in elfs if e.stem in target_ids]
        print(f"[+] 태그 '{args.filter_tag}' 필터: 전체 {before}개 중 {len(elfs)}개 선택")

    if args.sample and len(elfs) > args.sample:
        random.seed(42)
        elfs = random.sample(elfs, args.sample)
        print(f"[+] {args.sample}개 무작위 샘플링")
    print(f"[+] 분석 대상 ELF: {len(elfs)}개, GDB 워커 {args.workers}개")

    # 병렬 GDB 실행
    with mp.Pool(args.workers) as pool:
        results = []
        for i, r in enumerate(pool.imap_unordered(run_gdb_on_elf, elfs, chunksize=4), start=1):
            results.append(r)
            if i % 50 == 0 or i == len(elfs):
                print(f"  [{i}/{len(elfs)}] 진행 중...", flush=True)

    # 위치별 카운트
    loc_counter = Counter(r["loc"] for r in results)
    by_loc = defaultdict(list)
    for r in results:
        by_loc[r["loc"]].append(r)

    # 결과 보고서 작성
    cluster_txt = out_dir / "gdb_cluster.txt"
    with cluster_txt.open("w") as f:
        f.write(f"# GDB 자동 클러스터링 결과\n")
        f.write(f"# 분석 ELF: {len(elfs)}개\n")
        f.write(f"# 크래시 디렉토리: {crashes_dir}\n\n")

        f.write(f"## 위치별 빈도 (frame 0 기준)\n\n")
        f.write(f"{'빈도':>7}  {'분류':>6}  {'위치':<40}  설명\n")
        f.write("-" * 100 + "\n")

        for loc, cnt in loc_counter.most_common():
            tag = "KNOWN" if is_known(loc) else "NEW"
            desc = KNOWN_LOCATIONS.get(loc, "")
            for k, v in KNOWN_LOCATIONS.items():
                if k in loc and not desc:
                    desc = v
                    break
            f.write(f"{cnt:>7}  {tag:>6}  {loc:<40}  {desc}\n")

        # 신규 위치별 대표 ELF
        new_locs = [loc for loc in loc_counter if not is_known(loc)
                    and not loc.startswith("GDB_")]
        if new_locs:
            f.write(f"\n\n## 신규 위치별 대표 GDB 출력\n\n")
            for loc in new_locs:
                f.write(f"\n### {loc} ({loc_counter[loc]}건)\n\n")
                rep = by_loc[loc][0]
                f.write(f"대표 ELF: {rep['path']}\n")
                f.write(f"rip: {rep['rip']}\n")
                f.write(f"backtrace:\n{rep['bt']}\n")

                # 신규 위치별 디렉토리에 ELF + raw GDB 출력 복사
                safe_loc = re.sub(r"[^\w.:]", "_", loc)
                loc_dir = new_loc_dir / safe_loc
                loc_dir.mkdir(exist_ok=True)
                for sample in by_loc[loc][:3]:  # 위치당 최대 3개
                    src = Path(sample["path"])
                    dst = loc_dir / src.name
                    if not dst.exists():
                        dst.write_bytes(src.read_bytes())
                    raw_path = loc_dir / (src.stem + ".gdb.txt")
                    raw_path.write_text(sample["raw"])
        else:
            f.write(f"\n\n## 신규 위치 없음 — 모두 알려진 위치 (rtld.c:1673 / 1693 등)\n")

    # per-case CSV 출력 (case_id → location 매핑)
    per_case_csv = out_dir / "gdb_per_case.csv"
    with per_case_csv.open("w") as f:
        f.write("case_id,frame0_loc,rip\n")
        for r in results:
            case_id = Path(r["path"]).stem
            f.write(f"{case_id},{r['loc']},{r['rip']}\n")

    print(f"\n[+] 완료. 위치 종류: {len(loc_counter)}개")
    print(f"[+] 클러스터 보고서: {cluster_txt}")
    print(f"[+] per-case CSV: {per_case_csv}")
    if new_locs:
        print(f"[+] 신규 위치 {len(new_locs)}개 → {new_loc_dir}")
    else:
        print(f"[+] 신규 위치 없음")


if __name__ == "__main__":
    main()
