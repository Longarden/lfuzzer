#!/usr/bin/env python3
"""
mutator_field_v2.py
====================
PHT(프로그램 헤더 테이블) 엔트리의 8개 필드를 무작위로 변형해서
ld.so의 새 크래시 케이스를 찾는다.

기준 미팅: 2026-04-13 교수님 미팅
기준 로드맵: Phase 1 (5/7 ~ 5/17)
직전 결과: 셔플링으로 PHDR < INTERP, PHDR < DYNAMIC 규칙 발견 완료

사용법:
    python3 mutator_field_v2.py --mode A --field p_offset --seg 2 --count 100
    python3 mutator_field_v2.py --mode A --all --count 100
    python3 mutator_field_v2.py --mode B --combo p_vaddr,p_filesz --count 1000

WSL 경로 가정: ~/PE/Lfuzzer/

self-contained 버전: 외부 모듈(lfuzzer) 의존성 없음.
ELF 실행은 subprocess.run으로 직접 호출 — fuzzer_permute.py와 동일 패턴.
"""

import os
import struct
import random
import argparse
import subprocess
import time
import multiprocessing as mp
from pathlib import Path

import elf64


# ===== ELF 64-bit 상수 =====
ELF_HEADER_SIZE = 64

# ELF 헤더 필드 오프셋 (절대 건들지 말 것)
E_ENTRY_OFFSET = 0x18
E_PHOFF_OFFSET = 0x20
E_PHNUM_OFFSET = 0x38
E_PHENTSIZE_OFFSET = 0x36

# Program Header Entry 내부 오프셋 (PHT 엔트리 시작점 기준 상대 위치)
PH_FIELDS = {
    "p_type":   (0x00, 4, "<I"),
    "p_flags":  (0x04, 4, "<I"),
    "p_offset": (0x08, 8, "<Q"),
    "p_vaddr":  (0x10, 8, "<Q"),
    "p_paddr":  (0x18, 8, "<Q"),
    "p_filesz": (0x20, 8, "<Q"),
    "p_memsz":  (0x28, 8, "<Q"),
    "p_align":  (0x30, 8, "<Q"),
}

# 결과 디렉토리 (--outdir 인자로 덮어쓸 수 있게 main에서 재설정)
OUT_DIR = Path("0504_field_shuffle")
CRASH_DIR = OUT_DIR / "crashes"
STRACE_DIR = OUT_DIR / "strace_dump"
LOG_FILE = OUT_DIR / "log_per_field.txt"


# ===== ELF 실행 (self-contained, fuzzer_permute.py 패턴) =====
def run_elf_inline(elf_bytes: bytes, case_id: str, timeout: int = 5) -> dict:
    """
    ELF 바이트를 임시 파일로 저장 후 실행.
    케이스마다 고유 파일명 사용 → ETXTBSY 방지. 실행 후 unlink로 즉시 정리.
    return: {exit_code, stderr, timed_out, error}
    """
    tmp_path = f"./mutated_tmp_{os.getpid()}_{case_id}"
    try:
        with open(tmp_path, "wb") as f:
            f.write(elf_bytes)
        os.chmod(tmp_path, 0o755)

        try:
            result = subprocess.run(
                [tmp_path],
                timeout=timeout,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            return {
                "exit_code": result.returncode,
                "stderr": result.stderr[:200].decode(errors="replace").strip(),
                "timed_out": False,
                "error": None,
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


# ===== ELF 파싱 =====
def parse_elf_header(data: bytes):
    """ELF 헤더에서 PHT 정보 추출 (공유 elf64 리더 사용)."""
    if data[:4] != b"\x7fELF":
        raise ValueError("ELF magic 불일치")
    if data[4] != 2:  # EI_CLASS
        raise ValueError("64-bit ELF 아님")

    # elf64.u64/u16 는 여기 상수와 동일한 오프셋(0x20/0x38/0x36)을 읽음 → 동작 동일
    e_phoff = elf64.u64(data, E_PHOFF_OFFSET)
    e_phnum = elf64.u16(data, E_PHNUM_OFFSET)
    e_phentsize = elf64.u16(data, E_PHENTSIZE_OFFSET)
    return e_phoff, e_phnum, e_phentsize


def get_existing_types(data: bytes, e_phoff: int, e_phnum: int, e_phentsize: int):
    """현재 ELF에 존재하는 p_type 목록 (랜덤 type 선택용)."""
    # elf64.read_phdrs 가 동일 오프셋/stride 로 PHT 를 파싱 → set 결과 동일
    types = {ph["p_type"] for ph in elf64.read_phdrs(data)}
    return list(types)


# ===== 필드별 변형 함수 =====
def mutate_field(field_name: str, original_value: int, existing_types: list, mode: str = "near") -> int:
    """
    한 필드에 대해 변형값 반환.
    mode: "near" (80% 근방) / "random" (20% 완전 랜덤)
    """
    if field_name == "p_type":
        # 타입은 무조건 현재 존재하는 타입 중 랜덤 (교수님 지시)
        return random.choice(existing_types)

    if field_name == "p_flags":
        if mode == "near":
            bit = random.randint(0, 2)  # R(4)/W(2)/X(1)
            return original_value ^ (1 << bit)
        else:
            return random.randint(0, 7)

    if field_name == "p_align":
        if mode == "near":
            return original_value // 2 if random.random() < 0.5 else original_value * 2
        else:
            return random.choice([0, 1, 0x1000, 0x10000])

    # offset / vaddr / paddr / filesz / memsz
    if mode == "near":
        delta = random.randint(-0x3000, 0x3000)
        return max(0, original_value + delta)
    else:
        if field_name in ("p_offset", "p_filesz", "p_memsz"):
            return random.randint(0, 0x100000)
        else:
            return random.randint(0, 0xFFFFFFFFFFFFFFFF)


def apply_mutation(data: bytearray, e_phoff: int, e_phentsize: int,
                   seg_idx: int, field_name: str, new_value: int):
    """PHT 엔트리의 한 필드에 새 값 쓰기."""
    field_off, _, fmt = PH_FIELDS[field_name]
    abs_off = e_phoff + seg_idx * e_phentsize + field_off
    struct.pack_into(fmt, data, abs_off, new_value)


def read_field(data: bytes, e_phoff: int, e_phentsize: int,
               seg_idx: int, field_name: str) -> int:
    field_off, _, fmt = PH_FIELDS[field_name]
    abs_off = e_phoff + seg_idx * e_phentsize + field_off
    return struct.unpack_from(fmt, data, abs_off)[0]


# ===== 결과 분류 =====
def classify(result: dict) -> str:
    """run_elf_inline 결과 dict → 분류 태그."""
    if result["timed_out"]:
        return "TIMEOUT"
    if result["error"]:
        # OSError 메시지가 execve/커널 거부 패턴이면 EXECVE_REJECT로 통합
        err_low = result["error"].lower()
        reject_patterns = (
            "exec format error", "errno 8",      # ENOEXEC (ELF 형식 자체 망가짐)
            "no such file", "errno 2",           # ENOENT (변형된 INTERP 경로 무효)
            "permission denied", "errno 13",     # EACCES
        )
        if any(p in err_low for p in reject_patterns):
            return "EXECVE_REJECT"
        return f"ERROR({result['error'][:30]})"
    ec = result["exit_code"]
    if ec == 0:
        return "OK"
    # subprocess.run 은 시그널로 죽으면 음수 반환코드(-signal)를 준다.
    # (B21) 예전 ec==139 분기는 128+시그널 셸 규약을 가정했지만 subprocess 는
    # 그 형태를 절대 만들지 않으므로 죽은 코드였다. -6/-7 은 여태 OTHER 로
    # 오분류되었다 → 실제 시그널로 정확히 매핑한다.
    if ec == -11:
        return "SIGSEGV"
    if ec == -6:
        return "SIGABRT"
    if ec == -7:
        return "SIGBUS"
    # execve 거부 패턴: stderr에 "cannot execute" / "Exec format error" 등
    stderr_low = result["stderr"].lower()
    if "exec format error" in stderr_low or "no such file" in stderr_low:
        return "EXECVE_REJECT"
    return f"OTHER({ec})"


def is_crash(tag: str) -> bool:
    """크래시 ELF 저장 여부 판단.

    SIGABRT/SIGBUS 는 이전에 OTHER(-6)/OTHER(-7) 로 분류되어 startswith('OTHER')
    로 저장되던 케이스다. B21 재분류 후에도 저장 동작이 동일하도록 명시 포함한다.
    """
    return tag in ("SIGSEGV", "SIGABRT", "SIGBUS", "TIMEOUT") or tag.startswith("OTHER")


# ===== 공유 변형 헬퍼 (순차/병렬 경로 공통) =====
def _mutate_single(original: bytes, e_phoff: int, e_phentsize: int,
                   seg_idx: int, field_name: str, existing_types: list):
    """모드 A 한 케이스: 단일 필드 변형.
    반환: (mutated_bytearray, original_value, new_value, mode)
    난수 소비 순서(mode → mutate_field)를 순차/병렬에서 동일하게 유지한다.
    """
    original_value = read_field(original, e_phoff, e_phentsize, seg_idx, field_name)
    mode = "near" if random.random() < 0.8 else "random"
    new_value = mutate_field(field_name, original_value, existing_types, mode)

    mutated = bytearray(original)
    apply_mutation(mutated, e_phoff, e_phentsize, seg_idx, field_name, new_value)
    return mutated, original_value, new_value, mode


def _mutate_combo(original: bytes, e_phoff: int, e_phentsize: int,
                  seg_idx: int, fields: list, existing_types: list):
    """모드 B 한 케이스: 여러 필드 동시 변형.
    반환: (mutated_bytearray, applied) — applied 는 [(field, new_value), ...]
    필드별 난수 소비 순서(mode → mutate_field)를 순차/병렬에서 동일하게 유지한다.
    """
    mutated = bytearray(original)
    applied = []
    for field_name in fields:
        mode = "near" if random.random() < 0.8 else "random"
        original_value = read_field(original, e_phoff, e_phentsize, seg_idx, field_name)
        new_value = mutate_field(field_name, original_value, existing_types, mode)
        apply_mutation(mutated, e_phoff, e_phentsize, seg_idx, field_name, new_value)
        applied.append((field_name, new_value))
    return mutated, applied


def _log_line(case_id: str, tag: str) -> str:
    """로그 한 줄 포맷 (순차 write_log 와 병렬 인라인 기록 공통)."""
    return f"{case_id} → {tag}\n"


# ===== 모드별 실행 =====
def run_mode_a(original: bytes, seg_idx: int, field_name: str, count: int,
               existing_types: list, e_phoff: int, e_phentsize: int):
    """모드 A: 단일 필드만 변형."""
    results = []

    for i in range(count):
        mutated, original_value, new_value, mode = _mutate_single(
            original, e_phoff, e_phentsize, seg_idx, field_name, existing_types)

        case_id = f"A_seg{seg_idx}_{field_name}_{i:04d}"
        result = run_elf_inline(bytes(mutated), case_id=case_id, timeout=5)
        tag = classify(result)

        results.append({
            "case_id": case_id,
            "field": field_name,
            "seg_idx": seg_idx,
            "original": original_value,
            "new_value": new_value,
            "mode": mode,
            "tag": tag,
            "exit_code": result["exit_code"],
        })

        if is_crash(tag):
            crash_path = CRASH_DIR / f"{case_id}.elf"
            crash_path.write_bytes(bytes(mutated))

    return results


# ===== 병렬 실행 (8워커) =====
# 워커 프로세스 글로벌 (initializer로 세팅)
_W = {}


def _init_worker(original_bytes: bytes, e_phoff: int, e_phnum: int,
                 e_phentsize: int, existing_types: list, out_dir_str: str,
                 base_seed: int = None):
    """Pool 워커 초기화 — 각 워커에 ELF 정보 세팅 + 워커별 난수 시드."""
    _W["original"] = original_bytes
    _W["e_phoff"] = e_phoff
    _W["e_phnum"] = e_phnum
    _W["e_phentsize"] = e_phentsize
    _W["existing_types"] = existing_types
    _W["out_dir"] = Path(out_dir_str)
    # 워커별 seed: PID^시간 으로 다양성 확보, --seed 가 주어지면 그 값을 베이스로 XOR.
    seed = os.getpid() ^ (int(time.time() * 1000) & 0xFFFFFFFF)
    if base_seed is not None:
        seed ^= base_seed
    random.seed(seed)


def _worker_run_case(task):
    """한 케이스 처리 — 변형 + 실행 + 분류."""
    case_id, seg_idx, field_name = task

    original = _W["original"]
    e_phoff = _W["e_phoff"]
    e_phentsize = _W["e_phentsize"]
    existing_types = _W["existing_types"]

    mutated, original_value, new_value, mode = _mutate_single(
        original, e_phoff, e_phentsize, seg_idx, field_name, existing_types)

    result = run_elf_inline(bytes(mutated), case_id=case_id, timeout=5)
    tag = classify(result)

    crash_data = bytes(mutated) if is_crash(tag) else None
    return {
        "case_id": case_id,
        "field": field_name,
        "seg_idx": seg_idx,
        "original": original_value,
        "new_value": new_value,
        "mode": mode,
        "tag": tag,
        "exit_code": result["exit_code"],
        "crash_data": crash_data,
    }


def _format_progress_line(done: int, total: int, start_time: float, counts: dict) -> str:
    elapsed = time.time() - start_time
    rate = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / rate if rate > 0 else 0
    elapsed_s = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
    eta_s = f"{int(eta//60):02d}:{int(eta%60):02d}"
    pct = 100 * done / total if total else 0
    # 분류별 개수 요약
    tag_summary = " ".join(
        f"{k}={v}" for k, v in sorted(counts.items(), key=lambda x: -x[1])[:5]
    )
    return (f"[{time.strftime('%H:%M:%S')}] "
            f"{done:>7,}/{total:,} ({pct:5.1f}%) | "
            f"elapsed {elapsed_s} | ETA {eta_s} | rate {rate:5.1f}/s | "
            f"{tag_summary}")


def run_mode_a_parallel(original: bytes, count: int, existing_types: list,
                         e_phoff: int, e_phnum: int, e_phentsize: int,
                         n_workers: int = 8, only_field: str = None,
                         only_seg: int = None, base_seed: int = None) -> list:
    """모드 A 병렬 실행. only_seg/only_field 둘 다 None이면 --all."""
    # 모든 (seg, field) × count 케이스 task 생성
    tasks = []
    seg_range = [only_seg] if only_seg is not None else range(e_phnum)
    field_iter = [only_field] if only_field else list(PH_FIELDS.keys())

    for seg_idx in seg_range:
        for field_name in field_iter:
            for i in range(count):
                case_id = f"A_seg{seg_idx}_{field_name}_{i:04d}"
                tasks.append((case_id, seg_idx, field_name))

    total = len(tasks)
    print(f"[+] 총 {total:,} 케이스 / {n_workers} 워커 병렬 시작", flush=True)

    results = []
    counts = {}
    start = time.time()
    last_progress = 0.0
    PROGRESS_INTERVAL = 2.0  # 2초마다 progress.txt 갱신
    progress_file = OUT_DIR / "progress.txt"

    log_fh = LOG_FILE.open("a")
    try:
        with mp.Pool(n_workers, initializer=_init_worker,
                     initargs=(original, e_phoff, e_phnum, e_phentsize,
                               existing_types, str(OUT_DIR), base_seed)) as pool:

            for i, r in enumerate(pool.imap_unordered(
                    _worker_run_case, tasks, chunksize=10), start=1):

                # 크래시면 master가 디스크 저장 (워커 race 방지)
                if r["crash_data"]:
                    crash_path = CRASH_DIR / f"{r['case_id']}.elf"
                    crash_path.write_bytes(r["crash_data"])
                    os.chmod(crash_path, 0o755)  # GDB 분석 위해 실행 권한 부여
                r["crash_data"] = None  # 메모리 해제

                # 로그 한 줄 추가
                log_fh.write(_log_line(r["case_id"], r["tag"]))

                # 분류 카운트
                counts[r["tag"]] = counts.get(r["tag"], 0) + 1

                # 메모리 절약: results에는 핵심 필드만 저장
                results.append({
                    "case_id": r["case_id"],
                    "field": r["field"],
                    "seg_idx": r["seg_idx"],
                    "tag": r["tag"],
                    "exit_code": r["exit_code"],
                })

                # 진행 상황 파일 업데이트
                now = time.time()
                if now - last_progress > PROGRESS_INTERVAL:
                    line = _format_progress_line(i, total, start, counts)
                    progress_file.write_text(line + "\n")
                    last_progress = now

        # 마지막 진행 상황 한 번 더
        line = _format_progress_line(total, total, start, counts)
        progress_file.write_text(line + " [DONE]\n")
        print("\n" + line, flush=True)
    finally:
        log_fh.close()

    return results


def _worker_run_case_b(task):
    """모드 B 워커 — 여러 필드 동시 변형."""
    case_id, fields, seg_idx = task

    original = _W["original"]
    e_phoff = _W["e_phoff"]
    e_phentsize = _W["e_phentsize"]
    existing_types = _W["existing_types"]

    mutated, applied = _mutate_combo(
        original, e_phoff, e_phentsize, seg_idx, fields, existing_types)

    result = run_elf_inline(bytes(mutated), case_id=case_id, timeout=5)
    tag = classify(result)
    crash_data = bytes(mutated) if is_crash(tag) else None
    return {
        "case_id": case_id,
        "fields": applied,
        "seg_idx": seg_idx,
        "tag": tag,
        "exit_code": result["exit_code"],
        "crash_data": crash_data,
    }


def run_mode_b_parallel(original: bytes, fields: list, count: int,
                         existing_types: list, e_phoff: int, e_phnum: int, e_phentsize: int,
                         n_workers: int = 8, base_seed: int = None) -> list:
    """모드 B 병렬 실행. 콤보 한 개에 대해 count 케이스 무작위 (seg, 값) 생성."""
    tasks = []
    for i in range(count):
        seg_idx = random.randint(0, e_phnum - 1)
        case_id = f"B_seg{seg_idx}_{'_'.join(fields)}_{i:04d}"
        tasks.append((case_id, fields, seg_idx))

    total = len(tasks)
    print(f"[+] 모드 B 콤보 {fields} × {count} / {n_workers} 워커", flush=True)

    results = []
    counts = {}
    start = time.time()
    last_p = 0.0
    progress_file = OUT_DIR / "progress.txt"

    log_fh = LOG_FILE.open("a")
    try:
        with mp.Pool(n_workers, initializer=_init_worker,
                     initargs=(original, e_phoff, e_phnum, e_phentsize,
                               existing_types, str(OUT_DIR), base_seed)) as pool:
            for i, r in enumerate(pool.imap_unordered(
                    _worker_run_case_b, tasks, chunksize=10), start=1):
                if r["crash_data"]:
                    crash_path = CRASH_DIR / f"{r['case_id']}.elf"
                    crash_path.write_bytes(r["crash_data"])
                    os.chmod(crash_path, 0o755)
                r["crash_data"] = None
                log_fh.write(_log_line(r["case_id"], r["tag"]))
                counts[r["tag"]] = counts.get(r["tag"], 0) + 1
                results.append({k: v for k, v in r.items() if k != "crash_data"})
                now = time.time()
                if now - last_p > 2.0:
                    progress_file.write_text(_format_progress_line(i, total, start, counts) + "\n")
                    last_p = now
        progress_file.write_text(_format_progress_line(total, total, start, counts) + " [DONE]\n")
        print("\n" + _format_progress_line(total, total, start, counts))
    finally:
        log_fh.close()
    return results


def run_mode_b(original: bytes, fields: list, count: int,
               existing_types: list, e_phoff: int, e_phnum: int, e_phentsize: int):
    """모드 B: 여러 필드 동시 변형."""
    results = []

    for i in range(count):
        seg_idx = random.randint(0, e_phnum - 1)
        mutated, applied = _mutate_combo(
            original, e_phoff, e_phentsize, seg_idx, fields, existing_types)

        case_id = f"B_seg{seg_idx}_{'_'.join(fields)}_{i:04d}"
        result = run_elf_inline(bytes(mutated), case_id=case_id, timeout=5)
        tag = classify(result)

        results.append({
            "case_id": case_id,
            "fields": applied,
            "seg_idx": seg_idx,
            "tag": tag,
            "exit_code": result["exit_code"],
        })

        if is_crash(tag):
            crash_path = CRASH_DIR / f"{case_id}.elf"
            crash_path.write_bytes(bytes(mutated))

    return results


# ===== 로그 =====
def write_log(results: list):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a") as f:
        for r in results:
            f.write(_log_line(r["case_id"], r["tag"]))


# ===== 메인 =====
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="prac.elf", help="원본 ELF")
    ap.add_argument("--mode", choices=["A", "B"], required=True)
    ap.add_argument("--field", help="모드 A: 변형할 필드 (예: p_offset)")
    ap.add_argument("--seg", type=int, help="모드 A: PHT 엔트리 인덱스")
    ap.add_argument("--combo", help="모드 B: 콤마 구분 필드 (예: p_vaddr,p_filesz)")
    ap.add_argument("--all", action="store_true", help="모드 A: 모든 (seg, field) 조합")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--outdir", default="0504_field_shuffle", help="결과 디렉토리 (병렬 실행시 분리)")
    ap.add_argument("--workers", type=int, default=1, help="병렬 워커 수 (1이면 순차, 8 권장)")
    ap.add_argument("--seed", type=int, default=None,
                    help="난수 시드. 지정 시 순차 경로는 완전 재현 가능, "
                         "병렬 경로는 이 값을 베이스로 워커별 pid^time 과 XOR")
    args = ap.parse_args()

    # 순차 경로 재현성: 시작 시점에 전역 시드 고정.
    # (병렬 경로는 각 워커 _init_worker 에서 base_seed 로 이 값을 반영한다.)
    if args.seed is not None:
        random.seed(args.seed)

    global OUT_DIR, CRASH_DIR, STRACE_DIR, LOG_FILE
    OUT_DIR = Path(args.outdir)
    CRASH_DIR = OUT_DIR / "crashes"
    STRACE_DIR = OUT_DIR / "strace_dump"
    LOG_FILE = OUT_DIR / "log_per_field.txt"

    OUT_DIR.mkdir(exist_ok=True)
    CRASH_DIR.mkdir(exist_ok=True)
    STRACE_DIR.mkdir(exist_ok=True)

    original = Path(args.input).read_bytes()
    e_phoff, e_phnum, e_phentsize = parse_elf_header(original)
    existing_types = get_existing_types(original, e_phoff, e_phnum, e_phentsize)

    print(f"[+] ELF 분석: PHT @ 0x{e_phoff:x}, {e_phnum}개 엔트리, 엔트리 크기 {e_phentsize}")
    print(f"[+] 존재하는 p_type: {[hex(t) for t in existing_types]}")

    all_results = []

    if args.mode == "A":
        if args.workers > 1:
            # 병렬 실행 (--all / 단일 조합 둘 다 처리)
            only_seg = args.seg if not args.all else None
            only_field = args.field if not args.all else None
            if not args.all:
                assert args.field and args.seg is not None, "--field와 --seg 필수 (또는 --all)"
            rs = run_mode_a_parallel(original, args.count, existing_types,
                                     e_phoff, e_phnum, e_phentsize,
                                     n_workers=args.workers,
                                     only_seg=only_seg, only_field=only_field,
                                     base_seed=args.seed)
            all_results.extend(rs)
        else:
            # 순차 실행 (디버깅/소규모용)
            if args.all:
                for seg in range(e_phnum):
                    for field in PH_FIELDS:
                        print(f"\n[*] 모드 A: seg{seg} {field} × {args.count}")
                        rs = run_mode_a(original, seg, field, args.count,
                                        existing_types, e_phoff, e_phentsize)
                        all_results.extend(rs)
                        write_log(rs)
            else:
                assert args.field and args.seg is not None, "--field와 --seg 필수"
                print(f"\n[*] 모드 A: seg{args.seg} {args.field} × {args.count}")
                rs = run_mode_a(original, args.seg, args.field, args.count,
                                existing_types, e_phoff, e_phentsize)
                all_results.extend(rs)
                write_log(rs)

    elif args.mode == "B":
        assert args.combo, "--combo 필수 (예: p_vaddr,p_filesz)"
        fields = [f.strip() for f in args.combo.split(",")]
        for f in fields:
            assert f in PH_FIELDS, f"알 수 없는 필드: {f}"
        print(f"\n[*] 모드 B: {fields} × {args.count}")
        if args.workers > 1:
            rs = run_mode_b_parallel(original, fields, args.count,
                                     existing_types, e_phoff, e_phnum, e_phentsize,
                                     n_workers=args.workers, base_seed=args.seed)
            all_results.extend(rs)
        else:
            rs = run_mode_b(original, fields, args.count,
                            existing_types, e_phoff, e_phnum, e_phentsize)
            all_results.extend(rs)
            write_log(rs)

    # 통계
    counts = {}
    for r in all_results:
        counts[r["tag"]] = counts.get(r["tag"], 0) + 1

    print(f"\n===== 결과 통계 =====")
    for tag, n in sorted(counts.items(), key=lambda x: -x[1]):
        pct = n / len(all_results) * 100
        print(f"  {tag:20s} {n:6d}  ({pct:.1f}%)")
    print(f"  총 {len(all_results)} 케이스")
    print(f"  크래시 ELF 저장: {CRASH_DIR}")
    print(f"  로그 파일: {LOG_FILE}")


if __name__ == "__main__":
    main()
