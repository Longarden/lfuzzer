#!/usr/bin/env python3
"""
mutator_section_v1.py
=====================
섹션 헤더 테이블(SHT) 엔트리의 필드를 변형해 **정적 파서(readelf/objdump)** 의
크래시를 찾는다. mutator_field_v2.py(PHT/ld.so)의 SHT 판(版).

설계 근거: docs/METADATA_EXPANSION_SPEC.md §3.1
  - PHT 뮤테이션은 로더(ld.so)를 터뜨리지만, SHT 는 로더가 거의 안 읽는다.
    SHT 오염은 readelf/objdump 의 "길이·오프셋·인덱스 산술"을 터뜨린다.
  - 따라서 러너를 --target 으로 파라미터화한다: readelf(기본) / objdump / exec(ld.so).
  - 크래시 판정 = 시그널사망(음수 returncode) + 타임아웃.
    readelf 의 exit 1(포맷 거부)은 정상적 우아한 에러이므로 저장하지 않는다.

사용법:
    python3 mutator_section_v1.py --mode A --all --count 200 --workers 8
    python3 mutator_section_v1.py --mode A --field sh_entsize --sec 5 --count 100
    python3 mutator_section_v1.py --mode B --combo sh_offset,sh_size --count 500
    python3 mutator_section_v1.py --target objdump --mode A --all --count 200

WSL 경로 가정: ~/PE/Lfuzzer/  (원본 ELF = prac.elf)

⚠️ 상태: 작성 완료 / **미검증** — 이 세션에서 WSL 프로세스생성 오류로 실행 테스트 못 함.
   WSL 복구 후 `python3 mutator_section_v1.py --mode A --all --count 50 --workers 4` 로
   스모크 검증할 것. self-contained (elf64 리더만 의존).
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


# ===== ELF64 SHT 상수 (근거: core/elf64.py:36-46) =====
E_SHOFF_OFFSET = 0x28      # u64  섹션헤더 테이블 파일오프셋
E_SHENTSIZE_OFFSET = 0x3A  # u16  섹션헤더 엔트리 stride
E_SHNUM_OFFSET = 0x3C      # u16  섹션헤더 엔트리 수
E_SHSTRNDX_OFFSET = 0x3E   # u16  .shstrtab 섹션 인덱스

# Section Header Entry(Elf64_Shdr) 내부 오프셋 (엔트리 시작점 기준)
SH_FIELDS = {
    "sh_name":      (0x00, 4, "<I"),
    "sh_type":      (0x04, 4, "<I"),
    "sh_flags":     (0x08, 8, "<Q"),
    "sh_addr":      (0x10, 8, "<Q"),
    "sh_offset":    (0x18, 8, "<Q"),
    "sh_size":      (0x20, 8, "<Q"),
    "sh_link":      (0x28, 4, "<I"),
    "sh_info":      (0x2C, 4, "<I"),
    "sh_addralign": (0x30, 8, "<Q"),
    "sh_entsize":   (0x38, 8, "<Q"),
}

# 결과 디렉토리 (--outdir 로 덮어씀)
OUT_DIR = Path("0828_section")
CRASH_DIR = OUT_DIR / "crashes"
LOG_FILE = OUT_DIR / "log_per_field.txt"

# 러너 타깃 (main 에서 --target 으로 설정). 워커에도 전달된다.
TARGET = "readelf"


# ===== ELF 파싱 =====
def parse_elf_sht(data: bytes):
    """ELF 헤더에서 SHT 정보 추출 (공유 elf64 리더 사용)."""
    if data[:4] != b"\x7fELF":
        raise ValueError("ELF magic 불일치")
    if data[4] != 2:
        raise ValueError("64-bit ELF 아님")
    e_shoff = elf64.u64(data, E_SHOFF_OFFSET)
    e_shentsize = elf64.u16(data, E_SHENTSIZE_OFFSET)
    e_shnum = elf64.u16(data, E_SHNUM_OFFSET)
    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("섹션 헤더 테이블 없음 (e_shoff/e_shnum == 0)")
    return e_shoff, e_shnum, e_shentsize


# ===== 러너 (타깃별) =====
def _target_argv(target: str, path: str):
    if target == "readelf":
        return ["readelf", "-a", "-W", path]
    if target == "objdump":
        return ["objdump", "-x", path]
    if target == "exec":
        return [path]          # ld.so 로 실행 (PHT 처럼 로더 크래시)
    raise ValueError(f"알 수 없는 target: {target}")


def run_case_inline(elf_bytes: bytes, case_id: str, target: str, timeout: int = 5) -> dict:
    """변형 ELF 를 임시파일로 저장 후 target(readelf/objdump/exec)에 투입.
    return: {exit_code, stderr, timed_out, error}. exit_code 는 subprocess 규약(시그널=-signal)."""
    tmp_path = f"./mutated_tmp_{os.getpid()}_{case_id}"
    try:
        with open(tmp_path, "wb") as f:
            f.write(elf_bytes)
        os.chmod(tmp_path, 0o755)
        try:
            result = subprocess.run(
                _target_argv(target, tmp_path),
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


# ===== 결과 분류 =====
def classify(result: dict) -> str:
    if result["timed_out"]:
        return "TIMEOUT"
    if result["error"]:
        return f"ERROR({result['error'][:30]})"
    ec = result["exit_code"]
    if ec == 0:
        return "OK"
    # subprocess 규약: 시그널 사망은 음수(-signal).
    if ec == -11:
        return "SIGSEGV"
    if ec == -6:
        return "SIGABRT"     # ASAN abort 포함
    if ec == -7:
        return "SIGBUS"
    if ec == -8:
        return "SIGFPE"      # sh_entsize=0 등 0나눗셈
    if ec < 0:
        return f"SIG({-ec})"
    # 양수 nonzero = readelf/objdump 의 우아한 포맷거부 → 크래시 아님.
    return f"REJECT({ec})"


def is_crash(tag: str) -> bool:
    """정적 파서 크래시 판정: 시그널 사망 + 타임아웃(무한루프)만.
    REJECT(양수 exit)은 정상적 에러 처리이므로 저장하지 않는다(노이즈 방지)."""
    return tag in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "TIMEOUT") or tag.startswith("SIG(")


# ===== 필드별 변형 =====
def mutate_field(field_name: str, original_value: int, e_shnum: int, mode: str = "near") -> int:
    """SHT 한 필드 변형값. 정적 파서의 길이·오프셋·인덱스 산술을 겨냥한다."""
    if field_name == "sh_entsize":
        # 0 → size/entsize 나눗셈·무한, 또는 거대값
        return random.choice([0, 1, 0xFFFF, 0xFFFFFFFF]) if mode != "near" else \
            (0 if random.random() < 0.5 else original_value * 2)
    if field_name == "sh_link":
        # 유효 인덱스 밖 (없는 섹션 가리키기)
        return random.choice([0, e_shnum, e_shnum + 1, 0xFFFF, 0xFFFFFFFF])
    if field_name == "sh_info":
        return random.randint(0, 0xFFFFFFFF)
    if field_name == "sh_type":
        return random.choice([0, 1, 2, 3, 6, 11, 0x6fffffff, random.randint(0, 0xFFFFFFFF)])
    if field_name == "sh_flags":
        if mode == "near":
            return original_value ^ (1 << random.randint(0, 11))
        return random.randint(0, 0xFFFFFFFF)
    if field_name == "sh_addralign":
        return random.choice([0, 1, 3, 0x1000, 0xFFFFFFFF])
    # sh_name / sh_offset / sh_size / sh_addr : 오프셋·크기 계열
    if mode == "near":
        delta = random.randint(-0x3000, 0x3000)
        return max(0, original_value + delta)
    if field_name in ("sh_offset", "sh_size"):
        # 파일 경계 밖으로 밀기 (OOB read 유도)
        return random.choice([random.randint(0, 0xFFFFFFFF), 0xFFFFFFFFFFFFFFFF])
    return random.randint(0, 0xFFFFFFFFFFFFFFFF)


def read_field(data: bytes, e_shoff: int, e_shentsize: int, sec_idx: int, field_name: str) -> int:
    off, _, fmt = SH_FIELDS[field_name]
    abs_off = e_shoff + sec_idx * e_shentsize + off
    return struct.unpack_from(fmt, data, abs_off)[0]


def apply_mutation(data: bytearray, e_shoff: int, e_shentsize: int,
                   sec_idx: int, field_name: str, new_value: int):
    off, _, fmt = SH_FIELDS[field_name]
    abs_off = e_shoff + sec_idx * e_shentsize + off
    struct.pack_into(fmt, data, abs_off, new_value)


def _mutate_single(original: bytes, e_shoff: int, e_shentsize: int, e_shnum: int,
                   sec_idx: int, field_name: str):
    original_value = read_field(original, e_shoff, e_shentsize, sec_idx, field_name)
    mode = "near" if random.random() < 0.8 else "random"
    new_value = mutate_field(field_name, original_value, e_shnum, mode)
    mutated = bytearray(original)
    apply_mutation(mutated, e_shoff, e_shentsize, sec_idx, field_name, new_value)
    return mutated, original_value, new_value, mode


def _mutate_combo(original: bytes, e_shoff: int, e_shentsize: int, e_shnum: int,
                  sec_idx: int, fields: list):
    mutated = bytearray(original)
    applied = []
    for field_name in fields:
        mode = "near" if random.random() < 0.8 else "random"
        ov = read_field(original, e_shoff, e_shentsize, sec_idx, field_name)
        nv = mutate_field(field_name, ov, e_shnum, mode)
        apply_mutation(mutated, e_shoff, e_shentsize, sec_idx, field_name, nv)
        applied.append((field_name, nv))
    return mutated, applied


# ===== 병렬 워커 =====
_W = {}


def _init_worker(original_bytes, e_shoff, e_shnum, e_shentsize, out_dir_str, target, base_seed=None):
    _W["original"] = original_bytes
    _W["e_shoff"] = e_shoff
    _W["e_shnum"] = e_shnum
    _W["e_shentsize"] = e_shentsize
    _W["out_dir"] = Path(out_dir_str)
    _W["target"] = target
    seed = os.getpid() ^ (int(time.time() * 1000) & 0xFFFFFFFF)
    if base_seed is not None:
        seed ^= base_seed
    random.seed(seed)


def _worker_run_case(task):
    case_id, sec_idx, field_name = task
    mutated, ov, nv, mode = _mutate_single(
        _W["original"], _W["e_shoff"], _W["e_shentsize"], _W["e_shnum"], sec_idx, field_name)
    result = run_case_inline(bytes(mutated), case_id, _W["target"], timeout=5)
    tag = classify(result)
    return {
        "case_id": case_id, "field": field_name, "sec_idx": sec_idx,
        "original": ov, "new_value": nv, "mode": mode, "tag": tag,
        "exit_code": result["exit_code"],
        "crash_data": bytes(mutated) if is_crash(tag) else None,
    }


def _fmt_progress(done, total, start, counts):
    elapsed = time.time() - start
    rate = done / elapsed if elapsed > 0 else 0
    pct = 100 * done / total if total else 0
    summ = " ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda x: -x[1])[:5])
    return f"[{time.strftime('%H:%M:%S')}] {done:>7,}/{total:,} ({pct:5.1f}%) | rate {rate:5.1f}/s | {summ}"


def run_mode_a_parallel(original, count, e_shoff, e_shnum, e_shentsize, target,
                        n_workers=8, only_field=None, only_sec=None, base_seed=None):
    tasks = []
    sec_range = [only_sec] if only_sec is not None else range(e_shnum)
    field_iter = [only_field] if only_field else list(SH_FIELDS.keys())
    for sec_idx in sec_range:
        for field_name in field_iter:
            for i in range(count):
                tasks.append((f"A_sec{sec_idx}_{field_name}_{i:04d}", sec_idx, field_name))
    total = len(tasks)
    print(f"[+] SHT 모드 A: 총 {total:,} 케이스 / {n_workers} 워커 / target={target}", flush=True)

    results, counts, start, last = [], {}, time.time(), 0.0
    progress_file = OUT_DIR / "progress.txt"
    log_fh = LOG_FILE.open("a")
    try:
        with mp.Pool(n_workers, initializer=_init_worker,
                     initargs=(original, e_shoff, e_shnum, e_shentsize, str(OUT_DIR), target, base_seed)) as pool:
            for i, r in enumerate(pool.imap_unordered(_worker_run_case, tasks, chunksize=10), start=1):
                if r["crash_data"]:
                    (CRASH_DIR / f"{r['case_id']}.elf").write_bytes(r["crash_data"])
                    r["crash_data"] = None
                log_fh.write(f"{r['case_id']} → {r['tag']}\n")
                counts[r["tag"]] = counts.get(r["tag"], 0) + 1
                results.append({k: r[k] for k in ("case_id", "field", "sec_idx", "tag", "exit_code")})
                now = time.time()
                if now - last > 2.0:
                    progress_file.write_text(_fmt_progress(i, total, start, counts) + "\n")
                    last = now
        progress_file.write_text(_fmt_progress(total, total, start, counts) + " [DONE]\n")
        print("\n" + _fmt_progress(total, total, start, counts), flush=True)
    finally:
        log_fh.close()
    return results


def run_mode_a_seq(original, count, e_shoff, e_shnum, e_shentsize, target,
                   only_field=None, only_sec=None):
    results = []
    sec_range = [only_sec] if only_sec is not None else range(e_shnum)
    field_iter = [only_field] if only_field else list(SH_FIELDS.keys())
    for sec_idx in sec_range:
        for field_name in field_iter:
            for i in range(count):
                case_id = f"A_sec{sec_idx}_{field_name}_{i:04d}"
                mutated, ov, nv, mode = _mutate_single(
                    original, e_shoff, e_shentsize, e_shnum, sec_idx, field_name)
                result = run_case_inline(bytes(mutated), case_id, target, timeout=5)
                tag = classify(result)
                results.append({"case_id": case_id, "field": field_name,
                                "sec_idx": sec_idx, "tag": tag, "exit_code": result["exit_code"]})
                if is_crash(tag):
                    (CRASH_DIR / f"{case_id}.elf").write_bytes(bytes(mutated))
    return results


def run_mode_b_seq(original, fields, count, e_shoff, e_shnum, e_shentsize, target):
    results = []
    for i in range(count):
        sec_idx = random.randint(0, e_shnum - 1)
        case_id = f"B_sec{sec_idx}_{'_'.join(fields)}_{i:04d}"
        mutated, applied = _mutate_combo(original, e_shoff, e_shentsize, e_shnum, sec_idx, fields)
        result = run_case_inline(bytes(mutated), case_id, target, timeout=5)
        tag = classify(result)
        results.append({"case_id": case_id, "fields": applied, "sec_idx": sec_idx,
                        "tag": tag, "exit_code": result["exit_code"]})
        if is_crash(tag):
            (CRASH_DIR / f"{case_id}.elf").write_bytes(bytes(mutated))
    return results


# ===== 메인 =====
def main():
    global OUT_DIR, CRASH_DIR, LOG_FILE, TARGET
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="prac.elf")
    ap.add_argument("--mode", choices=["A", "B"], required=True)
    ap.add_argument("--field", help="모드 A: 변형할 SHT 필드 (예: sh_entsize)")
    ap.add_argument("--sec", type=int, help="모드 A: 섹션 인덱스")
    ap.add_argument("--combo", help="모드 B: 콤마구분 필드 (예: sh_offset,sh_size)")
    ap.add_argument("--all", action="store_true", help="모드 A: 모든 (sec, field) 조합")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--outdir", default="0828_section")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--target", choices=["readelf", "objdump", "exec"], default="readelf",
                    help="크래시 대상: readelf(기본)/objdump/exec(ld.so)")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    TARGET = args.target
    OUT_DIR = Path(args.outdir)
    CRASH_DIR = OUT_DIR / "crashes"
    LOG_FILE = OUT_DIR / "log_per_field.txt"
    OUT_DIR.mkdir(exist_ok=True)
    CRASH_DIR.mkdir(exist_ok=True)

    original = Path(args.input).read_bytes()
    e_shoff, e_shnum, e_shentsize = parse_elf_sht(original)
    print(f"[+] SHT @ 0x{e_shoff:x}, {e_shnum}개 섹션, 엔트리 크기 {e_shentsize}, target={TARGET}")

    all_results = []
    if args.mode == "A":
        only_sec = None if args.all else args.sec
        only_field = None if args.all else args.field
        if not args.all:
            assert args.field and args.sec is not None, "--field 와 --sec 필수 (또는 --all)"
        if args.workers > 1:
            all_results = run_mode_a_parallel(original, args.count, e_shoff, e_shnum, e_shentsize,
                                              TARGET, n_workers=args.workers,
                                              only_field=only_field, only_sec=only_sec, base_seed=args.seed)
        else:
            all_results = run_mode_a_seq(original, args.count, e_shoff, e_shnum, e_shentsize,
                                         TARGET, only_field=only_field, only_sec=only_sec)
    else:
        assert args.combo, "--combo 필수 (예: sh_offset,sh_size)"
        fields = [f.strip() for f in args.combo.split(",")]
        for f in fields:
            assert f in SH_FIELDS, f"알 수 없는 SHT 필드: {f}"
        all_results = run_mode_b_seq(original, fields, args.count, e_shoff, e_shnum, e_shentsize, TARGET)

    counts = {}
    for r in all_results:
        counts[r["tag"]] = counts.get(r["tag"], 0) + 1
    print("\n===== 결과 통계 =====")
    for tag, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {tag:20s} {n:6d}  ({n/len(all_results)*100:.1f}%)")
    print(f"  총 {len(all_results)} 케이스 · 크래시 저장: {CRASH_DIR}")


if __name__ == "__main__":
    main()
