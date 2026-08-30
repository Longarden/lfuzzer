#!/usr/bin/env python3
"""
mutator_reloc_v1.py
===================
재배치(Elf64_Rela) 엔트리를 변형해 **ld.so(로더)** 의 재배치 처리 크래시를 찾는다.
mutator_field_v2.py(PHT)·mutator_dynamic_v3.py(.dynamic)와 같은 계열의 로더 타깃 뮤테이터.

설계 근거: docs/METADATA_EXPANSION_SPEC.md §3.4
  - 로더는 SHT 를 안 읽는다. 재배치 위치는 **DT_ 태그**로 잡는다(stripped .so 도 동작):
        DT_RELA(7)/DT_RELASZ(8)/DT_RELAENT(9)  = .rela.dyn 계열
        DT_JMPREL(23)/DT_PLTRELSZ(2)           = .rela.plt (PLT 재배치)
    → vaddr → file offset 변환(elf64.vaddr_to_offset) 후 24바이트 Elf64_Rela 순회.
  - 크래시 경로: elf_machine_rela / elf_machine_rela_relative — r_offset 오염 시
    "재배치 쓰기 주소" 가 야생 포인터가 됨(기존 RB05/RB12/RB18 버킷과 동일 사이트).
  - 타깃 = ld.so (변형 ELF 를 직접 실행). 판정 = 시그널 사망(subprocess 음수 returncode).

사용법:
    python3 mutator_reloc_v1.py --mode A --all --count 200 --workers 8
    python3 mutator_reloc_v1.py --mode A --field r_offset --count 500 --workers 8
    python3 mutator_reloc_v1.py --mode B --combo r_offset,r_info --count 500

WSL 경로 가정: ~/PE/Lfuzzer/  (원본 = prac.elf, 재배치가 있는 PIE/.so 권장)

⚠️ 상태: 작성 완료 / **미검증** — 이 세션 WSL 프로세스생성 오류로 실행 테스트 못 함.
   WSL 복구 후 `python3 mutator_reloc_v1.py --mode A --all --count 50 --workers 4` 스모크.
   self-contained (elf64 리더만 의존).
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


# ===== 재배치 관련 DT 태그 =====
DT_PLTRELSZ = 2
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_JMPREL = 23

RELA_ENTSIZE = 24  # Elf64_Rela

# Elf64_Rela 내부 오프셋 (엔트리 시작점 기준)
RELA_FIELDS = {
    "r_offset": (0x00, 8, "<Q"),
    "r_info":   (0x08, 8, "<Q"),
    "r_addend": (0x10, 8, "<Q"),
}

OUT_DIR = Path("0828_reloc")
CRASH_DIR = OUT_DIR / "crashes"
LOG_FILE = OUT_DIR / "log_per_field.txt"


# ===== 재배치 테이블 위치 찾기 (DT_ 기반, 로더 충실) =====
def find_rela_tables(data: bytes):
    """DT_RELA/DT_RELASZ 와 DT_JMPREL/DT_PLTRELSZ 로 재배치 배열의 (파일오프셋, 엔트리수)를 구한다.
    반환: [(file_off, n_entries, label), ...]. 없으면 빈 리스트."""
    dyn = {}
    for (_i, tag, val, _off) in elf64.iter_dynamic(data):
        dyn[tag] = val
    tables = []
    # .rela.dyn
    if DT_RELA in dyn and DT_RELASZ in dyn:
        foff = elf64.vaddr_to_offset(data, dyn[DT_RELA])
        if foff is not None and dyn[DT_RELASZ] >= RELA_ENTSIZE:
            tables.append((foff, dyn[DT_RELASZ] // RELA_ENTSIZE, "rela_dyn"))
    # .rela.plt (DT_JMPREL). PLT 재배치가 RELA 라는 가정(x86-64 기본).
    if DT_JMPREL in dyn and DT_PLTRELSZ in dyn:
        foff = elf64.vaddr_to_offset(data, dyn[DT_JMPREL])
        if foff is not None and dyn[DT_PLTRELSZ] >= RELA_ENTSIZE:
            tables.append((foff, dyn[DT_PLTRELSZ] // RELA_ENTSIZE, "rela_plt"))
    return tables


def enumerate_entries(data: bytes):
    """모든 재배치 엔트리의 절대 파일오프셋 목록. (entry_file_off, label, idx)."""
    out = []
    for (foff, n, label) in find_rela_tables(data):
        for i in range(n):
            out.append((foff + i * RELA_ENTSIZE, label, i))
    return out


# ===== 러너 (ld.so 실행) =====
def run_elf_inline(elf_bytes: bytes, case_id: str, timeout: int = 5) -> dict:
    tmp_path = f"./mutated_tmp_{os.getpid()}_{case_id}"
    try:
        with open(tmp_path, "wb") as f:
            f.write(elf_bytes)
        os.chmod(tmp_path, 0o755)
        try:
            result = subprocess.run([tmp_path], timeout=timeout,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            return {"exit_code": result.returncode,
                    "stderr": result.stderr[:200].decode(errors="replace").strip(),
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
        el = result["error"].lower()
        if any(p in el for p in ("exec format error", "errno 8", "no such file",
                                 "errno 2", "permission denied", "errno 13")):
            return "EXECVE_REJECT"
        return f"ERROR({result['error'][:30]})"
    ec = result["exit_code"]
    if ec == 0:
        return "OK"
    if ec == -11:
        return "SIGSEGV"
    if ec == -6:
        return "SIGABRT"
    if ec == -7:
        return "SIGBUS"
    if ec < 0:
        return f"SIG({-ec})"
    return f"OTHER({ec})"


def is_crash(tag: str) -> bool:
    return tag in ("SIGSEGV", "SIGABRT", "SIGBUS", "TIMEOUT") or tag.startswith("SIG(") or tag.startswith("OTHER")


# ===== 필드 변형 =====
def mutate_field(field_name: str, original_value: int, mode: str = "near") -> int:
    if field_name == "r_info":
        # r_info = (sym_index<<32) | type. 심볼 인덱스/타입 오염.
        if mode == "near":
            return original_value ^ (1 << random.randint(0, 40))
        return random.randint(0, 0xFFFFFFFFFFFFFFFF)
    # r_offset (재배치 대상 주소) / r_addend
    if mode == "near":
        delta = random.randint(-0x3000, 0x3000)
        return max(0, original_value + delta)
    if field_name == "r_offset":
        # 야생 쓰기 주소 유도
        return random.choice([random.randint(0, 0xFFFFFFFF), 0xFFFFFFFFFFFFFFFF, 0])
    return random.randint(0, 0xFFFFFFFFFFFFFFFF)


def read_field(data, entry_off, field_name):
    off, _, fmt = RELA_FIELDS[field_name]
    return struct.unpack_from(fmt, data, entry_off + off)[0]


def apply_mutation(data, entry_off, field_name, new_value):
    off, _, fmt = RELA_FIELDS[field_name]
    struct.pack_into(fmt, data, entry_off + off, new_value)


def _mutate_single(original, entry_off, field_name):
    ov = read_field(original, entry_off, field_name)
    mode = "near" if random.random() < 0.8 else "random"
    nv = mutate_field(field_name, ov, mode)
    mutated = bytearray(original)
    apply_mutation(mutated, entry_off, field_name, nv)
    return mutated, ov, nv, mode


def _mutate_combo(original, entry_off, fields):
    mutated = bytearray(original)
    applied = []
    for field_name in fields:
        mode = "near" if random.random() < 0.8 else "random"
        ov = read_field(original, entry_off, field_name)
        nv = mutate_field(field_name, ov, mode)
        apply_mutation(mutated, entry_off, field_name, nv)
        applied.append((field_name, nv))
    return mutated, applied


# ===== 병렬 워커 =====
_W = {}


def _init_worker(original_bytes, entries, out_dir_str, base_seed=None):
    _W["original"] = original_bytes
    _W["entries"] = entries
    _W["out_dir"] = Path(out_dir_str)
    seed = os.getpid() ^ (int(time.time() * 1000) & 0xFFFFFFFF)
    if base_seed is not None:
        seed ^= base_seed
    random.seed(seed)


def _worker_run_case(task):
    case_id, entry_off, field_name = task
    mutated, ov, nv, mode = _mutate_single(_W["original"], entry_off, field_name)
    result = run_elf_inline(bytes(mutated), case_id, timeout=5)
    tag = classify(result)
    return {"case_id": case_id, "field": field_name, "entry_off": entry_off,
            "original": ov, "new_value": nv, "mode": mode, "tag": tag,
            "exit_code": result["exit_code"],
            "crash_data": bytes(mutated) if is_crash(tag) else None}


def _fmt_progress(done, total, start, counts):
    elapsed = time.time() - start
    rate = done / elapsed if elapsed > 0 else 0
    pct = 100 * done / total if total else 0
    summ = " ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda x: -x[1])[:5])
    return f"[{time.strftime('%H:%M:%S')}] {done:>7,}/{total:,} ({pct:5.1f}%) | rate {rate:5.1f}/s | {summ}"


def run_mode_a_parallel(original, entries, count, n_workers=8, only_field=None, base_seed=None):
    field_iter = [only_field] if only_field else list(RELA_FIELDS.keys())
    tasks = []
    for (entry_off, label, idx) in entries:
        for field_name in field_iter:
            for i in range(count):
                tasks.append((f"A_{label}{idx}_{field_name}_{i:04d}", entry_off, field_name))
    total = len(tasks)
    print(f"[+] RELA 모드 A: 재배치엔트리 {len(entries)}개 × 필드 {len(field_iter)} × {count} = {total:,} 케이스 / {n_workers} 워커", flush=True)

    results, counts, start, last = [], {}, time.time(), 0.0
    progress_file = OUT_DIR / "progress.txt"
    log_fh = LOG_FILE.open("a")
    try:
        with mp.Pool(n_workers, initializer=_init_worker,
                     initargs=(original, entries, str(OUT_DIR), base_seed)) as pool:
            for i, r in enumerate(pool.imap_unordered(_worker_run_case, tasks, chunksize=10), start=1):
                if r["crash_data"]:
                    (CRASH_DIR / f"{r['case_id']}.elf").write_bytes(r["crash_data"])
                    os.chmod(CRASH_DIR / f"{r['case_id']}.elf", 0o755)
                    r["crash_data"] = None
                log_fh.write(f"{r['case_id']} → {r['tag']}\n")
                counts[r["tag"]] = counts.get(r["tag"], 0) + 1
                results.append({k: r[k] for k in ("case_id", "field", "entry_off", "tag", "exit_code")})
                now = time.time()
                if now - last > 2.0:
                    progress_file.write_text(_fmt_progress(i, total, start, counts) + "\n")
                    last = now
        progress_file.write_text(_fmt_progress(total, total, start, counts) + " [DONE]\n")
        print("\n" + _fmt_progress(total, total, start, counts), flush=True)
    finally:
        log_fh.close()
    return results


def run_mode_a_seq(original, entries, count, only_field=None):
    field_iter = [only_field] if only_field else list(RELA_FIELDS.keys())
    results = []
    for (entry_off, label, idx) in entries:
        for field_name in field_iter:
            for i in range(count):
                case_id = f"A_{label}{idx}_{field_name}_{i:04d}"
                mutated, ov, nv, mode = _mutate_single(original, entry_off, field_name)
                result = run_elf_inline(bytes(mutated), case_id, timeout=5)
                tag = classify(result)
                results.append({"case_id": case_id, "field": field_name,
                                "entry_off": entry_off, "tag": tag, "exit_code": result["exit_code"]})
                if is_crash(tag):
                    p = CRASH_DIR / f"{case_id}.elf"
                    p.write_bytes(bytes(mutated))
                    os.chmod(p, 0o755)
    return results


def run_mode_b_seq(original, entries, fields, count):
    results = []
    for i in range(count):
        entry_off, label, idx = random.choice(entries)
        case_id = f"B_{label}{idx}_{'_'.join(fields)}_{i:04d}"
        mutated, applied = _mutate_combo(original, entry_off, fields)
        result = run_elf_inline(bytes(mutated), case_id, timeout=5)
        tag = classify(result)
        results.append({"case_id": case_id, "fields": applied, "tag": tag, "exit_code": result["exit_code"]})
        if is_crash(tag):
            p = CRASH_DIR / f"{case_id}.elf"
            p.write_bytes(bytes(mutated))
            os.chmod(p, 0o755)
    return results


def main():
    global OUT_DIR, CRASH_DIR, LOG_FILE
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="prac.elf")
    ap.add_argument("--mode", choices=["A", "B"], required=True)
    ap.add_argument("--field", help="모드 A: r_offset|r_info|r_addend")
    ap.add_argument("--combo", help="모드 B: 콤마구분 (예: r_offset,r_info)")
    ap.add_argument("--all", action="store_true", help="모드 A: 모든 (엔트리, 필드)")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--outdir", default="0828_reloc")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    OUT_DIR = Path(args.outdir)
    CRASH_DIR = OUT_DIR / "crashes"
    LOG_FILE = OUT_DIR / "log_per_field.txt"
    OUT_DIR.mkdir(exist_ok=True)
    CRASH_DIR.mkdir(exist_ok=True)

    original = Path(args.input).read_bytes()
    entries = enumerate_entries(original)
    if not entries:
        raise SystemExit("[!] DT_RELA/DT_JMPREL 재배치 테이블을 못 찾음. "
                         "재배치가 있는 PIE 실행파일이나 .so 를 --input 으로 줄 것.")
    print(f"[+] 재배치 엔트리 {len(entries)}개 발견 (DT_RELA/DT_JMPREL 기반)")

    if args.mode == "A":
        only_field = None if args.all else args.field
        if not args.all:
            assert args.field, "--field 필수 (또는 --all)"
        if args.workers > 1:
            res = run_mode_a_parallel(original, entries, args.count,
                                      n_workers=args.workers, only_field=only_field, base_seed=args.seed)
        else:
            res = run_mode_a_seq(original, entries, args.count, only_field=only_field)
    else:
        assert args.combo, "--combo 필수"
        fields = [f.strip() for f in args.combo.split(",")]
        for f in fields:
            assert f in RELA_FIELDS, f"알 수 없는 RELA 필드: {f}"
        res = run_mode_b_seq(original, entries, fields, args.count)

    counts = {}
    for r in res:
        counts[r["tag"]] = counts.get(r["tag"], 0) + 1
    print("\n===== 결과 통계 =====")
    for tag, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {tag:20s} {n:6d}  ({n/len(res)*100:.1f}%)")
    print(f"  총 {len(res)} 케이스 · 크래시 저장: {CRASH_DIR}")


if __name__ == "__main__":
    main()
