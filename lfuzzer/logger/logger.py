#!/usr/bin/env python3
"""
logger.py — Melkor logger.c 대응. 변형 이력 기록 시설.

Melkor의 logger.c는 어떤 메타데이터가 어떤 규칙(rule)으로 퍼징됐는지를 로그로
남긴다 -> 크래시가 났을 때 '무엇을 건드려서 터졌나'를 역추적한다. 이 모듈이 그
역할이며, mutator_field_v2 / mutator_dynamic_v3 가 지금 흩어서 찍는 로그
(log_per_field.txt, OUTDIR 크래시 파일명)를 하나의 구조화된 기록으로 모은다.

기록 단위(한 뮤테이션) 필드:
    region     건드린 영역   : "PHDR" | "SHDR" | "DYNAMIC"
    field      메타데이터 필드 : "p_offset", "sh_name", "DT_STRTAB", "vna_name" ...
    rule       규칙 이름       : Melkor fuzz_<metadata>.c 의 rule 명 (예: "vna_name_oob")
    offset     쓴 파일 오프셋  : 절대 오프셋 (elf64 entry_offset+필드오프셋)
    old -> new 옛값/새값        : 정수 또는 bytes
    likelihood 적용 확률        : 이 규칙이 발동한 -l 확률 (기본 0.10, 공격적 0.70)
    seg_idx    (선택) PHT/SHT 인덱스
    case_id    (선택) 실행 케이스 식별자 (뮤테이터의 case_id 와 연결)
    verdict    (선택) 실행 결과 태그 ("SIGSEGV"/"TIMEOUT"/"OK"...) — 나중에 채움

출력:
    <REPORT_DIR>/<run_id>.jsonl   한 줄 = 한 뮤테이션 (스트리밍, flush 시 append)
    <REPORT_DIR>/<run_id>.json    런 요약(메타 + 집계 + 전체 뮤테이션 배열)
    <REPORT_DIR>/<run_id>.txt     사람이 읽는 리포트

stdlib 전용 (json, os, time, datetime). 크래시 안전: log_mutation 은 메모리에
쌓고, flush() 에서 디스크로 내린다. jsonl 은 append 라 중간에 죽어도 남는다.
"""

import json
import os
import time
from collections import Counter
from datetime import datetime


# 기본 리포트 디렉토리 (mutator 들의 OUTDIR 관례와 맞춤; 호출측이 덮어씀)
DEFAULT_REPORT_DIR = os.path.expanduser("~/PE/Lfuzzer/fuzz_reports")

# 결과 태그 중 '크래시로 간주' (mutator_field_v2.is_crash 와 동일 정신)
CRASH_VERDICTS = frozenset({"SIGSEGV", "SIGABRT", "SIGBUS", "TIMEOUT", "timeout"})


def _jsonable(v):
    """old/new 값이 bytes 일 수 있으므로 json 직렬화용으로 정규화.

    - int  -> {"int": v, "hex": "0x.."}  (16진 병기로 사람이 읽기 쉽게)
    - bytes-> {"bytes_hex": "..", "repr": ".."}
    - 그 외-> str(v)
    """
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return {"int": v, "hex": hex(v & 0xFFFFFFFFFFFFFFFF) if v >= 0 else hex(v)}
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        return {"bytes_hex": b.hex(), "repr": repr(b)}
    if v is None:
        return None
    return str(v)


def _fmt_val(v):
    """사람이 읽는 txt 리포트용 값 포맷."""
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, int):
        return f"0x{v & 0xFFFFFFFFFFFFFFFF:x}" if v >= 0 else str(v)
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        return b.hex() if len(b) <= 16 else b[:16].hex() + f"...(+{len(b) - 16}B)"
    return repr(v)


class Mutation:
    """한 번의 변형 기록. FuzzLogger.log_mutation 이 생성해 쌓는다."""

    __slots__ = ("seq", "ts", "region", "field", "rule", "offset",
                 "old", "new", "likelihood", "seg_idx", "case_id", "verdict")

    def __init__(self, seq, region, field, rule, offset, old, new,
                 likelihood, seg_idx=None, case_id=None, verdict=None):
        self.seq = seq
        self.ts = time.time()
        self.region = region
        self.field = field
        self.rule = rule
        self.offset = offset
        self.old = old
        self.new = new
        self.likelihood = likelihood
        self.seg_idx = seg_idx
        self.case_id = case_id
        self.verdict = verdict

    def to_dict(self):
        return {
            "seq": self.seq,
            "ts": self.ts,
            "region": self.region,
            "field": self.field,
            "rule": self.rule,
            "offset": self.offset,
            "offset_hex": hex(self.offset) if isinstance(self.offset, int) else None,
            "old": _jsonable(self.old),
            "new": _jsonable(self.new),
            "likelihood": self.likelihood,
            "seg_idx": self.seg_idx,
            "case_id": self.case_id,
            "verdict": self.verdict,
        }

    def to_line(self):
        """사람이 읽는 한 줄. mutator 로그의 '무엇->결과' 화살표 관례 유지."""
        off = f"@0x{self.offset:x}" if isinstance(self.offset, int) else "@?"
        seg = f" seg{self.seg_idx}" if self.seg_idx is not None else ""
        verd = f"  => {self.verdict}" if self.verdict else ""
        return (f"#{self.seq:05d} [{self.region}]{seg} {self.field} "
                f"({self.rule}, l={self.likelihood:.2f}) {off}  "
                f"{_fmt_val(self.old)} -> {_fmt_val(self.new)}{verd}")


class FuzzLogger:
    """런당 변형 이력 로거 (Melkor logger.c).

    사용:
        log = FuzzLogger(report_dir="out/run1", run_id="phdr_sprint",
                         base_file="prac.elf", likelihood=0.10)
        log.log_mutation(region="PHDR", field="p_offset", rule="offset_oob",
                         offset=0x88, old=0x1000, new=0xffffffff,
                         seg_idx=2, case_id="A_seg2_p_offset_0003")
        ...
        log.set_verdict("A_seg2_p_offset_0003", "SIGSEGV")   # 실행 후 결과 연결
        log.flush()   # jsonl + json + txt 기록

    크래시 안전성: log_mutation 은 메모리 리스트에 쌓고, jsonl 로도 즉시 append
    (stream=True 기본) 하므로 중간에 프로세스가 죽어도 jsonl 은 남는다.
    """

    def __init__(self, report_dir=None, run_id=None, base_file=None,
                 likelihood=0.10, target=None, stream=True):
        self.report_dir = report_dir or DEFAULT_REPORT_DIR
        os.makedirs(self.report_dir, exist_ok=True)
        # run_id 미지정 -> 타임스탬프. 리포트 파일명 접두사가 된다.
        self.run_id = run_id or datetime.now().strftime("run_%Y%m%d_%H%M%S")
        self.base_file = base_file          # 원본 ELF 경로 (재현용 메타)
        self.default_likelihood = likelihood  # -l 기본 확률 (Melkor: 0.10)
        self.target = target                # 실행 타깃 (예: ld.so 경로)
        self.stream = stream

        self.mutations = []
        self._seq = 0
        self._started = time.time()
        # case_id -> Mutation (실행 결과를 나중에 연결하기 위한 인덱스)
        self._by_case = {}

        self.jsonl_path = os.path.join(self.report_dir, self.run_id + ".jsonl")
        self.json_path = os.path.join(self.report_dir, self.run_id + ".json")
        self.txt_path = os.path.join(self.report_dir, self.run_id + ".txt")

        if self.stream:
            # 새 런 -> jsonl 헤더 한 줄 (append 모드지만 런 시작을 표시)
            self._jsonl_fh = open(self.jsonl_path, "a", encoding="utf-8")
            self._jsonl_fh.write(json.dumps({
                "_meta": True,
                "run_id": self.run_id,
                "started": self._started,
                "base_file": self.base_file,
                "target": self.target,
                "default_likelihood": self.default_likelihood,
            }, ensure_ascii=False) + "\n")
            self._jsonl_fh.flush()
        else:
            self._jsonl_fh = None

    def log_mutation(self, region, field, rule, offset, old, new,
                     likelihood=None, seg_idx=None, case_id=None, verdict=None):
        """한 번의 변형을 기록. old/new 는 int 또는 bytes 모두 허용.

        likelihood 미지정 -> 생성자 기본값(default_likelihood) 사용.
        Melkor 원칙: critical 필드일수록 규칙 내부에서 likelihood 를 낮춰 넘기면
        그 값이 그대로 기록돼 '얼마나 조심스럽게 건드렸나'가 리포트에 남는다.
        """
        self._seq += 1
        m = Mutation(
            seq=self._seq,
            region=region,
            field=field,
            rule=rule,
            offset=offset,
            old=old,
            new=new,
            likelihood=self.default_likelihood if likelihood is None else likelihood,
            seg_idx=seg_idx,
            case_id=case_id,
            verdict=verdict,
        )
        self.mutations.append(m)
        if case_id is not None:
            self._by_case[case_id] = m
        if self._jsonl_fh is not None:
            self._jsonl_fh.write(json.dumps(m.to_dict(), ensure_ascii=False) + "\n")
            self._jsonl_fh.flush()
        return m

    def set_verdict(self, case_id, verdict):
        """실행 후 결과 태그를 해당 case_id 변형에 연결.

        뮤테이터가 변형 시점(log_mutation)과 실행 시점(classify 결과)이 분리돼
        있으므로, case_id 로 나중에 결과를 붙인다. 알 수 없는 case_id 는 무시.
        """
        m = self._by_case.get(case_id)
        if m is not None:
            m.verdict = verdict
        return m

    def summary(self):
        """집계 dict — region/field/rule/verdict 별 카운트 + 크래시 수."""
        by_region = Counter(m.region for m in self.mutations)
        by_field = Counter(m.field for m in self.mutations)
        by_rule = Counter(m.rule for m in self.mutations)
        by_verdict = Counter(m.verdict for m in self.mutations if m.verdict)
        crashes = [m for m in self.mutations
                   if m.verdict in CRASH_VERDICTS]
        return {
            "total": len(self.mutations),
            "by_region": dict(by_region),
            "by_field": dict(by_field),
            "by_rule": dict(by_rule),
            "by_verdict": dict(by_verdict),
            "crash_count": len(crashes),
            "crash_cases": [
                {"case_id": m.case_id, "region": m.region, "field": m.field,
                 "rule": m.rule, "verdict": m.verdict}
                for m in crashes
            ],
        }

    def flush(self):
        """런 요약을 json + txt 로 내린다 (jsonl 은 이미 스트리밍됨).

        여러 번 호출해도 안전 (전체 스냅샷을 매번 덮어씀). 반환: (json_path, txt_path).
        """
        elapsed = time.time() - self._started
        summ = self.summary()
        doc = {
            "run_id": self.run_id,
            "base_file": self.base_file,
            "target": self.target,
            "default_likelihood": self.default_likelihood,
            "started": self._started,
            "started_iso": datetime.fromtimestamp(self._started).isoformat(),
            "elapsed_sec": round(elapsed, 3),
            "summary": summ,
            "mutations": [m.to_dict() for m in self.mutations],
        }
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)

        with open(self.txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 72 + "\n")
            f.write(f" Lfuzzer 변형 리포트  run_id={self.run_id}\n")
            f.write("=" * 72 + "\n")
            f.write(f" base_file : {self.base_file}\n")
            f.write(f" target    : {self.target}\n")
            f.write(f" 시작      : {datetime.fromtimestamp(self._started).isoformat()}\n")
            f.write(f" 경과      : {elapsed:.1f}s\n")
            f.write(f" 기본 -l   : {self.default_likelihood:.2f}\n")
            f.write(f" 총 변형   : {summ['total']}\n")
            f.write(f" 크래시    : {summ['crash_count']}\n")
            f.write("-" * 72 + "\n")
            f.write(" [영역별]   " + "  ".join(f"{k}={v}" for k, v in summ["by_region"].items()) + "\n")
            f.write(" [결과별]   " + "  ".join(f"{k}={v}" for k, v in summ["by_verdict"].items()) + "\n")
            f.write("-" * 72 + "\n")
            f.write(" [변형 상세]\n")
            for m in self.mutations:
                f.write("  " + m.to_line() + "\n")
            if summ["crash_count"]:
                f.write("-" * 72 + "\n")
                f.write(" [크래시 케이스]\n")
                for c in summ["crash_cases"]:
                    f.write(f"  {c['verdict']:10s} {c['region']:8s} {c['field']:12s} "
                            f"({c['rule']})  case={c['case_id']}\n")
            f.write("=" * 72 + "\n")
        return self.json_path, self.txt_path

    def close(self):
        """jsonl 파일 핸들 정리 + 최종 flush. with 문 종료 시 자동 호출."""
        try:
            self.flush()
        finally:
            if self._jsonl_fh is not None:
                self._jsonl_fh.close()
                self._jsonl_fh = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


if __name__ == "__main__":
    # 데모: PHDR/DYNAMIC 변형 몇 개 찍고 결과 연결 후 리포트 flush
    import tempfile
    demo_dir = os.path.join(tempfile.gettempdir(), "lfuzzer_logger_demo")
    with FuzzLogger(report_dir=demo_dir, run_id="demo_run",
                    base_file="prac.elf", likelihood=0.10,
                    target="/lib64/ld-linux-x86-64.so.2") as log:
        # PHDR p_offset 을 파일 밖으로 (critical 필드 -> likelihood 낮춰 기록)
        log.log_mutation(region="PHDR", field="p_offset", rule="offset_oob",
                         offset=0x88, old=0x1000, new=0xffffffffffff,
                         likelihood=0.05, seg_idx=2,
                         case_id="A_seg2_p_offset_0000")
        # DYNAMIC DT_STRTAB 포인터 깨기
        log.log_mutation(region="DYNAMIC", field="DT_STRTAB", rule="strtab_null",
                         offset=0x2f0, old=0x3f0, new=0x0,
                         case_id="dyn_strtab_0")
        # SHDR sh_name 을 strtab 밖으로 (bytes old/new 도 허용됨을 보여줌)
        log.log_mutation(region="SHDR", field="sh_name", rule="name_oob",
                         offset=0x1040, old=0x1, new=0xffffffff,
                         seg_idx=5, case_id="shdr_name_0")

        # 실행 결과 연결
        log.set_verdict("A_seg2_p_offset_0000", "SIGSEGV")
        log.set_verdict("dyn_strtab_0", "TIMEOUT")
        log.set_verdict("shdr_name_0", "OK")

        json_path, txt_path = log.flush()

    print("jsonl:", log.jsonl_path)
    print("json :", json_path)
    print("txt  :", txt_path)
    print("-" * 40)
    with open(txt_path, encoding="utf-8") as f:
        print(f.read())
