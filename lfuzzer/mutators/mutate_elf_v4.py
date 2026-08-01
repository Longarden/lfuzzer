#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mutate_elf_v4.py  -  필드테이블 구동 ELF 뮤테이터 (ld.so 타겟)

전략 문서 "ELF 필드별 퍼징 전략 — 전수 정리(0630)" 를 그대로 코드로 옮긴 것.
v3(mutator_dynamic_v3.py: DT_VERNEED/AUDIT/STRTAB 만)에서 다음을 확장한다:
  - 영역 전수: ELF헤더(Ehdr) + 프로그램헤더(PHT) + DYNAMIC(DT_) + 구조인식(Verneed 내부)
  - 각 필드 공통 2모드:  violate(검사 자체 타격) / keep(불변식 재계산해 깊이 도달)
  - 각 필드 경계값 세트:  {0, 1, 최대값, 실제값±작은수, 정렬경계, 오버플로 유발값}
  - constraint-repairing 골격: keep 모드에서 의존필드 재계산 → 로드 가능 유지

근거(glibc 2.39, 전략문서 1-A):
  vn_next/vna_name 무검증 순회      elf/dl-version.c  _dl_check_map_versions
  DT_NEEDED offset 무검증           elf/dl-deps.c     _dl_map_object_deps
  DT_RELA/RELASZ 무검증 루프        elf/do-rel.h      elf_dynamic_do_Rel(a)
  l_info[] demux                    elf/get-dynamic-info.h
  PHT만 순회(섹션헤더 미참조)        elf/dl-load.c     _dl_map_object_from_fd

전제: 타겟은 ELF64 LSB (x86-64). pyelftools 0.32 로 구조 위치만 파악하고,
      실제 변형은 raw 바이트 패치로 한다(pyelftools 는 쓰기를 안 하므로).

사용:
  python3 mutate_elf_v4.py base.elf outdir --max 300
  python3 mutate_elf_v4.py base.elf outdir --only verneed,pht_offset
  python3 mutate_elf_v4.py base.elf outdir --list      # 무엇을 칠지 표만 출력
"""

import os
import sys
import struct
import hashlib
import argparse

import elf64  # 공용 ELF64 read primitives (behavior-exact)

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("pyelftools 가 필요합니다:  pip install pyelftools")

# --------------------------------------------------------------------------
# DT_ 태그 상수 (필요한 것만)
# --------------------------------------------------------------------------
DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_HASH, DT_STRTAB = 0, 1, 2, 4, 5
DT_SYMTAB, DT_RELA, DT_RELASZ, DT_STRSZ = 6, 7, 8, 10
DT_INIT, DT_FINI, DT_RPATH, DT_SYMBOLIC = 12, 13, 15, 16
DT_REL, DT_RELSZ, DT_JMPREL = 17, 18, 23
DT_INIT_ARRAY, DT_INIT_ARRAYSZ = 25, 27
DT_RUNPATH = 29
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFFE, 0x6FFFFFFF
DT_AUDIT = 0x6FFFFFFC

# 값이 "주소(d_ptr)"인 태그 vs "오프셋/크기(d_val)"인 태그 구분 (전략문서 판별요령)
PTR_TAGS = {DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_INIT, DT_FINI,
            DT_JMPREL, DT_INIT_ARRAY, DT_GNU_HASH, DT_VERSYM, DT_VERNEED, DT_AUDIT}
OFFSET_TAGS = {DT_NEEDED, DT_RPATH, DT_RUNPATH}          # strtab 안 오프셋
SIZE_TAGS = {DT_STRSZ, DT_RELASZ, DT_RELSZ, DT_PLTRELSZ, DT_INIT_ARRAYSZ}

U16_MAX, U32_MAX, U64_MAX = 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF

# Elf64 구조체 내부 필드 오프셋
EHDR = {  # 필드: (파일오프셋, 폭바이트, 우선순위)
    "e_type":      (16, 2, "중"),
    "e_entry":     (24, 8, "중"),
    "e_phoff":     (32, 8, "높"),
    "e_phentsize": (54, 2, "중"),
    "e_phnum":     (56, 2, "높"),
}
PHDR_FIELDS = {  # 필드: (구조체내 오프셋, 폭, 우선)
    "p_type":   (0,  4, "높"),
    "p_flags":  (4,  4, "중"),
    "p_offset": (8,  8, "높"),
    "p_vaddr":  (16, 8, "높"),
    "p_filesz": (32, 8, "높"),
    "p_memsz":  (40, 8, "높"),
    "p_align":  (48, 8, "중"),
}
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_TLS = 1, 2, 3, 4, 7


# --------------------------------------------------------------------------
# ELF 이미지 — 구조 위치 파악 + 바이트 패치
# --------------------------------------------------------------------------
class ElfImage:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = bytearray(f.read())
        self.size = len(self.buf)
        self._parse()

    def clone_buf(self):
        return bytearray(self.buf)

    def _parse(self):
        import io
        elf = ELFFile(io.BytesIO(bytes(self.buf)))
        if elf.elfclass != 64 or elf.little_endian is False:
            print("경고: ELF64 LSB 전제인데 아닌 것 같음. 그래도 진행.", file=sys.stderr)
        h = elf.header
        self.e_phoff = h["e_phoff"]
        self.e_phnum = h["e_phnum"]
        self.e_phentsize = h["e_phentsize"]

        # 프로그램 헤더 각 엔트리의 파일오프셋 + p_type 기록
        self.phdrs = []          # [{idx, foff, p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_align}]
        self.loads = []          # PT_LOAD 만 (vaddr->offset 변환용)
        for i, seg in enumerate(elf.iter_segments()):
            foff = self.e_phoff + i * self.e_phentsize
            d = dict(idx=i, foff=foff, p_type=seg["p_type"],
                     p_offset=seg["p_offset"], p_vaddr=seg["p_vaddr"],
                     p_filesz=seg["p_filesz"], p_memsz=seg["p_memsz"],
                     p_align=seg["p_align"])
            self.phdrs.append(d)
            if seg["p_type"] == "PT_LOAD" or seg["p_type"] == PT_LOAD:
                self.loads.append(d)

        # DYNAMIC 배열 파싱 (Elf64_Dyn 16바이트씩) — 공용 elf64.iter_dynamic 사용
        # (d_tag@off, d_un@off+8 오프셋 동일; DT_NULL 포함 후 종료로 기존과 동치)
        self.dyn_entries = []    # [{foff, d_tag, d_val}]
        self.dt = {}             # d_tag -> d_val (마지막 채택)
        for _i, d_tag, d_val, off in elf64.iter_dynamic(self.buf):
            self.dyn_entries.append(dict(foff=off, d_tag=d_tag, d_val=d_val))
            self.dt[d_tag & 0xFFFFFFFFFFFFFFFF] = d_val

    # vaddr -> 파일오프셋 (PT_LOAD 기준). 못 찾으면 None
    def vaddr_to_off(self, vaddr):
        for c in self.loads:
            if c["p_vaddr"] <= vaddr < c["p_vaddr"] + c["p_filesz"]:
                return c["p_offset"] + (vaddr - c["p_vaddr"])
        return None

    @staticmethod
    def pack(width):
        return {2: "<H", 4: "<I", 8: "<Q"}[width]


# --------------------------------------------------------------------------
# 경계값 세트 (전략문서: {0,1,최대,실제±작은수,정렬경계,오버플로 유발})
# --------------------------------------------------------------------------
def boundary_set(width, real, file_size=None, strsz=None):
    bits = width * 8
    mx = (1 << bits) - 1
    vals = {0, 1, mx, mx - 1, 1 << (bits - 1)}      # 0,1,최대,최대-1,부호경계
    vals.add(0x1000)                                 # 페이지 경계
    if real is not None:
        real &= mx
        vals.update({real, (real + 1) & mx, (real - 1) & mx,
                     (real + 0x1000) & mx, (real << 1) & mx})  # 곱 오버플로 유발
    if file_size is not None:                        # 파일 끝 너머 (OOB read)
        vals.update({file_size & mx, (file_size + 0x1000) & mx})
    if strsz is not None:                            # strtab 끝 너머 (NEEDED OOB)
        vals.update({strsz & mx, (strsz + 1) & mx, (strsz + 0x1000) & mx})
    return sorted(v & mx for v in vals)


def is_pow2_or_01(x):
    return x in (0, 1) or (x & (x - 1)) == 0


# --------------------------------------------------------------------------
# constraint-repairing : keep 모드에서 PHT 교차필드 불변식 복구
#   p_align ∈ {0,1,2^n} · p_filesz ≤ p_memsz · p_offset+p_filesz ≤ 파일
#   p_vaddr ≡ p_offset (mod p_align)
# --------------------------------------------------------------------------
def repair_pht(buf, img):
    for c in img.phdrs:
        base = c["foff"]
        def rd(o, w): return struct.unpack_from(ElfImage.pack(w), buf, base + o)[0]
        def wr(o, w, v): struct.pack_into(ElfImage.pack(w), buf, base + o, v & ((1 << (w*8)) - 1))
        p_off  = rd(8, 8); p_va = rd(16, 8)
        p_fsz  = rd(32, 8); p_msz = rd(40, 8); p_al = rd(48, 8)
        # 1) align 정상화
        if not is_pow2_or_01(p_al) or p_al > (1 << 30):
            p_al = 0x1000; wr(48, 8, p_al)
        # 2) filesz ≤ memsz
        if p_fsz > p_msz:
            p_msz = p_fsz; wr(40, 8, p_msz)
        # 3) offset+filesz ≤ 파일크기  (넘으면 filesz 클램프)
        if p_off > img.size:
            p_off = img.size; wr(8, 8, p_off)
        if p_off + p_fsz > img.size:
            p_fsz = max(0, img.size - p_off); wr(32, 8, p_fsz)
            if p_fsz > p_msz:
                wr(40, 8, p_fsz)
        # 4) vaddr ≡ offset (mod align)
        if p_al > 1:
            want = p_off % p_al
            if (p_va % p_al) != want:
                p_va = (p_va - (p_va % p_al)) + want
                wr(16, 8, p_va)


# --------------------------------------------------------------------------
# 변형 작업(job) 생성 — 필드테이블 전수
#   job = dict(region, field, mode, value, apply=fn(buf))
# --------------------------------------------------------------------------
def build_jobs(img, only=None, modes=("violate", "keep")):
    jobs = []

    def add(region, field, prio, foff, width, value, mode):
        def apply(buf, foff=foff, width=width, value=value, mode=mode):
            struct.pack_into(ElfImage.pack(width), buf, foff,
                             value & ((1 << (width*8)) - 1))
            if mode == "keep":
                repair_pht(buf, img)
        jobs.append(dict(region=region, field=field, prio=prio,
                         mode=mode, value=value, apply=apply))

    want = (lambda k: True) if not only else (lambda k: k in only)

    # --- ELF 헤더 ---
    if want("ehdr"):
        for fld, (foff, w, prio) in EHDR.items():
            real = struct.unpack_from(ElfImage.pack(w), img.buf, foff)[0]
            for v in boundary_set(w, real, file_size=img.size):
                for m in modes:
                    if m == "keep":
                        continue   # B22: repair_pht 는 EHDR 를 안 건드림 → keep == violate (중복)
                    add("EHDR", fld, prio, foff, w, v, m)

    # --- 프로그램 헤더 (세그먼트별 8필드) ---
    if want("pht") or want("pht_offset"):
        for c in img.phdrs:
            tag = "pht_offset" if want("pht_offset") and not want("pht") else "pht"
            for fld, (o, w, prio) in PHDR_FIELDS.items():
                if want("pht_offset") and not want("pht") and fld != "p_offset":
                    continue
                foff = c["foff"] + o
                real = struct.unpack_from(ElfImage.pack(w), img.buf, foff)[0]
                for v in boundary_set(w, real, file_size=img.size):
                    for m in modes:
                        add("PHT[%d:%s]" % (c["idx"], _pt_name(c["p_type"])),
                            fld, prio, foff, w, v, m)

    # --- DYNAMIC (DT_ d_val / d_ptr) ---
    if want("dynamic"):
        for e in img.dyn_entries:
            t = e["d_tag"] & 0xFFFFFFFFFFFFFFFF
            if t == DT_NULL:
                continue
            foff = e["foff"] + 8                      # d_un 위치
            strsz = img.dt.get(DT_STRSZ)
            bs = boundary_set(8, e["d_val"],
                              file_size=img.size,
                              strsz=strsz if t in OFFSET_TAGS else None)
            prio = "높" if t in (DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_RELA,
                                 DT_RELASZ, DT_AUDIT) else "중"
            for v in bs:
                for m in modes:                       # 여기선 repair 대상 아님→둘 다 같음
                    add("DYNAMIC", "DT(%s)" % _dt_name(t), prio, foff, 8, v, m)

    # --- 구조인식: VERNEED 내부 (vn_next / vna_next / vna_name) ★최고 ---
    if want("verneed"):
        jobs.extend(_verneed_jobs(img, modes))

    # only 로 다른 것 다 끄고 verneed 만 원할 때를 위해 dedup 모드 정리
    return jobs


def _verneed_jobs(img, modes=("violate", "keep")):
    """DT_VERNEED 가 가리키는 Verneed/Vernaux 링크드리스트 내부 필드를 친다.
       근거: dl-version.c _dl_check_map_versions 가 vn_next/vna_next/vna_name 무검증."""
    out = []
    vn_ptr = img.dt.get(DT_VERNEED)
    strsz = img.dt.get(DT_STRSZ)
    if vn_ptr is None:
        return out
    base = img.vaddr_to_off(vn_ptr)
    if base is None:
        return out

    # Verneed(16) : vn_version(0,H) vn_cnt(2,H) vn_file(4,I) vn_aux(8,I) vn_next(12,I)
    # Vernaux(16) : vna_hash(0,I) vna_flags(4,H) vna_other(6,H) vna_name(8,I) vna_next(12,I)
    targets = []          # (이름, 파일오프셋, 폭, 경계값들)
    off = base
    guard = 0
    while 0 <= off and off + 16 <= img.size and guard < 64:
        guard += 1
        vn_file = struct.unpack_from("<I", img.buf, off + 4)[0]
        vn_aux  = struct.unpack_from("<I", img.buf, off + 8)[0]
        vn_next = struct.unpack_from("<I", img.buf, off + 12)[0]
        targets.append(("vn_file",  off + 4,  4, boundary_set(4, vn_file, strsz=strsz)))
        targets.append(("vn_cnt",   off + 2,  2, boundary_set(2, None)))
        targets.append(("vn_next",  off + 12, 4, [U32_MAX, U32_MAX - 1, 0x7FFFFFFF, 0x10000]))
        # vernaux 순회
        ao = off + vn_aux
        g2 = 0
        while 0 <= ao and ao + 16 <= img.size and g2 < 64:
            g2 += 1
            vna_name = struct.unpack_from("<I", img.buf, ao + 8)[0]
            vna_next = struct.unpack_from("<I", img.buf, ao + 12)[0]
            targets.append(("vna_name", ao + 8,  4, boundary_set(4, vna_name, strsz=strsz)))
            targets.append(("vna_next", ao + 12, 4, [U32_MAX, U32_MAX - 1, 0x7FFFFFFF, 0x10000]))
            if vna_next == 0:
                break
            ao += vna_next
        if vn_next == 0:
            break
        off += vn_next

    for name, foff, w, vals in targets:
        for v in vals:
            for m in modes:                       # B23: --modes 필터 준수 (violate 하드코딩 제거)
                def apply(buf, foff=foff, w=w, v=v):
                    struct.pack_into(ElfImage.pack(w), buf, foff, v & ((1 << (w*8)) - 1))
                out.append(dict(region="VERNEED", field=name, prio="최고",
                                mode=m, value=v, apply=apply))
    return out


# --------------------------------------------------------------------------
# 이름 헬퍼
# --------------------------------------------------------------------------
def _pt_name(t):
    m = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 7: "TLS",
         "PT_LOAD": "LOAD", "PT_DYNAMIC": "DYNAMIC", "PT_INTERP": "INTERP",
         "PT_NOTE": "NOTE", "PT_TLS": "TLS"}
    return m.get(t, str(t))


def _dt_name(t):
    m = {DT_NEEDED: "NEEDED", DT_STRTAB: "STRTAB", DT_SYMTAB: "SYMTAB",
         DT_STRSZ: "STRSZ", DT_RELA: "RELA", DT_RELASZ: "RELASZ",
         DT_JMPREL: "JMPREL", DT_GNU_HASH: "GNU_HASH", DT_VERSYM: "VERSYM",
         DT_VERNEED: "VERNEED", DT_AUDIT: "AUDIT", DT_INIT_ARRAY: "INIT_ARRAY",
         DT_RPATH: "RPATH", DT_RUNPATH: "RUNPATH", DT_HASH: "HASH"}
    return m.get(t, hex(t))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="필드테이블 구동 ELF 뮤테이터 v4")
    ap.add_argument("base", help="기준 ELF (예: prac.elf)")
    ap.add_argument("outdir", nargs="?", default="mut_v4_out", help="출력 폴더")
    ap.add_argument("--max", type=int, default=300, help="최대 생성 개수")
    ap.add_argument("--only", default=None,
                    help="콤마구분: ehdr,pht,pht_offset,dynamic,verneed")
    ap.add_argument("--modes", default="violate,keep",
                    help="violate,keep 중 (기본 둘 다)")
    ap.add_argument("--list", action="store_true", help="생성 안 하고 잡 목록만 출력")
    args = ap.parse_args()

    img = ElfImage(args.base)
    only = set(s.strip() for s in args.only.split(",")) if args.only else None
    modes = tuple(s.strip() for s in args.modes.split(","))
    jobs = build_jobs(img, only=only, modes=modes)

    # 우선순위 정렬 (최고>높>중) 후 캡
    rank = {"최고": 0, "높": 1, "중": 2, "낮": 3}
    jobs.sort(key=lambda j: rank.get(j["prio"], 9))

    print("기준 ELF: %s  (%d bytes)" % (args.base, img.size))
    print("세그먼트 %d개, DYNAMIC 엔트리 %d개, 생성 잡 %d개"
          % (len(img.phdrs), len(img.dyn_entries), len(jobs)))
    if not img.dt.get(DT_VERNEED):
        print("주의: DT_VERNEED 없음 → verneed 잡 비어있음 (베이스에 버전정보 있는 ELF 권장)")

    if args.list:
        for j in jobs[:args.max]:
            print("  [%-3s] %-16s %-10s %-8s = %#x"
                  % (j["prio"], j["region"], j["field"], j["mode"], j["value"]))
        return

    os.makedirs(args.outdir, exist_ok=True)
    n = 0
    manifest = []
    seen = set()                                  # B07: 결과 바이트 중복 제거
    for i, j in enumerate(jobs[:args.max]):
        buf = img.clone_buf()
        try:
            j["apply"](buf)
        except Exception as e:
            print("  skip(%s/%s): %s" % (j["region"], j["field"], e), file=sys.stderr)
            continue
        h = hashlib.sha1(bytes(buf)).digest()     # B07: repair_pht 로 동일해진 잡은 건너뜀
        if h in seen:
            continue
        seen.add(h)
        fname = "mut_%04d_%s_%s_%s.elf" % (
            n, j["region"].replace("[", "_").replace("]", "").replace(":", ""),
            j["field"].replace("(", "").replace(")", ""), j["mode"])
        with open(os.path.join(args.outdir, fname), "wb") as f:
            f.write(buf)
        manifest.append("%s\t%s\t%s\t%s\t%#x" %
                        (fname, j["region"], j["field"], j["mode"], j["value"]))
        n += 1

    with open(os.path.join(args.outdir, "MANIFEST.tsv"), "w", encoding="utf-8") as f:
        f.write("file\tregion\tfield\tmode\tvalue\n")
        f.write("\n".join(manifest) + "\n")
    print("생성 완료: %d개 → %s/  (MANIFEST.tsv 동봉)" % (n, args.outdir))
    print("다음: 이 폴더를 AFL 시드(-i)로 쓰거나, 각 파일을 ld.so --verify 로 직접 돌려 크래시 확인")


if __name__ == "__main__":
    main()
