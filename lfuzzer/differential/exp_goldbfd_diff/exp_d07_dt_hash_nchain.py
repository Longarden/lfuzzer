#!/usr/bin/env python3
"""
exp_d07_dt_hash_nchain.py — D07: .hash 의 nchain 을 부풀린 뒤 SHT 를 제거했을 때.

소스 근거:
  bfd  elflink.c  — SHT 가 없어 DT_HASH 폴백으로 들어가면 .hash 헤더의 두 번째
                    워드(nchain)를 "동적 심볼 개수"로 신뢰해 .dynsym 을 그만큼 순회한다.
                    섹션헤더가 사라지면 sh_size/sh_info 대신 이 nchain 이 유일한 개수 근거.
  gold  dynobj.cc:298  Sized_dynobj::find_dynsym_sections() — SHT(SHT_DYNSYM)에서
                    심볼테이블을 찾고 DT_HASH nchain 을 개수 근거로 신뢰하지 않는다.
                    → 이 뮤테이션에 무관(D07 은 GOLD 무관 예측).
예측:
  BFD  = SHT 0 → DT_HASH 폴백. 부풀린 nchain 을 심볼 수로 믿고 .dynsym 경계 밖(OOB)까지
         읽으려다 malformed/fatal/segfault 또는 엉뚱한 심볼 로드(rc!=0, stderr 발생).
  GOLD = DT_HASH nchain 무시 → 위조 영향 없음(정상 처리 또는 자체 근거로 판단).
         (BFD 와 다른 rc/stderr 로 갈릴 것)

크래프팅(외과적 — 초반 포맷검사를 통과시키는 것이 핵심):
  1) common.make_base_lib 로 정상 .so 빌드. gcc 가 .gnu.hash 만 넣으면 nchain 이 없으므로
     --hash-style=sysv 로 재빌드해 SysV .hash 를 강제.
  2) pyelftools 로 ".hash" 섹션 sh_offset 을 "스트립 전에" 확보(스트립 후엔 섹션 위치 소실).
  3) .hash 레이아웃 [nbucket(4) | nchain(4) | bucket[] | chain[]] 에서 nchain 워드는
     sh_offset+4. 여기만 common.patch_bytes 로 큰 값으로 덮어씀(나머지는 전부 유효 유지).
  4) common.strip_section_headers 로 e_shoff/e_shnum/e_shstrndx=0 → 유효하지만 SHT 없는 ELF.
  5) 이 .so 를 소비하는 프로그램을 두 링커로 각각 링크 → diff_report 로 대질.

직접 실행:  ./exp_d07_dt_hash_nchain.py      (사용자가 ! 로 직접 돌림)
"""
import os, struct, tempfile, common
from elftools.elf.elffile import ELFFile


def _hash_offset(so_path):
    """.hash 섹션의 (sh_offset, sh_size). 없으면 (None, None)."""
    with open(so_path, "rb") as f:
        h = ELFFile(f).get_section_by_name(".hash")
        if h is None:
            return None, None
        return h["sh_offset"], h["sh_size"]


def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d07_")

    # 1) 정상 .so 빌드 (초반 포맷검사 전부 통과하는 valid ELF)
    so = common.make_base_lib(wd, name="libd07")

    # SysV .hash 가 없으면(gnu-hash 뿐이면) nchain 워드가 없으므로 재빌드로 강제
    hash_off, hash_size = _hash_offset(so)
    if hash_off is None:
        c = os.path.join(wd, "libd07.c")
        open(c, "w").write("int foo(void){ return 42; }\n")
        rc, o, e = common.run(
            ["gcc", "-shared", "-fPIC", "-Wl,-soname,libd07.so.1",
             "-Wl,--hash-style=sysv", "-o", so, c], cwd=wd)
        assert rc == 0, f"sysv-hash rebuild failed: {e}"
        hash_off, hash_size = _hash_offset(so)
        assert hash_off is not None, ".hash 섹션 여전히 없음(--hash-style=sysv 실패)"

    # 2) 스트립 전에 nchain(원본) 기록 — sh_offset+4 워드
    raw = open(so, "rb").read()
    nbucket = struct.unpack_from("<I", raw, hash_off)[0]
    nchain0 = struct.unpack_from("<I", raw, hash_off + 4)[0]
    print(f".hash @ file_off=0x{hash_off:x} size={hash_size}  "
          f"nbucket={nbucket}  nchain(원본)={nchain0}")

    # 3) nchain 워드(sh_offset+4)만 외과적으로 큰 값으로 패치
    BIG = 0x00100000  # ≈100만: 실제 dynsym 개수보다 압도적으로 큼 → OOB 유도
    common.patch_bytes(so, hash_off + 4, struct.pack("<I", BIG))
    chk = struct.unpack_from("<I", open(so, "rb").read(), hash_off + 4)[0]
    print(f"nchain 패치: {nchain0} → {chk} (0x{chk:x}) @ off=0x{hash_off + 4:x}")

    # 4) 섹션헤더 테이블 제거 → DT_HASH 폴백 경로 강제(SHT 손상 아님, 유효 no-SHT)
    common.strip_section_headers(so)
    _, ro, _ = common.run(["readelf", "-h", so])
    for line in ro.splitlines():
        low = line.lower()
        if "section header" in low or "number of section" in low:
            print("   ", line.strip())

    # 5) 뮤테이트된 .so 를 소비하는 프로그램을 두 링커로 각각 링크 → 대질
    main_c = common.make_consumer(wd, so, name="main")
    out_b = os.path.join(wd, "out_bfd")
    out_g = os.path.join(wd, "out_gold")
    bfd  = common.link_with(common.BFD,  [main_c, so, "-o", out_b], wd)
    gold = common.link_with(common.GOLD, [main_c, so, "-o", out_g], wd)

    diverged = common.diff_report(
        "D07 .hash nchain 부풀리기 (SHT 제거·DT_HASH 폴백)", bfd, gold,
        extra=(f"nchain {nchain0}→{BIG} | 예측: BFD=nchain 신뢰 → OOB "
               f"fatal/segfault, GOLD=무관(정상 처리)"))
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")


if __name__ == "__main__":
    main()
