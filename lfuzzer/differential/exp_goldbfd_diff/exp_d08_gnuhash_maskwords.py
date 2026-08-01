#!/usr/bin/env python3
"""
exp_d08_gnuhash_maskwords.py — D08: .gnu.hash 의 maskwords(bloom filter 워드수) 위조.

소스 근거:
  bfd  elf.c / elflink.c  DT_GNU_HASH 파싱부: .gnu.hash 헤더 4워드
        [nbuckets][symndx][maskwords][bloom_shift] 를 읽어
        buckets 시작 위치를 산술로 계산한다:
          buckets_vma = gnu_hash + 16 + maskwords * (elfclass64 ? 8 : 4)
        maskwords 를 거대값으로 위조하면 buckets_vma 가 파일 밖/엉뚱한 곳을
        가리켜 이후 경계검사/문자열테이블 접근이 오염된다(BFD 산술경로).
  gold dynobj.cc  Sized_dynobj::read_symbols — DT_GNU_HASH 의 maskwords 산술로
        심볼을 재구성하지 않고 자체 심볼테이블 경로를 씀 → 이 값에 무관(영향 없음).
예측:
  BFD  = 위조 maskwords 로 buckets_vma 산술 오염 → 에러/경고/비정상 rc.
  GOLD = .gnu.hash 4워드 산술에 의존 안 함 → 정상 수락(rc 0).
  >>> DIVERGED <<< 가 목표.

크래프팅(왜 과거 방식이 실패했나 → 초반 포맷검사 통과가 관건):
  1) common.make_base_lib 로 완전 정상 .so 빌드(.gnu.hash 섹션 포함).
  2) 스트립 '전에' pyelftools 로 .gnu.hash 의 sh_offset 을 확보(스트립 후엔 못 찾음).
  3) maskwords 워드(섹션시작 + 8, 4바이트 LE)만 위조값으로 patch_bytes.
     나머지 nbuckets/symndx/bloom_shift/bloom/buckets/chain 은 그대로 유지.
  4) common.strip_section_headers 로 e_shoff/e_shnum/e_shstrndx 만 0 →
     여전히 유효한 '섹션헤더 없는' ELF → 초반 "wrong format" 검사 통과하고
     링커를 PT_DYNAMIC/DT_GNU_HASH 폴백 경로로 강제 진입시킴.
  5) 이 위조 .so 를 소비자(main)와 링크 → 두 링커 결과 비교.

직접 실행:  ./exp_d08_gnuhash_maskwords.py       (사용자가 ! 로 직접)

결과 판독:
  - DIVERGED: BFD 만 maskwords 산술 오염으로 rc≠0/경고, GOLD 는 rc 0 → 예측 적중.
  - 같음: .gnu.hash 산술이 심볼 로드 전에 방어됐거나 폴백 경로 미진입 → 스트립 확인.
"""
import os, struct, tempfile, common

FORGED_MASKWORDS = 0x0FFFFFFF  # 위조: bloom filter 워드수를 거대값으로(→buckets_vma 폭주)

def gnu_hash_offset(so_path):
    """스트립 '전에' pyelftools 로 .gnu.hash 섹션의 파일 오프셋을 구한다."""
    from elftools.elf.elffile import ELFFile
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".gnu.hash")
        assert sec is not None, ".gnu.hash 섹션 없음 (--hash-style=gnu 계열 확인)"
        return sec["sh_offset"]

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d08_")

    # 1) 정상 공유 라이브러리 빌드 (모든 필드 유효, .gnu.hash 포함)
    so = common.make_base_lib(wd, name="libd08")

    # 2) 스트립 전에 .gnu.hash 오프셋 확보
    gh_off = gnu_hash_offset(so)
    raw = open(so, "rb").read()
    nbuckets, symndx, maskwords, shift = struct.unpack_from("<IIII", raw, gh_off)
    print(f".gnu.hash @ file offset 0x{gh_off:x}")
    print(f"   원본 nbuckets={nbuckets} symndx={symndx} "
          f"maskwords={maskwords} bloom_shift={shift}")

    # 3) maskwords 워드(섹션시작 + 8, 4바이트)만 정밀 위조 (그 외 전부 유효 유지)
    common.patch_bytes(so, gh_off + 8, struct.pack("<I", FORGED_MASKWORDS))
    m2 = struct.unpack_from("<I", open(so, "rb").read(), gh_off + 8)[0]
    print(f"   위조 후 maskwords=0x{m2:x}  (buckets_vma = gnu_hash+16+maskwords*8 오염 유도)")

    # 4) 섹션헤더만 제거 → DT_GNU_HASH 폴백 경로 강제 (유효 ELF 유지)
    common.strip_section_headers(so)
    print("   strip_section_headers 적용 → e_shoff/e_shnum/e_shstrndx = 0 (유효 no-SHT ELF)")

    # (확인) 섹션헤더가 실제로 사라졌는지 — readelf 가 섹션 0개로 보여야 함
    _, ro, _ = common.run(["readelf", "-hS", so])
    for line in ro.splitlines():
        if "start of section" in line.lower() or "Number of section" in line:
            print("   ", line.strip())

    # 5) 위조 .so 를 소비하는 프로그램과 링크
    csrc = common.make_consumer(wd, so, name="main")
    args = ["-fPIC", csrc, so, "-o", os.path.join(wd, "prog")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report("D08 gnu.hash maskwords 위조 (+no-SHT)", bfd, gold,
        extra=f"forged maskwords=0x{FORGED_MASKWORDS:x} · 예측: BFD=buckets_vma 산술오염 오류 / GOLD=수락")
    print("\n결론:", "예측대로 갈림 ✓" if diverged
          else "안 갈림 — 스트립/폴백 경로 재확인 필요")

if __name__ == "__main__":
    main()
