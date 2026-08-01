#!/usr/bin/env python3
"""
exp_d11_shstrndx_oob.py — D11: e_shstrndx 가 섹션 개수 범위를 벗어난 경우.

소스 근거:
  bfd  elfcode.h elf_object_p / bfd_elf_get_str_section:
        e_shstrndx >= e_shnum 이면 shstrtab 인덱스를 잘못 짚음 → 경계·타입 검사로
        SHN_UNDEF 리셋 후 "invalid string table index" 류 경고를 낸다(방어적).
  gold  object.cc Sized_object::do_setup: 헤더의 shstrndx 를 그대로 신뢰(무검증
        인덱싱), 범위밖이어도 별도 리셋 없이 진행 → 두 링커 진단이 갈린다.
예측:
  BFD  = e_shstrndx 경계검사에 걸려 리셋/경고(진단 메시지 출력).
  GOLD = 검사 없이 진행 → rc/stderr 가 BFD 와 달라짐 → DIVERGED.

크래프팅(외과적):
  1) common.make_base_lib 로 "정상" .so 를 빌드(초반 포맷검사 통과 보장).
  2) common.patch_bytes 로 EHDR 의 e_shstrndx(ELF64 @0x3E, 2B) 한 필드만
     0xFFFF(범위밖)로 덮어쓴다.
     ── e_shoff/e_shnum/섹션내용 등 나머지는 전부 유효하게 유지 →
        BOTH 링커가 초반 "wrong format" 검사를 통과하고 shstrndx 해석 경로에 도달.
  3) 이전 실패 원인(-pie 와 -r 동시전달 플래그 충돌)을 제거: 충돌 플래그 없이
     평범한 -shared 링크로만 소비.

직접 실행:  ./exp_d11_shstrndx_oob.py      (사용자가 ! 로 직접 돌림)
           또는  python3 exp_d11_shstrndx_oob.py

결과 판독:
  diff_report 의 ">>> DIVERGED <<<" 여부 = BFD 경계검사 vs GOLD 무검증 갈림 확인.
  BFD stderr 에 shstrndx/string table index 경고가 뜨고 GOLD 가 조용하면 예측 적중.
"""
import os, struct, tempfile, common

# ELF64 EHDR 오프셋: e_shnum = 0x3C(2B), e_shstrndx = 0x3E(2B), little-endian
E_SHNUM_OFF    = 0x3C
E_SHSTRNDX_OFF = 0x3E
OOB_VALUE = 0xFFFF  # 어떤 정상 .so 의 e_shnum 보다도 큰 범위밖 인덱스

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d11_")

    # 1) 정상 공유 라이브러리 빌드 (여기까지는 완전 유효)
    so = common.make_base_lib(wd, name="libd11")

    # (확인) 패치 전 원래 e_shnum/e_shstrndx 값 기록
    raw = open(so, "rb").read()
    orig_shnum    = struct.unpack_from("<H", raw, E_SHNUM_OFF)[0]
    orig_shstrndx = struct.unpack_from("<H", raw, E_SHSTRNDX_OFF)[0]
    print(f"패치 전: e_shnum={orig_shnum}  e_shstrndx={orig_shstrndx}")

    # 2) 외과적 패치: e_shstrndx 한 필드만 범위밖 값으로. 나머지는 손대지 않음.
    common.patch_bytes(so, E_SHSTRNDX_OFF, struct.pack("<H", OOB_VALUE))
    new_shstrndx = struct.unpack_from("<H", open(so, "rb").read(), E_SHSTRNDX_OFF)[0]
    print(f"패치 후: e_shstrndx={new_shstrndx} (0x{new_shstrndx:04X}, 범위밖)")

    # (확인) readelf 도 헤더에서 경고를 낼 수 있음 — 참고용
    _, ro, re = common.run(["readelf", "-h", so])
    for line in (ro + re).splitlines():
        if "string table index" in line or "section header" in line.lower():
            print("   readelf:", line.strip())

    # 3) 충돌 플래그 없이 소비: consumer 를 이 .so 에 -shared 링크(-pie/-r 안 씀)
    main_c = common.make_consumer(wd, so, name="main")
    args = ["-shared", "-nostdlib", main_c, so, "-o", os.path.join(wd, "out.so")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report(
        "D11 e_shstrndx-out-of-bounds", bfd, gold,
        extra=(f"patched e_shstrndx {orig_shstrndx} -> 0x{OOB_VALUE:04X} "
               f"(e_shnum={orig_shnum})\n"
               "예측: BFD=경계·타입검사(리셋+경고) / GOLD=무검증 진행"))
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")

if __name__ == "__main__":
    main()
