#!/usr/bin/env python3
"""
exp_d01_strip_sht.py — D01: 섹션헤더 테이블(SHT)이 제거된 .so 를 입력으로 줬을 때.

소스 근거:
  bfd   elf.c / elfcode.h — e_shoff==0 이면 SHT 부재로 보고, PT_DYNAMIC 프로그램
        헤더의 DT_SYMTAB/DT_HASH 를 훑어 .dynsym/.dynstr 를 재구성하는 폴백 경로.
        → 공유객체 심볼(foo) 을 SHT 없이도 복원.
  gold  dynobj.cc Sized_dynobj::do_read_symbols() — 심볼 수집을 섹션헤더(SHT_DYNSYM
        섹션 인덱스) 기반으로 함. e_shnum==0 이면 dynsym 섹션 자체를 못 찾아
        재구성 폴백이 없이 심볼 0개 → undefined reference.
예측:
  같은 SHT-less DSO →
    BFD  = PT_DYNAMIC 폴백으로 foo() 재구성, 링크 진행(rc 0 또는 다른 사유).
    GOLD = 폴백 없어 undefined reference `foo' / 심볼 0, 링크 실패(rc!=0).
  → diff_report 에서 DIVERGED.

크래프팅(외과적):
  이전 실패 원인 → SHT 를 손으로 뭉개서 sh_type 바이트가 살아남는 바람에 gold 가
  "section name section has wrong type: 65794" 로 초반 포맷검사에서 거부됨.
  즉 타깃 파스 경로(심볼 재구성)에 도달조차 못했음.
  수정 → common.make_base_lib 로 완전 정상 .so 빌드 후, common.strip_section_headers
  로 EHDR 의 e_shoff/e_shnum/e_shstrndx 만 0 으로 덮어써 "SHT 가 통째로 없는" 유효
  ELF 를 만든다. SHT 바이트 자체는 안 건드리므로 wrong-type 조기거부가 사라지고
  두 링커 모두 폴백 분기까지 진입 → 진짜 차이가 드러남.

직접 실행:  ./exp_d01_strip_sht.py      (사용자가 ! 로 직접 돌림)

결과 판독:
  readelf -h 의 "Number of section headers: 0" 확인 → SHT 제거 성공 전제.
  diff_report 의 BFD/GOLD rc·stderr 비교. GOLD 만 undefined foo / 실패면 예측 적중.
"""
import os, tempfile, common

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d01_")

    # 1) 정상 공유 라이브러리 빌드 (foo() 심볼 보유, SHT 정상)
    so = common.make_base_lib(wd, name="libfoo")

    # 2) 외과적 패치: EHDR 의 e_shoff/e_shnum/e_shstrndx 만 0 → SHT 부재 유효 ELF
    common.strip_section_headers(so)

    # 3) (전제 확인) readelf -h 로 섹션헤더 수가 0 인지 검증
    _, ho, _ = common.run(["readelf", "-h", so])
    print("readelf -h libfoo.so (발췌):")
    for l in ho.splitlines():
        s = l.strip()
        if ("Number of section headers" in s
                or "start of section headers" in s.lower()):
            print("   ", s)

    # 4) 이 SHT-less DSO 를 소비하는 프로그램을 두 링커로 각각 링크
    main_c = common.make_consumer(wd, so, name="main")
    args = [main_c, so, "-o", os.path.join(wd, "app"), "-Wl,-rpath," + wd]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)

    diverged = common.diff_report("D01 strip-SHT (PT_DYNAMIC 폴백)", bfd, gold,
        extra="예측: BFD=PT_DYNAMIC 폴백으로 foo 재구성 / "
              "GOLD=폴백 없음→undefined foo·실패")
    print("\n결론:", "예측대로 갈림 ✓ (BFD 폴백 vs GOLD 실패)"
          if diverged else "안 갈림 — 재확인 필요")

if __name__ == "__main__":
    main()
