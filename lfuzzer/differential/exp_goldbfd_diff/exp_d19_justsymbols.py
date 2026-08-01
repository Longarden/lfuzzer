#!/usr/bin/env python3
"""
exp_d19_justsymbols.py — D19: --just-symbols(-R) 를 DSO(공유라이브러리)에 적용.

소스 근거:
  bfd  ld/ldelf.c:133-136  just_syms && (flags & DYNAMIC) -> fatal '--just-symbols may not be used on DSO'
  gold gold/target.cc:76-98 just_symbols()는 ET_EXEC 경로에서만 처리; ET_DYN은 항상 Sized_dynobj로
       빌드 → -R 로 준 DSO가 조용히 평범한 의존성으로 로드됨.
예측: 같은 .so 를 -R(--just-symbols)로 줄 때 BFD=fatal, GOLD=조용히 로드.

실행:  python3 exp_d19_justsymbols.py
"""
import os, tempfile, common

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d19_")
    lib = common.make_base_lib(wd)                 # libfoo.so (ET_DYN)
    cons = common.make_consumer(wd, lib)           # main.c (foo() 호출)
    # main 을 링크하되 libfoo 를 --just-symbols 로 준다
    args = [cons, f"-Wl,--just-symbols={lib}", "-o", os.path.join(wd, "main_out")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report("D19 --just-symbols on DSO", bfd, gold,
        extra="예측: BFD=fatal('may not be used on DSO') / GOLD=조용히 로드")
    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — 재확인 필요")

if __name__ == "__main__":
    main()
