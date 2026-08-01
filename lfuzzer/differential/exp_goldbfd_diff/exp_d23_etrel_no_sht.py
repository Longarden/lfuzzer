#!/usr/bin/env python3
"""
exp_d23_etrel_no_sht.py — D23: 섹션헤더 없는 ET_REL 오브젝트를 링크 "입력"으로 줬을 때.

소스 근거:
  ET_REL(.o) 은 프로그램헤더(PT_*)가 없고 오직 섹션헤더테이블(SHT)로만 내용이
  기술된다. SHT 를 지우면 relocatable 은 "내용 없음"과 동치가 된다.
  bfd  elfcode.c elf_object_p / elf_link_add_object_symbols: ET_REL 처리 경로가
       섹션 순회를 전제로 짜여 있어, e_shoff==0 인 relocatable 은 정상 입력으로
       받아들이지 못한다("file in wrong format" / "no sections" 계열 거부).
  gold object.cc Sized_relobj_file: SHT 를 순회해 입력 섹션을 모은다. e_shnum==0 이면
       "섹션이 0개인 relocatable" = 빈 오브젝트로 간주하고 조용히 수락(기여분 0).
예측: 동일한 SHT-제거 ET_REL 입력 →
      BFD  = 거부(포맷 오류, rc!=0), GOLD = 수락(빈 오브젝트로 링크 성공).

크래프팅(외과적):
  1) gcc -c 로 "정상" ET_REL 오브젝트(obj.o) 생성 — 유효해야 초반검사를 통과한다.
  2) common.strip_section_headers(obj.o): EHDR 의 e_shoff/e_shnum/e_shstrndx 만 0 으로
     패치 → SHT 만 사라지고 나머지(magic/class/type=ET_REL/machine)는 그대로 유효.
     (SHT 를 손으로 깨서 wrong-type(65794) 을 유발하던 예전 방식 금지 — 그건 두
      링커가 똑같이 초반 포맷검사에서 튕겨 목표 경로에 도달조차 못 했음.)
  3) 플래그 충돌(-pie/-r) 없이, obj.o 를 그냥 -shared 링크의 입력으로만 투입.

직접 실행:  ./exp_d23_etrel_no_sht.py    (chmod +x 후 사용자가 ! 로 직접)

결과 판독:
  DIVERGED + BFD rc!=0(포맷 거부) / GOLD rc==0(빈 오브젝트 수락) 이면 예측적중.
  둘 다 거부면 → strip 이전에 이미 갈렸는지 stderr 문구로 재확인.
"""
import os, tempfile, common

def main():
    common.banner()
    wd = tempfile.mkdtemp(prefix="exp_d23_")

    # 1) 정상 ET_REL 오브젝트(.o) 생성 — 유효해야 초반 포맷검사를 통과한다.
    src = os.path.join(wd, "obj.c")
    open(src, "w").write("int helper(int x){ return x + 1; }\n")
    obj = os.path.join(wd, "obj.o")
    rc, o, e = common.run(["gcc", "-c", "-fPIC", "-o", obj, src], cwd=wd)
    assert rc == 0, f"ET_REL 오브젝트 빌드 실패: {e}"

    # (확인) 패치 전: 진짜 ET_REL 이고 섹션이 존재하는지
    _, ro0, _ = common.run(["readelf", "-h", obj])
    print("readelf -h obj.o (패치 전, 발췌):")
    for line in ro0.splitlines():
        if any(k in line for k in ("Type:", "section header", "Number of section")):
            print("   ", line.strip())

    # 2) 외과적: SHT 만 제거(e_shoff/e_shnum/e_shstrndx → 0), 나머지는 유효 유지.
    common.strip_section_headers(obj)
    _, ro1, _ = common.run(["readelf", "-h", obj])
    print("\nreadelf -h obj.o (패치 후, 발췌):")
    for line in ro1.splitlines():
        if any(k in line for k in ("Type:", "Start of section", "Number of section",
                                   "string table index")):
            print("   ", line.strip())

    # 3) 플래그 충돌(-pie/-r) 없이 obj.o 를 그냥 -shared 입력으로만 투입.
    args = ["-shared", "-nostdlib", obj, "-o", os.path.join(wd, "out.so")]
    bfd  = common.link_with(common.BFD,  args, wd)
    gold = common.link_with(common.GOLD, args, wd)
    diverged = common.diff_report("D23 ET_REL-no-SHT-as-input", bfd, gold,
        extra="예측: BFD=포맷 거부(rc!=0) / GOLD=빈 오브젝트로 수락(rc 0)")

    print("\n결론:", "예측대로 갈림 ✓" if diverged else "안 갈림 — stderr 문구로 재확인 필요")

if __name__ == "__main__":
    main()
