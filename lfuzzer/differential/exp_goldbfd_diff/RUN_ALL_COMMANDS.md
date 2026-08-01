# 전체 테스팅 명령어 모음 (복붙용)

ELF 링커/분석기 differential — 처음부터 끝까지 직접 돌려보는 명령. WSL에서 실행.

---

## 0. (필요시) WSL 먹통이면 복구 — Windows PowerShell/cmd
```
wsl --shutdown
```

## 1. 의존성 확인 + 설치
```
which gcc readelf objdump valgrind patchelf; java -version
python3 -c "import elftools; print('pyelftools OK')"
sudo apt-get install -y build-essential binutils valgrind patchelf python3-pyelftools radare2 openjdk-21-jdk
ls -l ~/binutils-build-afl-bfd-clean/ld/ld-new ~/binutils-build-gold/gold/ld-new   # 링커 2종
```

## 2. gold vs bfd 실험 — 전부 (./ 로 실행)
```
cd ~/PE/Lfuzzer/exp_goldbfd_diff
bash run_all.sh                 # 핵심 4개
# 개별 (전 23개):
for f in exp_d0*.py exp_d1*.py exp_d2*.py; do echo "== $f =="; ./$f; done
```

## 3. readelf/Ghidra DISPLAY 축 — 직접 눈으로
```
cd ~/PE/Lfuzzer; F=prac.elf
readelf -d $F                        # (D1/R1) readelf = SHT '.dynamic' 기반
readelf -l $F | grep -A2 DYNAMIC     #         PT_DYNAMIC 세그먼트(로더 뷰)
readelf --dyn-syms $F                # (R2) 기본 = SHT .dynsym
readelf -D --dyn-syms $F             #      -D = PT_DYNAMIC+hash (로더 뷰)
objdump -T $F                        #      BFD(섹션 기반)
readelf -d prac_extratag_poc.elf | grep -i unknown   # (R4) 분석기엔 <unknown>
r2 -qc 'idj' $F 2>/dev/null           #      radare2 = PT_DYNAMIC 뷰
# 관측 실험 스크립트:
cd exp_goldbfd_diff
./exp_display_all.py   ./exp_r5_phdr_vs_sht.py   ./exp_r6_ehdr_unknown_enum.py
```

## 4. Ghidra 설치 (이미 됨) + R7/R8 실험
```
# 설치 (sudo 불필요 — 다운로드+압축해제만, Java 21 사용). 이미 ~/ghidra_12.1.2_PUBLIC 있음:
#   URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
#         | grep -oE 'https://[^"]+_PUBLIC_[0-9]+\.zip' | head -1)
#   wget -O ~/ghidra_dl.zip "$URL" && unzip -q ~/ghidra_dl.zip -d ~/
# R7: Ghidra가 64비트 d_tag를 32비트로 절단하는지 (라이브 실증 완료)
cd ~/PE/Lfuzzer/exp_goldbfd_diff
./exp_r7_ghidra_dtag.py          # → 0xDEADBEEFFFFFFFFD → Ghidra 0xfffffffd, readelf <unknown>
./exp_r8_ghidra_symcount.py      # Ghidra dynsym 수(nchain) vs readelf(sh_size)
# 직접 Ghidra 덤프도 가능:
GH=~/ghidra_12.1.2_PUBLIC
$GH/support/analyzeHeadless /tmp/gp p -import ~/PE/Lfuzzer/prac_extratag_poc.elf \
   -scriptPath ~/PE/Lfuzzer/exp_goldbfd_diff/ghidra_scripts \
   -postScript DumpDynamic.java -deleteProject 2>&1 | grep "DT tag"
```

## 5. 소스 대질 지점 직접 grep
```
B=~/binutils-src/binutils-2.42
sed -n '299,341p' $B/gold/dynobj.cc          # gold: 태그 3개만(default:break)
grep -n 'dyn.d_tag ==' $B/bfd/elflink.c      # bfd: 태그마다 if
sed -n '6741,6777p' $B/binutils/readelf.c    # (R1) readelf가 SHT로 덮어쓰는 줄
grep -oE 'case elfcpp::DT_[A-Z0-9_]+' $B/gold/dynobj.cc | sort -u   # gold DT_ census(3개)
```

## 6. VSCode (Windows Git Bash/PowerShell 에서 — WSL 원격)
```
code --remote wsl+Ubuntu /home/garden/PE/Lfuzzer/exp_goldbfd_diff
code --remote wsl+Ubuntu --goto /home/garden/binutils-src/binutils-2.42/binutils/readelf.c:6741
code --remote wsl+Ubuntu --goto /home/garden/binutils-src/binutils-2.42/gold/dynobj.cc:299
```
(WSL 안에서 `code`가 "Exec format error" 나면 위 Windows-원격 방식.)

---

## 현재 상태 (2026-07-22)
- 실험 27개 전부 `./` 실행가능. **R7 라이브 실증 완료**(Ghidra 12.1.2: d_tag 절단).
- 재검증 33주장 → 26 CONFIRMED / 5 PLAUSIBLE / 2 REFUTED(D18·D19 삭제).
- 실측 확정: D03 ✓적중 / D19 ✗(둘다거부, 재검증도 REFUTED) / D22 ~부분 / D02 ✗미재현 / R7 ✓라이브.
- 남은 것: 나머지 D0x/Rx 스크립트를 직접 `./` 로 돌려 결론 줄 확인.
```
```
