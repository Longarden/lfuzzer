#!/bin/bash
# step3 PRIMARY/SECONDARY divergence 재현 스크립트.
# 사전조건: scripts/setup_inputs.sh 로 diff/ 입력 생성됨.
# 주: 링커가 의도적으로 rc!=0을 반환하므로 set -e 미사용.
LD=~/binutils-build-afl-bfd-clean/ld/ld-new
GOLD=~/binutils-build-gold/gold/ld-new
D=/home/garden/PE/Lfuzzer/meeting_0714_step3/diff
cd "$D"

python3 - <<'PY'
import struct
def load(): return bytearray(open("libfoo.so.1","rb").read())
# B2: .dynamic 섹션(sh_type==SHT_DYNAMIC=6)의 sh_type -> 0x99
b=load()
shoff=struct.unpack_from("<Q",b,0x28)[0]; shentsz=struct.unpack_from("<H",b,0x3a)[0]; shnum=struct.unpack_from("<H",b,0x3c)[0]
for i in range(shnum):
    sh=shoff+i*shentsz
    if struct.unpack_from("<I",b,sh+4)[0]==6:
        struct.pack_into("<I",b,sh+4,0x99); print(f"B2: patched sh_type at file offset 0x{sh+4:x}"); break
open("b2_dyn_shtype.so","wb").write(b)
# B1: e_shstrndx -> 0xffff
b=load(); struct.pack_into("<H",b,0x3e,0xffff); open("b1_shstrndx_oob.so","wb").write(b)
print("B1: patched e_shstrndx=0xffff at 0x3e")
PY

run(){ "$@" >/tmp/o 2>/tmp/e; local rc=$?; echo "  rc=$rc | $(tr '\n' ' ' </tmp/e | cut -c1-200)"; }

echo "===== B2: .dynamic sh_type 손상 (PRIMARY) ====="
echo "[LD  ]"; run $LD   -shared --no-undefined -o out_b2_ld.so   main.o ./b2_dyn_shtype.so
echo "[GOLD]"; run $GOLD -shared --no-undefined -o out_b2_gold.so main.o ./b2_dyn_shtype.so
echo "[RUNTIME] pristine로 실행파일 빌드 후, on-disk .so만 b2로 교체하고 실행:"
cp libfoo.so.1 libfoo.so.1.bak
gcc run_test.c -L. -lfoo -Wl,-rpath,"$D" -o runtest     # pristine로 링크
cp b2_dyn_shtype.so libfoo.so.1                          # 실행 직전 손상본으로 교체
./runtest; echo "  runtime exit=$?"
cp libfoo.so.1.bak libfoo.so.1                           # 원복

echo "===== B1: e_shstrndx 손상 (SECONDARY) ====="
echo "[LD  ]"; run $LD   -shared --no-undefined -o /dev/null main.o ./b1_shstrndx_oob.so
echo "[GOLD]"; run $GOLD -shared --no-undefined -o /dev/null main.o ./b1_shstrndx_oob.so
echo "기대: B2 = LD거부/Gold수용/런타임정상 ; B1 = LD경고후진행/Gold하드에러"
