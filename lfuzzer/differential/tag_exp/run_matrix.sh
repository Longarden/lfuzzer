#!/bin/bash
cd ~/PE/Lfuzzer/tag_exp
SYS=/lib64/ld-linux-x86-64.so.2
DBG=~/glibc/build-dbg/elf/ld.so
run(){
  local ld="$1" f="$2"
  out=$("$ld" ./"$f" 2>&1); rc=$?
  # signal decode
  sig=""; [ $rc -gt 128 ] && sig=" SIG$((rc-128))"
  printf "%-14s rc=%-3s%-7s | %s\n" "$f" "$rc" "$sig" "$(echo "$out" | head -1)"
}
echo "################ SYSTEM ld.so (glibc 2.39) ################"
run $SYS hello
for v in v_neg_msb v_neg_ff v_neg_min1 v_neg_strtab v_loproc_lo v_loproc_hi v_valrnglo v_addrrnglo v_dup_strtab; do run $SYS $v; done
echo ""
echo "################ DEBUG ld.so (assert 활성) ################"
run $DBG hello
for v in v_neg_msb v_neg_ff v_neg_min1 v_neg_strtab v_loproc_lo v_loproc_hi v_valrnglo v_addrrnglo v_dup_strtab; do run $DBG $v; done
