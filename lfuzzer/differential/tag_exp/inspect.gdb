set pagination off
set breakpoint pending on
# _dl_relocate_object(l, ...) 에서 main map(l_name=="") 잡기
break _dl_relocate_object
commands
  silent
  printf "obj l_name=\"%s\"\n", l->l_name
  # DT_DEBUG=21 슬롯: 음수태그면 NULL 이어야 함
  printf "  l_info[21](DT_DEBUG) = %p\n", l->l_info[21]
  # DT_STRTAB=5 슬롯의 ptr: 중복이면 가짜(0x400000) 이어야 함
  printf "  l_info[5](DT_STRTAB) = %p", l->l_info[5]
  if l->l_info[5] != 0
    printf "  ->d_ptr(+l_addr) = %#lx\n", l->l_info[5]->d_un.d_ptr
  else
    printf "\n"
  end
  continue
end
run
quit
