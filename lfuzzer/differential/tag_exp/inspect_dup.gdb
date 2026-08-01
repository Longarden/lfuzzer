set pagination off
set breakpoint pending on
# _dl_map_object_deps(map,...) 진입 시점 = main의 dynamic info 이미 세팅됨, 의존성 해결 직전
break _dl_map_object_deps
commands
  silent
  printf "deps map l_name=\"%s\"\n", map->l_name
  printf "  l_info[5](DT_STRTAB)->d_ptr = %#lx  (baseline=0x400430, 가짜=0x400000)\n", map->l_info[5]->d_un.d_ptr
  continue
end
run
quit
