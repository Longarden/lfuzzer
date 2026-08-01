set pagination off
set breakpoint pending on
break _dl_map_object_deps
commands
  silent
  if map->l_name[0] == 0
    printf "MAIN map:\n"
    printf "  l_info[21](DEBUG)  = %p\n", map->l_info[21]
    printf "  l_info[58](EXTRA0) = %p\n", map->l_info[58]
    printf "  l_info[59](EXTRA1) = %p\n", map->l_info[59]
    printf "  l_info[60](EXTRA2) = %p\n", map->l_info[60]
  end
  continue
end
run
quit
