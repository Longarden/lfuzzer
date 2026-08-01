set pagination off
set breakpoint pending on
break _dl_map_object_deps
commands
  silent
  if map->l_name[0] == 0
    printf "  slot53=%p 54=%p 55=%p 56=%p 57=%p 58=%p 59=%p 60=%p\n", map->l_info[53],map->l_info[54],map->l_info[55],map->l_info[56],map->l_info[57],map->l_info[58],map->l_info[59],map->l_info[60]
  end
  continue
end
run
quit
