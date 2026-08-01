set pagination off
set breakpoint pending on
break _dl_map_object_deps
commands
  silent
  if map->l_name[0] == 0
    set $i=0
    while $i < 84
      if map->l_info[$i] != 0
        printf "%d:%p ", $i, map->l_info[$i]
      end
      set $i=$i+1
    end
    printf "\n"
  end
  continue
end
run
quit
