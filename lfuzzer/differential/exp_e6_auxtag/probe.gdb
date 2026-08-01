## probe.gdb -- GDB batch script used by run_experiment.sh
##
## Instruments glibc's _dl_map_object_deps() (elf/dl-deps.c) while the debug
## build of ld.so loads a single target ELF file, to answer:
##
##   1. Does l_info[AUXTAG] (idx 60) get set for the top-level object, and by
##      what raw dynamic-array entry (its d_tag/d_val)?
##   2. Is the literal-value re-check "d->d_tag == DT_AUXILIARY || d->d_tag
##      == DT_FILTER" (dl-deps.c:266) ever reached for the top-level object,
##      and does it ever actually match (i.e. does the branch BODY at
##      dl-deps.c:271, right before the openaux() call that would load an
##      auxiliary library, ever get entered)?
##
## Why "args.map" instead of the loop variable "l": this build is compiled
## -Og and GDB reports "l" as <optimized out> at every line we care about
## (verified empirically -- see run log). However dl-deps.c:216 does
## `args.map = l;` right when the l_info gate (line 208) is entered, and
## `args` is a stack-resident struct (its address is taken for
## _dl_catch_exception), so args.map is a reliable, always-visible proxy for
## the value of `l` for the remainder of that gate's body. We confirmed
## `args.map == map` (the function's own top-level parameter, i.e. the
## object requested by the caller) picks out exactly one iteration: the
## pass that processes the target ELF file itself, not any of its
## dependencies (e.g. libc.so.6) that also flow through this same loop.
##
## l_info[] slot indices (computed from elf.h / dl-dtprocnum.h constants for
## x86_64, and cross-checked against the source's AUXTAG/FILTERTAG macros):
##   DT_NEEDED  -> index 1
##   AUXTAG     -> index 60   (DT_NUM=38 + DT_THISPROCNUM=4 + DT_VERSIONTAGNUM=16 + DT_EXTRATAGIDX(DT_AUXILIARY)=2)
##   FILTERTAG  -> index 58   (... + DT_EXTRATAGIDX(DT_FILTER)=0)

# --- BP @ dl-deps.c:222 (top of the DT_NEEDED-processing for-loop, reached
#     only if the line-208 gate was true) -- report l_info[] state once for
#     the top-level object, then keep going.
break dl-deps.c:222 if args.map == map
commands
  silent
  printf "\n=== [BP222] scanning one dynamic-array entry of the TOP-LEVEL object (args.map == map); l_info gate at line 208 WAS TRUE to get here at all ===\n"
  printf "l_name (empty string = the main executable itself) = \"%s\"\n", args.map->l_name
  printf "l_info[DT_NEEDED]  (idx 1)  = %p\n", args.map->l_info[1]
  printf "l_info[AUXTAG]     (idx 60) = %p\n", args.map->l_info[60]
  printf "l_info[FILTERTAG]  (idx 58) = %p\n", args.map->l_info[58]
  if args.map->l_info[60]
    printf "  -> AUXTAG slot is NON-NULL. Pointee Elf64_Dyn: d_tag=%#lx d_val=%#lx\n", *(long*)args.map->l_info[60], *((long*)args.map->l_info[60]+1)
  else
    printf "  -> AUXTAG slot is NULL (no dynamic entry ever indexed into this slot).\n"
  end
  continue
end

# --- BP @ dl-deps.c:266 (the literal re-check "d->d_tag == DT_AUXILIARY ||
#     d->d_tag == DT_FILTER" against the RAW dynamic array) -- fires once per
#     non-DT_NEEDED dynamic entry scanned for the top-level object. Logs
#     every d_tag value the check was evaluated against.
break dl-deps.c:266 if args.map == map
commands
  silent
  printf "[BP266] else-if(d_tag==DT_AUXILIARY(0x7ffffffd) || d_tag==DT_FILTER(0x7fffffff)) EVALUATED.  d->d_tag = %#lx\n", (long)d->d_tag
  continue
end

# --- BP @ dl-deps.c:271 (first statement INSIDE that else-if's body) --
#     only reached if the line-266 check actually MATCHED. This is the code
#     path that leads directly to the openaux() call at dl-deps.c:287, i.e.
#     an actual auxiliary/filter library load.
break dl-deps.c:271 if args.map == map
commands
  silent
  printf "[BP271] *** AUXILIARY/FILTER BRANCH BODY ENTERED (openaux() about to run) ***  d->d_tag = %#lx\n", (long)d->d_tag
  continue
end

run
printf "\n=== target process exited; gdb script complete. BP271 hit count above (0 hits printed = never entered). ===\n"
