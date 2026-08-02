# V1 entrypoint selection — which ld.so parse each walk mirrors

> Scope: this file justifies the ld.so dynamic-parsing walks implemented in
> `asan_harness.c`, in build order, and states the precondition each imposes under
> the harness's single-clamp (`in_map`) trust model. Design authority:
> `docs/PIPELINE_VARIANTS.md` §V1 (kills W1). Confirmation authority: CASR + Tier-B
> stock replay via `lfuzzer/triage/tri_oracle.py` (§V5).

---

## The selection axis

We pick walks by **signal-per-clamp-cost**, not by "most code". A deeper loader
function reaches more logic but demands more load state to be faithfully present —
and every missing invariant is a **phantom-bug** generator. So the order is:
purest parser first, full mapper last.

```
             clamp/precondition cost ─────────────────────────────────────▶ high
   EP1 get_dynamic_info      EP2 check_map_versions    EP3 _dl_map_object_from_fd
   (pure DT_ tag transform)  (needs EP1's tag table)   (would mmap attacker PT_LOADs)
   ◀──────────────────────   signal purity / start here
```

The harness's `in_map(off,size)` clamp (guard the **start** of a dereference, let
the **body** overshoot into the ASan redzone) is what keeps EP1/EP2 phantom-free:
an in-bounds-start structure whose tail runs off the end is a *real* over-read,
while a wild far pointer is skipped instead of faked into a useless segv.

---

## EP1 — `get_dynamic_info`  ⟵ DEFAULT FIRST TARGET

| | |
|---|---|
| Mirrors | `elf_get_dynamic_info` — `elf/get-dynamic-info.h` (static inline) |
| What it does | Walks the `Elf64_Dyn` array at `PT_DYNAMIC`'s `p_offset`, indexes each `DT_*` tag into a local table (`di`), trusting `d_val` exactly like the loader fills `l_info[]` |
| Why first | Near-pure transform over exactly the bytes we splice. No fd, no mmap, no recursion. Smallest precondition, cheapest per-input → best exec/s. |
| Precondition | `find_dynamic` located a `PT_DYNAMIC` whose `p_offset` is `in_map`. Array count trusts `p_filesz/sizeof(Dyn)`, capped by `size` (hang guard, not safety guard). |
| Over-read spots | a `Dyn[i]` whose body crosses the image end (bogus `p_filesz`); the table walk aborts at the first out-of-range entry under ASan. |
| Gated real call | `build_harness.sh glibc` → `-DUSE_GLIBC_INTERNAL`; a live `elf_get_dynamic_info(l, false, false)` needs the in-tree `struct link_map.l_info[]` (glibc-TU build). |

---

## EP2 — `check_map_versions` (verneed / vernaux / versym walk)

| | |
|---|---|
| Mirrors | `_dl_check_map_versions` — `elf/dl-version.c` |
| What it does | From `DT_VERNEED` (+ `DT_VERNEEDNUM`) walks a chain of `Elf64_Verneed` via `vn_next`, and per record a chain of `Elf64_Vernaux` via `vn_aux`/`vna_next`, dereferencing `vn_file` and `vna_name` into `.dynstr` (`touch_dynstr`) |
| Why second | Highest research interest: the analyzer-side analogue (`llvm-objdump getVersionDependencies` VERNEED DoS) is already a confirmed candidate here (memory: `project_elf_parser_diff`), and the **loader-side** verneed walk is under-fuzzed (PIPELINE_VARIANTS §0.2 NOT-FOUND). |
| Precondition | **EP1 first** to set `have_verneed`/`verneed`/`have_strtab`/`strtab`. Records live at the trusted `DT_VERNEED` file offset. |
| Skip rule | No `DT_VERNEED` ⇒ nothing to walk — **skip, not a miss** (`if (!di->have_verneed) return;`). |
| Over-read spots | (1) a `Verneed`/`Vernaux` record tail past the image end; (2) `vn_file`/`vna_name` index past `.dynstr` → the classic dynstr redzone hit; (3) a `vn_next`/`vna_next` into a truncated tail. Chains are iteration-capped by `size` purely to stop cyclic-offset hangs. |

---

## EP3 — `_dl_map_object_from_fd`  ⟵ separate, gated concept

| | |
|---|---|
| Mirrors | `elf/dl-load.c` — the full map path: given an fd, `mmap`s PT_LOADs, locates PT_DYNAMIC, then calls the EP1/EP2 machinery |
| In this harness | We do **not** mmap attacker PT_LOADs. `find_dynamic` performs only the faithful **phdr scan** for `PT_DYNAMIC` (the front half of the map path) over the in-memory image; the actual segment `mmap` is intentionally **not** reproduced. |
| Why gated | A real `mmap` of a mutated PT_LOAD legitimately maps (or refuses) memory, so the "structure is in-bounds by construction" guarantee that keeps EP1/EP2 phantom-free **does not hold**. Phantom risk is intrinsic. |
| Discipline | If ever added, enable only behind an env flag and lean HARD on Tier-B stock replay to separate real map-path bugs from harness artifacts. Do **not** make it the default loop. |

---

## Precondition summary (why single-clamp, not build-from-bytes)

Fabricating a `link_map` from raw fuzz bytes points the parsers at memory we never
mapped → every crash is a phantom. The self-contained harness instead copies the
input into a **tight ASan allocation** and applies the loader's own arithmetic
with a single `in_map` start-clamp standing in for the real mapping bounds:
in-bounds-start structure in → a body-overshoot out is a real loader-shaped
defect. See `asan_harness.c` §0 (`in_map`, `touch_dynstr`) and §5
(`parse_elf64_like_ldso`).

---

## Reporting category produced here (feeds V5/CASR, never the raw metric)

An ASan fire is a **candidate**. Tier-B (`lfuzzer.triage.tri_oracle`) replays the
saved input under stock `ld.so` (`config.LOADER`) and the debug+assert loader
(`config.LFUZZER_DEBUG_LOADER`); `confirmed` = reproduces as signal/timeout on
stock **OR** assert-fires on debug.

```
ASAN + stock CRASHES        → crashing loader bug (both oracles agree)
ASAN + stock CLEAN          → "ASAN-CONFIRMED / STOCK-CLEAN"  ← the V1-unique row
                              (silent OOB the baseline QEMU loop can't see = W1)
ASAN clean + stock CRASHES  → not a V1 find (crash oracle's territory)
ASAN + debug-loader assert  → corroborating third signal
```

CASR does dedup/adjudication; MCP/LLM is advisory-only and any LLM claim without a
cited tool result is dropped (PIPELINE_VARIANTS §4).

---

## Citations

- AFL++ / persistent mode / CMPLOG — Fioraldi, Maier, Eißfeldt, Heuse, **WOOT'20**,
  "AFL++: Combining Incremental Steps of Fuzzing Research"
  (usenix.org/system/files/woot20-paper-fioraldi.pdf)
- LLVM libFuzzer — llvm.org/docs/LibFuzzer.html
- AFL++ persistent mode + dictionaries + CMPLOG — AFLplusplus.github.io
- glibc internals — `elf/get-dynamic-info.h`, `elf/dl-version.c`, `elf/dl-load.c`
  (source-of-truth for signatures; verify against your checked-out glibc version)
