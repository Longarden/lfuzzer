# V1 entrypoint selection — which ld.so parsing function to fuzz first

> Scope: this file justifies the three ld.so dynamic-parsing entrypoints wired in
> `asan_harness.c`, in build order, and states the precondition each one imposes
> on the captured-link_map fixture. Design authority: `docs/PIPELINE_VARIANTS.md`
> §V1 (kills W1). Confirmation authority: CASR + Tier-B stock replay (§V5).

---

## The selection axis

We pick entrypoints by **signal-per-fixture-cost**, not by "most code". A deeper
function reaches more loader logic but demands more load state to be faithfully
reconstructed — and every unreconstructed invariant is a **phantom-bug**
generator. So the order is: purest parser first, full mapper last.

```
             fixture cost / phantom risk  ──────────────────────────▶ high
   EP1 elf_get_dynamic_info   EP2 verneed walk        EP3 _dl_map_object_from_fd
   (pure DT_ table transform) (needs EP1's l_info)    (maps attacker PT_LOADs)
   ◀────────────────────────  signal purity / start here
```

---

## EP1 — `elf_get_dynamic_info`  ⟵ DEFAULT FIRST TARGET

| | |
|---|---|
| Location | `elf/get-dynamic-info.h` (static inline, #include'd by the harness TU) |
| What it does | Walks the PT_DYNAMIC `ElfW(Dyn)` array, indexes each `DT_*` tag into `l->l_info[]`, relocates pointer-valued tags by `l_addr`, light `DT_*NUM` bounds checks |
| Why first | Near-pure transform over exactly the bytes we mutate. No fd, no mmap, no recursion into other DSOs. Smallest fixture, cheapest reset → best exec/s. |
| Fixture precondition | A valid `link_map` whose `l_ld` points at the carrier's real, mapped PT_DYNAMIC window (the writable region `fixture_splice` targets). `l_addr` must be the carrier's true load bias so relocated `DT_` pointers land in-bounds. |
| Phantom guard | Mutation is clamped to the owned `dyn_capacity`; pointer tags resolve into the carrier's mapping, so an OOB means the parser mis-walked *in-bounds* structure. |
| Call | `elf_get_dynamic_info(carrier, /*bootstrap*/0, /*static_pie_bootstrap*/0)` |

---

## EP2 — verneed / version walk

| | |
|---|---|
| Location | `elf/dl-version.c` : `_dl_check_map_versions` (walks `Elf_Verneed` `vn_next`/`vn_aux` → `Elf_Vernaux` `vna_next`, cross-indexes `DT_VERSYM` vs `DT_STRTAB`) |
| What it does | Resolves symbol-version dependencies declared in `DT_VERNEED`; historically bug-rich pointer-chain walk over attacker-influenced counts/offsets |
| Why second | Highest research interest: the analyzer-side analogue (`llvm-objdump getVersionDependencies` VERNEED DoS) is already a confirmed candidate in this project (`project_elf_parser_diff`), and the **loader-side** verneed walk is under-fuzzed in the literature (PIPELINE_VARIANTS §0.2 NOT-FOUND). |
| Fixture precondition | **EP1 must run first** to populate `l_info[DT_VERNEED]`, `DT_VERNEEDNUM`, `DT_STRTAB`, `DT_VERSYM`. The `Elf_Verneed` records live at `l_addr + DT_VERNEED`, inside the carrier mapping. |
| Skip rule | If `l_info[VERSYMIDX(DT_VERNEED)]` is NULL after EP1, there is no verneed — **skip, don't count as a miss.** |
| Call | `_dl_check_map_versions(carrier, /*verbose*/0, /*trace_mode*/0)` |

---

## EP3 — `_dl_map_object_from_fd`  ⟵ separate, gated mode

| | |
|---|---|
| Location | `elf/dl-load.c` |
| What it does | Given an fd, `mmap`s the PT_LOAD segments, locates PT_DYNAMIC, then calls the EP1/EP2 machinery — the closest thing to production loading |
| Why last / gated | **It performs the mapping itself.** A mutated PT_LOAD legitimately maps (or refuses) memory, so the "structure is in-bounds by construction" guarantee that keeps EP1/EP2 phantom-free **does not hold**. Phantom risk is intrinsic here. |
| Fixture | Not the carrier-splice fixture — instead `memfd_create()` the raw input as an fd and pass it in. Many internal args (`name, origname, fd, fbp, realname, loader, l_type, mode, stack_endp, nsid`). |
| Discipline | Enable only behind an env flag; lean HARD on Tier-B stock replay to separate real map-path bugs from fixture artifacts. Do **not** make EP3 the default loop. |

---

## Fixture summary (why capture-and-replay, not build-from-bytes)

Building a `link_map` from raw fuzz bytes points the parsers at memory we never
mapped → every crash is a phantom. Instead: **one real load of a benign carrier
DSO** produces a valid `link_map` + valid mappings; per input we overwrite only
the carrier's already-mapped PT_DYNAMIC window (clamped) and re-run the parser.
In-bounds structure in → an OOB out is a real loader defect. See
`asan_harness.c` §0–§1.

---

## Reporting category produced here (feeds V5/CASR, never the raw metric)

An ASan fire is a **candidate**, not a confirmed bug. Tier-B replays the saved
input under stock `ld.so` (`config.LOADER`) and the debug+assert loader
(`config.LFUZZER_DEBUG_LOADER`):

```
ASAN + stock CRASHES        → crashing loader bug (both oracles agree)
ASAN + stock CLEAN          → "ASAN-CONFIRMED / STOCK-CLEAN"  ← the V1-unique row
                              (silent OOB the baseline QEMU loop can't see = W1)
ASAN clean + stock CRASHES  → not a V1 find (crash oracle's territory)
ASAN + debug-loader assert  → corroborating third signal
```

CASR does the dedup/adjudication; MCP/LLM is advisory-only and any LLM claim
without a cited tool result is dropped (PIPELINE_VARIANTS §4).

---

## Citations

- AFL++ / persistent mode / CMPLOG — Fioraldi, Maier, Eißfeldt, Heuse, **WOOT'20**, "AFL++: Combining Incremental Steps of Fuzzing Research" (usenix.org/system/files/woot20-paper-fioraldi.pdf)
- LLVM libFuzzer — llvm.org/docs/LibFuzzer.html
- glibc internals — `elf/get-dynamic-info.h`, `elf/dl-version.c`, `elf/dl-load.c` (source-of-truth for signatures; verify against your checked-out glibc version)
