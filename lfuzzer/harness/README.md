# lfuzzer / harness — V1: real-sanitizer, in-process ld.so target

> **Insight first:** V1 is the *honest core* of the pipeline. It doesn't invent a
> new bug class — it makes every later variant's finds **fast and memory-visible**.
> It replaces the baseline W1's two liabilities (QEMU whole-process exec + a *fake*
> ASan) with one **in-process persistent loop under a real `-fsanitize=address`
> oracle**. This directory is now a **working harness**, not a skeleton: the
> guaranteed build path is self-contained (no glibc build required) and compiles +
> runs under `clang -fsanitize=address,fuzzer` and `afl-clang-fast`.

```
harness/
├── README.md              ← you are here (why V1, trust model, reporting, plug-in)
├── entrypoints.md         ← which ld.so parser each walk mirrors + preconditions
├── asan_harness.c         ← self-contained ld.so-faithful ELF64 walk (LLVMFuzzerTestOneInput)
├── build_harness.sh       ← builds v1_libfuzzer / v1_afl(+cmplog) / v1_demo / v1_glibc
├── corpus_from_crashes.sh ← seeds ./corpus/ from real crash ELFs (valid \x7fELF only)
└── elf.dict               ← AFL/libFuzzer dictionary of ELF tokens (49 entries)
```

---

## Why V1 (kills W1)

The baseline (`docs/PIPELINE_VARIANTS.md` §1) fuzzes **raw production
`/lib64/ld-linux-x86-64.so.2`** under **AFL++ QEMU**. Two defects, jointly = W1:

```
baseline (W1)                             V1
────────────────────────────────────────  ────────────────────────────────────
whole-process exec per input (QEMU)   ──▶  in-process persistent loop
  = slow                                     100–1000x exec/s (WOOT'20 persistent)
"ASan" = debug+assert rerun           ──▶  real -fsanitize=address
  (rerun_debug_ldso.py)                      sees NON-crashing memory corruption
  → blind to silent heap/stack OOB           → the STOCK-CLEAN category becomes
                                               observable at all
```

The debug-loader rerun only surfaces bugs that trip an `assert` or crash. A heap
OOB **read** in the verneed walk that lands in mapped memory returns "clean"
everywhere in the baseline. Real ASan is what makes it a finding.

---

## What it does (self-contained, ld.so-faithful)

`asan_harness.c` re-implements — faithfully and deliberately **un-hardened** — the
exact pointer walks ld.so performs over an ELF's program headers, `.dynamic`
array, symbol table, and symbol-version tables. Each walk is commented with the
loader function it mirrors:

| walk (function) | mirrors ld.so | glibc site |
|---|---|---|
| `find_dynamic` | `open_verify` → `_dl_map_object_from_fd` (phdr scan for PT_DYNAMIC) | `elf/dl-load.c` |
| `get_dynamic_info` | `elf_get_dynamic_info` (`.dynamic` → tag table) | `elf/get-dynamic-info.h` |
| `touch_symbols` | `.dynsym`/`.dynstr` consumers (`symtab+i*syment`, `strtab+st_name`) | `elf/dl-lookup.c` |
| `check_map_versions` | `_dl_check_map_versions` (verneed/vernaux/versym chain) | `elf/dl-version.c` |

The input bytes are copied into a **tight ASan heap allocation** (exact size → a
right redzone sits immediately after the last real byte). An out-of-bounds *read*
that ld.so would perform silently trips that redzone here and is reported.

---

## The trust model — the whole point (replaces the old fixture story)

ld.so's dynamic parsers do **not** validate attacker-controlled offsets/sizes/
counts. They read `DT_STRTAB` / `DT_SYMTAB` / `DT_VERNEED` / `p_offset` /
`vn_next` / `vna_name` and dereference `base + value` on trust. The harness
mirrors that trust **exactly, with ONE concession**:

```
in_map(off, size)  ≡  off <= size      ← guard the START of a dereference only.
                                          NOT off+len<=size.
```

That single clamp is **not hardening** — it is the substitute for the real
mapping bounds a genuine `mmap` load would enforce. It draws a sharp line:

```
┌─ start off > size (wild, e.g. d_val=0x40_0000_0000) ─▶ SKIP  (a useless far segv,
│                                                                not the bug we want)
└─ start off in-bounds, BODY overshoots the image end ─▶ ASan redzone hit = REPORT
     (Verneed/Vernaux record tail, a non-terminated .dynstr string, phnum too large)
```

Sequential scans (`phdr[i]`, `Dyn[i]`, vernaux chains) are **self-limiting under
ASan**: the first entry crossing the boundary aborts the process, so a bogus
`e_phnum=0xffff` never actually walks 3 MB. Chain caps (`vn_next`/`vna_next`
loops bounded by `size` iterations) are **hang guards, not memory-safety guards**.

This is deliberately narrower than "load an arbitrary mutated ELF": it trades
reach for **signal purity**. V2 (structure-aware input) widens what reaches the
harness; V1's job is to make what reaches it trustworthy.

**Empirically verified on this tree (clang 18.1.3):** a valid template
(`templates/prac.elf`) walks clean (exit 0); 300 stock-`ld.so` sig11 crashers
replayed one-shot produce **0** ASan fires (their wild pointers are clamped to
skips — a different bug class); and libFuzzer's coverage-guided mutation *does*
fire, e.g. `heap-buffer-overflow in find_dynamic` — a genuine in-bounds-start /
body-overshoot over-read. That gap is exactly the STOCK-CLEAN category W1 is blind to.

---

## Build (all verified working)

```bash
./build_harness.sh                # builds every target the toolchain supports
./build_harness.sh libfuzzer      # subset: A only
./build_harness.sh afl            # subset: B only  (slower; compiles libAFLDriver)
```

| target | command it runs | output |
|---|---|---|
| **A** libFuzzer | `clang -g -O1 -fsanitize=address,fuzzer asan_harness.c` | `build/v1_libfuzzer` |
| **B** AFL++ | `AFL_USE_ASAN=1 afl-clang-fast -fsanitize=fuzzer asan_harness.c` (persistent, links `/usr/lib/afl/libAFLDriver.a`; also builds a `AFL_LLVM_CMPLOG=1` sibling) | `build/v1_afl`, `build/v1_afl_cmplog` |
| demo | `clang -fsanitize=address -DHARNESS_STANDALONE_DEMO` | `build/v1_demo` |
| **G** glibc (gated) | finds `get-dynamic-info.h` under `$GLIBC_SRC`, adds `-DUSE_GLIBC_INTERNAL -DGLIBC_SRC_ELF=<dir> -I<dir>` | `build/v1_glibc` |

> Note on mode B: the harness has **no** AFL persistent `main()` of its own — it
> exposes `LLVMFuzzerTestOneInput`, so AFL++ drives it via its libFuzzer-compat
> driver (`-fsanitize=fuzzer`). Plain `afl-clang-fast -fsanitize=address` would
> fail to link (`undefined reference to main`); the script uses the correct form.

**Gated glibc-internal path (SECOND option).** `build_harness.sh glibc` locates
the real `get-dynamic-info.h` under `$GLIBC_SRC` (default `~/glibc`) and compiles
with the gate on. If the header is absent it prints a clear message and skips —
the guaranteed A/B builds are unaffected. A **live** `elf_get_dynamic_info()` call
still needs a full glibc-TU build (glibc's private include/define set:
`_RTLD_LOCAL_`, `IS_IN(rtld)`, `dl-machine-rel.h`, the internal `struct link_map`
with `l_info[]`); the gate proves the include path and degrades honestly short of
that, exactly as designed. Located here: `~/glibc/glibc-src/elf/get-dynamic-info.h`.

---

## Seed the corpus

```bash
./corpus_from_crashes.sh          # -> ./corpus/  (all valid \x7fELF, content-deduped)
```

Mirrors `../../rebuild_seeds.sh`'s categorized sampling, retargeted at the
directory-of-inputs the in-process harness wants:

```
out_dynamic_v3/*.elf   ─┐  (main pool, N_DYNAMIC=400 random)
out_*/**/crashes*/id:* ─┼─▶  ./corpus/   filter: head -c4 == \x7fELF
templates/*.elf        ─┘  (valid baselines → good mutation starting structure)
```

Then: `./build/v1_libfuzzer corpus/ -dict=elf.dict` (loads 49 dictionary
entries) or `afl-fuzz -i corpus -o out -x elf.dict -c build/v1_afl_cmplog -- build/v1_afl @@`.

---

## Reporting category: "ASAN-CONFIRMED / STOCK-CLEAN" (+ Tier-B)

An in-process ASan fire is a **candidate**, never a confirmed unique bug. The
harness only writes the ASan report + the firing input to disk. Out of the hot
loop, **Tier-B** replays the saved input through `lfuzzer.triage.tri_oracle`,
which runs it under **stock `ld.so`** (`config.LOADER`) and the **debug+assert
loader** (`config.LFUZZER_DEBUG_LOADER`). tri_oracle's `confirmed` rule:
**reproduces as signal/timeout on stock OR assert-fires on debug** (gold/bfd diff
is corroborating only).

```
┌─ ASAN + stock CRASHES        → crashing loader bug (both oracles agree)
├─ ASAN + stock CLEAN          → ★ "ASAN-CONFIRMED / STOCK-CLEAN" — the V1-UNIQUE
│                                 category: a silent OOB the baseline QEMU loop is
│                                 blind to (W1). High value, but must pass
│                                 in_map-artifact review before it counts.
├─ ASAN clean + stock CRASHES  → not a V1 find (crash oracle's territory)
└─ ASAN + debug-loader assert  → corroborating third signal
```

**CASR is authoritative** for dedup/severity; **MCP/LLM is advisory-only** and any
LLM claim without a cited tool result is dropped (`PIPELINE_VARIANTS` §4/§V5). The
harness never adjudicates.

---

## How it plugs into `unified_runner` (collect-once → dual oracle)

`docs/UNIFIED_PIPELINE.md` defines **collect-once → dual oracle**: one observation
vector per mutant feeds a crash oracle and a divergence oracle. V1 slots in as a
**faster, memory-aware producer** of the `ld_so` leg, plus a new oracle row:

```
mutant ──▶ unified_runner (orchestrator/unified_runner.py, UNIFIED_PIPELINE §5)
             ├─ ld.so leg     ──▶ [V1] in-process ASan harness  (hot loop, TIER-1)
             │                       → emits ASan report + input on fire
             ├─ gold/bfd legs ──▶ existing differential (unchanged)
             └─ analyzer legs ──▶ readelf/objdump digests (unchanged)
                                     │
   ASan-firing inputs (few) ────────┘──▶ TIER-2 (survivors only):
                                         Tier-B stock/debug replay (tri_oracle)
                                         → category → CASR dedup/severity → V5 ledger
```

Cheap ASan fires stay in the tier-1 hot loop (persistent, no Ghidra); only
survivors pay for Tier-B + CASR + Ghidra (tier-2) — exactly the 2-tier split in
`UNIFIED_PIPELINE` §4. V1 does not replace the crash/divergence oracles; it
upgrades the loader leg they share and adds the STOCK-CLEAN row they couldn't see.
Build order across variants: **V5 → V1 → V2 → V3 → V4**; this is V1.

---

## Citations

- **AFL++ + persistent mode + CMPLOG** — Fioraldi, Maier, Eißfeldt, Heuse, *AFL++:
  Combining Incremental Steps of Fuzzing Research*, **USENIX WOOT'20** —
  usenix.org/system/files/woot20-paper-fioraldi.pdf
- **libFuzzer** (in-process persistent fuzzing, `LLVMFuzzerTestOneInput` /
  `LLVMFuzzerInitialize`, `-dict`) — llvm.org/docs/LibFuzzer.html
- **AFL++ persistent mode** (`afl-fuzz`, `libAFLDriver`, `-x` dictionaries, `-c`
  CMPLOG) — AFLplusplus.github.io / docs/fuzzing_in_depth.md
- **glibc internals** — `elf/get-dynamic-info.h`, `elf/dl-version.c`,
  `elf/dl-load.c` (source-of-truth for signatures; verify against your checkout)
- Project design — `docs/PIPELINE_VARIANTS.md` (§V1 kills W1; §V5 oracle
  authority), `docs/UNIFIED_PIPELINE.md` (collect-once → dual oracle, 2-tier),
  `lfuzzer/triage/tri_oracle.py` (Tier-B confirmation)
