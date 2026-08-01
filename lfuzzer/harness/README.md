# lfuzzer / harness — V1: real-sanitizer, in-process ld.so target

> **Insight first:** V1 is the *honest core* of the pipeline. It doesn't find a
> new bug class by itself — it makes every later variant's finds **fast and
> memory-visible**. It replaces the baseline's two W1 liabilities (QEMU whole-
> process exec + a *fake* ASan) with one in-process persistent loop under a
> **real** `-fsanitize=address` oracle. Build order: **V5 → V1 → V2 → V3 → V4**;
> this is V1.

**This directory is a compilable skeleton + docs, not a working harness.** No
full glibc is built. Everything needing a real glibc symbol or fixture is
`TODO()`-marked so an unfinished path fails loud (at link) instead of silently
no-op'ing. Fill it against a local glibc checkout via `build_harness.sh`.

```
harness/
├── README.md          ← you are here (why V1, reporting category, how it plugs in)
├── entrypoints.md     ← which ld.so parser to fuzz first + fixture preconditions
├── asan_harness.c     ← LLVMFuzzerTestOneInput skeleton + captured-link_map fixture
└── build_harness.sh   ← afl-clang-fast / clang -fsanitize=address,fuzzer builder
```

---

## Why V1 (kills W1)

The baseline (`docs/PIPELINE_VARIANTS.md` §1) fuzzes **raw production
`/lib64/ld-linux-x86-64.so.2`** under **AFL++ QEMU**. Two defects, jointly = W1:

```
baseline                                  V1
────────────────────────────────────────  ────────────────────────────────────
whole-process exec per input (QEMU)   ──▶  in-process persistent loop
  = slow                                     100–1000x exec/s (WOOT'20 persistent)
"ASan" = debug+assert rerun           ──▶  real -fsanitize=address
  (rerun_debug_ldso.py)                      sees NON-crashing memory corruption
  → blind to silent heap/stack OOB           → the STOCK-CLEAN category becomes
                                               observable at all
```

The debug-loader rerun only surfaces bugs that trip an `assert` or crash. A heap
OOB **read** in the verneed walk that happens to land in mapped memory returns
"clean" everywhere in the baseline. Real ASan is what makes it a finding.

---

## What it targets (see `entrypoints.md` for the full rationale)

Three ld.so dynamic-parsing entrypoints, wired easiest→deepest:

| # | entrypoint | glibc TU | role |
|---|---|---|---|
| EP1 | `elf_get_dynamic_info` | `elf/get-dynamic-info.h` | **default** — pure `DT_` table → `l_info[]` transform |
| EP2 | `_dl_check_map_versions` (verneed walk) | `elf/dl-version.c` | needs EP1; the under-fuzzed, bug-rich version-chain walk |
| EP3 | `_dl_map_object_from_fd` | `elf/dl-load.c` | gated mode — full map path, high phantom risk |

---

## Precondition fixture (captured link_map replay) — the phantom-bug guard

ld.so's parsers are **not** standalone: they assume input arrived via a real load
(`l_addr` = true load bias, `l_ld` inside a valid mapping, PT_LOADs mapped). Hand
them a `link_map` fabricated from fuzz bytes and every crash is a **phantom** —
an artifact of a malformed fixture, not a loader bug. Phantoms poison the
unique-bug metric.

**Strategy (`asan_harness.c` §0–§1):**

```
once   ─▶ real-load a benign "carrier" DSO ─▶ valid link_map + valid mappings  (fixture)
per-in ─▶ reset carrier PT_DYNAMIC to pristine
       ─▶ splice mutated bytes into ONLY the carrier's mapped, owned window (clamped)
       ─▶ re-run EP1/EP2 on the SAME valid mapping
result ─▶ in-bounds structure in → an OOB out is a REAL loader defect, not "we
          pointed it at nothing"
```

This trades reach for signal purity on purpose. V2 (structure-aware input)
widens what reaches the harness; V1's job is to make what reaches it trustworthy.

---

## Reporting category: "ASAN-CONFIRMED / STOCK-CLEAN" (+ Tier-B)

An in-process ASan fire is a **candidate**, never a confirmed unique bug. Out of
the hot loop, Tier-B replays the saved input under **stock `ld.so`**
(`config.LOADER`) and the **debug+assert loader** (`config.LFUZZER_DEBUG_LOADER`):

```
┌─ ASAN + stock CRASHES        → crashing loader bug (both oracles agree)
├─ ASAN + stock CLEAN          → ★ "ASAN-CONFIRMED / STOCK-CLEAN" — the V1-UNIQUE
│                                 category: silent OOB the baseline QEMU loop is
│                                 blind to (W1). High value, but must pass
│                                 fixture-artifact review before it counts.
├─ ASAN clean + stock CRASHES  → not a V1 find (crash oracle's territory)
└─ ASAN + debug-loader assert  → corroborating third signal
```

The harness only writes the ASan report + input to disk. **CASR is authoritative**
for dedup/severity; **MCP/LLM is advisory-only** and any LLM claim without a cited
tool result is dropped (`PIPELINE_VARIANTS` §4/§V5). The harness never adjudicates.

---

## How it plugs into `unified_runner`

`docs/UNIFIED_PIPELINE.md` defines **collect-once → dual oracle**: one observation
vector per mutant feeds a crash oracle and a divergence oracle. V1 slots in as a
**faster, memory-aware producer** of the `ld_so` leg of that vector, plus a new
oracle row:

```
mutant ──▶ unified_runner (orchestrator/unified_runner.py, per UNIFIED_PIPELINE §5)
             ├─ ld.so leg        ──▶  [V1] in-process ASan harness  (hot loop, tier-1)
             │                          → emits ASan report + input on fire
             ├─ gold/bfd legs    ──▶  existing differential (unchanged)
             └─ analyzer legs    ──▶  readelf/objdump digests (unchanged)
                                        │
   ASan-firing inputs (few) ───────────┘──▶ TIER-2 (survivors only):
                                            Tier-B stock/debug replay → category
                                            → CASR dedup/severity → V5 ledger
```

Cheap ASan fires stay in the tier-1 hot loop (persistent, no Ghidra); only
survivors pay for Tier-B + CASR + Ghidra (tier-2), exactly the 2-tier split in
`UNIFIED_PIPELINE` §4. V1 does not replace the crash/divergence oracles — it
upgrades the loader leg they share and adds the STOCK-CLEAN row they couldn't see.

---

## Build (skeleton)

```bash
# preflight-only on a fresh checkout: reports missing tools/paths, exits non-zero
HARNESS_ENGINE=afl   ./build_harness.sh     # afl-clang-fast + AFL_USE_ASAN (default)
HARNESS_ENGINE=libf  ./build_harness.sh     # clang -fsanitize=address,fuzzer

# the standalone demo always attempts to compile (proves the skeleton is intact);
# it fails at LINK on the intentional TODO_unimplemented stub until you fill the
# real glibc TU paths + include/define set. That link failure IS the "not done"
# signal — see build_harness.sh §3.
```

Fill `GLIBC_SRC` / `GLIBC_BUILD` and the TODO include/define set, then replace the
guard in `build_harness.sh` §3b with the templated build command. For AFL, also
build the CMPLOG sibling (`AFL_LLVM_CMPLOG=1`) that V2 will lean on.

---

## Citations

- **AFL++ + persistent mode + CMPLOG** — Fioraldi, Maier, Eißfeldt, Heuse, *AFL++: Combining Incremental Steps of Fuzzing Research*, **USENIX WOOT'20** — usenix.org/system/files/woot20-paper-fioraldi.pdf
- **libFuzzer** (in-process persistent fuzzing, `LLVMFuzzerTestOneInput` / `LLVMFuzzerInitialize`) — llvm.org/docs/LibFuzzer.html
- **glibc internals** — `elf/get-dynamic-info.h`, `elf/dl-version.c`, `elf/dl-load.c` (verify signatures against your checked-out glibc version)
- Project design — `docs/PIPELINE_VARIANTS.md` (§V1 kills W1; §V5 oracle authority), `docs/UNIFIED_PIPELINE.md` (collect-once → dual oracle, 2-tier)
