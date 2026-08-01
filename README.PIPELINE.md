# Pipeline: collect-once dual-oracle differential fuzzer

> Section linked from the main README. Design docs: [`docs/UNIFIED_PIPELINE.md`](docs/UNIFIED_PIPELINE.md) ·
> [`docs/PIPELINE_VARIANTS.md`](docs/PIPELINE_VARIANTS.md) · [`docs/ARCHITECTURE.html`](docs/ARCHITECTURE.html).

`lfuzzer` is a coverage-guided **differential** fuzzer for the ELF load/link path:
glibc **`ld.so`** and binutils **`gold`** / **`bfd`**. AFL++ is the search engine; coverage is engine
health, **not** a result metric.

---

## Collect-once, dual-oracle

The two flows the project ran separately — **A: crash hunting** and **B: gold-vs-bfd divergence
observation** — only ever shared one node: *"execute the mutant."* Running that execution twice is
pure waste. The unified design executes **once per mutant**, collects one observation vector, and
lets **two oracles feed on the same vector** ("collect-once, feed many oracles" = N-version
differential). Half the execution cost, both signals at once.

```
mutant ─▶ ONE execution ─▶ observation vector
                            { ld_so:{rc,signal}, gold:{link_rc,run_rc,sig},
                              bfd:{link_rc,run_rc,sig}, readelf:digest, objdump:digest }
                                     │
             ┌───────────────────────┴───────────────────────┐
      Oracle 1: CRASH                          Oracle 2: DIVERGENCE (parallel)
      gold/bfd run rc<0 or timeout(124)        gold≠bfd (runtime / link-time),
      → crashes/ + gdb `bt` triage             loader≠analyzer, analyzer≠analyzer
      → key = "SIGNAL:frame"                   → divergence/ + type rank
```

**Two tiers.** Ghidra headless costs 30–60 s just to start, so it cannot live in the hot loop.
- **Tier 1 (hot loop, all cheap):** `ld.so`, `gold`, `bfd`, `readelf`, `objdump`.
- **Tier 2 (survivors only):** Ghidra (`DumpDynamic.java`) + deep `gdb` + human, run only on the few
  inputs an oracle flagged as interesting.

---

## Build order — V5, V1, V2, V3, V4(glue)

Ordered by ROI (unique confirmed bugs / CPU-hour), cheapest-and-highest first. The five variants are
a **phase decomposition** of one SOTA control (AFL++ LTO+CMPLOG + libFuzzer/ASan + Nezha + CASR), not
competitors to it.

| # | Variant | One line |
|---|---|---|
| **V5** | Evidence-based triage | CASR-authoritative dedup + in-loop tri-oracle auto-confirmation; makes the metric deterministic **before** measuring any later gain. MCP/LLM advisory-only. |
| **V1** | Real instrumented target | LTO source build + real ASan + persistent/in-process harness → ~100–1000x exec/s and visibility into non-crashing memory bugs (the QEMU "fake ASAN" blind spot). |
| **V2** | Structure-aware input | FormatFuzzer-style binary templates + AFLSmart chunk-aware DT_ mutation + CMPLOG → pass the ELF magic/header gate, reach deep `PT_DYNAMIC`/verneed fields. |
| **V3** | Differential in-loop | Nezha δ-diversity oracle over {ld.so, gold, bfd}, divergence injected as virtual edges so asymmetry steers the search (not a post-hoc offline track). |
| **V4** | Ensemble + feedback (**glue only**) | Heterogeneous-corpus sync + self-feeding cmin/tmin back-edge daemon binding V1+V2+V3 into one loop. **No monolithic QEMU-only build** (that regresses the ASan oracle). |

---

## Current status (real vs scaffolded)

| State | What exists |
|---|---|
| **Implemented (V5)** | Triage logic ships today as the wrapped original scripts under `lfuzzer/analysis/`: `auto_gdb_classify.py`, `triage_v3.py`, `rerun_debug_ldso.py` (debug+assert glibc `ld.so`), plus the `sprint1–3` / `auto_followup` / `triage_*` shell drivers. The gold-vs-bfd differential experiments (`lfuzzer/differential/exp_*`, `parser_diff/`) also run. |
| **Scaffolded** | The dedicated module homes below (V1/V2/V3 + the unified top loop) are **designed in the docs but not yet coded** — no source files exist for them yet. |

> Scaffolded means: specified in `docs/UNIFIED_PIPELINE.md` / `docs/PIPELINE_VARIANTS.md`, dependencies
> present in the tree to reuse, but the module itself is not written. All existing code imports cleanly
> with external tools (casr, gdb, debug loader, gold/bfd) absent, degrading gracefully.

### Module map (new)

| Module | Variant | Role | Status |
|---|---|---|---|
| `lfuzzer/triage/` | V5 | Formalize the wrapped `analysis/` triage into a CASR-authoritative dedup + tri-oracle confirmation package. | Scaffolded (logic present in `analysis/`) |
| `lfuzzer/harness/` | V1 | libFuzzer+ASan / persistent harness at `ld.so` parse entrypoints (`_dl_map_object_from_fd`, `elf_get_dynamic_info`, verneed/versym). | Scaffolded |
| `lfuzzer/mutators/structure_aware` | V2 | Binary-template + chunk-aware mutator (validity gradient: valid enough to parse, broken enough to fault). | Scaffolded |
| `lfuzzer/differential/nezha_oracle` | V3 | Nezha δ-diversity differential oracle over {ld.so, gold, bfd}; emits virtual coverage edges. | Scaffolded |
| `lfuzzer/orchestrator/unified_runner` | V4 / glue | Thin top loop: collect the observation vector once, dispatch both oracles, feed survivors to Tier 2. | Scaffolded |

---

## Novelty finding (2026-08-01)

Web research across 2022–2026 top venues (USENIX / NDSS / S&P / CCS / WOOT / FSE / ISSTA) found
**no peer-reviewed paper that specifically fuzzes `ld.so` or the `gold`/`bfd` linker** (NOT-FOUND).
OSS-Fuzz binutils targets only BFD-library entrypoints (`readelf`/`objdump`/`nm`/`objcopy`), **not**
`ld`/`gold` link-time behavior; glibc+ASan+libFuzzer is documented as possible but manual (not turnkey).
→ **gold-vs-bfd / `ld.so` differential loader+linker fuzzing is effectively unclaimed at top venues.**
Caveat: absence of search results ≠ proof of absence — manual ACM DL / IEEE Xplore confirmation is the
next step. (Note: USENIX Sec 2025 "ELFuzz" is a *false friend* — LLM grammar-fuzzer synthesis evaluated
on cvc5, unrelated to the ELF format or `ld.so`.)

---

## Metric & the LLM boundary

- **Primary metric = unique CONFIRMED bugs** (per CPU-hour). Coverage is AFL engine health, a means, not
  a score. Differential yield is a secondary signal.
- **CASR is authoritative** for the unique set and severity (read-only). Cross-implementation dedup
  (gold≠bfd = different codebases) uses per-implementation CASR scores + Nezha δ-diversity, because a
  raw stack hash is meaningless across codebases.
- **MCP / LLM are advisory ONLY — never adjudicate.** Every LLM claim must cite a tool result (CASR
  report, `bt`, field diff, gcov); **any claim without a cited tool-result is DROPPED.** Metric numbers
  never read the LLM → reproducible, deterministic. The LLM only splits mis-merged buckets and drafts
  natural-language repro/cross-oracle hypotheses.
