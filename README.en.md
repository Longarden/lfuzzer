# Lfuzzer

**Lfuzzer** is an ELF64 / dynamic-linker (glibc `ld.so`) fuzzer and a **gold-vs-BFD differential research toolkit**. It mutates a valid ELF input across exactly three metadata regions — the **section header table (SHDR)**, the **`.dynamic` array (DT_ tags)**, and the **program header table (PHDR)** — then links the result with two static linkers (`ld.bfd`, `ld.gold`), loads it with the runtime loader (`ld.so`), and inspects it with analyzers (`readelf`, `objdump`, Ghidra) to observe where these tools **diverge**. Its module structure is a deliberate mirror of **Melkor** (Alejandro Hernandez, Black Hat 2014) — the `melkor.c → fuzz_<metadata>.c → generators.c + logger.c` design is the template — reorganized as a Python package with an added **differential-observation layer** that plain Melkor does not have.

> Defensive security research. Lfuzzer exists to find robustness bugs in linkers/loaders/parsers and to characterize how they disagree, not to weaponize them.

> **파이프라인 & 로드맵**: 통합 파이프라인(collect-once → dual oracle)과 개선 실험군(V5→V1→V2→V3→V4) 설계·현황은 [`README.PIPELINE.md`](README.PIPELINE.md) 참고. 상세 설계는 [`docs/UNIFIED_PIPELINE.md`](docs/UNIFIED_PIPELINE.md), SOTA 대조·인용은 [`docs/PIPELINE_VARIANTS.md`](docs/PIPELINE_VARIANTS.md), 시각 도시에는 [`docs/ARCHITECTURE.html`](docs/ARCHITECTURE.html).

---

## Overview

Lfuzzer takes a semi-valid seed ELF, applies **spec-aware mutation + generation** to one of the three targeted metadata regions, and runs it through a pipeline of consumers:

```
              ┌─────────────┐
  seed ELF ──▶│  mutators/  │──▶ mutated ELF ──┬──▶ ld.bfd  (static link)  ┐
              └─────────────┘                  ├──▶ ld.gold (static link)  ├─▶ differential/  ──▶ divergence
                                               ├──▶ ld.so   (runtime load) │      + analysis/  ──▶ triage/classify
                                               └──▶ readelf/objdump/Ghidra ┘
```

The research question is not merely "does it crash?" but **"where do BFD, gold, ld.so, and the analyzers disagree on the same bytes?"** — that gap is the signal.

---

## Why

| Axis | Plain Melkor | Lfuzzer |
|------|--------------|---------|
| **Target** | ELF metadata consumers, generic | **Dynamic linker (`ld.so`) + static linkers (BFD/gold)** specifically |
| **Scope** | All ELF metadata levels | Narrowed to **3 regions**: SHDR · `.dynamic` · PHDR |
| **Signal** | Crash / hang of one consumer | **Differential**: gold vs BFD, linker vs loader, loader vs analyzer |
| **Language** | C | Python (structural mirror, not a port) |

- **Dynamic-linker focus.** `ld.so` runs *every* dynamically linked program and parses attacker-influenceable `.dynamic`/PHDR data at process startup. It is a high-value, under-fuzzed surface.
- **3-region scope.** Restricting to SHDR / `.dynamic` / PHDR keeps mutations shallow enough to stay linkable/loadable (see *dependency levels* below) while covering the metadata that the linker and loader actually act on.
- **Differential angle.** Two independent linker implementations (BFD and gold) plus the loader plus analyzers give an oracle without ground truth: **any disagreement on identical input is a candidate bug**, even when no single tool crashes.

---

## Architecture

Lfuzzer keeps Melkor's role separation. Melkor modules map onto Lfuzzer packages as follows:

| Melkor (C) | Role | Lfuzzer (Python) |
|------------|------|------------------|
| `melkor.c` (main) | orchestrate fuzz + run + triage loop | `lfuzzer/orchestrator/` |
| `fuzz_<metadata>.c` | per-metadata fuzzing **rules** | `lfuzzer/mutators/` |
| `generators.c` + `numbers.h` | emit semi-valid test data | `lfuzzer/generators/` |
| `logger.c` | log which metadata was fuzzed | `lfuzzer/logger/` |
| ELF read primitives | parse ELF structures | `lfuzzer/core/` |
| *(no equivalent)* | **gold-vs-BFD / linker-vs-loader diff** | `lfuzzer/differential/` |
| `test_fuzzed.sh` | run orcs against target + classify | `lfuzzer/analysis/` |

```
lfuzzer/
├── core/            # canonical ELF64 read primitives (Melkor: ELF parsing layer)
│   ├── elf64.py           # u16/u32/u64 readers, read_phdrs, .dynamic walk
│   ├── drivers/common.py  # shared driver helpers
│   └── seeds/extract_phdr.py
├── mutators/        # per-metadata fuzzing RULES (Melkor: fuzz_<metadata>.c)
│   ├── mutate_elf_v4.py        # top-level mutation entrypoint
│   ├── mutator_field_v2.py     # PHT field mutation
│   ├── mutator_dynamic_v3.py   # .dynamic DT_ tag mutation
│   ├── mutator_interp_vaddr_v2.py
│   ├── mutator_shuffle.py      # PHDR entry reordering
│   └── fuzzer_overlap.py       # PT_LOAD segment overlap
├── generators/      # semi-valid value generation (Melkor: generators.c + numbers.h)  ── NEW
│   ├── generators.py
│   └── numbers.py
├── logger/          # records which metadata field was fuzzed (Melkor: logger.c)  ── NEW
│   └── logger.py
├── orchestrator/    # autonomous fuzz+triage loop (Melkor: melkor.c main)
│   ├── autorun_v3.py      # fuzz → link → run → triage loop
│   └── lfuzzer.py         # run_elf helper
├── differential/    # Lfuzzer-unique: gold vs BFD / linker vs loader / analyzer diff
│   ├── exp_goldbfd_diff/  # common.py + exp_d01..d24 + exp_r1..r8 + exp_display_all.py
│   │   └── ghidra_scripts/DumpDynamic.java
│   ├── parser_diff/       # static-parser differential replay
│   ├── exp_e1..e6/        # focused case studies (runpath, pie, shdrstrip, verneed, dupsoname, auxtag)
│   └── tag_exp/
├── analysis/        # triage + classification (Melkor: test_fuzzed.sh)
│   ├── auto_gdb_classify.py    # gdb-driven crash bucketing
│   ├── strace_classify.py
│   ├── analyze_crashes.py
│   ├── triage_v3.py
│   ├── rerun_debug_ldso.py
│   └── drivers/{triage,verify}.py
├── exploit/         # PoC / robustness study for confirmed findings
│   ├── exploit_analyze_dtors.py
│   ├── exploit_test_relro_off.py
│   ├── craft_extratag_poc.py
│   ├── minimal_repro_dl_load_885.py
│   └── dl-load-885-robustness.patch
├── overlap_lab/     # PT_LOAD overlap permutation lab
│   └── overlap_perm_lab/  # harness.py, mutate.py, detect_overlap.py, analyze.py, run.py, iter01-30.py
└── config.py        # centralized paths (linkers, loader, Ghidra, project root)
```

### Melkor design principles carried over

1. **Hybrid mutation + generation** with spec knowledge (not blind bitflips).
2. **Rule execution** driven by a likelihood gate — critical fields lower their own probability so the input stays semi-valid.
3. **Metadata dependency levels** (`HDR → SHT/PHT → symbol/reloc/string/dynamic tables`): deeper levels are fuzzed **last or not at all** to preserve dependencies and keep coverage high. Lfuzzer's 3-region scope (SHDR/PHDR/`.dynamic`) sits deliberately at the shallow, high-leverage tiers.
4. **templates/** holds seed ELFs.
5. A **run harness** drives the mutated "orcs" against the target.

---

## Install

```bash
pip install -r requirements.txt   # pyelftools (elftools.elf...), tqdm
```

**External tools** (must be on `PATH` or configured in `lfuzzer/config.py`):

```
readelf   objdump   strace   gdb   valgrind
gcc   ld (BFD)   ld.gold   patchelf   ghidra
```

**Custom binutils build (recommended).** The differential experiments prefer purpose-built linker binaries and fall back to system ones if absent:

```bash
# BFD ld  (AFL-instrumented clean build)
~/binutils-build-afl-bfd-clean/ld/ld-new     # fallback: /usr/bin/ld, /usr/bin/ld.bfd
# gold ld
~/binutils-build-gold/gold/ld-new            # fallback: /usr/bin/ld.gold, /usr/bin/gold
```

Ghidra requires **Java 21** (`~/ghidra_12.1.2_PUBLIC`). Loader path is `/lib64/ld-linux-x86-64.so.2` (or `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`).

---

## Quickstart

```bash
# 1) Mutate a seed ELF (.dynamic DT_ tags shown; swap module for PHDR/SHDR)
python -m lfuzzer.mutators.mutate_elf_v4 templates/prac.elf -o out/mutant.elf

# 2) Link the same mutant with both linkers and diff
python lfuzzer/differential/exp_goldbfd_diff/exp_d01_strip_sht.py

# 3) Load it with the runtime linker and capture behavior
python -m lfuzzer.orchestrator.lfuzzer out/mutant.elf     # runs under ld.so

# 4) Triage / classify any crash or hang
python -m lfuzzer.analysis.auto_gdb_classify out/mutant.elf

# Or run the whole autonomous loop (mutate → link → run → triage):
python -m lfuzzer.orchestrator.autorun_v3
```

---

## Differential experiments

The `differential/exp_goldbfd_diff/` suite is the heart of the gold-vs-BFD study. Each `exp_dNN` / `exp_rN` is a **self-contained, runnable** hypothesis: it builds a base library, applies one mutation, links it under both linkers via a `-B<dir>` wrapper trick (`common.py:link_with`), and reports the divergence.

```bash
cd lfuzzer/differential/exp_goldbfd_diff

./exp_d01_strip_sht.py        # strip section header table
./exp_d05_verneed_edge.py     # VERNEED edge case
./exp_d07_dt_hash_nchain.py   # DT_HASH nchain inconsistency
./exp_d22_runpath.py          # DT_RUNPATH handling
./exp_r5_phdr_vs_sht.py       # PHDR vs SHT view disagreement
./exp_r7_ghidra_dtag.py       # Ghidra .dynamic-tag readout diff

./exp_display_all.py          # aggregate + render all results
```

**Numbered series** (all in `exp_goldbfd_diff/`):

| Series | What it probes |
|--------|----------------|
| `exp_d01` … `exp_d24` | `.dynamic` / SHDR / symbol-table mutations vs both linkers (strip SHT, dynstr non-NUL, PIE, audit, verneed/verdef edges, hash tables, OSABI, shnum/shstrndx OOB, ET_CORE/ET_REL, syment, rpath/runpath, …) |
| `exp_r1, r5, r6, r7, r8` | Cross-view diffs: decoy `.dynamic`, PHDR-vs-SHT, unknown EHDR enums, Ghidra dtag / symcount readouts |
| `ghidra_scripts/DumpDynamic.java` | headless Ghidra `.dynamic` dumper used by `exp_r7/r8` |

> The `exp_d18` slot is intentionally absent; the series is `d01–d24` minus `d18`.

Focused case studies live alongside as `differential/exp_e1..e6/` (runpath, PIE, SHDR-strip, VERNEED, duplicate SONAME, aux-tag), and `differential/parser_diff/` replays the same corpus against static parsers to compare parser robustness.

---

## Config

All machine-specific paths are centralized in **`lfuzzer/config.py`** so no path is hardcoded in scripts. Each entry resolves to the first existing candidate, falling back to system tools:

| Key | Primary | Fallback |
|-----|---------|----------|
| `BFD` | `~/binutils-build-afl-bfd-clean/ld/ld-new` | `/usr/bin/ld`, `/usr/bin/ld.bfd` |
| `GOLD` | `~/binutils-build-gold/gold/ld-new` | `/usr/bin/ld.gold`, `/usr/bin/gold` |
| `GHIDRA` | `~/ghidra_12.1.2_PUBLIC` (Java 21) | — |
| `LOADER` | `/lib64/ld-linux-x86-64.so.2` | `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` |
| `PROJECT_ROOT` | repo root | — |

Override any of these via environment variable or by editing `config.py` for your machine.

---

## Repository layout

```
lfuzzer/            Python package (see Architecture)
templates/          representative seed ELFs (prac.elf, …)
docs/               ARCHITECTURE.html, MELKOR_MAPPING.md, *_0715.md planning docs
archive/            legacy mutators, meeting notes, old gold/bfd output dumps
README.md  LICENSE  requirements.txt  Makefile  pyproject.toml  .gitignore
```

**Not tracked** (generated data, ~150k files, `.gitignore`d): `out*/`, `in*/`, `crashes*/`, `glibc/`, `gcov/`, `classified_*/`, `representatives*/`, `overlap_perm_lab/iter*_out/`, `__pycache__/`, `*.log`, `*_report.txt`, `autorun_state.json`, and compiled ELF artifacts.

---

## Credits

Structural design after **Melkor — An ELF File Format Fuzzer**, Alejandro Hernandez (IOActive), Black Hat USA 2014. Lfuzzer mirrors Melkor's module roles and mutation philosophy in Python and adds the linker/loader/analyzer differential layer.

## License

MIT. See [LICENSE](LICENSE).
