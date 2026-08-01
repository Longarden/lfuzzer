# MELKOR_MAPPING.md — How Lfuzzer mirrors Melkor's architecture

> **One-line takeaway:** Lfuzzer is a *structural* re-implementation of Melkor's
> module layout in Python, restricted to three ELF regions (SHDR / .dynamic /
> PHDR), and extended with a **differential layer** (gold-vs-BFD link → run under
> ld.so → observe divergence) that Melkor, a pure single-parser ORC generator,
> does not have.

Melkor (Alejandro Hernandez, *"Melkor: An ELF Fuzzer"*, Black Hat USA 2014) is
written in **C**. Lfuzzer is written in **Python**. This document maps Melkor's
file/concept roles onto Lfuzzer's modules. **The mirror is by role, not by
language** — we keep the module *names and responsibilities*, not a line-for-line
port. Slide-page citations below refer to the Black Hat 2014 deck.

---

## 1. Module mapping table

| Melkor file / concept | Role in Melkor | Lfuzzer module / file | Role in Lfuzzer |
|---|---|---|---|
| `melkor.c` (main) | Entry point. Parses CLI, loads the template ELF, drives the fuzz loop, dispatches per-metadata rule modules, writes ORCs (fuzzed outputs). (p.53-54) | `orchestrator/autorun_v3.py` (+ `orchestrator/lfuzzer.py` `run_elf` helper) | Autonomous **fuzz + triage** loop. Loads `prac.elf`, calls the mutation dispatcher (`mutate()`), runs each candidate under `ld.so`, saves crashes, triages distinct sites via gdb, and accumulates state in `autorun_state.json`. This is the `main`. |
| `fuzz_<metadata>.c` (e.g. `fuzz_ehdr.c`, `fuzz_phdr.c`, `fuzz_sht.c`) | One module *per metadata type*, each holding the fuzzing **RULES** for that structure as an array of function pointers. (p.53-54, p.66-69) | `mutators/*` — `mutator_field_v2.py` (PHT fields), `mutator_dynamic_v3.py` (.dynamic DT_ tags), `mutator_interp_vaddr_v2.py`, `mutator_shuffle.py` (phdr order), `fuzzer_overlap.py` (LOAD overlap), `mutate_elf_v4.py` (top-level combiner) | Each mutator is the per-metadata rule module. e.g. `mutator_dynamic_v3.py` holds `gen_verneed` / `gen_audit` / `gen_phdr`, each a named rule that patches one field family of one structure. `mutator_field_v2.py` enumerates the 8 PHT fields (`PH_FIELDS`). |
| `generators.c` + `numbers.h` | `generators.c` returns *semi-valid* test data (interesting values chosen with spec knowledge + `rand()`); `numbers.h` is the table of "interesting numbers" (boundaries, huge, zero, signed-min). (p.53-54) | `generators/generators.py` + `generators/numbers.py` **(NEW — to author)** | Centralizes the interesting-value production currently inlined in mutators: `rbig()` in `autorun_v3.py` (`[0xffffffff, 0x7fffffff, 0x41414141, rand, 0xfffffff0, 0x10, 0x0, 0x80000000]`), the `ITAGS` DT_ tag pool, and the per-rule `big=[…]` lists in `mutator_dynamic_v3.py`. `numbers.py` = the boundary constants; `generators.py` = the functions that draw from them. |
| `logger.c` | Logs *which metadata was fuzzed* per ORC, so a crash can be traced back to the rule that produced it. (p.53-54) | `logger/logger.py` **(NEW — to author)** | Centralizes the labeling/recording currently inlined: the per-crash filename label (`{lab}__{h}__{cls}.elf`), the `.meta.json` sidecar (`seed/round/label/sha/class/rc`) in `autorun_v3.py`, and the `autorun_progress.log` / `sites_summary.txt` writers. Same job: bind each output back to the rule + RNG seed that made it. |
| `templates/` | Seed ELFs the fuzzer mutates. (p.53-54) | `templates/` (`prac.elf` and representative samples) | Seed ELFs. `prac.elf` is the canonical base every mutator reads as `BASE`. |
| `test_fuzzed.sh` | Runs the generated ORCs against the target parser and collects results. (p.53-54) | `analysis/*.sh` (`triage_crashes.sh`, `classify_multi.sh`, `sprint*_*.sh`, `triage_dos.sh`) **+** the `differential/` layer | Runs saved outputs against the target(s) and classifies results. In Lfuzzer the "target" is plural: `ld.so` at runtime, plus `ld`/`gold` at link time, plus `readelf`/`objdump`/Ghidra as analyzers (see §2c). |
| ELF read helpers (inline in Melkor's C headers) | u16/u32/u64 accessors, PHT/SHT/.dynamic walkers. | `core/elf64.py` (`u16/u32/u64`, `read_phdrs`, `iter_dynamic`, `vaddr_to_offset`) + `core/drivers/common.py`, `core/seeds/extract_phdr.py` | Single source of truth for ELF64 read primitives; mutators import these instead of re-deriving offsets (dedup — see the note in `autorun_v3.py` line 7/16). |
| *(no equivalent)* | — | `differential/exp_goldbfd_diff/` (`common.py`, 24 × `exp_d*.py`, 5 × `exp_r*.py`, `ghidra_scripts/DumpDynamic.java`), `parser_diff/`, `tag_exp/`, `exp_e1..e6` | **Lfuzzer-unique.** Feeds the *same* input to two linkers / two analyzers and reports where they diverge. Melkor has no analog. See §2c. |

---

## 2. Design-principle parallels and differences

### (a) Metadata dependency levels — honored, then deliberately narrowed

**Melkor (p.45-46):** ELF metadata forms a dependency hierarchy —
`ELF header → SHT / PHT → symbol / relocation / string / dynamic / note tables`.
Higher levels are *pointed to* by lower ones. Melkor's guidance: fuzz the deeper
(pointed-to) levels **last, or not at all**, because corrupting a string-table
offset early makes the parser bail before it ever reaches the interesting code,
collapsing coverage. Preserving the dependency chain buys depth.

```
  ELF HEADER (e_phoff, e_shoff, e_*num)          <- level 0 (roots)
        │
        ├── PROGRAM HEADER TABLE (PHDR)          <- level 1
        └── SECTION HEADER TABLE  (SHDR)         <- level 1
                    │
                    └── .dynamic / symtab /      <- level 2
                        strtab / rela / verneed
                            │
                            └── string & symbol  <- level 3 (leaves)
                                bytes
```

**Lfuzzer honors this ordering** the same way Melkor does — it mutates *one
field of one structure at a time and leaves the rest of the chain intact*, so the
loader/linker walks as deep as possible before diverging. Concretely:

- `mutator_field_v2.py` changes a single PHT field (`--field p_offset --seg 2`)
  and keeps every other header valid.
- `mutator_dynamic_v3.py` `gen_phdr` patches exactly one PHT field per variant
  (`p_offset`, then `p_filesz`, then `p_memsz`, then `p_align`) rather than
  randomizing the whole entry.
- `exp_goldbfd_diff/common.py::inject_dyn_tag` overwrites only the first
  `DT_NULL` slot — "정상 파일 구조 유지 → 초반 포맷검사 통과 후 해당 태그 경로
  도달" (keep the file structurally valid so early format checks pass and
  execution *reaches* the target tag path). That comment is the p.45-46
  principle restated.

**The deliberate restriction — and why.** Melkor fuzzes *all* metadata levels.
Lfuzzer intentionally restricts to **three regions only: SHDR, .dynamic, PHDR**
(levels 1-2 of the hierarchy). Rationale:

- **These three are the loader/linker's structural contract.** PHDR drives
  `ld.so`'s segment mapping, .dynamic drives symbol/version resolution, and SHDR
  drives the *static* linker's view. They are exactly the tables where a
  static-vs-runtime or gold-vs-BFD disagreement can exist (§2c).
- **Leaf-level fuzzing (raw string/symbol bytes) mostly yields shallow parser
  aborts,** not the deep loader-state bugs Lfuzzer targets (e.g. the VERNEED
  walk, `DT_AUDIT` reuse, LOAD overlap). Skipping the leaves is Melkor's
  "fuzz deeper levels last or not at all" taken to its logical end for a
  loader-focused study.
- Restricting the search space also makes the differential comparison (§2c)
  interpretable: a divergence can be attributed to a specific SHDR/.dynamic/PHDR
  field rather than to arbitrary byte noise.

### (b) Likelihood-gated, function-pointer rule execution — C arrays vs Python dispatch

**Melkor (p.66-69):** each `fuzz_<metadata>.c` registers its rules as an **array
of function pointers**, populated at load time with
`__attribute__((constructor))`. The main loop iterates the array and fires each
rule with probability `-l` (likelihood; default **10%**, aggressive **70%**).
Rules that touch **critical fields lower the likelihood internally** so the
structure stays semi-valid more often. That is the whole rule engine: *registry
+ probabilistic gate + self-throttling on critical fields*.

**Lfuzzer expresses the same three ideas in Python, without C constructors:**

| Melkor mechanism (C) | Lfuzzer expression (Python) |
|---|---|
| Function-pointer array per module | A list of named generator functions — e.g. `gens=[("verneed",gen_verneed),("audit",gen_audit),("phdr",gen_phdr)]` in `mutator_dynamic_v3.py`; or a `random.choice([...])` over category strings in `autorun_v3.py::mutate`. |
| `__attribute__((constructor))` registration | Plain module-level definition + explicit list construction (Python has no separate init phase; the list *is* the registry). |
| `-l` likelihood gate on each rule | Category selection weighting + per-round budget. `mutate()` uses `random.choice(["verneed","verneed","dynrand",…])` — VERNEED is listed twice, i.e. hand-weighted likelihood. The 60% mutate / 40% triage split (`mut_deadline=t0+budget*0.6`) is the run-level analog of `-l`. |
| Critical fields lower their own likelihood | Value pools are pre-filtered to *semi-valid* choices so critical fields are rarely fully destroyed: `rbig()` biases toward boundary values, `ITAGS` restricts DT_ tags to a known set, and single-field patching (§2a) keeps the rest valid — the same "don't nuke the structure" intent. |

So Melkor's *constructor-registered function-pointer array iterated under a
likelihood gate* becomes Lfuzzer's *explicit list of generator functions
dispatched under weighted `random.choice` + a time-budget split*. Same contract,
idiomatic to each language. The planned `generators/` + `logger/` extraction
(§1) makes this parallel exact by pulling the value pools and the rule-labeling
out of the mutators, mirroring Melkor's clean `generators.c` / `logger.c`
separation.

### (c) THE KEY DIFFERENCE — Lfuzzer's differential layer

**Melkor is a single-parser ORC generator.** It mutates an ELF, feeds it to
*one* target parser, and watches that one parser for a crash/hang. There is no
notion of comparing two implementations.

**Lfuzzer adds a differential layer that Melkor has no analog for.** The same
mutated input is driven through *multiple independent implementations* and the
fuzzer's signal is **where they disagree**, not merely whether one crashes:

```
            same mutated ELF / .so
                    │
      ┌─────────────┼──────────────┐
      ▼             ▼               ▼
   ld (BFD)      ld.gold        readelf / objdump / Ghidra
  static link   static link      (analyzer parse)
      │             │               │
      ▼             ▼               ▼
   (rc, stderr) (rc, stderr)   (dumped structure)
      └──────┬──────┘               │
             ▼                      ▼
     diverged?  ────────────►  analyzer divergence?
   (brc≠grc or one errors)     (readelf vs Ghidra disagree
             │                  on the same field)
             ▼
      run winner under ld.so  ──►  runtime crash / DoS
```

Concretely, in `differential/exp_goldbfd_diff/`:

- `common.py` resolves **two linker binaries** — `BFD =
  ~/binutils-build-afl-bfd-clean/ld/ld-new` and `GOLD =
  ~/binutils-build-gold/gold/ld-new` (with `/usr/bin` fallbacks) — and links the
  *same* input with each via the `gcc -B<dir>` symlink trick (`link_with`).
- `diff_report(title, bfd_res, gold_res)` decides `diverged = (brc != grc) or
  (bool(bfd_stderr) != bool(gold_stderr))` — the **divergence is the finding**.
- The 24 `exp_d*.py` experiments are pre-registered hypotheses (D01…D24) about
  *where* BFD and gold should split on SHDR/.dynamic/PHDR corruption; the
  `exp_r*.py` set are runtime replays; `ghidra_scripts/DumpDynamic.java` pulls
  Ghidra into the analyzer-divergence comparison.
- `parser_diff/` extends the idea to analyzer robustness (e.g. replaying a
  corpus against a static parser and diffing it against readelf/objdump).

Why this matters and Melkor can't express it: a bug that makes **gold accept
what BFD rejects** (or makes **ld.so map what the static linker declared
unmappable**, or makes **readelf and Ghidra disagree on a `DT_` value**) is
invisible to a single-parser fuzzer — nothing crashes; the *implementations just
diverge*. Lfuzzer's mutation front-end is Melkor-shaped, but its oracle is
differential, and that is the research contribution.

---

## 3. Architecture lineage — one-paragraph summary

Read top-to-bottom, Lfuzzer is Melkor with two edits. **Edit 1 (narrowing):**
keep Melkor's dependency-aware, single-field, likelihood-gated mutation
(p.45-46, p.66-69) but restrict the rule modules to the three
loader/linker-contract regions — SHDR, .dynamic, PHDR. **Edit 2 (extension):**
replace Melkor's single-parser crash oracle with a differential oracle that
links with BFD *and* gold, runs the result under ld.so, and cross-checks
readelf/objdump/Ghidra, treating *disagreement* as the bug signal. Everything
else — the `main` loop (`autorun_v3.py` ≙ `melkor.c`), the per-metadata rule
modules (`mutators/*` ≙ `fuzz_<metadata>.c`), the interesting-value generators
(`generators/*` ≙ `generators.c`+`numbers.h`), the rule/seed logging
(`logger/*` ≙ `logger.c`), and the seed templates (`templates/` ≙ `templates/`)
— is a role-preserving Python re-expression of the C original.

---

### Slide citations

- **p.53-54** — Melkor implementation: `melkor.c` main, per-metadata
  `fuzz_<metadata>.c` rule modules, `generators.c` + `numbers.h` semi-valid data,
  `logger.c`, `templates/`, `test_fuzzed.sh`.
- **p.45-46** — ELF metadata dependency levels (HDR → SHT/PHT → symbol / reloc /
  string / dynamic / note tables); fuzz deeper levels last or not at all to
  preserve dependencies and maximize coverage.
- **p.66-69** — rule execution: per-module function-pointer arrays initialized
  with `__attribute__((constructor))`, iterated under the `-l` likelihood gate
  (default 10%, aggressive 70%), with critical-field rules lowering the
  likelihood internally.
