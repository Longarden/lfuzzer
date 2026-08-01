# Lfuzzer Automation — Consensus Implementation Plan (iteration 4, final)

STATUS: pending approval

## Insight first
The whole fidelity argument turned on one modality error the reviewers isolated and agreed on: **the live debug ld.so is a REACHABILITY oracle, not a VIOLATION oracle** (spec:26 — live ASAN rtld is bootstrap-impossible, so the loader the gate runs is not ASAN-instrumented). Iteration-3 tried to certify an ASAN *bounds* claim (a violation-modality fact) by matching *access location* more finely (`mechanism_match = watchpoint fired`). Two reachability observations cannot certify a violation no matter how finely their locations agree. Under the plan's own AND-of-three admission, this did not merely admit false bugs — it **silently discarded the dominant genuine class**: a real redzone-class OOB (small overrun into still-mapped-but-poisoned memory — exactly what ASAN exists to catch, spec:25) produces NO signal in the uninstrumented real loader, so `fault_class_match=0` and the row is thrown away as `HARNESS_ARTIFACT`. A validator that discards the instrument's whole reason for existing is worse than no validator.

The fix (architect Rec 1, critic-adjudicated) is to give the *live* oracle a violation verdict it can actually compute without ASAN: **`mechanism_match = watchpoint_fired ∧ (accessed offset is OOB against the debug loader's reconstructed REAL segment bounds)`**. The real bounds are already available from `elf64.py` (`read_phdrs`, `vaddr_to_offset`, `iter_dynamic`; CHANGES:17) plus the live loader's real `l_addr`. This is machine-decidable, needs no ASAN rtld, admits genuine redzone bugs (OOB in reality too), and rejects harness redzone artifacts (in-bounds in reality). It also becomes the in-script decider that eliminates the P2.5 human spot-audit — closing the biggest classifier-division-of-labor leak. Admission is relaxed off the over-strict fault requirement per spec:28's reachability semantics: `location_match ∧ (fault_class_match ∨ bounds_violation)` — signal-death OR real-bounds-OOB, so the SEGV class and the redzone class each have the predicate they need.

---

## 1. Requirements Summary (AUTOMATION_SPEC_0715 + STRUCTURE_AUDIT_0715 + CHANGES_0715)
- Center of gravity = **differential (semantic-divergence) oracle** (spec:5,19-21); ASAN is an **evidence instrument** (spec:25), not the judge.
- Live ASAN rtld bootstrap-impossible (spec:26) → **extract-and-harness** at `_dl_map_object_from_fd` (spec:27). The live oracle is therefore a **reachability/bounds** oracle, never a violation oracle. Trust = harness precision × live reproduction, and reproduction must be measured at a **violation-capable resolution the non-ASAN loader can actually compute** (real-segment-bounds), not merely reachability, and not a violation verdict the loader cannot emit.
- One file mutates exactly one of {PHT, DYNAMIC/DT_ graph, SHT} (spec:13) → clean attribution. Cross-region excluded from v1 (spec:54).
- Reproducibility contract: `--seed` layer landed (branch `refactor/mutation-optim-0715`, CHANGES:19); ledger records seed+region+field+value (spec:16); replay from seed+log, never from a stored ELF (spec:59).
- **Division of labor under the safety classifier** (spec:58): Claude designs + interprets; USER runs every unit via `!`. Plan must NOT route around the classifier. Per-input logic and every equivalence/admission relation codified in-script; Claude reads only phase-level aggregate / bounded top-K verdict lines.
- Single crash oracle (audit:117): `signal-death (SEGV/ABRT/BUS) OR ASAN-report OR confirmed-timeout`; direct-execve BANNED — mutant is only ever a tool *input*.
- Non-goals (spec:50-54): live ASAN rtld, IDA automation, whole-ELF blind fuzzing as primary, cross-region mutation in v1.
- Landmine (audit B26, audit:98): the 478 corpus files are **extensionless** — any `.elf` suffix filter zeroes the dataset (a REFUTED "fix"); index by **content hash only**.
- Reused assets (audit:125-128, verified present): `mutate_elf_v4` (field sweep + repair + MANIFEST + B07/B22/B23 fixes), `mutator_dynamic_v3` (VERNEED/AUDIT/STRTAB meta), `exp_e*` 1-field primitives, AFL region drivers (byte-containment assert), `exp_e2/run_exp.sh` (multi-tool diff), `imap_unordered` worker skeleton (ETXTBSY-safe tmp, 5s timeout), `auto_gdb_classify` (frame0+rip triage), `rerun_debug_ldso.top` (only correct debug-loader + library-path caller), `minimal_repro_dl_load_885`, `auto_followup.sh` (si_code/si_addr family extraction), `elf64.py` (shared parser, CHANGES:17).

---

## 2. RALPLAN-DR SUMMARY  (mode: DELIBERATE — high-risk fidelity claim, deep-reviewer stressed)

### Principles
1. **Never discard** — record every observation, rank post-hoc (spec:20). Buckets/verdicts key on canonicalized signals (frame0 symbol + normalized line), never raw addresses (B14 guard, audit:74).
2. **Two oracles multiply on the SAME EVENT at a VIOLATION-CAPABLE resolution.** Harness precision × live reproduction, where the live verdict is `access-happened ∧ OOB-vs-real-bounds` — the strongest violation predicate a non-ASAN loader can compute (spec:26). Neither oracle trusted alone. This repairs the iteration-2/3 modality gap.
3. **One region per file** (spec:13); replay from seed+log, never a stored ELF (spec:59); hash only **canonicalized** observations — code (disasm-equivalence), Ghidra, and ASAN alike.
4. **Every gate/equivalence/admission decision is machine-decidable in-script** (three-boolean admission with an in-script bounds decider, frozen codegen-norm spec, per-tool semantic normalization). Claude reads only phase-level aggregate with a bounded-K class summary; the failure-descent path is pre-declared per phase, not improvised.
5. **Fidelity is a measured, spot-audited RATE staged on the failure distribution that actually exists** (Phase-2.5, on real harness artifacts, with an in-script bounds oracle doing the adjudication), never an assumption asserted before the instrument runs.

### Top-3 Decision Drivers
1. **Reproducibility contract** (seed+log replay, spec:16/59) — shapes the dispatcher, ledger schema (seed as PK, no raw ELF), canonicalization-before-hashing, every gate row's replay fields, and the Ghidra determinism resolution.
2. **Fidelity of ASAN evidence at a loader-computable violation resolution** — codegen-equivalence × real-bounds-matched live reproduction × staged discriminative calibration. This driver forced the real-bounds `mechanism_match`, the relaxed OR-admission, the `GATE_PATH_REACHES_L` positive control, and Phase-2.5.
3. **Classifier division-of-labor** (spec:58, no bypass) — forces per-input logic as code, three NAMED in-script deciders (`asan_to_watchpoint.py`, frozen `codegen_norm.spec`, bounds oracle), aggregate-only reads with bounded K, a sharded gate with a wall-clock budget, a capped `GATE_PATH_MISS` escape hatch, and a pre-declared descent protocol.

### Options (the live decision is GATE RESOLUTION; build order is settled as gate-before-harness with P2.5 staging)
```
OPTION                                   VERDICT     WHY
─────────────────────────────────────────────────────────────────────────────────────────
D  bounds-augmented mechanism_match      CHOSEN      Live verdict = watchpoint_fired ∧ OOB-vs-real-
   (watchpoint ∧ OOB-vs-real-bounds),                bounds. The ONLY option where the non-ASAN loader
   OR-admission with fault_class                     emits a real violation verdict (closes the redzone
                                                     hole with no ASAN rtld); bounds check is the
                                                     precision floor so LOW targets stay safe at
                                                     location+bounds; OR-admit with signal-death keeps
                                                     the SEGV class; doubles as the P2.5 in-script audit
                                                     oracle. Bounds from elf64.py (CHANGES:17).
─────────────────────────────────────────────────────────────────────────────────────────
C  watchpoint = access-happened          INVALIDATED Watchpoint proves access, never violation
   (iteration-3), AND-of-three                       (spec:26). Redzone-class real bug → no signal →
                                                     fault_class_match=0 → SILENTLY DISCARDED as
                                                     HARNESS_ARTIFACT. Discards the exact class ASAN
                                                     exists for (spec:25). Contradicts spec:28
                                                     reachability semantics.
─────────────────────────────────────────────────────────────────────────────────────────
B  uniform strict gate                   INVALIDATED Still access-vs-violation blind (same modality
   (mechanism always)                                gap as C); over-rejects shifted-address genuine
                                                     bugs on LOW targets. Worst of both.
─────────────────────────────────────────────────────────────────────────────────────────
A  flat coarse gate (iteration-2)        INVALIDATED Admits wrong-mechanism false bugs (BLOCKER a-i);
                                                     per-function budget decorative (BLOCKER a-ii).
─────────────────────────────────────────────────────────────────────────────────────────
Codegen check — canonicalized disasm-EQUIVALENCE   CHOSEN vs byte-identical (INVALIDATED: a macro-
   (normalize addrs/relocs/symbols; compare          expanded static inline compiled into the harness
   mnemonic+operand-class sequences)                 TU vs inlined into rtld is realistically never
                                                     byte-identical → HALT either always fires or gets
                                                     relaxed by a human reading a diff, the exact (c)
                                                     leak). Normalization frozen in codegen_norm.spec
                                                     BEFORE P2.
─────────────────────────────────────────────────────────────────────────────────────────
Ledger — SQLite per-worker shards + merge          CHOSEN vs single-writer SQLite (INVALIDATED:
                                                     imap_unordered multiprocess falsifies single
                                                     writer, audit:127) / Parquet-first (cold-export
                                                     tier only).
```

---

## 3. Implementation Plan (gate-before-harness vertical slice, staged fidelity arms)
```
elf64.py (done)
  → P0  Prereqs (USER installs; Claude verifies output signatures)
  → P1  Live REACHABILITY gate (location+class + POSITIVE re-confirmation) + labeled slice   ← validator shell first
        (mechanism/bounds arm is DEFERRED to P2.5 — nothing to bind a watchpoint to yet)
  → P2  ASAN harness PoC at fd-seam (KEYSTONE) + canonicalized codegen-equivalence            ← lands on a ready gate
        (libFuzzer coverage feedback comes online here)
  → P2.5 Gate-calibration + bounds-arm build — dual-run first ~50 REAL harness candidates,     ← violation arm + NEGATIVE arm
        build mechanism_match(bounds) + DISCRIMINATIVE artifact-rejection; gate PROVISIONAL→CALIBRATED
  → P3  Multi-tool runner (exp_e2 → N tools, tiered, Ghidra-on-divergence) + semantic-divergence spec
  → P4  Differential oracle + full-observability ledger (canonicalized, sharded write path)
  → P5  Seeded 3-region mutation dispatcher (coverage bias only where signal exists)
  → P6  478/24k regression replay (by content hash)
  → P7  Ranker
```
**Rationale for the inversion vs spec's keystone-first (spec:70-76):** the harness's fidelity is unprovable until the reproduction gate + labeled cases exist. But be honest about what P1 can prove: **P1 builds only the location+class gate + positive re-confirmation of the 4 legacy findings.** The mechanism/bounds arm needs an ASAN report that *names a slot/field* — which only the harness (P2) produces; the 4 legacy findings carry no ASAN-named slot (audit:130,132 — ASAN lane is entirely new; audit:128 — legacy triage is signal+frame0 only). So the violation arm is staged at **P2.5**, where real harness artifacts exist. Gate-before-harness front-loads bug *re-confirmation*; P2.5 front-loads the *violation verdict* and artifact *rejection*.

---

### Phase 0 — Prereqs (USER installs; Claude verifies output signatures)
**Artifacts:** environment only.
**Units (`!`):**
```
!  # Ghidra headless + DYNAMIC/symbol-dump postScript
analyzeHeadless <proj> -import prac.elf -postScript dump.py
!  # ASAN builds (bootstrap-free targets)
CC='clang -fsanitize=address' <build ld / readelf / objdump>
!  # gold ASAN via isolated all-gold build (dodge doc/aoutx.stamp, spec:45)
<all-gold isolated build tree> CFLAGS='-fsanitize=address'
!  # r2/rizin install
!  # debug ld.so build (glibc-2.39) WITH SYMBOLS for the gate
!  # pinned disassembler for the codegen-equivalence relation
objdump -d   # fixed flags, SAME version used for harness + shipped ld.so
```
**Observable verification:** `analyzeHeadless … -postScript dump.py` exits 0 and emits a DYNAMIC table; each ASAN binary on a poisoned input prints `==NNN==ERROR: AddressSanitizer` to stderr; debug ld.so resolves `_dl_map_object_from_fd` and `elf_get_dynamic_info` symbolically under GDB; disassembler produces stable output on a fixed `.o` across two runs (equivalence-relation prerequisite).
**Risk:** gold ASAN build fragility (`aoutx.stamp`) — isolate the build tree; capture the exact working invocation + all tool build hashes into the ledger's **one environment-provenance header row** so all 24k rows share one provenance record.

---

### Phase 1 — Live REACHABILITY gate (location+class) + positive re-confirmation + labeled slice  ← build FIRST
**Scope (relabeled honestly per critic Improvement 1):** P1 builds and proves ONLY the coarse gate — `location_match` + `fault_class_match` — and re-confirms the 4 legacy findings. The `mechanism_match(bounds)` arm is a Phase-2.5 deliverable (it has no ASAN-named slot to bind to until the harness runs).

**Artifacts (new):**
- `gate/repro_gate.py` — input `seed,region,field,value` → regenerates the ELF in-memory → runs **debug** ld.so under GDB with `--library-path` → emits two booleans now, a third stub at P2.5:
  - `location_match` = symbolic `file:line` breakpoint at L hit on the real loader.
  - `fault_class_match` = fault at L is the same class (signal ∈ {SEGV,ABRT,BUS} + matching `si_code`/`si_addr` family via `auto_followup.sh`).
  - `mechanism_match` = **STUB at P1 (always `null`)**; defined and populated at P2.5 (see below).
- `gate/path_control.py` — **per-target positive control (closes BLOCKER a-iii).** Before any `REPRODUCED=0` may discard, assert the gate's own `--library-path` invocation demonstrably reaches L on the real loader for that target (breakpoint hit under the gate's own path). Emits `GATE_PATH_REACHES_L ∈ {1,0}`. **A hard cap `GATE_PATH_MISS_MAX` (default 8) bounds the bespoke-path escape hatch (closes critic Improvement 4):** above the cap the gate HALTs and treats generic-path unreachability as a **harness-design signal**, not a per-target Claude patch loop.
- `gate/gate_batch.py` — **batch driver, sharded per-worker like the ledger, with a per-unit wall-clock budget (closes IMPROVE 3).** GDB + debug-loader replay is seconds/candidate → the gate is the slowest oracle and must not be a single stream at 24k scale.

**Reused:** `rerun_debug_ldso.top` (audit:128), `minimal_repro_dl_load_885`, `auto_followup.sh` (si_code/si_addr family), the `dl-load.c:885` CONFIRMED minimal repro.

**Admission rule at P1 (coarse only):**
```
target budget      P1 admission predicate
ANY                →  location_match ∧ fault_class_match
```
Rows failing this are tagged `HARNESS_ARTIFACT` **only when `GATE_PATH_REACHES_L=1`**; if `0` → `GATE_PATH_MISS` (escalated, not discarded, subject to the cap). The **final** budget-keyed OR-admission (with bounds) lands at P2.5.

**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && python3 gate/repro_gate.py --seed <s> --region <r> --field <f> --value <v>   # emits location/fault_class booleans
!  cd ~/PE/Lfuzzer && python3 gate/path_control.py --target dl-load.c:885                            # emits GATE_PATH_REACHES_L
!  cd ~/PE/Lfuzzer && python3 gate/gate_batch.py --shards 8 --wall 5 --in candidates.tsv --out gated/  # sharded, budgeted
```
**Observable verification (adversarial, coarse-arm only):**
1. `dl-load.c:885` CONFIRMED live finding → `location_match=1 ∧ fault_class_match=1` → admitted. (No mechanism claim at P1.)
2. **Reachable-but-non-faulting case:** `location_match=1, fault_class_match=0` → rejected.
3. **Path-miss case:** generic `--library-path` cannot reach → `GATE_PATH_REACHES_L=0` → `GATE_PATH_MISS`, escalated (within cap), NOT discarded.
4. All four confirmed findings (EXTRATAGIDX desync, RUNPATH hijacking, family 1, family 2) replay and land admitted — labeled slice pulled forward from P6 so the harness has ground truth waiting.
**Risk:** breakpoint/address drift under PIE/ASLR → symbolic `file:line` breakpoints, ASLR disabled, exact debug-loader build hash recorded per row. B13 guard (audit:73): `chmod +x` before GDB so frames are not all `EARLY_NO_STACK`.

---

### Phase 2 — ASAN harness PoC at the fd-seam (KEYSTONE)  ← lands on a ready coarse gate
**Artifacts (new):**
- `harness/asan_harness.c` — libFuzzer `LLVMFuzzerTestOneInput` → bytes to a memfd → drives `_dl_map_object_from_fd` down through `elf_get_dynamic_info` so the loader fills `l_info` itself.
- `harness/build_harness.sh` — `-fsanitize=address,fuzzer`.
- `harness/state_snapshot.c` — seeds a bootstrapped `link_map` + `GL(dl_*)` globals; **minimize fabricated state at the source**; records the fabricated `l_addr` / segment bases per run (consumed by the P2.5 bounds oracle).
- `harness/codegen_equiv.sh` — canonicalized disasm-equivalence check (REPLACES byte-identical — closes BLOCKER c-i).
- `codegen_norm.spec` — **NEW, FROZEN versioned artifact committed BEFORE P2 (closes critic Blocker 2 seam iii).** The normalization rule set: strip addresses / relocation targets / symbol names ONLY; keep opcode + operand-class. Tuning it is an **out-of-band spec version bump**, never a per-input feedback edit; `codegen_equiv.sh --explain` may DUMP the first divergent mnemonic pair for a descent unit but MUST NOT mutate the live relation.

**Codegen-EQUIVALENCE gate (machine-decidable HALT):** `elf_get_dynamic_info` is a macro-heavy `static inline` in `get-dynamic-info.h`. `codegen_equiv.sh` disassembles both copies under pinned `-DIS_IN(rtld)` / `DL_RO_DYN_SECTION` macros, applies `codegen_norm.spec`, and compares the mnemonic + operand-class sequence. The PoC is gated on **canonicalized-equivalent codegen**; the HALT verdict is emitted by the script, never adjudicated by Claude. **A wrong-macro positive control is part of verification** (compile under a deliberately wrong macro → assert NOT-equivalent) so normalization cannot silently swallow a real break.

**Per-function fidelity budget (re-scoped, closes IMPROVE 2):**
```
target                    what rides fabricated state                                    budget
elf_get_dynamic_info      populate l_info (pointers into REAL dynamic array)              LOW  ← indexing; bounds check is the floor
  (same fn, deref path)   deref via d_ptr = l_addr + d_val, l_addr from state_snapshot.c  MED  ← fabricated base; OOB-in-valid-vs-redzone
dl-version.c vna_name     walks l_info[VERSYM]+STRTAB, may cross l_scope                  MED
dl-setup_hash.c           depends on real l_info bases                                    MED
dl-load.c:885             pt_gnu_property reaches deep into surrounding load state        HIGH ← own budget; expect higher artifact rate
```
The LOW label no longer conflates "populate l_info" (genuinely LOW, and made safe by the P2.5 bounds floor) with "deref through a fabricated base" (MED). Each target carries its own codegen-equivalence check and its own budget-keyed predicate.

**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && bash harness/build_harness.sh                       # -fsanitize=address,fuzzer, expect clean
!  cd ~/PE/Lfuzzer && bash harness/codegen_equiv.sh elf_get_dynamic_info  # PASS or HALT (machine verdict)
!  cd ~/PE/Lfuzzer && bash harness/codegen_equiv.sh --wrong-macro elf_get_dynamic_info  # positive control: expect HALT
!  cd ~/PE/Lfuzzer && ./harness/asan_harness prac.elf                     # known-good: l_info populated, exit 0, ASAN silent
!  cd ~/PE/Lfuzzer && ./harness/asan_harness <EXTRATAGIDX mutant>         # expect ASAN report in get-dynamic-info.h + libFuzzer NEW
```
**Observable verification (4 signals):**
1. `build_harness.sh` compiles clean with `-fsanitize=address,fuzzer`.
2. `codegen_equiv.sh` → harness `elf_get_dynamic_info` canonicalized-equivalent to shipped ld.so copy (else HALT); wrong-macro control HALTs.
3. Known-good `prac.elf` → `l_info` populated, exit 0, ASAN silent.
4. Known EXTRATAGIDX desync mutant → ASAN report anchored in `get-dynamic-info.h`; libFuzzer prints `NEW` coverage counters; the same mutant through the P1 coarse gate returns admitted under location+class.
**Risk — CHALLENGE (a) FIDELITY:** self-map-seeded `link_map` yields realistic-looking-but-wrong state; an OOB `l_info[DT_x]` deref can land in valid harness memory (false negative) or a redzone (false positive). Mitigation is layered and completed at P2.5: `state_snapshot.c` minimizes fabricated state AND records the real bases the bounds oracle needs; `codegen_equiv.sh` proves the compiled function IS the loader's; the P2.5 **real-bounds `mechanism_match`** is the hard violation filter. Harness alone is NEVER a finding.

---

### Phase 2.5 — Gate violation-arm build + discriminative calibration  ← closes BLOCKER a (redzone hole) + IMPROVE 1
**This is where iteration-3's headline actually lands.** It could not be built at P1 because it needs (i) an ASAN report that names a slot/field and (ii) the real object bases — both exist only from the harness (P2).

**Artifacts (new):**
- `gate/asan_to_watchpoint.py` — **NEW named in-script decider (closes critic Blocker 2 seam ii).** Deterministic map `ASAN-report field F → GDB watchpoint expression on slot(F)`, computed from the debug loader's real `l_addr`. No Claude authoring per finding.
- `gate/bounds_oracle.py` — **NEW, the violation predicate (closes BLOCKER a / CRITICAL).** Reconstructs the mutant's **real** segment bounds from `elf64.py` (`read_phdrs` → `p_vaddr`/`p_memsz`, `vaddr_to_offset`, `iter_dynamic`; CHANGES:17) plus the live loader's real `l_addr`, then decides whether the watchpoint-accessed offset is **OOB against those real bounds**. Machine-decidable, no ASAN rtld.
- `gate/calibrate.py` — dual-runs the first ~50 REAL harness candidates through both harness and gate; tabulates `{location, fault_class, bounds_violation}` × admitted/artifact. **The P2.5 "spot-audit" is REPLACED by `bounds_oracle.py` as a second in-script cross-oracle (closes critic Blocker 2 seam i)** — no human confirms tags.
- `gate/calib_report.py` — emits one aggregate verdict line.

**Final `mechanism_match` definition (synthesis — the decisive change):**
```
mechanism_match = watchpoint_fired ∧ (accessed_offset OOB vs debug-loader reconstructed REAL segment bounds)
```
This is a **violation** verdict the non-ASAN loader CAN compute. It distinguishes:
- harness redzone artifact (in-bounds in reality) → `bounds_violation=0` → REJECT, and
- genuine redzone bug (OOB in reality too)        → `bounds_violation=1` → ADMIT.

**Final admission rule (OR-relaxed per spec:28 reachability semantics — closes the false-REJECT):**
```
target budget      final admission predicate
LOW                →  location_match ∧ (fault_class_match ∨ bounds_violation)
MED / HIGH         →  location_match ∧ (fault_class_match ∨ bounds_violation)   with bounds reconstruction REQUIRED
                      (if real bounds cannot be reconstructed for a MED/HIGH target → GATE_PATH_MISS, not silent admit)
```
`fault_class_match` is kept as an **OR admit-path for signal-death (SEGV-reachable) bugs** where the coarse signal already certifies a real fault; `bounds_violation` is the **precision floor for the redzone class** that emits no signal. Neither is a required AND — so the SEGV class and the redzone class are BOTH admitted, and only harness artifacts (no signal AND in-real-bounds) are rejected. (Open-Q resolved: the two booleans are complementary, not redundant — fault_class covers the unmapped-page SEGV class where bounds reconstruction may be unavailable; bounds covers the mapped-redzone class where there is no signal.)

**Gate status:** PROVISIONAL from P1; promoted to **CALIBRATED** only when (i) ≥50 real harness candidates dual-run, (ii) the `HARNESS_ARTIFACT` population is **non-empty** (a gate that admits everything is broken), and (iii) `bounds_oracle.py` cross-checks agree on the sample (in-script, no human).

**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && python3 gate/asan_to_watchpoint.py --report <asan.txt>       # emits watchpoint expr
!  cd ~/PE/Lfuzzer && python3 gate/bounds_oracle.py --seed <s> --field <F>          # emits bounds_violation ∈ {0,1}
!  cd ~/PE/Lfuzzer && python3 gate/calibrate.py --n 50 --harness ./harness/asan_harness --out calib/
!  cd ~/PE/Lfuzzer && python3 gate/calib_report.py calib/                           # one VERDICT line
```
**Observable verification:** `VERDICT phase=calib candidates=N artifacts=M bounds_rejects=K gate_status=CALIBRATED|PROVISIONAL`; the redzone E2E fixtures below classify correctly; si_addr family width and watchpoint mechanism frozen with recorded values before any downstream phase trusts a `REPRODUCED=0`.
**Decisive E2E fixtures (the modality test iterations 2-3 failed):**
```
(i)   real bug (OOB in reality)                                  → ADMITTED  (bounds_violation=1)
(ii)  reachable non-faulting                                     → rejected  (location=1, fault=0, bounds=0)
(iii) harness redzone artifact (in-bounds in reality, no signal) → HARNESS_ARTIFACT (fault=0 ∧ bounds=0)  ← the false bug
(iv)  genuine redzone bug (no signal, OOB in reality)            → ADMITTED  (bounds_violation=1)          ← the false REJECT iteration-3 caused
(v)   gate-path-miss target                                      → GATE_PATH_MISS (within cap)
```
Iteration-3 could not distinguish (iii) from (iv): both had `fault_class_match=0` and its AND-of-three discarded BOTH. Iteration-4's bounds predicate admits (iv), rejects (iii).
**Risk:** if the artifact population stays empty at N=50, either the harness fabricates no wrong state (unlikely) or the gate is too loose — **explicit HALT** (not a pass); descend via `calibrate.py --sample` to spot-check whether admits are genuine before promoting.

---

### Phase 3 — Multi-tool runner (generalize exp_e2 → N tools) + semantic-divergence equivalence spec
**Artifacts (new):**
- `runner/toolrunner.py` — `[tool, input]` matrix over ld.so · ASAN harness · readelf · objdump · pyelftools · r2 · Ghidra headless · ld/gold ASAN (spec:22), tiered: all cheap parsers every input → **Ghidra promotion only on divergence, decided IN-SCRIPT**.
- `runner/ghidra_schema.py` — fixes Ghidra postScript output columns → ledger column mapping NOW, on the critical path.
- `runner/semantic_equiv.py` — **per-tool normalization spec (closes IMPROVE 4).** Canonical field extraction (DT_ tag→value pairs, segment table rows, symbol/version records) stripped of tool-specific formatting/addresses/ordering, so "interpretations split" is a **machine-decidable predicate over normalized structured fields**, not a text diff. **K is explicitly bounded** (fixed small constant, default 10): only the top-K divergent *classes* (by ld.so-involvement rank) are surfaced to Claude, as an aggregate class summary, never per-input.

**Reused:** `exp_e2/run_exp.sh` (audit:127), `exp_e3.link_case`, the `imap_unordered` worker skeleton (ETXTBSY-safe tmp, 5s timeout).
**Codified per-input contract (challenge c):** divergence flagging AND Ghidra promotion happen entirely inside `toolrunner.py`, ZERO Claude. Claude reads only the phase-level aggregate (counts, top-K divergent classes).
**Confirmed-timeout predicate (kills B12, audit:67):** a timeout is a crash **only** after two-budget confirmation — re-run at a larger budget; a slow-but-progressing load that completes is `SLOW_NORMAL`. Fixed 2s→crash (the B12 defect) is banned.
**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && python3 runner/toolrunner.py --in mutants/ --shards 8 --out rows/   # aggregate verdict line only
!  cd ~/PE/Lfuzzer && python3 runner/semantic_equiv.py --rows rows/ --k 10                # top-K divergent classes
```
**Observable verification:** one mutant → one row of per-tool `(rc, stdout-hash, stderr-signature, artifact-hash)`; Ghidra fires only on in-script-flagged divergent inputs; **zero `direct-execve`** (assert: mutant only ever a tool *input* — kills B01/B03/B09 false-positive class, audit:117).
**Risk:** Ghidra seconds–minutes/file at 24k → strict in-script tiered gate; classifier blocks the batch shell → emitted as a standalone user-run unit printing only an aggregate verdict line.

---

### Phase 4 — Differential oracle + full-observability ledger
**Artifacts (new):**
- `oracle/differential.py` — compares normalized observation vectors in-script; flags ① crash-divergence ② **semantic-divergence (none dies, interpretations split = evasion vein, spec:21)**; anchors on ld.so; records everything, ranks post-hoc.
- `ledger/ledger.py` + schema, `ledger/canon.py`, `ledger/merge_shards.py`.

**Single crash oracle (unifies the 3 contradictory ones, audit:117):** `signal-death (SEGV/ABRT/BUS) OR ASAN-report OR confirmed-timeout` (per the P3 two-budget rule); all other predicates deleted.
**Canonicalization before hashing (closes AC noise):** `canon.py` normalizes BEFORE content-addressing: (i) Ghidra `analyzeHeadless` output — strip analysis timestamps + name churn; (ii) ASAN report blobs — normalize run-varying addresses + timestamps. Raw uncanonicalized text kept as an advisory blob, never on the determinism path.
**Ghidra determinism resolution (closes BLOCKER b / critic Blocker 3 — PICK ONE, chosen):** **Ghidra is canonicalized ONTO the hash path.** `canon.py` strips analyzeHeadless timestamps + symbol-name churn to a stable normal form; the observation vector — including the Ghidra column on divergence rows — IS seed-reproducible. The advisory/non-hash-reproducible escape hatch (former open-Q #3) is **withdrawn**; the Phase-4 core AC "replay from seed reproduces the identical canonicalized observation vector" holds without exception. (If a residual analyzeHeadless nondeterminism survives canonicalization in practice, that is a P3 `ghidra_schema.py` defect to fix, not an AC to weaken.)
**Write path (per-worker shards + merge):** reused execution skeleton is `imap_unordered` multiprocess (audit:127) → **per-worker shard DBs + `merge_shards.py`** (single-writer SQLite is falsified). `ledger-db` path and `coverage-corpus` dir are **named unit interfaces**.
**Schema (one record per input):**
```
seed, region, field, value,
per-tool NORMALIZED observation vector (incl. canonicalized Ghidra column),
crash/ASAN verdict,
gate: location_match, fault_class_match, mechanism_match(bounds), bounds_violation, GATE_PATH_REACHES_L,
admission tag {ADMITTED | HARNESS_ARTIFACT | GATE_PATH_MISS},
gate_status {PROVISIONAL | CALIBRATED},
target budget, coverage-novel?, canonicalized-ASAN-blob-ref
+ one shared env-provenance header row (tool build hashes incl. disassembler + Ghidra version, ASLR state)
```
**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && python3 oracle/differential.py --rows rows/ --ledger ledger/shards/
!  cd ~/PE/Lfuzzer && python3 ledger/merge_shards.py ledger/shards/ --out ledger/full.db
!  cd ~/PE/Lfuzzer && python3 ledger/canon.py --selftest      # idempotence check
```
**Observable verification:** every split-verdict input flagged + carries a rank tuple; `ledger row count == inputs processed` (after shard merge); **replay from `seed` alone reproduces the identical *canonicalized* observation vector, Ghidra column included** (core AC).
**Risk — CHALLENGE (b):** raw-ELF storage forbidden (spec:35); seed is PK; ASAN blobs content-addressed out-of-row after canonicalization; columnar/append-only so oracle + ranker are pure column scans.

---

### Phase 5 — Seeded 3-region mutation dispatcher
**Artifacts (new):** `dispatch/seed_dispatch.py` — draws `region ∈ {PHT, DYNAMIC, SHT}`, **one region per file** (spec:13), routes to the right primitive, logs `seed+region+field+value`; consumes libFuzzer coverage from the P2 harness **where a coverage signal actually exists**.
**Coverage provenance — NOT uniform:**
```
DYNAMIC region → FULL loader coverage (harness drives the DT_ parse path)      → coverage-guided bias applies
PHT region     → PARTIAL (phdrs read in _dl_map_object_from_fd)                → partial bias
SHT region     → ZERO loader coverage (ld.so ignores section headers at load)  → NO coverage signal;
                 SHT value is static-parser-vs-loader EVASION divergence, not coverage
```
The plan does **not** claim uniform coverage guidance across all three regions.
**Reused:** `mutate_elf_v4.build_jobs` (field sweep + repair + MANIFEST, incl. B07/B22/B23 fixes per CHANGES:22-24), `mutator_dynamic_v3` (VERNEED/AUDIT/STRTAB meta, audit:126), `exp_e*` 1-field primitives, AFL region drivers (byte-containment assert, audit:126). Thin whole-ELF-random control lane only (spec:14).
**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && python3 dispatch/seed_dispatch.py --seed 12345 --mode record-only --out mut_a/
!  cd ~/PE/Lfuzzer && python3 dispatch/seed_dispatch.py --seed 12345 --mode record-only --out mut_b/  # diff mut_a vs mut_b: byte-identical
!  cd ~/PE/Lfuzzer && python3 dispatch/seed_dispatch.py --seed 12345 --feedback dynamic,pht           # bias only where signal exists
```
**Observable verification:** same `--seed` → byte-identical mutant + identical canonicalized observation vector (determinism AC); static assert each emitted file touched exactly one region (attribution AC); coverage-novel DYNAMIC/PHT inputs preserved across rounds (spec:66).
**Risk:** coverage-feedback wiring is the one genuinely new control loop → de-risk by running record-only first (confirm determinism), then enable feedback bias on DYNAMIC/PHT only.

---

### Phase 6 — 478/24k regression replay (full, by content hash)
**Artifacts (new):** `regression/replay_478.py` — replays the full dataset through the new pipe → validates plumbing + backfills differential/ASAN/gate columns.
**Note:** the 4-finding labeled *slice* was already pulled forward into P1; P6 is the full-corpus lossless pass (spec:38-39, spec:67).
**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && python3 regression/replay_478.py --corpus <478 dir> --index content-hash --ledger ledger/full.db
```
**Observable verification:** all 478 crashes reproduce lossless; the four known confirmed findings (spec:68) re-surface as ledger rows with matching (canonicalized) signatures.
**Risk — B26 trap (audit:98):** the 478 corpus files have **no extension**; any `.elf` filter zeroes the dataset (REFUTED "fix"). Guard: replay indexes by **content hash**, never by suffix.

---

### Phase 7 — Ranker
**Artifacts (new):** `rank/ranker.py` — post-hoc rank by ld.so-involvement · reproducibility · novelty (spec:20).
**Units (`!`):**
```
!  cd ~/PE/Lfuzzer && python3 rank/ranker.py --ledger ledger/full.db --top 50
```
**Observable verification:** ranked list where the known-confirmed bugs surface at/near the top; ranking is a **pure function of ledger columns** (re-runnable, no re-execution).
**Risk:** novelty dedup false-splitting (B14, audit:74: raw-hex `#0` address as bucket key inflates uniqueness) → key novelty on `frame0 symbol + normalized line`, never raw address (consistent with P4 canonicalization).

---

## 4. Risks & Mitigations

### CHALLENGE (a) — Harness fd-seam FIDELITY (now measured at a loader-computable violation resolution)
Four layered defenses:
1. **Codegen equivalence (P2):** canonicalized disasm-equivalence (not byte-identical) under pinned macros, against a FROZEN `codegen_norm.spec`, with a wrong-macro positive control → the compiled function IS the loader's. Machine-decidable HALT, no Claude adjudication.
2. **Real-bounds violation gate (P2.5, the decisive fix):** `mechanism_match = watchpoint_fired ∧ OOB-vs-real-segment-bounds`, bounds from `elf64.py`. This is a **violation** verdict the non-ASAN loader can compute — it admits genuine redzone bugs (the class iteration-3 silently discarded) and rejects harness redzone artifacts (the class the modality gap admitted). Closes the redzone hole with no ASAN rtld.
3. **Gate path-fidelity positive control + cap (P1):** `GATE_PATH_REACHES_L` gates the discard; a capped `GATE_PATH_MISS_MAX` prevents the bespoke-path escape hatch from becoming a per-target Claude factory (above the cap → HALT, harness-design signal).
4. **Staged discriminative calibration (P2.5):** gate PROVISIONAL until the artifact-rejection arm is calibrated on ≥50 real harness artifacts, with `bounds_oracle.py` as the in-script cross-check (no human spot-audit). Fidelity is a measured, cross-checked RATE.

### CHALLENGE (b) — FULL-observability ledger at 24k+ (write path + determinism resolved)
- No raw ELF stored; `seed` is PK; mutant regenerated on demand (spec:35,59).
- **Canonicalize Ghidra + ASAN + code BEFORE content-addressing** → dedup claim true, determinism AC passes on regressions not noise.
- **Ghidra is ON the hash path** (advisory escape hatch withdrawn) → the observation vector is seed-reproducible on divergence rows, the highest-value rows. No self-contradiction between the core AC and the Ghidra column.
- **Per-worker shard DBs + `merge_shards.py`** resolves multiprocess-vs-single-writer (audit:127); `ledger-db` + `coverage-corpus` are named interfaces.
- One env-provenance header row shared by all rows (tool build hashes incl. disassembler + Ghidra version, ASLR state).

### CHALLENGE (c) — USER-runnable units under the classifier (per-input logic is CODE, Claude reads AGGREGATE)
- **Per-input logic — divergence flagging, Ghidra promotion, reproduction gating, bounds adjudication — FULLY in-script, ZERO Claude.**
- **Three previously-leaking judgment seams are now NAMED in-script deciders:** `gate/asan_to_watchpoint.py` (report field → watchpoint expr), `gate/bounds_oracle.py` (replaces the P2.5 human spot-audit), and FROZEN `codegen_norm.spec` (tuning = out-of-band version bump, never per-input feedback; `--explain` dumps but does not mutate).
- **`GATE_PATH_MISS` escape hatch is capped** (`GATE_PATH_MISS_MAX`, default 8) → above it, HALT; generic unreachability is a harness-design signal, not a Claude patch loop.
- **Codegen HALT and semantic-divergence are machine-decidable** (frozen equivalence relation; per-tool normalization to structured fields with bounded K, default 10, stated up front).
- **Descent protocol (pre-declared per phase):** on AC fail Claude requests a NAMED finer `!` diagnostic unit — `codegen_equiv.sh --explain` (first divergent mnemonic pair), `canon.py --diff` (first non-canonical field), `calibrate.py --sample` (spot rows), `bounds_oracle.py --trace` (bounds computation). Pre-declared, not improvised.
- Named cross-unit interfaces: coverage-corpus dir (P2→P5), ledger-db path (P3→P4). Each unit prints one machine-parseable aggregate verdict line. Granularity: one unit per phase boundary — matches audit cluster seams, cheap to re-run.

---

## 5. ADR (final consensus record)
- **Decision:** Build **gate-before-harness** (coarse location+class reproduction gate + 4-finding labeled slice at P1, BEFORE the ASAN harness PoC at P2), then a **Phase-2.5 violation-arm build + discriminative calibration** on real harness artifacts. Split `REPRODUCED` into `{location_match, fault_class_match, mechanism_match}` where **`mechanism_match = watchpoint_fired ∧ OOB-vs-debug-loader-reconstructed-REAL-segment-bounds`** (a violation predicate the non-ASAN loader can compute, bounds from `elf64.py`). Admit via a per-function-budget-keyed **OR** predicate: `location_match ∧ (fault_class_match ∨ bounds_violation)` (signal-death OR real-OOB), MED/HIGH requiring bounds reconstruction. Gate the discard on a per-target `GATE_PATH_REACHES_L` positive control with a hard `GATE_PATH_MISS_MAX` cap. Enforce **canonicalized disasm-equivalence** (not byte-identical) against a FROZEN `codegen_norm.spec`. Name three in-script deciders (`asan_to_watchpoint.py`, `bounds_oracle.py`, `codegen_norm.spec`); the P2.5 human spot-audit is replaced by `bounds_oracle.py`. Canonicalize Ghidra + ASAN + code before hashing, with **Ghidra ON the hash path** (advisory escape hatch withdrawn). Bound cross-tool semantic-divergence with per-tool normalization + fixed K. SQLite-first seed-keyed ledger with per-worker shards + merge; sharded gate with a wall-clock budget; pre-declared per-phase descent units. Per-input logic and all equivalence/admission relations machine-decidable in-script; Claude reads aggregate only.
- **Drivers:** reproducibility contract (spec:16/59); ASAN-evidence fidelity at a loader-computable violation resolution; classifier division-of-labor (spec:58).
- **Alternatives considered:** keystone-first (spec order — instrument before validator); spine-first (validator early but harness/coverage late); **flat coarse gate** (fault-class+location — admits wrong-mechanism false bugs); **uniform strict gate** (mechanism-always — modality-blind, over-rejects shifted addresses); **iteration-3 access-happened `mechanism_match`** (AND-of-three — silently DISCARDS genuine redzone bugs as HARNESS_ARTIFACT because the non-ASAN loader emits no signal); byte-identical codegen check (never true for inlined `static inline`, forces human adjudication); reachability-only gate (iteration-1 hole); advisory-Ghidra column (contradicts the seed-reproducibility AC on the highest-value rows); single-writer SQLite with multiprocess writers (contradictory); Parquet-first ledger.
- **Why chosen:** the harness is the single most fidelity-risky and most load-bearing component (3 roles), but its fidelity is unprovable until the reproduction gate + labeled cases exist — so the validator precedes the instrument. Crucially, a validator must match the *modality* of what it validates: an ASAN bounds report is a **violation** claim, and the live loader is a **reachability** oracle (spec:26) — so matching access *location* more finely (iteration-3) cannot certify it, and under an AND-of-three it actively discards the redzone class ASAN exists for. The only violation verdict the non-ASAN loader CAN emit is **OOB-vs-real-bounds**, reconstructable from `elf64.py`; making that the precision floor, OR'd with signal-death, both closes the false-admit (harness redzone artifact, in-bounds in reality) and repairs the false-reject (genuine redzone bug, no signal but OOB in reality). Because the violation arm needs real ASAN reports, Phase-2.5 stages it honestly on the failure distribution that actually exists, with `bounds_oracle.py` as the in-script adjudicator that removes the last human judgment seam. Ghidra on the hash path removes the reproducibility self-contradiction at the highest-value rows.
- **Consequences:** the 4-finding labeled slice is pulled forward from P6 into P1; the mechanism arm is explicitly a P2.5 deliverable, not P1 (P1 proves only location+class); Phase-0 debug-ld.so + pinned-disassembler burden lands earlier; per-function verification cost rises (each target its own codegen-equivalence + bounds reconstruction + path control); a new Phase-2.5 checkpoint gates progress on real-artifact calibration; the gate carries a PROVISIONAL→CALIBRATED status column consumed by every downstream trust decision; Ghidra canonicalization must be robust enough to stay on the hash path (a P3 `ghidra_schema.py` obligation) — accepted, this is the fidelity price at the violation resolution.
- **Follow-ups (open questions — also persist to `.omc/plans/open-questions.md`):**
  1. Exact fd-seam entry symbol/version for glibc-2.39 `_dl_map_object_from_fd`, and the exact pinned macro set (`IS_IN(rtld)`, `DL_RO_DYN_SECTION`) the codegen-equivalence disasm must compile under.
  2. The exact segment-bounds reconstruction model for `bounds_oracle.py` under PIE/relocation — how the real `l_addr` from the debug loader combines with `elf64.read_phdrs` `p_vaddr`/`p_memsz` to yield the OOB test (must track relocation correctly).
  3. Whether `fault_class_match` and `bounds_violation` are both retained long-term or whether bounds subsumes fault-class for all but the unmapped-page SEGV class (resolved as complementary for v1; revisit after P2.5 data).
  4. The exact `codegen_norm.spec` rule set (which operand classes are addresses/relocs/symbols vs semantically load-bearing) — the boundary that keeps the HALT machine-decidable without over-relaxing (guarded by the wrong-macro control).
  5. The value of K (semantic-divergence classes surfaced to Claude, default 10) and the per-tool normalized field schema for readelf/objdump/pyelftools/Ghidra.
  6. `GATE_PATH_MISS_MAX` value (default 8) — tune once P1 reveals the real miss count.

## Pre-mortem (DELIBERATE mode — 3 failure scenarios)
1. **The redzone class is systematically MIS-HANDLED** (was mislabeled a LOW-budget tuning nuisance in iteration-3; it is the CRITICAL false-reject). If `bounds_oracle.py`'s segment reconstruction is wrong (e.g. mishandles PIE relocation), either genuine redzone OOBs read as in-bounds (false reject returns) or harness artifacts read as OOB (false admit). *Guard:* open-Q #2 pins the reconstruction model; a two-sided positive control at P2.5 — a KNOWN real-OOB fixture must yield `bounds_violation=1` AND a KNOWN in-bounds harness artifact must yield `0` — before the gate is CALIBRATED; `bounds_oracle.py --trace` is the descent unit.
2. **Codegen-equivalence normalizes away a real fidelity break.** The frozen spec strips an operand class that actually mattered. *Guard:* `codegen_norm.spec` is conservative (only addresses/relocs/symbols stripped, opcode+operand-class kept), FROZEN before P2 so no per-input feedback relaxes it, with a wrong-macro positive control asserting NOT-equivalent as part of P2 verification.
3. **Phase-2.5 artifact population stays empty at N=50.** Either the harness fabricates no wrong state or the gate silently admits everything. *Guard:* empty population is an explicit HALT (not a pass); `bounds_oracle.py` cross-check and `calibrate.py --sample` descent verify whether admits are genuine before promoting.

## Expanded test plan (DELIBERATE mode)
- **Unit:** `repro_gate.py` boolean emission on synthetic fixtures (each boolean independently forced); `bounds_oracle.py` on a known-OOB and a known-in-bounds pair (1/0); `asan_to_watchpoint.py` field→expr determinism; `codegen_equiv.sh` on a known-equivalent pair (PASS) and a deliberately-wrong-macro pair (HALT); `canon.py` idempotence incl. the Ghidra normal form; `semantic_equiv.py` normalization on hand-built divergent/identical tool-output pairs.
- **Integration:** P1→P2 handoff (harness first report → coarse gate admits under location+class); P2→P2.5 (50-candidate dual-run + bounds-arm build); P2.5 cross-oracle (bounds vs admission tag agree on the sample); P3→P4 (normalized observation vector incl. canonicalized Ghidra → sharded ledger row).
- **E2E (the decisive violation-modality test):** the five P2.5 fixtures (i)-(v) → expect ADMITTED / rejected(class) / HARNESS_ARTIFACT(bounds=0) / ADMITTED(bounds=1) / GATE_PATH_MISS. Iteration-3 collapsed (iii) and (iv) into a single discard.
- **Observability:** every row carries `{location, fault_class, mechanism(bounds), bounds_violation, GATE_PATH_REACHES_L, admission tag, gate_status, budget}`; one env-provenance header; `VERDICT` aggregate line per phase; `ledger row_count == inputs` post-merge; replay-from-seed reproduces the canonicalized vector including the Ghidra column.

## Verification steps (end-to-end)
- **Fidelity (decisive):** the five-input P2.5 E2E — fixture (iii) harness-redzone-artifact must be REJECTED via `bounds_violation=0`, and fixture (iv) genuine-redzone-bug must be ADMITTED via `bounds_violation=1`. This is the pair iterations 2-3 could not separate.
- **Codegen equivalence:** `codegen_equiv.sh` PASS on the shipped-vs-harness pair, HALT on the wrong-macro control; verdict machine-emitted against the frozen spec.
- **Gate path fidelity:** `path_control.py` asserts `GATE_PATH_REACHES_L=1` for each admitted target; unreachable → `GATE_PATH_MISS` (within `GATE_PATH_MISS_MAX`), not a discard.
- **Discriminative calibration:** P2.5 `VERDICT gate_status=CALIBRATED` only after ≥50 dual-runs with non-empty, bounds-cross-checked artifact population.
- **Determinism:** run any dispatcher unit twice with `--seed 12345` → identical mutant bytes + identical canonicalized observation vectors (Ghidra column included).
- **Ledger integrity:** `row_count == inputs` after shard merge; random row → regenerate from seed → re-run → canonicalized vector matches.
- **Regression:** replay 478 by content hash → all four known findings re-surface; row count unchanged; no extension-filter data loss (B26 guard holds).

---

## 6. Changelog — improvements applied from the consensus loop (iteration 3 → 4)
```
BLOCKER a (CRITICAL, critic-adjudicated over architect) ─▶ mechanism_match REDEFINED from "watchpoint fired"
  iteration-3 AND-of-three SILENTLY DISCARDED genuine        (access-happened) to "watchpoint fired ∧ OOB-vs-
  redzone bugs (fault_class=0 in a non-ASAN loader);         debug-loader-reconstructed-REAL-bounds" (a violation
  a false-REJECT of the dominant ASAN class (spec:25)        predicate; bounds from elf64.py, CHANGES:17). New
                                                             gate/bounds_oracle.py. Landed at P2.5 (real ASAN
                                                             reports exist only there).
Admission relaxed off over-strict AND (spec:28 reachability)▶ location_match ∧ (fault_class_match ∨ bounds_violation)
                                                             — OR, not AND. SEGV class via signal-death, redzone
                                                             class via real-OOB. Only harness artifacts (no signal
                                                             ∧ in-real-bounds) rejected.
BLOCKER c seam i (P2.5 human spot-audit) ────────────────▶ REPLACED by gate/bounds_oracle.py as an in-script
                                                             cross-oracle. No human confirms artifact tags.
BLOCKER c seam ii (ASAN-report→watchpoint per finding) ──▶ NAMED gate/asan_to_watchpoint.py (deterministic
                                                             field→watchpoint-expr map).
BLOCKER c seam iii (codegen-norm tuned per instance) ────▶ codegen_norm.spec FROZEN as a versioned artifact
                                                             before P2; --explain dumps but never mutates; tuning
                                                             is an out-of-band spec bump.
BLOCKER b (determinism self-contradiction) ─────────────▶ Ghidra put ON the hash path (canonicalized in
                                                             canon.py); advisory/non-reproducible escape hatch
                                                             WITHDRAWN. Core AC holds on divergence rows.
IMPROVE 1 (P1 overclaims mechanism arm) ────────────────▶ P1 relabeled: location+class + positive re-confirmation
                                                             ONLY; mechanism/bounds arm is a P2.5 deliverable
                                                             (4 legacy findings carry no ASAN-named slot, audit:128/130/132).
IMPROVE 4 (GATE_PATH_MISS unbounded escape hatch) ──────▶ hard cap GATE_PATH_MISS_MAX (default 8); above → HALT,
                                                             treated as harness-design signal, not Claude patch loop.
Pre-mortem #1 reclassified ──────────────────────────────▶ from "LOW-budget tuning nuisance" to the CRITICAL
                                                             redzone false-reject; guard tied to bounds_oracle.py
                                                             two-sided positive control.
LOW-budget justification audited ────────────────────────▶ "indexing is low-risk" now backed by the bounds check
                                                             as the precision floor (not an unaudited assertion).
Carried forward from iteration 3 (accepted): three-boolean ledger schema, per-target budget, canonicalized
  codegen-equivalence, per-tool semantic normalization + bounded K, SQLite per-worker shards + merge,
  gate-before-harness build order, Phase-2.5 staging, single crash oracle, B26/B14/B12 guards.
```
