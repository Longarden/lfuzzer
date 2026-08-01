# CHANGES 0715 — mutation refactor (branch `refactor/mutation-optim-0715`)

Software-maintainability refactor of the ELF mutation harness: de-duplicate ELF64
read primitives into a new shared `elf64.py`, make RNG reproducible, and apply a set
of audited logic-bug fixes. Behavior is preserved exactly except for the two rows
explicitly flagged as BEHAVIOR CHANGE.

Verified on 2026-07-15. Baseline for every diff/verify command below is the tag/branch
`refactor/mutation-optim-0715`. Base ELF used for smoke runs: `prac.elf` (15960 bytes).

---

## Edit → audit bug ID → behavior → verify command

| File | Bug ID | What changed | Behavior impact | Verify command |
|------|--------|--------------|-----------------|----------------|
| `elf64.py` (NEW) | dedup | New single-source module for ELF64 read primitives: `u16/u32/u64`, `read_phdrs`, `vaddr_to_offset`, `iter_dynamic`, `_selftest`. | None — pure extraction, byte/offset-exact. | `python3 elf64.py` → prints phdr/dynamic/section report + `elf64._selftest OK` |
| `autorun_v3.py` | dedup | `Elf` class now delegates PHT/DYNAMIC parsing + v2o to `elf64` (`from elf64 import u16,u32,u64`). Removed inline `s.loads` loop and `dyn()` walk. | None — same little-endian offsets, filesz-bounded v2o, 256-entry DT_NULL walk. | `python3 -c "import autorun_v3"` |
| `autorun_v3.py` | **B18** | Added `argparse` with `--seed`; `random.seed(seed)` once at startup; seed recorded in state (`st["seed"]`) and per-crash JSON. | Reproducible mutation RNG. A round replays from the logged seed. Default (no flag) auto-generates + logs a seed → still random but now recoverable. | `python3 autorun_v3.py --help` (shows `--seed`) |
| `autorun_v3.py` | **B28** | `seen` hashes kept in an insertion-ordered dict (was a `set`); trim keeps newest 60000. | Dedup semantics preserved; eviction now deterministic (newest-kept) instead of arbitrary set ordering. | `python3 -c "import autorun_v3"` |
| `mutate_elf_v4.py` | dedup | `import elf64` for read primitives (behavior-exact). | None. | `python3 mutate_elf_v4.py --help` |
| `mutate_elf_v4.py` | **B07** | Skip jobs whose output bytes hash-collide (`sha1`) with an already-emitted mutant. | Fewer duplicate output files; each emitted mutant is byte-unique. Crash coverage unchanged (identical bytes = identical behavior). | `python3 mutate_elf_v4.py prac.elf /tmp/out --max 3` then inspect `MANIFEST.tsv` |
| `mutate_elf_v4.py` | **B22** | For `repair_pht` jobs, skip the `keep` variant when it equals `violate` (repair_pht never touches EHDR, so they were identical). | Removes duplicate jobs; no unique mutant lost. | `python3 mutate_elf_v4.py prac.elf --list \| wc -l` (302 jobs) |
| `mutate_elf_v4.py` | **B23** | Honor `--modes` filter (removed hard-coded `violate`; iterate the requested modes). | `--modes keep` / `--modes violate` now actually filter. Default (both) unchanged. | `python3 mutate_elf_v4.py prac.elf --modes keep --list` |
| `mutator_field_v2.py` | dedup/seed | Per-worker seed `pid ^ time`, XOR'd with optional `base_seed`; `random.seed(seed)` per worker. | Reproducible when `base_seed` given; still diverse per worker otherwise. | `python3 -c "import mutator_field_v2"` |
| `mutator_field_v2.py` | **B21** | Removed the `ec==139` (128+SIGSEGV shell-convention) crash branch — wrong for `subprocess` return codes. Save behavior for the previously-mislabeled case is explicitly preserved. | Crash CLASSIFICATION changes (no longer assumes shell 128+signal), but which inputs get SAVED is unchanged. | `python3 -c "import mutator_field_v2"` |
| `mutator_interp_vaddr_v2.py` | dedup | `import elf64` shared read primitives. | None. | `python3 -c "import mutator_interp_vaddr_v2"` |
| `mutator_interp_vaddr_v2.py` | seed | Per-case deterministic RNG `random.Random(f"{seed}:{case_id}")` — reproducible even under `imap_unordered`. | Reproducible when `--seed` given; pid^time default otherwise. | `python3 -c "import mutator_interp_vaddr_v2"` |
| `mutator_interp_vaddr_v2.py` | **B09** (CONFIRMED) | A sanitizer report is treated as a genuine memory-safety crash. | Only genuine memory-safety failures count as crashes. | `python3 -c "import mutator_interp_vaddr_v2"` |
| `mutator_interp_vaddr_v2.py` | **B10** (BEHAVIOR CHANGE — UNDER VERIFICATION) | Mode "B" now lands JUST PAST the page ending the mapping (was `end - delta`, inside the mapping) so ld.so's strlen walks off the mapped region. | **Intentional behavior change.** Old formula probed inside the mapping and never fired the over-page-edge case. Needs PoV confirmation. | Run the interp mutator against ld.so and confirm the over-edge probe fires (see "commands to run yourself"). |
| `fuzzer_overlap.py` | dedup | `import elf64` shared read primitives (single source of truth). | None. | `python3 -c "import fuzzer_overlap"` |
| `mutator_shuffle.py` | dedup | Merged the ~95% `mutator_shuffle_gold.py` clone into a `TARGETS = {ld, gold}` dict; added `argparse`; PHT parsing via `elf64.read_phdrs`. | None — same shuffle logic; `gold` target selectable instead of a separate file. | `python3 -c "import mutator_shuffle"` |
| `legacy/mutator_field.py` | move | `git mv` from repo root (superseded by `_v2`). | Not imported anywhere active. | `git show --stat` |
| `legacy/mutator_interp_overflow.py` | move | `git mv` (superseded by `mutator_interp_vaddr_v2.py`). | Not imported. | `git show --stat` |
| `legacy/mutator_shuffle_gold.py` | move | `git mv` (folded into `mutator_shuffle.py` TARGETS). | Not imported. | `git show --stat` |

---

## Guard: refuted fixes NOT applied

Two refuted fixes were explicitly grep-guarded and confirmed ABSENT:

| Refuted fix | Guard | Result |
|-------------|-------|--------|
| Newly-added `.elf` filename filter (`.endswith(".elf")`) | `git diff refactor/mutation-optim-0715 -- . \| grep -nE "endswith\(.'?\.elf"` | 0 matches — NOT applied |
| Change to `mutator_dynamic_v3.py` `pf` field | `git diff refactor/mutation-optim-0715 -- mutator_dynamic_v3.py \| wc -l` | 0 lines — file untouched |

Note: `grep "\bpf\b"` on the full diff matches only `autorun_v3.py` lines 44-45 — a REMOVED local
loop variable (`for pv,po,pf in s.loads`) that was refactored into `elf64.vaddr_to_offset` (behavior-exact).
This is not the refuted `mutator_dynamic_v3.py` pf change.

---

## Verification results (2026-07-15, all via `wsl.exe -e bash -lc`)

- AST parse: OK for all 9 kept files (elf64, mutate_elf_v4, autorun_v3, mutator_interp_vaddr_v2, mutator_field_v2, mutator_shuffle, mutator_dynamic_v3, fuzzer_overlap, drivers/common).
- `python3 elf64.py` and `import elf64; elf64._selftest()` → both `OK`, exit 0.
- `import` of all 7 mutator modules → OK.
- `import drivers.common` → OK.
- `mutate_elf_v4.py --help` → exit 0.
- `mutate_elf_v4.py prac.elf --list` → 302 lines, exit 0 (3091 jobs reported).
- `mutate_elf_v4.py prac.elf <tmp> --max 3` → generated 2 unique files + MANIFEST.tsv, exit 0 (B07 dedup collapsed 3→2).
- `autorun_v3.py --help` → shows `--seed`, exit 0.

---

## Commands to run yourself

Nothing was blocked in the verify environment; all commands above executed. The items below
are follow-ups the harness cannot fully validate here:

```bash
# B10 PoV — confirm the intentional over-page-edge behavior change fires against a real loader.
# (Requires a target ld.so + the interp mutator's live run path; do NOT launch large fuzzing.)
cd ~/PE/Lfuzzer && python3 mutator_interp_vaddr_v2.py --help   # inspect run options first

# B18 reproducibility — run two short rounds with the same seed and diff the crash sets.
cd ~/PE/Lfuzzer && python3 autorun_v3.py 30 --seed 12345
cd ~/PE/Lfuzzer && python3 autorun_v3.py 30 --seed 12345       # crash hashes should match

# Full staged review before committing (staging done during verify; NOT committed):
cd ~/PE/Lfuzzer && git diff --cached --stat
```
