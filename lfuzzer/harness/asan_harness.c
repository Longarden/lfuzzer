/* asan_harness.c — V1 in-process, real-sanitizer target for ld.so dynamic parsing
 *
 * STATUS: COMPILABLE SKELETON (not a working harness). Every place that needs a
 * real glibc symbol or a real fixture is marked TODO() and will not link until
 * you build against a glibc source TU (see build_harness.sh) and drop in a
 * captured link_map fixture. The point of this file is to pin the *shape* of the
 * harness — entrypoints, precondition fixture, phantom-bug guards, reporting
 * categories — so the C build is a fill-in, not a design task.
 *
 * WHY V1 (kills W1): baseline runs raw production ld.so under AFL++ QEMU. That is
 * (a) slow (whole-process exec per input) and (b) memory-blind — the "ASAN" in
 * the baseline is a debug+assert glibc rerun (rerun_debug_ldso.py), NOT
 * -fsanitize=address. A non-crashing heap OOB read inside verneed/DT_ parsing is
 * invisible there. V1 replaces both: in-process persistent loop (100–1000x
 * exec/s, AFL++ WOOT'20 persistent mode) + a *real* ASan oracle that sees silent
 * memory corruption.
 *
 * ORACLE CONTRACT (matches PIPELINE_VARIANTS V1 / V5): ASan is a *detector*, not
 * an adjudicator. A fire here is a CANDIDATE. Authority for "confirmed unique
 * bug" stays with CASR + the Tier-B stock-ld.so replay below. MCP/LLM never
 * touches this path.
 *
 * BUILD: see build_harness.sh (afl-clang-fast OR clang -fsanitize=address,fuzzer).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <link.h>      /* struct link_map, ElfW(...) */
#include <elf.h>

/* ------------------------------------------------------------------------- *
 * 0. Phantom-bug problem statement (read before touching the fixture)
 * ------------------------------------------------------------------------- *
 * ld.so's dynamic-section parsers (elf_get_dynamic_info, the verneed walk,
 * _dl_map_object_from_fd) are NOT standalone parsers. They assume their input
 * arrived through a real, consistent load:
 *   - l_addr is the actual mmap load bias; DT_ pointers are relocated by +l_addr.
 *   - l_ld points at a PT_DYNAMIC that lives inside a correctly mmap'd segment.
 *   - the enclosing PT_LOADs are mapped with the right sizes/prot.
 *
 * If we hand these functions a link_map we fabricated from raw fuzz bytes, they
 * dereference (l_addr + DT_val) into memory WE never mapped. Every such crash is
 * a PHANTOM BUG — an artifact of a malformed fixture, not a loader defect.
 * Reporting phantoms poisons the unique-bug metric.
 *
 * PRECONDITION-FIXTURE STRATEGY (captured link_map replay):
 *   1. Once, at process start, do a REAL load of a benign, minimal DSO (the
 *      "carrier") so the kernel/loader build a valid link_map with valid PT_LOAD
 *      mappings, valid l_addr, valid l_ld. Snapshot it — this is the fixture.
 *   2. Per fuzz input, DO NOT rebuild a link_map. Instead overwrite ONLY the
 *      bytes of the carrier's already-mapped PT_DYNAMIC (and, for the verneed
 *      walk, its DT_VERNEED region) with the mutated bytes, clamped to the
 *      region we actually own. Then zero l_info[] and re-run the parser on the
 *      SAME, still-valid mapping.
 *   3. Result: pointer arithmetic still lands inside memory we mapped, so a
 *      crash means the *parser* walked out of bounds given in-bounds structure —
 *      a real loader bug — not that we pointed it at nothing.
 *
 * This is deliberately narrower than "load arbitrary mutated ELF". It trades
 * reach for signal purity: V2 (structure-aware input) widens what reaches here;
 * V1's job is to make what reaches here TRUSTWORTHY.
 */

/* ------------------------------------------------------------------------- *
 * TODO() marker — compiles, but forces a link/build failure until filled.
 * We intentionally reference an undefined symbol so `nm` / the linker flags any
 * unfinished path instead of it silently no-op'ing at runtime.
 * ------------------------------------------------------------------------- */
extern void TODO_unimplemented(const char *what);
#define TODO(what) TODO_unimplemented(what)

/* ========================================================================= *
 * 1. Fixture: captured, valid link_map for the carrier DSO
 * ========================================================================= */

/* Holds everything the parsers need + the writable window we are allowed to
 * mutate (the carrier's PT_DYNAMIC image, in mapped memory). */
typedef struct {
    struct link_map *carrier;      /* real link_map from the one-time real load  */
    ElfW(Dyn)       *dyn_window;   /* == carrier->l_ld : writable, mapped         */
    size_t           dyn_capacity; /* # of ElfW(Dyn) entries we own (clamp here)  */
    /* Pristine copy of the carrier's original dynamic image, restored between
     * inputs so state never leaks across fuzz iterations. */
    ElfW(Dyn)       *dyn_pristine;
    int              ready;
} fixture_t;

static fixture_t g_fx;

/* One-time: perform a REAL load of the benign carrier and snapshot its link_map.
 * Returns 0 on success. Called once from LLVMFuzzerInitialize. */
static int fixture_init(void) {
    /* TODO(): dlopen()/dlmopen(LM_ID_NEWLM, ...) a MINIMAL, trusted carrier .so
     *   built by build_harness.sh, so glibc constructs a valid link_map with
     *   real PT_LOAD mappings. Grab it via the returned handle / _r_debug /
     *   dl_iterate_phdr. DO NOT fabricate this struct by hand. */
    TODO("fixture_init: real carrier load + link_map snapshot");

    /* Sketch of what must be populated after the real load:
     * g_fx.carrier      = <link_map* of carrier>;
     * g_fx.dyn_window   = g_fx.carrier->l_ld;          // already mapped, writable page
     * g_fx.dyn_capacity = <count PT_DYNAMIC entries>;  // from the carrier's PT_DYNAMIC filesz
     * g_fx.dyn_pristine = <malloc + memcpy of dyn_window>;
     * g_fx.ready = 1;
     */
    return -1;
}

/* Restore the carrier's dynamic image to pristine so iteration N+1 does not see
 * iteration N's mutation. Cheap; runs every input. */
static void fixture_reset(void) {
    if (!g_fx.ready) return;
    memcpy(g_fx.dyn_window, g_fx.dyn_pristine,
           g_fx.dyn_capacity * sizeof(ElfW(Dyn)));
    /* TODO(): also zero carrier->l_info[] before each parse. l_info lives in
     * glibc's INTERNAL struct link_map (elf/link.h under IS_IN(rtld)), not the
     * public <link.h> one, so it is only reachable once build_harness.sh puts
     * the internal include path on the command line. Left as a TODO so the
     * skeleton stays syntax-clean against public headers. */
    TODO("fixture_reset: zero carrier->l_info[] (needs glibc-internal link_map)");
}

/* Splice mutated bytes into the mapped dynamic window, CLAMPED to what we own.
 * Clamping is the second phantom-bug guard: an over-long fuzz input can never
 * make us write past the carrier's real PT_DYNAMIC page. */
static void fixture_splice(const uint8_t *data, size_t size) {
    size_t cap_bytes = g_fx.dyn_capacity * sizeof(ElfW(Dyn));
    size_t n = size < cap_bytes ? size : cap_bytes;
    memcpy(g_fx.dyn_window, data, n);
}

/* ========================================================================= *
 * 2. Entrypoints under test (see entrypoints.md for selection rationale)
 * ========================================================================= *
 * Ordered easiest→deepest. Start with EP1; it is the purest parser and the
 * cheapest to fixture. EP2/EP3 need more of the load state wired up.
 */

/* --- EP1: elf_get_dynamic_info — DT_ tag table → l_info[] -----------------
 * elf/get-dynamic-info.h. A near-pure transform: walks the PT_DYNAMIC array and
 * indexes each DT_ tag into l->l_info[]. It also does light validation
 * (DT_*NUM bounds, relocation of pointer-valued tags by l_addr). Highest-value
 * first target: no I/O, tiny fixture, directly exercises the mutated bytes. */
static void run_elf_get_dynamic_info(void) {
    /* TODO(): call glibc's  elf_get_dynamic_info(carrier, bootstrap=0,
     *   static_pie_bootstrap=0).  It is a static inline in a header, so the
     *   harness TU must include the glibc internal header under the right
     *   feature macros (build_harness.sh sets the include path + -D_GNU_SOURCE
     *   and the internal build defines). See entrypoints.md EP1 for the exact
     *   include and the macro set. */
    TODO("EP1: elf_get_dynamic_info(carrier)");
}

/* --- EP2: verneed / version walk -----------------------------------------
 * elf/dl-version.c : _dl_check_map_versions -> walks DT_VERNEED chain
 * (Elf_Verneed vn_next / vn_aux Elf_Vernaux vna_next), cross-indexes DT_VERSYM
 * against the string table. This is the historically bug-rich path (llvm
 * getVersionDependencies VERNEED DoS was found on the analyzer side; the loader
 * side is under-fuzzed). Needs l_info[] already populated → run EP1 first. */
static void run_verneed_walk(void) {
    /* PRECONDITION: EP1 populated l_info[DT_VERNEED], DT_VERNEEDNUM, DT_STRTAB,
     * DT_VERSYM. The verneed structs live at l_addr + DT_VERNEED, which — thanks
     * to the fixture — is inside the carrier's mapping. */
    /* TODO(): call _dl_check_map_versions(carrier, verbose=0, trace_mode=0).
     *   Guard: if l_info[VERSYMIDX(DT_VERNEED)] is NULL after EP1, skip (no
     *   verneed to walk) -- skipping is correct, not a miss. */
    TODO("EP2: _dl_check_map_versions(carrier)");
}

/* --- EP3: _dl_map_object_from_fd — full map path -------------------------
 * elf/dl-load.c. The heaviest target: given an fd to an ELF image it mmaps
 * PT_LOADs, reads PT_DYNAMIC, calls the above. Closest to production, but the
 * hardest to keep phantom-free because IT does the mapping, so a mutated
 * PT_LOAD can legitimately map (or fail to map) memory — meaning the "in-bounds
 * structure" guarantee of the EP1/EP2 fixture does NOT hold. Treat EP3 as a
 * SEPARATE, later mode with its own confirmation discipline, not the default. */
static void run_map_object_from_fd(const uint8_t *data, size_t size) {
    /* TODO(): write `data` to a memfd_create() fd, then call the (many-arg)
     *   internal _dl_map_object_from_fd(...). Because EP3 maps attacker-chosen
     *   PT_LOADs, phantom risk is high — gate EP3 behind an env flag and rely
     *   MORE heavily on the Tier-B stock replay below. See entrypoints.md §EP3
     *   for the full argument list and the memfd fixture. */
    (void)data; (void)size;
    TODO("EP3: _dl_map_object_from_fd(memfd)");
}

/* ========================================================================= *
 * 3. Tier-B: stock-ld.so confirmation (phantom filter + report category)
 * ========================================================================= *
 * An ASan fire in-process is necessary but NOT sufficient. Two failure modes we
 * must separate:
 *   (a) REAL loader bug  — stock ld.so also mishandles the same input.
 *   (b) HARNESS artifact — our fixture/splice created a state the real loader
 *       would never construct; stock ld.so is fine.
 *
 * Tier-B replay (run OUT of the hot loop, on saved ASan-firing inputs only):
 *   - Materialize the input as a real ELF/DSO and run it under STOCK
 *     /lib64/ld-linux-x86-64.so.2 (config.LOADER) exactly like the baseline.
 *   - Also run under the debug+assert loader (config.LFUZZER_DEBUG_LOADER).
 *
 * Resulting REPORTING CATEGORIES (feed to V5/CASR, never to the metric raw):
 *   ┌─ ASAN + stock CRASHES        → strong: crashing loader bug, both oracles agree.
 *   ├─ ASAN + stock CLEAN          → "ASAN-CONFIRMED / STOCK-CLEAN": the V1-UNIQUE
 *   │                                category. Silent OOB the baseline QEMU loop
 *   │                                is blind to (W1). HIGH research value BUT must
 *   │                                pass fixture-artifact review before counting.
 *   ├─ ASAN clean + stock crashes  → not a V1 find; belongs to the crash oracle.
 *   └─ ASAN + debug-loader assert  → corroborating third signal for either row above.
 *
 * This harness does NOT decide the category. It emits the ASan report + the input
 * to disk; unified_runner/V5 runs Tier-B and CASR does the adjudication.
 */
static void tierB_note(void) {
    /* Intentionally empty in-process. Documented here so the boundary is explicit:
     * confirmation is an out-of-loop responsibility (see README §"plugging in"). */
}

/* ========================================================================= *
 * 4. libFuzzer / AFL++ persistent entrypoints
 * ========================================================================= */

/* libFuzzer one-time init hook. AFL's persistent mode (afl-clang-fast) also
 * honors LLVMFuzzerInitialize via the AFL libFuzzer shim. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    if (fixture_init() != 0) {
        /* Fixture failed to build → refuse to run rather than emit phantoms. */
        TODO("LLVMFuzzerInitialize: fixture_init failed — abort, do not fuzz");
    }
    (void)tierB_note;
    return 0;
}

/* THE hot path. Same body serves libFuzzer and, under afl-clang-fast, the
 * AFL_LOOP() persistent harness (see build_harness.sh). Keep it allocation-free
 * and side-effect-free except for the reset/splice/parse triad — that is what
 * makes 100–1000x exec/s (WOOT'20 persistent mode) real. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_fx.ready) return 0;          /* never fuzz without a valid fixture */
    if (size < sizeof(ElfW(Dyn))) return 0;

    fixture_reset();                    /* isolate iterations                 */
    fixture_splice(data, size);         /* mutate ONLY the owned window       */

    run_elf_get_dynamic_info();         /* EP1 (default)                      */
    run_verneed_walk();                 /* EP2 (needs EP1)                    */
    /* run_map_object_from_fd(data,size);   EP3: enable via build flag only   */

    return 0;                           /* ASan aborts the process on a fire  */
}

/* ------------------------------------------------------------------------- *
 * 5. __main__-style demo (parity with the Python modules' `if __name__`):
 * a standalone main so the skeleton can be compiled WITHOUT libFuzzer to prove
 * it builds and to smoke-test the fixture wiring. Guarded so it never collides
 * with the libFuzzer/AFL driver's own main.
 * ------------------------------------------------------------------------- */
#ifdef HARNESS_STANDALONE_DEMO
#include <stdio.h>
int main(int argc, char **argv) {
    fprintf(stderr,
        "[asan_harness demo] skeleton only — fixture + glibc TU are TODO.\n"
        "  build a real harness with build_harness.sh, then run under AFL++/libFuzzer.\n");
    if (LLVMFuzzerInitialize(&argc, &argv) != 0) return 1;
    static const uint8_t probe[16] = {0};
    return LLVMFuzzerTestOneInput(probe, sizeof probe);
}
#endif
