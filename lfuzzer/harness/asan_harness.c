/* asan_harness.c — V1 in-process, REAL-AddressSanitizer target for ld.so-style
 *                  ELF64 dynamic-section parsing.
 *
 * =========================================================================
 * WHAT THIS IS (and why it kills baseline W1)
 * =========================================================================
 * The project baseline (W1) runs *stock* production ld.so under AFL++ QEMU:
 *   (a) SLOW    — a whole-process exec per input, no persistent loop.
 *   (b) MEMORY-BLIND — its "ASAN" was a debug+assert glibc rerun
 *       (rerun_debug_ldso.py), NOT -fsanitize=address. A *non-crashing* heap
 *       over-read inside verneed / DT_ / dynstr parsing is INVISIBLE there.
 *
 * V1 replaces both. It is an in-process, coverage-instrumented, REAL ASan
 * target (clang -fsanitize=address,fuzzer / afl-clang-fast + AFL_USE_ASAN)
 * that re-implements — faithfully and deliberately UN-hardened — the exact
 * pointer walks ld.so performs over an ELF's .dynamic array, program headers,
 * and symbol-version (verneed/versym) tables. Because the input image lives in
 * a tight ASan heap allocation, an out-of-bounds *read* that ld.so would
 * perform silently trips an ASan redzone here and is reported.
 *
 *   Citations:  AFL++ persistent mode — Fioraldi et al., WOOT'20.
 *               LLVM libFuzzer      — llvm.org/docs/LibFuzzer.html
 *
 * =========================================================================
 * ORACLE CONTRACT (matches docs/PIPELINE_VARIANTS.md §V1 / §V5)
 * =========================================================================
 * ASan here is a *DETECTOR*, not an adjudicator. A fire is a CANDIDATE.
 * Authority for "confirmed unique bug" stays with V5 CASR + the Tier-B
 * stock-ld.so replay (run OUT of this hot loop, on saved firing inputs only).
 * MCP/LLM never touches this path.
 *
 * =========================================================================
 * THE TRUST MODEL — the whole point of the harness
 * =========================================================================
 * ld.so's dynamic parsers do NOT validate attacker-controlled offsets/sizes/
 * counts. They read DT_STRTAB / DT_SYMTAB / DT_VERNEED / p_offset / vn_next /
 * vna_name and dereference `base + value` on trust. We mirror that trust
 * EXACTLY, with ONE concession: before every dereference we check that the
 * START offset lands inside the mapped image (`off <= image_size`). That single
 * clamp is not "hardening" — it is the substitute for the real mapping bounds
 * that a genuine mmap load would enforce. It converts a *wild* pointer (d_val =
 * 0x4000000000 -> a useless far-away SIGSEGV) into a "skip", while STILL letting
 * a structure/string whose start is in-bounds but whose *body runs past the end*
 * over-read into the ASan redzone — which is precisely the interesting bug class
 * (verneed/dynstr over-read). Sequential scans (phdr[i], Dyn[i], vernaux chains)
 * are self-limiting under ASan: the first entry that crosses the boundary aborts
 * the process, so a bogus e_phnum=0xffff never actually walks 3 MB.
 *
 * Each parse site is commented with the ld.so function it mirrors:
 *   open_verify / _dl_map_object_from_fd  (magic + phdr scan)
 *   elf_get_dynamic_info                  (.dynamic -> l_info[] transform)
 *   _dl_check_map_versions                (verneed/vernaux/versym walk)
 *
 * =========================================================================
 * BUILD (see build_harness.sh; guaranteed path is self-contained, no glibc):
 *   clang -g -fsanitize=address,fuzzer asan_harness.c -o v1_harness
 *   afl-clang-fast -fsanitize=fuzzer + AFL_USE_ASAN=1 ...   (persistent)
 * Standalone smoke (no libFuzzer runtime):
 *   clang -g -fsanitize=address -DHARNESS_STANDALONE_DEMO asan_harness.c -o v1_demo
 *   ./v1_demo some.elf
 * Gated glibc-internal entrypoint (SECOND, optional path):
 *   clang ... -DUSE_GLIBC_INTERNAL -DGLIBC_SRC_ELF=/home/you/glibc/glibc-src/elf ...
 * ========================================================================= */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>       /* Elf64_Ehdr / Phdr / Dyn / Sym / Verneed / Vernaux */

/* ------------------------------------------------------------------------- *
 * Optional SECOND path: call the REAL glibc transform (elf_get_dynamic_info).
 * Gated behind -DUSE_GLIBC_INTERNAL. It needs glibc's internal header, which
 * pulls a large private include/define set — so we do NOT wire the full call
 * here (that belongs to build_harness.sh's glibc-TU mode). Instead we detect
 * whether the header path was provided and degrade to a clear compile-time
 * message otherwise, exactly as the task requires.
 * ------------------------------------------------------------------------- */
#ifdef USE_GLIBC_INTERNAL
#  ifndef GLIBC_SRC_ELF
#    error "USE_GLIBC_INTERNAL set but GLIBC_SRC_ELF=<glibc>/elf not provided. \
Locate it with: find ~/glibc -name get-dynamic-info.h ; then pass \
-DGLIBC_SRC_ELF=/abs/path/to/glibc/elf and the glibc internal include/define \
set (see build_harness.sh). Falling back is not automatic on purpose."
#  endif
   /* NOTE: the actual `#include <get-dynamic-info.h>` + elf_get_dynamic_info()
    * call is performed only in build_harness.sh's glibc-TU compilation unit,
    * where the full private include search order and feature macros
    * (_RTLD_LOCAL_, IS_IN(rtld), ...) are set. Reaching it from THIS TU without
    * that scaffold does not compile — which is the intended, honest signal. */
#endif

/* ========================================================================= *
 * 0. Bounds primitive — the ONE clamp (mirrors the real mapping's extent)
 * ========================================================================= *
 * in_map(off,size)  -> is `off` a legal START inside the mapped image?
 *   - off == size is allowed (one-past-end): dereferencing there trips the
 *     right-hand ASan redzone, which is a legitimate over-read report.
 *   - We DO NOT check off+len<=size. That overshoot IS the bug we hunt; ASan
 *     catches it. Checking it would be the hardening ld.so does not have.
 */
static inline int in_map(uint64_t off, size_t size) {
    return off <= (uint64_t)size;
}

/* Read a NUL-terminated string the way ld.so consumes .dynstr entries: no
 * length bound, trusting the terminator. If `base+idx` starts in-bounds but the
 * string has no NUL before the image end, the scan walks straight into the ASan
 * redzone and reports a heap-buffer-overflow — the classic dynstr over-read.
 * We only guard the START (in_map); the scan itself is deliberately unbounded
 * so ASan, not us, decides where it ends. Returns the string length "seen". */
static size_t touch_dynstr(const uint8_t *img, size_t size,
                           uint64_t strtab_off, uint64_t str_idx) {
    uint64_t o = strtab_off + str_idx;         /* ld.so: strtab + st_name/vna_name */
    if (!in_map(o, size)) return 0;            /* wild index -> skip (not a segv)   */
    const char *s = (const char *)(img + o);
    /* volatile sink so the compiler cannot elide the reads that ASan must see. */
    volatile char sink = 0;
    size_t n = 0;
    while (s[n] != '\0') {                      /* <-- OOB read lands here on a  */
        sink = (char)(sink ^ s[n]);            /*     non-terminated string      */
        n++;
    }
    (void)sink;
    return n;
}

/* ========================================================================= *
 * 1. PT_DYNAMIC location — mirrors open_verify / _dl_map_object_from_fd
 * ========================================================================= *
 * ld.so reads the program header table straight out of the mapped image and
 * scans it for PT_DYNAMIC. We do the identical arithmetic (e_phoff + i*phentsize)
 * over e_phnum entries. e_phoff/e_phnum are attacker-controlled: a bogus e_phoff
 * far past the image is rejected by in_map (would be a wild segv); a bogus
 * e_phnum that runs the sequential scan off the end trips the redzone at the
 * first out-of-range entry and ASan aborts — self-limiting, no 3 MB walk.
 * Returns the file offset of PT_DYNAMIC's contents (p_offset) and its p_filesz,
 * or 0/0 if none found.
 */
static void find_dynamic(const uint8_t *img, size_t size,
                         const Elf64_Ehdr *eh,
                         uint64_t *out_dyn_off, uint64_t *out_dyn_sz) {
    *out_dyn_off = 0;
    *out_dyn_sz  = 0;

    uint64_t phoff = eh->e_phoff;              /* trusted, like ld.so */
    uint16_t phnum = eh->e_phnum;
    uint16_t phentsize = eh->e_phentsize;      /* ld.so assumes == sizeof(Phdr) */
    if (phentsize == 0) phentsize = sizeof(Elf64_Phdr);

    if (!in_map(phoff, size)) return;          /* wild e_phoff -> skip */

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t poff = phoff + (uint64_t)i * phentsize;
        /* Guard only the START of THIS entry. If it is in-map but the 56-byte
         * Phdr body overshoots the image end, the typed read below over-reads
         * into the redzone -> ASan fires (real "phnum too large" bug shape). */
        if (!in_map(poff, size)) break;        /* sequential scan crossed the end */
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(img + poff);
        if (ph->p_type == PT_DYNAMIC) {         /* <-- read may hit redzone here  */
            *out_dyn_off = ph->p_offset;        /* attacker-controlled file offset */
            *out_dyn_sz  = ph->p_filesz;        /* attacker-controlled span        */
            return;
        }
    }
}

/* ========================================================================= *
 * 2. .dynamic transform — mirrors elf_get_dynamic_info (get-dynamic-info.h)
 * ========================================================================= *
 * ld.so walks the ElfW(Dyn) array and indexes each DT_ tag into l_info[]. We
 * capture the tags we care about (the string/symbol/version tables) into a tiny
 * local table, doing the SAME "trust d_val" you see in elf_get_dynamic_info,
 * then follow those offsets into the image in §3/§4 exactly as the later loader
 * stages do. The array walk itself is bounded only by the mapping and by a hard
 * iteration cap (a bogus DT array with no DT_NULL must not spin forever — that
 * is a hang guard, not a memory-safety guard).
 */
typedef struct {
    int      have_strtab, have_symtab, have_verneed, have_versym, have_hash;
    uint64_t strtab, strsz;      /* DT_STRTAB (offset), DT_STRSZ  */
    uint64_t symtab, syment;     /* DT_SYMTAB (offset), DT_SYMENT */
    uint64_t verneed, verneednum;/* DT_VERNEED(offset), DT_VERNEEDNUM */
    uint64_t versym;             /* DT_VERSYM (offset) */
    uint64_t hash;               /* DT_HASH   (offset) */
} dyninfo_t;

static void get_dynamic_info(const uint8_t *img, size_t size,
                             uint64_t dyn_off, uint64_t dyn_sz,
                             dyninfo_t *di) {
    memset(di, 0, sizeof(*di));
    if (!in_map(dyn_off, size)) return;        /* wild p_offset -> skip */

    /* ld.so trusts p_filesz for the entry count; we do too, but cap the walk so
     * a missing DT_NULL cannot hang the fuzz loop. The cap is generous (one Dyn
     * per possible byte) so it never masks a real over-read — ASan still fires
     * first on any entry that crosses the image end. */
    uint64_t declared = dyn_sz / sizeof(Elf64_Dyn);
    uint64_t cap = (uint64_t)size / sizeof(Elf64_Dyn) + 1;
    uint64_t nmax = declared ? declared : cap;
    if (nmax > cap) nmax = cap;

    for (uint64_t i = 0; i < nmax; i++) {
        uint64_t eoff = dyn_off + i * sizeof(Elf64_Dyn);
        if (!in_map(eoff, size)) break;        /* sequential scan hit the end */
        const Elf64_Dyn *d = (const Elf64_Dyn *)(img + eoff); /* may hit redzone */
        Elf64_Sxword tag = d->d_tag;
        uint64_t     val = d->d_un.d_val;

        if (tag == DT_NULL) break;             /* faithful terminator */
        switch (tag) {
        case DT_STRTAB:     di->strtab = val;      di->have_strtab  = 1; break;
        case DT_STRSZ:      di->strsz  = val;                            break;
        case DT_SYMTAB:     di->symtab = val;      di->have_symtab  = 1; break;
        case DT_SYMENT:     di->syment = val;                            break;
        case DT_VERNEED:    di->verneed = val;     di->have_verneed = 1; break;
        case DT_VERNEEDNUM: di->verneednum = val;                        break;
        case DT_VERSYM:     di->versym = val;      di->have_versym  = 1; break;
        case DT_HASH:       di->hash   = val;      di->have_hash    = 1; break;
        default: break;                        /* ignore the rest, like l_info fill */
        }
    }
}

/* ========================================================================= *
 * 3. Symbol + string table touch — mirrors the .dynsym/.dynstr consumers
 * ========================================================================= *
 * Once l_info[DT_SYMTAB]/[DT_STRTAB] are set, ld.so resolves symbols by reading
 * Elf64_Sym records at symtab + i*syment and their names at strtab + st_name.
 * We touch the first few symbols (bounded, since we have no real symbol count
 * here) and follow each st_name into .dynstr. A DT_STRTAB/DT_SYMTAB pointing
 * near the image end, or an st_name past DT_STRSZ, over-reads into the redzone.
 */
static void touch_symbols(const uint8_t *img, size_t size, const dyninfo_t *di) {
    if (!di->have_symtab || !di->have_strtab) return;
    uint64_t syment = di->syment ? di->syment : sizeof(Elf64_Sym);
    if (syment < sizeof(Elf64_Sym)) syment = sizeof(Elf64_Sym);

    /* We do not trust a symbol count from the input (there isn't a clean one
     * without DT_HASH/GNU_HASH parsing); probe a small fixed window. Each probe
     * still runs the same trusted `symtab + i*syment` arithmetic ld.so uses. */
    for (uint64_t i = 0; i < 8; i++) {
        uint64_t soff = di->symtab + i * syment;
        if (!in_map(soff, size)) break;
        const Elf64_Sym *sym = (const Elf64_Sym *)(img + soff); /* may hit redzone */
        /* Follow the name into .dynstr exactly as _dl_lookup_symbol_x would. */
        (void)touch_dynstr(img, size, di->strtab, sym->st_name);
    }
}

/* ========================================================================= *
 * 4. Version walk — mirrors _dl_check_map_versions (elf/dl-version.c)
 * ========================================================================= *
 * THE historically bug-rich path, and the analyzer-side analogue
 * (llvm-objdump getVersionDependencies VERNEED DoS) is already a confirmed
 * candidate in this project (memory: project_elf_parser_diff). The loader-side
 * verneed walk is under-fuzzed.
 *
 * ld.so, given DT_VERNEED (a file offset here) and DT_VERNEEDNUM, walks a chain
 * of Elf64_Verneed records via vn_next, and for each, a chain of Elf64_Vernaux
 * via vn_aux/vna_next, dereferencing vna_name (and vn_file) into .dynstr. Every
 * offset — vn_aux, vn_next, vna_next, vna_name — is attacker-controlled and
 * UNVALIDATED in the loader. We reproduce that verbatim. Over-reads surface at:
 *   - a Verneed/Vernaux record whose body overshoots the image end,
 *   - a vna_name/vn_file index past .dynstr (touch_dynstr redzone hit),
 *   - a vn_next/vna_next that points to a truncated tail record.
 * Chains are capped by iteration count purely to prevent cyclic-offset hangs.
 */
static void check_map_versions(const uint8_t *img, size_t size,
                               const dyninfo_t *di) {
    if (!di->have_verneed) return;
    /* Skip rule (entrypoints.md EP2): no verneed => nothing to walk, not a miss */
    uint64_t vn_off = di->verneed;
    if (!in_map(vn_off, size)) return;

    /* Outer bound: DT_VERNEEDNUM, but hard-capped so a self-referential vn_next
     * cannot spin. One record is >= 16 bytes, so `size` iterations is a safe,
     * over-generous ceiling that never hides a real over-read. */
    uint64_t outer_cap = di->verneednum ? di->verneednum : (uint64_t)size;
    if (outer_cap > (uint64_t)size) outer_cap = (uint64_t)size;

    for (uint64_t vi = 0; vi < outer_cap; vi++) {
        if (!in_map(vn_off, size)) break;
        const Elf64_Verneed *vn = (const Elf64_Verneed *)(img + vn_off); /* redzone? */
        uint16_t cnt      = vn->vn_cnt;         /* attacker-controlled aux count */
        uint64_t aux_rel  = vn->vn_aux;         /* offset from THIS record       */
        uint64_t next_rel = vn->vn_next;        /* offset to NEXT record         */
        uint64_t file_idx = vn->vn_file;        /* index into .dynstr            */

        /* vn_file -> .dynstr (over-read spot #1) */
        if (di->have_strtab)
            (void)touch_dynstr(img, size, di->strtab, file_idx);

        /* Walk the Vernaux chain: base = this Verneed + vn_aux, then vna_next. */
        uint64_t aux_off = vn_off + aux_rel;
        uint64_t aux_cap = cnt ? cnt : (uint64_t)size;
        if (aux_cap > (uint64_t)size) aux_cap = (uint64_t)size;
        for (uint64_t ai = 0; ai < aux_cap; ai++) {
            if (!in_map(aux_off, size)) break;
            const Elf64_Vernaux *va =
                (const Elf64_Vernaux *)(img + aux_off);   /* may hit redzone */
            uint64_t name_idx  = va->vna_name;  /* index into .dynstr           */
            uint64_t vna_next  = va->vna_next;  /* offset to next aux           */

            /* vna_name -> .dynstr (over-read spot #2, the classic one) */
            if (di->have_strtab)
                (void)touch_dynstr(img, size, di->strtab, name_idx);

            if (vna_next == 0) break;           /* faithful chain terminator */
            aux_off += vna_next;                /* trusted advance */
        }

        if (next_rel == 0) break;               /* faithful chain terminator */
        vn_off += next_rel;                     /* trusted advance */
    }
}

/* ========================================================================= *
 * 5. Top-level parse — the ld.so open_verify -> map -> dynamic-info sequence
 * ========================================================================= */
static void parse_elf64_like_ldso(const uint8_t *img, size_t size) {
    /* --- open_verify: reject fast on bad magic / wrong class ---------------
     * ld.so's open_verify reads a full header and checks e_ident before doing
     * anything else. A short buffer can't hold a header -> reject (this mirrors
     * the "read returned < sizeof(Ehdr)" reject, and keeps us from OOB-reading
     * our OWN header fields, which would be a harness bug, not a loader bug). */
    if (size < sizeof(Elf64_Ehdr)) return;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)img;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return;   /* not ELF */
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return;         /* 64-bit only */

    /* --- _dl_map_object_from_fd: find PT_DYNAMIC in the phdr table --------- */
    uint64_t dyn_off = 0, dyn_sz = 0;
    find_dynamic(img, size, eh, &dyn_off, &dyn_sz);
    if (dyn_off == 0) return;                    /* no PT_DYNAMIC -> nothing to walk */

    /* --- elf_get_dynamic_info: .dynamic -> tag table ---------------------- */
    dyninfo_t di;
    get_dynamic_info(img, size, dyn_off, dyn_sz, &di);

    /* --- downstream consumers that trust the tag table -------------------- */
    touch_symbols(img, size, &di);              /* .dynsym/.dynstr walk */
    check_map_versions(img, size, &di);         /* verneed/vernaux/versym walk */
}

/* ========================================================================= *
 * 6. Fuzzer entrypoints (libFuzzer + AFL++ persistent share this body)
 * ========================================================================= */

/* Optional one-time init. Nothing global to build in the self-contained path;
 * kept so the AFL libFuzzer-compat shim and libFuzzer both have their hook. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

/* THE hot path. Copy the input into a TIGHT ASan heap allocation (exact size ->
 * a right redzone sits immediately after the last real byte, so any 1-byte
 * over-read is caught), then run the ld.so-faithful parse. Allocation-free
 * except this one malloc/free pair, which keeps persistent-mode exec/s high
 * (WOOT'20). ASan aborts the process on a fire; libFuzzer/AFL save the input. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    uint8_t *img = (uint8_t *)malloc(size);     /* exact size -> tight redzone */
    if (!img) return 0;
    memcpy(img, data, size);

    parse_elf64_like_ldso(img, size);

    free(img);
    return 0;
}

/* ========================================================================= *
 * 7. Standalone demo (parity with the Python modules' `if __name__ == ...`)
 * ========================================================================= *
 * Lets the harness be built WITHOUT the libFuzzer runtime, to smoke-test the
 * parse on a single file:
 *   clang -g -fsanitize=address -DHARNESS_STANDALONE_DEMO asan_harness.c -o v1_demo
 *   ./v1_demo path/to/input.elf
 * Guarded so it never collides with the libFuzzer/AFL driver's own main().
 */
#ifdef HARNESS_STANDALONE_DEMO
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <elf-file> [more-elf-files...]\n", argv[0]);
        fprintf(stderr,
            "  self-contained ld.so-faithful ELF64 dynamic-parse under ASan.\n");
        return 2;
    }
    LLVMFuzzerInitialize(&argc, &argv);
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb");
        if (!f) { fprintf(stderr, "open %s failed\n", argv[a]); continue; }
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (n <= 0) { fclose(f); continue; }
        uint8_t *buf = (uint8_t *)malloc((size_t)n);
        if (!buf) { fclose(f); continue; }
        size_t got = fread(buf, 1, (size_t)n, f);
        fclose(f);
        fprintf(stderr, "[demo] %s (%zu bytes)\n", argv[a], got);
        LLVMFuzzerTestOneInput(buf, got);       /* ASan will abort here on a fire */
        free(buf);
    }
    fprintf(stderr, "[demo] done — no ASan fire on the given input(s).\n");
    return 0;
}
#endif
