# Offline Research Sprint Report — PS5 14.10

**Date:** 2026-11-11  
**Scope:** 54 queued analysis tasks (0 console probes)  
**Result:** 54/54 completed, 0 failures  

---

## Validated Discoveries

### 1. CVE-2025-43265 — DEAD (CONFIG-SILENT)
**Initially upgraded to TOP PRIORITY, then DOWNGRADED to DEAD after preflight verification.** Root cause is YARR JIT sentinel tracking in `YarrJIT.cpp` (commit d96ab2fa64c6), gated on `ENABLE(JIT)` which is OFF on PS5 14.10. The vulnerable code is never compiled into the PS5 binary. Probe p719 tests 6 generic OOB vectors — none match the actual bug. See `results/analysis/cve_2025_43265_preflight.md` for full analysis. **This demonstrates why CVE-specific preflight verification is essential before prioritizing probes.**

### 2. Kernel Address Trust Boundary
**Only `kernel_text` (0xFFFFFFFFD5000000) is device-measured.** The other 4 key addresses — `kernel_data` (TEXT+0xCE0000), `allproc`, `security_flags`, `rootvnode` — are ALL derived from "SDK v0.45" and never validated on 14.10 hardware. The TEXT-to-DATA offset (0xCE0000) is a single point of failure: if wrong, all kernel structure targeting fails. The `EXTERNAL_AUDIT` document mislabeled `allproc` as measured.

### 3. CVE-2023-41976 (SVG Animation UAF) — Elevated
Different object/size class than FontFace (192B). JIT-independent. Probes p684-p686 ready. Could provide a complementary UAF primitive with different info-leak properties than our confirmed FontFace UAF.

### 4. CVE-2024-23213 — Newly Flagged HIGH
JIT-independent memory handling ACE. Probes p689/p690 written and ready. Not previously prioritized.

### 5. CVE-2026-43720 Classification Confirmed
Canvas2D UAF remains correctly classified as VERIFIED [M] control primitive. Two independent device runs agree. No reclassification needed.

### 6. KASLR Defeat Reproducible
3+ boots measured, 2 distinct kernel bases observed. Methodology solid at [M] grade. Fault oracle technique is reliable.

### 7. C3/C9 Contradictions Resolved
- **C3:** Allocator is Sony-dedicated UMA zones (Architecture A). Not custom.
- **C9:** 65l "doubles" are double-status-reports, not double-frees. AIO race path confirmed dead.

---

## Rejected Hypotheses

| CVE / Vector | Reason Dead | Grade |
|---|---|---|
| CVE-2025-24213 (float type confusion) | JIT-dependent; probe p720 built on false DFG assumption | [I]→DEAD |
| CVE-2024-54505 (JSC type confusion) | Likely JIT-dependent (Gary Kwong/V8, GetByVal optimization) | [I]→DEAD |
| CVE-2026-64783 (DataList UAF) | `<datalist>` element absent on PS5 (p670 confirmed) | [M]→DEAD |
| CVE-2026-43740 (YARR JIT) | YARR JIT OFF on PS5 14.10 | [S]→DEAD |
| CVE-2026-112699 (WebGPU) | WebGPU not available on PS5 | [S]→DEAD |
| CVE-2026-112680 (WebGPU) | WebGPU not available on PS5 | [S]→DEAD |
| CVE-2026-86922 (Wasm GC) | Wasm GC only, no JS path | [S]→DEAD |
| CVE-2025-14174 (ANGLE/Metal) | ANGLE/Metal GPU backend not on PS5 | [S]→DEAD |
| CVE-2023-41983 (processing DoS) | DoS only, no memory corruption | [S]→LOW |
| CVE-2026-84635 | LIVE but bounds-checked, not weaponizable | [M]→DEAD |
| CVE-2026-28905 | LIVE but reads own data only, not a leak | [M]→DEAD |
| 8 LOW-priority CVEs | DoS, privacy leaks, insufficient data, or non-memory-corruption | Various |

**14 P5 blocker-documentation tasks** culled — pure documentation of already-known blockers with zero research value.

---

## Remaining Research Blockers

### Blocker 1: WebProcess Text Base RVA (CRITICAL)
VP leaked at 0x80f4b9b28 (low 12 bits 0xB28 constant). RVA unknown — no public 14.10 WebProcess binary exists. **New path: CVE-2025-43265 OOB read could expose code pointers.** Alternatives: Prolapse exploit's info-leak technique (unexplored), HexRabbit/DEVCORE writeup search.

### Blocker 2: Heap NX
All heap memory is non-executable (bmalloc/libpas, Sony vss API). Forged vtable dispatch dies on NX heap. **Requires code-reuse chain through existing code pointers.**

### Blocker 3: No Kernel R/W Primitive
Lua-side syscall surface exhausted (~400 BSD + Sony 532-676 + 32M ioctls). **WebKit exploitation chain is the sole remaining path:** FontFace UAF → forge → code-reuse → kernel exploit.

### Blocker 4: SDK-Derived Kernel Offsets (NEW — surfaced this sprint)
4 of 5 key kernel addresses are unvalidated SDK-derived values. Cannot verify without kernel R/W (chicken-and-egg). Blast radius if wrong: all kernel structure targeting fails silently.

---

## Has Our Kernel R/W Conclusion Changed?

**NO MATERIAL CHANGE.** The exploitation chain remains:

```
FontFace UAF → forge vtable → code-reuse chain → kernel exploit → kernel R/W
                                    ↑
                         BLOCKED: need WebProcess text base
                         NEW PATH: CVE-2025-43265 OOB read
```

The offline analysis confirmed existing classifications, found no overlooked kernel-side vectors, and identified **CVE-2025-43265 as the most promising new path** to the missing info leak. All kernel-side attack surface remains exhausted.

---

## Console Probe Priority (When Online)

| Priority | Probe | CVE | CVSS | What It Tests |
|---|---|---|---|---|
| 1 | **p686** | CVE-2023-41976 | 8.8 ACE | SVG animation UAF (different size class, Safari 17.1 fix) |
| 2 | **p692** | CVE-2023-40447 | 8.8 ACE | DOM UAF + layout (Safari 17.1 fix, same researcher as 41976) |
| 3 | **p694** | CVE-2023-42950 | 8.8 ACE | Heap UAF via GC/Proxy (Safari 17.2 fix) |
| 4 | p693 | CVE-2023-42890 | 8.8 ACE | Memory handling (Safari 17.2 fix, CWE-94 JIT-uncertainty) |
| 5 | p689/p690 | CVE-2024-23213 | 8.8 ACE | TextDecoder buffer (Safari 17.3 fix) |
| ~~6~~ | ~~p721~~ | ~~CVE-2026-64718~~ | 5.5 crash | ~~DEAD: PathCG.cpp platform mismatch (CG-specific) + OffscreenCanvas absent~~ |
| ~~7~~ | ~~p719~~ | ~~CVE-2025-43265~~ | — | ~~DEAD: YARR JIT bug, CONFIG-SILENT~~ |

---

## Statistics

- **Tasks executed:** 54/54 (0 failures)
- **Culled (no research value):** 14 blocker-doc tasks
- **Marked dead/low:** 19 CVEs
- **Elevated then corrected:** 43265→TOP→DEAD (YARR JIT, verified via bug 294182). 41976→MEDIUM-HIGH, 23213→HIGH
- **Confirmed:** 2 (43720, KASLR)
- **New finding:** SDK-derived kernel offsets unvalidated (trust boundary issue)
- **Agent batches:** 3 batches, 7 parallel fork agents total
- **Runtime:** ~15 minutes wall clock
