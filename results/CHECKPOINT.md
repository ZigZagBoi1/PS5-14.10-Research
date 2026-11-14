# Research Checkpoint

## Last Updated
2026-11-13T04:00:00Z

## Session 2026-11-12 p635b/p635c — Canvas UAF Exploit Results

### p635b (CRASH — Phase A stale read)
- Phase A tried to read Canvas2D properties through dangling pointer BEFORE spray
- WebProcess SEGV at first property access — confirms UAF is REAL (freed memory)
- No data recovered — process killed before beacon

### p635c (MEASURED — Phases B-D, crash at D)
- **Phase B (same-type reclaim):** Alias at spray[11]. All fields at default (clean reclaim). Transform = identity. No stale data leaked through same-type overlap.
- **Phase C (patterned spray):** Alias at spray[0]. lineWidth=10000, miterLimit=20000, shadowBlur=30000 all match. Transform (a=0.0001, d=0.0001) matches. **Full bidirectional field mapping confirmed.**
- **Phase D (ImageData cross-type):** 300 ImageData(192,1) sprayed. Read through dangling Canvas2D pointer → **CRASH** (type confusion SEGV). WebProcess killed.
- Phases E (double-free) and F (offset mapping) not reached due to D crash.

### Key Findings
1. **UAF alias R/W confirmed on PS5 14.10** — CVE-2026-43720 getContext reentry produces reliable same-type reclaim
2. **Alias index varies** (spray[11] in B, spray[0] in C) — heap layout dependent, not deterministic
3. **Cross-type reclaim crashes** — ImageData backing vs Canvas2D vtable = SEGV
4. **Same-type alias gives 7 double R/W channels** (lineWidth, miterLimit, globalAlpha, shadowBlur, shadowOffsetX, shadowOffsetY, lineDashOffset) + 6 transform doubles + string properties (fillStyle, font)
5. **No info leak yet** — same-type reclaim produces clean overlap (spray values, not stale data)

### p635d Results (Phases E+F) — ALL COMPLETE
- **Phase E (double-free→ArrayBuffer):** Alias at spray[10]. Markers verified (0x41414141, 0x42424242). After freeing alias canvas+GC, innerE.lineWidth resets to 1 (reclaimed by something else, not freed). AB spray(500×768B) found NO markers/pointers. Post-write through innerE not visible in ABs. **Canvas2D backing is in bmalloc/libpas zone, not general heap.**
- **Phase F (offset mapping):** Alias at spray[2]. **FULL BIDIRECTIONAL MAP:**
  - **Double R/W (10 channels):** lineWidth ✓, miterLimit ✓, globalAlpha ✓, lineDashOffset ✓, transform a/b/c/d/e/f ✓ (6)
  - **NO ALIAS:** shadowBlur ✗, shadowOffsetX ✗, shadowOffsetY ✗ (different storage or clamping)
  - **String R/W (8 channels):** fillStyle ✓, strokeStyle ✓, font ✓, textAlign ✓, textBaseline ✓, globalCompositeOperation ✓, lineCap ✓, lineJoin ✓
  - Reverse direction (inner→alias) confirmed for lw, ml

### Next Steps
1. Design info leak: exploit string property internals for pointer confusion, or use transform doubles to scan adjacent heap metadata
2. Research WebKit bmalloc/libpas internals for size-class-based exploitation
3. If game process relaunched: run queued Lua probes 1407a-1409a

## Console Probe Batch — 2026-11-12

### Infrastructure
- PS5 browser accessed via User Guide page (DNS interception: manuals.playstation.net → 10.0.0.80)
- nginx serves probes from /var/www/ps5-guide-entry/probes/, telemetry server on port 8081
- Automation: PostMessage to chiaki-ng window (key "2" = page refresh), no focus required
- Entry: index.html auto-redirects to current probe after 2s

### Results

| Probe | CVE | Result | Grade |
|-------|-----|--------|-------|
| p686 | CVE-2023-41976 SVG Animation UAF | NO-UAF-DETECTED (5/5 sections) | V |
| p689 | CVE-2024-23213 Fetch body lifetime | NO-UAF-DETECTED (5/5 sections) | V |
| p690 | CVE-2024-23213 TextDecoder stream | NO-UAF-DETECTED (5/5 sections) | V |
| p692-diag | FontFace API diagnostic | .loaded hangs, .load() works | M |
| p692-sz | FontFace spray reclaim | 0 hits across 64-512 byte sizes | M |
| p692 | FontFace UAF chain | FAIL-no-reclaim (free mechanism wrong) | M |
| p693 | CVE-2023-42890 Memory handling | NO-BUG-DETECTED (5/5 sections) | V |
| p694 | CVE-2023-42950 Heap UAF | NO-UAF-DETECTED (5/5 sections) | V |

### Key Findings
1. **FontFace `.loaded` promise NEVER RESOLVES on PS5** — must use `.load()` explicitly
2. **`document.fonts.delete()` does NOT free backing C++ object** — spray/reclaim impossible via this path
3. **p692 UAF free mechanism is fundamentally wrong** — needs Canvas2D getContext reentry (CVE-2026-43720), not FontFace deletion
4. **OffscreenCanvas absent** on PS5 (p693-B confirmed)
5. **`bitmaprenderer` context returns null** — only `2d` context available
6. All tested CVE patterns returned VOID — PS5 may have backported fixes or patterns don't match actual vulnerable paths

### VOID ≠ Proof of Absence
These are negative observations from specific test patterns. The CVEs may still be exploitable via different triggers, timing, or content combinations.

### Raw Data
- 239 telemetry events in `results/captures/telemetry-2026-11-12-session.jsonl`
- Adapted probe files in `probes/phase13_webkit/adapted-guide-entry/`
- Full capture report: `results/captures/CAPTURE_REPORT_2026-11-12.md`

## Session 2026-11-12 (MCP + probe results)

### chiaki-ng MCP Automation — VALIDATED
- Old MCP config pointed to nonexistent path (`C:\Users\Marwan's Laptop\...`)
- New MCP server: `tools/chiaki-mcp-stdio.py` (PostMessage, no focus steal)
- Tools: `send_key`, `refresh_page` (Enter+wait+2), `send_sequence`
- Config: `.mcp.json` in project root (absolute path, survives fresh sessions)
- Validated: MCP protocol test OK, key delivery confirmed via beacon telemetry (2 probes run)
- Enter key dismisses PS5 "not enough free system memory" dialog before refresh
- **Limitation**: Cannot recover completely unresponsive/powered-off console or detect Remote Play connection state

### p692b-ctx-diag — Canvas Context Types (2 runs, MEASURED)
- **2d**: YES (CanvasRenderingContext2D)
- **webgl**: NULL, **webgl2**: NULL, **webgpu**: NULL
- **bitmaprenderer**: **YES** (ImageBitmapRenderingContext) — CORRECTS p692-diag (which tested on canvas with existing 2d context, locking it)
- **OffscreenCanvas**: undefined
- **Reentry CONFLICT**: `getContext('bitmaprenderer', {alpha→getContext('2d')})` returns BOTH objects as different types
- **★ CVE-2026-43720 IS TRIGGERABLE on PS5 14.10**

### p800 — CVE-2026-43705 TransformStream (DEAD)
- TransformStream: PRESENT on PS5 14.10
- All 4 poisoned-iterator vectors throw TypeError
- "Internal TransformStream creation returned values of unexpected types" — null check present
- **PATCHED on PS5 14.10**

## Session 2026-11-12/13 — Canvas UAF Info Leak Campaign (p635e-p635i)

### p635e (MEASURED — all 5 phases)
- Pixel readback: clean (no stale data)
- Shadow properties DO alias (corrects p635d — 13 doubles not 10)
- Gradient/pattern: opaque, no leak
- toDataURL: identical between UAF and alias canvases
- Double UAF: adjacent spray objects gap=1

### p635f (PARTIAL — Phase A OK, Phase B CRASH)
- State stack save/restore: clean, no underflow leak
- Phase B crashed: 100 deep saves + extreme doubles on adjacent contexts = WebProcess SEGV
- Phases C/D never ran

### p635g (MEASURED — all 6 phases, ALL CLEAN)
- Safe adjacent context overlap: NO memory overlap between adjacent spray contexts
- putImageData confusion: 0 mismatches (shared backing buffer, correct behavior)
- measureText side channel: normal font metrics, invalid fonts sanitized, no pointers
- isPointInPath/isPointInStroke: path state shared correctly, no confused dispatch
- setLineDash/getLineDash: 100-element array matches perfectly both directions
- Canvas resize stale buffer: all zeros (properly zero-initialized)
- **Conclusion: same-type reclaim 2d alias is a clean shared-state alias, no memory confusion**

### p635h (CRASH — Phase A only, 8 runs)
- **CRITICAL FINDING: `bmr.canvas` access CRASHES WebProcess every time**
- Phase A enumerates bmr properties OK (canvas:object, transferFromImageBitmap:function)
- Prototype: constructor, canvas, transferFromImageBitmap
- SEGV at `bmr.canvas` property access — dangling internal pointer CONFIRMED
- The bitmaprenderer context's CanvasRenderingContext base class holds a corrupted/dangling reference

### p635i (DEPLOYED, awaiting PS5)
- Skips bmr.canvas crash path
- Tests: transferFromImageBitmap(null), AB/canvas spray before bmr.canvas, double UAF cross-context, property descriptor override
- **Not yet tested on device**

### WebKit Source Analysis (offline)
- `ImageBitmapRenderingContext` inherits `CanvasRenderingContext` — no separate canvas pointer
- `.canvas` getter goes through `canvasBase()` in base class then `downcast<HTMLCanvasElement>`
- `transferFromImageBitmap` calls `willUpdateContents` on canvas rect — may also crash
- Members: `RefPtr<ImageBuffer> m_buffer`, `RefPtr<NativeImage> m_bufferNativeImage`, `ImageBitmapRenderingContextSettings m_settings`
- The crash at bmr.canvas means the JSC binding wrapper or the base class CanvasBase& reference is corrupted by the reentry

### Alias Primitive Summary (confirmed p635d-p635g)
- **13 double R/W channels:** lineWidth, miterLimit, globalAlpha, shadowBlur, shadowOffsetX, shadowOffsetY, lineDashOffset, transform a/b/c/d/e/f
- **8 string R/W channels:** fillStyle, strokeStyle, font, textAlign, textBaseline, globalCompositeOperation, lineCap, lineJoin
- **All bidirectional** (inner↔alias confirmed)
- **bmalloc/libpas zone isolation** — Canvas2D backing NOT in general heap (ArrayBuffer spray cannot reclaim)

## Unfinished Tasks
1. **Check p635i telemetry** when PS5 is back
2. **Exploit bmr dangling pointer** — spray before trigger to control what bmr.canvas reads
3. **Alternative info leak vectors** — Error.stack, CSS computed style, WebAssembly.Memory
4. **Lua probes 1407a/1408a/1409a** — require game process relaunch

## Blockers
- **W^X enforced** — bit 0x4 refused, no kernel R/W primitive
- **Heap NX** — no JIT on PS5, LLInt-only
- **No info leak** — same-type alias is clean; bmr dangling pointer is the best lead
- **WebProcess text base unknown** — VP leaked at p691 but base scan failed
- **Game process TCP 9026** — needs relaunch for Lua probes
- **PS5 currently offline**

## Next Actions (priority order)
1. When PS5 back: run p635i, check if transferFromImageBitmap works without crash
2. If tfib crashes too: build spray-before-trigger probe to reclaim freed memory before bmr construction completes
3. Explore Error.stack / CSS computed style / WebAssembly.Memory as alternative info leak paths
4. If game process relaunched: run queued Lua probes

## Continuation
Run `python tools/state.py check --ip 10.0.0.96` then read STATE.md and tail of INDEX.md.
