# Research Checkpoint

## Last Updated
2026-11-12T00:50:00Z

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

## Unfinished Tasks
1. **p635b Canvas reentry UAF exploit** — CVE-2026-43720 confirmed triggerable. Build full exploit: trigger reentry, spray to reclaim freed CanvasRenderingContext2D backing, achieve alias for R/W primitive.
2. **Lua probes 1407a/1408a/1409a** — Queued but require game process relaunch (Lua loader on TCP 9026 broken)

## Blockers
- **W^X enforced** — bit 0x4 refused, no kernel R/W primitive
- **Heap NX** — no JIT on PS5, LLInt-only
- **WebProcess text base RVA unknown** — VP leaked at p691 but base scan failed (p692 reclaim broken)
- **Game process TCP 9026** — port open but resets on data, needs relaunch for Lua probes

## Next Actions (priority order)
1. Build p635b: Canvas reentry UAF full exploit (bitmaprenderer+2d confirmed, build spray+reclaim+alias)
2. Research alternative WebProcess base discovery (e.g., CSS property leak, Error.stack parsing)
3. If game process relaunched: run queued Lua probes 1407a-1409a

## Continuation
Run `python tools/state.py check --ip 10.0.0.96` then read STATE.md and tail of INDEX.md.
