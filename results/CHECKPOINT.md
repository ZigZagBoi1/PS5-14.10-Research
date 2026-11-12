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

## Unfinished Tasks
1. **p692 redesign** — Needs correct UAF free trigger using Canvas2D getContext reentry (CVE-2026-43720). Current probe triggers FontFace UAF + spray but free mechanism doesn't work.
2. **p800 TransformStream typeconf** — Not yet tested on console
3. **Lua probes 1407a/1408a/1409a** — Queued but require game process relaunch (Lua loader on TCP 9026 broken)
4. **chiaki-ng programmatic API** — User requested adding API to ZigZagBoi1/chiaki-ng fork for automated input without PostMessage. PostMessage works but requires chiaki-ng window to exist.

## Blockers
- **W^X enforced** — bit 0x4 refused, no kernel R/W primitive
- **Heap NX** — no JIT on PS5, LLInt-only
- **WebProcess text base RVA unknown** — VP leaked at p691 but base scan failed (p692 reclaim broken)
- **Game process TCP 9026** — port open but resets on data, needs relaunch for Lua probes

## Next Actions (priority order)
1. Redesign p692 UAF: use getContext reentry as free trigger, not document.fonts.delete()
2. Test p800 TransformStream typeconf probe
3. Research alternative WebProcess base discovery (e.g., CSS property leak, Error.stack parsing)
4. If game process relaunched: run queued Lua probes 1407a-1409a

## Continuation
Run `python tools/state.py check --ip 10.0.0.96` then read STATE.md and tail of INDEX.md.
