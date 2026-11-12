# Console Test Capture Report — 2026-11-12

## Environment
- **Console:** PS5 firmware 14.10, IP 10.0.0.96
- **Browser UA:** `Mozilla/5.0 (PlayStation; PlayStation 5/14.10) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`
- **Server:** 10.0.0.80, nginx + telemetry on port 8081
- **DNS interception:** manuals.playstation.net → 10.0.0.80 via dnsmasq
- **Entry point:** PS5 User Guide → index.html → auto-redirect to probe
- **Automation:** PostMessage to chiaki-ng (PID 2912, HWND 459980), key "2" = page refresh

## Test Window
- First event: 2026-11-12T00:32:59Z (p692 BOOT, old version)
- Last event: 2026-11-12T00:44:50Z (p694 DONE)

## Results Summary

| Probe | CVE | Sections | Events | Result | Grade |
|-------|-----|----------|--------|--------|-------|
| p686 | CVE-2023-41976 | A-E (5/5) | (prior session) | NO-UAF-DETECTED | V |
| p689 | CVE-2024-23213 | A-E (5/5) | 17 | NO-UAF-DETECTED | V |
| p690 | CVE-2024-23213 | A-E (5/5) | 21 | NO-UAF-DETECTED | V |
| p692 | FontFace UAF | - | 5 | FAIL-no-reclaim | M |
| p692-diag | FontFace API | - | 34 | .loaded hangs, .load() works | M |
| p692-sz | Spray reclaim | 10 sizes | 22 | 0 hits (64-512 bytes) | M |
| p693 | CVE-2023-42890 | A-E (5/5) | 24 | NO-BUG-DETECTED | V |
| p694 | CVE-2023-42950 | A-E (5/5) | 116 | NO-UAF-DETECTED | V |

## Verification Notes

### Negative result ≠ proof of absence
These VOID results mean our specific test patterns did not trigger the CVE on PS5.
This does NOT prove the vulnerabilities are absent — it means:
1. Our trigger patterns may not match the actual vulnerable code path
2. The heap/timing conditions may differ on PS5's allocator
3. Sony may have backported specific fixes without updating the UA version string
4. The CVEs may require specific content/resource combinations we didn't test

### Skipped sections
- p693-B: OffscreenCanvas — API absent on PS5 (NO-OFFSCREENCANVAS). Expected.
- p694-C: Only 49 of 50 FinalizationRegistry callbacks fired (GC timing). Normal.

### Key measured finding: FontFace API behavior on PS5
- `FontFace` constructor: available
- `document.fonts`: available, starts empty (size=0)
- `document.fonts.ready`: available (Promise)
- Font loading via `.load()`: works for Arial, Helvetica, Times, Courier, serif
- Font loading via `.load()`: FAILS for sans-serif, monospace ("A network error occurred")
- `FontFace.loaded` promise: **NEVER RESOLVES** (stays status=unloaded after add to document.fonts)
- `document.fonts.delete()`: does NOT free backing C++ object (0 spray reclaim hits across 64-512 byte buffers with 2048 allocations each)
- Canvas 2D context: available
- `bitmaprenderer` context: NOT available (returns null)

## Raw Data
- `telemetry-2026-11-12-session.jsonl` — 239 events, SHA256: b9c3093cea8d12a91d0f01fca4fc7f9b18a63f344cecee4eb7d3b72c8e4851a5

## Probe File Hashes (SHA256)
```
e3c45f4a p686-guide-entry.html
781dc47e p689-guide-entry.html
3e80102a p690-guide-entry.html
17510dd2 p692-diag.html
e46fa3a8 p692-size-probe.html
8973d4f0 p693-guide-entry.html
55e7525e p694-guide-entry.html
```
