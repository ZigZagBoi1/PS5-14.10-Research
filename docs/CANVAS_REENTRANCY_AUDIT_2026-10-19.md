# Canvas reentrancy: the next discriminating 14.10 test

**Status (updated 2026-10-29):** p553 executed on PS5 14.10 on 2026-10-26 via User Guide DNS spoofing. Full bidirectional R/W confirmed — see `results/phase13_webkit/p553_canvas_uaf_write_confirm_20261026.txt` and Finding 13 in `docs/WEBKIT_FINDINGS.md`. The original audit text below (2026-10-19) predates the on-device run and is preserved for context.

## Evidence reset

The [linked issue #6 correction](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/6#issuecomment-6279720945) confirms that stock p156's worker literal is 814 characters, so its 81,400-character string never changed length. Its detection and dump run before the metadata sweep. The bait literal is 798 characters, so the claimed 100 KiB bait size was also wrong. The external [V480 probe and log](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/ea1beed081/analysis/false-positive-81400.md) use verified 1,000-character chunks and show 0/14 changed lengths after compilation. Consequently the old p146/p156 string-header, heap-placement, and read-primitive claims are withdrawn. [WebKit fixed an upstream metadata overflow in August 2026](https://github.com/WebKit/WebKit/commit/97df94ead028), but the on-device compile/call behavior does not by itself prove this exact PS5 path is unpatched or that a controlled overwrite occurred.

## Why Canvas is worth testing

[WebKit's fix for bug 313175](https://github.com/WebKit/WebKit/commit/040ef6e21ffac03b6d6098e0e12354bdb5469ad1) explains the exact invariant. `HTMLCanvasElement::getContext()` checked its existing context before converting the settings dictionary. An `alpha` getter could enter `getContext()` again, installing an inner context. The outer call then installed another context, destroying the first while its JavaScript wrapper still existed. The fix checks again after conversion. [WebKitGTK's advisory](https://webkitgtk.org/security/WSA-2026-0004.html) maps CVE-2026-43720 to WebKit bug 313175 and describes a use-after-free crash. That upstream mapping does not establish the PS5 build's patch status.

Canvas 2D is reported available in the 14.10 guide browser. This path needs only one canvas and a JavaScript property getter, unlike the 4.29 GiB metadata sweep. The console's Safari 17.0 user-agent is insufficient to infer whether Sony backported this fix.

## First probe: context identity

Run [`p166-canvas-reentrant-identity.js`](../probes/phase13_webkit/p166-canvas-reentrant-identity.js) alone on a fresh guide page. It emits `P166-CANVAS-*` via `/beacon?m=` and writes the same records on screen. A plain pair of `getContext('2d')` calls is the control. The test then calls `getContext('2d', { get alpha() { inner = canvas.getContext('2d'); return true; } })` and compares the inner, outer, and subsequent current-context JavaScript objects. It retains the wrappers and does not deliberately collect garbage or use a possibly freed object.

| Observed record | Interpretation |
|---|---|
| `CONTROL same=true`, `getter>0`, `inner=true`, `outer=true`, `same=true`, `currentOuter=true` | Fixed behavior for this path: the outer call reused the inner context. |
| Same controls, but `same=false`, `currentOuter=true`, `currentInner=false` | Context replacement behavior: the exact invariant repaired upstream is violated. Repeat on a fresh page and collect the full beacons. This is the strongest currently cheap lead. |
| Getter absent, null context, exception, or missing `DONE` | Inconclusive. Record the last beacon and visible browser state. A crash alone does not identify a UAF. |

Do not call two wrappers drawing on the same canvas an arbitrary memory read/write primitive: sharing a canvas backing surface is normal. Even `same=false` establishes context replacement, not a controlled memory primitive or code execution. A separate repro with before/after bytes, controls, and preferably a native crash trace is needed for stronger claims.

## Acceptance criteria for the next stage

1. Save the exact served p166 bytes, console firmware, beacon sequence, and repeat count. Compare with the upstream WebKit layout test's patched `outer`/`inner` identity expectation.
2. If `same=false` is repeatable, add a separate, clearly crash-capable probe that releases only the inner wrapper and forces GC. A `START` without `DONE` must be paired with process crash evidence; timeout or navigation alone is not enough.
3. Keep any claimed aliased read/write experiment separate. Show a target independent of the canvas pixel buffer, a known written pattern, the observed readback, and a negative control. Until then, describe this as a candidate UAF entry, not arbitrary read/write.

The parallel CSSFontFace lead, CVE-2026-43715, has getter reentrancy on a third console but no crash in the reported rounds ([issue #9](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/9)). It remains lower priority than this single-call Canvas oracle.
