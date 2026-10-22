# WebKit findings — PS5 14.10

**Evidence update, 2026-10-19:** The reported p146/p156 `.length = 81400` corruption was a false positive. The literal was 814 characters, repeated 100 times. The corresponding bait literal was 798 characters, so the claimed equal-size bait placement was not tested. The independent [issue #6 correction](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/6#issuecomment-6279720945) and the [V480 fixed-literal probe and beacon log](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/ea1beed081/analysis/false-positive-81400.md) supersede this repository's earlier string corruption conclusions. V480 observed **0/14 changed lengths after compilation** with verified 100,000-character strings.

## Environment

The retail 14.10 guide browser executes JavaScript through a DNS/HTTPS redirect. The observed user-agent is `PlayStation 5/14.10`, `AppleWebKit/605.1.15`, `Version/17.0`. That string does not identify the exact WebKit source revision or prove a particular fix is absent. See [browser entry infrastructure](BROWSER_ENTRY_INFRA_2026-10-19.md) for the tested serving path.

Reported available APIs include Canvas 2D, Workers, fetch, WebSocket, WeakRef, and `structuredClone`. WebAssembly, SharedArrayBuffer, and WebGL were unavailable in the tested guide context.

## MetadataTable overflow: source bug, no proven target corruption

[WebKit's August 2026 fix for bug 317632](https://github.com/WebKit/WebKit/commit/97df94ead028) confirms a source-level 32-bit size accumulator issue in `UnlinkedMetadataTable::finalize()`. For the constructed `op_call` count, `38,348,816 × 112 = 4,295,067,392 = 2^32 + 100,096`; the low 32 bits are 100,096. Device probes compiled the large script, and calling it produced a delayed crash. Those observations do **not** establish whether the PS5 build has this exact unpatched path or where an out-of-bounds write landed.

The former proof of controlled heap corruption was the p146/p156 worker reporting `.length = 81400`. The probe itself built 81,400-character strings, so this is the expected value. The 798-character bait chunk similarly made 79,800-character baits, not the claimed 100,000-character baits. The 14/14 reports and apparent successful beacon timing are explained without target corruption. With corrected 1,000-character chunks, V480 reported 0/14 changes after compilation. A new placement experiment would need verified pre-sweep lengths, same-size allocations, a baseline read, and a changed post-sweep value.

There is no demonstrated JSString header overwrite, StringImpl pointer change, out-of-bounds read, KASLR leak, or arbitrary read/write from this path. The older [length-window audit](WEBKIT_LENGTH_WINDOW_AUDIT.md) is preserved as a superseded analysis of the erroneous premise.

## Relapse browser stage

The p160 browser probe and an independent 14.10 console observed the `super`/Proxy scope receiver as `undefined`. The 54/54 stage-1 attempts in [the live test](WEBKIT_STAGE1_1410_LIVE_TEST_2026-10-19.md) failed at that pure-JavaScript check. The tested Relapse browser entry therefore does not work on these 14.10 consoles; changing offsets cannot repair that first step. The other p160 checks observed normal `Symbol.toString` and `structuredClone` behavior, without a usable type confusion.

## Best next test: Canvas `getContext()` reentrancy

[CVE-2026-43720 / WebKit bug 313175](https://webkitgtk.org/security/WSA-2026-0004.html) has a precise [upstream fix and regression test](https://github.com/WebKit/WebKit/commit/040ef6e21ffac03b6d6098e0e12354bdb5469ad1): a settings getter re-enters `getContext()` while the outer call is converting its dictionary. On the fixed path, two nested 2D requests return the same context. The previously vulnerable path could replace and destroy the inner context while its JS wrapper remained.

The external research repo claims an on-device Canvas result, but its public tree at this audit does not contain a probe or raw log for the claimed bidirectional aliased read/write. We therefore treat PS5 patch status and primitive quality as **unverified** here. The small, non-GC [p166 identity probe](../probes/phase13_webkit/p166-canvas-reentrant-identity.js) and its [interpretation guide](CANVAS_REENTRANCY_AUDIT_2026-10-19.md) are the next discriminating test. A repeatable `outer !== inner` with the control passing would establish context replacement behavior, not yet arbitrary memory access.

## Other lead: CSSFontFace

The [third-console report](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/9) reached synchronous `FontFace.prototype.then` getter reentrancy, but two trigger forms completed without a crash across their reported rounds. That is useful API reachability evidence, not a demonstrated use-after-free on 14.10.

## Current status

| Step | Evidence |
|---|---|
| Browser JavaScript entry | Demonstrated through guide redirect |
| Relapse stage-1 scope leak | Failed on tested 14.10 consoles |
| Metadata accumulator source bug | Identified upstream; large script compiled on device |
| Controlled WebKit memory corruption | **Not demonstrated**; 81,400 result refuted |
| Canvas reentrancy patch status on PS5 | **Needs p166 device result** |
| Browser arbitrary read/write or code execution | **Not demonstrated** |

Original WebKit probe research: [pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research). This document records what the available source and device logs support after the October 19 correction.
