# WebKit Findings — PS5 14.10

Independent browser-side research on PS5 firmware 14.10. Findings are from probes run on the actual console via the PS5's built-in browser (User's Guide DNS redirect). No raw beacon logs are included; the results below are from the probe results table maintained in the source repository.

Source: [pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research)

## Console Fingerprint

Validated on device (p163).

| Property | Value |
|----------|-------|
| Platform | PlayStation 5 |
| Firmware | 14.10 |
| Browser | Safari 17.0 / AppleWebKit 605.1.15 |
| Source match | WebKit-1200 snapshot (Dec 2023) |
| JIT | Disabled (LLInt interpreter only) |
| CPU cores | 4 |
| Display | 1920x1080 |

### Measured engine level (p162, 2026-10-19)

The UA string is pinned; the API surface is not. `probes/phase13_webkit/p162-engine-fingerprint.js`
ran in the User's Guide page on 14.10 and beaconed a per-feature bitmap, each feature tagged with the
Safari release that shipped it:

| shipped in | feature | result |
|---|---|---|
| 12.0 | `Array.prototype.flatMap`, `BigInt` | present |
| 13.0 | `String.prototype.matchAll` | present |
| 13.1 | optional chaining, nullish coalescing, `replaceAll` | present |
| 14.0 | `#x in obj` | present |
| 14.1 | `WeakRef`, `FinalizationRegistry`, `Intl.Segmenter` | present |
| 15.0 | `||=`, `&&=`, `??=` | present |
| 15.4 | `Object.hasOwn`, `Array.prototype.at`, `findLast`, `findLastIndex`, `Error.cause`, `structuredClone`, RegExp `d` | present |
| 16.0 | `Atomics.waitAsync` | present |
| 16.4 | `toSorted`, `Array.prototype.with`, `isWellFormed` | present |
| 17.0 | `Set.prototype.union`, RegExp `v` | present |
| 17.4 | `Object.groupBy`, `Promise.withResolvers`, `ArrayBuffer.prototype.transfer` | **absent** |
| 18.x | `Float16Array`, `Promise.try`, iterator helpers, `Uint8Array#toBase64`, `RegExp.escape` | **absent** |

Every 17.0 feature present, every 17.4 feature absent: the JS surface is the Safari 17.0–17.3 band,
i.e. WebKit trunk from roughly September 2023. `navigator.hardwareConcurrency` reports 4 and
`navigator.deviceMemory` reports 0 (the API is absent, not zero memory).

This dates the *feature* surface, not the security patch level. A vendor fork normally freezes the API
at a revision and back-ports security fixes on top, so an absent 17.4 API says nothing about whether a
2026 JSC fix was merged. It does mean default code paths and bytecode shapes match the 2023 engine, so
candidate bugs have to be from that base plus whatever back-ports Sony applied.

### Measured capability surface (p163, 2026-10-19)

`probes/phase13_webkit/p163-capability-map.js` ran the same way and returns the table below. The list
that used to sit here was inherited prose; this one is measured, and it confirms those absences rather
than repeating them.

| capability | result | how it was measured |
|---|---|---|
| JIT (DFG/FTL) | **off** | six batches of a 2 M-iteration integer loop all read 11.5-12.5 ns/iter, flat. A compiling engine falls to ~0.5 ns/iter by the third batch (measured on Node 24 for reference). |
| WebAssembly | absent | `typeof WebAssembly` is `undefined`; the 8-byte module header cannot even be constructed |
| SharedArrayBuffer | absent | `typeof` is `undefined`; `new SharedArrayBuffer(16)` unreachable |
| Atomics | object present | inert without SharedArrayBuffer |
| crossOriginIsolated | false | COOP/COEP headers not set on this origin |
| WebGL / WebGL2 / WebGPU | absent | `getContext('webgl')` and `('webgl2')` return null; `navigator.gpu` undefined |
| OffscreenCanvas | absent | |
| WebAudio, IndexedDB, ServiceWorker, WebRTC, WebCodecs | absent | `AudioContext`, `indexedDB`, `navigator.serviceWorker`, `RTCPeerConnection`, `VideoEncoder` all undefined |
| Geolocation, USB, Bluetooth, Gamepad, Notifications | absent | |
| Workers (classic and blob-URL) | **ok** | `new Worker(URL.createObjectURL(new Blob([...])))` constructs and accepts `postMessage` |
| CacheStorage | object present | `caches` exists |
| CompressionStream | present | |
| dynamic `import()` | ok | resolves a `data:text/javascript` module |
| ResizableArrayBuffer | ok | 16-byte buffer resized to 64 |
| Crypto | present | `crypto.subtle` |

The JIT row matters most: the fingerprint table above has claimed "Disabled (LLInt interpreter only)"
since the doc was written, but nothing in this repository measured it. It is now measured. Everything
that a page can reach here is interpreted, so bugs that require the optimising tiers (typer confusion,
speculation) are unreachable by construction, and the reachable classes narrow to the LLInt, the
parser and bytecode generator, the C++ runtime builtins, and WebCore's DOM/CSS.


### Crash oracle (p164, 2026-10-19)

`probes/phase13_webkit/p164-crash-oracle.js` turns a candidate payload into an unambiguous
survived-or-died reading. Each case is its own file, `p164-case-<name>.js`, loaded from `/raw/`
after a `V164-BEFORE-<name>` beacon; the loader's `onload` emits `V164-SURVIVED-<name>`. A thrown
exception still reaches `onload`, so a case that merely throws is reported as survived. Only a
memory-safety failure or a system kill ends the process between those two beacons, and the absence
of `SURVIVED` is the signal.

| case | expected log | purpose |
|---|---|---|
| `control` | BEFORE-control, SURVIVED-control, ORACLE-DONE | proves the pair is emitted |
| `oom` | BEFORE-oom, then nothing, plus the system memory toast | proves death is detectable |

Both legs are already demonstrated: the control case returned BEFORE->SURVIVED->ORACLE-DONE in 42 ms
in Chromium against this server, and the console's own 146 MB run shows the negative leg
(`CALLING` at 22:23:57.125, then silence and the out-of-memory toast).

The page also emits `V164-WATCHDOG-ALIVE` at 20 s, which separates a hung renderer from a dead one.

**Available APIs:** Workers, WebSocket, fetch, SubtleCrypto, Canvas 2D, ReadableStream, ResizableArrayBuffer, WeakRef, FinalizationRegistry, Proxy, BigInt, structuredClone

**Not available:** WebAssembly, SharedArrayBuffer, WebGL, WebAudio, IndexedDB, ServiceWorker

## Finding 1: Unpatched MetadataTable Integer Overflow (JSC Bug 317632)

`UnlinkedMetadataTable::finalize()` in JavaScriptCore uses an `unsigned` accumulator to sum metadata entry sizes. With 38,348,816 `op_call` sites at 112 bytes each:

```
38,348,816 × 112 = 4,295,067,392
uint32 wraps to 100,096
```

The allocator reserves ~100 KiB. The interpreter writes 4.29 GiB forward into heap memory.

**On-device results:**

| Probe | Test | Result |
|-------|------|--------|
| p141 | Overflow with stride=96 (wrong) | SIGSEGV — confirms OOB write occurs |
| p142 | Overflow with stride=112 (correct) | Overflow triggers |
| p143 | Targets placed before buffer | No corruption — sweep is forward only |
| p144 | Bait-and-switch heap groom | Forward write confirmed |
| p146 | Worker polls `.length` on target strings | All 14 report `.length` = 81400 — **RETRACTED as false positive**: 814-char literal × 100 = 81,400 (real length, no corruption) |

Scripts: `p142-heap-survive.js`, `p146-string-primary.js`

## Finding 2: Controlled Heap Corruption via Bait-and-Switch

The heap groom pattern from p146:

1. Main thread allocates 20 "bait" strings (~100 KiB each, Primary heap)
2. Worker allocates 14 "target" strings (~100 KiB each, same heap, higher addresses)
3. Free baits + GC pressure — metadata buffer takes a freed bait slot (first-fit)
4. Overflow sweep writes forward into target strings
5. Worker detects corruption via `.length` change and `charCodeAt()` scan

**On-device result (p146) — RETRACTED (2026-10-20):** the `.length = 81400` reports were the real string length, not corruption: the p146/p156 worker chunk literal is 814 characters, so the strings are 814 × 100 = 81,400 chars from birth and the `len !== 100000` check fires trivially. Definitive test: [V480 with loop-built 1000-char chunks reports 0 of 14 corrupted](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/master/analysis/false-positive-81400.md). The MetadataTable overflow itself stands (compile OK, call crash ~88s in); no string corruption is demonstrated.

## Finding 3: StringImpl Backing Data Stays Intact

**Probes:** p147, p148, p156

The overflow corrupts the JSString header (`m_fiber`), not the StringImpl character data.

| Probe | Test | Result |
|-------|------|--------|
| p147, p148 | Substring and main-thread views | StringImpl data intact, JSString.m_fiber corrupted |
| p156 | `charCodeAt` scan over intact-header strings | All return 0x41 within `[0, 100000)`; header-corrupt strings were only read 32 bytes deep |

**Impact (revised 2026-10-20):** there was no header corruption and no length-window change to analyze — the strings were 81,400 chars with 81,400 capacity. The earlier impact text and the length-window audit both analyzed the false positive.

The length value must exceed the real capacity before this becomes a read primitive; see [WEBKIT_LENGTH_WINDOW_AUDIT.md](WEBKIT_LENGTH_WINDOW_AUDIT.md) and probe `p161-length-window.js`.

Script: `p156-bait-switch.js`

## Finding 4: All Relapse WebKit Bugs Patched on 14.10

**Probe:** p160

Tested three independent Relapse WebKit exploit primitives:

| Bug | Technique | Result |
|-----|-----------|--------|
| Scope object leak | `super.foo` + Proxy receiver | `receiver === undefined` — **patched** |
| Symbol.toString disclosure | Large string with heap pointers | Length mismatch — **patched** |
| structuredClone type confusion | `history.replaceState` graph | No type confusion — **patched** |

Combined with the Lua-side results in this repo (AF_ROUTE KASLR probe 43o, AIO bypass probe 43p), the Relapse chain is dead on 14.10 across both entry vectors.

Script: `p160-relapse-test.js`

## Finding 5: A Popup Request Kills the Console's WebProcess

**Probes:** p169 (`p169-tap-popup.js`), p170 (`p170-stage-ladder.js`), p171
(`p171-popup-paths.js`)

The console's browser is fatal to popup requests, and the popup blocker's refusal is not the only
fatal path. `window.open` is refused and the WebProcess dies a few tens of milliseconds after the
page beacons the refusal. A `<a target="_blank">` click that really produces a new window kills it
too: the server serves the popup document, and nothing the page schedules afterwards ever runs.
What the new context does with the document does not matter: a popup that runs no script, one that
runs script but never messages its opener, and one that loads no document at all are all fatal. The
one popup request that does not kill is the one a sandboxed frame refuses before the popup blocker
is consulted. The console keeps running in every case: the guide can be reopened, and the system's
own network activity continues.

| run | context | markers | outcome |
|---|---|---|---|
| 08:12:10 | top-level `window.open`, real controller tap | `TAP` -> `PRE-OPEN-1` -> `POPUP-BLOCKED-1` | death ~65 ms after the refusal |
| 08:15:32 | top-level `window.open`, no tap (`?auto=1`) | `AUTO` -> `PRE-OPEN-1` -> `POPUP-BLOCKED-1` | death ~45 ms after the refusal |
| 08:20:28 | `window.open` inside a child frame | `IFRAME-POPUP-FRAME-LOADED` -> `IFRAME-POPUP-REFUSED` | death, no later marker |
| 08:57:50 | `window.open` inside a `sandbox="allow-scripts"` frame | `SANDBOX-RESULT-BLOCKED` -> `SANDBOX-ALIVE` -> `NEXT-LINK` | survives; the sandbox refuses before the popup blocker |
| 08:57:51 | `<a target="_blank">` click | `LINK-START`, popup document `200` at +0.113 s, popup script `200` at +0.266 s, no child message | death, no later marker |
| 09:04:24 | the same link click, after a guide reload | `LINK-START`, popup document `200` at +0.097 s, no popup script, no child message | death, no later marker |
| 09:37:30 | link to `/blank.html`, a document with no script | `STATIC-START`, popup document `200` at +0.168 s | death, no later marker |
| 09:39:07 | link to the probe in `?child=2`, script but no opener message | `SILENT-START`, popup document `200` at +0.092 s, popup script `200` at +0.239 s | death, no later marker |
| 09:43:38 | link to `about:blank`, a window that loads no document | `BLANK-START`, no server request - there is nothing to fetch | death, no later marker |

The user gesture is irrelevant: the console refuses the popup with a real tap as well, and the
p170 stage ladder shows the three preceding stages survive with their liveness markers intact
(`BASE-ALIVE`, `IFRAME-ALIVE`, `NESTED-ALIVE` at 4 s each) while the refusal stage kills the
process. So a bare page, one child frame, a frame inside a frame and twenty frames created and
removed in a row are all safe on the console.

p171 walks the request paths one at a time, and its chain stops at the first death. The sandbox row
is the control that keeps the result from reading as "the console dies when asked for a window": a
frame with `sandbox="allow-scripts"` and no `allow-popups` refuses the request itself, the page
beacons that refusal, stays alive and starts the next variant. The LINK rows then show the popup
blocker is not the trigger either. The click produced a real navigation request for
`/probe/p171-popup-paths.js?child=1`, the server served it, and in the 08:57 run it served the
popup's own script as well; after that the WebProcess stops and the page's 2.5 s
`LINK-RESULT-REQUESTED` timer never fires. That the popup really opened is read from the server's
access log, not from the child: both LINK popups died with their opener, so neither the opener
message nor any child marker arrived.

The STATIC and SILENT rows close the "it is the script" reading. STATIC served a popup document
that runs nothing at all and SILENT served the probe's `?child=2` mode, which runs script but never
touches the opener; both died at the same place as LINK, with no `<LABEL>-RESULT-REQUESTED` timer
and no child message. So neither the child's script nor its opener handshake is required.

BLANK closes the question. Its popup needs no server at all, so there is no fetch to read: the page
beacons `BLANK-START`, and the `<LABEL>-RESULT-REQUESTED` marker it would have sent 2.5 s later never
arrives. A window that loads nothing is as fatal as one that loads a script-free document, so the
death precedes the load - asking for a new top-level browsing context is already enough. The only
survivor remains the sandbox refusal, which never reaches the popup blocker; the blocker's own
refusal is fatal (p169). So the fatal step is the new-context request itself, not the window that
appears from it.

**Consequence for the upstream corpus.** The harvested case
`fast/scrolling/mac/event-dispatcher-timer-close-crash.html` is not testable on the console. Its
upstream fix is a use-after-free of `RemoteLayerTreeEventDispatcher`'s `RunLoop::Timer` on the
scrolling thread, and it needs a real popup window to arm the display-link observer. The console
either refuses the popup or kills the WebProcess shortly after the window is created, so the case
never reaches the code the test exercises either way. The corpus runner therefore stubs
`window.open` for the cases that use it (two of the 124), and the stub announces itself with a
`V166-POPUP-STUB` beacon so an altered case is never counted as an unmodified pass.

**What is not established.** The mechanism inside WebKit is unknown. The guide browser has no
inspector and no debugger can be attached, and the failure does not reproduce in desktop Chromium
155, which opens popups freely in headless mode, so neither the refusal nor the creation path is
entered there. What is established is the trigger and the effect: a popup request that reaches the
browser's window handling ends the WebProcess, whether it is refused or served. The popup that was
served ran as a separate browsing context, but whether it ran in the same process, and whether it
reached its script before the death, is not established — the 08:57 run fetched the popup's script
and the 09:04 run did not, and neither returned a marker. As recorded it is a denial of service
against the guide, not a controlled memory-safety primitive, and nothing here shows that it is
exploitable.

## Finding 6: The crash corpus runs inside one document, because a popup cannot be used

**Probes:** p172 (`p172-jsc-corpus-runner.js`), with p171's STATIC and BLANK rows as the control

Finding 5 leaves no popup shape to work with: a refused request, a served script-free document and
`about:blank` all end the WebProcess, and only the sandbox refusal survives. So a crash-discovery
campaign cannot put a case in its own window, cannot isolate a case from the page's own globals, and
cannot use a child process boundary to keep a death local. Every case has to run inside the one
document the guide serves, which is what the corpus runner already does with iframes.

p172 is that runner aimed at a denser corpus. The 513 cases are `JSTests/stress` and
`JSTests/regress` files added by commits after the 17.0 branch point, filtered against the engine
features p163 found absent, each rendered as a self-contained page with a `jsc`-shell shim. The runner loads
them one at a time in a subframe and beacons `BEFORE`, `OK` and `GAP` per case, so the beacon log
alone says which case the death followed and the server's cursor resumes after it. The harness was
verified in desktop Chromium before any console time: six cases produced `BEFORE`/`OK`/`GAP` for
each and advanced the stored cursor from 0 to 6.

**What is not established.** No case has been run on the console yet, so the corpus says nothing
about 14.10's engine. A case that reports `OK` has been shown not to kill the guide's WebProcess
under this harness and nothing more, and a `GAP` is a death to attribute, not a bug. The shim also
makes the pages not-quite-upstream: a case that needs a shell helper the shim lacks throws, is
caught, and reports zero assertions.

## Entry Method

The PS5 browser is reachable without hardware modification:

1. Run a DNS/HTTPS server on the local network
2. Point PS5 DNS settings to the server
3. Open Settings → User's Guide on the PS5
4. PS5 browser loads the exploit page from the redirected domain

No jailbroken PS4, no save file chain, no game purchase required. Probes communicate via HTTP beacon callbacks (XHR GET/POST) to the host server.

## Current Status

Snapshot status below; the [source repository](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research) is authoritative for current progress.

| Stage | Status |
|-------|--------|
| Bug identification | Done |
| Trigger on device | Done |
| Heap grooming | Done |
| JSString corruption | Done |
| Data extraction (ASLR leak) | Not started — the 81400 "corruption" was a false positive (see Finding 2); no corruption primitive is demonstrated |
| Arbitrary read/write | Not started |

## Updates Since This Snapshot (2026-10-19)

- **p156 "reproduction" on a second console — same false positive (corrected 2026-10-20):** the 14/14 `.length` = 81400 reports were the literal string length (814-char chunk × 100), not corruption. The OOM-death-vs-beacon-ordering data from that console's 17 runs remains valid ([issue #6](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/6)).
- **p160 (Relapse primitives) also confirmed dead on the second console** — independent reproduction of our PR #32 result (54/54, scope receiver `undefined`).
- **New best lead: CVE-2026-43715 (CSSFontFace UAF)** — source-verified against WK-1400 (`iterateClients()` re-entrant client removal via a `FontFace.prototype.then` getter), patched upstream, unpatched on PS5 14.10. Device test deployed, awaiting crash confirmation. Not blocked by the JS builtin wall that limits the stream-based bugs.
- **Kernel audit published** (their [KERNEL_AUDIT.md](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/master/docs/KERNEL_AUDIT.md)): Tier-1 candidates CVE-2026-7270 (assessed in this repo), CVE-2026-45251 (poll/select UAF, not yet assessed here), and CVE-2024-43102 (umtx — patch status reopened by our PR #41: `_umtx_op` is 454 and alive; earlier "umtx" tests hit 557).
- **Length-window audit** ([WEBKIT_LENGTH_WINDOW_AUDIT.md](WEBKIT_LENGTH_WINDOW_AUDIT.md)) — analyzed the false positive; its capacity question dissolves. The p161 probe it inspired remains correct (PR #43 fixed its blob construction) and now tests whether the correct-strings groom corrupts at all.

## Attribution

Research by [@Arn0Stride7](https://x.com/Arn0Stride7). Built with Claude Opus 4.6, GPT-6.1-Sol, DeepSeek v4.1-Flash, and other models. Full credits in the source repository.
