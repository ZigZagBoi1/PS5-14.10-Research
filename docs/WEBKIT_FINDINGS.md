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
| p146 | Worker polls `.length` on target strings | **All 14 JSStrings corrupted, `.length` = 81400** |

Scripts: `p142-heap-survive.js`, `p146-string-primary.js`

## Finding 2: Controlled Heap Corruption via Bait-and-Switch

The heap groom pattern from p146:

1. Main thread allocates 20 "bait" strings (~100 KiB each, Primary heap)
2. Worker allocates 14 "target" strings (~100 KiB each, same heap, higher addresses)
3. Free baits + GC pressure — metadata buffer takes a freed bait slot (first-fit)
4. Overflow sweep writes forward into target strings
5. Worker detects corruption via `.length` change and `charCodeAt()` scan

**On-device result (p146):** All 14 target strings report `.length = 81400`. The corruption lands in the JSString header — specifically the field `.length` reads — while `charCodeAt` still returns the original characters (see Finding 3).

## Finding 3: StringImpl Backing Data Stays Intact

**Probes:** p147, p148, p156

The overflow corrupts the JSString header (`m_fiber`), not the StringImpl character data.

| Probe | Test | Result |
|-------|------|--------|
| p147, p148 | Substring and main-thread views | StringImpl data intact, JSString.m_fiber corrupted |
| p156 | `charCodeAt` scan over intact-header strings | All return 0x41 within `[0, 100000)`; header-corrupt strings were only read 32 bytes deep |

**Impact:** Header corruption is confirmed; an out-of-bounds read is not. With `.length` = 81400 on a 100,000-character string, `charCodeAt()` is bounded by the JSString length (`JSString::canGetIndex` is `i < length()`), so every permitted index still lands inside the original character buffer. The corrupted length narrows the readable window to 0–81399; it does not extend it. p156's scan covers `[0, 100000)` and so cannot observe bytes beyond the buffer at all.

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
| Data extraction (ASLR leak) | Blocked — needs length control or data-pointer control; the recorded 81400 length is below capacity ([audit](WEBKIT_LENGTH_WINDOW_AUDIT.md)) |
| Arbitrary read/write | Not started |

## Updates Since This Snapshot (2026-10-19)

- **Corruption confirmed on a second, independently-owned 14.10 console** ([their issue #6](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/6)): p156 bait-and-switch reproduces fully (14/14 target strings, `.length` = 81400, hex readbacks intact). The plain survive-step p142 does NOT hold on that console (3/3 clean runs died at CALLING) — bait-and-switch grooming is required for chain portability, not luck.
- **p160 (Relapse primitives) also confirmed dead on the second console** — independent reproduction of our PR #32 result (54/54, scope receiver `undefined`).
- **New best lead: CVE-2026-43715 (CSSFontFace UAF)** — source-verified against WK-1400 (`iterateClients()` re-entrant client removal via a `FontFace.prototype.then` getter), patched upstream, unpatched on PS5 14.10. Device test deployed, awaiting crash confirmation. Not blocked by the JS builtin wall that limits the stream-based bugs.
- **Kernel audit published** (their [KERNEL_AUDIT.md](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/master/docs/KERNEL_AUDIT.md)): Tier-1 candidates CVE-2026-7270 (assessed in this repo), CVE-2026-45251 (poll/select UAF, not yet assessed here), and CVE-2024-43102 (umtx — patch status reopened by our PR #41: `_umtx_op` is 454 and alive; earlier "umtx" tests hit 557).
- **Length-window audit** ([WEBKIT_LENGTH_WINDOW_AUDIT.md](WEBKIT_LENGTH_WINDOW_AUDIT.md), probe `p161-length-window.js`): the 81400 corrupted length is below the 100,000-character capacity, so it narrows rather than extends the readable window — extraction needs length control or data-pointer control, not just header corruption.

## Attribution

Research by [@Arn0Stride7](https://x.com/Arn0Stride7). Built with Claude Opus 4.6, GPT-6.1-Sol, DeepSeek v4.1-Flash, and other models. Full credits in the source repository.
