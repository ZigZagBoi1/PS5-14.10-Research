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

**On-device result (p146):** All 14 target strings report `.length = 81400`. The corruption is in JSString's `m_fiber` header field inside MarkedSpace.

## Finding 3: StringImpl Backing Data Stays Intact

**Probes:** p147, p148, p156

The overflow corrupts the JSString header (`m_fiber`), not the StringImpl character data.

| Probe | Test | Result |
|-------|------|--------|
| p147, p148 | Substring and main-thread views | StringImpl data intact, JSString.m_fiber corrupted |
| p156 | `charCodeAt` scan across corrupted strings | All return 0x41 — `m_data8` still points to original buffer |

**Impact:** Reading through a corrupted JSString with `.length` = 81400 gives out-of-bounds read access to adjacent heap data past the original 100,000-byte string, using `charCodeAt()`. The backing character data is not overwritten.

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

~30% toward kernel. 84 probes built across 9 sessions over 3 days.

| Stage | Status |
|-------|--------|
| Bug identification | Done |
| Trigger on device | Done |
| Heap grooming | Done |
| JSString corruption | Done |
| Data extraction (ASLR leak) | In progress |
| Arbitrary read/write | Not started |

## Attribution

Research by [@Arn0Stride7](https://x.com/Arn0Stride7). Built with Claude Opus 4.6, GPT-6.1-Sol, DeepSeek v4.1-Flash, and other models. Full credits in the source repository.
