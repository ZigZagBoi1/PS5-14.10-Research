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

**Update (2026-10-26):** p553 confirmed CVE-2026-43720 is **unpatched** on PS5 14.10. Full bidirectional R/W through same-type reclaim alias — see Finding 13 and `results/phase13_webkit/p553_canvas_uaf_write_confirm_20261026.txt`. The remaining blocker is an info leak (DAZ kills float64 pointer reads).

## Other lead: CSSFontFace

The [third-console report](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/9) reached synchronous `FontFace.prototype.then` getter reentrancy, but two trigger forms completed without a crash across their reported rounds. That is useful API reachability evidence, not a demonstrated use-after-free on 14.10.

## Current status

| Step | Evidence |
|---|---|
| Browser JavaScript entry | Demonstrated through guide redirect |
| Relapse stage-1 scope leak | Failed on tested 14.10 consoles |
| Metadata accumulator source bug | Identified upstream; large script compiled on device |
| Controlled WebKit memory corruption | **Not demonstrated**; 81,400 result refuted |
| Canvas reentrancy patch status on PS5 | **UNPATCHED** — CVE-2026-43720 confirmed (p553, 2026-10-26) |
| Canvas UAF bidirectional R/W | **Confirmed** — 6×float64 transform + 7 numeric properties (p553) |
| Browser arbitrary read/write or code execution | **Not demonstrated** — info leak blocked by DAZ |

Original WebKit probe research: [pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research). This document records what the available source and device logs support after the October 19 correction.
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

p172 is that runner aimed at a denser corpus. The 510 cases are `JSTests/stress` and
`JSTests/regress` files added by commits after the 17.0 branch point, filtered against the engine
features p163 found absent, each rendered as a self-contained page with a `jsc`-shell shim. The runner loads
them one at a time in a subframe and beacons `BEFORE`, `OK` and `GAP` per case, so the beacon log
alone says which case the death followed and the server's cursor resumes after it. The harness was
verified in desktop Chromium before any console time: six cases produced `BEFORE`/`OK`/`GAP` for
each and advanced the stored cursor from 0 to 6.

**What is not established.** A case that reports `OK` has been shown not to kill the guide's
WebProcess under this harness and nothing more, and a `GAP` is a death to attribute, not a bug. The
shim also makes the pages not-quite-upstream: a case that needs a shell helper the shim lacks throws,
is caught, and reports zero assertions. The console results are in the next finding and in
[WEBKIT_CORPUS.md](WEBKIT_CORPUS.md); one death out of that corpus is now attributed.

## Finding 7: One page exhausts the guide browser's memory through a Proxy handler

**Probes:** p172 corpus case 296, then p173 (`p173-poly-proto-oom.js`)

The corpus run stopped at the same index in every attempt. Case 288 was a 24-million-character
parser program and was dropped as `$memoryLimited`; after that the stop moved to index 295, and it
stayed there. The last attempt before the corpus was set aside loaded **that case alone** in its own
document from a fresh guide process: `BOOT-510-from-295-to-296`, one GET of
`/corpus/jsc-296-proxy-handler-traps-cache-poly-proto-handler.html`, `BEFORE-295`, and the console
answered "there is not enough free system memory" about a second later. Nothing else ran in that
process. So the case, not the accumulated heap of several hundred documents, ends the WebProcess.

The case is `JSTests/stress/proxy-handler-traps-cache-poly-proto-handler.js`, a regression test for
the handler-traps cache treating a matching structure identifier as proof that the handler's
prototype is still an object. The engine here was cut at Safari 17.0, before that fix. Six variants
then cut the case down, each in its own document, in one chain:

| Variant | What it keeps | Result |
|---------|---------------|--------|
| helper only | `makePolyProtoObject()` and a prototype change | `OK` |
| proxy get | `new Proxy({}, handler)` with a `get` trap | `OK` |
| prototype null | + `setPrototypeOf(handler, null)` then `proxy.foo` | **memory exhaustion** |
| keys | the `Object.keys` block | not reached |
| trap mutates | the trap changes the prototype mid-call | not reached |
| trap from proto | a trap that arrives through the prototype | not reached |

Four further controls all completed: the prototype replaced with `{}` instead of `null`, `null` set
before any trap was cached, an ordinary (non-poly-proto) handler object, and `null` set with nothing
read through the Proxy afterwards. The four ingredients are therefore all required - a poly-proto
handler, a cached `get` trap, the prototype removed after the trap was cached, and a read through the
Proxy after that.

The same four ingredients were then tried with the other handler traps, each in its own document so
that one death could not hide the next (2026-10-21 18:17-18:18 UTC, sessions `lcluko`, `bme8v3`). The
`has` shape was instrumented call by call: the trap answered `true` before the prototype change,
`Object.setPrototypeOf(handler, null)` itself returned (`A4-null`), and the `'foo' in proxy` after it
never came back. The `ownKeys` shape behaved identically: `Object.keys(proxy)` returned `a` before,
the prototype went, and the next `Object.keys(proxy)` exhausted memory. So the missing invalidation
is not specific to the `get` trap: at least `get`, `has` and `ownKeys` end the process through the
same stale cache, and the prototype change on its own is harmless.

**What it is and what it is not.** A single page, with legal JavaScript, takes the guide's WebProcess
past its memory limit in about a second; `p173-poly-proto-oom.js` is that page reduced to twelve
lines. It is an engine-level failure, and it is the first positive result the corpus has produced -
but the effect is a denial of service on the browser process, not a wrong value, not a corruption and
not a sandbox escape. Whether the exhaustion is an unbounded allocation in the cache invalidation
path or a recursion that allocates as it goes is not established: the page is gone before any
diagnostic could run, and the guide browser has no console.

## Finding 8: A `u`-mode regexp loops forever on a three-character string

**Probes:** p172 corpus case 379, then p174 (`p174-regexp-nonbmp-hang.js`)

```js
/.*X/u.test("\u{10000}a")   // never returns on 14.10
```

Three code units - one non-BMP character and one `a` - with no `X` in the subject, and the guide's
main thread does not come back. The same call returns immediately in Chromium and in V8.

The route to it was the corpus, and each step was measured separately because the beacon protocol
cannot distinguish a hang from a kill on its own (a wedged main thread cannot fire the page's own
stall timer either; only the console's "this page isn't responding" dialog separates them).

| step | page | result |
|---|---|---|
| corpus case | `jsc-379-regexp-unicode-greedy-charclass-backtrack-linear.html` | "page isn't responding", no marker for >2 min; V8 runs the body in 372 ms |
| complexity canary | `/[^"]*X/u.test("\u2014" + "a".repeat(n))`, n = 250/500/1000/2000 | 1/2/7/32 ms - the O(n^3) fix is present, so the hang is not the case's own canary |
| block bisection (8 blocks, one document each, 200 iterations) | block 7, "no match after full backtrack" | blocks 1-6 returned in 0-1 ms; block 7 never returned |
| character matrix | `/[^"]*X/u.test(...)` over the block's own characters | `"\u{10000}aaa"` hangs; the em-dash canary of 2000+ units does not |
| feature matrix | match present, no `u` flag, `.` instead of `[^"]`, ASCII only, em dash, other literal | all returned in 0-1 ms; `/.*X/u.test("\u{10000}aaa")` hung |
| quantifier matrix | `/X/u`, `.*X` with a match, ASCII no-match, astral alone, `.X`, `.*` | all returned; the astral **alone** is safe |
| position matrix | astral at end / in the middle | `"aa\u{10000}"` returned in 0 ms; `"aa\u{10000}aa"` hung |
| minimal form | `.*X` over `"\u{10000}a"` | hangs |

The ingredients, as far as the measurements separate them:

- the `u` flag - the identical call without it returns 0 ms;
- a quantifier that has to backtrack - `/X/u` over the same subject returns 0 ms;
- a non-BMP character with **at least one code unit after it** - the astral at the end of the
  subject returns 0 ms, the astral followed by one `a` does not;
- no match - the same pattern with the `X` present returns 0 ms.

The subject is three code units, so this is not a complexity problem: no amount of work proportional
to its length takes minutes, and the guide is still frozen when the page is stopped. The most likely
mechanism is the "bump the start offset along" step after a failed attempt: with the astral in the
middle, an attempt begins inside the surrogate pair, and the code that advances over a non-BMP
character does not move forward. That is a hypothesis from the shape of the results - the engine's
source is not available here and the failure leaves no trace other than the frozen page.

**What it is and what it is not.** A denial of service on the guide's WebProcess that fits in one line
of legal JavaScript, on a string a single character long plus one. It is the corpus's second
engine-level result (the first is [Finding 7](#finding-7-one-page-exhausts-the-guide-browsers-memory-through-a-proxy-handler)),
and like that one it is a hang or an OOM, not a wrong value, not a corruption and not a sandbox
escape. It does say something specific about the engine: the pointer to a code point inside a
surrogate pair is mishandled in the backtracking path, which is the sort of defect that more often
produces a memory error than a hang. Nothing here demonstrates that it does.

## Finding 9: The corpus ran end to end, and every divergence is a hang

**Probes:** p172 corpus, all 1919 pages

The full pass completed on 2026-10-21 across sessions `0he9lz`, `4f795r`, `patyt1`, `x88un3`,
`dgieji`, `oshir0`, `ayzkt5`, `hmul5a`, `g2bkbv`, `v9r5m5`, `7w40ad`, `mi1c28`, `ybho3o`, `6e1xf2`,
`teih4m`, `z36v1x` and `9nmzbj` (logs `results/webkit/server_20261021_*.log`):

| | count |
|---|---|
| corpus built | 1919 |
| reported `OK` | 1899 |
| pinned as unsafe to run | 27 |
| started and never finished, outside the pin list | **0** |

Every page that was not deliberately pinned ran to completion. The pass needed seven guide reloads,
and every one of them was a page that either exhausted the WebProcess's memory or froze its main
thread - not a crash, and not a lost beacon.

**Three hangs, one shape.** Each of the three cases below should throw and instead loops:

| case | should | does |
|---|---|---|
| `proxy-handler-traps-cache-poly-proto-handler` (Finding 7) | throw on a stale traps-cache entry | spins in the release build, asserts in a debug build, exhausts memory on the console |
| `regress-125602977` | throw `TypeError: Attempting to change configurable attribute of unconfigurable property.` | completes silently in our release build; spins in a debug build; memory message on the console |
| `use-static-private-member-in-computed-property-name` | `SyntaxError` at parse time | one call to `test()` never returns - `while`-equivalent loop inside class evaluation |

The third one is a single iteration: the loop in the test body is not what hangs, so the engine is
stuck inside the class definition itself. The second one is the only spec divergence in the pass:
`target.__defineGetter__('prototype', …)` on a non-configurable property is supposed to throw and does
not, after `Function.prototype.__proto__` has been pointed at a Proxy.

**What the pass did not find.** No memory-safety report, on the console or offline:

- 1919 sources replayed verbatim under a Debug+ASAN `jsc` with the shell shims: `{'clean': 1070,
  'asan': 0, 'assert': 0, 'signal': 0, 'timeout': 123, 'parse': 216, 'exception': 510}`. The 510
  exceptions and 216 parse failures are harness gaps (dynamic `import('./aN.js')`, `$vm`, async
  main), not engine bugs.
- ~17 000 number/compare/arithmetic mutants of the same sources under the same build: no ASAN
  report, no assertion, no signal.

**Why this closes the corpus as a route to code execution.** All three divergences are reachable
from a legal page and all three are denial of service. None of them hands the page a value it chose:
the proxy case's stale entry yields `jsNull` where a cell is expected, which upstream describes as "a
crash at a deterministic address" and which measures as a spin here; the `TypeError` case ends with
the write landing on the original object; the private-name case never returns at all. A hang is a way
to stop the console, not a way to read its memory, and nothing in this pass produced the latter.

The corpus itself is now filtered so a rebuild does not carry these classes: **1903 pages**, after
dropping shell-only helpers, `$memoryLimited`, `//@ memoryHog!`, resolved allocations at or above
256 MB, and watchdog loops under either `runDefault` or `requireOptions`.

## Finding 10: The font-face trigger hangs the guide instead of crashing it

**Probes:** p446 (`p446-fontface-uaf.js`), p447 (`p447-fontface-faithful.js`), p448
(`p448-fontface-localise.js`), p449 (`p449-fontface-cap.js`), p450 (`p450-layout-in-getter.js`)

The public CVE-2026-43715 write-up for 14.10 (WebKit bug 313577) claims a use-after-free in
`CSSFontFace::setStatus` reached through a `FontFace.prototype.then` getter. Both halves of that
claim were checked here: the upstream fix is real and the guide does reach the code on 14.10, but
the effect on the console is a hang, not a memory-safety crash.

**The fix is real and our engine is missing it.** Commit `5aedb82` ("Use-after-free in
CSSFontFace::setStatus via CSSFontFace::load", bug 313577, canonical `316482@main`, 2026-07-03)
adds one condition to the client loop in `Source/WebCore/css/CSSFontFace.cpp`:

```cpp
for (auto& client : copyToVectorOf<Ref<CSSFontFaceClient>>(clients)) {
    if (clients.contains(client))
        callback(client);
}
```

The `~/webkit-7617` tree used here has the loop without the `contains()` check
(`Source/WebCore/css/CSSFontFace.cpp:55`), so a Safari 17.0-era engine carries the pre-fix code.

**The guide reaches it.** The upstream regression test (`LayoutTests/fonts/font-face-load-crash.html`)
was replayed on the console page by page, each marker a beacon:

| probe | getter body | result |
|---|---|---|
| p446 | removes `#victim-style`, an element the page does not have | `DONE` - nothing happens |
| p447 | removes a real `<style id="v">` and forces layout | WebProcess dies, console says "there is not enough free system memory" |
| p448 | same, with markers either side of `face.loaded`, the getter install and `load()` | `BOOT` → `SETUP` → `FACE-found` → `M1-loaded` → `M2-getter` → nothing: the death is inside `face.load()` |
| p449 | B: removes a real element, **no** layout / A: same with layout | B returns `ffB-returned-fired=1`; A never returns |
| p450 | C: a plain `Promise.resolve(thenable)` with the same layout getter / D: the font trigger again | C returns `C-returned-got=1`; D hangs |

So the guide has `FontFace`, `document.fonts` resolves the injected `@font-face`, and the getter is
read synchronously during `face.load()` - the promise machinery does exactly what the write-up
depends on. What the page needs in order to die is the combination of a font-face status
notification, a getter that **removes an element that exists**, and a **forced layout** in that same
getter. Removing an element without layout is harmless, layout without a real removal is harmless,
and the same getter on a promise with no font face involved returns immediately.

**The loop is not JavaScript.** p448 capped the getter at 2000 entries and p449 at 4; neither cap
was reached before the process died. A resolved promise's `then` cannot be read twice, and block B
shows the getter runs exactly once, so the engine stops returning to script and loops inside the
layout it was asked to perform. Whether the loop is the font-status notification re-entering through
the style recalc or an allocation loop in the invalidation path is not established: the page is gone
within a second and the guide browser has no console.

**What this corrects in the public write-up.** The loop the fix guards is a snapshot of strong
references - `copyToVectorOf<Ref<CSSFontFaceClient>>` - so a client removed by the getter cannot be
freed while the iteration is still running. "Callback on the now-freed object" does not follow from
that code; what the missing check allows is a callback on a client that has been removed from the
set. On 14.10 the observable consequence is the recursion above, and the write-up's exploitation
section has nothing to build on: no object is freed to groom, and no reclaimable object of the
client's type is shown. CVE-2026-43715 is therefore **a denial of service against the guide's
WebProcess on 14.10**, the same shape as Findings 7-9, not a route to memory disclosure or control.

**To reproduce**, serve `probes/phase13_webkit/p450-layout-in-getter.js` as the default page
(`tools/webkit_server.py --port 443 --tls --cert ug_cert.pem --key ug_key.pem --dns --dns-domains
manuals.playstation.net --dns-log-queries --default p450-layout-in-getter.js`) and open the User's
Guide. `C-returned-got=1` arrives; `D-issued` arrives; the console then reports the memory message
and the page does not come back.

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

## Finding 11: The post-cut crash corpus reproduces as hangs, not crashes

**Probes:** `tools/layout_pages.py` + `p172-jsc-corpus-runner.js` over 232 LayoutTests that
commits after the 17.0 branch point added under `LayoutTests/` for `crash`, `use-after-free`,
`out-of-bounds`, `type confusion` and `security`.

This corpus is the one class the JavaScriptCore corpus could not cover: bugs whose trigger is
layout, animation, font or hit-testing rather than a language edge. Each test was wrapped as a
standalone page with a `testRunner`/`internals` stub, one document per case, and replayed on
14.10's guide.

| | count |
|---|---|
| pages in the corpus | 232 |
| cases started | 218 |
| cases completed | 214 |
| never started (popup cases, pinned up front) | 14 |
| pinned | 21 |

No case produced a memory-safety death. Every stop has an explanation:

- **14 cases call `window.open`** and were pinned before the run, because a popup request ends
  the console's WebProcess (Finding 5).
- **Six cases hang the engine** and were pinned after measurement: `hit-test-into-iframe-under-
  transformed-ancestor`, `named-slot-assignment-resolve-after-mutation-crash`,
  `font-face-load-crash` (Finding 10), `insecure-websocket-in-iframe-UpgradeMixedContent` (waits
  for a server that does not exist), `schedule-request-object-then-disconnect-crash` and
  `animation-suspension-no-timelines-controller-crash`. The last three fail with "there is not
  enough free system memory" rather than a stop, and one of them shows that dialog with no text.
- **Three were harness defects of ours**, not engine behaviour: a test whose own `<script>` is
  never closed, a test that builds markup in a JavaScript string containing `</body>`, and a test
  whose resource requests were answered with a second copy of the corpus runner. All three now
  return `OK`, and the wrapper has a test for each.
- **Cumulative pressure is real**: after ~86 documents the WebProcess refuses to continue even
  though every case up to that point completed. A reload resumes from the server cursor.

**What this does not say.** A layout test that reports `OK` here has been shown not to kill the
guide's WebProcess under this harness. Most of these tests were written to exercise a fix, and the
`testRunner`/`internals` stub answers every call successfully, so a test can pass without ever
reaching its crash path. The corpus therefore cannot clear 14.10 of these bugs; it can only show
that the obvious replay does not reproduce them.


## Finding 12: `FontFaceSet::load()` dies inside the call on 14.10, and the free is `style.remove()` (issue #143)

**Probe:** `p_ffset_uaf.js` → `/corpus/ffset-v9.html` (page kept out of the repository; see the
harness note at the end of Finding 10)

Issue #143 reports a use-after-free reached through `FontFaceSet::load()`, where the internal
`iterateClients()` snapshot holds clients strongly but the face vector built by
`matchingFacesExcludingPreinstalledFonts()` holds `std::reference_wrapper<CSSFontFace>` and so
dangles once a style is removed from the `then` getter. The report is for 14.00 and states the
14.10 hole by inheritance. It was measured here.

The page is the issue's v9 verbatim: add `FontFace('a', 'local(Helvetica)', {unicodeRange:
'U+0041'})`, install a `FontFace.prototype.then` getter that removes the `<style id="victim-style">`
that owns the matching face, forces layout, calls `document.fonts.delete(this)`, then call
`document.fonts.load('1em a, x', 'AB')`. Every step posts synchronously to `/beacon/<tag>`, so the
last line in the server log is the last step that ran. `ffset-config.json` selects an arm --
`spray` (CSS `@font-face` rules), `jsfaces` (JS `FontFace` objects created before the call),
`jsfaces_rm` (created in the getter between `st.remove()` and the forced layout), `jsfaces_ig`
(created in the getter after the layout), `cssrules` (plain non-font rules), `del`, `rm`, `layout`,
`rmtarget` (`victim`, `other`, `plain`) and `reload` -- so one manual page open yields repeated
attempts; a surviving attempt reloads itself after 700 ms and a dying one leaves the console
dialog. Faces created by any arm are watched with a 200 ms poll (`FACES <when> moved= settled=`)
and the resolved array is logged as `fams=[...]`.

| configuration | attempts | deaths inside `document.fonts.load()` |
|---|---|---|
| remove + `fonts.delete` | 5 | **4** |
| remove, no `fonts.delete` | 2 | **1** |
| **no removal**, `fonts.delete` | 19 | **0** |
| remove + `fonts.delete` + 1000-rule spray | 20 | **0** |

The first 46 attempts ran in one WebProcess. The `remove + delete` row is the last row re-tested after the
19 removal-free survivals, and it still died 2 of 3 times, so the comparison is not an artefact of a
fresh process going soft with age.

**The death is inside the call, not in the getter.** Every death ends at `GETTER returning` and
never reaches `PROMISE load returned`: the getter has run to completion and returned, and the
process dies after that, inside `FontFaceSet::load()`. That is the signature the issue predicts,
and it differs from Finding 10, where the same trigger through `FontFace::load()` produced a hang
that never returned to script.

**`style.remove()` is the free; `document.fonts.delete(this)` is not.** The 1000-rule spray and
the removal are the only knobs that change the outcome. With `fonts.delete` still called but the
style removal skipped, 19 of 19 attempts survive; with both called, 4 of 5 die. The reported
"only `style.remove()` causes the synchronous free" holds.

**The spray changes the promise, not just the survival rate.** Under 1000 `@font-face` rules the
load promise settled in 11 of 20 attempts and stayed **pending in the other 9**; the 14.00 report
describes an immediate resolve. A pending `document.fonts.load()` promise whose call already
returned is consistent with the face set having lost the client the resolution would have notified,
which is the same removal the getter performs.

**`"There is not enough free system memory"` is the death message, not an OOM.** The page lived
under a second in every death, and the 232-case layout corpus showed the same dialog for cases that
allocate nothing (Finding 11). It should be read as "the WebProcess died".

**The mechanism, read from the engine.** `FontFaceSet::load()`
(`Source/WebCore/css/FontFaceSet.cpp`) calls `updateStyleIfNeeded()`, then
`matchingFacesExcludingPreinstalledFonts()`, which returns
`Vector<std::reference_wrapper<CSSFontFace>>` -- raw pointers -- and walks that vector for the rest
of the call: `face.get().load()`, `face.get().status()`, `face.get().existingWrapper()`, and
finally `face.get().wrapper(...)` to build the resolved array. The faces are owned by
`CSSFontFaceSet::m_faces` (`Vector<Ref<CSSFontFace>>`, `CSSFontFaceSet.h:127`), and
`CSSFontFaceSet::clear()` drops every one of those refs (`m_faces.clear()`,
`CSSFontFaceSet.cpp:304`).

**Correction: the removal is incremental, not a whole-set rebuild.** An earlier revision of this
finding said a recalc inside the getter runs `clear()` and rebuilds the CSS-connected partition, and
used that to explain why removing a style whose family is not even in the load string kills the page
the same way. A control run contradicts it. The page injects eight filler rules (`m0`-`m7`), one
victim rule (`x`), and `FontFace('a')`; the getter removes the victim; the load string is `1em a`
so `x` is not in the captured vector. The process **survives**, resolves `fams=[a]`, and reports
`fonts.size=9 set=[m0,m1,m2,m3,m4,m5,m6,m7,a]` afterwards: every filler face is still alive and only
the victim was destroyed. The free is targeted at the removed rule, which is what makes it a
predictable object to fill rather than a bulk teardown.

**Every interleaving JavaScript can reach.** The free and the rebuild happen inside one synchronous
recalc, so the only question is whether an allocation can be placed in that window.

| arm | allocation point | attempts | outcome |
|---|---|---|---|
| none (`del=1 rm=1 lay=1`) | -- | 7 | died inside `load()`, 6/7 |
| unrelated style removed | -- | 1 | died inside `load()` |
| 64 `FontFace` objects | before `load()` | 1 | survived |
| 32 `FontFace` objects | in the getter, **after** the forced layout | 8 | 5 survived, 2 died at promise resolution, 1 died inside `load()` |
| 32 `FontFace` objects | in the getter, **between** removal and layout | 1 | died inside `load()` |
| 64 `FontFace` objects | in the getter, **after** the forced layout | 2 | 1 survived, 1 died inside `load()` |
| 1000-rule `@font-face` spray | before `load()` | 15 | survived |

**The bare trigger is not deterministic, so one page load is not an oracle.** A ladder page runs the
same trigger seven times in one load with 0, 1, 2, 4, 8, 16, 32 and 64 post-recalc allocations, each
step re-injecting its own victim style. All eight steps survived and every one resolved with
`RESOLVED size=2`, i.e. the load returned both `a` and the victim `x` and the victim was never
destroyed in those runs. Set against the 6-of-7 death rate for the same configuration elsewhere,
the free depends on page and heap state rather than on the trigger alone. Any conclusion about a
reclaim arm therefore needs repeated attempts, each from a fresh page, and a single survival is not
evidence that the arm works.

**The vector is used twice, and suppressing the first use only moves the death.** In the surviving
after-layout runs the process later died at the point where the promise resolves, which is the
`face.get().wrapper(...)` walk over the same stale vector. No arm ever showed one of our objects
being reached through it: `FACES ... moved=0 settled=0` on every survivor, and the resolved array
never contained a sprayed family.

**The dangling entry can be occupied by an object we choose (2026-10-24, later run).** A swap page
injects eight filler rules, injects a victim rule for family `x`, hooks `then`, and inside the getter
removes the victim rule, forces layout, then allocates N fresh `new FontFace('z<i>','local(Arial)')`
objects and keeps them in a global array. The load string is `1em a, x`, so the captured vector holds
`[a, x]` and `x` is destroyed before the walk reaches it.

| N | attempts | resolved array |
|---|---|---|
| 64 | 4 | `fams=[a,z39]`, `fams=[a,z39]`, `fams=[a,z59]`, one death at `GETTER returning` |
| 64, after 124 strings of 32-512 bytes | 2 | `fams=[a,z63]`, then a death at `GETTER returning` |

The walk returned **one of our own faces as a match for a family it does not have**. The stale
`CSSFontFace*` was reused by the `CSSFontFace` belonging to `z39` (or `z59`), which is what the engine
then read for `status()` and `wrapper(...)`. The index varies with heap state and roughly one attempt
in four dies instead, but the substitution itself repeated.

**What this establishes and what it does not.** On 14.10 a `FontFaceSet::load()` call in the guide's
WebProcess keeps a raw pointer to a `CSSFontFace` that a style removal in the `then` getter destroys,
and an allocation made later in the same getter takes that slot and is handed back through the
resolved array. Object substitution through a stale engine pointer is demonstrated; no value is read
out of freed memory, and no field of the substituted object is reinterpreted as a pointer or a
length, so this is not yet a memory-corruption primitive. The missing pieces are a same-size class
whose fields can be shaped into something the walk will follow, and an address disclosure -- no leak
was found, and ArrayBuffer-backed data was not observed to land in that size class (superseded 2026-10-29 - it does; see Finding 13).

**The slot only accepts another `CSSFontFace` (2026-10-24, string arm).** Before the sixty-four
`FontFace` allocations the same getter allocated 124 strings of 32 to 512 bytes in steps of 16, four
per length, with `new Array(n + 1).join('A')`. A `CSSFontFace` still took the slot on the first
attempt (`fams=[a,z63]`) and the second attempt died at `GETTER returning`; no string ever occupied
it. That matches the allocation policy in the upstream header: `DECLARE_ALLOCATOR_WITH_HEAP_IDENTIFIER(CSSFontFace)`
plus `WTF_DEPRECATED_MAKE_FAST_ALLOCATED_WITH_HEAP_IDENTIFIER(CSSFontFace, CSSFontFace)` give the
class its own bmalloc heap, so an allocation of a different type cannot reuse the chunk whatever its
size. The header is the upstream source read locally, not the 14.10 image; the build flag that
enables heap identifiers was not verified, so the measurement and the source agree rather than prove
each other. If it holds, type confusion through this bug is not reachable from script, and the
substitution cannot become a corruption primitive without a same-heap object whose contents script
can choose -- and script can choose the contents of no `CSSFontFace` field that the walk follows.

## Finding 13: the freed `CSSFontFace` is reclaimable by script, and the engine writes heap pointers into it (2026-10-29)

Finding 12 ended with the free demonstrated but nothing read out of it: "no value is
read out of freed memory, and no field of the substituted object is reinterpreted as a
pointer or a length". That gap is now closed for the disclosure half.

The same trigger, with thirteen size classes of `ArrayBuffer` allocated in the getter
after `style.remove()`, gives `P563-HIT-b19-s192-o0-n9`: a 192-byte backing store takes
the freed chunk and then reads `+0x00 = 1` (the `RefCounted` counter), `+0x58` and
`+0x68` as WebProcess heap pointers. The control page, identical apart from the
`style.remove()` so no object is freed, is byte-clean (`P563-ALL-CLEAN-104`). Since
`ArrayBuffer` data is zero-filled at allocation, the three values were written after
our buffer took the chunk, by the engine continuation that still holds the stale
pointer. A heap-churn arm moves both qwords and one navigation moves them again, so
they are addresses rather than constants.

`Source/WebCore/css/CSSFontFace.h` places the counter at offset 0 and the two slots in
the `m_sources` / `m_clients` / `m_wrapper` run; `addClient()` is `m_clients.add()`
with a `WeakHashSet` impl allocated on first use, which is the fresh allocation whose
address lands in our buffer.

A second stage (`p564`) frees another face, refills the chunk with a template carrying
**those engine pointers** at `+0x58`/`+0x68`, and lets the load continue: it resolves
and the page survives. A template that is zero apart from `0x4141414141414141` at
`+0x30`, `+0x58` or `+0x68` kills the page after the getter, so those slots are
dereferenced on this path.

Two corrections follow. The claim above that "ArrayBuffer-backed data does not land in
this allocator's size class" is wrong for this build: `Source/cmake/OptionsPlayStation.cmake`
leaves `USE_ISO_MALLOC` off, and the measurement shows the backing store in the
`CSSFontFace` chunk while the no-free control stays clean. And the statement that
nothing is read out of the freed object is superseded by `p563`.

What is still missing is an address of script's own memory: the leaked values belong to
the engine, so a fake client or source table cannot be aimed yet. Full measurements,
constraints (one successful run per WebProcess, family-name limits) and reproduction
steps are in `docs/FONTFACE_RECLAIM_LEAK_14_10.md`.

## Finding 14: Canvas UAF Bidirectional R/W (CVE-2026-43720) — CONFIRMED ON DEVICE

**Probe:** p553 (`p553-canvas-uaf-write-confirm.js`)
**Executed:** 2026-10-26 via User Guide DNS spoofing (host.py)
**Evidence:** `results/phase13_webkit/p553_canvas_uaf_write_confirm_20261026.txt`

CVE-2026-43720 is **unpatched** on PS5 14.10. The `desynchronized` getter in `getContext('2d', opts)` re-enters `getContext()`, producing two distinct JS wrappers (`outer !== inner`). The inner wrapper points to a freed 768B FastMalloc slot.

| Step | Result |
|------|--------|
| UAF trigger | `getter=1, inner=true, outer=true, same=false` — context replacement |
| Same-type reclaim | 80 Canvas2D spray, spray[9] lands in freed slot |
| Channel verification | `inner.getTransform()` reads spray sentinel — stale reads reclaimed memory |
| Write via stale | `inner.setTransform(99.001, ...)` — readback matches written values |
| Bidirectional alias | spray[9].getTransform() returns inner's written values |
| Reverse write | spray[9] writes, inner reads — both directions confirmed |
| Numeric properties | lineWidth, globalAlpha, shadowBlur, shadowOffsetX/Y, miterLimit, lineDashOffset all alias bidirectionally |
| State stack | save()/restore() functional on stale wrapper |
| Stability | No crash — repeatable primitive |

**Primitive scope:** Bidirectional R/W of Canvas2D numeric fields (6×float64 transform + 7 properties) through the C++ API. NOT arbitrary write — values pass through getters/setters that interpret them as floats.

**DAZ caveat:** MXCSR DAZ (Denormals-Are-Zero) is ON in PS5 14.10 WebKit. Heap pointers as IEEE754 float64 are denormals → FPU reads 0.0. BigUint64Array (BigInt, no FPU) is required for any pointer-reading approach.

**Cross-type reclaim DEAD:** ArrayBuffer spray does not land in the 768B Canvas2D slot — different bmalloc size classes (p554/b/c).

**Remaining blocker:** Info leak. The entire 14.10 community (49 documented dead paths) is blocked on reading a heap pointer as a JS number. API-level canvas reads all return zeros (V674). Decoder-level APNG overread and RAB sort OOB (P560) are the active angles.

## Updates Since This Snapshot (2026-10-19)

- **p156 "reproduction" on a second console — same false positive (corrected 2026-10-20):** the 14/14 `.length` = 81400 reports were the literal string length (814-char chunk × 100), not corruption. The OOM-death-vs-beacon-ordering data from that console's 17 runs remains valid ([issue #6](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/6)).
- **p160 (Relapse primitives) also confirmed dead on the second console** — independent reproduction of our PR #32 result (54/54, scope receiver `undefined`).
- **CSSFontFace (CVE-2026-43715) measured on the console — a hang through `FontFace::load()` (2026-10-22):** the trigger is reachable from the guide (probes p446-p450), but that entry point runs out of memory and dies rather than returning. The fix's client snapshot holds strong references, so nothing is freed mid-iteration; see **Finding 10**. After issue #143 the same trigger was re-measured through **`FontFaceSet::load()`**, the entry whose snapshot is not strong: there the process dies *inside* the call, needs a `style.remove()`, and is suppressed by a font-face spray — **Finding 12** (2026-10-24). Neither entry point has been shown to hand back the freed object's contents.
- **Kernel audit published** (their [KERNEL_AUDIT.md](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/master/docs/KERNEL_AUDIT.md)): Tier-1 candidates CVE-2026-7270 (assessed in this repo), CVE-2026-45251 (poll/select UAF, not yet assessed here), and CVE-2024-43102 (umtx — patch status reopened by our PR #41: `_umtx_op` is 454 and alive; earlier "umtx" tests hit 557).
- **Length-window audit** ([WEBKIT_LENGTH_WINDOW_AUDIT.md](WEBKIT_LENGTH_WINDOW_AUDIT.md)) — analyzed the false positive; its capacity question dissolves. The p161 probe it inspired remains correct (PR #43 fixed its blob construction) and now tests whether the correct-strings groom corrupts at all.

## Attribution

Research by [@Arn0Stride7](https://x.com/Arn0Stride7). Built with Claude Opus 4.6, GPT-6.1-Sol, DeepSeek v4.1-Flash, and other models. Full credits in the source repository.
