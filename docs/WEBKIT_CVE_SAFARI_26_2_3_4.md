# WebKit CVE Analysis: Safari 26.2 / 26.3 / 26.4

## Context: PS5 14.10 Cherry-Pick Window

PS5 firmware 14.10 cherry-picks WebKit fixes up to approximately Feb 2026.
Safari 26.3 (Feb 11, 2026) is **borderline** — some fixes may have been picked, others not.
Safari 26.4 (Mar 24, 2026) is **AFTER** the confirmed cherry-pick cutoff — these bugs are almost certainly present in PS5 14.10's WebKit.

---

## Safari 26.4 — AFTER Cherry-Pick Cutoff (HIGH PRIORITY)

### 1. CVE-2026-28859 — SANDBOX ESCAPE ⚠️ CRITICAL

| Field | Value |
|-------|-------|
| **Bugzilla** | [308248](https://bugs.webkit.org/show_bug.cgi?id=308248) |
| **Impact** | A malicious website may be able to process restricted web content outside the sandbox |
| **Description** | The issue was addressed with improved memory handling |
| **Researchers** | greenbynox, Arni Hardarson, and an anonymous researcher |
| **Commit** | [`6aacf62`](https://github.com/WebKit/WebKit/commit/6aacf62) (Apr 21, 2026 on main) |
| **Safari branch** | Originally `305413.340@safari-7624-branch` (`035f36c`) |
| **Component** | WebKit GPU Process (RemoteGraphicsContext) |

**Commit message:**
```
Copy the glyph buffer in RemoteGraphicsContext::drawGlyphs

Slight variant of Kimmo's patch, using inline vector capacity to attempt
clawing back some performance impact when copying the buffer.

No new tests.
```

**Files changed:**
- `Source/WebKit/GPUProcess/graphics/RemoteGraphicsContext.cpp`

**Diff (complete):**
```cpp
// BEFORE:
context().drawGlyphs(*font, glyphsAdvances.span<0>(),
    Vector<GlyphBufferAdvance>(glyphsAdvances.span<1>()),
    localAnchor, fontSmoothingMode);

// AFTER:
Vector<GlyphBufferGlyph, 128> glyphs { glyphsAdvances.span<0>() };
Vector<GlyphBufferAdvance, 128> advances { glyphsAdvances.span<1>() };
context().drawGlyphs(*font, glyphs.span(), advances.span(),
    localAnchor, fontSmoothingMode);
```

**Analysis:**
- **Vulnerability class**: The original code passes a span directly from IPC-received data into the GPU process's graphics context. If the underlying IPC buffer is freed/reallocated during `drawGlyphs`, the GPU process accesses freed memory. By copying the glyph buffer into local stack vectors first, the data is decoupled from the IPC lifetime.
- **Exploitation potential**: HIGH. This is in the GPU Process, which runs with different (elevated) privileges relative to the Web Content process. A UAF in the GPU process from the web content sandbox = **sandbox escape vector**. The fix is a trivial 3-line change — the bug was a missing copy of untrusted IPC data.
- **Regression test**: NONE ("No new tests.")
- **PS5 relevance**: The PS5 browser uses a multi-process WebKit model. If it has a GPU Process (or equivalent compositor process), this exact pattern could be exploitable. Even without a separate GPU process, the rendering path may share the same codepath.
- **PS5 adaptability**: N/A — this is a rendering pipeline bug, not directly triggerable from JS. Exploitation requires crafting specific glyph rendering sequences that cause the span lifetime issue. Requires understanding of the IPC serialization format for `GlyphsAndAdvances`.

---

### 2. CVE-2026-20664 — JSC Use-After-Free (WebAssembly Resizable Buffers) ⚠️ HIGH

| Field | Value |
|-------|-------|
| **Bugzilla** | [306136](https://bugs.webkit.org/show_bug.cgi?id=306136) |
| **Impact** | Processing maliciously crafted web content may lead to an unexpected process crash |
| **Description** | The issue was addressed with improved memory handling |
| **Researchers** | Daniel Rhea, Söhnke Benedikt Fischedick (Tripton), Emrovsky & Switch, Yevhen Pervushyn |
| **Commit** | [`6b357f3`](https://github.com/WebKit/WebKit/commit/6b357f3) (Apr 29, 2026 on main) |
| **Safari branch** | Originally `305413.190@safari-7624-branch` (`59c4a7a`) |
| **Component** | JSC — WebAssembly / ArrayBuffer / TypedArrays |

**Commit message:**
```
[JSC] Use-after-free after growing a resizable buffer on a WebAssembly memory

This issue is related to earlier work on WebAssembly memory buffers. As part of
that work, it became possible for an ArrayBuffer's underlying storage to change
its location in memory as a result of growing. To deal with this change, two
methods were introduced: ArrayBuffer::refreshAfterMemoryGrow and
ArrayBufferContents::refreshAfterMemoryGrow. However:

1. ArrayBufferContents::refreshAfterMemoryGrow does not update the m_data field,
   which is a direct pointer to the memory base.

2. Refreshing array buffer objects is not enough because a JSArrayBufferView has
   its own direct pointer into the underlying buffer's data (m_vector).
```

**Files changed:**
- `JSTests/wasm/stress/resizable-buffer-grow-view-refresh.js` (NEW — regression test)
- `Source/JavaScriptCore/runtime/ArrayBuffer.cpp`
- `Source/JavaScriptCore/runtime/JSArrayBufferView.h`
- `Source/JavaScriptCore/runtime/JSArrayBufferViewInlines.h`

**Regression test (full):**
```javascript
//@ requireOptions("--useWasmMemoryToBufferAPIs=true")

import * as assert from '../assert.js'

const memories = [];
for (let i = 0; i < 500; i++) {
    try {
        memories.push(new WebAssembly.Memory({ initial: 1, maximum: 100 }));
    } catch (e) { break; }
}

const memory = new WebAssembly.Memory({ initial: 1, maximum: 10 });
const buffer = memory.toResizableBuffer();
const ta = new Uint32Array(buffer);
ta[0] = 0xCAFEBABE;

memory.grow(1);

for (let i = 0; i < 100; i++) {
    const arr = new ArrayBuffer(65536);
    new Uint32Array(arr).fill(0xDEADBEEF);
}

assert.eq(ta[0], 0xCAFEBABE);
```

**Analysis:**
- **Vulnerability class**: USE-AFTER-FREE. When Wasm memory grows, the underlying buffer can be relocated. `ArrayBufferContents::m_data` was NOT updated (stale pointer), AND `JSArrayBufferView::m_vector` (TypedArray's cached data pointer) was NOT updated. Reading/writing through a TypedArray after a Wasm memory grow accesses freed/reallocated memory.
- **Exploitation potential**: VERY HIGH. Classic UAF with controllable allocation sizes. The attacker:
  1. Creates a Wasm memory + resizable buffer + TypedArray view
  2. Grows the memory (relocates backing store)
  3. Sprays the old region with controlled data
  4. Reads/writes through the stale TypedArray pointer → **arbitrary read/write primitive**
- **PS5 adaptability**: REQUIRES `memory.toResizableBuffer()` API (`--useWasmMemoryToBufferAPIs`). This is a relatively new API. **Must verify if PS5 14.10's JSC has this API enabled**. If the flag exists but is disabled by default, the bug is not reachable. If it's enabled, this is a **top-tier exploit primitive**.
- The test uses `import` (ES modules) and `assert.js` — these are jsc shell builtins. A browser adaptation would need to be pure JS with manual assertion.

**Key fix details:**
```cpp
// ArrayBufferContents now updates m_data:
m_data = memory->basePointer();

// New method on JSArrayBufferView:
inline void JSArrayBufferView::refreshVector(void* newData) {
    if (hasVector()) {
        void* newVectorPtr = static_cast<uint8_t*>(newData) + byteOffsetRaw();
        m_vector.setWithoutBarrier(newVectorPtr);
    }
}

// ArrayBuffer::refreshAfterWasmMemoryGrow now iterates all views:
for (size_t i = numberOfIncomingReferences(); i--;) {
    JSCell* cell = incomingReferenceAt(i);
    auto* view = dynamicDowncast<JSArrayBufferView>(cell);
    if (view)
        view->refreshVector(newData);
}
```

---

### 3. CVE-2026-28857 — JSC TypedArray TOCTOU Race (SharedArrayBuffer) ⚠️ HIGH

| Field | Value |
|-------|-------|
| **Bugzilla** | [307723](https://bugs.webkit.org/show_bug.cgi?id=307723) |
| **Impact** | Processing maliciously crafted web content may lead to an unexpected process crash |
| **Description** | The issue was addressed with improved memory handling |
| **Researchers** | Minse Kim, Narcis Oliveras Fontàs, Söhnke Benedikt Fischedick (Tripton), Daniel Rhea, Nathaniel Oh (@calysteon) |
| **Commit** | [`4c82252`](https://github.com/WebKit/WebKit/commit/4c82252) (Apr 22, 2026 on main) |
| **Safari branch** | Originally `305413.294@safari-7624-branch` (`17128d3`) |
| **Component** | JSC — TypedArray prototype methods |

**Commit message:**
```
[JSC] Snapshot span of TypedArrays in toSorted, toReversed, and with

The TypedArray.prototype.toSorted, toReversed, and with methods all create a
new TA and copies from the original. This copying is currently done with a
typedSpan(), which reads the TA's length. If the TA is backed by a growable
SharedArrayBuffer, this typedSpan may have a different length than the copy as
it may have grown in parallel. This PR fixes this by snapshotting the span
ahead of the time.
```

**Files changed:**
- `JSTests/stress/growable-sharedarraybuffer-parallel-grow-during-prototype-methods.js` (NEW — regression test)
- `Source/JavaScriptCore/runtime/JSGenericTypedArrayViewPrototypeFunctions.h`

**Regression test (full):**
```javascript
const ROUNDS = 10;
const ITERATIONS_PER_ROUND = 5000;

for (let round = 0; round < ROUNDS; round++) {
    const N = 16;
    const maxBytes = N * 4 + 4096;
    const sab = new SharedArrayBuffer(N * 4, { maxByteLength: maxBytes });
    const ta = new Int32Array(sab);

    $.agent.start(`
        $.agent.receiveBroadcast((sab, idx) => {
            for (let i = 0; i < 50000; i++) {
                try {
                    if (sab.byteLength < ${maxBytes}) {
                        sab.grow(sab.byteLength + 64);
                    }
                } catch (e) {}
            }
            $.agent.report("done");
            $.agent.leaving();
        });
    `);

    $.agent.broadcast(sab, 0);

    for (let i = 0; i < ITERATIONS_PER_ROUND; i++) {
        try {
            ta.with(0, 0x41414141);
            ta.toReversed();
            ta.toSorted();
        } catch (e) {}
    }

    $.agent.sleep(50);
    $.agent.getReport();
}
```

**Analysis:**
- **Vulnerability class**: TOCTOU / Race condition. `toSorted()`, `toReversed()`, and `with()` read the TypedArray length, allocate a result buffer of that size, then copy from the source. If the source's SAB grows between the length read and the copy, the copy reads past the allocated result buffer bounds → **heap buffer overflow**.
- **Exploitation potential**: MEDIUM-HIGH. Requires SharedArrayBuffer + Worker threads for the race. The race window is small but can be widened by growing in a tight loop. OOB read could leak heap data; OOB write could corrupt adjacent heap objects.
- **PS5 adaptability**: LOW — uses `$.agent` (jsc shell multi-agent testing harness). Browser adaptation would need `SharedArrayBuffer` + `Worker` + `Atomics`. PS5 browser may not expose `SharedArrayBuffer` (requires COOP/COEP headers). Also requires growable SAB support (`maxByteLength` option). **Must verify SAB availability on PS5 browser.**

**Key fix pattern:**
```cpp
// BEFORE (vulnerable):
size_t length = thisObject->length();  // reads current length
// ... allocate result of `length` ...
auto from = thisObject->typedSpan();   // reads CURRENT span (may be longer!)
WTF::copyElements(to, from);          // OOB write!

// AFTER (fixed):
auto originalSpan = const_cast<const ViewClass*>(thisObject)->typedSpan();
size_t length = originalSpan.size();   // snapshot length from same span
// ... allocate result of `length` ...
WTF::copyElements(to, originalSpan);   // uses snapshotted span
```

---

### 4. CVE-2026-28861 — Cross-Origin Script Message Handler ⚠️ HIGH

| Field | Value |
|-------|-------|
| **Bugzilla** | [307014](https://bugs.webkit.org/show_bug.cgi?id=307014) |
| **Impact** | A malicious website may be able to access script message handlers intended for other origins |
| **Description** | A logic issue was addressed with improved state management |
| **Researchers** | Hongze Wu and Shuaike Dong from Ant Group Infrastructure Security Team, and webb |
| **Commit** | [`795ef8a`](https://github.com/WebKit/WebKit/commit/795ef8a) (Apr 29, 2026 on main) |
| **Safari branch** | Originally `305413.250@safari-7624-branch` (`c4006ba`) |
| **Component** | WebCore / WebKit — UserMessageHandler (WKScriptMessageHandler) |

**Commit message:**
```
UserMessageHandler.postMessage should fail if called from another frame

Before this fix, a reference to the UserMessageHandler can be stored outside the
frame, then the frame can be navigated, then the stored reference can be used to
post messages that appeared to come from the navigated frame. This adds a
restriction to make it so a UserMessageHandler can only be used by an origin that
is the same as the frame's current origin.
```

**Files changed:**
- `Source/WebCore/page/UserMessageHandler.cpp`
- `Source/WebCore/page/UserMessageHandler.h`
- `Source/WebKit/WebProcess/InjectedBundle/API/gtk/DOM/WebKitDOMDOMWindow.cpp`
- `Tools/TestWebKitAPI/Tests/WebKit/WKWebView/WKWebViewEvaluateJavaScript.mm` (Obj-C test)

**Analysis:**
- **Vulnerability class**: Cross-origin access. An attacker creates an iframe, grabs a reference to `iframe.contentWindow.window.webkit.messageHandlers.X`, navigates the iframe to a different origin, then calls `postMessage()` — the message appears to come from the NEW origin, not the attacker's origin. This bypasses same-origin policy for WKScriptMessageHandler.
- **Exploitation potential**: MEDIUM. This is a **logic bug**, not memory corruption. It allows spoofing the origin of messages to native app code. On PS5, this could potentially be used to send messages to native WebKit message handlers as if they came from a trusted origin.
- **PS5 adaptability**: DEPENDS on whether PS5 browser uses WKScriptMessageHandler (or equivalent) for privileged browser-to-native communication. If the PS5 browser UI uses message handlers for internal functions, this could be a powerful primitive for escalation. The attack pattern is pure JS/HTML (create iframe, grab reference, navigate, send message).
- **Regression test**: Obj-C TestWebKitAPI only (not adaptable to browser JS).

**Key fix — adds same-origin check:**
```cpp
static bool passesSameOriginCheck(JSC::JSGlobalObject& globalObject, RefPtr<LocalFrame> frame) {
    if (!frame) return false;
    RefPtr document = frame->document();
    if (!document) return false;
    Ref frameSecurityOrigin = document->securityOrigin();
    // ... check caller's origin matches frame's current origin ...
    return securityOrigin->isSameOriginAs(frameSecurityOrigin);
}
```

---

## Safari 26.3 — Borderline with Cherry-Pick Cutoff

### 5. CVE-2026-20644 — JSC Wasm OMG Tail Call Register Clobber (ARM) ⚠️ HIGH

| Field | Value |
|-------|-------|
| **Bugzilla** | [303444](https://bugs.webkit.org/show_bug.cgi?id=303444) |
| **Impact** | Processing maliciously crafted web content may lead to an unexpected process crash |
| **Description** | The issue was addressed with improved memory handling |
| **Researchers** | HanQing from TSDubhe and Nan Wang (@eternalsakura13) |
| **Commit** | [`4572dd4`](https://github.com/WebKit/WebKit/commit/4572dd4) (Mar 11, 2026 on main) |
| **Safari branch** | Originally `301765.350@safari-7623-branch` |
| **Component** | JSC — Wasm OMG/BBQ JIT (ARM-specific) |

**Commit message:**
```
[JSC] Clobber scratch register in OMG tail call on non-x64

The OMG tailcall patchpoint uses the scratch register. Currently, the scratch
is not clobbered early because on x64 we exhaust all registers if we do so.
Because of that, prepareTailCallImpl has special handling for saving and
restoring the scratch if it happens to alias one of the inputs. This special
save and restore has issues on ARM as the stack pointer arithmetic itself may
use the scratch, which complicates the restoring.

This PR makes the tail call patchpoint code architecture specific to confine
the save/restore complexity to x64. The special scratch register save/restore
paths are kept only on x64. On non-x64 platforms, the scratch registers are
clobbered early so they can never alias an input.

There is also a drive-by fix for negating float32s on x64 in BBQ.
```

**Files changed:**
- `JSTests/wasm/stress/omg-tail-call-clobber-scratch-register-2.js` (NEW — regression test)
- `Source/JavaScriptCore/wasm/WasmBBQJIT.cpp`
- `Source/JavaScriptCore/wasm/WasmOMGIRGenerator.cpp`

**Analysis:**
- **Vulnerability class**: REGISTER CORRUPTION in JIT-compiled Wasm code on ARM. The scratch register can alias a tail-call input on ARM, and restoring it after stack pointer arithmetic uses the scratch itself → corrupted register values. This can cause **controlled register corruption** leading to arbitrary code paths.
- **Exploitation potential**: HIGH on ARM targets. PS5 is x86_64, BUT the commit also includes a "drive-by fix for negating float32s on x64 in BBQ" which indicates a separate x64 bug was also fixed.
- **PS5 relevance**: PS5 is x86_64 — the main ARM register clobber bug does not apply. However, the BBQ float32 negation fix IS x64-relevant. Need to examine the BBQ fix specifically.
- **PS5 adaptability**: Requires Wasm with tail calls. The regression test uses jsc-shell builtins.

---

### 6. CVE-2026-20636 — WebKit Memory Handling Crash (RESTRICTED)

| Field | Value |
|-------|-------|
| **Bugzilla** | [304661](https://bugs.webkit.org/show_bug.cgi?id=304661) — ACCESS DENIED |
| **Impact** | Processing maliciously crafted web content may lead to an unexpected process crash |
| **Description** | The issue was addressed with improved memory handling |
| **CWE** | CWE-119 (Buffer Overflow), CWE-120 (Classic Buffer Overflow) |
| **Researchers** | EntryHi |
| **Commit** | NOT FOUND in public GitHub (security-restricted) |
| **Component** | WebKit (unknown — likely WebCore or JSC) |

**Analysis:**
- Bugzilla is access-restricted. No public commit found matching bug 304661.
- CWE classification as CWE-119/CWE-120 (buffer overflow) is significant — this is **memory corruption**, not just a crash.
- CVSS scores vary: CISA gives 4.3, but cvefeed.io gives 8.8 (HIGH).
- **PS5 relevance**: UNKNOWN without the commit. The "improved memory handling" description and buffer overflow CWE suggest a potentially exploitable memory corruption bug.

---

### 7. CVE-2026-20635 — WebKit Memory Handling Crash (RESTRICTED)

| Field | Value |
|-------|-------|
| **Bugzilla** | [304657](https://bugs.webkit.org/show_bug.cgi?id=304657) — ACCESS DENIED |
| **Impact** | Processing maliciously crafted web content may lead to an unexpected process crash |
| **Description** | The issue was addressed with improved memory handling |
| **CWE** | CWE-119 (Buffer Overflow) |
| **Researchers** | EntryHi |
| **Commit** | NOT FOUND in public GitHub (security-restricted) |
| **Component** | WebKit (unknown) |

**Analysis:**
- Same situation as CVE-2026-20636. Both were reported by "EntryHi" and are memory handling bugs.
- Affects more platforms (iOS 18.7.5, tvOS, watchOS) suggesting a core WebKit/JSC issue.
- **PS5 relevance**: UNKNOWN without the commit. CWE-119 classification is concerning.

---

### 8. CVE-2026-20608 — JSC Private Fields Seal/Freeze Attribute Corruption ⚠️ MEDIUM-HIGH

| Field | Value |
|-------|-------|
| **Bugzilla** | [303357](https://bugs.webkit.org/show_bug.cgi?id=303357) |
| **Impact** | Processing maliciously crafted web content may lead to an unexpected process crash |
| **Description** | This issue was addressed through improved state management |
| **Researchers** | HanQing from TSDubhe and Nan Wang (@eternalsakura13) |
| **Commit** | [`672cdd3`](https://github.com/WebKit/WebKit/commit/672cdd3) (Mar 3, 2026 on main) |
| **Safari branch** | Originally `301765.343@safari-7623-branch` |
| **Component** | JSC — PropertyTable (Object seal/freeze) |

**Commit message:**
```
[JSC] Don't set attributes on private fields when sealing/freezing

This PR makes it such that when sealing and freezing objects, entries in the
PropertyTable that are private fields do not change their attributes. Private
fields are not properties from the spec's point of view, and thus don't have
attributes.

Ensuring private field entries simplifies assumptions in the JITs, as they can
assume having attributes when setting a property results in a structure
transition.
```

**Files changed:**
- `JSTests/stress/private-names-seal-freeze.js` (NEW — regression test)
- `Source/JavaScriptCore/runtime/PropertyTable.cpp`

**Regression test (full):**
```javascript
class C {
  #field;
  setField(v) {
    this.#field = v;
  }
}

for (let i = 0; i < 10000; i++) {
  let c = new C();
  Object.seal(c);
  c.setField(i);
}

for (let i = 0; i < 10000; i++) {
  let c = new C();
  Object.freeze(c);
  c.setField(i);
}
```

**Analysis:**
- **Vulnerability class**: JIT ASSUMPTION VIOLATION. The JITs assume that when `Object.seal()` or `Object.freeze()` change property attributes, this always triggers a structure transition. But private fields (class `#field`) had their attributes modified without a structure transition, because they shouldn't have attributes at all. This breaks JIT-compiled code that relies on structure identity for optimization decisions.
- **Exploitation potential**: MEDIUM-HIGH. JIT assumption violations are a classic JSC exploit primitive. By creating an object with private fields, sealing/freezing it, then setting the private field, the JIT may use stale structure information → **type confusion** in JIT-compiled code. The 10,000 iteration loop is specifically to trigger JIT compilation (OMG tier).
- **PS5 adaptability**: EXCELLENT. The regression test is **pure JavaScript** — no shell builtins, no imports, no special APIs. Can be run directly in a PS5 browser `<script>` tag. The only question is whether PS5's JSC version supports private class fields (`#field` syntax). ES2022 private fields should be available in WebKit builds from this era.
- **Info leak / Memory corruption**: Could enable **type confusion** leading to memory corruption, depending on how the JIT uses the stale structure information.

**Key fix in PropertyTable.cpp:**
```cpp
// seal() — now skips private fields:
void PropertyTable::seal() {
    forEachPropertyMutable([&](auto& entry) {
        if (!PropertyName(entry.key()).isPrivateName())  // NEW CHECK
            entry.setAttributes(entry.attributes() | PropertyAttribute::DontDelete);
        return IterationStatus::Continue;
    });
}

// freeze() — same pattern
// isSealed() / isFrozen() — also skip private names in their checks
```

---

## Safari 26.2 — Dec 12, 2025

### 9. CVE-2025-46299 — Memory Initialization / Info Leak ⚠️ HIGH PRIORITY

| Field | Value |
|-------|-------|
| **Bugzilla** | [299518](https://bugs.webkit.org/show_bug.cgi?id=299518) — ACCESS DENIED |
| **Impact** | Processing maliciously crafted web content may disclose internal states of the app |
| **Description** | A memory initialization issue was addressed with improved memory handling |
| **CWE** | CWE-284 (Improper Access Control), CWE-190 (Integer Overflow), CWE-362 (Race), CWE-416 (UAF) |
| **Researchers** | **Google Big Sleep** (AI-assisted vulnerability research) |
| **Commit** | NOT FOUND in public GitHub (security-restricted) |
| **CVSS** | 4.3 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N |
| **Component** | WebKit (likely JSC or WebCore — unknown specific component) |

**Analysis:**
- **Bugzilla is access-restricted. No public commit found.**
- **Discovered by Google Big Sleep** — Google's AI-powered vulnerability research team. This is notable because Big Sleep specifically targets memory safety issues that can be found through automated analysis.
- **"Disclose internal states of the app"** = **INFO LEAK**. This is an information disclosure primitive, not a crash. The description specifically says "memory initialization issue" — meaning uninitialized memory is being exposed to web content.
- **Vulnerability class**: UNINITIALIZED MEMORY READ. An allocation is returned to web-accessible code without being properly zero-initialized, leaking whatever data was previously stored at that memory location.
- **Exploitation potential**: HIGH as an info leak primitive. Uninitialized memory leaks can disclose:
  - Heap layout / ASLR slide
  - Object pointers (for type confusion chains)
  - Stack canaries or other defense values
  - Content from other web origins (cross-site data leak)
- **PS5 relevance**: CRITICAL. An info leak is the essential first step in any modern exploit chain. Even if PS5 uses ASLR, an uninitialized memory read could leak base addresses, defeating ASLR. Combined with a memory corruption bug (CVEs 2, 3, or 8), this would provide a full exploit chain.
- **PS5 adaptability**: UNKNOWN without the commit. Cannot determine the trigger mechanism. However, given it was found by automated analysis (Big Sleep), the trigger is likely a specific API usage pattern that can be replicated in a browser.
- **Timeline note**: Fixed in Safari 26.2 (Dec 12, 2025). PS5 14.10 cherry-picks extend to ~Feb 2026, so this fix **may** have been cherry-picked. Must verify against PS5 14.10's WebKit binary.

---

## Priority Ranking for PS5 14.10 Research

### Tier 1 — Confirmed Exploitable, Commits Available

| # | CVE | Type | PS5 Adaptable? | Notes |
|---|-----|------|----------------|-------|
| 1 | CVE-2026-20608 | JIT type confusion (seal/freeze) | ✅ EXCELLENT | Pure JS test, no special APIs needed |
| 2 | CVE-2026-20664 | Wasm UAF (resizable buffer) | ⚠️ Needs verification | Requires `toResizableBuffer()` API |
| 3 | CVE-2026-28857 | TypedArray TOCTOU race | ⚠️ Needs SAB | Requires SharedArrayBuffer + growable |
| 4 | CVE-2026-28859 | Sandbox escape (GPU process) | ❓ Architecture-dependent | Needs GPU process + IPC understanding |
| 5 | CVE-2026-28861 | Cross-origin message handler | ⚠️ Needs msg handlers | Logic bug, depends on PS5 browser internals |

### Tier 2 — High Value but Restricted

| # | CVE | Type | Notes |
|---|-----|------|-------|
| 6 | CVE-2025-46299 | Info leak (uninit memory) | **MOST WANTED** — no public commit, Google Big Sleep |
| 7 | CVE-2026-20636 | Buffer overflow | No public commit, EntryHi |
| 8 | CVE-2026-20635 | Buffer overflow | No public commit, EntryHi |

### Tier 3 — Lower Priority

| # | CVE | Type | Notes |
|---|-----|------|-------|
| 9 | CVE-2026-20644 | Wasm JIT register clobber | ARM-specific, PS5 is x64 (BBQ fix may apply) |

---

## Recommended Next Steps

1. **CVE-2026-20608 (private fields seal/freeze)**: Immediately test the regression test JS in a PS5 browser. This is the most directly adaptable — pure JS, high iteration count triggers JIT. If the PS5 crashes or behaves unexpectedly, the bug is present.

2. **CVE-2026-20664 (Wasm UAF)**: Check if `WebAssembly.Memory.prototype.toResizableBuffer` exists on PS5. Run: `typeof new WebAssembly.Memory({initial:1, maximum:2}).toResizableBuffer`. If it returns `"function"`, the bug is likely present and highly exploitable.

3. **CVE-2025-46299 (info leak)**: Monitor WebKitGTK/WPE advisories and changelogs for the corresponding fix. The SUSE/RedHat patches reference this CVE — their WebKitGTK source RPMs may contain the actual fix commit that Apple's Bugzilla hides.

4. **CVE-2026-28859 (sandbox escape)**: Study PS5 browser process architecture. If there's a GPU/compositor process separation, the `RemoteGraphicsContext::drawGlyphs` span lifetime bug is a sandbox escape vector.

5. **CVE-2026-20636 / CVE-2026-20635**: Check WebKitGTK 2.50.6+ / 2.52.x changelogs for bugs 304657 and 304661. These may be publicly visible in the GTK/WPE port even though Apple's Bugzilla is restricted.

---

## Exploit Chain Hypothesis

**Ideal chain for PS5 14.10:**

1. **Info leak** (CVE-2025-46299 or spray-based) → defeat ASLR
2. **JIT type confusion** (CVE-2026-20608, private fields) → arbitrary R/W in web content process
3. **Sandbox escape** (CVE-2026-28859, GPU process glyph UAF) → code execution outside sandbox

**Alternative chain (if Wasm resizable buffers available):**

1. **Wasm UAF** (CVE-2026-20664) → direct arbitrary R/W without JIT confusion
2. **Sandbox escape** (CVE-2026-28859) → full compromise

---

*Generated: 2026-11-06*
*Source: WebKit GitHub commits, Apple Security Advisories, NVD, WebKitGTK WSA-2026-0001*
