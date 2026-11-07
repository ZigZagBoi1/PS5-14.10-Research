# WebKit CVE Analysis — Safari 26.5 through Safari 27 (Remaining)

**Generated**: 2026-11-06
**Purpose**: Identify exploitable WebKit vulnerabilities for PS5 14.10 (WebKit ~Safari 26.x era)
**Focus**: INFO LEAK / arbitrary read primitives, DOM UAF, JSC type confusion — browser-testable without Wasm

---

## Summary Table

| # | CVE | Commit | Component | Rating | Wasm? | Browser Test? | Info Leak? |
|---|-----|--------|-----------|--------|-------|---------------|------------|
| 1 | CVE-2026-28905 | 392f508eef | JSC FTL OSR exit | 🔥 HIGH | No | ✅ Yes | **UNCONFIRMED — dense-map probe shape structurally negative; sparse-source re-arm required** |
| 2 | CVE-2026-64783 | be08720593 | WebCore DOM UAF | 🔥 HIGH | No | ⚠️ Needs user click | Possible (vptr read) |
| 3 | CVE-2026-64784 | 97df94ead0 | JSC bytecode metadata | ⬜ MEDIUM | No | ✅ Yes (slow) | Possible (OOB write) |
| 4 | CVE-2026-65341 | 28da9c5a83 | WebCore SVG SMIL | ⬜ MEDIUM | No | ✅ Yes | No (DoS/crash) |
| 5 | CVE-2026-43660 | f8ed382fb2 | WebCore CSP | ❌ SKIP | No | N/A | No |
| 6 | CVE-2026-28907 | 9a19d07c4f | WebCore CSP | ❌ SKIP | No | N/A | No |
| 7 | CVE-2026-28962 | c6cd4e07e9 | WebKit IPC/macOS | ❌ SKIP | No | N/A | No |
| 8 | CVE-2026-43658 | 9a16de46f2 | JSC Wasm BBQ | ❌ SKIP | Yes | N/A | N/A |
| 9 | CVE-2026-28947 | 76b3468621 | JSC Wasm Instance | ❌ SKIP | Yes | N/A | N/A |
| 10 | CVE-2026-28958 | 093f34607a | WebCore cookies | ❌ SKIP | No | N/A | No |
| 11 | CVE-2026-28971 | 4b574bf828 | WebKit UIProcess | ❌ SKIP | No | N/A | No |
| 12 | CVE-2026-43670 | 933debd495 | WebCore CSP/Worklet | ❌ SKIP | No | N/A | No |
| 13 | CVE-2026-43700 | 67b563b85f | WebCore WebGPU | ❌ SKIP | No | N/A | No |
| 14 | CVE-2026-43732 | 5be1236842 | WebKit IPC/Blob | ❌ SKIP | No | N/A | No |
| 15 | CVE-2026-43725 | ccf0c4874c | WebKit IPC/Network | ❌ SKIP | No | N/A | No |
| 16 | CVE-2026-43716 | a012babd4f | JSC Wasm Memory | ❌ SKIP | Yes | N/A | N/A |
| 17 | CVE-2026-43713 | 73645abad2 | WebCore Clipboard | ❌ SKIP | No | N/A | No |
| 18 | CVE-2026-43708 | 971435fdd3 | WebKit cookies/WS | ❌ SKIP | No | N/A | No |
| 19 | CVE-2026-43701 | f23ffb5a84 | WebKit UIProcess | ❌ SKIP | No | N/A | No |
| 20 | CVE-2026-64713 | 52cacff4c9 | WebCore timing | ❌ SKIP | No | N/A | No |
| 21 | CVE-2026-64730 | 1ab2bb4ff3 | WebCore fullscreen | ❌ SKIP | No | N/A | No |
| 22 | CVE-2026-64728 | c52bbb5187 | WebCore cookies | ❌ SKIP | No | N/A | No |
| 23 | CVE-2026-43804 | a37a650575 | WebCore popup | ❌ SKIP | No | N/A | No |
| 24 | CVE-2026-43821 | 74d0c628ff | WebKit sandbox | ❌ SKIP | No | N/A | No |
| 25 | CVE-2026-43795 | 79d7541f83 | WebCore WebAuthn | ❌ SKIP | No | N/A | No |
| 26 | CVE-2026-64780 | 9a17cd1100 | JSC Wasm OMG SIMD | ❌ SKIP | Yes | N/A | N/A |
| 27 | CVE-2026-43794 | d4a150e51b | WebGPU race | ❌ SKIP | No | N/A | No |
| 28 | CVE-2026-64753 | 71730beeaf | WebCore cache | ❌ SKIP | No | N/A | No |
| 29 | CVE-2026-86898 | ecb5a7bf75 | WebKit macOS | ❌ SKIP | No | N/A | No |
| 30 | CVE-2026-86872 | 9dcbd254af | JSC Wasm block types | ❌ SKIP | Yes | N/A | N/A |

---

## 🔥 HIGH PRIORITY — Detailed Analysis

---

### 🔥🔥🔥 CVE-2026-28905 — JSC FTL PhantomNewArrayWithButterfly Uninitialized Read
**Commit**: [392f508eef](https://github.com/WebKit/WebKit/commit/392f508eef)
**Component**: JSC FTL JIT — OSR exit materialization
**Files Changed**: `JSTests/stress/ftl-osr-exit-phantom-array-unwritten-slot.js`
**Priority**: 🔥🔥🔥 **HIGHEST — POTENTIAL INFO LEAK PRIMITIVE**

> **Evidence status (2026-11-06):** the browser probes `p665` and `p666` do
> not show an uninitialized read. Their “stale” values are ordinary
> `elem * 2` map results, and their dense-source shape cannot expose an
> unwritten slot: an OSR exit is a deoptimization continuation, not an
> exception, so `map` completes every callback. The same `p665` run's Phase D
> reports `ALL-OWN — no holes`, contradicting its Phase B `CVE LIVE` verdict.
> A sparse-source probe is the only proposed re-arm and has not been run.
> See `docs/WEBKIT_CVE_2026_28905_PROBE_VALIDITY_AUDIT_2026-11-06.md`.

#### Bug Description
When a `PhantomNewArrayWithButterfly` is materialized during FTL OSR exit, slots that were conditionally **not written** before the exit point should be treated as **holes** (the-hole value). Instead, `operationPopulateObjectInOSR` passed these unwritten slots directly to `putDirectIndex`, meaning **uninitialized butterfly memory** was exposed as array element values.

#### Vulnerable Behavior
```
Unwritten butterfly slots → passed to putDirectIndex as real values
```
This means stale heap data in the butterfly backing store is readable as JavaScript values.

#### Patched Behavior
```
Unwritten butterfly slots → treated as holes (skipped by putDirectIndex)
```

#### Why This Is Critical for INFO LEAK
- **Uninitialized butterfly memory** can contain JSC internal pointers (StructureID, JSCell*, butterfly pointers)
- Reading these as JavaScript numbers (via `Number()` or arithmetic) gives raw 64-bit pointer values
- This is EXACTLY the missing primitive for the PS5 exploitation chain
- Combined with the existing `addrof` primitive, leaked internal pointers break ASLR

#### Regression Test (BROWSER-COMPATIBLE!)
```javascript
function opt() {
    const arr = [0,0,0,0,0,0,0];
    function f() {
        arr[0];
        (0)[0];
        return arr;
    }
    const ret = arr.map(f)
    ret[0] = 1
}
for (let i = 0; i < 200; i++) {
    opt()
}
```

**No shell builtins!** No `noInline`, no `gc()`, no `$vm`, no `shouldBe`. This is pure JavaScript that triggers FTL compilation and OSR exit.

#### Exploitation Strategy
1. Allocate objects with known internal pointers (structures, cells)
2. Free them to leave pointer values in freed butterfly memory
3. Trigger the FTL-compiled function that materializes PhantomNewArrayWithButterfly during OSR exit
4. Read the "unwritten" slots which contain stale heap pointer values
5. Convert to numbers to extract raw pointer bits
6. Use leaked pointers to calculate JSC heap base, structure table, JIT code addresses

#### Adaptability for PS5
- Pure JavaScript, no Wasm needed ✅
- 200 iterations should be enough to trigger FTL on PS5's JSC ✅
- No special APIs needed ✅
- The difficult part: reliably controlling what data is in the uninitialized slots

---

### 🔥 CVE-2026-64783 — DataListButtonElement Use-After-Free
**Commit**: [be08720593](https://github.com/WebKit/WebKit/commit/be08720593)
**Component**: WebCore DOM — HTML form elements
**Files Changed**: `TextFieldInputType.cpp`, `DataListButtonElement.cpp`, `DataListButtonElement.h`
**Priority**: 🔥 HIGH — DOM UAF, browser-testable

#### Bug Description
`DataListButtonElement` stores its owner (`TextFieldInputType`) as a raw reference `DataListButtonOwner& m_owner`. When the input element's type is changed during a `click` event handler:

1. `HTMLInputElement::updateType()` calls `removeShadowSubtree()`
2. This nulls out `m_dataListDropdownIndicator` but does NOT clear the owner reference in `DataListButtonElement`
3. The `TextFieldInputType` is freed
4. `DataListButtonElement::defaultEventHandler()` is called, accessing `m_owner.dataListButtonElementWasClicked()` on freed memory

#### Vulnerable Behavior
```cpp
// DataListButtonElement.cpp — BEFORE fix
if (isAnyClick(*mouseEvent)) {
    m_owner.dataListButtonElementWasClicked(); // m_owner is a dangling reference!
    event.setDefaultHandled();
}
```

#### Patched Behavior
```cpp
// DataListButtonElement.cpp — AFTER fix
if (isAnyClick(*mouseEvent)) {
    if (RefPtr owner = m_owner) // m_owner is now WeakPtr
        owner->dataListButtonElementWasClicked();
    event.setDefaultHandled();
}
```

#### Regression Test
```html
<input id="input" type="text" list="list">
<datalist id="list"><option value="a"><option value="b"></datalist>
<script>
input.addEventListener('click', (e) => {
    input.type = 'button';
    gc();
}, { once: true });
// Then click the datalist dropdown button in shadow DOM
</script>
```

**Requires**: `internals.shadowRoot()` and `UIHelper.activateElement()` to programmatically click the shadow DOM button. However, the underlying bug is triggerable by real user interaction with the datalist dropdown indicator.

#### Info Leak Potential
The UAF dereferences a virtual method on freed memory. If the freed `TextFieldInputType` is reclaimed with controlled data (heap spray), this becomes:
- **Controlled vptr read** → code execution
- **Or**: Partial pointer leak if the freed memory is partially overwritten

#### Adaptability for PS5
- Requires `<datalist>` support — need to verify if PS5 WebKit supports it
- Requires user interaction (click on the datalist button)
- No Wasm needed ✅
- GC trigger needed — `gc()` is a shell builtin, but natural GC can substitute (allocate heavily after type change)

---

## ⬜ MEDIUM PRIORITY — Detailed Analysis

---

### ⬜ CVE-2026-64784 — UnlinkedMetadataTable::finalize() Overflow
**Commit**: [97df94ead0](https://github.com/WebKit/WebKit/commit/97df94ead0)
**Component**: JSC bytecode compiler — metadata table allocation
**Files Changed**: `UnlinkedMetadataTable.cpp`, `BytecodeGenerator.cpp`, `UnlinkedCodeBlockGenerator.cpp`

#### Bug Description
When a JavaScript function has an extremely large number of opcodes (with metadata), the 32-bit unsigned buffer offsets computed in `UnlinkedMetadataTable::finalize()` can **overflow**. This causes an undersized buffer to be allocated for the metadata table, leading to heap buffer overflow when the metadata is later populated.

#### Vulnerable Behavior
```cpp
// BEFORE: no overflow check
offset += numberOfEntries * metadataSize(static_cast<OpcodeID>(i));
// offset wraps around if total > UINT32_MAX
```

#### Patched Behavior
```cpp
// AFTER: CheckedArithmetic detects overflow → returns false → treated as OOM
checkedOffset += CheckedUint32(numberOfEntries) * metadataSize(static_cast<OpcodeID>(i));
```

#### Regression Test
```javascript
let n = 44739242;
let s = 'a();'.repeat(n);
let f = new Function('a', s);
try {
    f(function() { });
} catch (e) {
    // Expected RangeError
}
```

**Practical concern**: Requires generating a string of ~180MB of JavaScript source code. The test is marked `slow!` and requires `addressBits > 32` and `!memoryLimited`. PS5 has 64-bit addressing but limited memory in WebKit context.

#### Info Leak / Write Potential
- Heap OOB write via undersized metadata table
- Could corrupt adjacent heap objects
- More useful for write primitive than read primitive

---

### ⬜ CVE-2026-65341 — SVG SMIL Animation Repeat Count Overflow
**Commit**: [28da9c5a83](https://github.com/WebKit/WebKit/commit/28da9c5a83)
**Component**: WebCore SVG — SMIL animation
**Files Changed**: `SVGSMILElement.cpp`

#### Bug Description
When seeking SVG animation to a large time value with a tiny `dur` and `repeatCount="indefinite"`, the computed repeat count overflows the `unsigned` type via `static_cast<unsigned>()`. This also triggered dispatching millions of repeat events (one per skipped interval), causing DoS.

#### Regression Test
```html
<svg id="svg">
    <rect width="100" height="100" fill="green">
        <animate attributeName="x" from="0" to="10" dur="0.0001s" repeatCount="indefinite"/>
    </rect>
</svg>
<script>
    svg.setCurrentTime(400000);
</script>
```

**Browser-compatible**, no shell builtins. But this is primarily a DoS/crash bug with limited memory corruption potential. The overflow is in a `static_cast<unsigned>` of a float division result, which mostly causes a bad repeat count value rather than a heap overflow.

---

## ❌ SKIP — Brief Summaries

| CVE | Commit | Why Skip |
|-----|--------|----------|
| CVE-2026-43660 | f8ed382fb2 | CSP policy loss on blob: URLs. Policy bug, no memory safety impact. |
| CVE-2026-28907 | 9a19d07c4f | CSP path traversal via %2F..%2F. Policy bypass, no memory corruption. |
| CVE-2026-28962 | c6cd4e07e9 | Attachment file path validation. macOS IPC, requires compromised WebContent process. |
| CVE-2026-43658 | 9a16de46f2 | Wasm BBQCallee lifetime bug. **Requires WebAssembly.** |
| CVE-2026-28947 | 76b3468621 | Wasm InstanceAnchor destructor ordering. **Requires WebAssembly.** |
| CVE-2026-28958 | 093f34607a | SameSite=Strict cookie leak via FrameLoader. Cookie policy, no memory safety. |
| CVE-2026-28971 | 4b574bf828 | Safe browsing bypass for downloads. macOS UI process only. |
| CVE-2026-43670 | 933debd495 | CSP not propagated to WorkletGlobalScope (AudioWorklet/PaintWorklet). Policy bug. |
| CVE-2026-43700 | 67b563b85f | WebGPU importExternalTexture cross-origin bypass. WebGPU not on PS5. |
| CVE-2026-43732 | 5be1236842 | Blob file path validation in IDB. IPC sandbox escape, requires compromised renderer. |
| CVE-2026-43725 | ccf0c4874c | LoadImageForDecoding accepts file:// URLs. IPC, requires compromised renderer. |
| CVE-2026-43716 | a012babd4f | Wasm Memory ArrayBuffer GC lifetime. **Requires WebAssembly.** |
| CVE-2026-43713 | 73645abad2 | Clipboard read/write via cross-origin iframe postMessage. Clipboard policy only. |
| CVE-2026-43708 | 971435fdd3 | WebSocket cookie partitioning bug (Cocoa-only). Cookie policy. |
| CVE-2026-43701 | f23ffb5a84 | data: URL navigation→download writes bytes to disk. UIProcess IPC. |
| CVE-2026-64713 | 52cacff4c9 | LCP renderTime coarsened to 4ms. Privacy/timing side channel mitigation. |
| CVE-2026-64730 | 1ab2bb4ff3 | Fullscreen keyboard lock reverted to unstable. Feature flag change. |
| CVE-2026-64728 | c52bbb5187 | SameSite cookie bypass via srcdoc iframe. Cookie policy bug. |
| CVE-2026-43804 | a37a650575 | Popunder bypass via transient activation. UI policy, no memory safety. |
| CVE-2026-43821 | 74d0c628ff | Network process temp dir file read (iOS only). Sandbox policy. |
| CVE-2026-43795 | 79d7541f83 | WebAuthn CBOR iterator dereference. Requires WebAuthn hardware, iterator UB. |
| CVE-2026-64780 | 9a17cd1100 | Wasm OMG SIMD inlining bug. **Requires WebAssembly + SIMD.** |
| CVE-2026-43794 | d4a150e51b | WebGPU race condition UAF. GPU process, race window. |
| CVE-2026-64753 | 71730beeaf | Cache partition refactor (m_cachePartition → firstPartyForCookies). Hardening. |
| CVE-2026-86898 | ecb5a7bf75 | Quarantine bypass with # in filename. macOS only. |
| CVE-2026-86872 | 9dcbd254af | Wasm block type widening bug. **Requires WebAssembly + GC types.** |

---

## Exploitation Chain Recommendations

### For INFO LEAK (Missing Primitive)

**Primary candidate: CVE-2026-28905 (PhantomNewArrayWithButterfly)**

This is the strongest candidate for an info leak:
1. Pure JavaScript — no Wasm, no shell builtins
2. Exposes uninitialized butterfly memory as array values
3. Stale heap data can contain JSC internal pointers
4. 200 iterations is enough for FTL compilation
5. The PoC is already browser-compatible

**Exploitation approach**:
```
1. Allocate many JSObjects with interesting internal pointers
2. Free some of them to create holes in butterfly memory
3. Trigger opt() to compile in FTL
4. Read returned array values — some will be stale heap data
5. Convert to float64 and extract bits for raw pointer values
```

### Combined with Existing Primitives

If combined with the already-analyzed CVE-2026-112673 (GetByStatus type confusion) for the write primitive:

```
INFO LEAK (CVE-2026-28905) → leak StructureID, heap base, JIT page addresses
    ↓
TYPE CONFUSION (CVE-2026-112673) → fake object / arbitrary R/W
    ↓
JIT CODE WRITE → shellcode in RWX JIT page
    ↓
CODE EXECUTION
```

### Alternative INFO LEAK: CVE-2026-64783 (DataListButtonElement UAF)

If the PhantomNewArrayWithButterfly approach doesn't work reliably:
- The DataListButtonElement UAF provides a vptr read on freed memory
- Requires user interaction (click) and `<datalist>` support
- More complex to exploit but gives a direct object pointer leak
