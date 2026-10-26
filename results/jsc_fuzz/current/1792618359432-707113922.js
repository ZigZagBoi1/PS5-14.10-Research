var window = this;
var __ok = 0, __fail = 0, __failNames = [];
function __is(a, b) { return (a === b) || (a !== a && b !== b); }
function __eq(a, b) {
  if (__is(a, b)) return true;
  if (typeof a === 'bigint' && typeof b === 'bigint') return a === b;
  try { return JSON.stringify(a) === JSON.stringify(b); } catch (e) { return false; }
}
function shouldBe(a, b, msg) { if (__eq(a, b)) { __ok++; } else { __fail++; if (__failNames.length < 5) __failNames.push(String(msg || '') + ' got=' + String(a) + ' want=' + String(b)); } }
function shouldNotBe(a, b, msg) { if (!__eq(a, b)) { __ok++; } else { __fail++; } }
function shouldBeTrue(a, msg) { shouldBe(a, true, msg); }
function shouldBeFalse(a, msg) { shouldBe(a, false, msg); }
function shouldBeUndefined(a, msg) { shouldBe(a, undefined, msg); }
function shouldBeNull(a, msg) { shouldBe(a, null, msg); }
function shouldBeEqualToString(a, b, msg) { shouldBe(a, b, msg); }
function shouldBeGreaterThan(a, b) { if (a > b) { __ok++; } else { __fail++; } }
function shouldBeGreaterThanOrEqual(a, b) { if (a >= b) { __ok++; } else { __fail++; } }
function shouldBeLessThan(a, b) { if (a < b) { __ok++; } else { __fail++; } }
function shouldBeLessThanOrEqual(a, b) { if (a <= b) { __ok++; } else { __fail++; } }
function shouldThrow(fn) { try { fn(); __fail++; } catch (e) { __ok++; } }
function shouldNotThrow(fn) { try { fn(); __ok++; } catch (e) { __fail++; } }
function shouldThrowError(fn) { shouldThrow(fn); }
function shouldNotThrowError(fn) { shouldNotThrow(fn); }
function testPassed() { __ok++; }
function testFailed(m) { __fail++; if (__failNames.length < 5) __failNames.push(String(m)); }
function describe() {}
function debug() {}
function print() {}
function noInline(f) { return f; }
var noDFG = noInline, noFTL = noInline, noOSRExitFuzz = noInline, noTailCalls = noInline;
var noEagerCompilation = noInline, noExceptions = noInline, noStructureCheck = noInline;
function evaluate(s) { try { return (0, eval)(s); } catch (e) { return undefined; } }
function markAndSweep() {}
function gc() { if (window.GCController) GCController.collectAll(); }
function drainMicrotasks() {}
function createGlobalObject() { return {}; }
function quit(status) { throw new Error('QUIT:' + status); }
window.onerror = function () { return true; };
var testLoopCount = 200;

// Tests that the ArrayConcatIntrinsic's fast path bails correctly for inputs that would
// require ArrayStorage: the DFG operation returns empty, the JIT speculation-checks against
// that and OSR-exits with ExoticObjectMode. After enough exits, subsequent compilations of
// the same call site see the exit profile and decline the intrinsic, so execution proceeds
// through the host function (which correctly handles large-size concat).

function assert(cond, msg) {
    if (!cond)
        throw new Error("Bad: " + (msg || ""));
}
noInline(assert);

function makeInt32(n) {
    const a = [];
    for (let i = 0; i < n; i++)
        a.push(i | 0);
    return a;
}
noInline(makeInt32);

function doConcat(a, b) { return a.concat(b); }
noInline(doConcat);

for (let i = 0; i < testLoopCount; i++)
    doConcat(makeInt32(2), makeInt32(2));

{
    const a = makeInt32(60000);
    const b = makeInt32(30000);
    const r = doConcat(a, b);
    assert(r.length === 90000, "under-threshold length " + r.length);
    assert(r[0] === 0 && r[59999] === 59999 && r[60000] === 0 && r[89999] === 29999,
           "under-threshold contents");
}

{
    const a = makeInt32(60000);
    const b = makeInt32(60000);
    for (let i = 0; i < 200; i++) {
        const r = doConcat(a, b);
        assert(r.length === 120000, "oversized length " + r.length);
        assert(r[0] === 0 && r[59999] === 59999 && r[60000] === 0 && r[119999] === 59999,
               "oversized contents");
    }
}

for (let i = 0; i < testLoopCount; i++) {
    const r = doConcat(makeInt32(2), makeInt32(3));
    assert(r.length === 5, "post-threshold small length " + r.length);
}

