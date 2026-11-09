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

// Regression test for https://bugs.webkit.org/show_bug.cgi?id=316132
//
// Resolving an async generator request reads `.then` on the iterator result object. A user-defined
// `then` getter on Object.prototype can reentrantly call `iter.next()` while the generator is
// suspended at a yield. The old driver resumed the generator nested inside that resolve and could
// leave it awaiting, then resumed it again from the outer drain — asserting/crashing.
//
// After aligning the driver to the current spec (AsyncGeneratorDrainQueue / AsyncGeneratorResume /
// AsyncGeneratorCompleteStep with a draining-queue state), the resolve in AsyncGeneratorYield runs
// while the generator is in an execution state, so the reentrant next() only enqueues; the request
// is then resumed inline. The observed order matches SpiderMonkey (the spec sequences CompleteStep,
// which fulfils the first next()'s promise, before the inline resume re-suspends on the awaited
// return value). It intentionally differs from V8's order; engines do not agree here.

function shouldBe(actual, expected) {
    if (actual !== expected)
        throw new Error(`bad value: expected ${expected} but got ${actual}`);
}

let log = [];
let iter;
let thenGets = 0;

Object.defineProperty(Object.prototype, "then", {
    get() {
        log.push("then:" + thenGets);
        if (thenGets++ === 0)
            iter.next();
        return undefined;
    },
    configurable: true,
});

async function* gen() {
    log.push("start");
    yield 1;
    log.push("resume");
    return 2;
}

let error = null;
let resolvedWith = null;

(async function main() {
    iter = gen();
    await iter.next();
    log.push("await-first");
    await 0;
    await 0;
    return 10;
})().then(result => { resolvedWith = result; }, e => { error = e; });

drainMicrotasks();

if (error)
    throw error;
shouldBe(log.join("|"), "start|then:0|resume|await-first|then:1");
shouldBe(resolvedWith, 10);

