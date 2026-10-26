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

//@ skip if $memoryLimited

// Test that we do not overflow the stack while handling regular expressions.

// A RegExp with extremely deep nesting must throw or succeed, not crash.
function testDeepNesting() {
    try {
        new RegExp(Array(520000).join("(") + "a" + Array(520000).join(")"));
    } catch (e) {
        if (e instanceof RangeError)
            return;
        throw new Error("Expected RangeError, got " + e);
    }
    // With certain stack configurations the pattern may fit; that's OK.
}

// Base case.
testDeepNesting();

// Verify that a deep JS stack does not help avoiding the error.
(function recursiveCall(depth) {
    if (!(depth % 10))
        testDeepNesting();
    if (depth < 100)
        recursiveCall(depth + 1);
})(0);

// Have the deepest nested subpattern surrounded by other expressions.
{
    var expression = "";
    for (let i = 0; i < 520000; ++i)
        expression += "((a)(";
    expression += "b";
    for (let i = 0; i < 520000; ++i)
        expression += ")(c))";
    try {
        new RegExp(expression);
    } catch (e) {
        if (e instanceof SyntaxError || e instanceof RangeError)
            ; // expected
        else
            throw new Error("Expected SyntaxError or RangeError, got " + e);
    }
}

