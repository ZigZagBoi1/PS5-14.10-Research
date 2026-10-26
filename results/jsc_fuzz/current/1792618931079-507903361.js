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

//@ runDefault

// Regression test for a YarrJIT crash on patterns where a FixedCount multi-alt
// parenthesis has an alternative whose content ends with a ParentheticalAssertion.
//
// The FixedCount multi-alt mechanism stores a "content backtrack" return address
// per alternative. When the alternative that just matched completes, its return
// address is patched to the next sibling alternative's content-backtrack entry
// label, which is positioned immediately after the sibling's backtrack code.
// That position then happens to be the first instruction emitted for the
// assertion's inner disjunction backtrack (a dispatch via frame slot that holds
// the inner alt's resume address).
//
// When the assertion "succeeded" on the forward path via the assertion-success
// branch (an inverted lookahead whose inner disjunction failed), that frame
// slot was never written, so dispatching via it jumped to garbage. Fix is to
// emit an unconditional jump at ParentheticalAssertionEnd.bt so that any
// control flow reaching that position is redirected past the assertion via
// ParentheticalAssertionBegin.bt's End-jumps list.

function shouldBe(actual, expected) {
    if (JSON.stringify(actual) !== JSON.stringify(expected))
        throw new Error("bad value: actual=" + JSON.stringify(actual) + " expected=" + JSON.stringify(expected));
}

for (var i = 0; i < 1e4; ++i) {
    // Minimal reproducer: inverted lookahead with inner disjunction inside a
    // FixedCount multi-alt paren. Pre-fix, the JIT would SIGSEGV/SIGBUS here.
    shouldBe(/(^(?!(X|Y))c|Zc){2}/.exec("cccccc"), null);
    shouldBe(/(^(?!(X|Y))c|Zc){3}/.exec("cccccc"), null);
    shouldBe(/(^(?!(X|Y))c|(Z)c){3}/.exec("cccccc"), null);
    shouldBe(/(^(?!d(X|Y))c|(Z)c){3}/.exec("cccccc"), null);
    shouldBe(/(^(?!(XX|YY))c|Zc){2}/.exec("cccccc"), null);
    shouldBe(/(^(?!(?:X|Y))c|Zc){2}/.exec("cccccc"), null);

    // Valid matches must still succeed.
    shouldBe(/(^(?!(X|Y))c|Zc){2}/.exec("ZcZc"), ["ZcZc", "Zc", null]);
    shouldBe(/(^(?!(X|Y))c|Zc){2}/.exec("cZc"), ["cZc", "Zc", null]);

    // Original crashing test input.
    var r = new RegExp(unescape(
        "%28%5E%28%3F%21%64%28%28%3D%28%28%7E%58%28%3F%3C%E2%3E%28%3F%3C%66%3E" +
        "%29%28%28%28%28%2C%28%28%28%28%28%29%29%29%29%29%29%29%29%29%28%28%28" +
        "%28%28%28%28%28%28%3E%28%28%28%28%29%29%29%28%28%29%28%29%29%29%29%29" +
        "%29%29%29%29%29%29%29%29%29%29%29%7C%28%28%28%28%29%28%28%28%28%28%28" +
        "%28%28%3F%3C%E2%3E%28%28%4D%29%29%29%29%29%29%29%29%29%28%28%28%28%28" +
        "%28%29%29%29%29%29%29%28%28%28%28%3F%3C%66%3E%28%28%29%29%29%29%29%29" +
        "%29%28%29%29%28%29%28%28%28%28%28%28%28%28%28%28%28%28%3F%3C%66%35%32" +
        "%73%3E%28%28%28%29%29%29%28%29%28%28%28%28%29%29%29%29%29%28%28%29%28" +
        "%29%29%29%29%29%29%29%29%A9%29%29%29%29%29%29%29%29%29%63%7C%28%3E%29" +
        "%63%7C%28%3A%29%28%28%29%29%29%7B%33%7D%FF%FF%FF%FF%3C"), "dis");
    "aabbbccc".match(r);
    "aabbbccc".replace(r, "$1,$2");
    r.exec("caffeeeee");
    "cccccccc".match(r);
}

