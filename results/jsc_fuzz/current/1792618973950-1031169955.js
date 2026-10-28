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

// Regression test for non-greedy backreference infinite loop when the
// capture is non-zero-width but there is not enough remaining input to
// match another repetition.
//
// In the JIT, the NonGreedy reentry code stored beginIndex AFTER
// checkNotEnoughInput. When checkNotEnoughInput failed (not enough
// input), beginIndex kept its stale value from a previous successful
// iteration. The backtrack code's zero-width progress check then saw
// index != beginIndex (stale) and allowed retry, looping forever.
//
// These patterns must all terminate promptly.

function shouldBe(actual, expected, description) {
    let actualStr = JSON.stringify(actual);
    let expectedStr = JSON.stringify(expected);
    if (actualStr !== expectedStr)
        throw new Error(description + ": expected " + expectedStr + ", got " + actualStr);
}

// ---- Core bug pattern: one successful match then insufficient input ----

// \1*? matches "ab" once (index 2→4), then can't match again (need 2
// chars but only 1 left). Without the fix the JIT loops forever here.
shouldBe(/(ab)\1*?X/.exec("ababY"), null,
    "one match then insufficient input, no X");

shouldBe(/(ab)\1*?X/.exec("abab"), null,
    "one match then insufficient input, string ends");

// ---- Longer capture ----

shouldBe(/(abc)\1*?X/.exec("abcabcY"), null,
    "longer capture, one match then insufficient input");

shouldBe(/(abcde)\1*?X/.exec("abcdeabcdeYY"), null,
    "5-char capture, one match then insufficient input");

// ---- Multiple successful matches before running out ----

shouldBe(/(ab)\1*?X/.exec("ababababY"), null,
    "three matches possible, then insufficient input");

// ---- Finite max count (should still terminate) ----

shouldBe(/(ab)\1{0,100}?X/.exec("ababY"), null,
    "finite max count, one match then insufficient input");

// ---- Case-insensitive ----

shouldBe(/(ab)\1*?X/i.exec("ababY"), null,
    "case-insensitive, one match then insufficient input");

shouldBe(/(AB)\1*?x/i.exec("ABABZ"), null,
    "case-insensitive upper, one match then insufficient input");

// ---- Named backreference ----

shouldBe(/(?<cap>ab)\k<cap>*?X/.exec("ababY"), null,
    "named backref, one match then insufficient input");

// ---- Correct matches still work ----

shouldBe(/(ab)\1*?X/.exec("ababX"), ["ababX", "ab"],
    "correct: one backref match then X");

shouldBe(/(ab)\1*?X/.exec("abX"), ["abX", "ab"],
    "correct: zero backref matches then X");

shouldBe(/(ab)\1*?X/.exec("abababX"), ["abababX", "ab"],
    "correct: two backref matches then X");

// ---- Zero-width captures still handled (original fix) ----

shouldBe(/()\1*?X/.exec("Y"), null,
    "empty capture, no match");

shouldBe(/(a)|\1*?X/.exec("Y"), null,
    "undefined capture in other alternative, no match");

