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
// referenced capture is undefined or empty. The backtrack code for \N*?
// must detect that repeating zero-width matches cannot make progress and
// fail, rather than looping forever.
//
// These patterns must all terminate promptly. On buggy engines they hang
// because the non-greedy quantifier keeps retrying zero-width matches.

function shouldBe(actual, expected, description) {
    let actualStr = JSON.stringify(actual);
    let expectedStr = JSON.stringify(expected);
    if (actualStr !== expectedStr)
        throw new Error(description + ": expected " + expectedStr + ", got " + actualStr);
}

// ---- Backreference to capture in a different alternative (undefined) ----

// \1 refers to group 1 which is in alternative 1. When alternative 2 is
// tried, group 1 is undefined, so \1*? matches zero-width on every attempt.
shouldBe(/(a)|\1*?X/.exec("YYYYYY"), null,
    "backref to group in other alternative, no match");

shouldBe(/(a)|\1*?X/.exec("X"), ["X", undefined],
    "backref to group in other alternative, X matches");

shouldBe(/(a)|\1*?X/.exec("aYYYYY"), ["a", "a"],
    "backref to group in other alternative, alt 1 matches");

// ---- Backreference to empty capture ----

// Group 1 captures the empty string. \1*? repeatedly matches empty.
shouldBe(/()\1*?X/.exec("YYYYYY"), null,
    "backref to empty capture, no match");

shouldBe(/()\1*?X/.exec("X"), ["X", ""],
    "backref to empty capture, X matches");

// ---- Backreference to unmatched optional group ----

// (a)? may or may not capture. When it doesn't, \1 is undefined.
shouldBe(/(a)?\1*?X/.exec("YYYYYY"), null,
    "backref to unmatched optional group, no match");

shouldBe(/(a)?\1*?X/.exec("X"), ["X", undefined],
    "backref to unmatched optional group, X matches");

shouldBe(/(a)?\1*?X/.exec("aaX"), ["aaX", "a"],
    "backref to matched optional group, a then backref then X");

// ---- Named backreference to undefined capture in another alternative ----

shouldBe(/(?<t>A)|(?<t>\k<t>*?B)/.exec("BBBB"), ["B", undefined, "B"],
    "named backref to group in other alternative");

// ---- Multiple undefined backreferences with non-greedy quantifiers ----

shouldBe(/(a)(b)|\1*?\2*?X/.exec("YYYYYY"), null,
    "two undefined backrefs with non-greedy quantifiers");

shouldBe(/(a)(b)|\1*?\2*?X/.exec("X"), ["X", undefined, undefined],
    "two undefined backrefs, X matches");

// ---- Case-insensitive with undefined backref ----

shouldBe(/(a)|\1*?X/i.exec("yyyyyy"), null,
    "case-insensitive undefined backref, no match");

// ---- Non-greedy backref that does match (should still work correctly) ----

shouldBe(/^(.)\1*?(X)/.exec("======X"), ["======X", "=", "X"],
    "non-greedy backref to non-empty capture");

shouldBe(/^(.)\1*?(.+)/.exec("======="), ["=======", "=", "======"],
    "non-greedy backref greedy suffix");

// ---- The original crashing pattern from regexp-backreference-backtrack-interpreter.js ----

shouldBe(/A(B(\k<t>C)D(?<t>))EFGHIJKLM|(?<t>\k<t>*?B)B/.exec("aabbbccc"), null,
    "complex pattern with forward ref and non-greedy backref");

shouldBe(/A(B(\k<t>C)D(?<t>))EFGHIJKLM|(?<t>\k<t>*B)B/.exec("aabbbccc"), null,
    "complex pattern with greedy backref (should not hang)");

shouldBe(/A(B(\k<t>C)D(?<t>))EFGHIJKLM|(?<t>\k<t>*?B)B/.exec("aabbbccc"), null,
    "complex pattern with non-greedy variant");

