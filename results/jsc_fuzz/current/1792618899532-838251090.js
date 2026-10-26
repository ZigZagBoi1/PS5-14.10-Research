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

// Verifies that the Boyer-Moore fast-skip tables built for counted quantifiers
// ({n} on character classes and pattern characters) never skip over a real match.
// Each pattern is slid across every alignment 0..maxPad so that every residue of
// the skip stride is exercised, including expansions truncated at the BM table
// length cap (32) and 16-bit subject strings.

function shouldBe(actual, expected, context)
{
    if (actual !== expected)
        throw new Error("bad value: " + actual + ", expected: " + expected + " (" + context + ")");
}

function slide(re, matchStr, pad, maxPad)
{
    for (var p = 0; p <= maxPad; ++p) {
        var string = pad.repeat(p) + matchStr + pad.repeat(5);
        for (var k = 0; k < 50; ++k) {
            var m = re.exec(string);
            shouldBe(m !== null, true, re + " pad=" + p);
            shouldBe(m.index, p * pad.length, re + " pad=" + p);
            shouldBe(m[0], matchStr, re + " pad=" + p);
        }
    }
}

function never(re, string)
{
    for (var k = 0; k < 50; ++k)
        shouldBe(re.exec(string), null, re + " on " + string);
}

// Basic counted character classes, all alignments.
slide(/\d{3}/, "123", "x", 40);
slide(/\d{3}-\d{2}-\d{4}/, "078-05-1120", "x", 40);
slide(/\b\d{3}-\d{2}-\d{4}\b/, "078-05-1120", " ", 40);

// Counted pattern characters.
slide(/a{3}b/, "aaab", "x", 40);
slide(/a{30}b/, "a".repeat(30) + "b", "x", 40);

// Expansion truncated at the BM table length cap (32): minimum size crosses the cap.
slide(/\d{31}x/, "7".repeat(31) + "x", "q", 40);
slide(/\d{32}y/, "7".repeat(32) + "y", "q", 40);
slide(/\d{33}z/, "7".repeat(33) + "z", "q", 40);
slide(/z{40}!/, "z".repeat(40) + "!", "q", 40);

// Cursor starts mid-table, then the counted term crosses the cap.
slide(/ab\d{31}c/, "ab" + "5".repeat(31) + "c", "x", 40);

// Case-insensitive counted pattern character: both cases must be in the table.
slide(/a{4}b/i, "aAaAb", "x", 40);
slide(/a{4}b/i, "AAAAB", "x", 40);

// Inverted class and dot (setAll path) with counted quantifiers.
slide(/[^0-9]{3}=/, "abc=", "5", 40);
slide(/.{4}#/, "abcd#", "\n", 20);
slide(/.{4}#/s, "abcd#", "\n", 20);

// 16-bit subject strings.
slide(/\d{3}-\d{2}/, "123-45", "あ", 20);
slide(/[あ-ん]{3}!/, "あいう!", "z", 20);

// Counted quantifiers inside alternatives of a group: both alternative lengths.
slide(/(\d{3}|ab)z/, "123z", "x", 20);
slide(/(\d{3}|ab)z/, "abz", "x", 20);

// Counted group containing a counted class (group-level {3} still bails; must stay correct).
slide(/(?:\d{2}){3}x/, "123456x", "q", 20);

// {m,n} splits into fixed prefix + greedy remainder.
slide(/w\d{2,4}z/, "w12z", "x", 20);
slide(/w\d{2,4}z/, "w1234z", "x", 20);

// Unicode flag (BM collection disabled; sanity-check identical results).
slide(/\d{3}-\d{2}-\d{4}/u, "078-05-1120", "x", 20);

// Global matching from a nonzero lastIndex.
var globalRe = /\d{3}-\d{2}/g;
for (var k = 0; k < 50; ++k) {
    globalRe.lastIndex = 0;
    var m1 = globalRe.exec("xx 123-45 yy 678-90 zz");
    shouldBe(m1.index, 3, "global first");
    shouldBe(m1[0], "123-45", "global first");
    var m2 = globalRe.exec("xx 123-45 yy 678-90 zz");
    shouldBe(m2.index, 13, "global second");
    shouldBe(m2[0], "678-90", "global second");
    shouldBe(globalRe.exec("xx 123-45 yy 678-90 zz"), null, "global third");
}

// Near-misses: partial shapes that the skip loop flies over must stay non-matches.
never(/\d{3}-\d{2}-\d{4}/, "x".repeat(20) + "12-345-6789 12a-45-6789 123-4-51120" + "x".repeat(20));
never(/w\d{2,4}z/, "x".repeat(30) + "w1z w12345z" + "x".repeat(30));
never(/\d{31}x/, "q".repeat(10) + "7".repeat(30) + "x" + "q".repeat(10));
never(/a{4}b/i, "x".repeat(20) + "aAaB AaAB" + "x".repeat(20));

// Long scan with digit runs shorter than the counted quantifier: skip loop runs many strides.
never(/\d{3}-\d{2}-\d{4}/, "ab1cd23ef-45gh".repeat(100));

