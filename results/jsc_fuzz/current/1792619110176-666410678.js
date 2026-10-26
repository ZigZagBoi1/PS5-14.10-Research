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

function shouldBe(actual, expected) {
    if (actual !== expected)
        throw new Error('bad value: ' + actual + ' expected: ' + expected);
}

function shouldThrow(func, errorMessage) {
    var errorThrown = false;
    var error = null;
    try {
        func();
    } catch (e) {
        errorThrown = true;
        error = e;
    }
    if (!errorThrown)
        throw new Error('not thrown');
    if (String(error) !== errorMessage)
        throw new Error(`bad error: ${String(error)}`);
}

// Direct next() calls on ASCII strings, including the done step.
function sumCodePoints(string) {
    var result = 0;
    var iterator = string[Symbol.iterator]();
    var step;
    while (!(step = iterator.next()).done)
        result += step.value.codePointAt(0);
    return result;
}
noInline(sumCodePoints);

// Iterator result object shape and values, including after exhaustion.
function stepShapes(string) {
    var iterator = string[Symbol.iterator]();
    var steps = [];
    for (var i = 0; i < 4; ++i) {
        var step = iterator.next();
        steps.push(step.value, step.done, Object.keys(step).join(','));
    }
    return steps;
}
noInline(stepShapes);

// Surrogate pairs through direct next() calls.
function collect(string) {
    var iterator = string[Symbol.iterator]();
    var result = [];
    var step;
    while (!(step = iterator.next()).done)
        result.push(step.value);
    return result.join('|');
}
noInline(collect);

for (var i = 0; i < 1e4; ++i) {
    shouldBe(sumCodePoints("abc"), 0x61 + 0x62 + 0x63);
    shouldBe(sumCodePoints(""), 0);
    shouldBe(sumCodePoints("a\u{1F600}b"), 0x61 + 0x1F600 + 0x62);

    var steps = stepShapes("ab");
    shouldBe(steps[0], "a");
    shouldBe(steps[1], false);
    shouldBe(steps[2], "value,done");
    shouldBe(steps[3], "b");
    shouldBe(steps[4], false);
    shouldBe(steps[6], undefined);
    shouldBe(steps[7], true);
    shouldBe(steps[8], "value,done");
    shouldBe(steps[9], undefined);
    shouldBe(steps[10], true);

    shouldBe(collect("x😀y"), "x|😀|y");
    // Lone surrogates are returned as-is.
    shouldBe(collect("x\uD83Dy"), "x|\uD83D|y");
    shouldBe(collect("\uDE00"), "\uDE00");
    // Surrogate pair at the end of the string.
    shouldBe(collect("z😀"), "z|😀");
    // Lone lead surrogate at the end of the string.
    shouldBe(collect("z\uD83D"), "z|\uD83D");
}

// Rope strings.
function makeRope(a, b) {
    return a + b;
}
noInline(makeRope);
for (var i = 0; i < 1e4; ++i)
    shouldBe(sumCodePoints(makeRope("abc".repeat(10), "d\u{1F600}")), (0x61 + 0x62 + 0x63) * 10 + 0x64 + 0x1F600);

// 16-bit strings without surrogate pairs.
for (var i = 0; i < 1e4; ++i)
    shouldBe(collect("あい"), "あ|い");

// next() with a bad |this| throws a TypeError.
var stringIteratorNext = ""[Symbol.iterator]().next;
function callNextWithBadThis(receiver) {
    return stringIteratorNext.call(receiver);
}
noInline(callNextWithBadThis);
for (var i = 0; i < 1e4; ++i) {
    shouldThrow(() => callNextWithBadThis({}), 'TypeError: %StringIteratorPrototype%.next requires that |this| be a String Iterator instance');
    shouldThrow(() => callNextWithBadThis(undefined), 'TypeError: %StringIteratorPrototype%.next requires that |this| be a String Iterator instance');
    shouldThrow(() => callNextWithBadThis([1][Symbol.iterator]()), 'TypeError: %StringIteratorPrototype%.next requires that |this| be a String Iterator instance');
}

// Mixing for-of (fast iteration) and direct next() calls on the same kind of iterator.
function mixed(string) {
    var result = 0;
    for (var character of string)
        result += character.codePointAt(0);
    var iterator = string[Symbol.iterator]();
    var step;
    while (!(step = iterator.next()).done)
        result += step.value.codePointAt(0);
    return result;
}
noInline(mixed);
for (var i = 0; i < 1e4; ++i)
    shouldBe(mixed("a\u{1F600}b"), 2 * (0x61 + 0x1F600 + 0x62));

