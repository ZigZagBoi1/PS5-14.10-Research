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

var regExp = /^\/(?:event\/([^/]+)(?:$()|\/comments$())|map\/([^/]+)\/events$()|static(?:|\/.*)$()|user\/lookup\/(?:email\/([^/]+)$()|username\/([^/]+)$()))/;

function indexOfEmpty(array) {
    return array.indexOf('', 1);
}
noInline(indexOfEmpty);

function indexOfValue(array, value) {
    return array.indexOf(value);
}
noInline(indexOfValue);

function indexOfUndefined(array) {
    return array.indexOf(undefined, 1);
}
noInline(indexOfUndefined);

function indexOfNegativeFrom(array, value) {
    return array.indexOf(value, -3);
}
noInline(indexOfNegativeFrom);

function includesEmpty(array) {
    return array.includes('');
}
noInline(includesEmpty);

function includesValue(array, value) {
    return array.includes(value);
}
noInline(includesValue);

for (var i = 0; i < 1e5; ++i) {
    var match = '/user/lookup/username/hey'.match(regExp);
    shouldBe(indexOfEmpty(match), 10);
    shouldBe(indexOfValue(match, 'hey'), 9);
    shouldBe(indexOfValue(match, 'nonexistent'), -1);
    shouldBe(indexOfUndefined(match), 1);
    shouldBe(indexOfNegativeFrom(match, ''), 10);
    shouldBe(includesEmpty(match), true);
    shouldBe(includesValue(match, 'hey'), true);
    shouldBe(includesValue(match, 'nonexistent'), false);

    var match2 = regExp.exec('/event/42/comments');
    shouldBe(indexOfEmpty(match2), 3);
    shouldBe(indexOfValue(match2, '42'), 1);
    shouldBe(includesValue(match2, '42'), true);
}

var namedRegExp = /(?<year>\d{4})-(?<month>\d{2})(?:-(?<day>\d{2}))?/;
function indexOfOnNamed(array, value) {
    return array.indexOf(value);
}
noInline(indexOfOnNamed);

for (var i = 0; i < 1e5; ++i) {
    var match = '2026-07'.match(namedRegExp);
    shouldBe(indexOfOnNamed(match, '07'), 2);
    shouldBe(indexOfOnNamed(match, undefined), 3);
    shouldBe(indexOfOnNamed(match, '2026-07'), 0);
}

