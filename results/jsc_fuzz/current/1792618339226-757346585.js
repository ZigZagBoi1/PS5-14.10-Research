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

function getMappedArguments(a, b) { return arguments; }
function getUnmappedArguments(a, b) { "use strict"; return arguments; }

function shouldBeArray(actual, expected) {
    var isEqual =
        actual.length === expected.length &&
        actual.every((item, index) => item === expected[index]);
    if (!isEqual)
        throw new Error(`Expected [${actual.map(String)}] to equal [${expected.map(String)}]`);
}

function forIn(object) {
    var keys = [];
    for (var key in object)
        keys.push(key);
    return keys;
}

noInline(getMappedArguments);
noInline(getUnmappedArguments);
noInline(forIn);

(function() {
    for (var i = 0; i < 1e4; ++i) {
        var mappedArguments = getMappedArguments(0, 1, 2);
        shouldBeArray(forIn(mappedArguments), ["0", "1", "2"]);
        shouldBeArray(Object.keys(mappedArguments), ["0", "1", "2"]);
        shouldBeArray(Reflect.ownKeys(mappedArguments), ["0", "1", "2", "length", "callee", Symbol.iterator]);

        var unmappedArguments = getUnmappedArguments(0);
        shouldBeArray(forIn(unmappedArguments), ["0"]);
        shouldBeArray(Object.keys(unmappedArguments), ["0"]);
        shouldBeArray(Reflect.ownKeys(unmappedArguments), ["0", "length", "callee", Symbol.iterator]);
    }
})();

(function() {
    for (var i = 0; i < 1e4; ++i) {
        var mappedArguments = getMappedArguments(0, 1);
        mappedArguments[8] = 8;
        mappedArguments[2] = 2;
        shouldBeArray(forIn(mappedArguments), ["0", "1", "2", "8"]);
        shouldBeArray(Object.keys(mappedArguments), ["0", "1", "2", "8"]);
        shouldBeArray(Reflect.ownKeys(mappedArguments), ["0", "1", "2", "8", "length", "callee", Symbol.iterator]);

        var unmappedArguments = getUnmappedArguments();
        unmappedArguments[12] = 12;
        unmappedArguments[3] = 3;
        shouldBeArray(forIn(unmappedArguments), ["3", "12"]);
        shouldBeArray(Object.keys(unmappedArguments), ["3", "12"]);
        shouldBeArray(Reflect.ownKeys(unmappedArguments), ["3", "12", "length", "callee", Symbol.iterator]);
    }
})();

(function() {
    for (var i = 0; i < 1e4; ++i) {
        var mappedArguments = getMappedArguments(0);
        mappedArguments.foo = 1;
        mappedArguments.bar = 2;
        shouldBeArray(forIn(mappedArguments), ["0", "foo", "bar"]);
        shouldBeArray(Object.keys(mappedArguments), ["0", "foo", "bar"]);
        // FIXME: Symbol.iterator should come after "foo" and "bar" 
        // shouldBeArray(Reflect.ownKeys(mappedArguments), ["0", "length", "callee", "foo", "bar", Symbol.iterator]);

        var unmappedArguments = getUnmappedArguments(0, 1, 2);
        unmappedArguments.foo = 1;
        unmappedArguments.bar = 2;
        shouldBeArray(forIn(unmappedArguments), ["0", "1", "2", "foo", "bar"]);
        shouldBeArray(Object.keys(unmappedArguments), ["0", "1", "2", "foo", "bar"]);
        // FIXME: "callee" should come before "foo" and "bar"
        // shouldBeArray(Reflect.ownKeys(unmappedArguments), ["0", "1", "2", "length", "callee", "foo", "bar", Symbol.iterator]);
    }
})();

// FIXME: Add more tests, covering:
// * added symbol properties;
// * added together index, non-index, and symbol properties;
// * deleted, re-added, and redefined as DontEnum index properties, both within and beyond "length";
// * deleted, re-added, and redefined as DontEnum "length", "callee", and Symbol.iterator properties.

