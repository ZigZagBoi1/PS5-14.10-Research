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

function testScopeRestorationAfterExceptionInTry() {
  try {
    {
      let x = 1;
      var captureX = function() { print(x) };
      throw new Error("foo");
    }
  } catch {
    shouldBe(typeof x, "undefined");
  } finally {
    x
  }
}

function testScopeRestorationAfterExceptionInTry2() {
  try {
    for (let x of [1, 2, 3]) {
      var captureX = function() { print(x) };
      throw new Error("foo");
    }
  } catch {
    shouldBe(typeof x, "undefined");
  } finally {
    x
  }
}

function testScopeRestorationAfterExceptionInCatch() {
  try {
    throw new Error("foo");
  } catch (error) {
    {
      let x = 1;
      var captureX = function() { print(x) };
      throw new Error("foo");
    }
  } finally {
    shouldBe(typeof x, "undefined");
    x
  }
}

function testScopeRestorationAfterExceptionInCatch2() {
  try {
    throw new Error("foo");
  } catch {
    for (let x of [1, 2, 3]) {
      var captureX = function() { print(x) };
      throw new Error("foo");
    }
  } finally {
    shouldBe(typeof x, "undefined");
    x
  }
}

function shouldBe(actual, expected) {
  if (actual !== expected)
    throw new Error(`Bad value: ${actual}!`);
}

function shouldThrow(func, expectedMessage) {
  let errorThrown = false;
  try {
    func();
  } catch (error) {
    errorThrown = true;
    if (error.toString() !== expectedMessage)
      throw new Error(`Bad error: ${error}`);
  }
  if (!errorThrown)
    throw new Error(`Didn't throw!`);
}

for (var i = 0; i < 1e4; i++) {
  shouldThrow(testScopeRestorationAfterExceptionInTry, "ReferenceError: Can't find variable: x");
  shouldThrow(testScopeRestorationAfterExceptionInTry2, "ReferenceError: Can't find variable: x");
  shouldThrow(testScopeRestorationAfterExceptionInCatch, "ReferenceError: Can't find variable: x");
  shouldThrow(testScopeRestorationAfterExceptionInCatch2, "ReferenceError: Can't find variable: x");
}

