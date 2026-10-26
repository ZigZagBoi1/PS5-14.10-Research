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

function test() {
    var obj = {};
    Object.defineProperty(obj, "__esModule", { value: true });
    if (obj.__esModule !== true)
        throw new Error("Expected __esModule to be true");

    var desc = Object.getOwnPropertyDescriptor(obj, "__esModule");
    if (desc.writable !== false)
        throw new Error("Expected writable to be false");
    if (desc.enumerable !== false)
        throw new Error("Expected enumerable to be false");
    if (desc.configurable !== false)
        throw new Error("Expected configurable to be false");
    if (desc.value !== true)
        throw new Error("Expected value to be true");

    return obj;
}

for (var i = 0; i < 1e5; i++)
    test();

// Test with different descriptor types
function testWritable() {
    var obj = {};
    Object.defineProperty(obj, "x", { value: 42, writable: true, enumerable: true, configurable: true });
    if (obj.x !== 42)
        throw new Error("Expected x to be 42");
    obj.x = 100;
    if (obj.x !== 100)
        throw new Error("Expected x to be 100 after assignment");
    return obj;
}

for (var i = 0; i < 1e5; i++)
    testWritable();

// Test accessor descriptor
function testAccessor() {
    var obj = {};
    var val = 0;
    Object.defineProperty(obj, "y", {
        get: function() { return val; },
        set: function(v) { val = v; },
        enumerable: true,
        configurable: true
    });
    obj.y = 55;
    if (obj.y !== 55)
        throw new Error("Expected y to be 55");
    return obj;
}

for (var i = 0; i < 1e5; i++)
    testAccessor();

// Test return value (should return the target object)
function testReturnValue() {
    var obj = {};
    var result = Object.defineProperty(obj, "z", { value: 1 });
    if (result !== obj)
        throw new Error("Expected Object.defineProperty to return the target object");
    return result;
}

for (var i = 0; i < 1e5; i++)
    testReturnValue();

// Test with symbol key
function testSymbol() {
    var s = Symbol("test");
    var obj = {};
    Object.defineProperty(obj, s, { value: "hello", writable: false });
    if (obj[s] !== "hello")
        throw new Error("Expected symbol property to be 'hello'");
    return obj;
}

for (var i = 0; i < 1e5; i++)
    testSymbol();

// Test non-object first argument (should throw)
function testThrows() {
    var threw = false;
    try {
        Object.defineProperty(42, "x", { value: 1 });
    } catch (e) {
        threw = true;
    }
    if (!threw)
        throw new Error("Expected TypeError for non-object target");
}

for (var i = 0; i < 1e5; i++)
    testThrows();

