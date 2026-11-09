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
        throw new Error(`bad value: ${actual}`);
}

function makePolyProtoObject() {
    function foo() {
        class C {
            constructor() { this._field = 42; }
        };
        return new C;
    }
    for (let i = 0; i < 15; ++i)
        foo();
    return foo();
}

// A poly-proto object stores its prototype in the object rather than in its structure, so
// Object.setPrototypeOf leaves its StructureID untouched. The Proxy handler-traps cache must not
// treat a matching StructureID as proof that the prototype is still an object.

{
    let handler = makePolyProtoObject();
    Object.setPrototypeOf(handler, Object.prototype);
    handler.get = (target, key) => `got ${key}`;

    let proxy = new Proxy({ }, handler);
    shouldBe(proxy.foo, "got foo");

    Object.setPrototypeOf(handler, null);
    shouldBe(proxy.foo, "got foo");
    shouldBe(proxy.bar, "got bar");
}

{
    let handler = makePolyProtoObject();
    Object.setPrototypeOf(handler, Object.prototype);

    let proxy = new Proxy({ a: 1 }, handler);
    shouldBe(Object.keys(proxy).join(), "a");

    Object.setPrototypeOf(handler, null);
    shouldBe(Object.keys(proxy).join(), "a");

    handler.ownKeys = () => ["b"];
    handler.getOwnPropertyDescriptor = () => ({ value: 2, enumerable: true, configurable: true });
    shouldBe(Object.keys(proxy).join(), "b");
}

{
    let handler = makePolyProtoObject();
    Object.setPrototypeOf(handler, Object.prototype);
    handler.get = function (target, key) {
        Object.setPrototypeOf(handler, null);
        return 42;
    };

    let proxy = new Proxy({ }, handler);
    shouldBe(proxy.foo, 42);
    shouldBe(proxy.foo, 42);
}

// A poly-proto handler whose prototype gains a trap must pick the new trap up.
{
    let handler = makePolyProtoObject();
    Object.setPrototypeOf(handler, Object.prototype);

    let proxy = new Proxy({ foo: 1 }, handler);
    shouldBe(proxy.foo, 1);

    Object.setPrototypeOf(handler, { get: () => "from prototype" });
    shouldBe(proxy.foo, "from prototype");
}

