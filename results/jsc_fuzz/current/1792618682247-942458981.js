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

"use strict";

let globalSink = 0;

function attempt(round) {
  function rootACtor() { this.round = round; }
    const rootA = new rootACtor();
    const rootB = {};
    const rootC = {};
    const mid = {};
    const leaf = {};

    Object.setPrototypeOf(mid, rootA);
    Object.setPrototypeOf(leaf, mid);

    let tick = 0;
    let sink = 0;

    const proxyProto = new Proxy(rootB, {
        getPrototypeOf(target) {
            tick++;
            if ((tick & 3) === 0)
                Object.setPrototypeOf(mid, rootA);
            return Reflect.getPrototypeOf(target);
        }
    });

    const quietGate = { get trip() { return 1; } };
    const noisyGate = {
        get trip() {
            tick++;
            Object.setPrototypeOf(mid, (tick & 1) ? proxyProto : rootC);
            return 1;
        }
    };

    function hot(value, proto, gate) {
        const guard = gate.trip;
        const result = value instanceof proto;
        sink ^= result ? guard : (guard << 1);
        return result;
    }

    function drive(i) {
        const gate = i < 42000 ? quietGate : noisyGate;
        if (i === 42000)
            Object.setPrototypeOf(mid, proxyProto);
        return hot(leaf, rootACtor, gate);
    }

    for (let i = 0; i < 70000; i++)
        drive(i);

    globalSink ^= sink;
}

for (let round = 0; round < 8; round++)
    attempt(round);

if (globalSink === 0x12345678)
    throw new Error("unreachable");

