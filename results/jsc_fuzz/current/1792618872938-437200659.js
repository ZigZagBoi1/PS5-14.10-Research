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

//@ runDefault("--watchdog=500", "--watchdog-exception-ok")
function placeholder() {}
function main() {
  const z48431 = [0.4, 1145324612];
  for (let v4 = 0; v4 < 100; v4++) {
    const v6 = Array(46139);
    let v7 = undefined;
    const v9 = class V9 extends Int16Array {
      constructor(v11, v12, v13) {
        super();
      }
      split() {
        return 'Test262Error: ' + this.message;
      }
    };
    const v16 = new v9();
    function v18(v19, v20, v21, v22) {
      v7 = forceGCSlowPaths;
    }
  }
  const z570009 = [0.4, 1145324612];
  const z676068 = [0.4, 1145324612];
  const v23 = 0;
  const v24 = 100;
  const z106237 = [0.4, 1145324612];
  const z788844 = [0.4, 1145324612];
  const z115753 = [0.4, 1145324612];
  const z913254 = [0.4, 1145324612];
  const z438038 = [0.4, 1145324612];
  const v25 = 1;
  for (let v29 = 0; v29 < 1099511627776n; v29++) {
    async function* v30(v31, v32, v33, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) {}
    const v34 = v30();
  }
  const z637976 = [0.4, 1145324612];
  gc();
  const z112286 = [0.4, 134217728n];
  const z709419 = [0.4, 1145324612];
}
noDFG(main);
noFTL(main);
main();

