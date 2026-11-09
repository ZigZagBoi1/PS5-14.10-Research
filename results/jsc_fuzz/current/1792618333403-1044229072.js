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

//@ skip if $buildType == "debug"
//@ runDefault("--useConcurrentJIT=false", "--jitPolicyScale=0", "--maximumFunctionForCallInlineCandidateBytecodeCostForFTL=500")

let g = 0;
function restY(c, ...r) { g = c ? 1 : 2; return r; }
function h(c, ...r) { return r; }
function h2(...r) { return r; }
function sink() {
    let out = [];
    for (let i = 0; i < arguments.length; i++) out.push(arguments[i]);
    return out;
}
noInline(sink);

function restX(c, ...rx) {
    let arr = [...rx, ...restY(c, ...rx)];
    let dummy = [0, 0, 0, 0, 0, 0, 0, h(50, 9.9, 8.8)];
    return [sink.apply(null, arr), dummy];
}
for (let i = 0; i < 1000000; i++) restX(i & 1, 0.1, 0.2);

function makeSrc(k) {
return `
(function() {
function victim${k}(c1) {
    let q = restX(c1, 0.1, 0.2);
    let z = h2(7.7, 6.6);
    return [q, z];
}
noInline(victim${k});
for (let i = 0; i < 1000000; i++) {
    victim${k}(i & 1);
}
})()
`;
}

for (let k = 0; k < 30; k++) eval(makeSrc(k));

