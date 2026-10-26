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

function shouldBe(actual, expected, message) {
    // Distinguish -0 from 0 and treat NaN as equal to NaN.
    let same = actual === expected ? (actual !== 0 || 1 / actual === 1 / expected)
        : (actual !== actual && expected !== expected);
    if (!same)
        throw new Error(`${message}: expected ${expected === 0 && 1 / expected < 0 ? "-0" : expected}, got ${actual === 0 && 1 / actual < 0 ? "-0" : actual}`);
}

function negLeft(w, r) { return -w * r; }
noInline(negLeft);

function negRight(w, r) { return w * -r; }
noInline(negRight);

function negBoth(w, r) { return -w * -r; }
noInline(negBoth);

// The negation has two users, so it cannot be absorbed into the multiply.
function sharedNeg(w, r) {
    let n = -w;
    return n * r + n;
}
noInline(sharedNeg);

// Integer operands, so this stays on the Int32 path.
function negLeftInt(w, r) { return (-w * r) | 0; }
noInline(negLeftInt);

let signedZeroCases = [
    // w, r, -w * r, w * -r, -w * -r
    [0, 3, -0, -0, 0],
    [-0, 3, 0, 0, -0],
    [0, -3, 0, 0, -0],
    [-0, -3, -0, -0, 0],
    [0, 0, -0, -0, 0],
    [-0, -0, -0, -0, 0],
    [0, -0, 0, 0, -0],
];

let specialCases = [
    // w, r, -w * r, w * -r, -w * -r
    [0, Infinity, NaN, NaN, NaN],
    [2, Infinity, -Infinity, -Infinity, Infinity],
    [-2, Infinity, Infinity, Infinity, -Infinity],
    [NaN, 3, NaN, NaN, NaN],
    [3, NaN, NaN, NaN, NaN],
    [1.5, 2.5, -3.75, -3.75, 3.75],
    [-1.5, 2.5, 3.75, 3.75, -3.75],
    [Number.MIN_VALUE, 0.5, -Number.MIN_VALUE / 2, -Number.MIN_VALUE / 2, Number.MIN_VALUE / 2],
    [Number.MAX_VALUE, 2, -Infinity, -Infinity, Infinity],
];

let cases = signedZeroCases.concat(specialCases);

for (let i = 0; i < 1e4; ++i) {
    for (let [w, r, expectNegLeft, expectNegRight, expectNegBoth] of cases) {
        shouldBe(negLeft(w, r), expectNegLeft, `-${w} * ${r}`);
        shouldBe(negRight(w, r), expectNegRight, `${w} * -${r}`);
        shouldBe(negBoth(w, r), expectNegBoth, `-${w} * -${r}`);
        shouldBe(sharedNeg(w, r), expectNegLeft + -w, `shared -${w} * ${r}`);
    }
}

// Int32 path: (-w * r) | 0 wraps like the two's complement product.
let intCases = [
    [1, 1, -1],
    [-1, 1, 1],
    [3, 7, -21],
    [-3, 7, 21],
    [0x7fffffff, 2, 2],
    [-0x80000000, 2, 0],
    [0x10000, 0x10000, 0],
];

for (let i = 0; i < 1e4; ++i) {
    for (let [w, r, expected] of intCases)
        shouldBe(negLeftInt(w, r), expected, `(-${w} * ${r}) | 0`);
}

