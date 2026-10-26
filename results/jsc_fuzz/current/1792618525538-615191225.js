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

//@ slow!
function shouldBe(actual, expected, message) {
    if (actual !== expected)
        throw new Error(`${message}: expected ${expected.toString(16).slice(0, 40)}... but got ${actual.toString(16).slice(0, 40)}...`);
}

function refMul(a, b) {
    let result = 0n;
    let shift = 0n;
    while (b > 0n) {
        const chunk = b & 0xffffffffn;
        if (chunk)
            result += (a * chunk) << shift;
        b >>= 32n;
        shift += 32n;
    }
    return result;
}

function combine(parts, begin, end) {
    if (end - begin === 1)
        return parts[begin];
    const middle = (begin + end) >> 1;
    return (combine(parts, begin, middle) << BigInt(64 * (end - middle))) | combine(parts, middle, end);
}

function makeOperand(digits, seed, shape) {
    const parts = new Array(digits);
    let mix = BigInt.asUintN(64, 0x9e3779b97f4a7c15n * BigInt(seed + 1));
    for (let i = 0; i < digits; i++) {
        mix = BigInt.asUintN(64, mix * 6364136223846793005n + 1442695040888963407n);
        switch (shape) {
        case "random":
            parts[i] = mix;
            break;
        case "ones":
            parts[i] = 0xffffffffffffffffn;
            break;
        case "sparse":
            parts[i] = (i * 7 + seed) % 5 === 0 ? mix : 0n;
            break;
        case "halves":
            parts[i] = i < digits / 2 ? 0n : mix;
            break;
        }
    }
    if (shape !== "ones")
        parts[0] = (parts[0] & 0x0fffffffffffffffn) | 0x8000000000000000n;
    return combine(parts, 0, digits);
}

function check(x, y, message) {
    const p = x * y;
    shouldBe(y * x, p, `${message} commutes`);
    shouldBe(p / y, x, `${message} quotient`);
    shouldBe(p % y, 0n, `${message} remainder`);
    shouldBe((-x) * y, -p, `${message} sign`);
    return p;
}

const shapes = ["random", "ones", "sparse", "halves"];

for (const size of [480, 507, 508, 509, 510, 512, 700, 1000, 1525]) {
    for (const shape of shapes) {
        const x = makeOperand(size, size, shape);
        const y = makeOperand(size, size * 3 + 1, shapes[(shapes.indexOf(shape) + 1) % shapes.length]);
        const p = check(x, y, `${size} x ${size} ${shape}`);
        if (shape === "random" && size < 800)
            shouldBe(p, refMul(x, y), `${size} x ${size} reference`);
        shouldBe((x + 1n) * (x + 1n) - x * x, 2n * x + 1n, `${size} square ${shape}`);
    }
}

for (const [larger, smaller] of [[509, 508], [845, 508], [846, 508], [847, 508], [1016, 508], [1017, 508], [1524, 508], [1525, 508], [1500, 700], [2000, 700], [2000, 1000], [4000, 513], [4001, 600]]) {
    for (const shape of shapes) {
        const x = makeOperand(larger, larger + smaller, shape);
        const y = makeOperand(smaller, larger * smaller, shapes[(shapes.indexOf(shape) + 2) % shapes.length]);
        const p = check(x, y, `${larger} x ${smaller} ${shape}`);
        if (shape === "random" && larger <= 1000)
            shouldBe(p, refMul(x, y), `${larger} x ${smaller} reference`);
    }
}

for (const size of [507, 508, 509, 1000]) {
    const ones = (1n << BigInt(64 * size)) - 1n;
    shouldBe(ones * ones, (ones << BigInt(64 * size)) - ones, `${size} all ones squared`);
    shouldBe((ones + 2n) * ones, (ones << BigInt(64 * size)) + ones, `${size} power of two plus one times all ones`);
}

