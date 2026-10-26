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

// Multiplies by 16000-bit pieces of b (250 64-bit digits, 500 32-bit digits), which are too short for the FFT and Toom-3, so that Karatsuba computes the reference.
function mulByPieces(a, b) {
    const pieceBits = 64 * 250;
    let result = 0n;
    let shift = 0n;
    while (b > 0n) {
        result += (a * BigInt.asUintN(pieceBits, b)) << shift;
        b >>= BigInt(pieceBits);
        shift += BigInt(pieceBits);
    }
    return result;
}

function check(x, y, message, checkOperandOrderAndSign) {
    const p = x * y;
    shouldBe(p, mulByPieces(x, y), `${message} pieces`);
    if (checkOperandOrderAndSign) {
        shouldBe(y * x, p, `${message} commutes`);
        shouldBe((-x) * y, -p, `${message} sign`);
    }
    return p;
}

const shapes = ["random", "ones", "sparse", "halves"];

for (const [larger, smaller] of [
    [1088, 1088], [1089, 1088], [1089, 1089], [1153, 1152], [1281, 1280], [2177, 2176], [2305, 2304], [4993, 4992], [6913, 6912], [7681, 7680], [8192, 8192],
    [1592, 585], [1591, 586], [1590, 587], [4000, 585], [4000, 586], [3000, 1000], [6000, 2000], [10000, 3000], [12000, 586], [15798, 586], [15000, 1384],
]) {
    for (const shape of larger + smaller > 8000 ? ["random", "ones"] : shapes) {
        const x = makeOperand(larger, larger + smaller, shape);
        const y = makeOperand(smaller, larger * smaller, shapes[(shapes.indexOf(shape) + 1) % shapes.length]);
        const p = check(x, y, `${larger} x ${smaller} ${shape}`, shape === "random");
        if (shape === "random" && larger + smaller <= 5000) {
            shouldBe(p / y, x, `${larger} x ${smaller} quotient`);
            shouldBe(p % y, 0n, `${larger} x ${smaller} remainder`);
        }
    }
}

for (const size of [1088, 1089, 1500, 2177, 4000, 8192]) {
    for (const shape of size > 4000 ? ["random", "ones"] : shapes) {
        const x = makeOperand(size, size, shape);
        const square = x * x;
        shouldBe(square, mulByPieces(x, x), `${size} squared ${shape} pieces`);
        if (size < 8192)
            shouldBe((x + 1n) * (x + 1n) - square, 2n * x + 1n, `${size} squared ${shape} successor`);
    }
    const ones = (1n << BigInt(64 * size)) - 1n;
    shouldBe(ones * ones, (ones << BigInt(64 * size)) - ones, `${size} all ones squared`);
    if (size < 8192)
        shouldBe((ones + 2n) * ones, (ones << BigInt(64 * size)) + ones, `${size} power of two plus one times all ones`);
}

