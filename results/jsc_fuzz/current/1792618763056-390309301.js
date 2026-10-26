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
        throw new Error('bad value: ' + actual + ' expected: ' + expected);
}
noInline(shouldBe);

function forOfMap(map) {
    let sumKeys = 0;
    let sumValues = 0;
    let count = 0;
    for (const [k, v] of map) {
        sumKeys += k;
        sumValues += v;
        count++;
    }
    return [sumKeys, sumValues, count];
}
noInline(forOfMap);

function forOfSet(set) {
    let sum = 0;
    let count = 0;
    for (const v of set) {
        sum += v;
        count++;
    }
    return [sum, count];
}
noInline(forOfSet);

function testEmptyMap() {
    const m = new Map();
    const [k, v, c] = forOfMap(m);
    shouldBe(k, 0);
    shouldBe(v, 0);
    shouldBe(c, 0);
}

function testNonEmptyMap() {
    const m = new Map();
    let expectedK = 0;
    let expectedV = 0;
    for (let i = 0; i < 16; i++) {
        m.set(i, i * 2);
        expectedK += i;
        expectedV += i * 2;
    }
    const [k, v, c] = forOfMap(m);
    shouldBe(k, expectedK);
    shouldBe(v, expectedV);
    shouldBe(c, 16);
}

function testMapWithDeletions() {
    const m = new Map();
    for (let i = 0; i < 32; i++)
        m.set(i, i);
    for (let i = 0; i < 32; i += 2)
        m.delete(i);
    let expected = 0;
    for (let i = 1; i < 32; i += 2)
        expected += i;
    const [k, v, c] = forOfMap(m);
    shouldBe(k, expected);
    shouldBe(v, expected);
    shouldBe(c, 16);
}

function testEmptySet() {
    const s = new Set();
    const [sum, c] = forOfSet(s);
    shouldBe(sum, 0);
    shouldBe(c, 0);
}

function testNonEmptySet() {
    const s = new Set();
    let expected = 0;
    for (let i = 0; i < 16; i++) {
        s.add(i);
        expected += i;
    }
    const [sum, c] = forOfSet(s);
    shouldBe(sum, expected);
    shouldBe(c, 16);
}

function testSetWithDeletions() {
    const s = new Set();
    for (let i = 0; i < 32; i++)
        s.add(i);
    for (let i = 0; i < 32; i += 2)
        s.delete(i);
    let expected = 0;
    for (let i = 1; i < 32; i += 2)
        expected += i;
    const [sum, c] = forOfSet(s);
    shouldBe(sum, expected);
    shouldBe(c, 16);
}

function testMapMutationDuringIteration() {
    const m = new Map();
    m.set(1, 10);
    m.set(2, 20);
    let count = 0;
    for (const [k, v] of m) {
        count++;
        if (k === 1)
            m.set(3, 30);
        if (count > 10)
            break;
    }
    shouldBe(count, 3);
}
noInline(testMapMutationDuringIteration);

function testSetMutationDuringIteration() {
    const s = new Set();
    s.add(1);
    s.add(2);
    let count = 0;
    for (const v of s) {
        count++;
        if (v === 1)
            s.add(3);
        if (count > 10)
            break;
    }
    shouldBe(count, 3);
}
noInline(testSetMutationDuringIteration);

function testReusedEmptyMap() {
    const m = new Map();
    let total = 0;
    for (const [k, v] of m)
        total++;
    shouldBe(total, 0);
}

function testReusedEmptySet() {
    const s = new Set();
    let total = 0;
    for (const v of s)
        total++;
    shouldBe(total, 0);
}

for (let i = 0; i < 5000; i++) {
    testEmptyMap();
    testNonEmptyMap();
    testMapWithDeletions();
    testEmptySet();
    testNonEmptySet();
    testSetWithDeletions();
    testReusedEmptyMap();
    testReusedEmptySet();
}

for (let i = 0; i < 1000; i++) {
    testMapMutationDuringIteration();
    testSetMutationDuringIteration();
}

