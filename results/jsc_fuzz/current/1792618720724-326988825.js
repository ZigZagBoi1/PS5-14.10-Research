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
        throw new Error(`bad value: ${actual}, expected: ${expected}`);
}

function check(text) {
    shouldBe(JSON.stringify(JSON.parse(text)), JSON.stringify(JSON.parse(text, (key, value) => value)));
}

function checkThrows(text) {
    let threw = false;
    try {
        JSON.parse(text);
    } catch (error) {
        threw = error instanceof SyntaxError;
    }
    if (!threw)
        throw new Error(`should throw SyntaxError: ${text}`);
}

const wide = "あ";
const names = [
    "a", "id", "name", "abcdefg", "abcdefgh", "abcdefghi", "abcdefghijklmno", "abcdefghijklmnop",
    "abcdefghijklmnopq", "abcdefghijklmnopqrstuvwxyz0123456789",
];

for (let i = 0; i < testLoopCount; ++i) {
    for (const name of names) {
        const repeated = `[${Array.from({ length: 4 }, (_, j) => `{"${name}":"${wide}${j}","next":${j}}`).join(",")}]`;
        check(repeated);

        check(`[{"${name}":1,"x":"${wide}"},{"${name}x":3,"x":4},{"${name.slice(0, -1)}":5,"x":6}]`);
        check(`[{"${name}":1},{"${name}":"${wide}"},{"${name.slice(0, -1)}\\"":2},{"${name}\\\\":3},{"${name}\\u0041":4}]`);
        check(`[{"${name}":"${wide}"},{"${name.slice(0, -1)}\\u${name.charCodeAt(name.length - 1).toString(16).padStart(4, "0")}":2}]`);
        check(`[{"${name}":1},{"${name}${wide}":2},{"${wide}${name}":3}]`);
        check(`[{"${name}":"${wide}"},{"${name}":1}]`);
        check(`[{"${name}":"${wide}"},{"${name}"  :  1}]`);
        check(`[{"${name}":"${wide}"},{ "${name}":1}]`);

        const tail = `[{"${name}":"${wide}"},{"${name}":1}]`;
        for (let cut = 1; cut < tail.length; ++cut)
            checkThrows(tail.slice(0, cut));
    }

    check(`[{"${wide}":1,"a":2},{"${wide}":3,"a":4},{"${wide}${wide}":5}]`);
    check(`[{"été":1,"${wide}":2},{"été":3,"${wide}":4}]`);
    check(`[{"a":{"b":{"c":"${wide}"}}},{"a":{"b":{"c":1}}},{"a":{"b":{"d":1}}}]`);
    check(`[{"a":1,"a":2},{"a":3,"a":"${wide}"}]`);
    check(`[{"0":1,"1":2},{"0":3,"1":"${wide}"}]`);
    check(`[{"__proto__":1},{"__proto__":"${wide}"}]`);
    check(`[{"abcdefghijklmnopqrstuvwxyz":"${wide}"},{"abcdefghijklmnopqrstuvwxyz":1}]`.padEnd(200, " "));
    check(`[{"a":1},{"":5,"x":6},{"":5,"x":6},{"b":1},{"":2}]`);
    check(`[{"a":1},{"":5,"x":6},{"":5,"x":6},{"b":1},{"":"${wide}"}]`);
    checkThrows(`[{"a":1},{"a\n":"${wide}"}]`);
    checkThrows(`[{"abcdefghijk":1},{"abcdefghijk\u0001":"${wide}"}]`);
    checkThrows(`[{"a":1},{"a":"${wide}"},{"a"}]`);
}

