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
    if (actual !== expected)
        throw new Error(`FAIL ${message}: expected ${expected}, got ${actual}`);
}

const codeUnits = [];
for (let unit = 0; unit < 0x10000; unit += 0x40)
    codeUnits.push(unit);
for (const unit of [0x03ff, 0x0400, 0x2014, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0xfffd, 0xffff])
    codeUnits.push(unit);

const followers = [0x0061, 0x0400, 0x3042, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xffff];

function codePointsOf(string) {
    const result = [];
    for (const character of string)
        result.push(character.codePointAt(0));
    return result;
}

const singleCodePoint = /^.$/u;
const twoCodePoints = /^(.)(.)$/u;
const greedy = /^([^X]*)X$/u;

for (let i = 0; i < testLoopCount; ++i) {
    for (const first of codeUnits) {
        for (const second of followers) {
            const subject = String.fromCharCode(first, second);
            const expected = codePointsOf(subject);
            const tag = `[${first.toString(16)},${second.toString(16)}]`;

            shouldBe(singleCodePoint.test(subject), expected.length === 1, `single code point ${tag}`);

            const matched = twoCodePoints.exec(subject);
            shouldBe(matched !== null, expected.length === 2, `two code points ${tag}`);
            if (matched) {
                shouldBe(matched[1].codePointAt(0), expected[0], `first code point ${tag}`);
                shouldBe(matched[2].codePointAt(0), expected[1], `second code point ${tag}`);
            }

            const scanned = greedy.exec(subject + "X");
            shouldBe(scanned !== null, true, `greedy scan ${tag}`);
            shouldBe(scanned[1], subject, `greedy capture ${tag}`);
        }
    }
}

