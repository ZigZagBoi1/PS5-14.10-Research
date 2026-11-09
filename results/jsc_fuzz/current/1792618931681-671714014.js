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

/*
 * Regression test for non-BMP first-character optimization stale register.
 *
 * BodyAlternativeNext / once-through-End reentry labels did not reset
 * m_regs.firstCharacterAdditionalReadSize. After a prior alternative read a
 * surrogate-pair character (setting the register to 1), the body loop would
 * incorrectly advance the index by an extra unit, skipping valid match
 * positions in subsequent alternatives.
 *
 * Triggered when m_useFirstNonBMPCharacterOptimization is enabled
 * (decodeSurrogatePairs && !inlineTest && !multiline && !containsBOL
 * && !containsLookbehinds && !containsModifiers).
 */

function shouldBe(actual, expected) {
    if (JSON.stringify(actual) !== JSON.stringify(expected))
        throw new Error("bad value: actual=" + JSON.stringify(actual) + " expected=" + JSON.stringify(expected));
}

for (var i = 0; i < 1e4; ++i) {
    // Two alternatives: alt1 reads non-BMP, alt2 should match later position.
    shouldBe("\u{10400}ZY".match(/\u{10400}X|Y/u), ["Y"]);
    shouldBe("\u{1F600}Xc".match(/\u{1F600}b|c/u), ["c"]);

    // Same shape with leading prefix forcing alt1 to consume non-BMP first.
    shouldBe("a\u{1F600}X".match(/a\u{1F600}b|\u{1F600}/u), ["\u{1F600}"]);

    // CharacterClass containing a non-BMP code point with a quantifier.
    shouldBe("a\u{1F600}X".match(/a[\u{1F600}]+b|\u{1F600}/u), ["\u{1F600}"]);

    // Mixed-width character class repeated, then second alternative.
    shouldBe("\u{10400}\u{10400}ZY".match(/[\u{10400}a]{2}X|Y/u), ["Y"]);

    // leftmost-first invariant: when both alternatives can match, the
    // earliest position must win. Bug version returned the longer alt at
    // a later index because the loop over-advanced.
    var m = "a\u{1F600}Xa\u{1F600}b".match(/a\u{1F600}b|\u{1F600}/u);
    shouldBe(m[0], "\u{1F600}");
    shouldBe(m.index, 1);

    // Sanity: with /m the optimization is disabled, behaviour must match.
    shouldBe("\u{10400}ZY".match(/\u{10400}X|Y/um), ["Y"]);

    // Body loop iterates: prior alt reads non-BMP, body advances by one,
    // alt2 must find the match at the next code unit.
    shouldBe("ZZ\u{1F600}aXY".match(/\u{1F600}aZ|XY/u), ["XY"]);
}

