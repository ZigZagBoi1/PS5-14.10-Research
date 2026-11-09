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

// With verbose set to false, this test is successful if there is no output.  Set verbose to true to see expected matches.
let verbose = false;

function arrayToString(arr)
{
    let str = '';
    arr.forEach(function(v, index) {
        if (typeof v == "string")
            str += "\"" + v + "\"";
        else
            str += v;

        if (index != (arr.length - 1))
            str += ',';
      });
  return str;
}

function objectToString(obj)
{
    let str = "";

    firstEntry = true;

    for (const [key, value] of Object.entries(obj)) {
        if (!firstEntry)
            str += ", ";

        str += key + ": " + dumpValue(value);

        firstEntry = false;
    }

    return "{ " + str + " }";
}

function dumpValue(v)
{
    if (v === null)
        return "<null>";

    if (v === undefined)
        return "<undefined>";

    if (typeof v == "string")
        return "\"" + v + "\"";

    let str = "";

    if (v.length)
        str += arrayToString(v);

    if (v.groups) {
        groupStr = objectToString(v.groups);

        if (str.length) {
            if ( groupStr.length)
                str += ", " + groupStr;
        } else
            str = groupStr;
    }

    return "[ " + str + " ]";
}

function compareArray(expected, actual)
{
    if (expected === null && actual === null)
        return true;

    if (expected === null) {
        print("### expected is null, actual is not null");
        return false;
    }

    if (actual === null) {
        print("### expected is not null, actual is null");
        return false;
    }

    if (expected.length !== actual.length) {
        print("### expected.length: " + expected.length + ", actual.length: " + actual.length);
        return false;
    }

    for (var i = 0; i < expected.length; i++) {
        if (expected[i] !== actual[i]) {
            print("### expected[" + i + "]: \"" + expected[i] + "\" !== actual[" + i + "]: \"" + actual[i] + "\"");
            return false;
        }
    }

    return true;
}

function compareGroups(expected, actual)
{
    if (expected === null && actual === null)
        return true;

    if (expected === null) {
        print("### expected group is null, actual group is not null");
        return false;
    }

    if (actual === null) {
        print("### expected group is not null, actual group is null");
        return false;
    }

    for (const key in expected) {
        if (expected[key] !== actual[key]) {
            print("### expected." + key + ": " + dumpValue(expected[key]) + " !== actual." + key + ": " + dumpValue(actual[key]));
            return false;
        }
    }

    return true;
}

let testNumber = 0;

function testRegExp(re, str, exp, groups)
{
    testNumber++;

    if (groups)
        exp.groups = groups;

    let actual = re.exec(str);

    let result = compareArray(exp, actual);;

    if (exp && exp.groups) {
        if (!compareGroups(exp.groups, actual.groups))
            result = false;
    }

    if (result) {
        if (verbose)
            print(re.toString() + ".exec(" + dumpValue(str) + "), passed ", dumpValue(exp));
    } else
        print(re.toString() + ".exec(" + dumpValue(str) + "), FAILED test #" + testNumber + ", Expected ", dumpValue(exp), " got ", dumpValue(actual));
}

function testRegExpSyntaxError(reString, flags, expError)
{
    testNumber++;


    try {
        let re = new RegExp(reString, flags);
        print("FAILED test #" + testNumber + ", Expected /" + reString + "/" + flags + " to throw \"" + expError + "\", but it didn't");
    } catch (e) {
        if (e != expError)
            print("FAILED test #" + testNumber + ", Expected /" + reString + "/" + flags + " to throw \"" + expError + "\" got \"" + e + "\"");
        else if (verbose)
            print("/" + reString + "/" + flags + " passed, it threw \"" + expError + "\" as expected");
    }
}

// Test 1
testRegExp(/(?<=($)(N*?)*)x/i, "aabbbccc", null);
testRegExp(/(?<=a(N*?)*)b/i, "aabbbccc", ["b", undefined]);
testRegExp(/(?<=a(b*?)*)bc/i, "aabbccc", ["bc", "b"]);
testRegExp(/(?<=A(?:b*?))bc/i, "aaaaaabbccc", ["bc"]);



