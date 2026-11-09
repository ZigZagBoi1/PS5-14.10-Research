// CRASH_CLASS: MODERATE
// PROBE 174: a u-mode regexp that never returns on three code units
//
// Context: p172 replays WebKit's own regression cases against the 14.10
// engine. Case 379 (`regexp-unicode-greedy-charclass-backtrack-linear.js`)
// stopped the corpus pass at index 378 with the console's "this page isn't
// responding" dialog, while V8 runs the same body in 372 ms. The case is a
// regression test for backtracking over mixed-width characters in a `u`-flagged
// regexp, and its last block is a complexity canary that the engine here
// passes (1/2/7/32 ms at n = 250/500/1000/2000), so the fix it tests is
// present and the hang was somewhere else.
//
// The case was then cut down on the console, one document per step, on
// 2026-10-21 between 19:04 and 19:21 UTC:
//
//   eight blocks, 200 iterations each   blocks 1-6 returned in 0-1 ms,
//                                       block 7 ("no match after full
//                                       backtrack") never returned
//   /[^"]*X/u.test("\u{10000}aaa")      hangs
//   /[^"]*X/u.test("\u2014" + 2000 a)   32 ms - the em-dash canary is fine
//   /.*X/u.test("\u{10000}aaa")         hangs - the negated class is irrelevant
//   /.*X/u.test("\u{10000}aaX")         0 ms - a match is fine
//   /.*X/.test("\u{10000}aaa")          0 ms - without `u` it is fine
//   /X/u.test("\u{10000}aaa")           0 ms - without a quantifier it is fine
//   /.*X/u.test("\u{10000}")            0 ms - the astral alone is fine
//   /.*X/u.test("aa\u{10000}")          0 ms - the astral at the end is fine
//   /.*X/u.test("aa\u{10000}aa")        hangs
//   /.*X/u.test("\u{10000}a")           hangs - the minimal form
//
// So the failure needs the `u` flag, a quantifier that has to backtrack, a
// non-BMP character with at least one code unit after it, and no match. The
// subject below is three code units; nothing proportional to its length can
// take minutes, so this is a loop rather than slow work. The likeliest
// mechanism is the step that advances the start offset after a failed attempt:
// with the astral in the middle an attempt starts inside the surrogate pair,
// and the code that moves over a non-BMP character does not move forward. That
// is inferred from the shape of the results - the engine source is not
// available and the failure leaves no trace but a frozen page.
//
// This probe is the minimal reproducer. Loading it in the guide browser wedges
// the WebProcess main thread; it does not touch the kernel and it is not an
// escape from the browser sandbox. What it establishes is that legal JavaScript
// can stop the guide browser with a three-character string.
//
// Beacon protocol: `P174-START` before the call and `P174-SURVIVED` after it.
// If the log shows START and no SURVIVED, the engine did not come back.

(function () {
  function mark(tag) {
    var url = location.origin + '/beacon/P174-' + tag + '?t=' + Date.now();
    try { if (navigator.sendBeacon && navigator.sendBeacon(url)) return; } catch (e) {}
    try { var x = new XMLHttpRequest(); x.open('GET', url, true); x.send(); } catch (e) {}
  }

  mark('START');

  var subject = '\u{10000}a';        // one non-BMP character, one 'a'
  var result = /.*X/u.test(subject); // no X in the subject: full backtrack

  mark('SURVIVED-' + result);
})();
