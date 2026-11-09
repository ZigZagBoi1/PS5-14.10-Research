// CRASH_CLASS: LOW
// PROBE 164: crash oracle
//
// Context: every future WebKit candidate needs one thing before it is worth running:
// a reliable way to tell "the payload threw" from "the WebProcess died". A thrown
// exception is caught by pcall-equivalent semantics in JS and still returns; a
// memory-safety failure takes the whole renderer with it and no beacon is sent.
// This page gives that signal structurally: each case is a separate script loaded
// from /raw/, with a BEFORE beacon emitted before the load and a SURVIVED beacon
// emitted from its onload. Only BEFORE arriving means the process died inside that
// case. LOADFAIL means the file did not load at all.
//
// Cases are files named p164-case-<name>.js in the served directory, so adding a
// candidate needs no server restart and no edit to this page.
//
// Run with ?cases=control,oom to validate the oracle itself: control must produce
// BEFORE and SURVIVED, oom must produce BEFORE and then nothing.

(function() {
  var BASE = location.protocol + '//' + location.host;

  function param(name, def) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : def;
  }

  function B(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V164-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch (e) {}
  }

  var cases = param('cases', 'control,oom').split(',');
  B('BOOT-' + cases.join('+'));

  function run(i) {
    if (i >= cases.length) {
      B('ORACLE-DONE');
      return;
    }
    var name = cases[i].replace(/[^A-Za-z0-9_-]/g, '');
    B('BEFORE-' + name);

    var s = document.createElement('script');
    s.src = BASE + '/raw/p164-case-' + name + '.js?t=' + Date.now();
    s.onload = function() {
      B('SURVIVED-' + name);
      setTimeout(function() { run(i + 1); }, 150);
    };
    s.onerror = function() {
      B('LOADFAIL-' + name);
      setTimeout(function() { run(i + 1); }, 150);
    };
    document.head.appendChild(s);
  }

  run(0);

  // Watchdog: a case that hangs the renderer without killing it will not reach here,
  // which is itself a distinct outcome from a crash.
  setTimeout(function() { B('WATCHDOG-ALIVE'); }, 20000);
})();
