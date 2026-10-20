// CRASH_CLASS: HIGH
// PROBE 167: popup-churn controls for case 30
//
// Context: corpus case fast/scrolling/mac/event-dispatcher-timer-close-crash.html
// killed the browser on every attempt. Its upstream fix is a use-after-free of
// RemoteLayerTreeEventDispatcher's RunLoop::Timer on the scrolling thread, armed
// when an accelerated animation registers a display-link observer and destroyed
// when the page closes. The same test also opens and closes 30 popup windows,
// and a popup storm can end a browser without any memory bug, so the corpus
// result alone does not say which of the two happened.
//
// One fact from the console decides how this probe has to be built: at the top
// level of the page, window.open() returns null (p167-A beaconed
// A-POPUP-BLOCKED), while the same call inside the corpus runner's iframe
// opened a real window. So the variants run inside a same-origin subframe,
// where the popup path is actually reachable.
//
// Variants, one after another in a single load, each preceded by a beacon so a
// death is attributed to the variant that was running:
//
//   E  one popup: open, write a plain div, close                   minimum trigger
//   A  30 x (open popup, write a plain div, close)                no animation
//   B  30 x (open popup, accelerated animation, two rAFs, close)   corpus shape
//   C  30 x (open popup, accelerated animation, close immediately) no rAF wait
//   D  30 x (iframe with the animation, remove it)                 no popup at all
//
// Per-cycle beacons count how far a variant got, so a death has a position:
// E dying means any popup is fatal, A dying after k cycles means a threshold.
// The outer page keeps a 2 s ALIVE beacon so "the browser died" is told apart
// from "the page stopped".

(function() {
  var BASE = location.protocol + '//' + location.host;
  var SESSION = Math.random().toString(36).slice(2, 8);
  var SEQ = 0;

  function param(name, def) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : def;
  }

  function B(tag) {
    var url = BASE + '/beacon/V167-' + SESSION + '-' + tag + '?t=' + Date.now() + '&n=' + (++SEQ);
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(url)) return;
    } catch (e) {}
    try {
      var x = new XMLHttpRequest();
      x.open('GET', url, true);
      x.send();
    } catch (e) {}
  }

  var ANIM = '<div style="width:50px;height:50px;background:green;' +
    'animation:s 10s linear infinite;will-change:transform"></div>' +
    '<style>@keyframes s{from{transform:rotate(0)}to{transform:rotate(360deg)}}</style>';
  var PLAIN = '<div style="width:50px;height:50px;background:green"></div>';
  var CYCLES = 30;

  function openPopup(html) {
    var p = window.open('about:blank', '', 'width=200,height=200');
    if (!p) return null;
    try { p.document.body.innerHTML = html; } catch (e) {}
    return p;
  }

  // Runs inside the subframe. Each variant returns after signalling, so a
  // browser death mid-variant is visible as the last beacon of that variant.
  function runVariants() {
    var i = 0;

    function cycles(body, waitFrames, name, done) {
      function step() {
        if (i++ >= CYCLES) { B(name + '-DONE'); return done(); }
        var p = openPopup(body);
        if (!p) { B(name + '-POPUP-BLOCKED'); return done(); }
        B(name + '-CYCLE-' + i);
        if (!waitFrames) { p.close(); return setTimeout(step, 0); }
        requestAnimationFrame(function() {
          requestAnimationFrame(function() {
            try { p.close(); } catch (e) {}
            setTimeout(step, 0);
          });
        });
      }
      step();
    }

    function onePopup(done) {
      var p = openPopup(PLAIN);
      if (!p) { B('E-POPUP-BLOCKED'); return done(); }
      B('E-OPENED');
      requestAnimationFrame(function() {
        requestAnimationFrame(function() {
          try { p.close(); } catch (e) {}
          B('E-CLOSED');
          done();
        });
      });
    }

    function frames(body, count, name, done) {
      var k = 0;
      (function step() {
        if (k++ >= count) { B(name + '-DONE'); return done(); }
        var f = document.createElement('iframe');
        f.style.cssText = 'width:200px;height:120px';
        if ('srcdoc' in f) {
          f.srcdoc = body;
        } else {
          // No srcdoc on this engine: load a same-origin blank page and write
          // the content in, so the variant is the same either way.
          f.src = '/blank.html';
          f.onload = function() {
            try { f.contentDocument.body.innerHTML = body; } catch (e) {}
          };
        }
        document.body.appendChild(f);
        B(name + '-CYCLE-' + k);
        requestAnimationFrame(function() {
          requestAnimationFrame(function() {
            try { f.parentNode.removeChild(f); } catch (e) {}
            setTimeout(step, 0);
          });
        });
      })();
    }

    var ANIM_ONLY = '<div style="width:50px;height:50px;background:green;' +
      'animation:s 10s linear infinite"></div>' +
      '<style>@keyframes s{from{transform:rotate(0)}to{transform:rotate(360deg)}}</style>';
    var WILLCHANGE_ONLY = '<div style="width:50px;height:50px;background:green;' +
      'will-change:transform"></div>';

    // The order is by cost of proof: a single create/remove first, then the
    // pieces of the animation, then the whole thing.
    var order = ['I', 'F', 'G', 'H', 'D'];
    var only = param('v', 'ALL').toUpperCase();
    if (only !== 'ALL') order = [only];
    var k = 0;
    (function next() {
      if (k >= order.length) { B('ALL-DONE'); return; }
      var name = order[k++];
      B('VAR-' + name);
      if (name === 'E') return onePopup(next);
      if (name === 'A') return cycles(PLAIN, false, 'A', next);
      if (name === 'B') return cycles(ANIM, true, 'B', next);
      if (name === 'C') return cycles(ANIM, false, 'C', next);
      if (name === 'I') return frames(ANIM, 1, 'I', next);
      if (name === 'F') return frames(PLAIN, CYCLES, 'F', next);
      if (name === 'G') return frames(ANIM_ONLY, CYCLES, 'G', next);
      if (name === 'H') return frames(WILLCHANGE_ONLY, CYCLES, 'H', next);
      return frames(ANIM, CYCLES, 'D', next);
    })();
  }

  // The outer page hosts the subframe and reports liveness.
  function runOuter() {
    var variant = param('v', 'ALL').toUpperCase();
    var f = document.createElement('iframe');
    f.style.cssText = 'width:220px;height:140px;border:1px solid #ccc';
    f.src = '/probe/p167-popup-controls.js?v=' + variant + '&inner=1';
    document.body.appendChild(f);
    B('OUTER-FRAME');
    var k = 0;
    setInterval(function() { B('ALIVE-' + (++k)); }, 2000);
  }

  if (/[?&]inner=1/.test(location.search)) runVariants();
  else runOuter();
})();
