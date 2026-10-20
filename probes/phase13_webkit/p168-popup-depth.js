// CRASH_CLASS: HIGH
// PROBE 168: popup depth and cycle threshold for the corpus case-30 crash
//
// Context: corpus case 30 (fast/scrolling/mac/event-dispatcher-timer-close-crash.html)
// kills the console browser on every attempt: the case loads, sets its text, and
// the browser is gone before the next case starts. The case's own script opens a
// popup holding an accelerated animation, waits two rAFs and closes it, 30 times.
// The upstream fix is a use-after-free of RemoteLayerTreeEventDispatcher's
// RunLoop::Timer on the scrolling thread: the animation arms a display-link
// observer, the page close destroys the dispatcher, and the scrolling thread
// then calls back into freed memory.
//
// Measured so far: popups are blocked one frame down (p167, p168 chain 3), the
// two-frame nesting on its own is safe (p168 chain 2), and the two-frame chain
// with an animated popup killed the browser (p168 chain 4) before the inner
// frame reported anything. That run could not say where it died, because only
// the innermost frame reported and it had not reported yet.
//
// So every step of a chain is now marked, on both sides:
//   P-*  markers come from the parent, at each construction step
//        P-CHAIN-START-<depth>-<variant>-<cycles>  before the chain is built
//        P-BUILD-<depth>-<variant>                   before a frame is appended
//        P-F1-APPENDED-<depth>                      after the append
//        P-F1-LOADED-<depth>                        in the frame's onload
//   I-*  markers come from the innermost frame
//        I-READY                                    script running
//        I-PRE-OPEN-<i> / I-OPENED-<i>              around window.open
//        I-POPUP-BLOCKED                            window.open returned null
//        I-BODY-<i>                                 the popup body was written
//        I-PRE-CLOSE-<i> / I-CLOSED-<i>             around popup.close()
//
// All markers are synchronous XHRs, on both sides: a marker is on the server
// before the next step runs, so a death is always attributed to a step and not
// to the step before it. A queued beacon would die with the process, which is
// exactly how the first two-frame run went silent.
//
// The probe builds a chain of same-origin frames by navigation, the same way
// the corpus runner loads its cases, and runs the popup loop in the innermost
// one. Chains run one after another, so a death is attributed to the chain
// that was running, and the safe chains come first:
//
//   ?chains=2:NOPOPUP:1,2:PLAIN:1,2:ANIM:1
//              each entry is a frame depth, a popup body and a cycle count
//              ANIM    accelerated animation + will-change (the corpus shape)
//              PLAIN   static div, no animation
//              NOWC    animation without will-change
//              NOCLOSE open + animate, never close
//              NOPOPUP no popup at all, the nesting control
//
// The top page keeps a 2 s ALIVE beacon to tell a browser death apart from a
// page that merely stopped.

(function () {
  var BASE = location.protocol + '//' + location.host;
  var SESSION = param('s', Math.random().toString(36).slice(2, 8));
  var SEQ = 0;

  function param(name, def) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : def;
  }

  // Synchronous marker. The server sees it before the caller continues, so a
  // crash in the next step cannot lose it. The marker carries the frame's own
  // query string, so the log says which URL that frame actually loaded: a
  // frame that loses a parameter shows up as a lost parameter.
  function S(tag) {
    var url = BASE + '/beacon/V168-' + SESSION + '-' + tag + '?t=' + Date.now() +
      '&n=' + (++SEQ) + '&w=' + encodeURIComponent(location.search);
    try {
      var x = new XMLHttpRequest();
      x.open('GET', url, false);
      x.send();
    } catch (e) {}
  }

  // Asynchronous marker, for the heartbeat only.
  function B(tag) {
    var url = BASE + '/beacon/V168-' + SESSION + '-' + tag + '?t=' + Date.now() +
      '&n=' + (++SEQ) + '&w=' + encodeURIComponent(location.search);
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
    '<style>@keyframes s{from{transform:rotate(0)}to{transform:rotate(360deg)}}' +
    '</style>';
  var PLAIN = '<div style="width:50px;height:50px;background:green"></div>';
  var NOWC = '<div style="width:50px;height:50px;background:green;' +
    'animation:s 10s linear infinite"></div>' +
    '<style>@keyframes s{from{transform:rotate(0)}to{transform:rotate(360deg)}}' +
    '</style>';

  var VARIANT = param('v', 'ANIM').toUpperCase();
  var CYCLES = parseInt(param('c', '1'), 10);

  // The popup loop, run in the innermost frame.
  function popupLoop(variant, cycles, body) {
    function done(tag) {
      S(tag);
      try { top.postMessage('V168-CHAIN-DONE', '*'); } catch (e) {}
    }

    function step(i) {
      if (i > cycles) { done('I-CYCLES-DONE'); return; }
      if (variant == 'NOPOPUP') { done('I-NOPOPUP-OK'); return; }
      var p = null;
      S('I-PRE-OPEN-' + i);
      try {
        p = window.open('about:blank', '', 'width=200,height=200');
      } catch (e) {
        p = null;
      }
      if (!p) { done('I-POPUP-BLOCKED'); return; }
      S('I-OPENED-' + i);
      try { p.document.body.innerHTML = body; } catch (e) {}
      S('I-BODY-' + i);
      if (variant == 'NOCLOSE') {
        setTimeout(function() { step(i + 1); }, 0);
        return;
      }
      requestAnimationFrame(function() {
        requestAnimationFrame(function() {
          S('I-PRE-CLOSE-' + i);
          try { p.close(); } catch (e) {}
          S('I-CLOSED-' + i);
          setTimeout(function() { step(i + 1); }, 0);
        });
      });
    }

    S('I-READY');
    step(1);
  }

  if (param('inner', '') == '1') {
    if (param('run', '') == '1') {
      popupLoop(VARIANT, CYCLES,
        VARIANT == 'PLAIN' ? PLAIN : VARIANT == 'NOWC' ? NOWC : ANIM);
    }
    return;
  }

  // Builds `depth` nested same-origin frames by navigation; the innermost one
  // runs the popup loop.
  function build(doc, depth, variant, cycles) {
    S('P-BUILD-' + depth + '-' + variant);
    var f = doc.createElement('iframe');
    f.style.cssText = 'width:200px;height:120px';
    f.src = '/probe/p168-popup-depth.js?inner=1&v=' +
      encodeURIComponent(variant) + '&c=' + cycles + '&s=' +
      encodeURIComponent(SESSION) + '&run=' + (depth == 1 ? '1' : '0');
    doc.body.appendChild(f);
    S('P-F1-APPENDED-' + depth);
    if (depth > 1) {
      f.onload = function() {
        S('P-F1-LOADED-' + depth);
        try {
          build(f.contentDocument, depth - 1, variant, cycles);
        } catch (e) {
          S('P-NEST-FAILED');
        }
      };
    }
  }

  // Chains run one after another: the next one starts when the previous one
  // reports that it is finished, so a death lands on a single chain. Each
  // entry is depth:variant[:cycles].
  var plan = param('chains', '1:ANIM,2:ANIM').split(',');
  var pi = 0;

  function nextChain() {
    if (pi >= plan.length) { S('P-PLAN-DONE'); return; }
    var spec = plan[pi++].split(':');
    var depth = parseInt(spec[0], 10);
    var variant = (spec[1] || 'ANIM').toUpperCase();
    var cycles = parseInt(spec[2] || CYCLES, 10);
    S('P-CHAIN-START-' + depth + '-' + variant + '-CYCLES-' + cycles);
    build(document, depth, variant, cycles);
  }

  window.addEventListener('message', function(e) {
    if (e.data == 'V168-CHAIN-DONE') nextChain();
  });

  nextChain();
  setInterval(function() { B('ALIVE'); }, 2000);
})();
