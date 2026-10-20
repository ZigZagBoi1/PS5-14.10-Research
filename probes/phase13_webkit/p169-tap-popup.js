// CRASH_CLASS: HIGH
// PROBE 169: gesture-driven popup loop, the upstream case-30 shape
//
// Context: upstream added fast/scrolling/mac/event-dispatcher-timer-close-crash.html
// with the fix for a heap-use-after-free of RemoteLayerTreeEventDispatcher's
// RunLoop::Timer on the scrolling thread. The test opens a popup holding an
// accelerated animation, waits two rAFs so the scrolling-thread display-link
// observer registers its 1 ms timer, closes the popup so the dispatcher is
// destroyed, and repeats 30 times.
//
// On this console every scripted window.open() so far came back null:
// p167 and p168 both report POPUP-BLOCKED. WebKit's popup blocker wants a
// user gesture, and a script has none. The upstream test cannot run its
// mechanism here while the blocker refuses, so the console's death on that
// case is a different thing and has to be separated from it.
//
// This probe asks the user for the one thing a script cannot fake: a tap.
// The page shows a single large button; the tap is a real user gesture, and
// the popup opens from the click handler, where WebKit allows a popup.
// The console is asked to press it, once per cycle, because the browser
// allows one popup per gesture and a gesture cannot be scripted.
//
// Each press runs the upstream shape once: open, write an accelerated
// animation, two rAFs so the scrolling-thread display-link observer
// registers, close so the dispatcher is destroyed. Every step is marked, and
// the markers are synchronous, so a death inside the close is attributed to
// the close and not to the step before it.
//
// Query: ?v=ANIM|PLAIN|NOWC|NOCLOSE (default ANIM), ?auto=1 runs one cycle
//        without a tap, to confirm that the gesture is what the popup blocker
//        wants.

(function () {
  var BASE = location.protocol + '//' + location.host;
  var SESSION = param('s', Math.random().toString(36).slice(2, 8));
  var SEQ = 0;

  function param(name, def) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : def;
  }

  function mk(tag, sync) {
    var url = BASE + '/beacon/V169-' + SESSION + '-' + tag + '?t=' + Date.now() +
      '&n=' + (++SEQ) + '&w=' + encodeURIComponent(location.search);
    try {
      var x = new XMLHttpRequest();
      x.open('GET', url, sync ? false : true);
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
  var CYCLES = parseInt(param('c', '30'), 10) || 30;
  var BODY = VARIANT == 'PLAIN' ? PLAIN : VARIANT == 'NOWC' ? NOWC : ANIM;

  // The probe is loaded as a script into the server's wrapper page, so it
  // builds its own control: one large button, big enough to hit with a
  // controller.
  (function buildUi() {
    if (!document.body) return;
    var box = document.createElement('div');
    box.style.cssText = 'margin:8px 0 16px 0;font:20px system-ui';
    var btn = document.createElement('button');
    btn.id = 'go';
    btn.textContent = 'TAP: one popup cycle (press it again for the next)';
    btn.style.cssText = 'font:28px system-ui;padding:28px 36px;width:100%;' +
      'max-width:520px;display:block;background:#1a6ef0;color:#fff;border:0';
    var status = document.createElement('div');
    status.id = 'out';
    status.style.cssText = 'margin-top:12px;font:18px system-ui';
    status.textContent = 'waiting for the tap';
    box.appendChild(btn);
    box.appendChild(status);
    document.body.insertBefore(box, document.body.firstChild);
  })();

  function say(line) {
    var o = document.getElementById('out');
    if (o) o.textContent = line;
  }

  // One upstream cycle per tap. The browser allows one popup per user gesture,
  // and a gesture cannot be faked, so the repetition has to come from the
  // controller: each press is a new gesture and a new popup.
  var cycle = 0;

  function runCycle(sync) {
    cycle++;
    mk('PRE-OPEN-' + cycle, sync);
    var p = null;
    try {
      p = window.open('about:blank', '', 'width=200,height=200');
    } catch (e) {
      p = null;
    }
    if (!p) {
      mk('POPUP-BLOCKED-' + cycle, sync);
      say('popup blocked at cycle ' + cycle);
      return;
    }
    mk('OPENED-' + cycle, sync);
    try { p.document.body.innerHTML = BODY; } catch (e) {}
    mk('BODY-' + cycle, sync);
    if (VARIANT == 'NOCLOSE') {
      say('cycle ' + cycle + ': popup left open');
      return;
    }
    requestAnimationFrame(function() {
      requestAnimationFrame(function() {
        mk('PRE-CLOSE-' + cycle, sync);
        try { p.close(); } catch (e) {}
        mk('CLOSED-' + cycle, sync);
        say('cycle ' + cycle + ' closed');
      });
    });
  }

  var button = document.getElementById('go');
  if (button) {
    button.onclick = function () {
      mk('TAP', true);
      say('running cycle ' + (cycle + 1));
      // The gesture is live here, so WebKit should allow the popup.
      runCycle(true);
    };
  }

  mk('READY', false);
  if (param('auto', '') == '1') {
    mk('AUTO', true);
    runCycle(true);
  }
})();
