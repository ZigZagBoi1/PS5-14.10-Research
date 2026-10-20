// CRASH_CLASS: LOW
// PROBE 163: browser capability map
//
// Context: docs/WEBKIT_FINDINGS.md lists WebAssembly, SharedArrayBuffer, WebGL,
// WebAudio, IndexedDB and ServiceWorker as unavailable, and says the JIT is disabled
// with only LLInt running. That list is inherited prose with no artifact behind it,
// and it decides which bug classes are worth hunting at all: a JIT bug is only
// reachable if the optimising tiers run, and an off-heap Wasm OOB only exists if
// Wasm compiles. This probe measures those capabilities instead of assuming them.
//
// JIT detection is behavioural, because there is no status API in a page. A warm
// function costs roughly the same per iteration under LLInt only; once DFG or FTL
// takes over, per-iteration cost drops by an order of magnitude. Six batches of the
// same loop are timed and the per-batch nanoseconds are reported, so the shape of
// the curve is visible rather than a single yes/no.
//
// Nothing allocated here except a 16x16 canvas and a tiny Wasm module.

(function() {
  var BASE = location.protocol + '//' + location.host;

  function B(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V163-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch (e) {}
  }

  function probe(name, fn) {
    try {
      return name + '=' + fn();
    } catch (e) {
      return name + '=throw:' + ((e && e.name) || 'Error');
    }
  }

  B('BOOT');

  // ── JIT: six timed batches of the same integer loop ──
  function hot(n) {
    var x = 0;
    for (var i = 0; i < n; i++) x = (x + i) | 0;
    return x;
  }

  var JIT_N = 2000000;
  var timings = [];
  hot(200000); // warm the function itself, not enough to tier up
  for (var b = 0; b < 6; b++) {
    var t0 = performance.now();
    hot(JIT_N);
    var t1 = performance.now();
    timings.push(((t1 - t0) * 1e6 / JIT_N).toFixed(2));
  }
  B('V163-JIT-' + timings.join(','));

  // ── Capabilities ──
  var caps = [];

  caps.push(probe('wasm', function() { return typeof WebAssembly; }));
  caps.push(probe('wasmCompile', function() {
    // smallest valid module: magic, version, empty section 1 (type)
    var bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
    if (typeof WebAssembly === 'undefined') return 'absent';
    var m = new WebAssembly.Module(bytes);
    return WebAssembly.Module.exports(m) ? 'ok' : 'ok';
  }));
  caps.push(probe('wasmStreaming', function() { return typeof WebAssembly.instantiateStreaming; }));

  caps.push(probe('sab', function() { return typeof SharedArrayBuffer; }));
  caps.push(probe('sabNew', function() {
    if (typeof SharedArrayBuffer === 'undefined') return 'absent';
    var s = new SharedArrayBuffer(16);
    return s.byteLength === 16 ? 'ok' : 'badlen';
  }));
  caps.push(probe('atomics', function() { return typeof Atomics; }));
  caps.push(probe('crossOriginIsolated', function() { return String(self.crossOriginIsolated); }));

  caps.push(probe('webgl', function() {
    var c = document.createElement('canvas');
    c.width = 16; c.height = 16;
    var gl = c.getContext('webgl');
    if (!gl) return 'absent';
    var ext = gl.getExtension('WEBGL_debug_renderer_info');
    return ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : 'no-debug-ext';
  }));
  caps.push(probe('webgl2', function() {
    var c = document.createElement('canvas');
    c.width = 16; c.height = 16;
    return c.getContext('webgl2') ? 'ok' : 'absent';
  }));
  caps.push(probe('webgpu', function() { return typeof navigator.gpu; }));
  caps.push(probe('offscreen', function() { return typeof OffscreenCanvas; }));

  caps.push(probe('webaudio', function() { return typeof (window.AudioContext || window.webkitAudioContext); }));
  caps.push(probe('indexedDB', function() { return typeof indexedDB; }));
  caps.push(probe('serviceWorker', function() { return typeof navigator.serviceWorker; }));
  caps.push(probe('rtc', function() { return typeof RTCPeerConnection; }));
  caps.push(probe('webcodecs', function() { return typeof VideoEncoder; }));
  caps.push(probe('cacheStorage', function() { return typeof caches; }));
  caps.push(probe('notification', function() { return typeof Notification; }));
  caps.push(probe('geolocation', function() { return typeof navigator.geolocation; }));
  caps.push(probe('usb', function() { return typeof navigator.usb; }));
  caps.push(probe('bluetooth', function() { return typeof navigator.bluetooth; }));
  caps.push(probe('gamepad', function() { return typeof navigator.getGamepads; }));

  caps.push(probe('worker', function() { return typeof Worker; }));
  caps.push(probe('blobWorker', function() {
    if (typeof Worker === 'undefined') return 'absent';
    var url = URL.createObjectURL(new Blob(['onmessage=function(){}'], { type: 'text/javascript' }));
    var w = new Worker(url);
    var ok = typeof w.postMessage === 'function';
    w.terminate();
    URL.revokeObjectURL(url);
    return ok ? 'ok' : 'bad';
  }));
  caps.push(probe('rab', function() {
    var b = new ArrayBuffer(16, { maxByteLength: 64 });
    b.resize(64);
    return b.byteLength === 64 ? 'ok' : 'badlen';
  }));
  caps.push(probe('crypto', function() { return typeof crypto.subtle; }));
  caps.push(probe('compression', function() { return typeof CompressionStream; }));
  caps.push(probe('presentation', function() { return typeof PresentationRequest; }));

  B('V163-CAPS-' + caps.join(','));

  // Dynamic import is the one probe that has to be asynchronous.
  try {
    import('data:text/javascript,export default 1').then(function(m) {
      B('V163-IMPORT-' + (m && m.default === 1 ? 'ok' : 'bad'));
    }, function(e) {
      B('V163-IMPORT-reject:' + ((e && e.name) || 'Error'));
    });
  } catch (e) {
    B('V163-IMPORT-throw:' + ((e && e.name) || 'Error'));
  }

  setTimeout(function() { B('V163-DONE'); }, 250);
})();
