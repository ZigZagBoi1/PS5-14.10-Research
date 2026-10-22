// p166: CVE-2026-43720 Canvas getContext reentrancy oracle.
// Run as a standalone script in the PS5 guide browser or via fuzz.html.
// This probe does not force GC or access a potentially freed context.
// WebKit's fixed behavior is outer === inner for two nested 2D requests.
(function () {
  var PREFIX = 'P166-CANVAS-';
  var retained = window.__p166CanvasContexts || [];
  window.__p166CanvasContexts = retained;

  function emit(message) {
    var record = PREFIX + message;
    if (typeof window.log === 'function') {
      window.log(record);
      return;
    }
    try {
      var image = new Image();
      image.src = '/beacon?m=' + encodeURIComponent(record);
      retained.push(image);
    } catch (e) {
      // The on-screen record remains available if the beacon endpoint is absent.
    }
    var line = document.createElement('div');
    line.textContent = record;
    document.body.appendChild(line);
  }

  emit('START ua=' + navigator.userAgent.slice(0, 70));
  try {
    var controlCanvas = document.createElement('canvas');
    var controlA = controlCanvas.getContext('2d');
    var controlB = controlCanvas.getContext('2d');
    retained.push(controlCanvas, controlA, controlB);
    if (!controlA || controlA !== controlB) {
      emit('INCONCLUSIVE baseline-2d-identity-failed');
      return;
    }
    emit('CONTROL same=true');

    var canvas = document.createElement('canvas');
    var inner = null;
    var getterCalls = 0;
    var outer = canvas.getContext('2d', {
      get alpha() {
        getterCalls++;
        if (getterCalls === 1)
          inner = canvas.getContext('2d');
        return true;
      }
    });
    var current = canvas.getContext('2d');
    retained.push(canvas, inner, outer, current);
    emit('RESULT getter=' + getterCalls + ' inner=' + !!inner +
      ' outer=' + !!outer + ' same=' + (outer === inner) +
      ' currentOuter=' + (current === outer) +
      ' currentInner=' + (current === inner));

    if (!getterCalls || !inner || !outer || !current)
      emit('INCONCLUSIVE getter-or-context-unavailable');
    else if (outer === inner && current === outer)
      emit('FIXED-BEHAVIOR existing-context-reused');
    else if (outer !== inner && current === outer)
      emit('REPLACEMENT-BEHAVIOR distinct-contexts');
    else
      emit('INCONCLUSIVE unexpected-context-identity');
  } catch (error) {
    emit('THREW ' + error.name + ':' + String(error.message).slice(0, 100));
  }
  emit('DONE');
})();
