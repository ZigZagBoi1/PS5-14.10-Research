/*
 * p450: is the layout inside a promise "then" getter enough on its own?
 *
 * p449 separated two font-face triggers:
 *
 *   ffB  getter removes a real element, no layout   -> returned, fired=1
 *   ffA  getter removes a real element and lays out -> never returned
 *
 * So the forced layout is what starts it, and with the getter capped at 4 the
 * engine still never came back, which means the loop is not JS re-entry: once
 * the promise has been resolved, our getter cannot run again.
 *
 * This probe asks whether the loop needs CSSFontFace at all. A plain resolved
 * promise with a thenable whose getter removes an element and forces layout is
 * enough, or it is not:
 *
 *   C  Promise.resolve(thenable) with a layout getter   -> C-returned or hang
 *   D  the font-face trigger (p449 block A) for reference -> D-returned or hang
 *
 * If C hangs, the defect is in the promise/layout path and any page can reach
 * it. If C returns and D hangs, it belongs to the font-face status path.
 */
(function () {
    var s = 'ff';
    try {
        s = sessionStorage.getItem('v172s') || Math.random().toString(36).slice(2, 8);
        sessionStorage.setItem('v172s', s);
    } catch (e) {}

    function mark(tag) {
        var url = location.origin + '/beacon/V172-' + s + '-' + tag + '?t=' + Date.now();
        try {
            var x = new XMLHttpRequest();
            x.open('GET', url, false);
            x.send();
        } catch (e) {
            try { navigator.sendBeacon(url); } catch (e2) {}
        }
    }

    mark('BOOT');

    /* ---- C: a plain resolved promise ---------------------------------- */
    var dummyC = document.createElement('style');
    dummyC.id = 'd-C';
    dummyC.textContent = 'x{}';
    document.head.appendChild(dummyC);
    document.body.offsetHeight;

    var gotC = 0;
    var thenableC = {};
    Object.defineProperty(thenableC, 'then', {
        get: function () {
            gotC++;
            var t = document.getElementById('d-C');
            if (t) t.remove();
            document.body.offsetHeight;
            return undefined;
        }
    });
    mark('C-issued');
    Promise.resolve(thenableC);
    mark('C-returned-got=' + gotC);

    /* ---- D: the font-face trigger ------------------------------------- */
    if (typeof FontFace === 'undefined' || !document.fonts) { mark('API-no'); return; }

    var st = document.createElement('style');
    st.textContent = '@font-face { font-family: ffD; src: local(Helvetica); }';
    document.head.appendChild(st);
    document.body.offsetHeight;

    var face = null;
    document.fonts.forEach(function (f) {
        if (f.family && f.family.replace(/['"]/g, '') === 'ffD') face = f;
    });
    mark('D-face-' + (face ? 'found' : 'missing'));
    if (!face) { mark('DONE'); return; }

    var dummyD = document.createElement('style');
    dummyD.id = 'd-D';
    dummyD.textContent = 'x{}';
    document.head.appendChild(dummyD);
    document.body.offsetHeight;

    var loaded = face.loaded;
    var gotD = 0;
    Object.defineProperty(FontFace.prototype, 'then', {
        get: function () {
            gotD++;
            if (gotD > 4) return undefined;
            var t = document.getElementById('d-D');
            if (t) t.remove();
            document.body.offsetHeight;
            return undefined;
        },
        configurable: true
    });
    mark('D-issued');
    face.load();
    mark('D-returned-got=' + gotD);
    delete FontFace.prototype.then;

    setTimeout(function () { mark('DONE'); }, 800);
})();
