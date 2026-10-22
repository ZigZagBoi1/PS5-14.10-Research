/*
 * p448: where the font-face path stops.
 *
 * p447 reached A-FACE-found and then the WebProcess died of memory exhaustion.
 * The three statements after that marker are:
 *
 *   var loadedA = faceA.loaded;      M1 after this
 *   Object.defineProperty(...)       M2
 *   faceA.load();                    M3, with the getter count in the marker
 *
 * This probe puts a marker after each one, and a second trigger whose getter
 * removes the style element but does not force layout, so the layout is
 * separated from the removal.
 *
 * The getter counts its own entries and caps them: after 2000 entries it
 * returns without touching the document. If the cap is reached and the page
 * survives, the loop is bounded by our own code and the exhaustion is not the
 * engine's. If the marker never appears, the engine re-entered before the cap
 * could be reached.
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
    if (typeof FontFace === 'undefined' || !document.fonts) { mark('API-no'); return; }

    function makeFace(family, styleId) {
        var st = document.createElement('style');
        if (styleId) st.id = styleId;
        st.textContent = '@font-face { font-family: ' + family + '; src: local(Helvetica); }';
        document.head.appendChild(st);
        document.body.offsetHeight;
        var face = null;
        document.fonts.forEach(function (f) {
            if (f.family && f.family.replace(/['"]/g, '') === family) face = f;
        });
        return face;
    }

    var dummy = document.createElement('style');
    dummy.id = 'v';
    dummy.textContent = 'x{}';
    document.head.appendChild(dummy);
    document.body.offsetHeight;
    mark('SETUP');

    var faceA = makeFace('ffA');
    mark('FACE-' + (faceA ? 'found' : 'missing'));
    if (!faceA) { mark('DONE'); return; }

    var loadedA = faceA.loaded;
    mark('M1-loaded');

    var fired = 0;
    var capped = false;
    Object.defineProperty(FontFace.prototype, 'then', {
        get: function () {
            fired++;
            if (fired > 2000) { capped = true; return undefined; }
            var t = document.getElementById('v');
            if (t) t.remove();
            document.body.offsetHeight;
            return undefined;
        },
        configurable: true
    });
    mark('M2-getter');

    faceA.load();
    mark('M3-load-returned-fired=' + fired + '-capped=' + capped);
    delete FontFace.prototype.then;

    setTimeout(function () { mark('DONE-fired=' + fired); }, 1000);
})();
