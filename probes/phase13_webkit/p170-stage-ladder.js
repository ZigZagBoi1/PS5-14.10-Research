// Stage ladder: one factor per stage, in the order that answers the open
// questions fastest.
//
// The console's browser dies in two observed situations, and the corpus
// harness needs both explained:
//
//   1. A refused window.open in a top-level page killed the WebProcess twice
//      (p169, 08:12 and 08:15). The upstream corpus case 30 also calls
//      window.open, from a nested document.
//   2. A nested frame chain died once (p168, 08:05) and survived once
//      (08:02), with no popup involved.
//
// So the ladder runs the frame stages first, because the top-level refusal is
// already established, and the frame stages are what blocks the corpus run.
// Every stage ends with a liveness marker several seconds after it started:
// if the marker never arrives, the browser died during that stage.
//
// Markers are synchronous XHRs, so a marker is on the server before the
// stage continues. The page has no other content, so a crash cannot be
// blamed on layout.
//
// Query: ?wait=<ms> per stage (default 4000), ?stages=<a,b,c> to run a
//        subset, ?v=1 to keep the stage list in the marker text.

(function () {
  var TAG = 'V170';
  var session = 's' + Math.random().toString(36).slice(2, 8);
  var seq = 0;
  var WAIT = parseInt(param('wait', '4000'), 10) || 4000;

  function param(name, dflt) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : dflt;
  }

  function S(tag) {
    // Synchronous on purpose: a marker must reach the server before the
    // next step of the ladder runs, or a death is attributed to the wrong
    // stage.
    var url = '/beacon/' + TAG + '-' + session + '-' + tag + '?t=' +
      Date.now() + '&n=' + (++seq) + '&w=' + encodeURIComponent(location.search);
    try {
      var x = new XMLHttpRequest();
      x.open('GET', url, false);
      x.send(null);
    } catch (e) {
      // Nothing to do: if the process is gone, the marker is lost anyway.
    }
  }

  function frame(doc, src, onload) {
    var f = doc.createElement('iframe');
    f.style.cssText = 'width:200px;height:120px;border:0;';
    f.src = src;
    f.onload = function () {
      try {
        onload(f);
      } catch (e) {
        S('STAGE-ERROR-' + e);
      }
    };
    doc.body.appendChild(f);
    return f;
  }

  var stages = [
    // 1. The page itself, with nothing on it.
    function (done) {
      S('BASE-START');
      setTimeout(function () {
        S('BASE-ALIVE');
        done();
      }, WAIT);
    },

    // 2. One same-origin child frame.
    function (done) {
      S('IFRAME-START');
      frame(document, '/blank.html', function (f) {
        S('IFRAME-LOADED');
        setTimeout(function () {
          S('IFRAME-ALIVE');
          done();
        }, WAIT);
      });
    },

    // 3. A frame inside a frame: the shape p168's chains build.
    function (done) {
      S('NESTED-START');
      frame(document, '/blank.html', function (outer) {
        var od = outer.contentDocument;
        S('NESTED-OUTER-LOADED');
        frame(od, '/blank.html', function (inner) {
          S('NESTED-INNER-LOADED');
          setTimeout(function () {
            S('NESTED-ALIVE');
            done();
          }, WAIT);
        });
      });
    },

    // 4. A refused window.open inside a child frame: the shape of corpus
    //    case 30, where the test document calls window.open and gets null.
    function (done) {
      S('IFRAME-POPUP-START');
      frame(document, '/blank.html', function (f) {
        var od = f.contentDocument;
        S('IFRAME-POPUP-FRAME-LOADED');
        var p = null;
        try {
          p = od.defaultView.open('about:blank', '', 'width=200,height=200');
        } catch (e) {
          p = null;
        }
        S(p ? 'IFRAME-POPUP-OPENED' : 'IFRAME-POPUP-REFUSED');
        setTimeout(function () {
          S('IFRAME-POPUP-ALIVE');
          done();
        }, WAIT);
      });
    },

    // 5. Twenty frames created and removed in a row.
    function (done) {
      S('CHURN-START');
      var i = 0;
      function step() {
        if (i >= 20) {
          S('CHURN-DONE');
          setTimeout(function () {
            S('CHURN-ALIVE');
            done();
          }, WAIT);
          return;
        }
        i++;
        var f = frame(document, '/blank.html', function (fr) {
          fr.parentNode.removeChild(fr);
        });
        setTimeout(step, 120);
      }
      step();
    },

    // 6. A refused window.open in this top-level page. Known to be fatal on
    //    the console, so it runs last.
    function (done) {
      S('POPUP-START');
      var p = null;
      try {
        p = window.open('about:blank', '', 'width=200,height=200');
      } catch (e) {
        p = null;
      }
      S(p ? 'POPUP-OPENED' : 'POPUP-REFUSED');
      setTimeout(function () {
        S('POPUP-ALIVE');
        done();
      }, WAIT);
    }
  ];

  var names = ['BASE', 'IFRAME', 'NESTED', 'IFRAME-POPUP', 'CHURN', 'POPUP'];
  var wanted = param('stages', '');
  var list = wanted
    ? wanted.split(',').map(function (n) {
        return names.indexOf(n.toUpperCase());
      }).filter(function (n) {
        return n >= 0;
      })
    : names.map(function (_, n) {
        return n;
      });

  S('LADDER-START');
  var idx = 0;
  function next() {
    if (idx >= list.length) {
      S('LADDER-DONE');
      return;
    }
    var n = list[idx++];
    S('STAGE-' + names[n] + '-BEGIN');
    try {
      stages[n](function () {
        S('STAGE-' + names[n] + '-END');
        setTimeout(next, 300);
      });
    } catch (e) {
      S('STAGE-' + names[n] + '-THREW');
      setTimeout(next, 300);
    }
  }
  next();
})();
