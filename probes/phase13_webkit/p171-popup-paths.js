// CRASH_CLASS: HIGH
// PROBE 171: which popup request paths kill the console's WebProcess
//
// Context: p169 and p170 show that every window.open() on this console is
// refused, and that the refusal kills the WebProcess within ~50 ms: at the
// top level, inside a child frame, with a real user gesture and without one.
// p171 adds the opposite case: on the console a popup request that goes
// through the navigation path really opens (the server sees the fetch), and
// that kills the browser too. So the death is not only the refusal path.
//
// This probe walks the ways a page can ask for a popup, in the order that
// separates the causes best:
//
//   SANDBOX  a sandboxed iframe calls window.open() - the sandbox refuses it
//            before the popup blocker is consulted
//   LINK     an <a target="_blank"> is clicked - the request goes through the
//            navigation path, not the window.open API; the popup really opens
//   STATIC   a link to a document with no script at all - a new browsing
//            context that runs nothing and never talks to the opener
//   SILENT   a link to a popup that runs script but never messages the opener
//   BLANK    a link to about:blank - a new context with no document load
//   NOOPENER window.open(..., 'noopener')
//   EMPTY    window.open(...)
//   FRAME    a same-origin child frame calls window.open()
//   NAMED    window.open(..., 'p171named')
//
// LINK, STATIC, SILENT and BLANK answer one question: is any new browsing
// context fatal, or only a context that runs script or that messages the
// opener? Their popups cannot report back, so the evidence that the popup
// was created is the server access log, not a message.
//
// Every other variant asks for a popup that points at this probe with
// ?child=1. The child posts a message when it really opens, so a refused
// popup and a popup that opened are told apart by evidence and not by the
// return value: window.open returns null for a noopener popup as well.
//
// The variants run in the order above and the harmless ones come first,
// because a refused popup ends the page: the variant that killed the browser
// is the last marker in the log. The server keeps the chain position, so
// reopening the guide resumes with the variant after the one that killed it.
//
// Query: ?from=N starts at variant N, ?only=NAME runs exactly one variant per
//        page load (the page then walks to the next variant by itself),
//        ?timeout=ms is how long a variant waits for its popup child
//        (default 2500).

(function () {
  var BASE = location.protocol + '//' + location.host;
  var SESSION = param('s', Math.random().toString(36).slice(2, 8));
  var SEQ = 0;

  function param(name, def) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : def;
  }

  function mk(tag) {
    var url = BASE + '/beacon/V171-' + SESSION + '-' + tag + '?t=' + Date.now() +
      '&n=' + (++SEQ) + '&w=' + encodeURIComponent(location.search);
    try {
      var x = new XMLHttpRequest();
      x.open('GET', url, false);
      x.send();
    } catch (e) {}
  }

  // The popup child is this same probe, loaded with ?child=1. It only reports
  // that it exists; every variant that needs a popup points here.
  if (param('child', '') == '1') {
    try {
      if (window.opener) window.opener.postMessage('P171-CHILD-OPENED', '*');
    } catch (e) {}
    return;
  }

  // ?child=2 is a popup that runs script but never talks to the opener. It
  // separates "the popup runs script" from "the popup messages the opener".
  if (param('child', '') == '2') {
    return;
  }

  // The order matters: a variant that kills the WebProcess ends the page, so
  // the variants that separate "a new browsing context is fatal" from "the
  // child page or the opener messaging is fatal" come first.
  //   STATIC   a link to a document with no script at all - the new window
  //            is created, and the child neither runs script nor talks back
  //   SILENT   a link to a popup that runs script but never messages the
  //            opener - a new context with script, without the handshake
  //   BLANK    a link to about:blank - a new context with no document load
  var VARIANTS = ['SANDBOX', 'LINK', 'STATIC', 'SILENT', 'BLANK',
                  'NOOPENER', 'EMPTY', 'FRAME', 'NAMED'];
  var CHILD = BASE + '/probe/p171-popup-paths.js?child=1';
  var CHILD_SILENT = BASE + '/probe/p171-popup-paths.js?child=2';
  var FROM = parseInt(param('from', '0'), 10) || 0;
  var TIMEOUT = parseInt(param('timeout', '2500'), 10) || 2500;
  // ?only=NAME runs exactly one variant per page load. On the console a
  // refused popup ends the page, so one variant per load is what tells the
  // variants apart: the guide is reopened after every crash.
  var ONLY = param('only', '');
  var START = FROM;
  var COUNT = VARIANTS.length - FROM;
  if (ONLY) {
    var oi = -1;
    for (var k = 0; k < VARIANTS.length; k++) {
      if (VARIANTS[k] === ONLY) { oi = k; break; }
    }
    if (oi < 0) {
      mk('ONLY-UNKNOWN');
      return;
    }
    START = oi;
    COUNT = 1;
  }

  var childOpened = false;
  var pending = null;

  window.addEventListener('message', function (ev) {
    if (ev.data !== 'P171-CHILD-OPENED') return;
    childOpened = true;
    var p = pending;
    pending = null;
    if (p) p('OPENED');
  });

  // Wait for the popup child to report itself. A popup that was refused
  // never reports, and the timeout is the evidence that it did not open.
  function withChild(done) {
    var settled = false;
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      pending = null;
      done(childOpened ? 'OPENED' : 'NO-REPLY');
    }, TIMEOUT);
    pending = function (res) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      done(res);
    };
  }

  function report(label, res) {
    mk(label + '-RESULT-' + res);
    mk(label + '-ALIVE');
  }

  // A sandboxed frame without allow-popups has its popup refused by the
  // sandbox. The frame has an opaque origin, so it reports back and the
  // parent cannot read it.
  function vSandbox(done) {
    var f = document.createElement('iframe');
    f.setAttribute('sandbox', 'allow-scripts');
    f.style.cssText = 'width:200px;height:80px;border:0';
    var settled = false;
    function finish(res) {
      if (settled) return;
      settled = true;
      window.removeEventListener('message', onMsg);
      report('SANDBOX', res);
      done();
    }
    function onMsg(ev) {
      if (typeof ev.data !== 'string') return;
      if (ev.data.indexOf('P171-SANDBOX:') !== 0) return;
      finish(ev.data.substring('P171-SANDBOX:'.length));
    }
    window.addEventListener('message', onMsg);
    try {
      f.srcdoc = '<script>try{var w=window.open("about:blank","_blank");' +
        'parent.postMessage("P171-SANDBOX:"+(w?"OPENED":"BLOCKED"),"*");}' +
        'catch(e){parent.postMessage("P171-SANDBOX:ERROR","*");}<\/script>';
    } catch (e) {}
    document.body.appendChild(f);
    setTimeout(function () { finish('NO-REPLY'); }, TIMEOUT);
  }

  // The navigation path: a link with target=_blank. The click is scripted, so
  // the popup blocker sees no gesture, but the request never touches the
  // window.open API.
  function vLink(done) {
    var a = document.createElement('a');
    a.href = CHILD;
    a.target = '_blank';
    a.textContent = 'p171 link';
    a.style.cssText = 'position:absolute;left:-9999px';
    document.body.appendChild(a);
    withChild(function (res) {
      report('LINK', res);
      done();
    });
    try {
      a.click();
    } catch (e) {
      mk('LINK-THREW');
    }
  }

  // A new browsing context that loads nothing: the link points at a plain
  // JSON document, so the popup has no script, never posts a message and
  // never touches the opener. The only thing that happens is that a second
  // page is created. The server access log shows whether the popup was
  // really fetched, so the evidence for "it opened" does not depend on the
  // child being able to talk back.
  function vStatic(done) {
    // A real document that runs no script. /blank.html is an empty HTML body,
    // not an application/json download, so the popup is rendered in a window
    // and the query string makes its fetch unique in the access log.
    vLinkTo(BASE + '/blank.html?t=' + Date.now(), 'STATIC', done);
  }

  // A new browsing context that runs script but never messages the opener:
  // the child is this probe with ?child=2. It separates "the popup runs
  // script" from "the popup messages the opener".
  function vSilent(done) {
    vLinkTo(CHILD_SILENT, 'SILENT', done);
  }

  // A new browsing context with no document load at all.
  function vBlank(done) {
    vLinkTo('about:blank', 'BLANK', done);
  }

  // Click a link that opens a new browsing context. The child cannot report
  // back, so the parent only says that the request was made and then that it
  // is still alive. Whether the popup was really created is read from the
  // server access log.
  function vLinkTo(url, label, done) {
    var a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.textContent = 'p171 ' + label;
    a.style.cssText = 'position:absolute;left:-9999px';
    document.body.appendChild(a);
    try {
      a.click();
    } catch (e) {
      mk(label + '-THREW');
    }
    setTimeout(function () {
      report(label, 'REQUESTED');
      done();
    }, TIMEOUT);
  }

  // The window.open API, with the three argument shapes that matter here.
  function vOpen(label, name, feature, done) {
    withChild(function (res) {
      report(label, res);
      done();
    });
    var w = null;
    try {
      w = window.open(CHILD, name, feature);
    } catch (e) {
      mk(label + '-THREW');
    }
    // A window that did open must not be left behind.
    if (w) {
      try { w.close(); } catch (e) {}
    }
  }

  // The request from a child frame. The frame runs its own script, so the
  // request comes from the frame and not from the parent.
  function vFrame(done) {
    var f = document.createElement('iframe');
    f.style.cssText = 'width:200px;height:80px;border:0';
    f.src = 'about:blank';
    document.body.appendChild(f);
    var settled = false;
    var started = false;
    function finish(res) {
      if (settled) return;
      settled = true;
      window.removeEventListener('message', onMsg);
      report('FRAME', res);
      done();
    }
    function onMsg(ev) {
      if (typeof ev.data !== 'string') return;
      if (ev.data.indexOf('P171-FRAME:') !== 0) return;
      finish(ev.data.substring('P171-FRAME:'.length));
    }
    window.addEventListener('message', onMsg);
    // The timer does not wait for the load event: a frame that never reports
    // must not leave the chain hanging.
    setTimeout(function () { finish('NO-REPLY'); }, TIMEOUT);
    function start() {
      if (started || settled) return;
      started = true;
      var doc = null;
      try { doc = f.contentDocument; } catch (e) {}
      if (!doc) {
        finish('NO-DOC');
        return;
      }
      try {
        doc.open();
        doc.write('<script>' +
          'window.addEventListener("message",function(e){' +
          'if(e.data==="P171-CHILD-OPENED")parent.postMessage("P171-FRAME:OPENED","*");});' +
          'try{var w=window.open("' + CHILD + '","_blank");' +
          'parent.postMessage("P171-FRAME:"+(w?"OPENED":"BLOCKED"),"*");}' +
          'catch(e){parent.postMessage("P171-FRAME:ERROR","*");}' +
          '<\/script>');
        doc.close();
      } catch (e) {
        finish('NO-DOC');
      }
    }
    f.onload = start;
    // The load event of an about:blank frame can have fired already.
    try {
      if (f.contentDocument && f.contentDocument.readyState === 'complete') start();
    } catch (e) {}
  }

  var RUNNERS = {
    SANDBOX: vSandbox,
    LINK: vLink,
    STATIC: vStatic,
    SILENT: vSilent,
    BLANK: vBlank,
    NOOPENER: function (done) { vOpen('NOOPENER', '_blank', 'noopener', done); },
    NAMED: function (done) { vOpen('NAMED', 'p171named', '', done); },
    EMPTY: function (done) { vOpen('EMPTY', '_blank', '', done); },
    FRAME: vFrame
  };

  function runVariant(i) {
    if (i >= START + COUNT) {
      mk(ONLY ? 'ONLY-DONE-' + ONLY : 'ALL-VARIANTS-DONE');
      return;
    }
    var name = VARIANTS[i];
    mk(name + '-START');
    RUNNERS[name](function () {
      // In single variant mode the page walks to the next variant by itself:
      // one page load per variant, so a variant that kills the WebProcess
      // cannot take the following variants down with it.
      if (ONLY && COUNT === 1 && i + 1 < VARIANTS.length) {
        mk('NEXT-' + VARIANTS[i + 1]);
        setTimeout(function () {
          try {
            location.href = '/probe/p171-popup-paths.js?only=' +
              encodeURIComponent(VARIANTS[i + 1]) + '&auto=1';
          } catch (e) {}
        }, 400);
        return;
      }
      runVariant(i + 1);
    });
  }

  mk('READY');
  mk('CHAIN-FROM-' + START);
  runVariant(START);
})();
