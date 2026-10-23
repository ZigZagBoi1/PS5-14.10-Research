"""Turn the harvested LayoutTests into one page per case.

The corpus runner loads one document per case, marks BEFORE/OK and hands off to
the next index. LayoutTests files are full documents built for WebKitTestRunner,
so each one is wrapped: the shell shim defines `debug`/`shouldBe`/..., a stub
object absorbs `testRunner` and `internals` calls, and the boot/hand-off scripts
add the same markers the JavaScriptCore pages use.

`python tools/layout_pages.py` writes lay-<n>-<slug>.html plus layout.json.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from webkit_crash_corpus import CORPUS, JSC_BOOT, JSC_HANDOFF, JSC_SHIM_JS  # noqa: E402

INDEX = os.path.join(CORPUS, "index.json")
MANIFEST = os.path.join(CORPUS, "layout.json")

# WebKitTestRunner objects do not exist in a browser. A recursive proxy answers
# any property with a callable that returns another such proxy, so a test that
# calls `internals.settings.setX(true)` gets a harmless no-op instead of a
# TypeError before it reaches the code that was supposed to crash.
STUB = """
var testRunner = (function () {
  function any() {
    return new Proxy(function () {}, {
      get: function (t, k) {
        if (k === Symbol.toPrimitive) return function () { return 0; };
        if (k === 'toString') return function () { return ''; };
        return any();
      },
      apply: function () { return any(); },
      construct: function () { return any(); }
    });
  }
  return any();
})();
var internals = testRunner;
var accessibilityController = testRunner;
"""

EXTERNAL_SCRIPT = re.compile(r"<script[^>]*\bsrc\s*=\s*[\"'][^\"']*[\"'][^>]*>\s*</script>", re.I)


TAG = re.compile(r"</?(script|body|head)\b[^>]*>", re.I)


def _outside_script(source, needle):
    """Index of the first `needle` that is not inside a <script> block.

    Several crash tests build markup in a JavaScript string, and that string
    contains `</body>`. A plain rfind put the hand-off inside the literal, the
    page threw a SyntaxError and the chain sat on the case (lay-047).
    """
    in_script = False
    for m in TAG.finditer(source):
        if m.group(1).lower() == "script":
            in_script = not m.group(0).startswith("</")
        elif not in_script and m.group(0).lower().startswith(needle):
            return m.start()
    return -1


def wrap(source: str, name: str, list_name: str = "layout.json") -> str:
    body = EXTERNAL_SCRIPT.sub("", source)
    opens = len(re.findall(r"<script\b", body, re.I))
    closes = len(re.findall(r"</script\s*>", body, re.I))
    if opens > closes:
        body += "</script>" * (opens - closes)
    head = "<script>%s\n%s\n%s</script>\n" % (JSC_SHIM_JS, STUB, JSC_BOOT[len("<script>"):-len("</script>")])
    tail = JSC_HANDOFF % {"file": name}
    # The hand-off rebuilds the runner URL from the query string it was given,
    # and the layout manifest is not the runner's default, so it has to ride
    # along or the next page falls back to jsc.json.
    tail = tail.replace(
        "'/probe/p172-jsc-corpus-runner.js?start='",
        "'/probe/p172-jsc-corpus-runner.js?list=%s&start='" % list_name)
    at = _outside_script(body, "<head")
    if at >= 0:
        close = body.find(">", at)
        body = body[:close + 1] + "\n" + head + body[close + 1:]
    else:
        body = head + body
    end = _outside_script(body, "</body")
    if end >= 0:
        body = body[:end] + tail + body[end:]
    else:
        body = body + tail
    return body


def main() -> int:
    with open(INDEX, encoding="utf-8") as fh:
        index = json.load(fh)
    ready = [t for t in index["tests"].values() if t.get("file")]
    ready.sort(key=lambda t: t["path"])
    for stale in os.listdir(CORPUS):
        if re.match(r"lay-\d+-.*\.html$", stale):
            os.remove(os.path.join(CORPUS, stale))
    entries = []
    for n, test in enumerate(ready, 1):
        path = os.path.join(CORPUS, test["file"])
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        if not re.search(r"<html|<body|<script", source, re.I):
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", test["path"].rsplit("/", 1)[-1].lower()).strip("-")[:60]
        name = "lay-%03d-%s.html" % (n, slug)
        with open(os.path.join(CORPUS, name), "w", encoding="utf-8") as fh:
            fh.write(wrap(source, name))
        entries.append({"file": name, "subject": test["path"].rsplit("/", 1)[-1]})
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=1)
    print("built %d layout pages" % len(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
