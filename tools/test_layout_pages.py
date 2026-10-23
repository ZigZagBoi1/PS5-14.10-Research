"""Tests for the layout-test wrapper.

Each test pins a defect that actually cost a corpus run: a page whose own
<script> was never closed, a page that builds markup in a JavaScript string
containing `</body>`, an external script the wrapper had to drop, and a
hand-off that dropped the manifest name so the chain fell back to the wrong
corpus.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layout_pages  # noqa: E402

HANDOFF = "p172-jsc-corpus-runner.js"


class WrapTests(unittest.TestCase):
    def test_unclosed_script_is_closed(self):
        page = "<html><head></head><body><script>var a = 1;</body></html>"
        out = layout_pages.wrap(page, "x.html")
        self.assertEqual(len(re.findall(r"<script\b", out)), len(re.findall(r"</script\s*>", out)))

    def test_handoff_is_not_placed_inside_a_script_string(self):
        page = (
            "<html><head></head><body><script>\n"
            "var html = '<body><\\/body>';\n"
            "document.write(html);\n"
            "</script></body></html>"
        )
        out = layout_pages.wrap(page, "x.html")
        # the hand-off must land after the page's own script, not inside it
        self.assertGreater(out.index(HANDOFF), out.index("document.write(html);"))

    def test_external_script_tags_are_removed(self):
        page = '<html><head><script src="resources/js-test.js"></script></head><body></body></html>'
        self.assertNotIn("resources/js-test.js", layout_pages.wrap(page, "x.html"))

    def test_handoff_carries_the_requested_manifest(self):
        page = "<html><head></head><body></body></html>"
        self.assertIn("list=retest.json",
                      layout_pages.wrap(page, "x.html", "retest.json"))
        self.assertIn("list=layout.json", layout_pages.wrap(page, "x.html"))


if __name__ == "__main__":
    unittest.main()
