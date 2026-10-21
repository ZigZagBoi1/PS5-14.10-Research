#!/usr/bin/env python3
"""Tests for the JSC stage of tools/webkit_crash_corpus.py.

The stage that matters here is `jsc_build`: it turns a fetched test source into
the page the console loads, and a mistake in it is silent on the console (the
case loads, throws before its first assertion, and reports zero). These tests
pin the three things that decide whether a page is usable: directives and
`load()` are stripped, the shell shim is present, and a case that needs `$vm` is
dropped rather than shipped.

Run: python tools/test_webkit_crash_corpus.py
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import webkit_crash_corpus as corpus  # noqa: E402


class JscBuildTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.src = os.path.join(self.root, "jsc_src")
        os.makedirs(self.src)
        self._saved = (corpus.CORPUS, corpus.JSC_INDEX, corpus.JSC_SRC)
        corpus.CORPUS = self.root
        corpus.JSC_INDEX = os.path.join(self.root, "jsc_index.json")
        corpus.JSC_SRC = self.src

    def tearDown(self):
        corpus.CORPUS, corpus.JSC_INDEX, corpus.JSC_SRC = self._saved
        self.tmp.cleanup()

    def _write_source(self, name, text):
        with open(os.path.join(self.src, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def _write_index(self, entries):
        tests = {}
        for path, name in entries:
            tests[path] = {"path": path, "sha": "0" * 40, "date": "2026-01-01T00:00:00Z",
                           "subject": path.rsplit("/", 1)[-1], "file": name}
        with open(corpus.JSC_INDEX, "w", encoding="utf-8") as fh:
            json.dump({"commits": {}, "tests": tests, "skipped": {}}, fh)

    def test_directives_and_load_are_stripped(self):
        body = corpus._jsc_body("//@ skip if $architecture == 'x86'\n"
                                "load(\"utils.js\", \"message\")\n"
                                "var a = 1;\n")
        self.assertNotIn("//@", body)
        self.assertNotIn("load(", body)
        self.assertIn("var a = 1;", body)

    def test_page_carries_shim_and_body(self):
        self._write_source("case.js", "shouldBe(1 + 1, 2);\n")
        self._write_index([("JSTests/stress/case.js", "case.js")])
        corpus.jsc_build()
        pages = [n for n in os.listdir(self.root) if n.startswith("jsc-")]
        self.assertEqual(len(pages), 1)
        with open(os.path.join(self.root, pages[0]), encoding="utf-8") as fh:
            page = fh.read()
        self.assertIn("function shouldBe(", page)
        self.assertIn("shouldBe(1 + 1, 2);", page)
        self.assertIn("id=\"err\"", page)
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            listed = json.load(fh)
        self.assertEqual(listed, [{"path": "jsc", "file": pages[0], "subject": "case.js"}])

    def test_handoff_honours_the_batch_end(self):
        # The handoff used to navigate on unconditionally, so `count` bounded
        # nothing and a bounded run could never be measured. It also shadowed
        # the page's session object with the `v=` match, which threw before the
        # end-of-batch marker could be sent.
        self._write_source("case.js", "shouldBe(1, 1);\n")
        self._write_index([("JSTests/stress/case.js", "case.js")])
        corpus.jsc_build()
        pages = [n for n in os.listdir(self.root) if n.startswith("jsc-")]
        with open(os.path.join(self.root, pages[0]), encoding="utf-8") as fh:
            page = fh.read()
        self.assertIn("if (e && next >= +e[1]) { v.mark('BATCH-END-' + v.i); return; }", page)
        self.assertIn("var sv = /[?&]v=([A-Za-z0-9]+)/", page)
        self.assertIn("(sv ? sv[1] : '')", page)

    def test_dollar_vm_case_is_dropped(self):
        self._write_source("plain.js", "var x = 1;\n")
        self._write_source("vmcase.js", "noInline($vm.getRandomSeed);\n")
        self._write_index([("JSTests/stress/plain.js", "plain.js"),
                           ("JSTests/stress/vmcase.js", "vmcase.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            listed = json.load(fh)
        self.assertEqual([e["subject"] for e in listed], ["plain.js"])

    def test_shell_terminating_case_is_dropped(self):
        self._write_source("quitcase.js", "for (;;) { if (x) quit(0); }\n")
        self._write_source("detachcase.js", "transferArrayBuffer(v);\n")
        self._write_index([("JSTests/stress/quitcase.js", "quitcase.js"),
                           ("JSTests/stress/detachcase.js", "detachcase.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), [])

    def test_memory_limited_case_is_dropped(self):
        self._write_source("huge.js", "//@ skip if $memoryLimited\nconst s='x'.repeat(1e9);\n")
        self._write_index([("JSTests/stress/huge.js", "huge.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), [])

    def test_memory_limited_inside_a_compound_directive_is_dropped(self):
        # The tree spells the flag two ways; the console hung for minutes on the
        # compound form, which builds a 179 MB program before it asks for memory.
        self._write_source("huge2.js",
                           '//@ skip if $buildType == "debug" or $memoryLimited\n'
                           "const s = 'a();'.repeat(44739242);\n")
        self._write_index([("JSTests/stress/huge2.js", "huge2.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), [])

    def test_memory_hog_case_is_dropped(self):
        # `//@ memoryHog!` marks a case that allocates by design; the console
        # answered "there is not enough free system memory" on the first one it
        # reached, which asks Array.from for 268 million elements.
        self._write_source("hog.js",
                           "//@ memoryHog!\n//@ skip if $addressBits <= 32\n"
                           "function target() { arguments.length = 0x10000001;"
                           " return Array.from(arguments); }\n")
        self._write_index([("JSTests/stress/hog.js", "hog.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), [])

    def test_gigabyte_allocation_is_dropped(self):
        # The size is a named constant, so the filter has to follow the
        # definitions before it can see that this allocates four gigabytes.
        self._write_source("gigs.js",
                           "const oneGiga = 1024 * 1024 * 1024;\n"
                           "const fourGigs = 4 * oneGiga;\n"
                           "const buffer = new ArrayBuffer(fourGigs,"
                           " { maxByteLength: fourGigs });\n")
        self._write_index([("JSTests/stress/gigs.js", "gigs.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), [])

    def test_ordinary_allocation_is_kept(self):
        self._write_source("small.js", "const buffer = new ArrayBuffer(16);\n")
        self._write_index([("JSTests/stress/small.js", "small.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(len(json.load(fh)), 1)

    def test_watchdog_loop_is_dropped(self):
        # `runDefault("--watchdog=5000")` on a `for(;;)` is a test of the
        # engine's watchdog, which the browser does not have; the loop then runs
        # until the console says the page is not responding.
        self._write_source("wd.js",
                           '//@ runDefault("--watchdog=5000", "--watchdog-exception-ok")\n'
                           "for(;;){ class C {} }\n")
        self._write_index([("JSTests/stress/wd.js", "wd.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), [])

    def test_bounded_loop_with_a_watchdog_option_is_kept(self):
        self._write_source("wdb.js",
                           '//@ runDefault("--useJIT=0", "--watchdog=6000")\n'
                           "for (let i = 0; i < 10; i++) {}\n")
        self._write_index([("JSTests/stress/wdb.js", "wdb.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            self.assertEqual(len(json.load(fh)), 1)

    def test_slow_case_is_marked(self):
        self._write_source("slow.js", "//@ slow!\n//@ runDefault\nvar a = 1;\n")
        self._write_index([("JSTests/stress/slow.js", "slow.js")])
        corpus.jsc_build()
        with open(os.path.join(self.root, "jsc.json"), encoding="utf-8") as fh:
            entries = json.load(fh)
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].get("slow"))

    def test_rebuild_removes_stale_pages(self):
        self._write_source("a.js", "var a = 1;\n")
        self._write_index([("JSTests/stress/a.js", "a.js")])
        corpus.jsc_build()
        first = [n for n in os.listdir(self.root) if n.startswith("jsc-")]
        self._write_source("b.js", "var b = 2;\n")
        self._write_index([("JSTests/regress/b.js", "b.js")])
        corpus.jsc_build()
        second = [n for n in os.listdir(self.root) if n.startswith("jsc-")]
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
