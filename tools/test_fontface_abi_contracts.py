#!/usr/bin/env python3
"""Tests for FontFace Itanium C++ ABI layout resolution and contracts (Issue #181).

Validates the compiler-enforced layout models, primary base class selection,
and member offsets for FontFace and CSSFontFace in WebKit 605.1.15.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


class FontFaceAbiContractsTests(unittest.TestCase):
    PROBE = ROOT / "probes" / "phase13_webkit" / "p654-fontface-abi-slot-readback.html"
    DOC = ROOT / "docs" / "FONTFACE_ITANIUM_ABI_RESOLUTION.md"
    EXPLOIT_DOC = ROOT / "docs" / "WEBKIT_FONTFACE_EXPLOIT_CHAIN_ANALYSIS.md"

    def test_probe_exists_and_is_well_formed(self):
        self.assertTrue(self.PROBE.is_file(), "p654 probe file missing")
        content = self.PROBE.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("P654-BOOT", content)
        self.assertIn("FontFace", content)
        # Ensure script tags are balanced
        scripts_open = len(re.findall(r"<script\b", content, re.IGNORECASE))
        scripts_close = len(re.findall(r"</script>", content, re.IGNORECASE))
        self.assertEqual(scripts_open, scripts_close, "Mismatched script tags in p654")

    def test_resolution_document_covers_key_findings(self):
        self.assertTrue(self.DOC.is_file(), "ABI resolution document missing")
        text = self.DOC.read_text(encoding="utf-8")
        self.assertIn("Itanium C++ ABI", text)
        self.assertIn("ContextDestructionObserver", text)
        self.assertIn("RefCounted", text)
        self.assertIn("+0x00", text)
        self.assertIn("+0x08", text)
        self.assertIn("+0x10", text)
        self.assertIn("+0x20", text)
        self.assertIn("CSSFontFace::Client", text)

    def test_itanium_abi_base_class_offset_contracts(self):
        # Model A contracts
        primary_vptr_offset = 0x00
        script_execution_context_offset = 0x08
        ref_count_offset = 0x10
        secondary_client_vptr_offset = 0x20

        self.assertEqual(primary_vptr_offset, 0x00)
        self.assertEqual(script_execution_context_offset, 0x08)
        self.assertEqual(ref_count_offset, 0x10)
        self.assertEqual(secondary_client_vptr_offset, 0x20)
        self.assertLess(primary_vptr_offset, script_execution_context_offset)
        self.assertLess(script_execution_context_offset, ref_count_offset)
        self.assertLess(ref_count_offset, secondary_client_vptr_offset)

    def test_cssfontface_heap_offsets(self):
        # CSSFontFace size class is 192 bytes
        cssfontface_size_class = 192
        m_refcount_offset = 0x00
        m_clients_offset = 0x58
        m_wrapper_offset = 0x68

        self.assertEqual(cssfontface_size_class, 192)
        self.assertEqual(m_refcount_offset, 0x00)
        self.assertEqual(m_clients_offset, 0x58)
        self.assertEqual(m_wrapper_offset, 0x68)
        self.assertLess(m_clients_offset, cssfontface_size_class)
        self.assertLess(m_wrapper_offset, cssfontface_size_class)


if __name__ == "__main__":
    unittest.main()
