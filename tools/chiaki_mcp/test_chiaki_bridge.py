"""Guardrail tests; no live PS5 or desktop input is used."""

import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from chiaki_bridge import ChiakiBridge, ChiakiError, Frame


class FakeGui:
    @staticmethod
    def GetForegroundWindow():
        return 123

    @staticmethod
    def IsIconic(_hwnd):
        return False


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.bridge = ChiakiBridge()
        self.bridge.last_hwnd = 123
        self.frame = Frame(b"png", 100, 100, "hash", "token", time.monotonic(), 25, 10)
        self.bridge.last_frame = self.frame
        self.bridge.find_window = lambda: 123
        self.bridge._win = lambda: (FakeGui, None, None)

    def test_stale_and_reused_tokens_never_inject(self):
        with self.assertRaises(ChiakiError):
            self.bridge.press("cross", "wrong")
        self.assertIs(self.bridge.last_frame, self.frame)
        self.bridge.last_frame = Frame(b"png", 100, 100, "hash", "token", time.monotonic() - 11, 25, 10)
        with self.assertRaises(ChiakiError):
            self.bridge.press("cross", "token")

    def test_one_press_consumes_token_and_returns_new_frame(self):
        events = []
        fake_pyautogui = types.SimpleNamespace(keyDown=lambda k: events.append(("down", k)), keyUp=lambda k: events.append(("up", k)))
        next_frame = Frame(b"next", 100, 100, "new", "next-token", time.monotonic(), 30, 20)
        self.bridge.capture = lambda: next_frame
        with patch.dict(sys.modules, {"pyautogui": fake_pyautogui}), patch("chiaki_bridge.time.sleep"):
            result = self.bridge.press("cross", "token")
        self.assertEqual(events, [("down", "enter"), ("up", "enter")])
        self.assertIs(result, next_frame)
        with self.assertRaises(ChiakiError):
            self.bridge.press("cross", "token")

    def test_injection_failure_releases_key_and_invalidates_token(self):
        events = []
        fake_pyautogui = types.SimpleNamespace(keyDown=lambda k: events.append(("down", k)), keyUp=lambda k: events.append(("up", k)))
        with patch.dict(sys.modules, {"pyautogui": fake_pyautogui}), patch("chiaki_bridge.time.sleep", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                self.bridge.press("ps", "token")
        self.assertEqual(events, [("down", "esc"), ("up", "esc")])
        self.assertIsNone(self.bridge.last_frame)


if __name__ == "__main__":
    unittest.main()
