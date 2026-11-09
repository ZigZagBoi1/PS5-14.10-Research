"""
Screen Analyzer — Detect PS5 state from screenshots.

Uses image hashing + pixel analysis for fast local detection,
with optional AI vision (Claude/OpenAI) for complex decisions.
"""
import os
import hashlib
import logging
import json
import base64
import subprocess

log = logging.getLogger("ps5remote.analyzer")


class ScreenState:
    UNKNOWN = "unknown"
    HOME_SCREEN = "home_screen"
    GAME_RUNNING = "game_running"
    GAME_CRASHED = "game_crashed"
    GAME_FROZEN = "game_frozen"
    ERROR_DIALOG = "error_dialog"
    LOADING = "loading"
    BLACK_SCREEN = "black_screen"
    REST_MODE = "rest_mode"
    SYSTEM_UPDATE = "system_update"
    CHIAKI_DISCONNECTED = "chiaki_disconnected"
    CHIAKI_CONNECTING = "chiaki_connecting"


def get_image_stats(image_path):
    try:
        from PIL import Image
        import statistics
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())
        r_vals = [p[0] for p in pixels[::100]]
        g_vals = [p[1] for p in pixels[::100]]
        b_vals = [p[2] for p in pixels[::100]]
        avg_brightness = sum(r_vals + g_vals + b_vals) / (len(r_vals) * 3)
        variance = statistics.variance(r_vals[:1000]) if len(r_vals) > 1 else 0
        return {
            "brightness": avg_brightness,
            "variance": variance,
            "width": img.width,
            "height": img.height,
        }
    except ImportError:
        return _get_stats_sips(image_path)


def _get_stats_sips(image_path):
    try:
        result = subprocess.run(
            ["sips", "-g", "pixelWidth", "-g", "pixelHeight", image_path],
            capture_output=True, text=True, timeout=5
        )
        w, h = 0, 0
        for line in result.stdout.split("\n"):
            if "pixelWidth" in line:
                w = int(line.split(":")[-1].strip())
            if "pixelHeight" in line:
                h = int(line.split(":")[-1].strip())
        return {"brightness": -1, "variance": -1, "width": w, "height": h}
    except Exception:
        return {"brightness": -1, "variance": -1, "width": 0, "height": 0}


def image_hash(image_path):
    with open(image_path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


class ScreenAnalyzer:
    def __init__(self, ai_provider=None, api_key=None):
        self.ai_provider = ai_provider
        self.api_key = api_key
        self.last_hash = None
        self.same_hash_count = 0
        self.freeze_threshold = 5

    def detect_basic(self, image_path):
        if not os.path.exists(image_path):
            return ScreenState.UNKNOWN

        current_hash = image_hash(image_path)
        if current_hash == self.last_hash:
            self.same_hash_count += 1
        else:
            self.same_hash_count = 0
            self.last_hash = current_hash

        stats = get_image_stats(image_path)

        if stats["brightness"] >= 0:
            if stats["brightness"] < 5:
                return ScreenState.BLACK_SCREEN
            if stats["variance"] < 10 and stats["brightness"] < 20:
                return ScreenState.BLACK_SCREEN

        if self.same_hash_count >= self.freeze_threshold:
            return ScreenState.GAME_FROZEN

        return ScreenState.UNKNOWN

    def detect_with_ai(self, image_path):
        basic = self.detect_basic(image_path)
        if basic in (ScreenState.BLACK_SCREEN, ScreenState.GAME_FROZEN):
            return basic

        if not self.api_key:
            return basic

        return self._ask_ai(image_path)

    def _ask_ai(self, image_path):
        if self.ai_provider == "anthropic":
            return self._ask_claude(image_path)
        return ScreenState.UNKNOWN

    def _ask_claude(self, image_path):
        try:
            import anthropic
            with open(image_path, "rb") as f:
                img_data = base64.standard_b64encode(f.read()).decode()

            ext = os.path.splitext(image_path)[1].lower()
            media_type = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}.get(ext.lstrip("."), "image/png")

            client = anthropic.Anthropic(api_key=self.api_key)
            resp = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=200,
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": img_data}},
                        {"type": "text", "text": (
                            "This is a screenshot of a PS5 via Remote Play. "
                            "Classify it as exactly ONE of: home_screen, game_running, game_crashed, "
                            "error_dialog, loading, black_screen, system_update, chiaki_disconnected, chiaki_connecting. "
                            "Reply with ONLY the classification word, nothing else."
                        )}
                    ]
                }]
            )
            state = resp.content[0].text.strip().lower()
            if state in (ScreenState.HOME_SCREEN, ScreenState.GAME_RUNNING, ScreenState.GAME_CRASHED,
                         ScreenState.ERROR_DIALOG, ScreenState.LOADING, ScreenState.BLACK_SCREEN,
                         ScreenState.SYSTEM_UPDATE, ScreenState.CHIAKI_DISCONNECTED, ScreenState.CHIAKI_CONNECTING):
                return state
            return ScreenState.UNKNOWN
        except Exception as e:
            log.error(f"Claude vision failed: {e}")
            return ScreenState.UNKNOWN

    def analyze(self, image_path, use_ai=False):
        if use_ai and self.api_key:
            return self.detect_with_ai(image_path)
        return self.detect_basic(image_path)
