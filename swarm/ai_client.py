"""AI client — calls LLMs via opencode CLI (free, no API key), OpenRouter, or Anthropic API."""

import json
import time
import threading
import logging
import subprocess
import os
import tempfile

logger = logging.getLogger("swarm")


class AIClient:
    """Calls AI models. Priority order:
    1. opencode CLI (free, no key needed — uses user's OpenCode session)
    2. OpenRouter free models (free key, no credit card)
    3. Anthropic API (paid, needs key)
    """

    def __init__(self, model: str, api_key: str = "", use_opencode: bool = True):
        self.model = model
        self.api_key = api_key
        self.use_opencode = use_opencode
        self.openrouter_key = os.environ.get("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_KEY", ""))
        self._rate_limiter = threading.Semaphore(20)
        self.total_calls = 0
        self.total_errors = 0
        self._backend = self._pick_backend()

    def _pick_backend(self) -> str:
        if self.use_opencode and self._opencode_available():
            return "opencode_cli"
        if self.openrouter_key:
            return "openrouter"
        if self.api_key:
            return "anthropic"
        # Fallback: try opencode CLI anyway, then openrouter keyless (will fail gracefully)
        return "opencode_cli"

    def _opencode_available(self) -> bool:
        try:
            r = subprocess.run(["opencode", "--version"], capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def chat(self, prompt: str, system: str = None, max_tokens: int = 4096) -> str:
        self._rate_limiter.acquire()
        try:
            if self._backend == "opencode_cli":
                result = self._call_opencode_cli(prompt, system)
                if result:
                    return result
                # Fallback to API methods
                if self.openrouter_key:
                    return self._call_openrouter(prompt, system, max_tokens)
                if self.api_key:
                    return self._call_anthropic(prompt, system, max_tokens)
                return self._call_openrouter_free(prompt, system, max_tokens)
            elif self._backend == "openrouter":
                return self._call_openrouter(prompt, system, max_tokens)
            else:
                return self._call_anthropic(prompt, system, max_tokens)
        except Exception as e:
            self.total_errors += 1
            logger.error(f"AI call failed ({self.model}): {e}")
            return ""
        finally:
            self._rate_limiter.release()
            self.total_calls += 1

    def _call_opencode_cli(self, prompt: str, system: str) -> str:
        """Call via the opencode CLI — free, no API key needed."""
        try:
            full_prompt = prompt
            if system:
                full_prompt = f"[System: {system}]\n\n{prompt}"

            # Write prompt to temp file to avoid shell escaping issues
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
                f.write(full_prompt)
                tmp_path = f.name

            try:
                result = subprocess.run(
                    ["opencode", "chat", "--model", self.model, "--file", tmp_path],
                    capture_output=True, text=True, timeout=180, encoding='utf-8'
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
                logger.warning(f"opencode CLI returned {result.returncode}: {result.stderr[:200]}")
            finally:
                os.unlink(tmp_path)

        except subprocess.TimeoutExpired:
            logger.warning("opencode CLI timed out (180s)")
        except FileNotFoundError:
            logger.warning("opencode CLI not found in PATH")
        except Exception as e:
            logger.warning(f"opencode CLI error: {e}")
        return ""

    def _call_openrouter(self, prompt: str, system: str, max_tokens: int) -> str:
        """Call via OpenRouter API (free models available with free key)."""
        import urllib.request
        import urllib.error

        url = "https://openrouter.ai/api/v1/chat/completions"

        # Map our model names to OpenRouter model IDs
        or_model = self._map_to_openrouter(self.model)

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": or_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.openrouter_key}",
            "HTTP-Referer": "https://github.com/ZigZagBoi1/PS5-14.10-Research",
        }

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            logger.error(f"OpenRouter API error {e.code}: {body[:200]}")
            time.sleep(5)
            return ""

    def _call_openrouter_free(self, prompt: str, system: str, max_tokens: int) -> str:
        """Try OpenRouter free models without a key (likely fails, but worth trying)."""
        try:
            return self._call_openrouter(prompt, system, max_tokens)
        except Exception:
            logger.error("No working AI backend — set OPENROUTER_API_KEY (free, no credit card at openrouter.ai)")
            return ""

    def _map_to_openrouter(self, model: str) -> str:
        """Map swarm model names to OpenRouter model IDs."""
        # Smart = 550B Nemotron Ultra, Fast = Nemotron Lightning, Haiku = Gemma 4
        smart = "nvidia/nemotron-3-ultra-550b-a55b:free"
        fast = "nvidia/nemotron-3.5-lightning:free"
        small = "google/gemma-4-26b-a4b-it:free"

        mapping = {
            "deepseek-v4-flash-free": fast,
            "deepseek-v4-flash": fast,
            "big-pickle": smart,
            "nemotron-3-super-free": fast,
        }
        return mapping.get(model, fast)

    def _call_anthropic(self, prompt: str, system: str, max_tokens: int) -> str:
        """Call via Anthropic Messages API."""
        import urllib.request
        import urllib.error

        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["content"][0]["text"]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            logger.error(f"Anthropic API error {e.code}: {body[:200]}")
            time.sleep(5)
            return ""
