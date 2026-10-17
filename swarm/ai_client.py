"""AI client — wraps OpenCode Zen API or Anthropic API for agent inference."""

import json
import time
import threading
import logging
import subprocess
import os

logger = logging.getLogger("swarm")

class AIClient:
    """Calls AI models via OpenCode's Zen API (free tier) or Anthropic API."""

    def __init__(self, model: str, api_key: str = "", use_opencode: bool = True):
        self.model = model
        self.api_key = api_key
        self.use_opencode = use_opencode
        self._rate_limiter = threading.Semaphore(20)  # max concurrent calls
        self.total_calls = 0
        self.total_errors = 0

    def chat(self, prompt: str, system: str = None, max_tokens: int = 4096) -> str:
        self._rate_limiter.acquire()
        try:
            if self.use_opencode:
                return self._call_opencode(prompt, system, max_tokens)
            else:
                return self._call_anthropic(prompt, system, max_tokens)
        except Exception as e:
            self.total_errors += 1
            logger.error(f"AI call failed ({self.model}): {e}")
            return ""
        finally:
            self._rate_limiter.release()
            self.total_calls += 1

    def _call_opencode(self, prompt: str, system: str, max_tokens: int) -> str:
        """Call via OpenCode Zen API (free models)."""
        import urllib.request
        import urllib.error

        # OpenCode Zen API endpoint
        url = "https://opencode.ai/zen/v1/chat/completions"

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
        }
        # Add API key if available (some Zen models need it)
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            logger.error(f"OpenCode API error {e.code}: {body[:200]}")
            # Retry with backoff
            time.sleep(5)
            return ""
        except Exception as e:
            logger.error(f"OpenCode API error: {e}")
            return ""

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
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return ""
