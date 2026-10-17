"""AI client — uses OpenCode CLI (free models, no API key) as primary backend."""

import json
import time
import threading
import logging
import subprocess
import os

logger = logging.getLogger("swarm")

OPENCODE_CLI = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "Programs", "@opencodedesktop", "resources", "opencode-cli.exe"
)


class AIClient:
    """Calls AI models via OpenCode CLI (free, no key needed).

    Primary: opencode-cli.exe run --model <model> --format json
    Fallback: OpenRouter API (if OPENROUTER_API_KEY set)
    """

    def __init__(self, model: str, api_key: str = "", use_opencode: bool = True):
        self.model = model
        self.api_key = api_key
        self.use_opencode = use_opencode
        self.openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
        self._rate_limiter = threading.Semaphore(20)
        self.total_calls = 0
        self.total_errors = 0
        self._cli_path = OPENCODE_CLI if os.path.isfile(OPENCODE_CLI) else None
        self._opencode_model = self._map_to_opencode(model)
        self._openrouter_model = self._map_to_openrouter(model)

    def _map_to_opencode(self, model: str) -> str:
        """Map config model names to OpenCode model IDs."""
        mapping = {
            "nemotron-ultra-550b": "opencode/nemotron-3-ultra-free",
            "nemotron-lightning": "opencode/nemotron-3.5-lightning-free",
            "gemma-4-26b": "opencode/deepseek-v4.1-flash-free",
            "deepseek-v4.1-flash": "opencode/deepseek-v4.1-flash-free",
        }
        return mapping.get(model, "opencode/deepseek-v4.1-flash-free")

    def _map_to_openrouter(self, model: str) -> str:
        """Fallback: map to OpenRouter model IDs."""
        mapping = {
            "nemotron-ultra-550b": "nvidia/nemotron-3-ultra-550b-a55b:free",
            "nemotron-lightning": "nvidia/nemotron-3.5-lightning:free",
            "gemma-4-26b": "google/gemma-4-26b-a4b-it:free",
        }
        return mapping.get(model, "nvidia/nemotron-3.5-lightning:free")

    def chat(self, prompt: str, system: str = None, max_tokens: int = 4096) -> str:
        self._rate_limiter.acquire()
        try:
            # OpenRouter API is primary (handles concurrency well)
            if self.openrouter_key:
                result = self._call_openrouter(prompt, system, max_tokens)
                if result:
                    return result

            # Fallback to OpenCode CLI (free but serialized)
            if self._cli_path:
                result = self._call_opencode_cli(prompt, system)
                if result:
                    return result

            logger.error(f"No working AI backend for {self.model}")
            return ""
        except Exception as e:
            self.total_errors += 1
            logger.error(f"AI call failed ({self.model}): {e}")
            return ""
        finally:
            self._rate_limiter.release()
            self.total_calls += 1

    def _call_opencode_cli(self, prompt: str, system: str) -> str:
        """Call via OpenCode CLI — free, no API key needed."""
        try:
            full_prompt = prompt
            if system:
                full_prompt = f"{system}\n\n{prompt}"

            result = subprocess.run(
                [self._cli_path, "run",
                 "--model", self._opencode_model,
                 "--format", "json",
                 "--auto",
                 full_prompt],
                capture_output=True, text=True, timeout=120, encoding='utf-8',
                cwd=os.path.dirname(os.path.dirname(self._cli_path))
            )

            if result.returncode != 0:
                logger.warning(f"opencode CLI returned {result.returncode}")
                return ""

            # Parse streaming JSON output — extract text parts
            text_parts = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("type") == "text":
                        part = obj.get("part", {})
                        text_parts.append(part.get("text", ""))
                except json.JSONDecodeError:
                    continue

            return "\n".join(text_parts) if text_parts else ""

        except subprocess.TimeoutExpired:
            logger.warning(f"opencode CLI timed out (120s) for {self._opencode_model}")
            return ""
        except Exception as e:
            logger.warning(f"opencode CLI error: {e}")
            return ""

    def _call_openrouter(self, prompt: str, system: str, max_tokens: int) -> str:
        """Fallback: OpenRouter API."""
        import urllib.request
        import urllib.error

        url = "https://openrouter.ai/api/v1/chat/completions"

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": self._openrouter_model,
            "messages": messages,
            "max_tokens": max(max_tokens, 8192),
            "temperature": 0.7,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.openrouter_key}",
        }

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    msg = choices[0].get("message", {})
                    # Handle reasoning models (content null, text in reasoning)
                    content = msg.get("content")
                    if not content:
                        content = msg.get("reasoning", "")
                    return content or ""
                return ""
        except Exception as e:
            logger.error(f"OpenRouter error: {e}")
            time.sleep(5)
            return ""
