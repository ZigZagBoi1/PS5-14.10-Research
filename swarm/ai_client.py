"""AI client — uses OpenCode CLI with serialized queue for free model access."""

import json
import time
import threading
import logging
import subprocess
import os
import queue

logger = logging.getLogger("swarm")

OPENCODE_CLI = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "Programs", "@opencodedesktop", "resources", "opencode-cli.exe"
)


class AIClient:
    """Calls AI models via OpenCode CLI (free, no key needed).

    Uses a shared worker pool to avoid overwhelming the CLI with
    100 concurrent calls. 3 workers process requests in parallel.
    """

    # Shared class-level worker pool (all AIClient instances share it)
    _work_queue = queue.Queue()
    _workers_started = False
    _workers_lock = threading.Lock()
    _NUM_WORKERS = 3  # concurrent CLI calls

    def __init__(self, model: str, api_key: str = "", use_opencode: bool = True):
        self.model = model
        self._cli_path = OPENCODE_CLI if os.path.isfile(OPENCODE_CLI) else None
        self._opencode_model = self._map_to_opencode(model)
        self.total_calls = 0
        self.total_errors = 0

        # Start worker threads once
        with AIClient._workers_lock:
            if not AIClient._workers_started and self._cli_path:
                for i in range(AIClient._NUM_WORKERS):
                    t = threading.Thread(target=AIClient._worker_loop, daemon=True, name=f"ai-worker-{i}")
                    t.start()
                AIClient._workers_started = True
                logger.info(f"AI worker pool started ({AIClient._NUM_WORKERS} workers, model: {self._opencode_model})")

    def _map_to_opencode(self, model: str) -> str:
        mapping = {
            "deepseek-v4.1-flash": "opencode/deepseek-v4.1-flash-free",
            "nemotron-ultra-550b": "opencode/nemotron-3-ultra-free",
            "nemotron-lightning": "opencode/nemotron-3.5-lightning-free",
            "gemma-4-26b": "opencode/glm-5.3-flash-free",
        }
        return mapping.get(model, "opencode/deepseek-v4.1-flash-free")

    def chat(self, prompt: str, system: str = None, max_tokens: int = 4096) -> str:
        if not self._cli_path:
            logger.error("OpenCode CLI not found — install OpenCode desktop from https://opencode.ai")
            return ""

        # Submit to worker pool and wait for result
        result_event = threading.Event()
        result_holder = {"text": ""}

        AIClient._work_queue.put((self._opencode_model, prompt, system, result_event, result_holder))

        # Wait up to 180s for result
        if result_event.wait(timeout=180):
            self.total_calls += 1
            if not result_holder["text"]:
                self.total_errors += 1
            return result_holder["text"]
        else:
            self.total_calls += 1
            self.total_errors += 1
            logger.warning(f"AI call timed out waiting in queue ({self._opencode_model})")
            return ""

    @staticmethod
    def _worker_loop():
        """Worker thread — pulls requests from the shared queue and calls OpenCode CLI."""
        cli = OPENCODE_CLI
        while True:
            try:
                model, prompt, system, event, holder = AIClient._work_queue.get()

                full_prompt = prompt
                if system:
                    full_prompt = f"{system}\n\n{prompt}"

                # Truncate very long prompts (CLI has limits)
                if len(full_prompt) > 30000:
                    full_prompt = full_prompt[:30000] + "\n\n[TRUNCATED]"

                try:
                    result = subprocess.run(
                        [cli, "run", "--model", model, "--format", "json", "--auto", full_prompt],
                        capture_output=True, text=True, timeout=120, encoding='utf-8'
                    )

                    if result.returncode == 0 and result.stdout.strip():
                        text_parts = []
                        for line in result.stdout.strip().split("\n"):
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                                if obj.get("type") == "text":
                                    part = obj.get("part", {})
                                    t = part.get("text", "")
                                    if t:
                                        text_parts.append(t)
                            except json.JSONDecodeError:
                                continue
                        holder["text"] = "\n".join(text_parts)
                    else:
                        stderr_snippet = (result.stderr or "")[:200]
                        if stderr_snippet:
                            logger.warning(f"opencode CLI error: {stderr_snippet}")

                except subprocess.TimeoutExpired:
                    logger.warning(f"opencode CLI timed out for {model}")
                except Exception as e:
                    logger.warning(f"opencode CLI error: {e}")

                event.set()
                AIClient._work_queue.task_done()

            except Exception as e:
                logger.error(f"AI worker error: {e}")
