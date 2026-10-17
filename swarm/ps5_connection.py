"""PS5 probe sender — serial queue, auto-retry, health monitoring."""

import socket
import struct
import time
import threading
import os
from datetime import datetime

class PS5Connection:
    def __init__(self, ip: str, port: int, results_dir: str):
        self.ip = ip
        self.port = port
        self.results_dir = results_dir
        self._lock = threading.Lock()
        self.alive = True
        self.last_success = None
        self.last_failure = None
        self.consecutive_failures = 0
        self.total_probes_sent = 0
        self.total_bytes_received = 0

    def health_check(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.ip, self.port))
            payload = b'print("PING")'
            sock.sendall(struct.pack("<Q", len(payload)) + payload)
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()
            alive = len(response) > 0 and b"PING" in response
            self.alive = alive
            if alive:
                self.consecutive_failures = 0
                self.last_success = time.time()
            else:
                self.consecutive_failures += 1
                self.last_failure = time.time()
            return alive
        except Exception:
            self.alive = False
            self.consecutive_failures += 1
            self.last_failure = time.time()
            return False

    def send_probe(self, lua_source: str, probe_name: str) -> dict:
        with self._lock:
            result = {
                "probe_name": probe_name,
                "sent_at": time.time(),
                "success": False,
                "response": "",
                "bytes_received": 0,
                "error": None,
                "saved_to": None,
            }

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(60)
                sock.connect((self.ip, self.port))

                encoded = lua_source.encode("utf-8")
                sock.sendall(struct.pack("<Q", len(encoded)) + encoded)

                response = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                sock.close()

                text = response.decode("utf-8", errors="replace")
                result["response"] = text
                result["bytes_received"] = len(response)
                result["success"] = len(response) > 0

                self.total_probes_sent += 1
                self.total_bytes_received += len(response)

                if result["success"]:
                    self.consecutive_failures = 0
                    self.last_success = time.time()
                    self.alive = True
                else:
                    self.consecutive_failures += 1
                    self.last_failure = time.time()
                    if self.consecutive_failures >= 3:
                        self.alive = False

                # Save result
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_name = probe_name.replace("/", "_").replace("\\", "_")
                result_file = os.path.join(self.results_dir, f"{safe_name}_{ts}.txt")
                os.makedirs(os.path.dirname(result_file), exist_ok=True)
                with open(result_file, "w", encoding="utf-8") as f:
                    f.write(text)
                result["saved_to"] = result_file

            except Exception as e:
                result["error"] = str(e)
                self.consecutive_failures += 1
                self.last_failure = time.time()
                if self.consecutive_failures >= 3:
                    self.alive = False

            return result

    def wait_for_loader(self, timeout: int = 3600, check_interval: int = 30) -> bool:
        """Wait for PS5 loader to come back online. Blocks up to timeout seconds."""
        start = time.time()
        while time.time() - start < timeout:
            if self.health_check():
                return True
            time.sleep(check_interval)
        return False

    def get_status(self) -> dict:
        return {
            "alive": self.alive,
            "ip": self.ip,
            "port": self.port,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "consecutive_failures": self.consecutive_failures,
            "total_probes_sent": self.total_probes_sent,
            "total_bytes_received": self.total_bytes_received,
        }
