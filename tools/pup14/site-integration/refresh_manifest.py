"""Refresh hashes for the PUP research integration in the deployed manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path("/var/www/ps5-research")
MANIFEST = ROOT / "release-manifest.json"
FILES = (
    "server/server.py",
    "server/pup_bridge.py",
    "web/index.html",
    "web/relapse/launch.js",
    "deploy/ps5-research.service",
    "private/pup14/PS5_1410_RESEARCH_LAN.elf",
    "private/pup14/pup_unpacker_linux",
)


def main() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for relative in FILES:
        data["files"][relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    data["pup14_source_sha256"] = "9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de"
    MANIFEST.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
