"""Unpack and inventory every component from a 14.10 decrypted PUP on a PC.

Uses the pinned local Linux build of zecoxao/ps5-pup-unpacker through WSL.
No PS5 connection or hardware operation occurs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import shlex
import shutil
import subprocess
import sys

from prepare_usb import detect_usb_root

ROOT = pathlib.Path(__file__).resolve().parents[2]
ART = ROOT / "artifacts" / "pup14"
UNPACKER = ART / "pup_unpacker_linux"


def wsl_path(path: pathlib.Path) -> str:
    return subprocess.check_output(
        ["wsl.exe", "bash", "-lc", f"wslpath -a {shlex.quote(str(path.resolve()))}"],
        text=True,
    ).strip()


def digest_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    return -sum((n / len(sample)) * math.log2(n / len(sample)) for n in counts if n)


def classify(head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"SCE\0") or head.startswith(b"\x4f\x15\x3d\x1d"):
        return "possible Sony SELF/container"
    if head.startswith(b"SLB2"):
        return "SLB2"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP"
    if head.startswith(b"MZ"):
        return "PE"
    if not head:
        return "empty"
    return "opaque/unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("usb_root", nargs="?", type=pathlib.Path, help="USB root after payload execution")
    parser.add_argument("--auto", action="store_true", help="Use the only mounted USB disk volume")
    args = parser.parse_args()
    if args.auto == (args.usb_root is not None):
        parser.error("Pass either a USB drive root or --auto")
    try:
        usb = (detect_usb_root() if args.auto else args.usb_root).resolve()
    except (ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    if not usb.is_dir():
        parser.error(f"USB path missing: {usb}")
    log = usb / "PS5_1410_RESEARCH.log"
    log_text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    complete = "RESEARCH EXTRACTION SUCCESS" in log_text
    dec_files = sorted(usb.glob("PS5_1410_*.PUP.dec"))
    if not dec_files:
        parser.error("No .dec PUP files found. Preserve the USB and inspect the research log.")
    if not UNPACKER.is_file():
        parser.error("The local pup_unpacker_linux binary is missing")
    out = ART / "extracted"
    if out.exists():
        parser.error(f"Output folder already exists; preserving it: {out}")
    out.mkdir(parents=True)
    runner = "/tmp/ps5_pup14_unpacker"
    cmd = f"cp {shlex.quote(wsl_path(UNPACKER))} {runner} && chmod 700 {runner}"
    subprocess.run(["wsl.exe", "bash", "-lc", cmd], check=True)
    unpack_status = {}
    for dec in dec_files:
        target = out / dec.name.replace(".PUP.dec", "")
        target.mkdir()
        cmd = f"{runner} {shlex.quote(wsl_path(dec))} {shlex.quote(wsl_path(target))}"
        proc = subprocess.run(["wsl.exe", "bash", "-lc", cmd], text=True, capture_output=True)
        unpack_status[dec.name] = {
            "sha256": digest_file(dec),
            "size": dec.stat().st_size,
            "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-4000:],
            "stderr_tail": proc.stderr[-4000:],
            "valid_pup": "Invalid PUP image provided." not in proc.stdout,
        }
    files = []
    for path in sorted(out.rglob("*")):
        if not path.is_file():
            continue
        with path.open("rb") as f:
            head = f.read(65536)
        record = {
            "path": str(path.relative_to(out)),
            "size": path.stat().st_size,
            "sha256": digest_file(path),
            "head_hex": head[:32].hex(),
            "head_entropy_bits_per_byte": round(entropy(head), 4),
            "format_hint": classify(head),
        }
        files.append(record)
    kernel = [f for f in files if "kernel.bin" in f["path"].lower()]
    report = {
        "source_log_present": log.exists(),
        "payload_reported_success": complete,
        "decrypted_pups": unpack_status,
        "component_count": len(files),
        "kernel_candidates": kernel,
        "files": files,
        "interpretation": (
            "A kernel.bin name alone does not establish plaintext kernel code. "
            "Inspect its inner format and code sections before treating it as a 14.10 image."
        ),
    }
    report_path = ART / "extraction_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Inventory: {report_path}")
    print(f"Payload success marker: {complete}; components: {len(files)}")
    for item in kernel:
        print(f"Kernel candidate: {item['path']} {item['size']} bytes {item['format_hint']}")
    return 0 if complete and files and all(
        v["returncode"] == 0 and v["valid_pup"] for v in unpack_status.values()
    ) else 1


if __name__ == "__main__":
    sys.exit(main())
