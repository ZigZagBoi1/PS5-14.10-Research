"""Stage a verified 14.10 recovery PUP and research ELF on a USB drive."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ART = ROOT / "artifacts" / "pup14"
PUP = ART / "PS5UPDATE_14.10_RECOVERY.PUP"
ELF = ART / "PS5_1410_RESEARCH.elf"
EXPECTED_PUP_SHA256 = "9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de"
EXPECTED_PUP_SIZE = 1_418_890_240


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_usb_root() -> pathlib.Path:
    """Find one mounted USB disk volume; refuse an ambiguous choice."""
    script = (
        "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | "
        "Get-Partition | Where-Object { $_.DriveLetter } | "
        "ForEach-Object { $_.DriveLetter }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        check=True, capture_output=True, text=True,
    )
    letters = sorted(set(line.strip().upper() for line in result.stdout.splitlines() if line.strip()))
    if len(letters) != 1 or len(letters[0]) != 1 or not letters[0].isalpha():
        raise ValueError(f"Expected exactly one mounted USB volume; found {letters or 'none'}. Pass its drive root explicitly.")
    return pathlib.Path(f"{letters[0]}:\\")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("usb_root", nargs="?", type=pathlib.Path, help="USB drive root, for example E: drive")
    parser.add_argument("--auto", action="store_true", help="Use the only mounted USB disk volume")
    args = parser.parse_args()
    if args.auto == (args.usb_root is not None):
        parser.error("Pass either a USB drive root or --auto")
    try:
        usb = (detect_usb_root() if args.auto else args.usb_root).resolve()
    except (ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    if not usb.is_dir():
        parser.error(f"USB root does not exist: {usb}")
    if pathlib.Path(usb.anchor) != usb:
        parser.error("Pass the root of the USB drive, not a subdirectory")
    if usb.drive.lower() == pathlib.Path.home().drive.lower():
        parser.error("Refusing to stage on the Windows system drive")
    if not PUP.is_file() or PUP.stat().st_size != EXPECTED_PUP_SIZE:
        parser.error("The official 14.10 recovery PUP is missing or has the wrong size")
    actual = sha256(PUP)
    if actual != EXPECTED_PUP_SHA256:
        parser.error(f"14.10 PUP SHA-256 mismatch: {actual}")
    if not ELF.is_file() or ELF.stat().st_size < 8_000:
        parser.error("Research ELF missing; build it first")
    if shutil.disk_usage(usb).free < PUP.stat().st_size * 3:
        parser.error("USB needs at least 3 PUP sizes free for input and decrypted output")
    outputs = ((PUP, usb / "PS5_1410_RESEARCH.PUP"), (ELF, usb / ELF.name))
    for src, dst in outputs:
        if dst.exists() and sha256(dst) != sha256(src):
            parser.error(f"Refusing to overwrite a different file: {dst}")
    for src, dst in outputs:
        if dst.exists():
            print(f"Already staged: {dst}")
            continue
        shutil.copyfile(src, dst)
        print(f"Staged: {dst}")
        if sha256(dst) != sha256(src):
            parser.error(f"Copy verification failed: {dst}")
    note = usb / "PS5_1410_RESEARCH_README.txt"
    note.write_text(
        "PS5 14.10 PUP research USB. No firmware installer is included.\n"
        "PS5_1410_RESEARCH.PUP is outside PS5/UPDATE and is not named PS5UPDATE.PUP.\n"
        "On the jailbroken 13.60 PS5, launch PS5_1410_RESEARCH.elf with your existing ELF loader.\n"
        "The payload writes .dec files and PS5_1410_RESEARCH.log to this USB root.\n"
        "Back on the PC, run tools/pup14/ANALYZE_USB.cmd from the research repo.\n"
        "PUP SHA-256: " + EXPECTED_PUP_SHA256 + "\n"
        "Do not select System Software Update. Cross-version decryption is unverified.\n",
        encoding="utf-8",
    )
    print("Ready. The PUP has not been placed in a PS5 update directory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
