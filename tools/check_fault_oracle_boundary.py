"""Verify saved 1199b/c sampling evidence offline, not firmware mapping identity.

Paths are relative to the checkout containing this tool. SHA-256 pins whole
captures; selected records additionally pin index, header byte offset, address,
and raw little-endian discriminator at context offset 0x18. No probe is run.
"""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = Path("results/phase17_new_vectors")
SPECS = {
    "1199b": ("1199b_fault_oracle_upper_20261104_234410.txt",
              "4bd9cecccba2eeaeb7d0cb807d6e533035b0754556b989a1426eddcebd0ca424", 512,
              ((160, 45306, 0xFFFFFFFFD4000000, 0x15),
               (210, 59406, 0xFFFFFFFFDA400000, 0x15),
               (211, 59688, 0xFFFFFFFFDA600000, 0x14))),
    "1199c": ("1199c_fault_oracle_edges_20261104_235448.txt",
              "a77164adc3b6bacd755ea19fe6dd830169a4441d5cccc54d518c594b4371af02", 528,
              ((7, 2151, 0xFFFFFFFFD3FFF000, 0x14),
               (8, 2497, 0xFFFFFFFFDA400000, 0x15),
               (519, 146599, 0xFFFFFFFFDA5FF000, 0x15),
               (520, 146936, 0xFFFFFFFFDA600000, 0x14))),
}


def verify_capture(root, filename, digest, count, expected):
    path = root / CAPTURE_DIR / filename
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f"missing capture: {CAPTURE_DIR / filename}") from exc
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"SHA-256 mismatch: {filename}")
    rows, pos = {}, 0
    while pos < len(data):
        offset = pos
        nl = data.find(b"\n", pos)
        if nl < 0:
            break
        line, pos = data[pos:nl], nl + 1
        match = re.fullmatch(rb"\[T(\d+)\] (0x[0-9A-Fa-f]+)", line)
        if match:
            if pos + 256 > len(data):
                raise ValueError(f"truncated context: {filename} byte {offset}")
            index = int(match[1])
            if index in rows:
                raise ValueError(f"duplicate record index: {filename} T{index:03d}")
            rows[index] = (offset, int(match[2], 16),
                           int.from_bytes(data[pos+24:pos+28], "little"))
            pos += 256
    if sorted(rows) != list(range(count)):
        raise ValueError(f"record count/index mismatch: {filename}")
    for index, offset, address, raw in expected:
        if rows.get(index) != (offset, address, raw):
            raise ValueError(f"record offset/address/discriminator mismatch: {filename} T{index:03d}")
    return rows


def verify_gap(left, right):
    delta = right - left
    if delta <= 0 or delta % 4096 or delta // 4096 - 1 != 25600:
        raise ValueError("gap arithmetic mismatch: expected 25,600 intervening 4 KiB positions")
    return delta // 4096 - 1


def verify(root=ROOT):
    captures = {name: verify_capture(root, *spec) for name, spec in SPECS.items()}
    b, c = captures["1199b"], captures["1199c"]
    gap = verify_gap(c[7][1], c[8][1])
    if any(c[7][1] < row[1] < c[8][1] for row in c.values()):
        raise ValueError("unexpected observation inside documented 1199c gap")
    a, z = {row[1]: row[2] for row in b.values()}, {row[1]: row[2] for row in c.values()}
    shared = set(a) & set(z)
    if shared != {0xFFFFFFFFDA400000, 0xFFFFFFFFDA600000} or any(a[x] != z[x] for x in shared):
        raise ValueError("overlapping evidence mismatch")
    if b[160][1] - c[7][1] != 4096 or c[520][1] - c[519][1] != 4096:
        raise ValueError("4 KiB bracket arithmetic mismatch")
    return captures, gap


def main():
    try:
        captures, gap = verify()
    except (OSError, ValueError) as exc:
        print(f"fault-oracle evidence check failed: {exc}", file=sys.stderr)
        return 1
    for name, rows in captures.items():
        filename, digest, _, expected = SPECS[name]
        print(f"{CAPTURE_DIR / filename}: SHA-256 {digest}; {len(rows)} records")
        for index, offset, address, raw in expected:
            print(f"  T{index:03d} byte={offset} address=0x{address:016X} raw=0x{raw:02X}")
    print(f"1199c gap: {gap:,} intervening 4 KiB positions unobserved")
    print("1199c trailing observed transition: 0xFFFFFFFFDA5FF000 -> 0xFFFFFFFFDA600000 (4 KiB)")
    print("CONDITIONAL shared-stable-state bracket: 1199c 0xFFFFFFFFD3FFF000 -> 1199b 0xFFFFFFFFD4000000 (4 KiB)")
    print("Two shared addresses agree. Matching process metadata does not authenticate stability.")
    print("No continuous-image-mapping claim is verified by this checker.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
