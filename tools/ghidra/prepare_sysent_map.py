"""Prepare reference labels, not symbols/prototypes, from the retained range index."""
import argparse
import json
from pathlib import Path


def number(value):
    if isinstance(value, bool):
        raise ValueError("boolean is not an integer field")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError("expected integer or integer string")


def prepare(document):
    base = number(document["kernel_base"])
    if not 0 <= base < 2**64:
        raise ValueError("invalid recorded base")
    seen = set()
    rows = []
    for i, entry in enumerate(document["entries"]):
        num = number(entry["num"])
        argc = number(entry["narg"])
        target = number(entry["sy_call"])
        offset = number(entry["sy_call_off"])
        if num < 0 or num in seen:
            raise ValueError("negative or repeated selector: %s" % num)
        if not 0 <= offset < 2**64 or not 0 <= target < 2**64:
            raise ValueError("invalid target/offset at entry %s" % i)
        if base + offset != target:
            raise ValueError("conflicting recorded coordinates at entry %s" % i)
        seen.add(num)
        # Preserve unusual counts; never turn them into a guessed prototype.
        status = "COUNT_UNVERIFIED" if 0 <= argc <= 8 else "COUNT_IMPLAUSIBLE"
        rows.append((num, argc, hex(target), hex(offset), status, "/entries/%d" % i))
    return sorted(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows = prepare(json.loads(args.index.read_text(encoding="utf-8-sig")))
    # Exclusive creation prevents accidental replacement of prior analysis.
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("selector\trecorded_narg\trecorded_target\trecorded_offset\tstatus\tjson_pointer\n")
        for row in rows:
            stream.write("\t".join(map(str, row)) + "\n")
    print(json.dumps({"entries": len(rows), "distinct_targets": len({r[3] for r in rows}),
                      "qualification": "13.60-labeled; acquisition authenticity unresolved"}))


if __name__ == "__main__":
    main()
