#!/usr/bin/env python3
"""Compile all probe sources with Lua 5.1 without executing them.

Sources are read with ``utf-8-sig`` because a UTF-8 BOM is not valid Lua 5.1
source and would otherwise reject every BOM-prefixed probe.  Lupa decodes the
Lua error text when the call returns; catch undecodable bytes so one probe
cannot abort the whole check.
"""

from pathlib import Path

from lupa.lua51 import LuaRuntime


def main():
    root = Path(__file__).resolve().parent.parent
    compiler = LuaRuntime().eval("loadstring")
    probes = sorted((root / "probes").rglob("*.lua"))
    failures = []
    for probe in probes:
        source = probe.read_text(encoding="utf-8-sig")
        try:
            result = compiler(source, str(probe.relative_to(root)))
        except UnicodeDecodeError:
            failures.append((probe.relative_to(root),
                             "Lua error text was not valid UTF-8"))
            continue
        if isinstance(result, tuple) and result[0] is None:
            error = result[1]
            failures.append((probe.relative_to(root), error))

    print(f"Compiled {len(probes)} Lua 5.1 probe sources; failures={len(failures)}")
    for probe, error in failures:
        print(f"{probe}: {error}")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
