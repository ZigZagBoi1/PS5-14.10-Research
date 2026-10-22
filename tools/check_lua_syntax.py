#!/usr/bin/env python3
"""Compile all probe sources with Lua 5.1 without executing them."""

from pathlib import Path

from lupa.lua51 import LuaRuntime


def main():
    root = Path(__file__).resolve().parent.parent
    compiler = LuaRuntime().eval("loadstring")
    probes = sorted((root / "probes").rglob("*.lua"))
    failures = []
    for probe in probes:
        source = probe.read_text(encoding="utf-8")
        result = compiler(source, str(probe.relative_to(root)))
        if isinstance(result, tuple) and result[0] is None:
            error = result[1]
            failures.append((probe.relative_to(root), error))

    print(f"Compiled {len(probes)} Lua 5.1 probe sources; failures={len(failures)}")
    for probe, error in failures:
        print(f"{probe}: {error}")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
