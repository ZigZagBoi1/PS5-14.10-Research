#!/usr/bin/env python3
"""Receive one bounded, read-only 13.60 UMTX jump-table record."""

from pathlib import Path
import socket


OUTPUT = Path("artifacts/private_1360_umtx_454/umtx_table_live.txt")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("10.0.0.231", 8889))
    server.listen(1)
    server.settimeout(60)
    print("Waiting for 13.60 collector on 10.0.0.231:8889", flush=True)
    with server.accept()[0] as connection:
        connection.settimeout(10)
        record = connection.recv(512)
        if not record.startswith(b"UMTX_TABLE_V1 ") or len(record) > 256:
            raise ValueError("unexpected collector record")
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(record)
        print(record.decode("ascii", errors="replace"), flush=True)
