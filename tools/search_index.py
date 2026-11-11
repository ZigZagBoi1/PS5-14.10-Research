#!/usr/bin/env python3
"""SQLite FTS5 search index for the PS5 14.10 research corpus.

Usage:
    python tools/search_index.py build          # rebuild index (incremental)
    python tools/search_index.py build --full   # force full rebuild
    python tools/search_index.py search "query" [--type TYPE] [--limit N]
    python tools/search_index.py stats          # file counts by type
"""

import argparse
import os
import pathlib
import re
import sqlite3
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "tools" / "research.db"

SCAN_DIRS = {
    "probes":   ROOT / "probes",
    "results":  ROOT / "results",
    "docs":     ROOT / "docs",
    "evidence": ROOT / "evidence",
}

TEXT_EXTS = {
    ".lua", ".html", ".js", ".css", ".txt", ".md", ".csv", ".json",
    ".py", ".sh", ".ps1", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    ".log", ".xml",
}

BINARY_PEEK = 8192


def _is_text(path):
    if path.suffix.lower() in TEXT_EXTS:
        return True
    try:
        chunk = path.read_bytes()[:BINARY_PEEK]
        if b"\x00" in chunk:
            return False
        return True
    except OSError:
        return False


def _read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _file_type(path):
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if parts[0] in SCAN_DIRS:
        return parts[0]
    return "other"


_HEADER_RE = re.compile(
    r"^(--[^\n]*\n)+", re.MULTILINE
)
_CRASH_RE = re.compile(r"CRASH_CLASS:\s*(\S+)")
_PROBE_RE = re.compile(r"PROBE\s+(\S+?):")
_CONTEXT_RE = re.compile(r"Context:\s*(.+?)(?:\n(?!--)|\Z)", re.DOTALL)


def _extract_lua_meta(text):
    m = _HEADER_RE.match(text)
    if not m:
        return ""
    header = m.group(0)
    parts = []
    cm = _CRASH_RE.search(header)
    if cm:
        parts.append(f"CRASH_CLASS={cm.group(1)}")
    pm = _PROBE_RE.search(header)
    if pm:
        parts.append(f"PROBE={pm.group(1)}")
    ctx = _CONTEXT_RE.search(header)
    if ctx:
        parts.append(f"CONTEXT={ctx.group(1).strip()}")
    return " | ".join(parts)


_RESULT_NAME_RE = re.compile(r"^(\w+?)_\d{8}_\d{6}")


def _extract_result_probe(path):
    m = _RESULT_NAME_RE.match(path.stem)
    return m.group(1) if m else ""


def _init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS files (
            path  TEXT PRIMARY KEY,
            type  TEXT,
            mtime REAL,
            meta  TEXT
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
            path, type, meta, content,
            tokenize='porter unicode61'
        );
    """)


def _build(full=False):
    conn = sqlite3.connect(str(DB_PATH))
    _init_db(conn)

    if full:
        conn.execute("DELETE FROM files")
        conn.execute("DELETE FROM fts")
        conn.commit()

    existing = {}
    for row in conn.execute("SELECT path, mtime FROM files"):
        existing[row[0]] = row[1]

    indexed = set()
    added = updated = skipped = 0

    for type_name, scan_dir in SCAN_DIRS.items():
        if not scan_dir.exists():
            continue
        for path in scan_dir.rglob("*"):
            if not path.is_file():
                continue
            if not _is_text(path):
                continue

            rel = str(path.relative_to(ROOT))
            indexed.add(rel)
            mtime = path.stat().st_mtime

            if not full and rel in existing and existing[rel] >= mtime:
                skipped += 1
                continue

            text = _read_text(path)
            if text is None:
                continue

            ftype = _file_type(path)
            meta = ""
            if path.suffix.lower() == ".lua":
                meta = _extract_lua_meta(text)
            elif ftype == "results":
                meta = _extract_result_probe(path)

            if rel in existing:
                conn.execute("DELETE FROM fts WHERE path = ?", (rel,))
                conn.execute("DELETE FROM files WHERE path = ?", (rel,))
                updated += 1
            else:
                added += 1

            conn.execute(
                "INSERT INTO files (path, type, mtime, meta) VALUES (?, ?, ?, ?)",
                (rel, ftype, mtime, meta),
            )
            conn.execute(
                "INSERT INTO fts (path, type, meta, content) VALUES (?, ?, ?, ?)",
                (rel, ftype, meta, text),
            )

    removed = 0
    for old_path in set(existing) - indexed:
        conn.execute("DELETE FROM fts WHERE path = ?", (old_path,))
        conn.execute("DELETE FROM files WHERE path = ?", (old_path,))
        removed += 1

    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('last_build', ?)",
        (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),),
    )
    conn.commit()
    conn.close()

    print(f"Index built: {added} added, {updated} updated, "
          f"{skipped} unchanged, {removed} removed")
    print(f"Database: {DB_PATH}")


def _search(query, file_type=None, limit=10):
    if not DB_PATH.exists():
        print("No index found. Run: python tools/search_index.py build")
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))

    sql = """
        SELECT fts.path, fts.type, fts.meta,
               snippet(fts, 3, '>>>', '<<<', '...', 40) AS snip,
               bm25(fts) AS rank
        FROM fts
        WHERE fts MATCH ?
    """
    params = [query]

    if file_type:
        sql += " AND fts.type = ?"
        params.append(file_type)

    sql += " ORDER BY rank LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()

    if not rows:
        print(f"No results for: {query}")
        return

    print(f"Results for: {query}  ({len(rows)} matches)\n")
    for i, (path, ftype, meta, snip, rank) in enumerate(rows, 1):
        print(f"  {i}. [{ftype}] {path}")
        if meta:
            print(f"     meta: {meta}")
        snip_clean = snip.replace("\n", " ").strip()
        if len(snip_clean) > 200:
            snip_clean = snip_clean[:200] + "..."
        print(f"     {snip_clean}")
        print()


def _stats():
    if not DB_PATH.exists():
        print("No index found. Run: python tools/search_index.py build")
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute(
        "SELECT type, COUNT(*) FROM files GROUP BY type ORDER BY type"
    ).fetchall()
    total = sum(r[1] for r in rows)
    last = conn.execute(
        "SELECT value FROM meta WHERE key = 'last_build'"
    ).fetchone()
    conn.close()

    print(f"Index stats (last build: {last[0] if last else 'never'}):\n")
    for ftype, count in rows:
        print(f"  {ftype:12s} {count:5d} files")
    print(f"  {'TOTAL':12s} {total:5d} files")


def main():
    parser = argparse.ArgumentParser(description="Research corpus search index")
    sub = parser.add_subparsers(dest="command")

    bp = sub.add_parser("build", help="Build/rebuild the FTS5 index")
    bp.add_argument("--full", action="store_true", help="Force full rebuild")

    sp = sub.add_parser("search", help="Search the index")
    sp.add_argument("query", help="Search query (FTS5 syntax)")
    sp.add_argument("--type", dest="file_type",
                    choices=["probes", "results", "docs", "evidence"],
                    help="Filter by file type")
    sp.add_argument("--limit", type=int, default=10, help="Max results")

    sub.add_parser("stats", help="Show index statistics")

    args = parser.parse_args()
    if args.command == "build":
        _build(full=args.full)
    elif args.command == "search":
        _search(args.query, file_type=args.file_type, limit=args.limit)
    elif args.command == "stats":
        _stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
