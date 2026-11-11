#!/usr/bin/env python3
"""Progressive context loader for AI sessions.

Loads research context in four tiers, from minimal (always loaded) to full
historical detail. An agent reads only what it needs for the current task,
keeping the context window small.

Tiers
-----
    0  minimal    CLAUDE.md + STATE.md + last 10 INDEX rows (~2K tokens)
    1  standard   + CHECKPOINT.md + CAPABILITY_GRAPH.md (~5K tokens)
    2  focused    + topic-specific docs (dead ends, attack surface, etc.)
    3  full       + raw historical captures and probe sources

Usage
-----
    python tools/context.py 0              # minimal session start
    python tools/context.py 1              # standard working context
    python tools/context.py 2 --topic webkit   # focused on webkit
    python tools/context.py 2 --topic kaslr    # focused on kaslr
    python tools/context.py 2 --topic syscall  # focused on syscalls
    python tools/context.py 3 --probe 56i2     # full context for a probe
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TIER_0 = [
    "CLAUDE.md",
    "results/STATE.md",
]

TIER_1 = [
    "results/CHECKPOINT.md",
    "docs/CAPABILITY_GRAPH.md",
]

TOPICS = {
    "webkit": [
        "docs/ATTACK_PRIORITY_REFERENCE.md",
        "docs/EXPLOITATION_STATUS.md",
    ],
    "kaslr": [
        "docs/FINDINGS.md",
        "docs/KASLR_EVIDENCE_AUDIT_2026-10-20.md",
    ],
    "syscall": [
        "docs/ATTACK_SURFACE.md",
        "docs/DEAD_ENDS_REFERENCE.md",
    ],
    "umtx": [
        "docs/UMTX_454_EVIDENCE.md",
        "docs/DEAD_ENDS_REFERENCE.md",
    ],
    "dead_ends": [
        "docs/DEAD_ENDS_REFERENCE.md",
        "docs/DEAD_ENDS.md",
    ],
    "race": [
        "docs/KERNEL_RACE_OFFLINE_ASSESSMENT_2026-11-10.md",
        "docs/CVE_KERNEL_RW_ASSESSMENT_2026-11-10.md",
    ],
}

INDEX_TAIL_LINES = 10


def read_file(path):
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        return None
    with open(full, encoding="utf-8", errors="replace") as f:
        return f.read()


def read_index_tail():
    idx = os.path.join(ROOT, "results", "INDEX.md")
    if not os.path.exists(idx):
        return "(no INDEX.md found)"
    with open(idx, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    tail = lines[-INDEX_TAIL_LINES:] if len(lines) > INDEX_TAIL_LINES else lines
    return "".join(tail)


def load_tier(tier, topic=None, probe=None):
    sections = []

    # Tier 0: always loaded
    for path in TIER_0:
        content = read_file(path)
        if content:
            sections.append(f"=== {path} ===\n{content}")
    sections.append(f"=== INDEX.md (last {INDEX_TAIL_LINES} rows) ===\n{read_index_tail()}")

    if tier >= 1:
        for path in TIER_1:
            content = read_file(path)
            if content:
                sections.append(f"=== {path} ===\n{content}")

    if tier >= 2 and topic:
        topic_files = TOPICS.get(topic, [])
        if not topic_files:
            sections.append(f"(unknown topic '{topic}'; available: {', '.join(sorted(TOPICS))})")
        for path in topic_files:
            content = read_file(path)
            if content:
                sections.append(f"=== {path} ===\n{content}")

    if tier >= 3 and probe:
        # Find probe source and results
        import glob
        probe_files = glob.glob(os.path.join(ROOT, "probes", "**", f"*{probe}*"), recursive=True)
        result_files = glob.glob(os.path.join(ROOT, "results", "**", f"*{probe}*"), recursive=True)
        for f in probe_files + result_files:
            rel = os.path.relpath(f, ROOT)
            content = read_file(rel)
            if content:
                sections.append(f"=== {rel} ===\n{content[:10000]}")

    return "\n\n".join(sections)


def estimate_tokens(text):
    return len(text) // 4


def main():
    parser = argparse.ArgumentParser(description="Progressive context loader")
    parser.add_argument("tier", type=int, choices=[0, 1, 2, 3], help="Context tier (0=minimal, 3=full)")
    parser.add_argument("--topic", help="Topic for tier 2+ (webkit, kaslr, syscall, umtx, dead_ends, race)")
    parser.add_argument("--probe", help="Probe ID for tier 3 (e.g., 56i2)")
    parser.add_argument("--estimate", action="store_true", help="Show token estimate only, don't print content")
    args = parser.parse_args()

    content = load_tier(args.tier, args.topic, args.probe)

    if args.estimate:
        tokens = estimate_tokens(content)
        print(f"Tier {args.tier} context: ~{tokens:,} tokens ({len(content):,} chars)")
        if args.topic:
            print(f"  Topic: {args.topic}")
        if args.probe:
            print(f"  Probe: {args.probe}")
    else:
        print(content)


if __name__ == "__main__":
    main()
