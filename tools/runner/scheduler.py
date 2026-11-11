#!/usr/bin/env python3
"""Research task scheduler — generates analysis tasks from evidence state.

Priorities (from the master prompt):
1. Contradictory evidence requiring reconciliation
2. Unverified claims with existing raw captures
3. External research not yet compared against our evidence
4. Incorrect calculations and source inconsistencies
5. Reproducibility checks
6. Documentation of unresolved technical blockers

Does NOT generate new console probes.
"""

import hashlib
import json
import os
import re
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from tools.runner.task_db import TaskDB


def _read(path):
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        return ""
    with open(full, encoding="utf-8", errors="replace") as f:
        return f.read()


def _task_id(prefix, title):
    h = hashlib.sha256(title.encode()).hexdigest()[:8]
    return f"{prefix}-{h}"


def scan_contradictions(db):
    """Priority 1: Find contradictory evidence needing reconciliation."""
    tasks = []

    # Check external audit for items needing investigation
    audit = _read("docs/EXTERNAL_AUDIT_2026-11-11.md")
    if audit:
        # Look for NEEDS INVESTIGATION verdicts
        for line in audit.splitlines():
            if "NEEDS INVESTIGATION" in line or "CONTRADICTION" in line:
                title = line.strip("# -").strip()[:80]
                tid = _task_id("contra", title)
                if not db.is_investigated(title):
                    tasks.append({
                        "id": tid, "type": "reconcile_contradiction",
                        "title": title,
                        "description": f"Reconcile: {line.strip()}",
                        "priority": 0,
                        "evidence_refs": ["docs/EXTERNAL_AUDIT_2026-11-11.md"],
                    })

    # Check contradictions report
    contradictions = _read("docs/CONTRADICTIONS_REPORT.md") or _read("docs/2026-10-25/CONTRADICTIONS_REPORT.md")
    if contradictions:
        sections = re.split(r'\n##\s+', contradictions)
        for section in sections[1:]:
            lines = section.strip().splitlines()
            if not lines:
                continue
            title = lines[0].strip()[:80]
            if any(k in section.lower() for k in ("unresolved", "open", "disputed", "inconsistent")):
                tid = _task_id("contra", title)
                if not db.is_investigated(title):
                    tasks.append({
                        "id": tid, "type": "reconcile_contradiction",
                        "title": title,
                        "description": f"Check contradiction: {title}",
                        "priority": 0,
                    })

    return tasks


def scan_unverified_claims(db):
    """Priority 2: Claims graded [I] or [S] that have raw captures available."""
    tasks = []
    graph = _read("docs/CAPABILITY_GRAPH.md")
    if not graph:
        return tasks

    # Find INFERRED or SUPPORTED capabilities
    sections = re.split(r'\n### Capability:', graph)
    for section in sections[1:]:
        lines = section.strip().splitlines()
        name = lines[0].strip() if lines else "unknown"
        status = ""
        for line in lines:
            if "**Status**:" in line:
                status = line.split(":", 1)[1].strip()
                break

        if "INFERRED" in status or "SUPPORTED" in status:
            title = f"Verify {name} ({status})"
            tid = _task_id("verify", title)
            if not db.is_investigated(title):
                tasks.append({
                    "id": tid, "type": "verify_claim",
                    "title": title,
                    "description": f"Cross-check {name} against raw captures and source evidence",
                    "priority": 1,
                    "evidence_refs": ["docs/CAPABILITY_GRAPH.md"],
                })

    return tasks


def scan_external_research(db):
    """Priority 3: External research not compared against our evidence."""
    tasks = []

    # Check for WebKit CVEs not fully analyzed
    cve_docs = [
        "docs/WEBKIT_CVE_RESEARCH_2026-11-09.md",
        "docs/WEBKIT_CVE_POSTCHERRY_INFOLEAKS_2026-11-10.md",
        "docs/NEW_CVE_CANDIDATES_2026_11.md",
    ]

    for doc_path in cve_docs:
        content = _read(doc_path)
        if not content:
            continue
        # Find CVEs mentioned but not fully resolved
        cves = set(re.findall(r'CVE-\d{4}-\d+', content))
        for cve in cves:
            # Check if we have a dead-end or completed analysis for it
            title = f"Cross-reference {cve} against evidence"
            if not db.is_investigated(title):
                # Only add if the CVE isn't clearly marked dead in the doc
                if f"{cve}" in content and "DEAD" not in content.split(cve)[1][:200]:
                    tid = _task_id("xref", title)
                    tasks.append({
                        "id": tid, "type": "external_comparison",
                        "title": title,
                        "description": f"Compare {cve} details against local evidence and captures",
                        "priority": 2,
                        "evidence_refs": [doc_path],
                    })

    return tasks


def scan_calculation_checks(db):
    """Priority 4: Verify calculations and offsets in documentation."""
    tasks = []

    # Check STATE.md for kernel addresses that should be verified
    state = _read("results/STATE.md")
    if state:
        title = "Verify kernel address consistency across docs"
        tid = _task_id("calc", title)
        if not db.is_investigated(title):
            tasks.append({
                "id": tid, "type": "calculation_check",
                "title": title,
                "description": "Cross-check kernel_text, kernel_data, allproc, security_flags, rootvnode offsets against all documentation",
                "priority": 3,
                "evidence_refs": ["results/STATE.md"],
            })

    # Check SDK-derived addresses
    title = "Audit SDK-derived addresses vs measured addresses"
    tid = _task_id("calc", title)
    if not db.is_investigated(title):
        tasks.append({
            "id": tid, "type": "calculation_check",
            "title": title,
            "description": "kernel_data offset (TEXT+0xCE0000) is SDK-derived. Verify against any measured values.",
            "priority": 3,
            "evidence_refs": ["results/STATE.md", "docs/CAPABILITY_GRAPH.md"],
        })

    return tasks


def scan_reproducibility(db):
    """Priority 5: Check reproducibility of key findings."""
    tasks = []

    # Verify KASLR defeat reproducibility documentation
    title = "Document KASLR defeat reproducibility across boots"
    tid = _task_id("repro", title)
    if not db.is_investigated(title):
        tasks.append({
            "id": tid, "type": "reproducibility_check",
            "title": title,
            "description": "Check how many independent KASLR measurements exist across different boots. Document measurement methodology.",
            "priority": 4,
            "evidence_refs": ["docs/KASLR_EVIDENCE_AUDIT_2026-10-20.md"],
        })

    return tasks


def scan_blocker_docs(db):
    """Priority 6: Document unresolved technical blockers."""
    tasks = []

    graph = _read("docs/CAPABILITY_GRAPH.md")
    if not graph:
        return tasks

    # Find blockers mentioned in capability graph
    for line in graph.splitlines():
        if "**Blockers**:" in line:
            blocker_text = line.split(":", 1)[1].strip()
            if blocker_text and blocker_text != "None":
                title = f"Document blocker: {blocker_text[:60]}"
                tid = _task_id("block", title)
                if not db.is_investigated(title):
                    tasks.append({
                        "id": tid, "type": "document_blocker",
                        "title": title,
                        "description": f"Write detailed analysis of blocker: {blocker_text}",
                        "priority": 5,
                        "evidence_refs": ["docs/CAPABILITY_GRAPH.md"],
                    })

    return tasks


def generate_tasks(db=None):
    """Generate all research tasks, respecting deduplication."""
    if db is None:
        db = TaskDB()

    all_tasks = []
    all_tasks.extend(scan_contradictions(db))
    all_tasks.extend(scan_unverified_claims(db))
    all_tasks.extend(scan_external_research(db))
    all_tasks.extend(scan_calculation_checks(db))
    all_tasks.extend(scan_reproducibility(db))
    all_tasks.extend(scan_blocker_docs(db))

    added = 0
    for task in all_tasks:
        result = db.add_task(
            task["id"], task["type"], task["title"],
            description=task.get("description", ""),
            priority=task.get("priority", 2),
            evidence_refs=task.get("evidence_refs"),
        )
        if result:
            added += 1

    return added, len(all_tasks)


def main():
    db = TaskDB()
    added, total = generate_tasks(db)
    stats = db.get_stats()

    print(f"Task generation: {added} new of {total} scanned")
    print(f"  Pending:   {stats['pending']}")
    print(f"  Running:   {stats['running']}")
    print(f"  Completed: {stats['completed']}")
    print(f"  Failed:    {stats['failed']}")
    print(f"  Dead ends: {stats['dead_ends']}")

    pending = db.get_pending_tasks()
    if pending:
        print(f"\nNext tasks:")
        for t in pending[:5]:
            print(f"  [{t['priority']}] {t['title']}")


if __name__ == "__main__":
    main()
