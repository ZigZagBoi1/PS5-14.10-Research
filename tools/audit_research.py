#!/usr/bin/env python3
"""Read-only inventory and evidence review. Never imports or executes probes."""

import argparse
from collections import defaultdict
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote


EXPERIMENT = re.compile(r"^(\d+[a-z]*\d*)_(.+)$", re.I)
LOG_NAME = re.compile(r"^(.+)_\d{8}_\d{6}$")
PROBE_HEADER = re.compile(r"\bPROBE\s+(\d+[a-z]*\d*)\b", re.I)
STATES = {"observed", "inferred", "superseded", "unverified"}


def confined(root, name):
    """Reject absolute/escaping ledger paths, including symlinks outside root."""
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise ValueError("ledger paths must be nonempty relative paths")
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"path escapes repository: {name}")
    return path


def strings(value, field, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError(f"{field} must be a {'nonempty ' if nonempty else ''}list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{field} must contain nonempty strings")


def matches_experiment_artifact(experiment, reference):
    """Return whether an evidence path is a direct source or log for experiment."""
    path = Path(reference["path"])
    if not path.parts:
        return False
    if path.parts[0] == "probes" and path.suffix == ".lua":
        return path.stem == experiment
    if path.parts[0] == "results" and path.suffix == ".txt":
        match = LOG_NAME.fullmatch(path.stem)
        return match is not None and match[1] == experiment
    return False


def load_ledger(root, path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("ledger must be an object with version 1")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    ids = set()
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("each finding must be an object")
        for field in ("id", "experiment", "summary", "status"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"finding {field} must be a nonempty string")
        if item["id"] in ids or item["status"] not in STATES:
            raise ValueError("duplicate finding ID or unsupported status")
        if not EXPERIMENT.fullmatch(item["experiment"]):
            raise ValueError("experiment must be the complete filename stem")
        ids.add(item["id"])
        strings(item.get("superseded_by", []), "superseded_by")
        strings(item.get("notes", []), "notes")
        if (item["status"] == "superseded") != bool(item.get("superseded_by")):
            raise ValueError("only superseded findings must name superseded_by targets")
        evidence = item.get("evidence")
        references = item.get("references", [])
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("each finding needs nonempty evidence")
        if not isinstance(references, list):
            raise ValueError("references must be a list")
        for ref in evidence + references:
            if not isinstance(ref, dict):
                raise ValueError("evidence/references must contain objects")
            confined(root, ref.get("path"))
        for ref in evidence:
            if ref.get("hash_mode", "bytes") not in ("bytes", "lf"):
                raise ValueError("hash_mode must be bytes or lf")
            if not isinstance(ref.get("sha256"), str) or not re.fullmatch(
                    r"[0-9a-f]{64}", ref["sha256"]):
                raise ValueError("evidence needs a lowercase SHA-256 digest")
            strings(ref.get("anchors"), "anchors", nonempty=True)
        if not any(matches_experiment_artifact(item["experiment"], ref) for ref in evidence):
            raise ValueError(
                f"finding {item['id']} must include evidence for experiment "
                f"{item['experiment']} from probes/ or results/")
        for ref in references:
            if not isinstance(ref.get("anchor"), str) or not ref["anchor"].strip():
                raise ValueError("document references need a nonempty anchor")
    graph = {item["id"]: item.get("superseded_by", []) for item in findings}
    visiting, visited = set(), set()

    def visit(node):
        if node not in ids:
            raise ValueError(f"unknown supersession target: {node}")
        if node in visiting:
            raise ValueError("supersession cycle")
        if node in visited:
            return
        visiting.add(node)
        for target in graph[node]:
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(ids):
        visit(node)
    return findings


def expand_ids(cell):
    """Recognize single IDs and the index's 19c–g / 41n–41q grouped rows."""
    cell = cell.strip().replace("`", "")
    if re.fullmatch(r"\d+[a-z]*\d*", cell, re.I):
        return [cell.lower()]
    match = re.fullmatch(r"(\d+)([a-z])\s*[–-]\s*(\d+)?([a-z])", cell, re.I)
    if match:
        number, first, other, last = match.groups()
        if (other is None or number == other) and first.lower() <= last.lower():
            return [number + chr(c) for c in range(ord(first.lower()), ord(last.lower()) + 1)]
    return []


def index_patterns(cell):
    """Exact suffixes or terminal-* prefixes, optionally separated by '/'.

    Backticks are optional around each name. Descriptive prose, bare '*',
    and other glob syntax cannot identify group membership reliably.
    """
    patterns = []
    for part in cell.split("/"):
        part = part.strip()
        if part.startswith("`") and part.endswith("`"):
            part = part[1:-1]
        if not re.fullmatch(r"[A-Za-z0-9_]+\*?", part):
            return None
        patterns.append(part)
    return patterns


class Audit:
    def __init__(self, root, findings, link_root):
        self.root, self.findings, self.link_root = root, findings, link_root
        self.notices = []
        self.errors = []
        self.inputs = set()

    def link(self, path, line=None):
        relative = path.relative_to(self.root).as_posix()
        target = Path(os.path.relpath(path, self.link_root)).as_posix()
        suffix = f"#L{line}" if line else ""
        return f"[{safe(relative)}{':' + str(line) if line else ''}]({quote(target, safe='/.:')}{suffix})"

    def read(self, path):
        # Track resolved inputs to prevent overwriting any source via --output.
        path = path.resolve()
        if not path.is_relative_to(self.root):
            raise ValueError(f"input escapes repository: {path.name}")
        self.inputs.add(path)
        return path.read_bytes()

    def notice(self, code, text):
        self.notices.append(f"- **{code}**: {text}")

    def inventory(self):
        sources, by_id, logs = defaultdict(list), defaultdict(list), defaultdict(list)
        for path in sorted((self.root / "probes").rglob("*.lua")):
            match = EXPERIMENT.fullmatch(path.stem)
            if not match:
                continue
            sources[path.stem].append(path)
            by_id[match[1].lower()].append(path)
            content = self.read(path).decode("utf-8", errors="replace")
            header = PROBE_HEADER.search("\n".join(content.splitlines()[:40]))
            if header and header[1].lower() != match[1].lower():
                self.notice("HEADER_MISMATCH", f"{self.link(path)}: filename ID {match[1]}, header ID {header[1]} (review manually).")
        for path in sorted((self.root / "results").rglob("*.txt")):
            match = LOG_NAME.fullmatch(path.stem)
            if match and EXPERIMENT.fullmatch(match[1]):
                logs[match[1]].append(path)
        for probe_id, paths in sorted(by_id.items()):
            if len(paths) > 1:
                self.notice("ID_REUSED", f"{probe_id}: " + ", ".join(self.link(p) for p in paths)
                            + ". May be legitimate; do not merge by ID alone.")

        covered = set()
        index = self.root / "docs/PROBE_INDEX.md"
        for line_no, line in enumerate(self.read(index).decode("utf-8").splitlines(), 1):
            cells = [cell.strip() for cell in line.split("|")]
            if len(cells) < 5:
                continue
            ids = expand_ids(cells[1])
            if not ids:
                continue
            patterns = index_patterns(cells[2])
            if patterns is None:
                self.notice("INDEX_AMBIGUOUS", f"{self.link(index, line_no)}: unsupported name/pattern {safe(cells[2])}; membership needs an explicit mapping.")
            for probe_id in ids:
                paths = by_id.get(probe_id, [])
                if patterns is None:
                    # Still expose absent IDs, but never assign coverage by ID alone.
                    candidates = []
                    if paths:
                        continue
                else:
                    candidates = []
                    for path in paths:
                        suffix = EXPERIMENT.fullmatch(path.stem)[2]
                        if any(suffix.startswith(p[:-1]) if p.endswith("*")
                               else suffix == p for p in patterns):
                            candidates.append(path)
                if not candidates:
                    self.notice("INDEX_NO_SOURCE", f"{self.link(index, line_no)}: no matching source for {probe_id} / {safe(cells[2])}.")
                elif len(candidates) > 1:
                    self.notice("INDEX_AMBIGUOUS", f"{self.link(index, line_no)}: {probe_id} matches multiple source paths; none covered: "
                                + ", ".join(self.link(p) for p in candidates) + ".")
                else:
                    covered.update(candidates)

        rows = []
        for stem in sorted(set(sources) | set(logs)):
            paths, results = sources.get(stem, []), logs.get(stem, [])
            if not results:
                self.notice("NO_LOG", f"{safe(stem)}: no filename-matched log; execution status unknown.")
            if not paths:
                self.notice("LOG_NO_SOURCE", f"{safe(stem)}: log has no filename-matched Lua source.")
            if len(paths) > 1 and results:
                self.notice("AMBIGUOUS_LOG", f"{safe(stem)}: logs cannot identify which source path/revision was run.")
            for path in paths:
                if path not in covered:
                    self.notice("UNINDEXED", f"{self.link(path)}: no matching index row.")
            observations = []
            probe_id = EXPERIMENT.fullmatch(stem)[1]
            for path in results:
                content = self.read(path).decode("utf-8", errors="replace")
                complete = re.search(rf"^=== PROBE {re.escape(probe_id)} COMPLETE ===\s*$",
                                     content, re.M | re.I)
                state = "completion marker present" if complete else "no completion marker"
                observations.append(f"{self.link(path)} ({state})")
            rows.append(f"| {safe(stem)} | " + "<br>".join(self.link(p) for p in paths)
                        + " | " + "<br>".join(observations) + " |")
        self.source_count = sum(map(len, sources.values()))
        self.log_count = sum(map(len, logs.values()))
        self.stems = set(sources)
        return rows

    def anchors(self, ref, evidence=False):
        path = confined(self.root, ref["path"])
        try:
            raw = self.read(path)
        except FileNotFoundError:
            self.errors.append(f"- **MISSING_EVIDENCE**: {safe(ref['path'])}")
            return []
        lines = raw.decode("utf-8", errors="replace").splitlines()
        output = []
        if evidence:
            mode = ref.get("hash_mode", "bytes")
            hashed = raw.replace(b"\r\n", b"\n") if mode == "lf" else raw
            actual = hashlib.sha256(hashed).hexdigest()
            if actual != ref["sha256"]:
                self.errors.append(f"- **HASH_MISMATCH**: {self.link(path)}; expected `{ref['sha256']}`, got `{actual}`.")
            label = "LF-normalized SHA-256" if mode == "lf" else "byte SHA-256"
            output.append(f"- Evidence: {self.link(path)}; {label} `{actual}`"
                          + (" (matches ledger)." if actual == ref["sha256"] else " (CHANGED)."))
        for anchor in ref["anchors"] if evidence else [ref["anchor"]]:
            matches = [i for i, line in enumerate(lines, 1) if anchor in line]
            if not matches:
                self.errors.append(f"- **MISSING_ANCHOR**: {self.link(path)}: {safe(anchor)}")
            for line in matches:
                output.append(f"- {self.link(path, line)}: {safe(lines[line - 1])}")
        return output

    def render(self):
        rows = self.inventory()
        review = []
        for finding in self.findings:
            if finding["experiment"] not in self.stems:
                self.notice("REVIEW_NO_SOURCE", f"{safe(finding['id'])}: no source for {safe(finding['experiment'])}.")
            review += [f"### {safe(finding['id'])} — {finding['status']}", "",
                       f"Experiment: {safe(finding['experiment'])}. {safe(finding['summary'])}", ""]
            if finding.get("superseded_by"):
                review += ["Superseded by: " + ", ".join(map(safe, finding["superseded_by"])), ""]
            for ref in finding["evidence"]:
                review.extend(self.anchors(ref, evidence=True))
            for ref in finding.get("references", []):
                review.extend(self.anchors(ref))
            review += ["", *map(safe, finding.get("notes", [])), ""]
        return "\n".join([
            "# Offline research audit", "",
            "This report checks repository artifacts, not PS5 behavior. No hardware reproduction.",
            "Supersession and interpretations below are explicit, manually reviewed ledger entries;",
            "they are not inferred from chronology, keywords, return codes, or completion markers.",
            "A filename match does not prove a log was produced by the current source revision.", "",
            f"Sources: {self.source_count}. Filename-matched logs: {self.log_count}. "
            f"Reviewed findings: {len(self.findings)}. Integrity errors: {len(self.errors)}. "
            f"Review notices: {len(self.notices)}.", "",
            "## Evidence integrity errors", "", *(self.errors or ["None."]), "",
            "## Inventory review notices", "", *(self.notices or ["None."]), "",
            "Missing logs mean missing supporting artifacts, not failed or unrun experiments.",
            "Reused IDs and missing markers need human review; they are not scientific verdicts.", "",
            "## Reviewed evidence and potentially superseded conclusions", "", *review,
            "## Source and log inventory", "",
            "Markers only indicate that the named probe printed its end banner, not success.", "",
            "| Experiment stem | Source paths | Logs and completion markers |",
            "|---|---|---|", *rows, "",
        ])


def safe(text):
    """Escape artifact excerpts as plain Markdown, suppressing binary controls."""
    text = "".join(c if c.isprintable() else " " for c in text)
    text = html.escape(text, quote=False)
    return re.sub(r"([\\`*_[\]|#!])", r"\\\1", text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--ledger", default="docs/RESEARCH_EVIDENCE.json")
    parser.add_argument("--output", type=Path, help="Markdown destination (default: stdout)")
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        if not (root / "probes").is_dir() or not (root / "results").is_dir():
            raise ValueError("root must contain probes/ and results/")
        ledger = confined(root, args.ledger)
        findings = load_ledger(root, ledger)
        output = args.output.resolve() if args.output else None
        audit = Audit(root, findings, output.parent if output else root)
        audit.inputs.add(ledger)
        report = audit.render()
        if output:
            # Protect all research paths, even files not parsed by this version.
            protected = {root / name for name in (".git", "probes", "results", "docs", "swarm", "tools", "tests")}
            if output in audit.inputs or any(output.is_relative_to(p) for p in protected):
                raise ValueError("output would overwrite a research input; choose a separate report directory")
            if output.exists() and not output.read_bytes().startswith(b"# Offline research audit\n"):
                raise ValueError("output would overwrite an existing file that is not an audit report")
            output.write_text(report, encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(report)
        return 1 if audit.errors else 0
    except (OSError, ValueError, UnicodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
