# Offline evidence ledger and inventory

This is the usage and scope guide for `tools/audit_research.py` and
`RESEARCH_EVIDENCE.json`. It complements the existing
[evidence audit](EVIDENCE_AUDIT_2026-10-17.md) and
[independent audit](INDEPENDENT_EVIDENCE_AUDIT_2026-10-17.md); those dated reviews
are retained unchanged. Their historical open questions do not negate later
saved results. This guide does not replace their broader artifact reviews.

## Run locally

Python 3.10+, standard library only. From the repository root:

```bash
python -m unittest discover -s tests -v
python tools/audit_research.py
python tools/audit_research.py --output ../offline-audit.md
```

The CLI reads Lua sources as data. It never imports console, sender, watchdog,
or swarm code, evaluates Lua, or opens a network connection. It writes only an
explicit report destination, rejecting research paths and unrelated existing
files. Exit 0 means no ledger integrity errors; inventory notices may remain.
Exit 1 means missing/changed evidence or anchors; exit 2 is a usage/schema error.

## Index matching

IDs are expanded individually: `19c–g` and `41n–41q` are inclusive ranges. The
Name cell matches the filename suffix after `ID_`, case-sensitively:

- `fn_redirect` matches exactly, with optional Markdown backticks.
- `group_*` matches suffixes starting with `group_`; only a terminal `*` is
  supported. Bare `*`, other glob syntax and descriptive prose are ambiguous.
- Backticked or bare alternatives separated by `/` form a union, for example
  `heap_objects`/`uaf_spray`. Each ID must still have an individual match.
- No matching source for an ID produces `INDEX_NO_SOURCE`, even if another ID
  in the range matches. Unrelated sources sharing an ID remain `UNINDEXED`.
- Multiple matching paths for one ID produce `INDEX_AMBIGUOUS`; none is marked
  covered by that row. Split the row or supply a more specific mapping. Identical
  stems in different phases remain ambiguous; the tool does not guess a phase.

The index contains historical group labels that do not map every member by these
rules. Notices expose that uncertainty; they do not declare a probe failed,
unrun, or scientifically invalid. Filename-matched logs are inventory, not
authenticated source/run provenance. Non-Lua scripts and nonconforming filenames
are outside this version's inventory.

## Curated scope and interpretation

Six findings are explicitly reviewed in the JSON ledger. The original five
cover 43i/44a/45a/45b/45c; the sixth preserves later selected CClosure evidence.
The ledger pins observations, literal source anchors, and explicit supersession:

- 43i restores modified slot0 before getpid. Its fn_addr sentinel persists,
  but modified-slot persistence across that call was not tested.
- 44a's NOP success banner requires only pcall survival. The requested constant
  is not observed; ret=1 from syscall 585 does not prove page execution.
- 45a's observed length 2048 equals its initialization 0x800. Its result slot
  retains the sentinel, rather than demonstrating a native sysctl side effect.
- The completed 45c `192713` run contains the controls; `192602` stops in section
  B. Selected calls persisted after the tested mutations. This undermines that
  dependency model, without identifying a dispatcher or proving universal bypass.
- Later 56c A/B record distinguishing Lua values and restoration after selected
  existing C-function targets are substituted. C/D print stringified 42 without
  a type check. 56f adds string.len/math.abs target-like output. The two 56c
  captures are byte-identical, so they are not independent replications.

Selected Lua-compatible targets do not establish arbitrary executable targets,
machine-register argument control, a working general ROP chain, injected-page
execution, kernel R/W, KASLR defeat or hypervisor bypass. The 56e gadget tests
record nil returns; a saved timeout or binary suffix alone does not establish an
executed instruction, an internal type() call, or a kernel termination cause.
These are static readings of saved artifacts, with no new hardware reproduction.

## Ledger maintenance and limits

Each finding has an experiment stem, status (`observed`, `inferred`,
`unverified`, `superseded`), summary, evidence paths/SHA-256/literal anchors,
optional document locators, notes and explicit `superseded_by`. Its evidence must
include a direct artifact for that experiment: either the matching
`probes/**/<experiment>.lua` source or a matching
`results/**/<experiment>_YYYYMMDD_HHMMSS.txt` log. Supplemental artifacts from
other experiments may add context, but cannot be the sole support for a finding.
Unknown targets, cycles and malformed records are rejected. Supersession is human
curation, not a timestamp or keyword heuristic. It applies to the older claim,
not every future experiment with a different mechanism.

`hash_mode: "lf"` hashes bytes after CRLF-to-LF conversion; otherwise byte
hashing is used. Digests pin reviewed artifacts, not firmware identity, origin,
loader build, or the exact source that generated a run. Anchors are substring
locators with line links, not semantic checks on surrounding prose. A completion
marker proves that the banner is present, not successful execution or transport.
The tool does not discover arbitrary documentation contradictions or adjudicate
unlisted research. Extending coverage requires a separate source/log review.

Run upstream's additional offline tests separately:

```bash
python -m unittest discover -s tools -p "test_*.py" -v
python -m unittest discover -s tools/ghidra -p "test_*.py" -v
lua tools/test_probe46a.lua
```

The sender tests use a local loopback fixture, never a console; the Lua 5.1
harness uses a memory/syscall sandbox. Root unittest discovery only finds the
new `tests/` package, so it is not a substitute for those explicit commands.
