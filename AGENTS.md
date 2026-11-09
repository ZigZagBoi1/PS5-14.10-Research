# AGENTS.md — PS5 14.10 research repo

Kernel exploit research on PS5 firmware 14.10 (FreeBSD 11-based, r230171, 16 KB pages).
Two live entry vectors: a **Lua 5.1 loader over TCP 9026** and the **WebKit 605.1.15
browser**. This is an evidence repo, not a codebase: most files are probes and raw
captures. Optimize for not repeating dead ends and not overstating results.

## Read before proposing or writing a vector

| Source | Why |
|---|---|
| `CLAUDE.md` | Authoritative research state. Its **top "Current Evidence Correction"** supersedes older claims further down the file. 96 KB — read the correction block and dead-ends section, not the whole file. |
| `docs/DEAD_ENDS.md` | ~170 closed vectors. Read before writing any probe. |
| `docs/EXPLOITATION_STATUS.md` | One-page chain status and open blockers. |
| `docs/PROBE_INDEX.md` | Per-probe status (partially stale; check `probes/` and `results/` too). |
| `docs/RESEARCH_EVIDENCE.md` | Evidence ledger rules and `tools/audit_research.py` usage. |

Hard fact that invalidates most stale reasoning: the 13.60 dumps in `docs/dumps_13.60/`
are a *different firmware* and a fixed-range capture. Static findings do not transfer to
14.10 without a live probe.

## Evidence rules (non-negotiable)

- `results/**` and `tools/browser_runner/beacon_logs/**` are **committed raw captures**. Never edit, reformat, truncate, or delete one. Corrections go in a new capture plus a doc note.
- Keep three levels distinct: observed bytes, interpretation supported by those bytes, unresolved hypothesis. Write "not demonstrated" rather than inflating a primitive.
- Transport timeout/reset is **not** proof of a process kill — correlate with `tools/ps5_watchdog.py` (`ALIVE` / `LOADER_DOWN` / `REBOOTING`).
- A kill is **not** proof a syscall slot is absent. Install `sigaction(12, SIG_IGN)` first; then absence returns `-1` while a real handler that faults still dies.
- Kernel pointers are `0xFFFF8xxx_xxxxxxxx`. `0xFFFFFFFF_*` values are sentinels/bitmasks.
- Every claim needs a probe ID and a capture path. Update `docs/DEAD_ENDS.md` and `CHANGELOG.md` when a vector closes.

## Verification commands (no console needed)

```bash
python3 tools/verify_offline.py            # REQUIRED CI gate: 165 stdlib-only tests, ~16s
python3 tools/verify_offline.py --list     # exact selected module list
python3 -m unittest -v tests.test_offline_verification
python3 tools/audit_research.py            # ledger integrity; 0=clean, 1=drift, 2=usage
python3 tools/render_progress.py --check   # README progress block + docs/progress.json
python3 tools/check_lua_syntax.py          # needs lupa==2.6 (not installed by default)
```

Optional full suite (needs pinned deps, still no console):

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -r requirements-offline-optional.txt   # capstone, lupa
python3 -m unittest discover -s tools -p 'test_*.py' -v
```

CI also runs `bash -n` on every tracked `*.sh`, and a loopback-only sender matrix
(`tools/test_send_probe.py`, `tools/test_capture_collision_safety.py`,
`tools/test_send_probe_helpers.py`, plus the `bounds_fuzz` / `ioctl_isolation_sweep`
/ `restart_pressure` / `run_probe_batch` driver tests). Tests must never contact a console.
Root `unittest discover` only finds `tests/`, so it is not a substitute for the commands above.

`render_progress.py --check` legitimately fails right now: adding probes or result
captures changes the live inventory counts, and `docs/progress.json` still records
2,798/57/46/3,245/53 while the tree has 2,860/58/177/3,373/55. Re-audit and update
`inventory` (and `evidence_hashes` for any pinned evidence file) instead of hand-editing
the README block. Do not "fix" this by deleting the check.

## Console work

```bash
# one probe; --save mirrors the phase path into results/
PYTHONIOENCODING=utf-8 python3 tools/send_probe.py --save --metadata --strict \
    --ip <PS5_IP> probes/<phase>/<name>.lua

# bounded batch: stops on first timeout/reset unless --continue-on-failure
PYTHONIOENCODING=utf-8 python3 tools/run_probe_batch.py --save --strict <probe...>

# classify a wedge: ALIVE / LOADER_DOWN / REBOOTING
python3 tools/ps5_watchdog.py --ps5-ip <PS5_IP>
```

- The console IP is **not fixed**. Tool defaults are `10.0.0.96`; recent beacon logs show
  `192.168.1.37`. Always pass `--ip`.
- Frame format: 8-byte little-endian uint64 length + raw Lua source. Senders never retry.
- Every kill costs one loader process and recovery gets slower; repeated kills can wedge
  port 9026 until the console is power-cycled. Prefer one probe per connection, small
  batches, and the sweep drivers' `--resume` / `--wait-for-loader` / wedge guard.
- Per-connection ASLR: a fresh process spawns per TCP connection. Never hardcode addresses.

## Adding a Lua probe

Place in `probes/<phase_dir>/<id>_<description>.lua`. Continue the numeric ID sequence
(latest is `1404`); never reuse an ID. Start the file with:

```lua
-- CRASH_CLASS: LOW | MODERATE | HIGH | RISKY
-- PROBE <id>: one-line description
```

Follow the template and helpers in `CLAUDE.md` ("How to Write Probes"). Lua 5.1 only:
no `goto`/labels, `uint64()` for 64-bit values, `pcall` around risky calls,
`memory.alloc(N)` buffers zeroed before use. Reading execute-only pages kills the process
past `pcall`; `.sprx` `.rodata` (`p=0x1`) and GPU device mappings are unreadable. Eboot
text is RX and safe.

## Adding a WebKit probe

HTML/JS probes live in `probes/phase13_webkit/` as `p<num>-<description>.{html,js}`.
Continue the `p` sequence (latest is `p686`).

- Serve with `python3 tools/browser_runner/serve.py --cert <crt> --key <key>`; with neither
  it generates a self-signed cert for `ps5.np.playstation.net` / `manuals.playstation.net`.
- **New pages must be registered in the `STATIC` route map in `serve.py`** — dropping a
  file in `probes/phase13_webkit/` does not make it reachable.
- Probes beacon to `/beacon`; logs land in `tools/browser_runner/beacon_logs/beacons_<stamp>.log`
  and are committed evidence. Prefer beacon lines over `console.log` (no devtools).
- `serve.py` keeps p686 census state (`/p686state`) because a crash wipes the heap
  addresses the page would otherwise reuse. Reset/relaunch behaviour matters: each load
  after the first in a live process may die for reasons unrelated to the forge.
- Cert material and `tools/webkit_server.py` are gitignored on purpose; don't add them.

## Repo quirks

- `docs/ALL_PROBES.md` is a **stale snapshot** (2,682 probes, 2026-10-28). Read `probes/`.
- `4TheDoctor/` is a local nested checkout and is gitignored; it is not part of this tree.
- `docs/progress.json` pins 11 evidence files by SHA-256. Changing a pinned doc without
  updating its hash fails `render_progress.py --check`.
- The `SYSCALL_NAMES` block in `tools/ghidra_label_syscalls.py` is generated from
  `docs/sysent-names-13.60.csv`; regenerate with `python3 tools/gen_syscall_labels.py`,
  never hand-edit it.
- `tools/offline/` holds Ghidra/static-analysis helpers; `tools/ghidra/` has its own tests.

## Git

- Current checkout is a fork: `origin` = `4TheDoctor/PS5-14.10-Research`, `upstream` =
  `ZigZagBoi1/PS5-14.10-Research`. Confirm which remote a change belongs to before pushing.
- Work on a feature branch; subjects follow Conventional Commits (`feat:`, `fix:`, `docs:`,
  `chore:`) and describe the campaign, e.g. `feat: p686 v5 — +0x58 axis arms`.
- **No AI attribution or `Co-Authored-By` trailers** in commits, PRs, or code.
- Stage only files relevant to the current campaign; probe captures and beacon logs that
  the run produced belong in the same commit as the analysis that cites them.
