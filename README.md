# PS5 Firmware 14.10 — Kernel Research

Systematic kernel attack surface mapping on PlayStation 5 firmware **14.10**, conducted via a userland Lua 5.1 loader at `10.0.0.96:9026`.

> **Goal:** Userland code exec → Kernel R/W → Hypervisor bypass

## Status

All userland exploit primitives are confirmed working. The loader's ROP chain is fully writable from the heap primitive — both the function call target and all argument slots can be overwritten. The next milestone is achieving kernel memory access through the network input path.

See [CHANGELOG.md](CHANGELOG.md) for a detailed timeline.

## Repository Structure

```
├── probes/                      # Lua scripts sent to the PS5
│   ├── phase1_identity_layout/  # Probes 01–08: system ID, syscalls, memory layout
│   ├── phase2_kernel_objects/   # Probes 09–21: UMTX, nwake, dmem, AIO, kqueue
│   ├── phase3_signals_codexec/  # Probes 22–26: signals, sigaltstack, W^X, XOM
│   ├── phase4_ipc_network/      # Probes 27–31: threading, fd passing, socket opts
│   ├── phase5_buffer_io/        # Probes 32–33: buffer stress, MSG_DONTWAIT
│   ├── phase6_raw_packets/      # Probes 34–39: RAW sockets, fragments, IP options
│   ├── phase7_heap_exploitation/# Probes 40–41: GPU mmap, heap R/W, ROP, ASLR bypass
│   └── phase8_live_network/     # Probes 40tcp, 42: TCP fuzz, ktimer, live testing
├── results/                     # Raw output logs (mirrored phase structure)
├── tools/                       # Python utilities (send_probe, TCP fuzz server)
├── docs/
│   ├── ATTACK_SURFACE.md        # Complete syscall status map
│   ├── FINDINGS.md              # Detailed technical findings
│   ├── PROBE_INDEX.md           # Every probe with status and key result
│   └── STRATEGY.md              # Exploit strategy and next steps
└── CHANGELOG.md                 # Phase-by-phase progress log
```

## Environment

| Property | Value |
|----------|-------|
| Firmware | 14.10 |
| Kernel | FreeBSD r230171 (Sep 28 2026) |
| Entry point | Lua 5.1 loader on TCP 9026 |
| Page size | 16 KB (0x4000) |
| CPU | Zen 2, 8C/16T (16 logical cores) |
| Securelevel | 1024 (PS5-specific) |

## Confirmed Primitives

| Primitive | Source |
|-----------|--------|
| Arbitrary syscall | `make_syscall()` via Lua loader |
| Heap read/write (256+ pages) | GPU mmap adjacency — no guard pages |
| ASLR bypass | `dynlib_get_info` leaks all 39 module bases |
| Complete ROP gadget set | Extracted from eboot (RX, not XO) |
| Stack pivot (`pop rsp; ret`) | eboot+0x9A2 |
| ROP chain hijack | Chain + fn_addr writable from heap (probe 41z) |
| Kernel info via sysctl | FreeBSD r230171, securelevel=1024 |

## Key Constraints

- **W^X enforced** — `mmap(RWX)` gives RW only; `mprotect(EXEC)` always fails
- **Execute-only memory** — system lib text is XO (reading crashes); eboot is RX
- **No threading** — `fork`, `rfork`, `thr_new` all blocked
- **AIO sandbox-killed** — all `aio_*` syscalls terminate the process
- **Per-connection ASLR** — fresh process per TCP connection
- **No kernel pointers in userland heap** — exhaustive 10,240 qword scan

## Quick Start

```bash
# Send a probe to the PS5
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/phase1_identity_layout/01_identity.lua

# TCP connect-back fuzz session
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

See [tools/README.md](tools/README.md) for details.

## Lua Constraints

1. **uint64 for addresses >32 bits**: `uint64(string.format("0x%X%08X", hi, lo))`
2. **pcall wrapping**: `pcall(function() return memory.read_qword(addr) end)`
3. **Lua 5.1**: no `goto`/labels — use `repeat...until true` + `break`
4. **XO pages bypass pcall**: reading execute-only memory kills the process
5. **Fresh ASLR per connection**: re-derive all addresses each run

## Documentation

| Document | Contents |
|----------|----------|
| [CHANGELOG.md](CHANGELOG.md) | Phase-by-phase progress timeline |
| [docs/PROBE_INDEX.md](docs/PROBE_INDEX.md) | Full probe-by-probe breakdown |
| [docs/ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md) | Complete syscall status map |
| [docs/FINDINGS.md](docs/FINDINGS.md) | Detailed technical findings |
| [docs/STRATEGY.md](docs/STRATEGY.md) | Exploit strategy assessment |
| [docs/UNTESTED_THEORIES.md](docs/UNTESTED_THEORIES.md) | Untested exploit theories and attack chains |

## License

This research is for educational and authorized security research purposes only.
