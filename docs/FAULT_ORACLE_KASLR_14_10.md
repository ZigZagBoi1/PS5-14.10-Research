# Fault Oracle KASLR Defeat — PS5 14.10

Status: **independently measured on 14.10** (probes 1199a-1199c, 2026-11-04).

## Mechanism

The loader installs a SIGSEGV handler that pivots into `0xFB000000` and runs
a `ropchain`. We rebuild that chain to: write 0x100 bytes of mcontext to the
client socket, then call `thr_exit(431)` to end the faulting child thread.

A `thr_create(430)` child with `RIP = kernel_address` faults immediately. The
signal handler fires, writes the context dump, and the child exits. The parent
survives with the same pid.

The x86 #PF error code at `ucontext+0xD8` (dump offset 0x18) discriminates:
- `(value & 0xF) == 5` → page **present** (mapped, supervisor-only)
- `(value & 0xF) == 4` → page **not present** (unmapped)

For child thread faults the raw values are `0x15`/`0x14` (vs `0x05`/`0x04` for
main thread). The low nibble is what matters.

## Reported interpretation (this boot)

| Region | Address | Size |
|--------|---------|------|
| Stub page | `0xFFFFFFFFC0000000` | 2 MB |
| Kernel image (inferred) | `0xFFFFFFFFD4000000` – `0xFFFFFFFFDA5FFFFF` | 102 MB |
| KASLR slide | `+0x54000000` from canonical `0xFFFFFFFF80000000` | — |

Sampling limits (1199b/1199c; addresses below have prefix `0xFFFFFFFF`):
- 1199c observes `D3FFF000` unmapped, then `DA400000` mapped, leaving
  **25,600 intervening 4 KiB positions unobserved**. It does not sample `D4000000`.
- The reported `D4000000` interpretation is supported by a **conditional** local
  4 KiB bracket: 1199c's unmapped `D3FFF000` and 1199b's mapped `D4000000`,
  assuming both captures represent a shared, stable mapping state.
- Matching reported process metadata (pid=749/fd=22) and two agreeing overlapping
  samples (`DA400000`, `DA600000`) do not independently authenticate stability.
- 1199c directly samples 512 mapped addresses from `DA400000` through `DA5FF000`
  at 4 KiB spacing, then unmapped `DA600000`: adjacent trailing-transition endpoints.
  It also samples eight unmapped addresses immediately below `D4000000`.
- Neither capture establishes continuous mapping throughout the inferred image span.

These qualifications prevent attributing the leading 4 KiB bracket to 1199c alone
or treating sparse samples as proof of continuous coverage; the shared-stable-state
assumption is necessary for the combined interpretation.

Offline evidence check (SHA-256, record indices/byte offsets, raw values and arithmetic):

```sh
python3 -B tools/check_fault_oracle_boundary.py
python3 -B -m unittest -v tools.test_fault_oracle_boundary
```

The checker verifies observations and a conditional bracket, not mapping-state stability
or firmware authenticity. It requires no console and does not execute probe code.

## Performance

- 512 probes per connection, 33 seconds, process survives
- 60 ms sleep between child spawns (enough for handler + thr_exit)
- 1024 total probes (lower + upper half) to cover entire kernel VA range
- 528 probes for edge resolution at 4 KB

## What it is and is not

- **SUPPORTS:** the reported kernel image base, span, and KASLR slide interpretation
  for this boot, conditional on cross-capture stability; continuous mapping throughout
  the inferred span is not established.
- **IS:** proof that no KPTI is active (kernel pages present in userland tables)
- **IS NOT:** a read primitive — supervisor bit is enforced, content unreadable
- **IS NOT:** a window into kernel data structures (direct map not in page table)

## Key implementation details

- `push_set_reg_from_rax` clobbers `rdi` — fd must be loaded LAST in the write chain
- `mk(4)` for write and `mk(431)` for thr_exit avoid dependence on `syscall.write` global
- Child ucontext gates: `+0x108=0x480`, `+0x110=0x10000`, `CS=0x43`, `SS=0x3B`
- Binary output: each probe emits 0x100 bytes to the socket between text `[TXXX]` lines
- `tools/decode_fault_scan.py` parses the interleaved text+binary output

## Probe files

- `probes/phase17_new_vectors/1199a_fault_oracle_kaslr.lua` — lower half (80000000-BFFFFFFF)
- `probes/phase17_new_vectors/1199b_fault_oracle_upper.lua` — upper half (C0000000-FFFFFFFF)
- `probes/phase17_new_vectors/1199c_fault_oracle_edges.lua` — 4 KB edge resolution
- `tools/decode_fault_scan.py` — binary output decoder

## Credit

Technique discovered and first measured by ng643 (PR #183). This is an independent
reproduction using the same signal-handler-rebuild approach.
