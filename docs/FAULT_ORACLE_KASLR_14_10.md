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

## Results (this boot)

| Region | Address | Size |
|--------|---------|------|
| Stub page | `0xFFFFFFFFC0000000` | 2 MB |
| Kernel image | `0xFFFFFFFFD4000000` – `0xFFFFFFFFDA5FFFFF` | 102 MB |
| KASLR slide | `+0x54000000` from canonical `0xFFFFFFFF80000000` | — |

Edge resolution at 4 KB (probe 1199c) confirmed:
- Leading edge is exactly at `0xFFFFFFFFD4000000` (2 MB aligned)
- All 512 pages in the last 2 MB step are mapped
- First page past image (`DA600000`) is unmapped
- 8 pages below image start are all unmapped

## Performance

- 512 probes per connection, 33 seconds, process survives
- 60 ms sleep between child spawns (enough for handler + thr_exit)
- 1024 total probes (lower + upper half) to cover entire kernel VA range
- 528 probes for edge resolution at 4 KB

## What it is and is not

- **IS:** kernel image base, size, and KASLR slide per boot
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
