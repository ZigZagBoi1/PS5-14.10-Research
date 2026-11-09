# Fault Oracle KASLR Defeat — PS5 14.10

Status: **independently measured on 14.10** (probes 1199a-1199c, 2026-11-04).

## Mechanism

The loader installs a SIGSEGV handler that pivots into `0xFB000000` and runs
a `ropchain`. We rebuild that chain to: write 0x100 bytes of mcontext to the
client socket, then call `thr_exit(431)` to end the faulting child thread.

A `thr_create(430)` child with `RIP = kernel_address` faults immediately. The
signal handler fires, writes the context dump, and the child exits. The parent
survives with the same pid.

The x86 #PF error code at `ucontext+0xD8` (dump offset 0x18) records:
- Bit 0 (P): 1 = present/protection fault; 0 = non-present fault. In this probe
  class, this distinguishes mapped from unmapped targets.
- Observed low nibbles: 5 = present/protection fault, 4 = non-present fault
  in this probe class; these are not the complete architectural fault taxonomy.
- Bit 2 (U/S): the accessor's mode (1 = user, 0 = supervisor), not the page's
  permissions.

The published child instruction-fetch captures contain raw `0x14`/`0x15`, with
U/S=1 (vs the reported main-thread values `0x04`/`0x05`). For the mapped/unmapped
answer in these observations, the relevant discriminator is bit 0 (P), not the
whole low nibble.

## Reported interpretation (this boot)

| Region | Address | Size |
|--------|---------|------|
| Stub page | `0xFFFFFFFFC0000000` | 2 MB |
| Kernel image (inferred) | `0xFFFFFFFFD4000000` – `0xFFFFFFFFDA5FFFFF` | 102 MB |
| KASLR slide | `+0x54000000` from canonical `0xFFFFFFFF80000000` | — |

Sampling limits (1199b/1199c; addresses below have prefix `0xFFFFFFFF`):
- 1199c observes `D3FFF000` unmapped, then `DA400000` mapped, leaving
  **25,600 intervening 4 KiB positions unobserved**. It does not sample `D4000000`.
- 1199b independently brackets the leading edge in a single capture at 2 MiB
  sampling resolution: T159 `D3E00000` unmapped, immediately followed by T160
  `D4000000` mapped. This bracket does not require cross-capture stability.
- A **conditional** finer 4 KiB bracket combines 1199c's unmapped `D3FFF000`
  with 1199b's mapped `D4000000`. Only this cross-capture refinement assumes
  that the mapping state remained stable between captures.
- 1199b also samples 51 consecutive mapped positions at 2 MiB spacing from
  `D4000000` through `DA400000`, plus the separate mapped `C0000000` stub
  observation. These are sampled positions, not proof that every intervening
  4 KiB page was mapped.
- Matching reported process metadata (pid=749/fd=22) and two agreeing overlapping
  samples (`DA400000`, `DA600000`) support comparison but do not independently
  authenticate mapping-state stability or exclude in-process changes.
- 1199c directly samples 512 mapped addresses from `DA400000` through `DA5FF000`
  at 4 KiB spacing, then unmapped `DA600000`: adjacent trailing-transition endpoints.
  It also samples eight unmapped addresses immediately below `D4000000`.
- Continuous mapping at sub-2 MiB resolution remains unverified within the
  intervening unsampled 4 KiB windows; the final 2 MiB interval has the
  separate dense 1199c sampling described above.

These qualifications distinguish 1199b's single-capture 2 MiB bracket from
its conditional cross-capture 4 KiB refinement. Neither sparse sampling nor
matching process metadata proves continuous coverage or state stability.

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

- **SUPPORTS:** a single-capture 2 MiB leading-edge bracket and sampled image
  span at 2 MiB spacing; a 4 KiB leading-edge refinement is conditional on
  cross-capture mapping-state stability. Continuous sub-2 MiB mapping between
  sparse samples is not established.
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
