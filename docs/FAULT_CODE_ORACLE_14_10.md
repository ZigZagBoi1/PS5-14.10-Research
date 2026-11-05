# The fault context carries the #PF error code — a kernel mapping oracle

Status: **measured on 14.10, two boots.** A userland script can classify any 64-bit
address as mapped or not mapped, with no syscall that returns information, and recover
the kernel image's base, size and slide for the current boot.

## What is measured

The loader installs a `SIGSEGV` handler that pivots the stack into `0xFB000000` and runs
a `ropchain` built by `signal.setup_pivot_handler`. An uploaded script can rebuild that
chain (`992a` proves the globals are visible, `993b` proves the rebuild lands), and the
kernel hands the handler the faulting thread context in `RDX`.

Dumping `0x100` bytes from `ctx+0xC0` gives one line per fault:

| target | `ctx+0xD8` | `ctx+0x130` | `ctx+0xC8` |
|---|---|---|---|
| `0xFFFFFFFF80000000` (kernel, mapped) | 5 | `0x50E` | `FFFFFFFF80000007` |
| `0xFFFFFFFFA0000000` (kernel, unmapped) | 4 | `0x40E` | `FFFFFFFFA0000007` |
| `0x0000700000000000` (user, unmapped) | 4 | `0x40E` | `0000700000000007` |

Low byte `0x0E` is trap 14; the byte above it is the x86 page-fault error word, bit 0 =
`P`. So **5 = mapped, present, supervisor-only** and **4 = not present**. The third row
is the control that makes this an oracle rather than a signal echo: the same kernel
region answers differently depending on the address, and an unmapped user address
answers exactly like the unmapped kernel one.

`ctx+0xC8` is the fault address OR 7 in all three rows, so it is not the discriminator.

## Consequences

- Kernel pages are present in this process's page tables for that range: no KPTI.
- A userland script can classify any 64-bit address without a syscall.
- Fault classes (`SEGV_MAPERR` vs `SEGV_ACCERR`) become visible from userland, which
  `547`, `639`, `638`, `mincore` and `md` could not do.

## Cost, and turning it into a scanner

A fault on the main thread used to kill the loader process, so one address cost one
relaunch. `999a` settled the confinement: a `thr_create` child whose `RIP` is the kernel
address faults, the rebuilt chain writes its marker, `thr_exit(431)` ends that thread,
and the parent keeps the **same pid**. `1000a` then ran eight addresses in one connection
(`spawned=8 failed=0 alive pid=171`), and `1001a` ran the whole range:

```
[0] pid=171 fd=21 base=0xFFFFFFFF80000000 step=0x200000 count=512
[E] spawned=512 failed=0 alive pid=171
=== COMPLETE ===        (33.5 s, 79,117 bytes)
```

Reading `(ctx+0x130 >> 8) & 0xF` for all 512 steps gives 462 unmapped and 50 mapped, in
exactly two runs:

```
0xFFFFFFFF80000000 - 0xFFFFFFFF80000000   1 step   (2 MB stub at the canonical base)
0xFFFFFFFF91800000 - 0xFFFFFFFF97800000  49 steps  (98 MB image)
```

So the 14.10 kernel image is **not** at the canonical `0xFFFFFFFF80000000`; it sits
`0x11800000` higher, which is the KASLR slide, recovered in one connection without any
syscall that returns information.

## The mapped image, edge to edge

`1002a` (3584 probes at 4 KB over both edges, one connection, `alive pid=171`) resolves
both edges: the first present page is `0xFFFFFFFF91800000` and the last is
`0xFFFFFFFF979FF000`. The image is therefore **98 MB (`0x6200000`)**, aligned to 2 MB.

`1003a` and `1003b` cover the rest of the kernel half:

```
0xFFFFFFFFC0000000 .. 0xFFFFFFFFFFFFFFFF   512 probes at 2 MB   0 mapped
0xFFFFFFFF00000000 .. 0xFFFFFFFF7FFFFFFF  1024 probes at 2 MB   0 mapped
0xFFFF800000000000 .. 0xFFFF807FFFFFFF     128 probes at 4 GB   0 mapped
```

So the direct map is **not present in this process's page table** — the kernel half
visible from userland is the image plus a single 2 MB page, and nothing else.

## The slide is per boot

Same probe, two boots:

| boot | image base | size | stub page |
|---|---|---|---|
| A (`1001a`/`1002a`) | `0xFFFFFFFF91800000` .. `0xFFFFFFFF979FF000` | 98 MB | `0xFFFFFFFF80000000` |
| B (`1004a`/`1005a`) | `0xFFFFFFFFD8000000` .. `0xFFFFFFFFDE1FF000` | 98 MB | `0xFFFFFFFFC0000000` |

Between boots the image moved `+0x46800000`, and the whole pre-reboot window is empty:
`1001a` after the reboot reports 0 of 512 steps mapped from `0xFFFFFFFF80000000` to
`0xFFFFFFFFC0000000`, including the stub page. Both bases are 2 MB aligned, so the oracle
is a genuine per-boot KASLR read rather than a constant.

## What it is and is not

- **Is:** the kernel image base and size per boot, and a mapped/not-mapped verdict for a
  candidate kernel text pointer (5 or 4), one thread per candidate, process survives.
- **Is not:** a read primitive. `1006a` had children execute a stack chain
  (`pop rax; target; mov rax,[rax]; pop rdi; out; mov [rdi],rax`) against the stub page,
  three image addresses and two controls. Every kernel address faulted and left the
  `0xDEADBEEF` sentinel intact, so the supervisor bit is enforced and presence is all the
  oracle reports.
- **Is not:** a window into kernel data structures. The image is visible; the data map is
  not in our page table, so the oracle cannot locate objects or the sysent table.

## Field notes

The absolute values of `ctx+0xD8` and `ctx+0x130` drift between runs (`5`/`0x50E` for a
main-thread fault, `0x15`/`0x150E` for a child fault), so compare the nibble
`(value >> 8) & 0xF` and not the whole qword: 5 = present, 4 = not present.

`push_set_reg_from_rax` clobbers `rdi`, so the fd has to be loaded **after** `rsi` is
computed (`push_set_reg_from_memory("rdi", signal.fd_addr)`), exactly as
`signal.lua:66-70` does. Loading `rdi` first silently writes to fd 0 and the dump never
arrives.

## Probe files

`probes/phase17_new_vectors/995a_fault_class_dump.lua`, `996a_fault_code_oracle.lua`,
`997a_child_fault_survival.lua`, `998a_fault_scan_loop.lua`, `999a_handler_exit_test.lua`,
`1000a_fault_scan.lua`, `1001a_kernel_map_sweep.lua`, `1002a_kernel_base_edges.lua`,
`1003a_kva_layout.lua`, `1003b_below_kernel.lua`, `1004a_kernel_half_sweep.lua`,
`1005a_postboot_edges.lua`, `1006a_kernel_read_probe.lua`, `1008a_cpl_test.lua` (the
privilege-level control below), with their captures under `results/phase17_new_vectors/`.

`1008a` keeps both runs: the `17:10` capture is the shifted-chain version where every
case reads the `0xDEADBEEF` sentinel, and the `17:11` capture is the same probe after the
fix, where `CS` 0x43, 0x40 and 0x00 all read the user buffer and the kernel target leaves
it untouched.

## Two probe-side bugs from the same session

`1006a` and `1008a` had the ROP stack shifted by one slot (RIP is the first gadget, so
the stack starts with its operand), which made a control read of a user buffer fail and
produced a "kernel pages are not user-readable" verdict from a chain that never ran.
`1009a` and `1010a` called `as_addr`, an undefined global, so four "lethal" syscalls were
never entered and their survival was meaningless. Both classes of defect are why every
claim above is tied to a capture with a control case.
