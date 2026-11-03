# The loader's fault channel: SIGSEGV reports reach the PC

Status: measured, 2026-11-03, firmware 14.10.

Every probe in this repository that dies does so silently. The capture stops and the
cause is unknown, which is why so many entries in `docs/ATTACK_SURFACE.md` say only
"killed". The loader already ships the instrumentation to fix that, and it was never
used: `savedata/signal.lua` installs a handler for `SIGILL`, `SIGBUS` and `SIGSEGV`
that writes a report to the client socket.

## What the loader installs

From the loader's own source (readable at fd 18, see below):

```lua
local signals = {SIGILL, SIGBUS, SIGSEGV}
memory.write_qword(sigaction_struct, handler_addr)      -- sa_handler
memory.write_qword(sigaction_struct+0x20, SA_SIGINFO)   -- sa_flags
syscall.sigaction(signal, sigaction_struct, 0)
```

`signal.register()` points that at a stack-pivot gadget and builds a ROP chain on a
fixed pivot page (`map_fixed_address(pivot_handler.pivot_base, 0x2000)`). The chain
writes to the client fd:

```lua
memory.write_qword(output_addr, 0x13371337)                 -- magic
chain:push_store_rdi_into_memory(output_addr + 0x8)         -- "rdi contains signal code"
chain:push_store_rax_into_memory(output_addr + 0x10)        -- "rax contains crashing address"
chain:push_store_rdx_into_memory(ucontext_struct_addr)
-- write(fd, output_addr, 0x18)
-- write(fd, ucontext + 0x40, 0x100)                        -- mcontext
```

`enable_signal_handler = true` is the default in `main.lua`, and
`signal.set_sink_fd(client_fd)` points the sink at whoever is connected.

## What actually arrives

`probes/phase17_new_vectors/988a_fault_channel.lua` reads the unmapped user address
`0x10` on purpose. The reply is **440 bytes of binary**, not a Lua error:

| offset | value | meaning |
|---|---|---|
| `+0x00` | `0000000013371337` | the magic |
| `+0x08` | `000000000000000b` | **11 = SIGSEGV**, the signal number |
| `+0x10` | `0000000000000000` | the "crashing address" slot, unfilled here |
| `+0x20` | `c048110300000010` … | the `mcontext` register block, `0x100` bytes |

The `mcontext` carries the saved register file at the fault: `RDI`,
`RFLAGS`-shaped `0x0400000000000000`, `0xFFFFFFFFFFFFFFFF`, and `RIP 0x3113fe7a0`
(the instruction that faulted). So a death is now **decodable**: signal number plus
the complete register state.

## What it costs

**The loader process.** The report is delivered, the script does not resume, and the
process is gone: after 993a faulted, the next connection was refused until the loader
was relaunched. Every fault below was paid for with a relaunch. So the channel is a
*reporter*, not a recoverable trap — but it converts a silent death into a signal
number plus a register file, which is the difference between "the probe died" and "the
probe faulted at `RIP` while holding this address".

## What it does not give

The report carries the **signal number**, not `si_code`, and no `si_addr` — the chain
stores `RDX` (the `ucontext`) but never `RSI` (the `siginfo`). That matters because
the obvious use, a mapped/unmapped oracle over kernel addresses, needs `SIGSEGV`
`si_code` to separate `SEGV_MAPERR` from `SEGV_ACCERR`. Both fault classes arrive as
`11` here, so the channel is a crash decoder and **not** an address-probe oracle.

Getting `si_code` would mean rewriting the pivot chain to store `RSI` and write
`0x100` bytes from it, which needs the pivot base of that fixed page and a chain edit;
it is not attempted here.

## Historical reports: the channel was already in every capture

The report is written by the loader, not by the probe, so **every capture in this
repository where a probe faulted already contains it** — `23362` reports across `395`
captures, counted with the tool below. They were read as binary garbage and discarded.

`tools/decode_fault_report.py` finds every report in a capture and prints the header and
the context block:

```
python tools/decode_fault_report.py --scan results
python tools/decode_fault_report.py --verbose results/phase17_new_vectors/988a_fault_channel_20261103_153229.txt
```

Two offsets were validated against probes whose faulting site is known, so the context
is usable for attribution:

| offset | field | evidence |
|---|---|---|
| context `+0xA0` | **`RIP`** at the fault | `952a` spawned a thread into the page `0x65AC0000` and the report carries `0x65AC0000` there |
| context `+0x78` | the register that held the faulting data address | `988a` read the address `0x10`, and `0x10` appears there |

The rest of the block is the loader's own context structure (the same `0x480`, `CS=0x43`
and `SS=0x3B` fields documented in `docs/THREADING_ALIVE_14_10.md`), not a plain
`sigcontext`, which is why the field map stops at the two offsets that were verified.

The immediate use is retroactive: a death that was recorded as "the process died" can
now be checked for a `RIP` in a known module and a data address in the context, which
separates a userland fault in our own chain from a kernel-side kill. A death with **no**
report at all is the other half of the signal — `990a` called `221 semget(IPC_PRIVATE,
1, 0666)`, which kills the process, and no report was produced, so those kills are
`SIGSYS`/`SIGKILL`-class rather than a fault the handler can see.

## The chain is rebuildable from a script

An uploaded script runs inside the loader's own Lua state, so the modules it required
are still globals: `ropchain`, `signal`, `gadgets`, `kernel`, `thread`, `native`,
`lua`, `syscall`, `uint64`, `bit32`, `struct`, `gpu` all report as tables (`992a`).
`gadgets.stack_pivot` resolves at runtime to
`{gadget = eboot+0x3963d4, pivot = 0xFB0000BD, base = 0xFB000000}`, and
`signal.fd_addr` holds the descriptor of the connection the report is written to.

That means the handler's behaviour is a script decision, not a fixed policy: build a
`ropchain({stack_base = 0xFB0000BD})` and the next fault runs it. `993b` proves the
mechanism by writing a marker — the chain produced `CHAIN-OK-9F3A` on the socket — and
`993c` uses it to copy memory the shipped chain never touches.

Dumping the frame this way is how the register convention was checked. Reading from
`RSI` at handler entry yields no bytes, so `RSI` is not a pointer here, while `RDX`
is the thread context: `993c` and `995a` each returned `0x300` bytes containing the
faulting address at `+0x50` and `+0xB8`.

## The context carries the page-fault error code, and that is a kernel mapping oracle

Two runs of the same fault class are byte-identical outside the heap and `RIP` fields,
and the fields that track the address are `+0xD8` and `+0x130`:

| target | `ctx+0xD8` | `ctx+0x130` | reading |
|---|---|---|---|
| `0xFFFFFFFF80000000` (kernel) | `5` | `0x50E` | present, user access denied |
| `0x0000700000000000` (unmapped) | `4` | `0x40E` | not present |
| `0xFFFFFFFFA0000000` (kernel, unmapped) | `4` | `0x40E` | not present |

The low byte `0x0E` is trap 14, and the value above it is the x86 page-fault error
word: bit 0 is `P`. So `5` means the page **is mapped** and only the user/supervisor
bit denies the access, while `4` means it is not mapped at all. The third row is what
makes this an oracle rather than a signal-number echo: the same kernel range answers
differently depending on the address, so the field follows the mapping.

Two consequences. Kernel pages are present in this process's page tables — there is no
KPTI for the probed range — and a kernel address can be classified from userland
without a syscall that returns information.

The cost is decisive for how it can be used: a fault kills the loader process, so one
address costs one relaunch. `997a` spawned a `thr_create` child with its `RIP` on the
kernel address, and the child's fault took the process with it - the frame was dumped
but the parent never reached its `ALIVE` line. Without a resuming handler the oracle
is a per-address instrument for a short list of candidates, not a scanner.

## The second channel: the loader's own source at fd 18

`read(3)` on descriptor 18 returns the loader's `main.lua` (first bytes `\noptions`),
in chunks of up to `0x100` bytes. `probes/phase17_new_vectors/987a_loader_source_extract.lua`
reads it and prints only lines that mention the mechanisms of interest, which turns
the loader's capability list into something readable rather than inferred:

```
enable_signal_handler = true,
require "ropchain"
require "signal"
require "kernel_offset"
syscall.resolve({
    sigaction = 0x1a0,
    thr_self = 0x1b0,
    dlsym = 0x24f,
    dynlib_load_prx = 0x252,
    dynlib_unload_prx = 0x253,
```

and the command path that drives the handler (`signal.set_sink_fd(client_fd)`,
`signal.clear()`, `signal.register()`).

Descriptor 18 is **read-only and destructive to the connection**: it is a stream, so a
second read continues where the first stopped, and reading descriptors 20 or 21 (the
loader's listener and the accepted PC connection) blocks forever and wedges the
loader. Use `fcntl` for classification; see
[DEVICE_DESCRIPTORS_14_10.md](DEVICE_DESCRIPTORS_14_10.md).

## Related

- [DEVICE_DESCRIPTORS_14_10.md](DEVICE_DESCRIPTORS_14_10.md) — the descriptor
  table this channel was found through.
- `docs/CHANGELOG.md` 2026-10-24 already records that `SIGSYS` is ignored through
  `sigaction(12, SIG_IGN)` (probes 353a/353b): the handler was known, its report
  channel was not.
