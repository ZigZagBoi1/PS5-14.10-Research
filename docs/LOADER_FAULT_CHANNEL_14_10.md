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

One connection. The script does not resume, but **the game survives**: a fresh
`print("alive check")` returns `COMPLETE` immediately after a deliberate fault, so a
crash no longer requires relaunching the loader.

## What it does not give

The report carries the **signal number**, not `si_code`, and no `si_addr` — the chain
stores `RDX` (the `ucontext`) but never `RSI` (the `siginfo`). That matters because
the obvious use, a mapped/unmapped oracle over kernel addresses, needs `SIGSEGV`
`si_code` to separate `SEGV_MAPERR` from `SEGV_ACCERR`. Both fault classes arrive as
`11` here, so the channel is a crash decoder and **not** an address-probe oracle.

Getting `si_code` would mean rewriting the pivot chain to store `RSI` and write
`0x100` bytes from it, which needs the pivot base of that fixed page and a chain edit;
it is not attempted here.

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
