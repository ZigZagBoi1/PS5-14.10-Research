# What the loader sends when it faults (and why 1173a died)

Local-only note: derived from `.local/loader_payload/signal.lua` and a live capture. Not for publishing.

## The format

`signal.register()` installs a pivot handler on SIGILL, SIGBUS and SIGSEGV
(`.local/loader_payload/signal.lua:4`, `register_signal_handler`) and the ROP chain it builds writes
two blobs straight back over the probe socket:

| bytes | content |
|---|---|
| 0x00 | magic `0x13371337` |
| 0x08 | `rdi` = signal number (`0x0B` = SIGSEGV) |
| 0x10 | `rax` = "crashing address" as the kernel left it (0 is common — do not trust it) |
| 0x18 | `rdx` = pointer to the ucontext (0 when the handler was not entered with SA_SIGINFO data) |
| 0x20 | `0x100` bytes starting at ucontext+0x40, i.e. the mcontext |

So a capture that suddenly turns into 320 bytes of binary after a clean text header is **not**
corruption: it is the loader reporting its own crash. `send_probe` then reports `COMPLETE` with no
`=== DONE` marker, which looks like a tidy finish and is the opposite.

Decoding rule for the mcontext blob: `ctx+0x08` is the last qword of the register file that the
kernel filled before the fault — in the 1173a capture it read `0x000000015b17c000`, and the probe had
been reading from `libc_base = 0x000000015B05C000`.

## What it measured

`0x15b17c000 - 0x15b05c000 = 0x120000`. The scan walked upward in 4-byte steps and the last readable
byte was at the very end of that window: **this libc's mapping is exactly `0x120000` bytes**, and the
probe read one dword past its end and took the loader with it.

That also cross-checks the offset table: `libc_addrofs.gettimeofday_import = 0x11c010` sits just
below the top of a `0x120000` mapping, which is where the last syscall wrapper of a libc usually
lands.

## Consequences

* Any libc scan must be bounded by `0x120000`, not by a guessed size. 1173a now uses it.
* A read past a mapping is **not** recoverable in-probe: the loader's handler does not resume the
  faulting instruction, it reports and lets the process die. So "probe by faulting" costs a relaunch
  each time — the scan has to be right the first time.
* The blob is a free, reliable crash detector for every future probe: text-then-binary means a fault,
  and the mcontext's `+0x08` names the address range involved.
