# Threading is alive on 14.10

Status: **console-verified, firmware 14.10, 2026-10-20.** The evidence files are
in `results/phase17_new_vectors/`; the probes are `156a`–`156d` in
`probes/phase17_new_vectors/`. The loader process answered throughout with the
same pid (91) and the console never restarted.

## Result

`thr_create(430)` starts a second userland thread on 14.10 when the context
carries the three fields the handler validates **and** `CS = 0x43`,
`SS = 0x3B`. The child executes our `RIP`, with our registers and our stack, in
ring 3, and the process survives.

| probe | context | outcome |
|---|---|---|
| 80a | `CS`/`RIP`/`RSP`/`SS` written at `+0x90..0xB0`, magic at `+0x118` | `rv = -1`, no thread, process alive |
| 156a | same offsets, child aimed at `jmp $` | `rv = -1`, TID written, `thr_kill(tid, 0) = -1` |
| 156b | `thr_get_ucontext(634)`, two argument shapes | `rv = -1`, buffer untouched |
| 156c | gates passed, `CS = 0x43`, `RIP = jmp $`, `RSP =` our stack | `rv = 0`, TID 0x18EE3, `thr_kill(tid, 0) = 0` |
| 156d | gates passed, `RIP = mov [rdi], rax; ret`, `RAX = 0xDEADBEEFCAFE` | marker written into our page, `thr_kill(tid, 0) = 0` |

156d is the decisive one: the child ran two real instructions
(`48 89 07 C3` at `0x64832C67`, in eboot's RX `.text`), stored
`0x00000000DEADBEEFCAFE` through `RDI`, hit `jmp $` at `0x647B5481` and stayed
alive. A live TID alone would only prove that a thread object exists.

## What the earlier captures actually contain

The 2026-10-19 thread series is the reason this document exists, and it does not
say what its index rows say. Read line by line:

- `80c_thread_register_exec` returned `rv = -1` and printed `marker unchanged —
  thread did not write`.
- `80h_thread_write_test` returned `rv = 0`, so its context *was* accepted, but
  the capture ends in binary bytes and never reads the marker back.
- `80i_thread_write_final` stops at `calling thr_create` in all four captures;
  none records a return value or a marker readback.

So the earlier series proved context acceptance (`rv = 0`) and nothing about
execution. The index rows for 80a/80c/80h/80i have been corrected here rather
than left as they were. The difference between their accepted contexts and the
rejected ones is the gate fields, not the segment selectors.

## The context the kernel accepts

The 13.60 decode (`docs/THR_CREATE_430_CONTEXT.md`, `docs/THR_CREATE_PANIC_PATH_13.60.md`)
supplies the offsets; 14.10 now confirms them by acceptance and by execution.

| field | offset | value used | source |
|---|---|---|---|
| magic | `+0x108` (qword) | `0x480` | validator, must match exactly |
| flags | `+0x0d0` (dword) | `0` | validator, must be `<= 7` |
| type | `+0x110` (qword) | `0x10000` | validator, `0x10000` or `0x10002` |
| subtype | `+0x118` (qword) | — | checked only for type `0x10002` |
| GPRs | `+0x048`..`+0x0B8` | `rdi, rsi, rdx, rcx, r8, r9, rax, rbx, rbp, r10, r11, r12, r13, r14, r15` | register copy |
| CS | `+0x0c0` | `0x43` | `tf_cs` |
| RIP | `+0x0e0` | our gadget | `tf_rip` |
| RSP | `+0x0f8` | our stack | `tf_rsp` |
| SS | `+0x100` | `0x3b` | `tf_ss` |

The 430 body copies `0x500` bytes, and the id out-pointer is written **before**
the context is validated. That is why `rv = -1` arrives together with a fresh
TID: the TID proves the call reached thread allocation, not that a thread
exists. `thr_kill(id, 0)` is the discriminator — `0` means the TID is real,
`-1` means it was never created.

80a's earlier "CS=0x43 prevents the panic" line was **not** a threading result.
That context had none of the three gates set (`+0x108` was zero), so the handler
rejected it before it read CS, and the process survived because no thread was
ever started.

## What this changes

The "no threading" wall is gone for `thr_create(430)`. A second execution
context with attacker-chosen `RIP`, GPRs, `RSP` and stack contents is available
from the loader, which is the precondition for the UMTX-class races
(`docs/UMTX_454_EVIDENCE.md`) that every public PS5 chain inherits from WebKit
instead of creating.

## What this does not establish

- **Not a kernel primitive by itself.** The child runs in ring 3 with the same
  process privileges as the loader. No kernel memory was read or written.
- **CS attribution is still inferential.** 58e section D (`CS = 0`, `RIP = 0`)
  panicked; 156c/156d (`CS = 0x43`, real `RIP`) did not. Both the selector and the
  entry point differ between the two, so CS is the best explanation, not a
  measured single-variable result. The clean control — `CS = 0` with a valid
  `RIP` — would reboot the console and has not been run.
- **Thread lifetime.** The child keeps running after the probe returns;
  `thr_suspend(442)` returned `-1` for it, so there is no userland way yet to
  stop it. Two probes left two spinning threads in the loader process.
- **No TLS.** The child starts with whatever FS base the thread inherits; no
  probe has exercised a libc call inside the new thread.
- **No scheduling or signal work.** Priority, affinity, signal delivery and
  `thr_exit` from the child are untested.

## Reproduce

```bash
python tools/send_probe.py probes/phase17_new_vectors/156c_thr_create_correct_offsets.lua \
    --ip <console> --port 9026 --save --metadata --timeout 150
python tools/send_probe.py probes/phase17_new_vectors/156d_thr_create_child_executes.lua \
    --ip <console> --port 9026 --save --metadata --timeout 150
```

156c prints `THREAD EXISTS` when `thr_kill(tid, 0)` answers `0`; 156d prints
`CHILD EXECUTED` when the marker page receives `0xDEADBEEFCAFE`. Both take about
a second of console time after the eboot scan, which is the slow part (a 1 MB
byte scan over the loader bridge; pass `--timeout 150` so the client does not
give up while the scan runs).
