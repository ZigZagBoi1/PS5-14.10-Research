# aio cmd=2 as a kernel-read candidate: the write path runs, and a flag bug wedged the loader

Idea, 2026-11-05. The project has kernel position (the fault oracle) but no reader. `669 aio_submit_cmd`
takes a request array whose `+0x10` slot is a buffer pointer, and **cmd = 2 is a write**: the kernel
reads *from* that pointer. If the handler does not check that the pointer is a user address, then
putting a **kernel address** in `+0x10` turns the write into an arbitrary kernel read - the bytes land
in a socket we own and we read them back. That is a read primitive at any address, which is exactly
what is missing.

## What was measured (probe 1231a)

| step | result |
|---|---|
| `socketpair(1,1,0)` | fds 24, 25 |
| `669(cmd=1, reqs, 1, class=1, ids)` | 0, id 0x4205 |
| `664(ids,1,state)` | state **2** (dispatched, waiting for data) |
| `669(cmd=0x1002, reqs, 1, class=1, ids)` | 0, id 0x206 |
| `664` again | state **3** (completed) |

So **the write path executes**: a cmd=2 request against a socketpair descriptor completes. The
`result` dword at the caller's `+0x18` pointer stayed 0xAAAAAAAA, so either that slot is not the byte
count for this path or it is only written under conditions we have not met yet.

## The bug that ended the run

The follow-up `recvfrom(fd1, buf, 32, 0x40, 0, 0)` **blocked**. On FreeBSD `0x40` is `MSG_WAITALL`;
`MSG_DONTWAIT` is **0x80** (`MSG_NOSIGNAL` is 0x20000). The payload sat in the blocking receive, the
client timed out with zero bytes, and `port_witness` reports **LOADER-STUCK** afterwards. The Linux
value 0x40 was used by mistake; this corpus's own aio notes already say every parent-side call in the
family must be non-blocking.

## Why the idea is still worth a run

* cmd=2 completes on a real descriptor, so the source pointer is consumed by a working path.
* The aio family already stores caller-supplied pointers in kernel request objects; the question is
  only whether the copy that reads them is `copyin` (which validates) or a raw dereference.
* A user-address positive control costs nothing: submit cmd=2 from a marker buffer we allocated and
  receive the marker on the peer. If the marker arrives, the source semantics are proven, and the next
  run can point the same field at a kernel address.

## Next three runs, in order

1. **1231b** (written): cmd=2 from a user marker buffer, `recvfrom` with flags **0x80**, four `664`
   polls. Success = the marker bytes appear on the peer.
2. **Kernel-source attempt**: same request with `+0x10 = kernel_base + 0x0` (text) and a 16-byte
   length. A user-range check shows up as EFAULT and costs nothing; a raw read shows up as code bytes
   on the peer; a fault costs a relaunch. This is the one run where the fault oracle's base is the
   input.
3. If the source path validates but the *destination* path of cmd=1 does not, the same trick on cmd=1
   is a kernel **write** (kernel bytes into a chosen kernel address) - strictly more dangerous, and
   worth knowing about either way.
