# Console findings, 25 Oct 2026 — AIO 669 verification, dmem0 destination, physhm refutation, AllocateDirectMemory via GOT wrapper

All results from live 14.10 console (Hamidashi Creative Lua loader, TCP 9026),
probes step163–step190. Each probe ran on a fresh interpreter; result words,
not return values, were read everywhere. Raw captures available on request.

## 1. AIO 669 batch engine — independently verified, plus one new capability

The `docs/AIO_BATCH_14_10.md` contract replays 1:1 on our console:
`669(cmd, reqs, count 1..128, class 1..3, ids)`, stride 0x28, `cmd=1` read /
`cmd=2` write, `664` poll → `state=0x3`, `662` delete → 0. Gates refuse
cmd 0/3, count 0/129, class 0/4. Hostile destinations (unmapped VA,
kernel-half VA) return `0x8002000E` in the result word and the queue
survives; controls complete after each hostile case.

**New, not in the repo:** a **dmem0-backed mapping works as an AIO
destination**. Reading 16 bytes of `/dev/urandom` into a `/dev/dmem0`
mmap returned `result=0x10` and the target page changed
(`0xC0012800` → urandom bytes), verified through two independent paths
(kernel copyin via writev-iovec AND the Lua memory API). The kernel copies
into device-backed user VAs without complaint.

Boundary behavior (step166): the known "count not clamped" defect, aimed at a
device-backed destination, is absorbed by the device pager — `count=0x4000`
into a 1-page dmem0 mapping completed fully, and the pager faulted in two
extra device pages on demand (they became readable, zeros). `count>=0x10000`
returns `0x8002000E`. The overrun lands in device memory, not adjacent
mappings; no corruption primitive from this direction.

## 2. AIO lifecycle window — measured, then stress-tested safe

Deleting an in-flight request does not cancel the copy: polling the deleted
id returned `state=1` (pending) in **100/100** rounds (step167). The request
object outlives delete until its copy completes — a real, deterministic
window. However: 2000-request exhaustion churn (capacity >200, step181) and
50 rounds of true 3-way thread concurrency (poll 664 + cancel 666 on one
thread, delete 662 on another, copy in flight; step187) produced **zero
crashes**. One unexplained crash was observed once in an earlier
cooperative-scheduling churn (slot table hot from ~100 prior rounds) and
never reproduced in ~10 attempts; we treat it as a fluke, not a lead.

## 3. physhm write claim — REFUTED (our own earlier claim)

Our earlier "physical memory write confirmed" via `physhm_open(1,2)` +
mmap + mprotect(RW) + `memory.write_dword`/`read_dword` readback was a
**Lua memory-API shadow artifact**. Cross-validation (step163/164):
kernel copyin (writev-iovec with `iov_base` = physhm VA, and plain
`write(pipe, va, n)`) both return EFAULT for the physhm mapping before AND
after the write, and on a second independent mapping of the same fd; a
CPU-side `memory.read_dword` on the VA faults lethally. Control in the same
probe (peek on a normal allocation) returns correct data. physhm
mmap/mprotect "success" does not imply backed pages. Any result in the tree
resting on `memory.*` readback from physhm should be treated as
unconfirmed.

## 4. dmem0 R/W is REAL (contrast with §3)

Same cross-validation method, opposite verdict (step179): kernel copyin
reads dmem0 pages fine; `memory.write_dword(0xCAFEBABE)` is visible through
the copyin path; AIO-written bytes agree on both paths. dmem0 is a genuine
R/W window over GPU direct memory (offsets 0..~0x110000000).

## 5. AllocateDirectMemory works from the game sandbox — via the GOT wrapper, not the raw syscall

Raw Sony syscalls 546–554 all return -1 from the sandbox, but eboot's GOT
imports callable libkernel wrappers. Using module info segment discovery +
the GOT, and identifying functions behaviorally (zero/one-arg return
signatures):

- `libkernel+0x17810` = sceKernelGetDirectMemorySize → `0x150000000`
- `libkernel+0x02E10` = __error (returns errno-pointer)
- `libkernel+0x17EF0` = sceKernelAllocateDirectMemory with the real PS5
  signature `(searchStart, searchEnd, len, alignment, memoryType, &physOut)`
  — rv=0, fresh boots hand out phys `0x110010000`+ for every memoryType
  tested (0,1,2,3,10).

The map wrapper (`libkernel+0x15020`, candidate sceKernelMapDirectMemory)
accepts `arg1=0` with clean EINVAL but crashes the process with a real
out-pointer + valid phys on every arg shape tried. Hypothesis: it is the
7-arg *named* variant and the loader's fcall only forwards six argument
registers (confirmed in the loader's own native.lua: `native.fcall(fn,
rdi..r9)`), leaving a garbage 7th (name) pointer. Not yet re-attempted via
the ropchain class (which has `push_sysv`/`align_stack`).

## 6. osem family works; delete-while-waiting is safe

With the corrected 14.10 ABI — `549 create(name, attributes, initial,
maximum)`, 553 wait, 554 poll, 555 post, 556 cancel, 550 delete — the full
lifecycle runs on our console (handle `0xA9D`+). The 553 timeout-budget
writeback copies 4 bytes out even on failure, as the 13.60 handler decode
predicts. A concurrent delete(550) while a second thread is blocked in
553 + 60-object create spray + mass post(555) wakes the waiter cleanly with
-1. No UAF symptoms (step184b).

## 7. Loader thread machinery — reproduction notes

`thread:new(fcall(syscall.syscall_address, N), args...):run(true)` runs
arbitrary syscall N on a concurrent thread; `thr:join()` +
`thr.chain:get_last_retval_addr()` recover the return value. If you ever
hand-roll the jmpbuf instead of using the class: libc `longjmp` on this
target restores FPU control word (+0x40) and MXCSR (+0x44); both must come
from a real `setjmp` capture (a zeroed MXCSR faults the new thread
instantly), RIP lives at jmpbuf+0 (use `gadgets["ret"]`), RSP at +0x10.

## 8. PUP self-decryption path is dead from the game sandbox

`/dev/pup_update0` and every plausible alias (`pup_update`, `pup0`,
`update`, `encdec[0]`, `sbl_srv`, `pup_decrypt`) refuse open in both modes
(step186). The same-firmware inner-layer decryption condition cannot be
exercised from this process.

---

### Net assessment

The AIO family is alive, validated, and stable under everything we threw at
it; its one confirmed defect (unclamped count) is absorbed by device pagers
and self-corrupts anon memory — useful for neither. The two findings with
continued offensive value are **§4 (dmem0 real R/W)** and **§5 (wrapper-path
direct-memory allocation)**. Our next console work targets the SCM_RIGHTS
fd-refcount leak (CVE-2019-5607 shape) with slab reclamation via IPC objects
— the "ghost handle" chain from `docs/NOVEL_ATTACK_CHAINS_2026-10-21.md`,
for which this session confirmed every prerequisite primitive (SCM_RIGHTS
fd passing, threads, osem/eventflag creation).
