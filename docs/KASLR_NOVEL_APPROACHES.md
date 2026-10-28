# Novel KASLR Defeat Approaches — PS5 14.10

> Generated 2026-10-25. Everything below is a *hypothesis*; none has been run.
> Each entry cites the evidence gap it aims at and the probe that would test it.

## What has been exhaustively ruled out

All "classic" FreeBSD KASLR info leaks are dead on 14.10:

- **sysctl** — every CTL_* subtree scanned, zero kptrs (56g3)
- **kinfo_proc** — full 1096 bytes, sentinels only (43d)
- **AF_ROUTE** — sanitized, zeroed sockaddrs (53b)
- **NET_RT_DUMP** — false positives, sockaddr boundary artifacts (56e/56e2)
- **ioctl overcopy** — all 34 /dev nodes, 48K+ calls, zero overcopy (387a/387c/56m)
- **GPU page residue** — pages zeroed on allocation, 64 MiB scanned (348a)
- **kqueue / kevent output** — clean (56q, 271g-271i)
- **Signal frame (sendsig)** — zero-initialized, no kptrs (56r)
- **Thread ucontext (634)** — all userland (56n)
- **getsockopt** — TCP_INFO, SO_LINGER, TCP_CONGESTION — all clean (56n)
- **SCM_CREDS / SCM_RIGHTS** — small ints / stripped (56o, 56q)
- **fstat / getdirentries / getrusage / getrlimit / procctl** — clean (56o-56p)
- **SO_TIMESTAMP / SO_BINTIME** — valid timestamps only (56p)
- **sendfile error / poll** — untouched (56q)
- **sigaction structs** — userland handlers + bitmasks (56o)
- **CClosure Lua stack read** — rax=0..8, only userland (56d5-56d7)
- **mprotect timing** — scheduling noise (56h-56i2)
- **sys 624 side channel** — no intra-kernel discrimination (56f)
- **mincore** — rejects kernel VA (43l)
- **GS base** — zeroed (43c)
- **Module data segments** — constants only (42c2)
- **kern.msgbuf** — 8-byte stub (43j)
- **sys 674 VM map** — 317 regions, all userland VA (55e/55f)
- **sys 587 credentials** — 0x88 bytes, one cap bit (55e)

---

## Ranked novel approaches

### 1. ★★★ Double-free → reclaim → read-back kernel pointer (AIO UAF)

**Feasibility: HIGH** — the double-free is confirmed (65l), and the AIO
subsystem's freed object almost certainly contains back-pointers.

**What hasn't been tried:** After the double-free fires, the freed slab slot
sits on the zone's free list. If we spray a *different kernel object* into that
slot — one whose user-visible output includes fields that overlap the old
object's kernel-pointer fields — reading the new object back leaks a kernel
address.

The key insight: 663/666 currently return only a status dword (67a: changed=0,
kptrs=0) because those calls operate on the *AIO-family* view of the slot. But
if a *different object type* reclaims the freed memory and we read it through
its own interface, its output format may include pointer-bearing fields.

**Concrete plan:**
1. Fire the double-free (65l recipe: 16 individual submits → poll → 2 children
   × 662).
2. Immediately spray objects whose kernel allocation size matches the AIO
   request sub-object. Candidates:
   - **kqueue knote structs** — `kqueue(362)` + `kevent(363)` with EVFILT_USER.
     Each EV_ADD allocates one `knote` (~128 bytes on FreeBSD 11).
   - **Pipe buffer headers** — `pipe(42)` returns -1 via make_syscall, but
     socketpair works; internal pipe buffers vary.
   - **shm_open metadata** — `shm_open(482)` creates a `shmfd` struct.
   - **Named evf/osem objects** — `538`/`549` create kernel objects with
     predictable placement (435a-445a).
3. Read the sprayed object through its family's interface:
   - For evf: `543` (trywait) returns the event pattern (8 bytes) — too small.
   - For pipe/socket: read data through the pipe — but that reads the *data
     buffer*, not the header.
   - For shm: `fstat(189)` on the shm fd — returns stat struct, not the shmfd
     kernel object.

**The gap:** None of the available readback interfaces dump raw kernel object
bytes. The spray must therefore aim for *type confusion within the AIO family
itself*: submit new AIO requests after the double-free so they reclaim the freed
slot, then read the new request's completion record, which may now contain the
old object's stale kernel pointer at a field offset that maps to the completion
status.

**Probe:** `68a_aio_reclaim_kptr.lua` — fire double-free → submit 32 new AIO
reads → poll/wait → dump every byte of the completion state for kernel-shaped
values.

**Why it might work:** The AIO request struct in the 13.60 capture contains
`proc` and `td` back-pointers (standard FreeBSD `aiocb` kernel copy has
`aio_proc` at a known offset). If the freed sub-object and the newly submitted
request share the same slab zone, the new request's metadata may overlap the
old object's pointer fields, and 664's status output (or 663's wait output)
might expose bytes from those fields. Even if the *output* is sanitized, the
*result word* (which is the byte count on success) comes from the object — if
the reclaiming object's byte-count field overlaps a pointer field, the result
word IS the leak.

---

### 2. ★★★ sys 591 `dynlib_dlsym` — ungated kernel-side symbol resolution

**Feasibility: HIGH** — the 13.60 decode shows NO authid gate, NO bit-62 gate.
14.10's `-1` on six zeros is just the handle-0 failure (error 3).

**What hasn't been tried:** Calling 591 with a *real* module handle (from the
593/659 handle space) and a known symbol name or NID string. If this works, it
resolves a symbol to its *loaded address* — and for kernel-internal symbols,
that address defeats KASLR instantly.

**Subtlety:** The 13.60 handler has a caller-module check (`b3cbd50`) that
compares the return address against allowed modules. If the Lua loader's module
is in the allowed set, any symbol in any loaded module is resolvable. If not,
error 3. The discriminator is errno: error 1 = dynlib object NULL, error 3 =
handle invalid or caller blocked.

**BUT:** The resolved address from 591 is a *userland* address (the module's
loaded VA), not a kernel VA. 591 resolves userland dynamic library symbols, not
kernel symbols. It would give the loaded base of any sprx the game has — which
is already available from 593. So 591 is NOT a KASLR defeat for the *kernel*.

**Still worth testing** because: (a) it may resolve symbols from modules not
visible in the 593 scan (hidden/debug modules), and (b) the output address
might point to a kernel trampoline if the module has kernel-resident stubs.

**Probe:** `68b_dlsym_real.lua` — try 591 with every handle from the 593 scan
(0, 2, 17, 19, 20, ...) and a known NID like `sceKernelGetCompiledSdkVersion`.

---

### 3. ★★★ AIO result word as implicit kernel pointer (type-punned read)

**Feasibility: MEDIUM-HIGH** — requires understanding the freed object's layout.

**What hasn't been tried:** The 13.60 AIO family decode (`AIO_FAMILY_13_60_DECODE.md`)
shows `669` returns `result[0]` = bytes transferred. But what if, after a
double-free and reclaim by a *non-AIO* object, 664's poll reads the `result`
field from memory that now contains something else's data?

The 664 poll output is: one 32-bit status dword per ID. The status is read from
the kernel's request object at a fixed offset. After reclaim by a different
object, that offset may now contain:
- A pointer fragment (low 32 bits of a kernel address)
- A size or count field from the reclaiming object
- Raw heap metadata

**The status dword pathway:**
- Normal: `0x3` (completed), `0x10003` (already-polled)
- After double-free + reclaim: whatever 32-bit value sits at that offset in the
  reclaiming object

**Probe:** `68c_aio_status_typepun.lua` — double-free → spray with differently-
sized socket option buffers → poll the freed IDs → check if the status dwords
are pointer fragments or controlled values. If controlled, we have a kernel
info leak. If they're pointer fragments, we have KASLR defeat.

---

### 4. ★★ sys 624 VM-op counter as heap-spray validation oracle

**Feasibility: MEDIUM** — 624 is a confirmed monotonic counter (+5 per mmap).

**What hasn't been tried:** Using 624 to *validate* that a heap spray landed.
After the double-free, each spray object that causes a kernel VM operation
increments 624 by a predictable delta. By comparing the counter before and
after a spray of N objects, we can confirm exactly how many kernel allocations
occurred, which tells us whether our spray objects landed in the freed zone.

This isn't KASLR defeat directly, but it's a *critical primitive* for making
the double-free exploitable: spray → check 624 delta → if delta matches
expectation, the reclaim succeeded → proceed with the read-back.

**Probe:** `68d_624_spray_oracle.lua` — baseline 624 → double-free → spray
(shm_open, kevent, namedobj) → read 624 → compare deltas.

---

### 5. ★★ Zen 2 microarchitectural side channels (TSC + cache timing)

**Feasibility: MEDIUM** — PS5 has AMD Zen 2, which has known
microarchitectural leaks, but we lack `rdtsc` and a clean timing source.

**What hasn't been tried:**

**5a. Prime+Probe via AIO timing:**
Submit an AIO read to `/dev/zero` with a known size. The completion time
(measured by polling 664 in a tight loop with `os.clock()`) depends on cache
state. If we prime the L1/L2 cache with kernel-address-shaped accesses (via
sysctl, mmap, etc.) and then measure AIO completion time, timing differences
might correlate with kernel page table residency.

Problem: `os.clock()` has ~90μs granularity — too coarse for cache timing.

**5b. RDTSC via eboot gadget:**
We need a `rdtsc; ret` or `rdtsc; mov [rdi], eax; ret` gadget. The 56s scan
found zero `0F 31 C3` (`rdtsc; ret`) sequences in 4.6MB of eboot. But:
- `rdtsc` is `0F 31` — check for `rdtsc` followed by *any* store-and-return
  sequence, not just `rdtsc; ret`
- `rdtscp` is `0F 01 F9` — also check for this variant
- A multi-gadget chain could work: `rdtsc` (somewhere) → `mov [rdi], eax` →
  `ret`

**5c. Clock_gettime as poor-man's timer:**
Even at 90μs resolution, if we repeat measurements enough times
(Law of Large Numbers), we can detect sub-microsecond signals. Run 100K
iterations of mprotect on a kernel VA vs a known-mapped VA, accumulate
clock_gettime deltas, and look for a statistically significant difference.

Problem: 56h-56i2 already tried this with 2000 calls × 5 rounds and saw only
scheduling noise. But those probes used the *Lua* main thread. A *child thread*
ROP chain that does tight rdtsc-bracketed mprotect loops at native speed might
extract a cleaner signal.

**Probe:** `68e_rdtsc_scan.lua` — exhaustive eboot scan for `0F 31` (rdtsc),
`0F 01 F9` (rdtscp), and multi-gadget timing chains.

---

### 6. ★★ Errno value as partial kernel address leak

**Feasibility: MEDIUM** — the 13.60 decode reveals positive SCE error codes.

**What hasn't been tried:** Many Sony handlers return different error codes
depending on internal state. If a handler reads a kernel pointer as part of
its validation and uses a comparison result to select between error codes,
the *specific error code returned* may encode partial kernel address information.

Concrete target: sys 622's 0x400 group *kills the process after a successful
copyin*. The kill implies the handler dereferences a pointer from the copied
data. If instead of killing, the handler returns different error codes depending
on what it reads from the copied data, we can binary-search for valid kernel
pointer prefixes by varying the copied bytes and observing errno.

**Better target: sys 637.** It writes a caller-chosen qword to `child+0x280`.
The offset `+0x280` is fixed, but the *base* (`child`) is a kernel address.
If we can find a handler that *reads back* from `child+0x280` and returns its
value or compares it, we have a kernel write-what-read-where.

**Probe:** `68f_errno_oracle.lua` — call every accessible Sony syscall with
SIGSYS ignored, capture errno via `__error()` (the TLS errno pointer at
`%fs:0`), and look for errno values that change with arguments in ways that
suggest internal pointer-dependent branching.

---

### 7. ★★ Thread exit status as kernel pointer carrier

**Feasibility: MEDIUM** — `thr_new(455)` delivers arg in rdi, and
`thr_exit(431)` takes a status in the first argument.

**What hasn't been tried:** When a child thread calls `thr_exit(status)`, FreeBSD
copies the status to the parent's `child_tid` location (the `+0x30` field of
`struct thr_param`). If the child executes a ROP chain that:
1. Calls a syscall that returns a kernel pointer (if any exist)
2. Moves the return value to rdi
3. Calls `thr_exit` with that value

...the kernel pointer arrives in userland at `child_tid`.

The question: which syscall returns a kernel pointer? Candidates:
- `sysarch(GET_GSBASE=130)` — returned 0 from the main thread, but a child
  thread is a different kernel thread with a different `td`. Worth re-testing
  from child context via ROP.
- Any syscall whose return value is an internal kernel address on error paths.

**Probe:** `68g_child_gsbase.lua` — child thread ROP: `sysarch(130, &buf)` →
read buf → `thr_exit(buf_value)`. Check if the child's GS base differs from
the main thread's (which was 0).

---

### 8. ★★ AIO request struct offset mapping via controlled writes

**Feasibility: MEDIUM** — requires understanding the freed object's field
layout.

**What hasn't been tried:** Instead of trying to *read* a kernel pointer from a
freed object, use the double-free to create *two live references* to the same
memory. Then:
1. Submit a new AIO write request that lands in the freed slot
2. The write destination is our own userland buffer
3. The AIO engine copies data from the fd into our buffer, but the request's
   metadata (including the destination pointer) was corrupted by the other
   reference
4. If we can control the metadata through the second reference (by submitting
   another request or modifying the slot), we redirect where the AIO engine
   writes

This is the classic UAF→arbitrary-write path. The challenge is that 662's
double-delete frees the *sub-objects* of the request, not the request slot
itself. We need to know which sub-object is freed and what it controls.

**13.60 clue:** The AIO handler decode says `aio_multi_delete` frees per-request
metadata — the `aiocb` kernel copy. In FreeBSD, the kernel `aiocb` contains:
- `aio_fildes` — the fd
- `aio_offset` — file offset
- `aio_buf` — *the destination pointer* (userland address, but kernel trusts it)
- `aio_nbytes` — byte count
- `aio_proc` — process pointer (KERNEL ADDRESS)
- `aio_lio_opcode` — operation type

If the freed sub-object is the kernel `aiocb`, and we reclaim it with attacker-
controlled data, and then trigger an AIO completion that reads from the
reclaimed (now attacker-controlled) struct, we can:
- Set `aio_buf` to a kernel address → the completion writes there
- Read `aio_proc` → KASLR defeat

**Probe:** `68h_aio_uaf_rw.lua` — after double-free, spray with attacker-
controlled data (named objects with chosen values via 557), then trigger the
AIO completion path and monitor what happens.

---

### 9. ★ sys 599 `dynlib_process_needed_and_relocate` — ungated, deep copyout

**Feasibility: LOW-MEDIUM** — ungated in 13.60, but the copyout is at call
depth 4-5 and the argument shape is unknown.

**What hasn't been tried:** 599 is ungated and has two copyout sites reachable
at depth 4-5 through the dynamic loader path. If the right arguments trigger
the relocation path, the output may include kernel VA (relocation targets,
GOT entries). The risk is that triggering relocation might crash the process
or corrupt loader state.

**Probe:** `68i_dynlib_relocate.lua` — 599 with valid module handles and
various flag combinations, with errno capture.

---

### 10. ★ Exploit the fd leak from SCM_RIGHTS (Finding 83)

**Feasibility: LOW-MEDIUM** — fd leak is confirmed (151d/151e), but converting
it to KASLR is indirect.

**What hasn't been tried:** The fd leak installs descriptors into the receiver's
fd table without the receiver's knowledge. These leaked fds are fully
functional. If we can leak an fd that refers to a *kernel object* whose
user-visible interface exposes kernel pointers, we have KASLR defeat.

The challenge: all fds we can create refer to sockets, pipes, kqueues, shm, or
files — none of which leak kernel pointers through their interfaces. But the fd
leak might be chained with the AIO double-free: leaked fds that are never
properly closed accumulate in the fd table, consuming kernel memory in a
predictable pattern. This can be used as an alternative heap spray mechanism
for the AIO UAF.

---

### 11. ★ AIO completion timing side channel

**Feasibility: LOW** — requires sub-microsecond timing.

**What hasn't been tried:** Submit an AIO read of N bytes from `/dev/zero`.
The kernel copies N zero bytes to our buffer. The time to complete depends on
the *physical pages* backing our buffer. If we mmap a page, touch it (so it's
in L1 cache), then submit an AIO read targeting that page, the completion is
fast. If we submit targeting a page that will cause a TLB miss, it's slower.

By submitting AIO reads with destination pointers at different offsets and
measuring 664 poll timing, we might detect the kernel's page table structure
and infer KASLR from the page table layout.

Problem: `os.clock()` granularity and the kernel's scheduling add noise far
above the signal.

---

## Summary priority

| Rank | Approach | Feasibility | Key question |
|---:|---|---|---|
| 1 | AIO double-free → reclaim → type-punned readback | HIGH | Which slab zone does the freed sub-object live in? |
| 2 | AIO result/status word as implicit kptr | MED-HIGH | Does 664's poll output come from the freed offset? |
| 3 | sys 591 dlsym with real handles | HIGH | Does it resolve symbols beyond the 593 scan? |
| 4 | sys 624 as spray validation oracle | MEDIUM | Does the delta distinguish spray from no-spray? |
| 5 | Zen 2 rdtsc gadget scan + native timing | MEDIUM | Does any rdtsc-usable sequence exist in eboot? |
| 6 | errno oracle across Sony syscalls | MEDIUM | Do error codes encode pointer-dependent branching? |
| 7 | Child thread GS base / sysarch from ROP | MEDIUM | Does the child's GS base differ from the main thread's? |
| 8 | AIO UAF → controlled write via aiocb fields | MEDIUM | Is the freed sub-object the kernel aiocb? |
| 9 | sys 599 dynlib relocation with real args | LOW-MED | Do the copyout sites emit kernel VA? |
| 10 | SCM_RIGHTS fd leak as spray mechanism | LOW-MED | Can leaked fds shape the kernel heap predictably? |
| 11 | AIO completion timing side channel | LOW | Can os.clock distinguish cache-hot from cold? |

## Recommendation

**Approaches 1, 2, and 8 are the same exploit path** — the AIO double-free is
the only confirmed kernel memory corruption primitive, and the KASLR defeat
should come from the same bug. The immediate next step is:

1. **Determine the freed object's size and zone** (from the 13.60 decompile of
   662's free path — which allocator function, which zone argument).
2. **Map the freed object's field layout** (find `aio_proc`, `aio_td`, or any
   kernel pointer field and its offset).
3. **Write a reclaim probe** that sprays matching-zone objects and reads back
   through the AIO interface to check if stale pointer bytes survived.

If the AIO interface sanitizes its output (zeroes fields before copyout), the
fallback is cross-zone spraying: reclaim with a *different* object type and
read through *that* type's interface. The object table research (435a-445a)
showed that the free list is shared across families and placement is predictable
— this is the tool for controlling which object type reclaims the freed slot.
