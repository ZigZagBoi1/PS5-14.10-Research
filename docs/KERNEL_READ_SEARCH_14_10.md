# Looking for a reader: base recovered, aio validated, ten deref candidates to triage

Static and live, 2026-11-05 (probes 1001a, 1231b, 1232a, 1233a).

## 1. The base is a solved input

Upstream's `1001a_kernel_map_sweep.lua` runs 512 `thr_create` children, each with `RIP` set to a
2 MB candidate; the SIGSEGV chain writes 0x80 bytes of the fault context per attempt and the parent
parses `(ctx+0x130 >> 8) & 0xF` - 5 present, 4 absent.

This boot: 50 mapped, 462 absent, `spawned=512 failed=0 alive`, image at
**`0xFFFFFFFF85000000` .. `0xFFFFFFFF8B000000`** (98 MB). The slide is per boot and the sweep costs
no relaunch.

## 2. aio is not a reader (closed)

* `669(cmd=0x1002)` from a **user** marker buffer: state 3 and the exact 16 marker bytes arrive on the
  socketpair - so the write path does copy *from* the address we supply.
* the same call with `+0x10 = 0xFFFFFFFF85000000`: accepted, state 3, **zero bytes delivered**.
  The user-range mask (`and rdi,0x7fffffffffff`) turns it into `0x7FFFFFFF85000000` and the copy takes
  the bad-pointer path.

So both aio directions go through validated user copies. (Also recorded: FreeBSD `MSG_DONTWAIT` is
**0x80**; 0x40 is `MSG_WAITALL` and is what wedged the loader in 1231a.)

## 3. The classic kernel-memory files do not exist

`/proc/kcore`, `/proc/kallsyms`, `/proc/self/mem`, `/proc/self/maps`, `/dev/kmem`, `/dev/mem`,
`/dev/mem0`, `/dev/physmem` all return **ENOENT**. No procfs, no memory device.

## 4. Where a reader can still come from: a kernel dereference of an influenceable pointer

With the copy helpers validated, the only shape left is a handler that treats a **value** from the
argument array as a pointer and dereferences it - ideally without the mask, ideally before any
validation. A first pass over the 301 bodies (track `mov rX,[rsi+slot]`, then look for
`mov rY,[rX+disp]` before the next `call`) yields ten candidates:

| body | syscall | instruction |
|---|---|---|
| 0x34B510 | 592 | `mov r14,[rax+0x3e8]` |
| 0x34B790 | 659 dynlib_get_list2 | `mov r14,[rax+0x3e8]` |
| 0x3B01F0 | 663 aio_multi_wait | `mov rax,[rax]` |
| 0x3B0FB0 | 664 aio_multi_poll | `mov rax,[rax]` |
| 0x531080 | 30 | `mov rax,[rcx]` |
| 0x91C640 | 629 physhm_open | `mov rcx,[rax+0x10]` |
| 0xAB83C0 | 477 mmap | `mov r14,[rcx+0x40]` |
| 0xAB8AF0 | 65 | `mov rbx,[rcx+0x200]` |
| 0xAB8BB0 | 73 | `mov rbx,[rcx+0x200]` |
| 0xC42760 | 404 | `mov rax,[rdx]` |

Most are certainly false positives - the register was reloaded from a kernel source before the deref,
or the slot read was the uap array itself rather than an argument value. **None has been triaged.**
That triage is the next static job: for each candidate, decide what the register actually holds at the
dereference, using the instruction-by-instruction window, and keep only the ones where the value came
straight out of `[rsi+slot]` with no intervening copyin, mask or kernel load.

A true candidate would be a *reader*: point the argument at a known kernel address
(`0xFFFFFFFF85000000` this boot), have the handler dereference it, and recover the loaded value in
whatever it returns or copies back.


## 5. Triage of the ten deref candidates: all ten are kernel loads

Each window was read instruction by instruction. Every "user register" in the heuristic was actually
overwritten by a kernel load before the dereference:

| syscall | site | what the base register really is |
|---|---|---|
| 592 / 659 | `0x34b7d4 mov r14,[rax+0x3e8]` | `rax = [rdi+8]` = `td_proc`, then a `proc` field at +0x3e8 |
| 663 | `0x3b0247 mov rax,[rax]` | `lea rax,[rip+0x356c0de]` - a **global** (stack canary) |
| 664 | `0x3b0ffd mov rax,[rax]` | same pattern, global canary |
| 30 | `0x5310be mov rax,[rcx]` | `lea rcx,[rip+0x33eb255]` - global canary |
| 629 physhm_open | `0x91c917 mov rcx,[rax+0x10]` | `rax` is a **list node** walked from a kernel list, not an argument |
| 477 mmap | `0xab84bd mov r14,[rcx+0x40]` | `rcx = [rdi+0x460]` - a thread field |
| 65 / 73 | `0xab8bfb mov rbx,[rcx+0x200]` | `rcx = [rdi+8]` = `td_proc`, then a `proc` field at +0x200 |
| 404 | `0xc4279b mov rax,[rdx]` | `lea rdx,[rip+0x2cd9b75]` - global canary |

**Zero survivors.** The heuristic is defeated by its own simplicity: any kernel load into the tracked
register silently replaces the "user value", and the bodies that do unpack the argument array
(`mov rax,[rsi]` … `jmp body`) hand the *value* over in rsi, where a later dereference usually goes
through a procedure that reloads the register first.

There is also a structural reason the shape is rare: the copy helpers wrap user accesses in
`stac`/`clac`, so a raw dereference of a user-supplied pointer would fault under SMAP unless the
handler had already opened a window. A real bug of this class would have to sit *inside* such a
window, after a validated copy, and look like "re-read the pointer from the kernel struct and use
it" - which is the double-fetch shape, not the direct-deref shape.

## 6. Where that leaves the reader question

Ranked by what is still unexplored rather than by what is easy:

1. **Double-fetch inside the copy windows.** The census in `docs/COPYIN_SLEEP_CENSUS_14_10.md` found
   only the aio family with copyin-then-sleep, but its extents were unreliable. A correct
   function-extent pass plus a search for "copyin, then a *second* load from the same user pointer"
   is the honest version of that census and has not been done.
2. **OBJECT-sourced copyouts** (`docs/INTERPROC_COPYOUT_SOURCES.md`): sites that copy out of a kernel
   object field. If any object field can be made to hold a kernel address we influence, the copyout
   becomes a reader. None of them has been called with real arguments.
3. **A pointer stored by one syscall and dereferenced by another.** The aio request holds a buffer
   pointer; kqueue knote holds udata; sigevent holds a function. The question is which subsystem
   dereferences a stored pointer *without* the mask.


## 7. Double-copyin census: 43 bodies, 14 of them reuse the same source register

A double fetch needs the handler to copy from user memory **twice** through the same pointer. Scanning
all 301 bodies for two or more calls to copyin (`0x259280`) and recording the register that fed `rdi`
at each call gives 43 bodies; the ones where the *same* register is reused are the interesting set:

| syscall | body | copyin sites (same register) |
|---|---|---|
| 659 dynlib_get_list2 / 593 dynlib_get_info | 0x34B790 / 0x34B7B0 | rbx, rbx (0x34b820, 0x34bcd0) |
| 598 / 599 | 0x34C990 / 0x34CAA0 | r14, r14 (0x34cd7c, 0x34cdac) |
| 165 | 0x47B030 | r13, r13 (0x47b0fd, 0x47b13b) |
| 98 connect | 0x531260 | r12, r12 (0x5312cb, 0x5316db) |
| 29 recvfrom | 0x5328D0 | r15 three times (0x532925, 0x532a2b, 0x532d22) |
| 27 | 0x5329E0 | r15, r15 |
| 105 setsockopt | 0x532BC0 | r15, r15 |
| 118 getsockopt | 0x532CD0 | r15, r15 |
| 32 | 0x533030 | r15, r15 |
| 90 / 41 / 92 | 0x729A40 / 0x729D80 / 0x729DC0 | r14, r14 |
| 138 utimes | 0x8FA310 | r14, r14 |
| 345 sigtimedwait | 0x55E550 | r12, r12 |

Two shapes stand out:

* **the socket-address family** (29, 32, 41, 90, 92, 98, 105, 118) all funnel through the same bodies and
  copy a user length and a user address in separate calls. That is the canonical double-fetch
  layout - the length is validated once and the address is copied around it - and the corpus has never
  raced it.
* **598 / 599 and 605-608** copy a descriptor struct twice from one register; 598 was never called at
  all in this corpus.

Neither is a reader by itself. They are the *places to look* for one, and the difference from the
direct-deref class is that a double fetch does not need SMAP to be off: both accesses are legitimate
user copies, and the bug is that the second one sees different bytes.

## 8. The experiment this points to

With 632/633 now giving a deterministic suspend, the race can be made controllable rather than timed:

1. call the target with a user length that is valid (e.g. `sizeof(sockaddr_in)`);
2. from a second thread, rewrite the length field to a larger value;
3. observe whether the copy-out returns more bytes than the structure holds - kernel stack bytes in the
   reply buffer are the leak.

The corpus's copyout audits say every non-constant length is clamped, so the expected outcome is
"clamped, nothing leaks" - but those audits measured the *copy length against the buffer*, not the
*re-read of the user length between two calls*, which is the shape here.


## 9. The double-fetch lead is closed by inspection, and so is the whole copy-source class

Three bodies were read in full to test the shape "user length validated once, address copied around it":

**29 `recvfrom`, body 0x5328D0.** `r15 = [rsi+0x28]` is the fromlen pointer; `copyin(r15, [rbp-0x58], 4)` at
0x532925 reads the length **once**, and the syscall is then called with the kernel copy. The later
`copyout([rbp-0x58], r15, 4)` at 0x5329B2 writes it back. The reload at 0x532932 is
`mov r15,[r14+0x28]` - the **uap slot**, i.e. kernel memory, not the user buffer. There is no second
read of user memory.

**105 `setsockopt` / 118 `getsockopt`, body 0x533050.** `r15 = [rsi+0x10]` is the optlen pointer;
`copyin(r15, [rbp-0x3c], 4)` at 0x53307D, then `call 0x532e60` uses `[rbp-0x3c]` and `[rbp-0x38]`, and the
copyout at 0x5330D5 uses `r14 = [rbp-0x3c]` - again the **kernel copy** of the length, not a re-read.

**41/90/92, body 0x729A40.** Two copyins from the same register, at 0x729E6A (0x20 bytes) and 0x729F29
(0x18 bytes) - both **constant sizes** into stack buffers. No user length at all.

**165, body 0x47B030.** Two copyins of 0xc and 8 bytes from the same register - constant sizes into two
different stack slots.

So every repeated copy in the image is either constant-sized or reads the length from the kernel's own
stack copy. **The double-fetch class is empty**, and it was the last copy-shaped route.

That agrees with the earlier interprocedural audit in `docs/INTERPROC_COPYOUT_SOURCES.md`, whose verdict
is explicit: *"no such primitive exists in this image. 0 of 301 bodies performs a raw memory access
whose base derives from a syscall argument; 0 of 39 reachable copyout sites take their source from user
input; 0 of 57 reachable copyin sites take their destination from user input."*

## 10. What this means for the reader problem

Four independent searches now agree:

| class | result |
|---|---|
| aio copies from a kernel address (source and destination) | **closed** - the user-range mask rejects it, measured |
| a handler that dereferences an argument value directly | **closed** - 10/10 candidates are kernel loads |
| a double fetch of a user length or pointer | **closed** - constant sizes, or the kernel copy is used |
| a copyout whose source or copyin whose destination comes from user input | **closed** by the interprocedural audit, 0/301 |

A reader therefore cannot come from the *copy semantics* of this syscall table. It has to come from a
memory-safety bug - a freed object still referenced, an out-of-bounds index into a kernel array, or a
type confusion - and then the leak has to be harvested through an interface that returns the damaged
object's bytes. The remaining unexplored surfaces of that shape are the ones the corpus has not
exhausted: the object families whose lifetime the loader can influence (osem, evf, namedobj, kqueue
knotes), and the blockpool family's page work, which is closed only because no userland path creates
the type-0xb object.
