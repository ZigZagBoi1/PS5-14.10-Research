# Native syscall chains from the Lua loader (probes 404a-433a, 2026-10-22)

A thread context is enough to run arbitrary native code when the only executable memory in
the process is code that already exists. `thr_create(430)` lets the game process start a
thread at any address it likes, and eboot's text is mapped RX and readable, so a gadget
chain placed on a stack we mapped turns the child into a native program.

This page records the layout that works, the constraints that were measured the hard way,
the seven object-lifetime races the chain was built to run, and what those races returned.
It also records the three things the chain was pointed at that came back negative, because
negatives measured with a real primitive are worth more than the assumptions they replace.


## What was built

A child thread created by `thr_create(430)` can be pointed at a gadget chain in eboot's
readable RX text, which turns it into a native program: it issues syscalls at native speed
with full register control, and ends by exiting.

The layout that walks:

```
RIP = pop rax; ret            eboot base + 0x992
stack: [num][syscall;ret][pop rax][num][syscall;ret] ... [park]
```

`pop rax; ret` consumes the next word as the number and the word after it as the return
address; the syscall gadget's own `ret` must land on `pop rax` again. For a call that needs
a different argument each time, `pop rdi; ret` (eboot base + 0x75DFE) goes between links:

```
stack: [rdi value][pop rax][num][syscall;ret][pop rdi][next rdi value][pop rax][num] ...
```

Terminate with `pop rax; 431; syscall` (`thr_exit`). A child that exits frees its core;
a child that parks on `jmp $` (base + 0x1481) does not, and cannot be killed.

## Constraints measured

- **Stack size**: a chain stack must be large. 1200 links on a 0x8000 mapping faulted; the
  same 1200 links on a 0x200000 mapping ran clean (413c/413d). Use 2 MiB.
- **Parked children are permanent**: `thr_kill` on a spinning thread blocks the caller
  forever (398a). One is harmless, five starve the loader completely (405a). Exiting
  children do not accumulate (418a: six children, loader healthy afterwards).
- **RFLAGS**: a child whose `+0x0F0` is zero has `IF` clear and never yields; the core it
  lands on stops scheduling (397a). Always set `0x202`.
- **Gadget verification**: 5 of the 6 `pop rax; ret` byte hits in eboot are real; the sixth
  (base + 0x2B75F) is not. Byte hits must be checked by execution, not by pattern.
- Both children of a race must be native. A Lua-side loop costs ~180 us per syscall and
  cannot overlap a native child that finishes its work in microseconds (414a: 1200 native
  submits finished before the Lua thread's first read of the id slot).

## Races run

| probe | race | result |
|---|---|---|
| 410a | 200 native `551` opens vs 200 Lua create/delete on a registered name | clean |
| 415a | 1200 submits vs 1200 cancels (AIO) | clean |
| 416a | 1200 submits vs 1200 deletes (AIO) | clean |
| 419a | 1200 `fstat` vs one `close` | clean, fd number reused by the next open |
| 420a | 1200 submits vs 1200 polls vs 1200 deletes (AIO) | clean |
| 421a | 1200 `kevent` vs one `close` | clean |
| 422b | 1200 `fstat` vs 500 close/open cycles on the same number | clean |

Every one left the process intact and the object usable afterwards (`thr_self` 0, and for
AIO a fresh `submit` returning `state 0x3`). No fault, no panic, no console event.

## What it means

The three object lifetimes that historically break — the AIO request queue, the file
descriptor table, and the kqueue — are reference-safe on 14.10 against the races that are
reachable from a game process. That is a negative result, and a fairly strong one: the
racing side is now native, the loops are long enough to overlap, and the objects are
provably freed and reused underneath the concurrent call.

The method is the more durable result. Any syscall whose contract is known can now be
called from a second thread at full speed with exact register arguments, which is what
every probe before this round had to approximate from Lua.

## Not attempted

- Races on objects we cannot create (ELF, prison, mount).
- `dup2`-based slot swapping (needs a second descriptor and a different chain shape).
- Any reclaim strategy: even a fault would need one, and none was produced.

## Added after the race set (423a-428a)

**423a - every mprotect protection value.** 65536 calls on an ordinary mapping and the same
on a GPU mapping: **32768 accepted, exactly the values with bit 2 clear** (`0x0-0x3`,
`0x8-0xB`, `0x10-0x13`, `0x18-0x1B` ...). Bit `0x4` is the execute bit and it is the one
refused. So mprotect is not blocked; it refuses execute specifically, after the fact.

**424a/424b/424c - mmap asked for execute.** `prot=0x5` (R|X): the mapping cannot be written
(pages stay zero, the loader's write path swallows the failed store) and the child faults
executing zeros. `prot=0x7` (RWX) and `prot=0x33` (the GPU protection) both map and are
writable, and the child faults on first instruction in both. **No protection value this
process can ask mmap for is executable.** A faulting child also drives the loader's signal
handler into a dump loop (257 dumps in one run), which is worth knowing before designing
any test that expects a fault.

**425a - fstat x dup2.** 1200 fstats racing 1200 `dup2(zero, target)`, i.e. the file object
behind the number released and rebuilt on every link. Clean.

**426a/427a - dlsym.** Syscall `0x24f` is resolved as `dlsym` by the loader, but neither
`(handle, name)` for handles -2/0/1/-1 nor `(handle 0..15, name, &out)` resolved anything,
and a NID-shaped string did not either. The JIT helper names (`sceKernelJitCreateSharedMemory`,
`sceKernelJitCreateAliasOfSharedMemory`, `sceKernelJitMapSharedMemory`) are not reachable
this way from a game process.

**428a - every command of sys 532.** Commands `0x00`-`0x4F` x 4 sub-commands with a valid
0x800 page: **36 of 1024 calls answer**, every one of them `cmd 0x18`-`0x20` returning
`0x800D0202` (missing argument, because slot 3 is zero here), and `cmd 0x2F` returning 0
with a zeroed output. No command returns data. The handler is reachable and inert for a
game process: with the handle slot filled it reaches the decode (432a), and the decode
still finds no entry (433a).

## Where that leaves it

The execute wall is now mechanical rather than empirical: execute is a protection bit, both
paths refuse it, and no mapping this process can create runs code. The object lifetimes
reachable from a game process hold under native-speed races. The Sony handlers that accept
calls return status codes, not data.

## The shape fuzzer (tools/syscall_shape_fuzz.py)

Built after the race set. It takes the population of handlers that actually reach their
body - every one of them established by a probe that returned something other than -1 -
and drives two fields per case: the user pointer (mapped page, page end, page edge, NULL,
unmapped, kernel-shaped) and the length or count field (0, 1, 8, 0x10, 0x3F, 0x40, 0x100,
0x800, 0x1000, 0x2000, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF).

One connection per case. A fault sends the loader's signal handler into a dump loop, so a
shared connection would lose every case after the first crash; the runner stops at the
first CONNECT_FAILED and names the case that took the process down.

Population and the probe that established the shape:

| sys | shape | established by |
|---|---|---|
| 532 | `(cmd, sub, page, 0, size, 0)` for cmd 0x18 and 0x2F | 307a, 428a |
| 601 | `(0x00 or 0x10, page, size, 0, 0, 0)` | 322a |
| 602 606 617 620 624 638 639 640 | `(page, size, 0, 0, 0, 0)` | isolation sweep |
| 657 | `(page, count, page2, 0, 0, 0)` | 350a |
| 669 | `(1, page, count, 1, page2, 0)` | 352a |
| 674 | `(page, size, 0, 0, 0, 0)` | 55e |
| 547 | `(page, page2, size, 0, 0, 0)` | 247a |
| 549 | `(name, 0, 0, size, 0, 0)` | 349b |
| 551 | `(name, 0, 0, 0, 0, 0)` | 349c |
| 557 538 540 | `(name, 0, 0, 0, 0, 0)` | 334a, 336a |
| 189 | `(fd or page, page2, 0, 0, 0, 0)` | 353c |

A case that returns something other than -1, or that does not complete, is the output.

## Exec: the wall is now named, not assumed

`423a` (`probes/phase17_new_vectors/423a_mprotect_prot_sweep.lua`) walked all 65536
protection values on an ordinary mapping and on a GPU-shaped one:

- **32768 accepted on both** — exactly the values with **bit 2 clear** (`0x0-0x3`,
  `0x8-0xB`, `0x10-0x13`, `0x18-0x1B`, …).
- Bit `0x4` is the execute bit. `mprotect` is not blocked; it refuses execute and nothing
  else.

`424a`/`424b`/`424c` asked `mmap` directly, and each candidate was checked by **execution**
rather than by a return value: the page is filled with `mov [rdi],rax; ret`, a child starts
at the page with `RAX` = marker and `RDI` = marker page, and the marker is read afterwards.

- `prot=0x5` (R|X) maps but cannot be written, so the fill stays zero and the child executes
  zeros — that run produced the loader's fault-dump loop (257 dumps, 72 KB) and proves
  nothing.
- `prot=0x7` (RWX) maps and is writable; the child faults on its first instruction.
- `prot=0x33` (the GPU shape) maps, is writable, and also faults.

So no protection this process can request produces an executable page, and the reason is
the execute bit itself.

## Sys 532: the handle decode, reached and capped

`430a`: cmd `0x18` writes exactly one dword (the status) and nothing else — no copyout
leak, no overrun into the buffer.

`432a`/`433a` reached the handle check with the slots 308a used —
`532(cmd, 0, out, inp, size, 0)`, output third, packed handle fourth — and with the
checksum the dossier states (`byte[3] + byte[0] + byte[1] + byte[2] + byte[5]*byte[4]`; the
`bextr(0x810)` term is byte[2]). `433a` then mapped the whole reachable space: 13 types ×
5 byte positions × 256 values.

- `byte[0..3]` change nothing: 256/256 are `0x800D0203` (entry not found).
- `byte[5]` is the byte that feeds the XOR decode: 12-13 of its 256 values return
  `0x800D0205` (decryption variant mismatch), the rest pass the variant and then fail the
  entry lookup.

Nothing resolves. The registration table is empty for a game process, which is the same
shape as the AIO handle table and the `654` type-11 object: the mechanism is reachable,
the object it needs does not exist in this process.

## What this round adds up to

The chain turned every previous "call it and see" probe into a native program, and the
answer it produced on the three biggest assumptions is no:

| assumption | measurement |
|---|---|
| execute is denied by `mprotect` but maybe allowed by `mmap` | no: bit 2 is refused by `mprotect`, and RWX `mmap` pages fault on execution |
| the object lifetimes are racy at native speed | no: seven races, including three-way on one id slot and close/open reuse |
| sys 532's handle check can be forged into a real entry | the decode is reached; the table is empty |
