# State of play after the 2026-11-05 session, and what is actually left

This merges the upstream inventory (`docs/UPSTREAM_STATE_2026_11_05.md`), the duplicate audit
(`docs/DUP_AUDIT_14_10.md`), the creative route list (`docs/ROUTES_III_14_10.md`) and everything
measured live today. Written so the next session does not re-derive it.

Upstream tip at the time of writing: `c7f3b000` (23 docs ahead of the `ab3379c6` that most of this
repository was written against).

## 1. What has been done

| area | state | evidence |
|---|---|---|
| kernel R/W | **not achieved**; no supervisor-range value has ever been produced by a live path | `UPSTREAM_STATE` P17/P18 |
| KASLR | 17+ techniques dead; no kernel pointer from any syscall | `UPSTREAM_STATE` §1 |
| AIO | dead twice over: the delete never frees (boot tunable gates submit), and `663 mode 0 && count>1` returns EINVAL on 14.10 | `AIO_GATE_14_10.md`, `AIO_MODE0_GUARD_14_10.md` |
| argument 4 (r10) | **never broken** — the stock stub is `mov rax,<num>; mov r10,rcx; syscall`; retracted theory | `SYSCALL_ARG4_R10_14_10.md` retraction, probe 1221a |
| socket ioctl | dispatch works, permission gate refuses (`SIOC*` EACCES, legacy ENOTTY), 0 leaks in 37 requests | `SOCKET_IOCTL_14_10.md`, probe 1222a |
| 638 timezone | bounded binary search over a counted table; no index escapes the array | disassembly 0x6BE5C0, this session |
| blockpool | `653` returns a handle; `654`/`655` only look up an **existing** type-0xb mapping; `mmap(fd=handle)` refused | `BLOCKPOOL_ROUTE_14_10.md`, probes 1223a-d |
| eboot | readable, complete 4.8 MB dump, **zero `syscall` instructions**, no r10 shim | `SYSCALL_ARG4_R10` §12 |
| libc | readable; 94 libkernel import slots mapped through PLT thunks with per-stub call counts | `SYSCALL_ARG4_R10` §12.2 |

## 2. What has not been done

Ranked by what a live measurement could settle:

| # | question | why it is not a duplicate |
|---|---|---|
| 1 | **Which call installs a type-0xb vm_object into a user mapping** | route R1 stopped at `654`'s lookup; the installer is unidentified in both trees |
| 2 | **653's precondition** (returns 0x17/0x18/0x19 then -1 for the same arguments) | one run of four differed; never investigated |
| 3 | 17 OBJECT-sourced copyout candidates — are any reachable with real arguments | upstream calls them "worth testing", nobody called them |
| 4 | `637`'s stored qword at `child+0x280` — does the value change an outcome (probe 346a) | upstream says the A/B never ran |
| 5 | `IPV6_MSFILTER` lock ordering (CVE-2026-49412) with a timing control | upstream got 16 KiB lists accepted, never proved the window |
| 6 | `poll`+`close` race (CVE-2026-45251) on non-procdesc descriptors | upstream says explicitly untested |
| 7 | `604 dl_get_metadata` gate `ctx+0x58 == 0x4800000000000007` | never called in this corpus |
| 8 | `656 dynlib_get_info_for_libdbg` — one call decides whether libdbg/672 can open | gate is debug predicates, not bit 62 |
| 9 | `572` flag mask differs by `proc+0xc81`; every sweep used the wrong layout | never reached the branch |
| 10 | sysent tail 705/713/733 as the table-end discriminator | open row O5 |

## 3. What we can use

* Lua 5.1 exec in an unprivileged game process; 6-argument raw syscalls with all arguments delivered.
* `thr_create(430)` real kernel threads with a controlled ring-3 context (CS 0x43, RIP +0xe0, RSP
  +0xf8, SS 0x3b, gates +0x108=0x480, +0x0d0<=7, +0x110=0x10000).
* 384 MiB zeroed GPU heap via `mmap(477, 0, size, 0x33, 0x1002, -1, 0)`.
* `547` entry metadata (start, end, prot, class, flags) for any mapped VA.
* `674` full VM map; `593` module bases; `638` bounded timezone read; `624` VM-op counter.
* Readable eboot and libc images for static work; libkernel callable but not readable.

## 4. The next five experiments, in order

1. **653 determinism** (one process): `653(0,0)` twice, mmap one anonymous page, `653(0,0)` twice
   more. Four values tell whether the handle depends on vm state.
2. **Installer hunt** (static): disassemble `0x9a6c00`-`0x9a7d10` and `0x9a7f00`-`0x9a9560`,
   looking for a call after `0x9a782b` that hands the constructed object to a map-insert helper;
   that call names the syscall that installs it.
3. **`654` retry** on the VA of any mapping whose `547` class byte is 0xb (none known yet) — this is
   gated on 1 and 2.
4. **`637` A/B** on a fresh process: allocate 64 MiB GPU chunks until one fails, call
   `637(0, size)`, retry; compare with a run that does not call 637.
5. **`604` first call** with the exact five-argument shape and a buffer, recording whether the
   identity gate (`ctx+0x58 == 0x4800000000000007`) is satisfied — it is also an oracle for which
   credential context this process actually runs in.

## 5. Rules this session earned

* Before believing a negative result, run the same call through a second independent route
  (the r10 mistake).
* Before starting a line, `git grep origin/master` for the mechanism (the AIO and wrapper facts were
  already upstream).
* A kill is a result about the call, never about the handler.
* Errno is only written on failure; stale codes survive successful calls.
* One new shape per connection; print the address before executing it.
