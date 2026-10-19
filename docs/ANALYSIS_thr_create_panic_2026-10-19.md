# Analysis: thr_create(430) delayed panic — CS/SS hypothesis

**Date:** 2026-10-19
**Author:** Hermes (cobrajet's agent) — FreeBSD-source cross-reference per CONTRIBUTING
**Probes reviewed:** 58e (phase16), 76c, 76d, 76e, 77a (written, unrun)

## TL;DR

Every crashing probe builds a context with **all segment fields zero** (`mc_cs`,
`mc_ss`, `mc_ds`, `mc_es`, `mc_fs`, `mc_gs` are never written — only `mc_len`,
the +0x0d0 dword, the +0x110 type, rsp and rip are). If the 14.10 kernel copies
those zero selectors into the new thread's trapframe, the child never executes
a single userland instruction: **`iretq` with CS=0 always faults** (CS cannot
be loaded from a null selector). The #GP fires in kernel context inside
`doreti`, and on a 2012-era kernel (r230171) the iret-fault fixup path may not
cover it → double fault → panic. This explains the full crash table,
**including why 76d's clean `Thrd_exit` entry still crashes**: under this
hypothesis the entry point never runs, so entry choice is irrelevant.

## Evidence alignment

| Observation | CS=0 explanation |
|---|---|
| 58e-D/E: rv=0, real TID, crash *seconds later* | Child is scheduled on another core ms later; main Lua thread finishes printing first |
| 76c (longjmp entry) crashes | Entry never reached; panic is at the userland *transition* |
| 76d (Thrd_exit entry) crashes | Same — entry irrelevant |
| 76e crashed *during* the call | Child scheduled before main thread printed |
| Stock FreeBSD would reject this context | `set_mcontext()` calls `is_seg_val()` on `mc_ss`/`mc_cs` and returns EINVAL for selector 0 — rv=0 means **Sony's patched handler dropped that check** (or moved validation to the user-side wrapper at 0xa0ac60, which only gates mc_len/type) |

## Ranked hypotheses

- **H1 (primary): iretq with CS=0/SS=0 → #GP in `doreti` → double fault → panic.**
  Stock FreeBSD 11 `exception.S` has an iret-fault fixup (`cmpq $doreti_iret`
  redirect → SIGSEGV forced on the victim). r230171 predates PTI and several
  hardening passes; Sony's patching may narrow or break the fixup. A #GP whose
  fixup fails = double fault = fatal.
- **H2: RIP=0 fetch fault → sigexit → teardown panic** in thread cleanup
  (the "fault/cleanup handler bug" the TODO suspects). Cannot be distinguished
  from H1 by 76c/76d, because under H1 the entry never runs either.
- **H3: RFLAGS=0 → IF=0 on entry** → CPU runs that thread with interrupts
  masked → stall → Sony watchdog power-off. Weaker: exceptions still deliver
  with IF=0, and the child should fault into the kernel quickly.

## Discriminating probes (new)

1. **78a `getmcontext_layout`** — syscall 78 (`getmcontext`) into a buffer,
   dump the live mcontext: reveals Sony's real `cs/ss/rip/rsp` field offsets
   and selector values with **zero crash risk** (no thread creation).
2. **78b `thr_create_real_segs`** — same crashing context as 76d, but with
   `mc_cs`/`mc_ss` set to the real selector values harvested by 78a
   (expected ~0x33/0x2b-class, PS5 values may differ).
   - **rv=0 and no panic → H1 confirmed**, and we gain a *safe* null-entry
     thread: the child faults at RIP=0 in userland and dies by signal.
   - rv=0 and still panics → H1 dead, H2/H2 favored; next step is
     thr_kill/thr_suspend-before-fault (77c) to intercept the child.

## Review note on probe 77a (panic boundary map)

77a tests 7 **RIP** classes but every section still carries **CS=0/SS=0**.
If H1 is correct, all 7 sections panic at `iretq` before RIP is ever consumed,
and the boundary map measures nothing. Recommend: run 78b first; if H1 holds,
re-base 77a on real selectors (one constant change) before burning console
reboot cycles.

## Caveats

- Sony's mcontext layout is not stock FreeBSD 11 (`mc_len` observed at
  consumer+0xC8, entry at consumer+0xB8, rsp at consumer+0xA0, type/subtype
  dwords at +0xD0/+0xD8). Field mapping above is inferred from probe writes,
  not from 14.10 kernel disassembly. 78a resolves this empirically.
- Kernel-side confirmation needs the 13.60 live dump in Ghidra (in progress):
  locate `sys_thr_create`/`set_mcontext` and the `doreti` fixup tables to see
  exactly which checks Sony removed.
- Selector 0 is *legal* for FS/GS but never for CS/SS via iretq.

## Static RE findings from the 13.60 live dump (2026-10-19, Ghidra 12.1.4)

Attempted to resolve `sysent[430]` and `set_mcontext` in `kernel-13.60-live.bin`
(terrafirma2021 dump, text VA 0xffffffff9e3f0000 + 0xCC0000, data 0xffffffff9f0b0000):

1. **`sysentnames[]` found** at file off 0x254bb10 (stride-8 name pointers, verified:
   `thr_create`@+0xD70=430*8, `thr_exit`@+0xD78, `thr_kill`@+0xD98, `thr_new`@+0xE38).
   A second copy exists at 0x2befa90.
2. **The only stride-32 sysent-shaped table (2048 entries, off 0x34baf50) is an
   all-nosys placeholder** — every entry points to one handler (0xffffffff9e65a7f0).
   No alignment of it yields real handlers for 3/20/430/431/433/455. The real native
   sysent table is not present in the dumped pages (688 pages unmapped).
3. **Syscall handlers are orphan code** in this dump: auto-analysis never disassembles
   them (no xrefs). Force-disassembly around the `mov $0x480,%edx` cluster
   (0x29dc95–0x29fc73) shows it is Sony thread/upcall machinery (proc-type checks
   0x918/0x901, `0x267200` type tags), **not** `cpu_set_mcontext`.
4. `"Fatal double fault"` string exists (off 0x12bdc9f); `"iret trap"` does **not** —
   consistent with a pre-`handle_user_doreti` (2012-era) trap path, supporting the
   H1 double-fault chain.

**Conclusion:** the 13.60 dump cannot cheaply answer the mcontext-layout or
segment-validation questions (wrong pages, orphan code, and the panic is 14.10
behavior anyway). Probe **78a (getmcontext on the live 14.10 console) is the
correct instrument** — it is zero-crash-risk and returns Sony's real field offsets
and selector values directly. Probe **78b** then discriminates H1 vs H2/H3.

## Relapse source read (2026-10-19) -> probe 78c

Read `Relapse-Exploit` source (kexp.js, relapse_exploit.js race core, syscalls.js):

- Kernel stage = **ioctl-speculation race**: `ioctl(0xffffffff, 0x80000000|len<<16|0x4101, nodes)`
  on a bad fd must return -1 (fast fault -> speculation window), driven from a
  syscall ROP chain; `aio_multi_wait(0x297)` frees AIO nodes while
  `aio_submit_cmd(0x29D)` sprays replacements. Node layout: +0x00/+0x08 targets,
  +0x10 = nodeMutex kptr, +0x20 = fd 0xffffffff. Win -> pipe_buffer hijack ->
  kernel r/w -> allproc -> patched shellcode -> elfldr :9021.
- 14.00 killed the race. The open question for 14.10: did Sony remove an
  *ingredient* (bad-fd ioctl speculation, the aio family, or the aio_info gate)
  or only close the *node-lifetime window*? Different targets for the next
  kernel-dump diff.
- Probe **78c** (probes/phase18_race_ingredients/) checks all three ingredients
  with bogus args only (errno returns, no race window entered, zero crash risk).
