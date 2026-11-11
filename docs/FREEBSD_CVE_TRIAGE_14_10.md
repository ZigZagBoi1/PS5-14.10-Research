# FreeBSD CVE Triage for PS5 14.10 (r230171)

**Date:** 2026-11-04
**Question:** which published FreeBSD 11.x-13.x local privilege-escalation bugs have a precondition that an unprivileged PS5 process (uid 1, gid 1, Lua loader inside a game process) can actually create with plain syscalls, and which of those are worth a probe.

**Evidence grades used on every row:**
- **[M]** measured on 14.10, with the capture cited.
- **[S]** static reading of a 13.60 artifact. Says nothing about 14.10 behaviour; useful only to identify what a slot is *named*.
- **[R]** recalled upstream fact, not verified anywhere in this repository. Treat the CVE id as a search key, not as a citation.

---

## 0. Bottom line

1. **The corpus has been triaging the wrong decade.** The console kernel is an **11.0.0-era fork** (`docs/EXPLOIT_SURFACE_ANALYSIS_13.60.md:4`, `:10`, `:34`; `docs/CVE-2026-49424-PS5-14.10.md:45` says "based on r230171 (roughly FreeBSD 11.x era)"; the reference tree used for every handler comparison is `refs/freebsd-11.0.0/sys/`). Every 2026 CVE in `docs/` is scoped to FreeBSD 14.3, 14.4, 15.0 or 15.1. Code that was written in 2024-2026 cannot be missing-and-therefore-vulnerable in a 2016 fork: it was never there. Those CVEs are **not "patched" and not "unresolved" - they are out of scope by construction**, and the corpus has spent a great deal of effort on them.
2. **Zero corpus CVEs survive as live hypotheses.** After the version filter, the argument filters, and the removal of whole syscall families, no 2025-2026 CVE has a reachable trigger on 14.10. Section 4 records the mechanism of removal for each.
3. **The one CVE whose precondition is fully confirmed cannot be measured.** CVE-2019-5607 (SCM_RIGHTS `f_count` leak) needs a refcount oracle the console does not have. It is parked, not cut (section 6).
4. **The live surface is Sony's own syscall table, not FreeBSD's.** The reachable objects that can still be corrupted are: `struct file`, a socket buffer, a kqueue knote, and a umtx object. The missing capability is a **kernel write**; there are exactly two untested candidates for one (657 and 596, section 5).
5. **Two repository errors were found while triaging** (section 7). The first would have produced a false negative on the repository's own top candidate.

---

## 1. Which FreeBSD this is, and why it decides everything

| Evidence | Claim |
|---|---|
| `docs/EXPLOIT_SURFACE_ANALYSIS_13.60.md:4` | "kernel dump (16,391-symbol Ghidra project) + FreeBSD 11.0.0 source" |
| `docs/EXPLOIT_SURFACE_ANALYSIS_13.60.md:10` | analysed "against the PS5 13.60 kernel (FreeBSD 11.0.0 fork)" |
| `docs/SYSCALL_NAME_MAP_13.60.md:5` | names assigned "via FreeBSD 11.0.0 syscall numbering + `__func__`/sysent string refs" |
| `docs/CVE-2026-49424-PS5-14.10.md:45` | "The PS5 kernel is based on r230171 (roughly FreeBSD 11.x era)" |
| `docs/sysent-names-13.60.csv:67` | `65,msync` - the FreeBSD 11 numbering, not 12/13/14 numbering |
| `docs/sysent-names-13.60.csv:228` | `226,msgsnd` |

**The triage rule that follows:** a bug is *potentially live* only if the vulnerable code existed at the fork point **and** the fix landed after Sony's merge point. Bugs fixed in 11.0-RELEASE or earlier are patched by the base. Bugs introduced in 12.0 or later are absent by construction. The interesting window is therefore **FreeBSD 11.1 / 11.2 / 12.0 security fixes against 11.0.0 code** - a 2016-2018 corpus, not a 2026 one.

A second consequence: syscall numbers >= 500 in the 13.60 table are Sony's, not FreeBSD's (`538+` `evf_*`/`osem_*`, `601` `mdbg_service`, `622` `ipmimgr_call`, `653-657` blockpool). No upstream CVE can be mapped onto those by number. They need their own audit, and that is where the remaining reachable surface actually is.

---

## 2. Corpus CVEs, by subsystem, with 14.10 status

Status vocabulary: **PRESENT** = the syscall/subsystem answers on 14.10; **ABSENT** = the entry point or the data structure does not exist; **UNKNOWN** = never measured.

### 2.1 File descriptors and unix sockets
| CVE | Mechanism (one line) | Precondition | 14.10 | Citation |
|---|---|---|---|---|
| CVE-2019-5607 | `unp_internalize()` `fhold` without a matching `fdrop` on the error path; `f_count` is uint32 and wraps, leaving a dangling `struct file` | socketpair + sendmsg SCM_RIGHTS | **PRESENT** (precondition confirmed: 16+ fds, 5 cycles) | `docs/EXPLOIT_SURFACE_ANALYSIS_13.60.md:34`; `probes` 28, 30b |
| CVE-2026-58090 | unix SOCK_STREAM receive path frees control messages still linked to the socket buffer | recvmsg with cmsg + error path | **ABSENT** - advisory scope is 15.0/15.1 only, post-fork | `docs/CVE-2026-58090-PS5-14.10.md:21` |
| CVE-2026-49417 | `/dev/dsp` close-while-mapped UAF | open `/dev/dsp` | **ABSENT** at every tested path (`/dev/null` opens, `/dev/dsp`, `/dev/dsp0.0`, `/dev/sndstat` all -1) | `docs/REMAINING_CVE_TRIAGE.md`; `results/54a_dsp_access_check_20261018_032254.txt:3-7` |
| CVE-2026-45258 | `/dev/dsp` mmap integer overflow | same | **ABSENT** (same open failure) | as above |

### 2.2 Networking
| CVE | Mechanism | Precondition | 14.10 | Citation |
|---|---|---|---|---|
| CVE-2020-7457 | `ip6_pcbopts()` called without the inp lock from `IPV6_2292PKTOPTIONS` setsockopt | a pktopts object that the option actually stores | **ABSENT in effect** - the RFC2292 aliases store nothing; `getsockopt(25)` returns empty | `docs/IPV6_ANCILLARY_14_10.md` (probe 50n) |
| CVE-2026-49412 | IPV6_MSFILTER: lock dropped during copyin, source-filter list UAF | option 74 + a second thread + a joined group | **PRESENT but clean** - option reachable, 173 accepted / 1875 rejected during 2048 parent leave/rejoin, no UAF | `docs/CVE-2026-49412-PS5-14.10.md:4`; probe 50w |
| CVE-2026-49422 | TCP RACK `setsockopt` handler | `tcp_rack.ko` loaded, `TCP_CONGESTION=rack` | **ABSENT** - stack reports `newreno`, no module load path | `docs/CVE-2026-49422-PS5-14.10.md:21`, `:80` |
| CVE-2019-11477 / 2019-5599 | SACK scoreboard arithmetic / panic | a TCP peer sending crafted SACKs | **PRESENT** (loopback TCP works) but **DoS only**, no escalation | `docs/EXPLOIT_SURFACE_ANALYSIS_13.60.md`; probe 49b |
| (no CVE) SCTP | large 11.0.0 state machine | `socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)` | **ABSENT** - see section 7.2 | `results/48a_sctp_ipv6_icmp_20261016_201145.txt` |

### 2.3 AIO (the public Relapse bug)
| CVE | Mechanism | Precondition | 14.10 | Citation |
|---|---|---|---|---|
| Relapse `aio_multi_wait` UAF (no CVE id in corpus) | new wait modes double-link AIO requests; a controlled decrement at an arbitrary kernel address corrupts a `pipe_buffer` | aio 661-670 live | **ABSENT** - 661/665/668 are `nosys` stubs, 662/663/664/666/667/669 answer -1, 670 returns 0; the delete lock-drop is gated off behind a boot tunable | `docs/AIO_RANGE_14_10_EVIDENCE.md:642`, `:646`, `:649`; `docs/CHANGELOG.md` 2026-10-27 (`[W+4]`/`[W+0xc]`, tunable `0x8b4c78d0`) |
| CVE-2026-49418 | `msync(MS_INVALIDATE)` on a device-pager mapping leaves pages on the pager list; second invalidate UAFs | a device-backed mapping + MS_INVALIDATE accepted | **ABSENT** - MS_INVALIDATE returns -1 on anon, GPU, `/dev/dmem0` and `/dev/gc` mappings, while MS_SYNC/MS_ASYNC return 0 | `results/phase17_new_vectors/455a_msync_invalidate_20261023_110152.txt:5`, `:8`, `:12`, `:15` |

### 2.4 Shared memory, sendfile, TLS
| CVE | Mechanism | Precondition | 14.10 | Citation |
|---|---|---|---|---|
| CVE-2026-45257 | KTLS receive + loopback sendfile overwrites page cache | sendfile + KTLS | **ABSENT** - `sendfile` returns -1 | `docs/REMAINING_CVE_TRIAGE.md`; `docs/CHANGELOG.md` 2026-10-22 |
| CVE-2026-49427 | POSIX shm largepage + sendfile | `shm_open` + `SHM_LARGEPAGE` + sendfile | **ABSENT** - `shm_open` works end to end (58d) but `SHM_LARGEPAGE` and `sendfile` return -1 | `docs/CVE-2026-49427-PS5-14.10.md:31`; `docs/CHANGELOG.md` 2026-10-22 |

### 2.5 kqueue, ttys, jails, kernel modules
| CVE | Mechanism | Precondition | 14.10 | Citation |
|---|---|---|---|---|
| CVE-2026-58083 | kqueue copy-on-fork: a timer knote becomes active and is enqueued during the copy | `fork`/`rfork` | **ABSENT twice** - scope is 15.1, and `fork`(2)/`rfork`(251)/`thr_new`(455) return -1 | `docs/CVE-2026-58083-PS5-14.10.md:4`; `docs/ATTACK_SURFACE.md` blocked list |
| CVE-2026-58093 | `TIOCSCTTY` ioctl on a tty | ioctl 54 + a tty fd | **ABSENT** - ioctl blocked, no tty fd | `docs/CVE-2026-58093-PS5-14.10.md:4` |
| CVE-2026-49416 | vt(4) CONS_HISTORY ioctl overflow | ioctl 54 + `/dev/console` | **ABSENT** | `docs/REMAINING_CVE_TRIAGE.md`; `docs/FINDINGS.md:616` |
| CVE-2026-49419 | jail refcount underflow frees an in-use prison | jail_get/jail_set | **ABSENT** - 338/496/497 sit on the `nosys` slot in the 13.60 dump | `docs/CVE-2026-49419-PS5-14.10.md:4`, `:55` |
| CVE-2026-49424 | Linuxulator `linux_waitid()` | `linux.ko`/`linux64.ko` | **ABSENT** - loadable module, no load path, wrong era | `docs/CVE-2026-49424-PS5-14.10.md:4`, `:45` |
| CVE-2026-7270 | `execve` argument parsing precedence overflow | execve(59) reachable | **UNKNOWN** - no probe has ever issued 59 | `docs/CVE-2026-7270-ASSESSMENT.md` |
| CVE-2026-49414 | ELF ASLR disabled for setuid PIE | setuid exec | **UNKNOWN** - precondition unestablished, same missing probe | `docs/REMAINING_CVE_TRIAGE.md:119` |
| CVE-2020-25579 [R] | msdosfs `readdir` padding leaks kernel memory | a FAT mount | **ABSENT** - no mount syscall | - |
| CVE-2026-45251, CVE-2026-45256, CVE-2026-49428 | - | - | **UNKNOWN** - no assessment doc in `docs/` | - |

### 2.6 Removed families (whole-subsystem cuts)
| Subsystem | 14.10 | Citation |
|---|---|---|
| SysV IPC (sem/msg/shm) | **ABSENT** - 221/222/225/226/227/228/230/231 kill; 936a/936b/936c kill; 220/229/223/224 -1 | `docs/SYSV_IPC_14_10.md` |
| kld* / sysctlbyname | **ABSENT** - 307/308/337/570 deliver SIGSYS | `docs/SYSCALL_ABSENT_VS_LETHAL.md` |
| capsicum | **ABSENT** - `cap_rights_limit` 533, `cap_rights_get` 515 blocked | `docs/ATTACK_SURFACE.md` |
| procctl | **ABSENT** - 689 kills; 544 is `evf_set`, not procctl | `docs/SYSENT_PRESENCE_14_10.md` |
| `_umtx_op` PI ops | **ABSENT** - 32-37 all -1 | `docs/CHANGELOG.md` (probe 941a) |
| `_umtx_op` SHM (op 25) | **ABSENT** - confirmed stub, all sub-ops return 0/-1 with no state | `docs/CLAUDE.md` (probes 151a-152k) |

---

## 3. Upstream classes the corpus never named

These are 11.0.0-era mechanisms with no CVE id in `docs/`. They are listed because the id is not what decides applicability - the source location and fix era are.

| Class | Mechanism | Precondition | 14.10 |
|---|---|---|---|
| `_umtx_op` ROBUST_LISTS (op 26) | `umtx_robust_lists` is kmalloc'd, linked to `td`, and freed on unregister and on thread exit; a walk concurrent with the free is a small-object UAF | op 26 + two threads | **UNKNOWN** - never issued (`docs/UMTX_454_EVIDENCE.md:52`) |
| `sosend` / SO_SNDBUF accounting | `setsockopt(SO_SNDBUF)` takes SOCKBUF_LOCK, `sosend_generic()` drops it inside `m_uiotombuf()`, so `sb_cc` can pass `sb_hiwat` | two threads, one resizing, one sending | **UNKNOWN** - identified as window 5 in `docs/EXPLOIT_SURFACE_ANALYSIS_13.60.md`, never raced |
| `poll`/`select` vs close | fd-set scan against a concurrent close | 2 threads + poll(209) | **UNKNOWN** - 45251 never assessed; `poll` works, `select(0,0,0,0,0)` blocks forever |
| `ptrace` | native 26 was never swept (only `compat.ptrace` is known to be `nosys`) | a traceable child | **UNKNOWN** - worth one presence call |
| `EVFILT_PROC` NOTE_TRACK | knote re-parenting on process exit | kqueue + a child | **UNKNOWN** - one unexplained console power-off after probe 105a, never attributed (`docs/KQUEUE_PROC_14_10.md`) |

---

## 4. Cuts, and the exact mechanism of removal

1. **Relapse's own kernel bug (aio_multi_wait).** 661, 665 and 668 are `jmp 0x265760` nosys stubs on 14.10, and the delete path's lock drop is gated behind `[W+4]` which nothing reachable sets. This is not a patch to the UAF; the family was withdrawn. Worse for the technique: **`pipe(42)` returns fds 0,0 on 14.10**, so the `pipe_buffer` corruption that converts the decrement into kernel R/W has no target object. Any new work in this class needs a different payoff object.
2. **CVE-2026-49418 (msync device pager).** The trigger bit is filtered. `MS_INVALIDATE` returns -1 on four mapping types while `MS_SYNC` and `MS_ASYNC` return 0 (`455a`). This is an argument filter at the syscall, upstream of any pager code.
3. **CVE-2020-7457 (IPv6 pktopts).** The object the race operates on is never created: the RFC2292 aliases store nothing (50n).
4. **CVE-2026-49412 (IPV6_MSFILTER).** Reachable and raced; 2048 leave/rejoin cycles produced no UAF (50w). Also 14.3+ scope.
5. **CVE-2026-58083 (kqueue fork-copy).** Requires fork, and fork is gone. Scope is 15.1.
6. **CVE-2026-58090 (unix recvmsg cmsg).** Scope is 15.0/15.1; the control-message detach was rewritten after the fork.
7. **/dev/dsp pair (45258, 49417) and vt(4) (49416).** No device node opens; ioctl 54 is blocked outright.
8. **sendfile/KTLS pair (45257, 49427).** `sendfile` and `SHM_LARGEPAGE` both return -1.
9. **SysV IPC, kld*, capsicum, procctl, jail.** Entry points are either lethal or `nosys` (section 2.6).

---

## 5. Survivors, ranked

Ranking is (payoff x reachability) / cost, with crash risk as a tiebreak. Each survivor names the one probe that decides it. All probes assume the SIG_IGN shield prologue from `docs/SYSCALL_ABSENT_VS_LETHAL.md` (sigaction 416, signal 12, `act[0]=1`) and put unfamiliar numbers last.

### S1 - sysctl corrected MIBs: `net.inet.tcp.pcblist` as a KASLR oracle  (KASLR)
**Why it is new.** The repository's pcblist verdict rests on `{4,1,6,1}`, which is the AF_UNIX tree, not TCP. The correct MIB is `{4,2,6,11}` (CTL_NET, AF_INET, IPPROTO_TCP, TCPCTL_PCBLIST). A non-existent leaf returns `ret=0 len=0`, which is exactly the false-negative shape the earlier probe produced (`docs/CORRECTED_MIB_14_10_EVIDENCE.md`). The handler copies out an array of `struct xtcpcb`; in 11.0.0 that record embeds `struct xsocket`, whose `so_pcb` field is the inpcb's kernel address. No privilege check sits in that path. If it is unsanitised, an ordinary TCP socket becomes a kernel-pointer leak - the same class as Relapse's AF_ROUTE trick, through a different interface.
**Precondition.** One bound or connected TCP socket (loopback listener on 31337 works) and `sysctl`(202), which is reachable via `make_syscall` (`docs/ATTACK_SURFACE.md`).
**Probe.** `probes/phase14_final_push/56l_corrected_mib_probe.lua` is already written, offline-validated with 46 assertions in `tools/test_probe56l.lua`, CRASH_CLASS LOW. Run it. Then scan the returned record for any 8-byte word with high half `0xFFFF8000` or `0xFFFFFFFF` and a plausible low half.
**Vulnerable vs patched.** `len > 0` with a kernel-range word = leak, KASLR defeated for the direct map. `len == 0` or all-zero `so_pcb` = sanitised, cut. Second MIB in the same probe, `{1,14,15,pid}` (KERN_PROC_KSTACK, leaf 15 - not the 35 that was tried), returns symbol strings; if symbolisation fails it may print raw addresses.

### S2 - 601 `mdbg_service`: find the setter for the three gate bits  (kernel debug service)
**Why it is new.** The 2026-11-04 handler audit established that 601 has a 40-entry relative jump table at RVA `0x1a51160` and **no capability-bit test at all** (`docs/CLAUDE.md`). Its gates are three state bits: `[td+0x529]&1`, `[proc+0x563]&4`, `[proc+0x464]&1`, plus boot-state helper `0xb078d0`. The audit stopped there and never asked **which reachable syscall writes those bits**. If any Sony setter flips one, the debugger command set opens - including the memory operations, and the two commands (0x03, 0x04) that are lethal today.
**Precondition.** Nothing. 601 answers -1 or 0 without crashing for every non-lethal command.
**Probe.** Baseline the return vector of the non-lethal commands (0x00, 0x01, 0x02, 0x07, 0x09, 0x0d, 0x12, 0x13, 0x14, 0x15-0x19). Then, for each candidate setter - 643 `set_chicken_switches` (writes `proc+0xa34`), 675 reset globals, 640 `set_uevt`, 648 `app_state_change`, 602 `randomized_path`, 637 `set_phys_fmem_limit`, 636, 652, 587 - call the setter, re-run the baseline, and diff. Any -1 to 0 transition on a previously refused command is the gate opening. Only then approach 0x03/0x04.
**Vulnerable vs patched.** A transition = the gate is a state machine, not a privilege check, and the debug service is reachable from uid 1. No transition across all setters = the bits are set only by the boot/debugger path, cut.
**Crash class.** LOW while 0x03/0x04 are excluded.

### S3 - 657 `blockpool_batch`: raw store or copyout?  (the only write candidate)
**Why it is new.** The handler writes a dword 0 at `arg3` for every count 0..8, returns 0 only at count 0, **keeps writing after `close(h)`**, and writes 16 bytes when `arg2=0` (`docs/CHANGELOG.md:1287`; `docs/ATTACK_SURFACE.md:221`). "Writes after the descriptor is closed" and "no descriptor revalidation" are the signature of a compiled `*out_status = 0`, not of a checked `copyout`. If the store is raw, then 657 is an **arbitrary 16-byte zero write**, and the only thing standing between it and a working primitive is KASLR. Nothing in the repository has ever asked this question - every probe passed a mapped user buffer, where a raw store and a copyout are indistinguishable.
**Precondition.** Nothing (no descriptor needed - it writes without one).
**Probe.** One call with `arg3` = an address in the user range that is mapped **read-only** (mmap RW, then `mprotect` PROT_READ; `mprotect` with prot 0/1/3 returns 0 per `docs/RWX_ORACLE_14_10.md`). A copyout returns -1/EFAULT and the process lives. A raw store faults at CPL0 with no `pcb_onfault` and takes the process - or the console - down.
**Vulnerable vs patched.** EFAULT + alive = copyout, cut. Kill or panic = raw store, and 657 becomes the write half the project is missing.
**Crash class.** MEDIUM-HIGH. Run it last in a session, after the loader is known to be relaunchable, and record the pre-call pid so a console death is distinguishable from a process death.

### S4 - `_umtx_op` op 26 ROBUST_LISTS: the last live umtx path  (kmalloc UAF)
**Why it is new.** umtx was closed twice - op 25 is a confirmed stub, PI ops 32-37 are refused - but **op 26 was never issued** (`docs/UMTX_454_EVIDENCE.md:52`). It is the only umtx operation that allocates and frees kernel memory under user-controlled lifetime: `umtx_robust_lists` is copied in, linked to `td`, freed on unregister, and freed again at thread exit. That is a two-thread UAF on a small kmalloc object, the same shape as the bug Relapse used, reachable with no fork, no pipes and no AIO.
**Precondition.** 454 (works), a mapped 16-byte buffer, and thr_create(430) for the second thread.
**Probe (reachability ladder, one process, no race).** (a) `454(26, buf, 0, 0, 0)` with `buf = {rd, rdl}` and `rdl = 1`; expect 0. (b) register a second time on the same thread; expect EEXIST/EBUSY. (c) `454(26, 0, 0, 0, 0)` to unregister; expect 0. (d) repeat (c); expect EINVAL. (e) `rdl = 25` (> 24); expect EINVAL.
**Vulnerable vs patched.** All five shapes answering -1/ENOSYS = the op is a stub, cut. The upstream errno ladder (0 / EEXIST / 0 / EINVAL / EINVAL) = the object exists, and the race in (b)+(c) against a thread blocked on a robust mutex becomes the experiment.
**Crash class.** LOW for the ladder.

### S5 - 619 `test_debug_rwmem`: stub or gated implementation?  (kernel R/W)
**Why it is new.** 13.60's 619 body is `mov eax,0x4e; ret` - a stub. 14.10 returns -1 for fifteen argument layouts (`results/phase17_new_vectors/179a_debug_rwmem_args_20261020_194308.txt`), which is consistent with a stub *and* with a gated implementation. Nobody has separated the two. The discriminator is that a stub ignores its arguments completely, while a gated handler validates `arg1` (a pid) before refusing.
**Precondition.** Nothing.
**Probe.** Read the result of `probes/phase17_new_vectors/706a_sys619_slot.lua` first - it was written for exactly this. If unrun, run it, then add: `619(getpid(), buf, 8, 0, 0, 0)` vs `619(0x7fffffff, ...)` vs `619(0, ...)`, with a timing sample per shape. Identical return and identical timing across all three = stub. Different errno, or a repeatable timing gap, = implemented and gated.
**Vulnerable vs patched.** Implemented-and-gated means the remaining work is the same as S2: find the flag. A stub means the only memory syscall in the table is 601's command set.

### S6 - 596 `dynlib_do_copy_relocations` with a real module  (possible 8-byte write)
**Why it is new.** It returns 0 for six zeros, which is the shape of a loop that ran and found zero relocations to apply - not of an ENOSYS stub (`docs/SYSENT_PRESENCE_14_10.md:78`). A copy relocation writes a symbol's value into a module's data. If the target address is caller-supplied and not range-checked against the module, that is an arbitrary 8-byte write. The handler has only ever been called with zeros.
**Precondition.** A module handle from 593 or 649, and a user buffer.
**Probe.** `596(handle, buf, n, 0, 0, 0)` and one variant per argument position, pre-filling `buf` with a sentinel and diffing afterwards; also vary the handle to an invalid one to see whether the return changes from 0.
**Vulnerable vs patched.** Sentinel changed = the handler wrote through a caller pointer; check whether the write address is taken from the buffer. All shapes 0 with no write = no-op, cut.

### S7 - execve(59) reachability, to scope 7270 and 49414  (scope only)
**Probe.** `59("/nonexistent", 0, 0)`: ENOENT means the exec path is live; a kill means the slot is absent. Then `59("/app0/eboot.bin", argv, envp)` with a legal argv: ENOEXEC/EACCES means the ELF loader ran; a kill means it did not.
**Do not** run an oversized-argument trigger; the repository has no authenticated 14.10 kernel code for the 7270 expression (`docs/CVE-2026-7270-ASSESSMENT.md`). The reachability call is the deliverable.

---

## 6. Parked and flagged

**Parked: CVE-2019-5607 (SCM_RIGHTS `f_count` leak).** Precondition fully confirmed, mechanism sound, and the only upstream CVE that a plain-syscall process can set up today. It is parked because the repository has **no refcount oracle**: `kern.proc.filedesc` is refused, `fstat` returns no `f_count`, and probe 89a cannot distinguish fd reuse from a wrapped count. The chain claim was withdrawn for a good reason - the fix is `unp_internalize_cleanup_rights()` on the error path, so the absence of an inline decrement proves nothing (`docs/CHANGELOG.md:1167`). Before this can be ranked, someone must design a *countable* observable: for example, leak the same `struct file` N times, close the sender's copy, and test whether the receiver's fd still resolves after `N` error-path iterations - a difference in the number of iterations before EBADF is a count, even if the absolute value is unknown.

**Flagged, do not run first: 561 `suspend_process`.** It is the only Sony syscall that both hangs (six zeros) and kills (pid 999999) on argument variation, i.e. the only one that walks the process table as uid 1. Calling it on a system pid is the shortest path to an unbootable console in this entire document. If it is ever probed, the argument should be `getpid()` only.

---

## 7. Two repository errors found during this triage

### 7.1 The repository's top CVE candidate is built on the wrong syscall number
`docs/CVE-2026-49418-PS5-14.10.md:39` and `:55` treat **226** as `msync`, and the prepared probe `58a` issues `make_syscall(226)`. But `docs/sysent-names-13.60.csv:228` reads `226,msgsnd`, and `docs/sysent-names-13.60.csv:67` reads `65,msync`. `docs/ATTACK_SURFACE.md:105` already records the correction ("226 is `msgsnd` in the 13.60 sysent table, not `msync`"). 226 is a SysV IPC entry, and every SysV entry tested on 14.10 **kills the process** (`docs/SYSV_IPC_14_10.md`). Had 58a been run as written, it would have killed the loader and been recorded as "msync blocked" - a false negative on the repository's strongest candidate, produced by the probe itself.
The real msync number, 65, has since been measured: `455a` shows `msync(flags=0)=0`, `msync(MS_ASYNC)=0`, and `msync(MS_INVALIDATE)=-1` on anon, GPU, `/dev/dmem0` and `/dev/gc` mappings. So the CVE is cut on evidence, not on a numbering accident - but the document and probe 58a should be corrected rather than deleted, because the *next* reader will hit the same trap.
One cheap confirmation remains: `msync(MS_INVALIDATE)` on a `shm_open`-backed `MAP_SHARED` mapping. If it also returns -1, the refusal is a global flag filter (which the anon result already implies); if it returns 0, the filter is mapping-type dependent and the pager path deserves one more look.

### 7.2 "SCTP available: true" is a raw-socket artefact
`results/48a_sctp_ipv6_icmp_20261016_201145.txt:246` and `docs/ALL_RESULTS.md:3725` report SCTP as available, and `docs/research/scene_research_oct2026.md` inherits the claim. The same capture shows why that is wrong: `SCTP/INET stream`, `dgram` and `seqpacket` all return **-1**, and only `SOCK_RAW, IPPROTO_SCTP` opens. A raw socket with protocol 132 is handled by the generic raw-IP path, which accepted 143 of 255 protocol numbers in the same run. There is no SCTP protocol switch, so no association state machine, no chunk parser, and no 11.0.0 SCTP attack surface. The stream/dgram failures are the finding; the summary line is the artefact.

---

## 8. What this implies for the mission

- **The FreeBSD CVE well is dry for this console.** Not because Sony patched everything, but because the fork predates almost the entire modern corpus. Future triage should read 11.0.0 sources against 11.1/11.2/12.0 advisories, not 2026 advisories.
- **The reachable corruption targets are four objects**: `struct file` (via unix sockets and SCM_RIGHTS), a socket buffer (via `sosend`/`sb_cc`), a kqueue knote (EVFILT_PROC/NOTE_TRACK), and a umtx object (op 26). The Relapse payoff object, `pipe_buffer`, does not exist here because `pipe(42)` returns fds 0,0.
- **The missing capability is a kernel write.** Two untested candidates exist (657, 596). A raw store in either one converts the whole problem into a KASLR problem.
- **The missing capability on the other side is a kernel read.** The cheapest untested leak is an ordinary TCP socket plus a correct sysctl MIB (S1). If that fails, the next candidates are the `kstack` leaf and the fault oracle, in that order.
- **The Sony table is the real attack surface.** 601's jump table has no capability test, only state bits; 619's gate has never been characterised; 561 walks the process table. These are not memory-safety bugs, they are state-machine bugs, and they are exactly the "ordinary interface used in an untried way" shape the mission is asking for.

---

*Written offline from the repository's committed evidence. No console access was used. Every [M] row is a committed capture; every [S] row is a 13.60 static reading and must not be read as 14.10 behaviour.*

## Measured after this document was written (2026-11-04 15:32 and 15:33)

### S1 is closed by measurement, not by argument

Probe `probes/phase14_final_push/56l_corrected_mib_probe.lua` ran with the corrected MIBs
(capture `results/phase14_final_push/56l_corrected_mib_probe_20261104_153236.txt`, 0.03 s, no panic):

```
[B] TCP pcblist {4,2,6,11}
  MIB sent: {4,2,6,11}
  size query ret=-1 needed=0
  no data (refused or size query failed)
[C] kstack {1,14,15,80}
  size query ret=-1 needed=0
```

The corrected leaf is refused **exactly like the wrong one**: ret=-1 with needed=0 on the size query, i.e. the
refusal happens before any OID walk, at the sysctl rnode level (the same wall as `kern.proc.filedesc`,
`kern.proc.vmmap`, `kern.file`, `kern.proc.kstack` in `docs/CLAUDE.md:217`). So the pcblist KASLR leak was never a
MIB-shape problem and the corrected MIB does not reopen it. `{1,14,15,pid}` fails identically: the kstack leak is
also an rnode refusal.

The same capture re-measured the ktimer numbering as a side effect and confirms it from behaviour, not from the name
table: D1 armed a fresh timer with `237(id,0,its,its2)` and `238` then reported it live (`237 = ktimer_settime`);
D2 removed a fresh timer with `236(id)` and `238` then failed (`236 = ktimer_delete`).

### S3's store is an out-parameter behind a gate we cannot satisfy

`results/kernel_handlers/decompiled/sys_657.c:16-31` gives the whole shape: uap `{commands, count, pad, processed_count,
flags, pad}`; 22 if `flags != 0` or `count < 0`; then one 32-byte record per iteration, a lookup of the record's
`address` in `td->proc->map` **requiring object byte +0x9d == 11**, and only then the helpers. The 16-byte store that
`docs/CHANGELOG.md:1287` saw is `store32_259790` publishing `(cursor-start)/32` - a processed-count out-parameter,
not an arbitrary store. Its precondition is the same type-11 object that `docs/GPU_VM_OPS_14_10.md:77` shows we
cannot create (`mmap(477)` GPU mappings are not accepted by 654/655/657). S3 is therefore not the write half: the
store is downstream of a lookup that cannot succeed for a game process, and the read-only-page discriminator would
only confirm that the out-parameter is reached after the gate.
