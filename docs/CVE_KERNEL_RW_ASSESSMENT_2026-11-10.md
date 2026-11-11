# Kernel R/W CVE Assessment — PS5 14.10 (2026-11-10)

## Summary

Comprehensive offline analysis of every known FreeBSD kernel CVE from 2019-2026
that could provide kernel read/write, cross-referenced against PS5 14.10's
confirmed capabilities and restrictions. **Result: all known CVEs are blocked.**

## CVE Analysis

### CVE-2020-7457 — IPv6 ip6_setpktopt Race (MOST RELEVANT)

**Bug:** Race condition in `IPV6_2292PKTOPTIONS` handler. The `ip6_pcbopts()`
call ran WITHOUT `INP_WLOCK`, so a concurrent `close()` could free the
`ip6_pktopts` struct while `ip6_setpktopt` was writing into it.

**Exploit:** Metasploit module by Andy Nguyen (@theflow0). Overwrites
`ip6po_pktinfo` pointer in freed memory → arbitrary kernel R/W. Uses `allproc`
walk for privilege escalation.

**Patch (SA-20:20/ipv6.patch):** Adds `INP_WLOCK`/`INP_WUNLOCK` around ONLY
the `ip6_pcbopts()` call (the 2292PKTOPTIONS path). Changes allocation from
`M_WAITOK` to `M_NOWAIT` to avoid sleeping under the lock. Does NOT change any
other option handler.

**PS5 14.10 status: BLOCKED**
- Sony blocked `IPV6_2292PKTOPTIONS(6)` entirely (returns -1)
- `IPV6_PKTINFO(46)` and `IPV6_TCLASS(61)` use the same `ip6_setpktopt`
  function but go through `ip6_ctloutput` which already holds `INP_WLOCK`
- Tested: 91d (11,548 concurrent PKTINFO calls), 92c (20 rounds, 160 children,
  PKTINFO vs close) — both survived with zero anomalies
- Conclusion: The lock is held for PKTINFO on PS5 14.10

**Why this matters:** The exploit pattern (master/victim socket, ip6po_pktinfo
pointer overwrite) is EXACTLY what our SDK v0.45 documents. If we found a way
to reach `ip6_setpktopt` without the lock, the entire exploitation chain is
known.

### CVE-2024-43102 — UMTX_OP_SHM Double-Destroy Race

**Bug:** `UMTX_SHM_DESTROY` race — two concurrent destroys drop refcount twice,
third thread gets fd to freed `shmfd`. Threads only, affects FreeBSD 11.0+.

**PS5 14.10 status: DEAD** — Sony stubbed the entire UMTX SHM subsystem.
All sub-ops (create=1, destroy=4, alive=8) return 0 but do nothing: zero VM
ops, zero fd allocation, zero slab allocation. Probes 151a-152k.

### CVE-2021-29626 (SA-21:08.vm) — Stale VM Mapping After COW

**Bug:** Stale virtual memory mapping after copy-on-write. Descendant process
keeps mapping to freed page, reads other processes'/kernel data.

**PS5 14.10 status: DEAD** — Requires `fork()`. fork/rfork both return -1 on
PS5. Threading (thr_new/thr_create) shares address space, no COW trigger.

### CVE-2026-49427 — POSIX SHM Largepage sendfile UAF

**Bug:** sendfile with SF_NOCACHE on largepage-backed shm objects releases pages
that still have live mappings.

**PS5 14.10 status: DEAD** — `shm_open2(571)` is nosys. SHM_LARGEPAGE flag
unavailable. Probes 391a-391d.

### CVE-2026-45251 (SA-26:19.file) — poll/close UAF

**Bug:** File descriptor closed while thread blocked in poll/select; kernel
doesn't unlink waiting thread before freeing object.

**PS5 14.10 status: DEAD** — Confirmed present (seldrain absent 150/150) but
unexploitable: zone isolation blocks every spray path. 0/35 reclaim across
same-CPU readback and safe-reclaim oracles. Probes 500a-500o.

### CVE-2026-49422 (SA-26:43.tcp) — TCP RACK setsockopt UAF

**Bug:** RACK TCP stack handler drops connection lock to copyin, concurrent
stack switch frees the saved pointer.

**PS5 14.10 status: DEAD** — RACK was added in FreeBSD 12+. Affected versions
are 14.3-15.1. PS5's FreeBSD 11 fork does not have the RACK stack.

### CVE-2026-58093 — TTY ioctl Race

**PS5 14.10 status: DEAD** — No /dev/tty access. Probe 58d.

### CVE-2026-58091 — Audio sync-group ioctl UAF

**PS5 14.10 status: DEAD** — No /dev/dsp in device inventory. /dev/ajm is
Sony's custom audio chip, not FreeBSD sound(4).

### CVE-2026-58090 — Socket recv-buf UAF

**PS5 14.10 status: DEAD** — FreeBSD 15.0+ only.

### CVE-2026-58094 (SA-26:63.posixshm) — POSIX SHM Largepage TOCTOU

**PS5 14.10 status: DEAD** — Requires FIOSSHMLPGCNF ioctl and largepage infra,
both absent. shm_open2(571) is nosys.

### CVE-2026-49418 — Device Pager msync UAF

**PS5 14.10 status: DEAD** — msync(65) with MS_INVALIDATE returns -1 on ALL
mapping types. Probes 58a/58b.

### CVE-2019-5596 (SA-19:02.fd) — SCM_RIGHTS Refcount Overflow

**Bug:** Receiving SCM_RIGHTS into undersized buffer leaks f_count, wrapping
u32 to achieve UAF. FreeBSD 12.0 bug.

**PS5 14.10 status: DEAD** — SCM_RIGHTS stripped in jail (recvmsg returns
controllen=0). Probe 56q section B.

### SA-26:71.sound — sound(4) mmap TOCTOU Race

**PS5 14.10 status: DEAD** — No /dev/dsp in device inventory.

### CVE-2026-49412 — IPV6_MSFILTER UAF

**PS5 14.10 status: DEAD** — Sony removed RFC 3678 multicast source filtering
API entirely. Probes 50e2/50e3.

### CVE-2026-45257 — KTLS Page-Cache Overwrite

**PS5 14.10 status: DEAD** — Sony did not include KTLS. Probe 50f.

### CVE-2019-15879 — cryptodev Race

**PS5 14.10 status: DEAD** — No /dev/crypto in device inventory.

### CVE-2026-98432 — TCP IPv4 Options UAF

**PS5 14.10 status: DEAD** — This is a Linux kernel bug, not FreeBSD.

## Race Testing Summary (Phase 34)

The shm ftruncate race vector was extensively tested (Nov 4-5, 2026):

| Test | Probes | Iterations | Result |
|------|--------|------------|--------|
| shm ftruncate + read | 1100a-1110a, 94a | ~10,000+ | 0 kernel pointers, 1 torn-read |
| sendfile + ftruncate | 1111a, 94b, 94d | ~1,000+ | Child died round 1, 0 leaks |
| read + ftruncate | 1114a | ~1,000 | 0 kernel pointers |
| mmap + munmap race | 98a, 98b | ~1,000 | 0 anomalies |
| poll + close | 93e2-93e3 | 100+ | POLLHUP (normal, not UAF) |
| kqueue + close | 93e4 | 100+ | 0 anomalies |
| close + dup2 | 93e5 | 100+ | 0 anomalies |
| /dev/gc ioctl + close | 96a | 100+ | 0 anomalies |
| dual child setsockopt | 93d0 | 100+ | 0 anomalies |
| camera child read | 93d9 | 100+ | 0 anomalies |

## What Remains

### Queued probes (console down, untested)
- **1402a**: Dual PKTINFO setsockopt with thr_new (more iterations than 91d)
- **1402b**: SO_SNDBUF TOCTOU (completely different code path from PKTINFO)
- **1403a**: PKTINFO race with spray for kernel pointer detection
- **1404a**: Full kernel R/W exploitation chain if race succeeds
- **1405a**: Master orchestrator running all 3 strategies

### Open questions
1. **SO_SNDBUF resize TOCTOU** — BSD socket layer, not IPv6. Child writes 4KB×30
   while second child shrinks/expands buffer. Never tested on PS5.
2. **Sony custom syscall races** — 11 accessible Sony syscalls. Custom code is
   less reviewed than upstream BSD. Potential targets: 643 (chicken switches),
   622 (device control), 601 (process control).
3. **WebKit → kernel bridge** — WebProcess is a different address space from the
   Lua loader. If WebKit exploit achieves code exec in WebProcess, it has a
   DIFFERENT set of available syscalls and capabilities.

## Conclusion

Every known FreeBSD kernel CVE that could provide kernel R/W is blocked on PS5
14.10 by one of four mechanisms:
1. Feature removal (UMTX SHM, 2292PKTOPTIONS, SCM_RIGHTS, KTLS, msfilter)
2. Missing prerequisites (fork, RACK, largepage SHM, /dev/crypto, /dev/dsp)
3. Zone isolation (poll/close UAF spray blocked)
4. Existing locks (PKTINFO setsockopt serialized by INP_WLOCK)

The kernel attack surface is narrower than any public FreeBSD. The remaining
path to kernel R/W requires either:
- A bug in Sony's CUSTOM kernel code (not upstream FreeBSD)
- A novel race in a code path that hasn't been tested
- A 0-day in the upstream FreeBSD code that no one has found yet

Sources:
- [FreeBSD-SA-20:20.ipv6 (CVE-2020-7457)](https://bsdsec.net/articles/freebsd-announce-freebsd-security-advisory-freebsd-sa-20-20-ipv6)
- [CVE-2020-7457 Metasploit module](https://vulners.com/metasploit/MSF:EXPLOIT-FREEBSD-LOCAL-IP6_SETPKTOPT_UAF_PRIV_ESC-)
- [FreeBSD-SA-20:20 patch](https://www.freebsd.org/security/patches/SA-20:20/ipv6.patch)
- [FreeBSD umtx privesc (CVE-2024-43102)](https://accessvector.net/2024/freebsd-umtx-privesc)
- [FreeBSD-SA-21:08.vm](https://www.freebsd.org/security/advisories/FreeBSD-SA-21:08.vm.asc)
- [FreeBSD-SA-26:43.tcp (CVE-2026-49422)](https://lists.freebsd.org/archives/freebsd-security/2026-June/000526.html)
- [SA-19:02.fd (CVE-2019-5596)](https://secfault-security.com/blog/FreeBSD-SA-1902.fd.html)
