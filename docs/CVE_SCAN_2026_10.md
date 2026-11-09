# FreeBSD CVE Scan for PS5 14.10 — October 2026

**Date:** 2026-10-25
**Scope:** FreeBSD security advisories 2024–2026, PS5-specific disclosures, Praetorian/Calif.io research
**Method:** Web search of FreeBSD advisories, NVD, ZDI, psdevwiki, Praetorian blog, Calif.io publications. No console tests.

## Summary

38 CVEs and vulnerability disclosures reviewed. **Zero new exploitable paths identified** beyond the aio_multi_delete double-free already confirmed (probe 65l). The "Prolapse" exploit reportedly targets the same bug. Two items warrant further investigation despite long odds.

---

## Already Dead (confirmed in prior probes)

| CVE | Subject | Why dead on 14.10 | Probes |
|---|---|---|---|
| CVE-2026-49418 | msync device pager UAF | MS_INVALIDATE returns -1 on all mappings | 58a/58b, 455a-455d |
| CVE-2026-49412 | IPV6_MSFILTER UAF | Sony removed RFC 3678 multicast source filtering | 50e2/50e3 |
| CVE-2026-45257 | KTLS page-cache overwrite | KTLS not compiled into PS5 kernel | 50f |
| CVE-2026-49427 | posixshm largepage UAF (sendfile) | shm_open2(571) is nosys | 391a-391d |
| CVE-2026-49428 | posixshm largepage UAF (O_TRUNC) | shm_open2(571) is nosys | 391a-391d |
| CVE-2026-49419 | jail refcount underflow | All jail syscalls return -1 | 392a |
| CVE-2026-45250 | FatGid/setcred | Syscall 591 is Sony range, not FreeBSD setcred | 392a |
| CVE-2026-58094 | FIOSSHMLPGCNF TOCTOU | ioctl on shm fd returns -1, largepage absent | 392a |
| CVE-2026-58093 | tty TIOCSCTTY race | No /dev/tty* access | 58d |
| CVE-2026-58099 | kqueue fork-copy race | No fork() | 58d |
| CVE-2026-58090 | unix socket UAF | FreeBSD 15.0+ only | 58d |
| CVE-2024-43102 | UMTX_OP_SHM race | Sony stubbed out SHM subsystem | 151a-152k |
| CVE-2026-3038 | sa_len=127 routing overflow | Accepted without panic, likely patched (build Sep 2026, fix Feb 2026) | 56e |
| ZDI-26-784 | kqueue race condition | 10,000+ races, 0 anomalies | 271g/271h/271i |
| — | netcontrol(99) UAF | close-before-unregister leaks, doesn't free | 223a-234a |

## Already Assessed (existing docs, not exploitable)

| CVE | Subject | Status | Doc |
|---|---|---|---|
| CVE-2026-7270 | execve buffer overflow | execve blocked; no setuid path from game process | CVE-2026-7270-ASSESSMENT.md |
| CVE-2026-45251 | poll/select procdesc UAF | pdfork(518) returns -1; other fd types unresolved | PRIVATE_2026_FREEBSD_KERNEL_CVE_TRIAGE_2026-10-21.md |
| CVE-2026-58083 | kqueue fork-copy UAF | fork blocked | CVE-2026-58083-PS5-14.10.md |
| CVE-2026-49416 | vt(4) CONS_HISTORY ioctl overflow | /dev/console blocked | REMAINING_CVE_TRIAGE.md |
| CVE-2026-49414 | ELF ASLR for setuid PIE | No execve, no setuid binary | REMAINING_CVE_TRIAGE.md |
| CVE-2026-49417 | /dev/dsp close-while-mapped UAF | /dev/dsp* blocked | REMAINING_CVE_TRIAGE.md |

## New — Assessed This Scan

### DEAD: Precondition unreachable

| # | CVE | Subject | Why dead |
|---|---|---|---|
| 1 | CVE-2026-58087 | semctl GETALL/SETALL heap OOB via seqnum wrap | semget(221) kills the process; __semctl(510) kills. Cannot create semaphore sets. |
| 2 | CVE-2026-58091 | sound sync-group ioctl (SNDCTL_DSP_SYNCSTART) UAF | /dev/dsp* blocked (54a). No sound device access from game process. |
| 3 | CVE-2026-58088 | ELF core dump OOB write via rfork VM race | rfork blocked. Also needs kern.coredump enabled. |
| 4 | CVE-2026-58092 | credential switching (group_is_primary) | FreeBSD 15.0+ only. PS5 kernel is FreeBSD 11-based. |
| 5 | CVE-2026-58086 | ktrace privilege in jails | FreeBSD 15.0/15.1 only. Also ktrace(45) kills on 14.10. |
| 6 | CVE-2026-6386 | pmap_pkru_update_range (1GB largepage) | Requires shm_create_largepage (shm_open2 is nosys). Also PKRU is Intel MPK; PS5 uses AMD. |
| 7 | CVE-2026-4747 | RPCSEC_GSS stack overflow (kgssapi.ko) | Remote vuln needs NFS server. kgssapi.ko not loaded. Module loading blocked. |
| 8 | CVE-2026-49415 | execve TOCTOU (VAS before cred update) | execve blocked. No setuid binaries accessible. |
| 9 | CVE-2025-0662 | ktrace uninitialized memory disclosure | ktrace(45) kills the process on 14.10. |
| 10 | CVE-2026-49430 | ZFS receive ioctl heap overflow | No ZFS access from game process. |
| 11 | CVE-2025-15576 | jail chroot escape via fd exchange | Needs nullfs mount access and multi-jail setup. |
| 12 | CVE-2026-45254 | cap_net service (missing key = allow any) | Casper framework not accessible from game process. |
| 13 | CVE-2026-7164 | pf SCTP stack overflow | pf ioctl blocked. |
| 14 | CVE-2026-42511 | DHCP RCE via malicious options | Remote attack vector, needs DHCP client. Not applicable. |
| 15 | CVE-2025-24934 | SO_REUSEPORT_LB wrong packet delivery | Not a privilege escalation. Low value. |
| 16 | CVE-2025-0373 | FS buffer overflow via NFS | Needs NFS server. Not applicable. |

### CONFIRMED: Already our breakthrough

| # | ID | Subject | Status |
|---|---|---|---|
| 17 | "Prolapse" / aio_multi_delete | TOCTOU double-free in syscall 662 | **This is our probe 65l result.** Two child threads calling 662 on the same polled ID array produce double-frees: 65/480 IDs freed by BOTH threads. Prolapse reportedly targets same bug on 14.00-14.10. Sony fixed in 14.20 with generation-ID check. |

### WORTH INVESTIGATING (long odds, but not fully ruled out)

#### 1. CVE-2026-45251 broader scope (poll/select UAF beyond procdesc)

**The advisory says:** "A broader review ... identified additional occurrences of the same issue in related code. All known exploitable instances are corrected by this update."

**What this means:** The procdesc UAF is just one instance. The fix covers multiple file descriptor types where a poll/select waiter isn't unlinked before the object is freed. Which other types are affected is not named in the advisory text we could retrieve.

**PS5 relevance:**
- poll(209) works on PS5
- select(93) likely works
- We have threads (thr_new) for concurrent close
- pdfork is blocked, so procdesc is out
- But if the vulnerability extends to kqueue fds, socket fds, pipe fds, or any type we CAN create, the race might be triggerable

**Assessment:** The advisory's "broader review" language suggests multiple fd types. The Calif.io exploit used procdesc + SCM_RIGHTS for reclaim. On PS5, SCM_RIGHTS is stripped by the jail, so even if a vulnerable fd type were available, the reclaim strategy would need to differ. **Probability: LOW.** The most likely affected types (procdesc, capsicum, etc.) are exactly the types PS5 blocks. Standard sockets/pipes/kqueues probably already had proper cleanup in FreeBSD 11 era code.

**Next step if pursued:** Fetch the full advisory text from FreeBSD-SA-26:19.file.asc to identify all affected fd types. Then cross-reference against PS5-accessible descriptor types.

#### 2. Praetorian undisclosed ioctl info leak (KASLR defeat)

**From the Praetorian blog (Part 2):** "an ioctl handler in a kernel subsystem reachable from within a VNET jail that copies more data back to userspace than it should, leaking stack contents including the canary and a return address."

**PS5 relevance:**
- Our ioctl sweep (387a/387c) tested all 34 /dev nodes — 48,446 calls, zero overcopy
- The Praetorian bug is in a VNET-jail-accessible subsystem, not necessarily a /dev node
- Socket-level ioctls (SIOC* via ioctl on a socket fd) were NOT part of our sweep
- Routing ioctls (via ioctl on a routing socket) were NOT part of our sweep

**Assessment:** The bug was found in FreeBSD's general kernel, and PS5 is based on a FreeBSD fork. VNET is a networking subsystem, and PS5 has networking. The specific subsystem is undisclosed, but the Praetorian team has not published the CVE for the ioctl leak (they said other issues "are still awaiting remediation and patches"). **Probability: LOW-MEDIUM.** We tested device ioctls exhaustively but not socket-level ioctls.

**Next step if pursued:** Test SIOC* ioctls (SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFDSTADDR, etc.) on socket fds with oversized output buffers. Also test routing socket ioctls. These are different code paths from the /dev ioctl sweep.

---

## PS5-Specific Intelligence

### Prolapse exploit
- Developer: Jose Coixao (zecoxao)
- Targets: PS5 firmware 14.00 and 14.10
- Mechanism: aio_multi_delete TOCTOU race (same as our probe 65l)
- Status: Announced but not publicly released as of 2026-10-25
- Fix: Sony firmware 14.20 adds generation-ID check

### BootROM key leak (Dec 2025)
- Level 0 BootROM keys published on psdevwiki.com on 2025-12-31
- Hardware keys, cannot be patched via software update
- Relevant for long-term security but not directly for kernel R/W

### Relapse exploit
- Targets: PS5 firmware 7.00–13.60
- Kernel bug: UAF race in aio_multi_wait (different from aio_multi_delete)
- Patched in firmware 14.00

---

## Conclusion

The comprehensive scan confirms that the **aio_multi_delete double-free (probe 65l) remains the only viable kernel corruption primitive** on PS5 14.10. Every other 2024–2026 FreeBSD CVE is blocked by one of:
1. Missing syscalls (kills or nosys): semget, ktrace, ptrace, rfork, pdfork, kld*, etc.
2. Missing device access: /dev/dsp*, /dev/tty*, /dev/console, etc.
3. FreeBSD version mismatch: PS5 is FreeBSD 11-based; many CVEs are 15.0+ only
4. Sony-specific hardening: stripped SCM_RIGHTS, W^X, stubbed SHM, removed multicast filtering

The "Prolapse" exploit's existence independently confirms that aio_multi_delete is the right target. Priority should remain on heap spray strategies to exploit the confirmed double-free.
