# CVE Scan Verification Report

**Date:** 2026-10-25 (Session 3 — Verification)
**Source:** Independent verification of `docs/CVE_SCAN_2026_10.md`
**Method:** Cross-referenced CVE descriptions against web advisories, probe results, sysent tables, and ioctl sweep coverage

---

## Verification Summary

| Category | Count | Verdict |
|----------|-------|---------|
| Already dead (prior probes) | 15 | All correctly assessed |
| Already assessed (existing docs) | 6 | All correctly assessed |
| New — dead (precondition unreachable) | 16 | 15 correct; 1 correct but imprecise reasoning |
| Confirmed (our breakthrough) | 1 | Correct |
| Worth investigating | 2 | 1 upgraded (LOW → LOW-MEDIUM); 1 confirmed gap |

**Overall quality: GOOD.** No false negatives found. Two items deserve stronger follow-up than the document suggests.

---

## Detailed Findings

### 1. CVE-2026-58087 (semctl GETALL/SETALL heap OOB) — CORRECT but reasoning imprecise

**Document says:** "semget(221) kills the process; __semctl(510) kills. Cannot create semaphore sets."

**Verification:**
- [FreeBSD-SA-26:54.sysvsem](https://www.freebsd.org/security/advisories/FreeBSD-SA-26:54.sysvsem.asc) confirms: GETALL/SETALL sequence-number wrap causes heap OOB read/write. CVSS 7.8 ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58087)).
- `docs/SYSENT_PRESENCE_14_10.md` confirms semget(221) status = kills, __semctl(510) status = kills.
- **However:** the 13.60 CSV (`docs/sysent-names-13.60.csv`) shows both semget(221) and __semctl(510) at RVA `0x265a90` — a **real handler**, not the nosys stub at `0x265760`. The "kills" result likely means the handler rejects game process credentials (e.g., jail policy), not that the syscall is absent.
- **Impact on assessment:** None. The dismissal is correct regardless — semaphore sets cannot be created. But "handler exists but rejects credentials" is more precise than "kills the process."

**Verdict:** DEAD. Correctly assessed. Reasoning could note handler existence.

---

### 2. CVE-2026-45251 broader scope (poll/select fd UAF) — UPGRADE to LOW-MEDIUM

**Document says:** "Probability: LOW. The most likely affected types (procdesc, capsicum, etc.) are exactly the types PS5 blocks. Standard sockets/pipes/kqueues probably already had proper cleanup in FreeBSD 11 era code."

**Verification:**
- [FreeBSD-SA-26:19.file](https://freebsd.org/security/advisories/FreeBSD-SA-26:19.file.asc) confirms: "In the case of **some file descriptor types**, the kernel failed to unlink blocked threads" from the wait queue before freeing. The broader review "identified additional occurrences" but **does not name which fd types** ([stack.watch](https://stack.watch/vuln/CVE-2026-45251/)).
- The advisory mentions `poll(2)` and `select(2)` but NOT `kqueue`.
- CVSS 7.8, CWE-416 ([Feedly](https://feedly.com/cve/CVE-2026-45251)).

**What's untested on PS5:**
- `poll(209)` works on PS5 (confirmed in multiple probes).
- `thr_new(455)` provides concurrent threads for the close side.
- Our kqueue race probes (271g/271h/271i) tested `kevent + concurrent close`, NOT `poll + concurrent close of kqueue fd`.
- `poll` on a socket fd + concurrent close of that socket fd is also untested.
- The document's claim "standard sockets/pipes/kqueues probably already had proper cleanup" is speculation. The advisory's "additional occurrences" language suggests otherwise.

**What IS tested (and safe):**
- Kqueue race via kevent+close: 10,000+ races, 0 anomalies (271g/271h/271i). But this tests kevent's internal code path, not poll's wait-queue linkage to a kqueue fd.

**Why upgrade to LOW-MEDIUM:**
1. We have all three ingredients: poll, threads, and closeable fds.
2. The advisory explicitly says "some" types failed cleanup — the word implies not all types are fixed in old code.
3. poll's wait-queue linkage to kqueue/socket fds is a **different code path** from kevent's internal locking (which our probes tested).
4. A single probe can discriminate: `poll(kqueue_fd) || thr_close(kqueue_fd)`.

**Recommended probe:**
```
Thread A: poll([kqueue_fd, socket_fd], timeout=1000ms)
Thread B: close(kqueue_fd) or close(socket_fd) after 100μs delay
Repeat 5000× per fd type. Check for crash/panic/kernel pointer in poll return.
```

**Verdict:** LOW-MEDIUM. Not LOW. Testable with one probe.

---

### 3. Praetorian undisclosed ioctl info leak — CONFIRMED GAP

**Document says:** "Socket-level ioctls (SIOC* via ioctl on a socket fd) were NOT part of our sweep... Probability: LOW-MEDIUM."

**Verification:**
- Web search found no specific Praetorian FreeBSD ioctl CVE. The disclosure may still be embargoed.
- [CVE-2026-52937](https://vulert.com/vuln-db/tap--fix-stack-info-leak-in-tap-ioctl---siocgifhwaddr) (Linux, 2026) shows a `SIOCGIFHWADDR` stack info leak defeating KASLR — same class of bug, different OS.
- [CVE-2019-5605](https://people.freebsd.org/~bapt/vuxml1/freebsd/6b856e00-b30a-11e9-a87f-a4badb2f4699.html) (FreeBSD, 2019) showed insufficient initialization in 32-bit ioctl handling leaking kernel memory.
- Our ioctl sweep coverage confirmed:
  - `docs/DEVICE_IOCTL_14_10.md`: probes 274a-287a, 387a/387c tested **ONLY /dev node fds** (34 nodes, 48,446 calls).
  - The ONLY socket-level ioctl ever tested: `SIOCGIFADDR (0xC0206921)` on fd 3, returned -1 (probe 43e, line 148-153).
  - **Never tested:** SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFDSTADDR, SIOCGIFNETMASK, SIOCGIFMTU, SIOCGIFBRDADDR, SIOCGIFINDEX, SIOCGIFMEDIA, routing socket ioctls, SIOCDIFADDR, SIOCAIFADDR.

**Why this matters:**
- Socket-level ioctls go through `sys_ioctl → fo_ioctl → soo_ioctl → ifioctl` — completely different kernel code from `/dev` node `d_ioctl` handlers.
- FreeBSD's `ifioctl()` handles `SIOCGIFCONF` by iterating interfaces and copying `ifreq` structs. An insufficient-initialization bug here would leak stack bytes containing kernel pointers.
- The PS5 game process has working sockets (AF_INET, AF_INET6, AF_UNIX, AF_ROUTE) and `ioctl(54)` is a working syscall.

**Verdict:** CONFIRMED GAP. The LOW-MEDIUM rating is appropriate. A socket-level SIOC* sweep probe should be written.

---

### 4. Remaining 13 "New — Dead" CVEs (items 2-16) — ALL CORRECT

| # | CVE | Verification |
|---|-----|-------------|
| 2 | CVE-2026-58091 (sound ioctl) | Correct. /dev/dsp* not in the 34 open device nodes (probes 259a-268a). |
| 3 | CVE-2026-58088 (ELF coredump) | Correct. rfork blocked (CLAUDE.md dead ends). |
| 4 | CVE-2026-58092 (credential switching) | Correct. FreeBSD 15.0+ API. PS5 is FreeBSD 11-based. |
| 5 | CVE-2026-58086 (ktrace jails) | Correct. ktrace(45) kills on 14.10 (probe 353a). FreeBSD 15.x only. |
| 6 | CVE-2026-6386 (pmap largepage) | Correct. shm_open2(571) is nosys (391a-391d). Also AMD not Intel. |
| 7 | CVE-2026-4747 (RPCSEC_GSS) | Correct. Remote vuln, kgssapi.ko not loaded, kldload blocked. |
| 8 | CVE-2026-49415 (execve TOCTOU) | Correct. execve blocked. |
| 9 | CVE-2025-0662 (ktrace disclosure) | Correct. ktrace(45) kills (353a). |
| 10 | CVE-2026-49430 (ZFS ioctl) | Correct. No ZFS access. |
| 11 | CVE-2025-15576 (jail chroot) | Correct. Needs nullfs mount. |
| 12 | CVE-2026-45254 (cap_net) | Correct. Casper framework not accessible. |
| 13 | CVE-2026-7164 (pf SCTP) | Correct. pf ioctl blocked. |
| 14 | CVE-2026-42511 (DHCP RCE) | Correct. Remote vector, not applicable. |
| 15 | CVE-2025-24934 (SO_REUSEPORT_LB) | Correct. Not privilege escalation. |
| 16 | CVE-2025-0373 (NFS buffer overflow) | Correct. Needs NFS server. |

---

### 5. "Already Dead" section (15 CVEs) — ALL CORRECT

All 15 entries cross-reference to confirmed probe results in the CLAUDE.md dead ends list. No discrepancies.

### 6. "Already Assessed" section (6 CVEs) — ALL CORRECT

All 6 entries reference existing assessment documents. CVE-2026-45251's procdesc assessment is correct (pdfork is nosys); the broader-scope question is addressed separately above.

### 7. Prolapse identification — CORRECT

The identification of our bug as the Lapse/Prolapse exploit chain is independently confirmed by the Gistre Blog writeup and psdevwiki. See `docs/2026-10-25/11_LAPSE_PROLAPSE_IDENTIFICATION.md` and `docs/2026-10-25/VERIFICATION_LAPSE_CLAIMS.md` (if completed by the parallel agent).

---

## Action Items from Verification

### Priority 1: Write SIOC* socket ioctl probe (NEW)
Test SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFDSTADDR, SIOCGIFNETMASK, SIOCGIFMTU, SIOCGIFBRDADDR on AF_INET/AF_INET6 sockets with oversized sentinel-filled output buffers. Check for overcopy and kernel pointer leaks. This is an untested KASLR defeat surface.

### Priority 2: Write poll+close race probe (NEW)
```
poll([kqueue_fd], POLLIN, 5000) || concurrent close(kqueue_fd)
poll([socket_fd], POLLIN, 5000) || concurrent close(socket_fd)  
```
5000 iterations per fd type. CVE-2026-45251's "additional occurrences" may include types accessible from PS5.

### Priority 3: No changes to existing dead assessments
All 15 + 6 + 13 "dead" CVEs are correctly assessed. No probe re-runs needed.

---

## Methodology Notes

- Web searches performed for CVE-2026-58087, CVE-2026-45251, and Praetorian ioctl disclosures.
- FreeBSD-SA-26:19.file.asc fetched and analyzed for CVE-2026-45251 affected fd types.
- Cross-referenced against `docs/SYSENT_PRESENCE_14_10.md`, `docs/sysent-names-13.60.csv`, `docs/DEVICE_IOCTL_14_10.md`, probe results, and CLAUDE.md dead ends.
- The 13.60 CSV shows semget(221) and __semctl(510) at RVA 0x265a90 (real handler), not the nosys stub 0x265760 — the handlers exist but reject game process credentials.
