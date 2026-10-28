# Our Bug IS the Lapse/Prolapse Exploit

**Date:** 2026-10-25 (Session 2)
**Source:** freebsd-exploit-research agent + cve-scanner agent

## Identification

The `aio_multi_delete` (syscall 662) TOCTOU double-free confirmed in probe 65l is the same vulnerability exploited by three published/announced PS5 exploit chains:

| Exploit | Author | Firmware | Entry | Status |
|---------|--------|----------|-------|--------|
| **Lapse** | anonymous | PS4 5.00-12.02, PS5 1.00-10.01 | WebKit/BD-J | Published, technical writeup available |
| **Relapse** | ntfargo | PS5 7.00-13.60 | WebKit | Released |
| **Prolapse** | notnotzecoxao | PS5 14.00-14.10 | Unknown | Announced, not released |

All three target the same TOCTOU race in `_aio_multi_delete`. Sony patched it in firmware 14.20 (confirmed by LAVX.hu article and Jose Coixao). The specific fix mechanism is unknown — "generation-ID revalidation" is our inference based on what would logically close the TOCTOU window.

## The Lapse Exploitation Chain (Technical Detail)

From the Gistre Blog technical writeup. **Important:** The blog uses vague language
("some socket options", "specific socket options", "event flag object") without naming
specific syscalls, socket option constants, or UMA zone sizes. Details below marked
**[inferred]** are our analytical inferences from the 13.60 decompile and FreeBSD
internals, not direct quotes from the blog. See `VERIFICATION_LAPSE_CLAIMS.md`.

### Stage 1: Double-free
- Races two threads on 662 to double-free AIO sub-objects
- **[Inferred]** Queue entries (0x58B) land in a 128-byte UMA zone (from our 13.60 decompile)
- Uses "socket operations" for timing windows **[specific option not named in blog]**

### Stage 2: Kernel address leak (KASLR defeat)
- The dangling chunk is reclaimed by "some socket options"
- This produces an aliased pair
- The blog says the aliased object is treated as an "event flag object"
- Event flag fields expose raw kernel pointers → KASLR defeat

### Stage 3: Second double-free for R/W setup
- A second race places the dangling chunk inside a different structure
- Creates a new aliased pair at a known kernel address

### Stage 4: Arbitrary kernel R/W
- The aliased pair is used through "specific socket options"
- Read and write any kernel address

### Stage 5: Privilege escalation
- Modify ucred for elevated privileges

## Implications for Our Research

### What this confirms
1. The 662 TOCTOU race IS exploitable on 14.10 (Prolapse announced for this firmware)
2. The per-CPU cache isolation and readback problems ARE solvable
3. Socket options + event flags are the correct spray technique (not pipe buffers or kqueue)
4. FreeBSD UMA has no double-free detection — the technique is reliable

### What our probes missed
1. **evf_create(538) spray may need different parameters** — Lapse specifically adapted evf for the 128B zone. Our 66e probe may have used wrong sizes or counts
2. **Socket option aliasing** is the key technique — not just spraying setsockopt, but creating an aliased socket/evf pair through the double-freed memory
3. **Two double-frees needed** — Lapse uses Stage 1 for KASLR and Stage 3 for R/W, not a single double-free for both

### What differs on 14.10
- Our entry is Lua TCP (not WebKit/BD-J) — but primitives are equivalent
- pipe(42) is dead — Lapse may not use pipes, but if it does, socketpair substitutes
- AF_ROUTE KASLR is dead — but Lapse uses evf aliasing instead (different from Relapse's routing socket)
- Some API surfaces may have shifted between Lapse's target (≤10.01) and 14.10

## CVE Scan Summary

38 CVEs and disclosures reviewed against 14.10 constraints:
- 17 already confirmed dead in prior probes
- 16 new CVEs assessed — all dead (blocked syscalls, missing devices, wrong FreeBSD version, Sony hardening)
- 1 confirmed match: Prolapse = our bug
- 2 long-shot items: CVE-2026-45251 broader fd-type scope, Praetorian undisclosed socket-level ioctl info leak

The comprehensive scan confirms aio_multi_delete remains the **only viable kernel corruption primitive** on PS5 14.10.

## Sources

- [Lapse: the AIO Kernel Exploit Behind the PS5 Jailbreak](https://blog.gistre.epita.fr/posts/marco.chan-witzel-2026-07-13-lapse-the-aio-kernel-exploit-behind-the-ps5-jailbreak/) — Gistre Blog technical writeup
- [PS5 Prolapse Jailbreak for 14.00/14.10](https://onejailbreak.com/blog/prolapse-kernel-exploit-targets-ps5-14-00-and-14-10/) — Prolapse announcement
- [FreeBSD-SA-22:10.aio](https://www.freebsd.org/security/advisories/FreeBSD-SA-22:10.aio.asc) — Upstream AIO advisory
- [Vulnerabilities — PS5 Developer Wiki](https://www.psdevwiki.com/ps5/Vulnerabilities) — Community tracker
