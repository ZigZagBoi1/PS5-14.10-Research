# PS5 Scene Research - October 2026

## Executive Summary

As of October 18, 2026, **no public kernel exploit exists for PS5 firmware 14.xx**. The latest exploitable firmware is **13.60**, served by the Relapse exploit chain (ntfargo) and the Byepervisor-Reborn hypervisor exploit (ChendoChap). Firmware 14.00 (Sep 16, 2026) and 14.10 (Oct 1, 2026) patch both bugs. However, several 2026 FreeBSD kernel CVEs look promising for 14.10 research.

---

## 1. Current PS5 Exploit Landscape

### Relapse (ntfargo) - Firmware 7.00-13.60
- **Published:** September 29, 2026 on GitHub
- **Author:** Nathan Fargo (ntfargo)
- **Chain:** WebKit JSC structured-clone object-pool mismatch -> kernel aio_multi_wait UAF race
- **Kernel bug:** A flaw in `aio_multi_wait` where new wait modes allow double-linking of AIO requests, causing a use-after-free. The UAF gives a controlled decrement at an arbitrary kernel address, used to corrupt a `pipe_buffer` descriptor for kernel R/W.
- **KASLR defeat:** Uses AF_ROUTE RTM_GET socket to leak kernel addresses (confirmed patched on 14.10 per our probe 42b)
- **Status:** Tethered (RAM-only, lost on reboot). Unreliable (~30% success rate on kernel stage). Can hang/panic.
- **Firmware 14.00+:** NOT supported. Sony patched the aio_multi_wait bug.
- **Sources:** https://github.com/ntfargo/Relapse-Exploit, https://gbhackers.com/sony-ps5-relapse-jailbreak-exploit-uses/

### Byepervisor-Reborn (ChendoChap) - Firmware 6.xx-13.60
- **Published:** October 12, 2026 on GitHub (PS5Dev org)
- **Author:** ChendoChap (implementation), TheFloW (original discovery), Jordy (independent discovery)
- **Bug:** S3 resume (rest mode wake) vulnerability. The `startup_mp` hypercall brings up CPU cores 1-15 under an insecure nested page table configuration. This lets an attacker with kernel execution remap hypervisor memory.
- **What it gives:** Hypervisor memory access, disables execute-only protection on kernel pages, enables kernel dump and patching.
- **Status:** Developer proof-of-concept only. No HEN, no FPKG loader, no patches included.
- **Firmware 14.00+:** Patched. The rest-mode resume path was hardened.
- **Sources:** https://wccftech.com/byepervisor-reborn-cracks-ps5-hypervisor-13-60-not-useful-regular-users-yet/, https://www.psdevwiki.com/ps5/Vulnerabilities

### PS5 BootROM Key Leak (Jan 2026)
- **Date:** December 31, 2025 / January 2026
- **What:** BootROM key hex strings leaked on Discord and psdevwiki
- **Impact:** Unpatchable via software. Would require hardware revision. But does NOT give an immediate jailbreak by itself - still needs a runtime exploit chain.
- **Current status:** No public exploit using these keys. One researcher claimed a FW 12.00 exploit using Star Wars: Racer Revenge (CUSA-03474) + keys, but no code released.
- **Sources:** https://www.notebookcheck.net/Sony-faces-an-unfixable-PS5-vulnerability-as-BootROM-keys-are-dumped-and-shared-publicly.1194911.0.html

---

## 2. Key Researcher Activity (2026)

| Researcher | Recent Activity |
|------------|----------------|
| **ntfargo** | Published Relapse (Sep 29, 2026). Active on GitHub. |
| **ChendoChap** | Published Byepervisor-Reborn (Oct 12, 2026). Active. |
| **TheFloW (Andy Nguyen)** | Demonstrated PS5 Slim running Linux + GTA V via Steam (Mar 6, 2026). Discovered the HV rest-mode bug used by Byepervisor-Reborn. No disclosure plans stated. |
| **Flat_z** | Has PSP (Platform Secure Processor) access. Decided not to disclose exploits or bugs. |
| **SpecterDev** | Last public PS5 work was Hardwear.io 2024 (HV exploits for FW <=2.50). No 2026 PS5 activity found. |
| **sleirsgoevy** | No 2026 PS5 work found. Active on PS4. |
| **Znullptr** | No 2026 PS5 work found. Active on PS4. |
| **EchoStretch** | No 2026 findings in search results. |

---

## 3. FreeBSD Kernel CVEs (2025-2026) - Potential PS5 Applicability

These are all LOCAL privilege escalation bugs in recent FreeBSD. The PS5 runs a modified FreeBSD kernel (r230171). The key question for each is whether the vulnerable code path exists in the PS5's fork.

### REQUIRES PS5-SPECIFIC EVIDENCE

**CVE-2026-58083 - kqueue fork-copy UAF**
- Published: August 19, 2026
- Bug: Use-after-free in kqueue's fork-copy routine, triggered by timer-based knotes
- Impact: Kernel use-after-free with potential privilege escalation (per the FreeBSD CVE description); no PS5 impact is established.
- Upstream affected scope: FreeBSD 15.1-RELEASE before `p2`; do not transpose this range to Sony's kernel.
- PS5 relevance: **UNKNOWN**. Probes 20 and 21 show kqueue and timer-filter operations, but do not exercise copy-on-fork. Probe 27 records `fork`, `rfork`, and `thr_new` returning -1. The PS5 version string `r230171/releases/14.10` does not identify the corresponding upstream source or patch state. See [the PS5 14.10 assessment](../CVE-2026-58083-PS5-14.10.md).

**CVE-2026-49412 - IPV6_MSFILTER UAF**
- Bug: Lock released during copyin in IPv6 multicast source filter setsockopt
- Impact: Use-after-free, potential kernel R/W
- PS5 relevance: **HIGH** - PS5 has IPv6 support (confirmed by our probes). setsockopt is accessible via make_syscall. The lock-drop-during-copyin pattern is a classic exploitable primitive.
- Affected: FreeBSD 14.3, 14.4, 15.0
- Note: One source says no vendor fix was available as of late June 2026

**CVE-2026-7270 - execve operator precedence overflow**
- Published: April 30, 2026
- Bug: Operator-precedence bug causes buffer overflow in execve argument handling
- Impact: High severity, low attack complexity
- PS5 relevance: **UNCONFIRMED** - upstream FreeBSD facts are verified, but this repository has no authenticated 14.10 kernel code artifact proving the vulnerable expression, syscall reachability, or execution order relative to sandbox enforcement. See [the CVE-2026-7270 assessment](../CVE-2026-7270-ASSESSMENT.md).

### MEDIUM PRIORITY

**CVE-2026-45258 - /dev/dsp mmap integer overflow**
- Bug: Integer overflow in sound device mmap lets crafted offset/length bypass size check
- Impact: Kernel memory R/W from any local user
- PS5 relevance: **MEDIUM** - PS5 has audio hardware but /dev/dsp may not be accessible from the sandbox. Worth testing if the device node exists.

**CVE-2026-49417 - /dev/dsp close-while-mapped UAF**
- Bug: UAF when sound device closed while buffer mapping remains
- PS5 relevance: **MEDIUM** - Same access question as above.

**CVE-2026-49419 - jail refcount underflow**
- Bug: Reference-count underflow in jail set/get paths frees in-use prison structure
- PS5 relevance: **UNRESOLVED, trigger surface unmeasured** - no probe or capture ever issues 338/429/496/497, and in the 13.60 dumps 338/496/497 sit at the nosys slot (only 429 has a body). The "may use jails" hypothesis has no call behind it. See the [evidence assessment](../CVE-2026-49419-PS5-14.10.md); reachability probe `57e_jail_reachability` is prepared, not run.

**CVE-2026-45257 - KTLS receive page cache overwrite**
- Bug: sendfile over loopback with KTLS overwrites page cache
- PS5 relevance: **LOW-MEDIUM** - Requires KTLS and loopback sendfile. Complex setup.

### LOWER PRIORITY

**CVE-2026-49416 - vt(4) CONS_HISTORY ioctl overflow**
- PS5 relevance: **LOW** - console driver ioctl, unlikely accessible from sandbox.

**CVE-2026-49414 - ELF ASLR disable for setuid PIE**
- PS5 relevance: **LOW** - Information leak, not direct escalation.

---

## 4. Implications for Firmware 14.10 Research

### What's Patched on 14.10
1. **AF_ROUTE RTM_GET KASLR leak** (Relapse technique) - confirmed dead by our probe 42b
2. **aio_multi_wait UAF** (Relapse kernel bug) - patched in 14.00
3. **Byepervisor rest-mode HV bug** - patched in 14.00/14.10
4. **AIO generally** - sandbox-killed at kernel level (may be separate from the UAF patch)

### What Might Still Work
1. **IPV6_MSFILTER setsockopt UAF (CVE-2026-49412)** - PS5 applicability is unresolved: option 74 was never issued, no multicast group was joined, and no second thread is available through any tested path; see the [evidence assessment](../CVE-2026-49412-PS5-14.10.md). Reachability probe `50e_ipv6_msfilter_reach` is prepared, not run.
2. **kqueue timer knote UAF (CVE-2026-58083)** - applicability is unknown. Timer filters work in a saved run, but the required copy-on-fork path is not demonstrated; see the [evidence assessment](../CVE-2026-58083-PS5-14.10.md).
3. **execve argument overflow (CVE-2026-7270)** - PS5 applicability is unconfirmed; see the source and evidence assessment. Do not treat pre-sandbox reachability as established.
4. **Sound device bugs (CVE-2026-45258, CVE-2026-49417)** - If /dev/dsp or equivalent is accessible.

### Recommended Next Probes

**Probe A: IPV6_MSFILTER setsockopt (CVE-2026-49412)**
- Create an IPv6 socket
- Call setsockopt with IPV6_MSFILTER
- Craft arguments to trigger the lock-drop-during-copyin window
- Reachability first: probe `50e_ipv6_msfilter_reach` (prepared, not run) issues option 74 and maps the handler's early checks; the race itself requires a second thread no tested path provides.

**Probe B: kqueue timer knotes (CVE-2026-58083)**
- Create a kqueue (already confirmed working for fd allocation)
- Register timer-based knotes via kevent
- Test if the knote timer path triggers the UAF without needing fork

**Probe C: execve argument parsing (CVE-2026-7270)**
- Status: superseded by the non-triggering source and evidence assessment in [CVE-2026-7270-ASSESSMENT.md](../CVE-2026-7270-ASSESSMENT.md).
- Do not run an oversized-argument trigger against the console as part of this probe plan. The repository lacks the authenticated 14.10 kernel code needed to establish applicability, and a runtime trigger would be a kernel privilege-escalation attempt.

**Probe D: Sound device access**
- Try to open /dev/dsp via make_syscall (open = syscall 5)
- If accessible, test mmap with crafted offset (CVE-2026-45258)

**Probe E: jail syscall access**
- Test jail_get/jail_set via make_syscall
- If accessible, attempt refcount underflow (CVE-2026-49419)

---

## 5. Sources

### Relapse Exploit
- [Relapse GitHub](https://github.com/ntfargo/Relapse-Exploit)
- [GBHackers - JSC Memory Corruption and Kernel UAF](https://gbhackers.com/sony-ps5-relapse-jailbreak-exploit-uses/)
- [Cyberpress - WebKit and Kernel Exploit](https://cyberpress.org/ps5-relapse-jailbreak-uses-webkit-and-kernel-exploit/)
- [Kotaku - PS5 Jailbreak July 2026 Firmware](https://kotaku.com/new-ps5-jailbreak-exploit-works-on-systems-running-july-2026-firmware-2000738283)
- [Kod.ru - Technical details (Russian)](https://kod.ru/playstation-5-relapse-exploit-jailbreak)

### Byepervisor-Reborn
- [WCCFTech - Hypervisor Exploit](https://wccftech.com/byepervisor-reborn-cracks-ps5-hypervisor-13-60-not-useful-regular-users-yet/)
- [OneJailbreak - Byepervisor-Reborn](https://onejailbreak.com/blog/byepervisor-reborn-ps5-hypervisor-exploit-up-to-13-60/)
- [PS5 Developer Wiki - Vulnerabilities](https://www.psdevwiki.com/ps5/Vulnerabilities)
- [TwistedVoxel - HV Exploit FW 13.60](https://twistedvoxel.com/ps5-hypervisor-exploit-now-available-for-firmware-13-60/)

### BootROM Leak
- [Notebookcheck - BootROM Keys](https://www.notebookcheck.net/Sony-faces-an-unfixable-PS5-vulnerability-as-BootROM-keys-are-dumped-and-shared-publicly.1194911.0.html)
- [RedHotCyber - BootROM Key Leaked](https://www.redhotcyber.com/en/post/ps5-bootrom-key-leaked-sonys-security-compromised)

### FreeBSD CVEs
- [CVE-2026-58083 - kqueue UAF](https://www.sentinelone.com/vulnerability-database/cve-2026-58083/)
- [CVE-2026-49412 - IPV6_MSFILTER UAF](https://app.opencve.io/cve/CVE-2026-49412)
- [CVE-2026-7270 - execve overflow](https://stack.watch/vuln/CVE-2026-7270/)
- [CVE-2026-45258 - /dev/dsp mmap overflow](https://www.sentinelone.com/vulnerability-database/cve-2026-45258/)
- [CVE-2026-49419 - jail refcount underflow](https://www.sentinelone.com/vulnerability-database/cve-2026-49419/)

### General Scene
- [PushSquare - PS5 Jailbreaks Escalating](https://www.pushsquare.com/news/2026/10/ps5-jailbreaks-are-escalating-at-an-unprecedented-pace-and-sony-must-be-sweating)
- [VideoCardz - PS5 13.60 Jailbreak](https://videocardz.com/newz/ps5-13-60-jailbreak-released-almost-every-ps5-can-now-be-jailbroken)
- [Wololo - SpecterDev Defeats Hypervisor](https://wololo.net/2024/09/30/ps5-specterdev-defeats-the-hypervisor/)
