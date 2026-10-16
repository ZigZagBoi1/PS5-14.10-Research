# Untested Theories — PS5 14.10

Potential exploit paths identified from analyzing existing probe data. Cross-referenced against all probe results to avoid duplicating tested paths.

---

## Theory 1: `kern.proc.pid` Full Dump Contains Kernel Pointers

**Priority: HIGHEST**

Probe 42a confirmed `sysctl kern.proc.pid` works via `make_syscall()` and returns 1,096 bytes of `kinfo_proc`. However, the dump only sampled every 8th qword — most of the structure was never printed.

In FreeBSD, `struct kinfo_proc` (1,096 bytes) contains multiple kernel pointers:

- `ki_paddr` — pointer to `struct proc` in kernel memory
- `ki_addr` — pointer to `struct user`
- `ki_tracep` / `ki_textvp` — kernel vnode pointers
- `ki_fd` — pointer to the filedesc table
- `ki_vmspace` — pointer to the process vmspace

The probe found `0xFFFFFFFF00000000` at offset +0x060, but this is likely a bitmask/flag field (e.g. `ki_flag`), not a real kernel pointer. The real kernel pointers (`ki_paddr`, `ki_addr`, etc.) sit at other offsets that were skipped by the every-8th-qword sampling.

**What was already tested:** Probe 42a dumped kern.proc.pid but only printed every 8th qword (8 out of ~137 qwords). The full 1,096 bytes were never examined.

**Test:** Write a probe that dumps ALL 1,096 bytes of `kern.proc.pid`, scanning for values matching `0xFFFFxxxx_xxxxxxxx` (kernel VA range). If kernel pointers leak, combine with the ROP chain hijack to call sysctl with crafted MIBs targeting known offsets from those pointers → kernel R/W.

**Why it could work:** The sysctl sandbox filter appears to be in `syscall.resolve()`, not the kernel itself (proven by 41w). `kern.proc.pid` is a standard FreeBSD sysctl that copies out the full kinfo_proc, and Sony may not have scrubbed kernel pointers from it since sysctl was "blocked."

---

## Theory 2: `kern.proc.vmmap` Needs a Larger Buffer

**Priority: HIGH**

Probe 42a tried `kern.proc.vmmap` with a 16,384-byte buffer and got rv=-1. In FreeBSD, the vmmap sysctl typically needs 100KB+ because it dumps every VMA entry. The failure may be ENOMEM (buffer too small), not EPERM (blocked).

**Test:** Retry with progressively larger buffers (64KB, 128KB, 256KB) and the exact MIB `{CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid}`. If it works, it dumps every VMA with kernel addresses — full memory map with kernel pointers for every mapping.

---

## Theory 3: IPv6 RTHDR Uninitialized Memory Leak

**Priority: LOW (mostly tested)**

Probe 09 shows `setsockopt(IPV6_RTHDR)` accepts buffers up to 8,184 bytes, but readback is always 0. Probe 09 also tested:
- 200 alloc/free churn rounds on same socket → no leak
- 32 multi-socket PKTINFO alloc → no cross-socket leaks
- Close upper half, read lower half → no UAF signs
- PKTOPTIONS after churn → 8,192 bytes all zero

**What remains untested:** Reading `IPV6_PKTOPTIONS` on a **connected** IPv6 socket (probe 09 only tested unconnected). The connected-socket path assembles options differently in FreeBSD and might copy from the routing header allocation's uninitialized tail. Long shot given how thoroughly probe 09 got zeros.

---

## Theory 4: Re-test "Blocked" Syscalls via `make_syscall()`

**Priority: HIGHEST (tied with Theory 1)**

Probe 41w proved sysctl works through `make_syscall()` while `syscall.resolve()` reports it blocked. The sandbox filter may live in the resolve path, not the kernel. If true, every "blocked" verdict needs re-testing through raw syscall numbers.

**Already tested via make_syscall (dead):**
| Syscall | Number | Result |
|---------|--------|--------|
| `pipe` | 42 | Probe 41o called `make_syscall(42)` — returned fds 0,0 (failed). **Dead.** |
| `sysctl` | 202 | Probe 41w/42a confirmed WORKING via make_syscall. Already exploited for kern.proc.pid. |

**Never tested via make_syscall (need probes):**
| Syscall | Number | Impact if unblocked |
|---------|--------|---------------------|
| `ioctl` | 54 | Device access, massive kernel attack surface |
| `dup` / `dup2` | 41 / 90 | fd table manipulation, possible double-close races |
| `fstat` | 189 | Kernel pointer leak from stat buffer (st_dev, st_ino on some BSDs) |
| `thr_new` | 455 | **Reopens the entire race condition bug class** — TOCTOU, UAF-via-race, refcount races all become possible |
| `pipe2` | 542 | Different syscall number than pipe(42), might have different sandbox handling |

**Test:** For each, call `make_syscall(N)` with proper arguments instead of using `syscall.resolve()`. Probe 27 tested all of these via `syscall.resolve()` only — the same path that falsely reported sysctl as blocked. Even one working (especially `thr_new`) changes the exploit landscape dramatically.

---

## Theory 5: ktimer Signal Delivery as Kernel Corruption Vector

**Priority: MEDIUM-LOW**

Probe 42a confirmed ktimer_create (clocks 0+4), ktimer_settime, and ktimer_getoverrun work. Timers are live kernel objects with signal delivery callbacks.

**Test:** Create a timer with `SIGEV_SIGNAL` delivering a signal (e.g., SIGUSR1) to a handler that itself manipulates timer state (arms another timer, or calls ktimer_settime on the firing timer). Since there's no threading, the signal handler runs in the context of whatever syscall was interrupted — this is a form of reentrancy.

If the kernel's timer expiry path and the settime path share state without proper locking (common in older FreeBSD), overlapping a timer fire with a settime from the signal handler could corrupt the timer's `callout` structure.

Cap of 27 timers means we can create many timers firing near-simultaneously to increase collision probability.

---

## Theory 6: TCP Input-Side Attacks via Connect-Back

**Priority: HIGH**

Probe 40 confirmed TCP connect-back works with the fake-IP ARP responder technique. 26 malformed segments were delivered without crash. The variant space is barely explored.

**Untested attack classes:**
- **TCP SACK processing** — CVE-2019-11477 "SACK Panic" class: send SACK blocks that force the kernel to fragment skbufs into tiny pieces, overflowing a 16-bit length field. FreeBSD r230171 may predate this fix.
- **TCP urgent pointer + OOB** — the urgent data state machine in `tcp_input()` is notoriously complex; send URG with urgptr past window edge, or URG on a FIN'd connection.
- **TCP MD5/AO option processing** — option kinds 19 (MD5) and 29 (TCP-AO) hit authentication code paths that allocate and compare. Malformed lengths or unexpected presence on non-MD5 connections may hit unchecked paths.
- **PAWS (Protection Against Wrapped Sequences)** — send timestamps that wrap the 32-bit counter; PAWS validation in older FreeBSD has had edge cases.
- **TCP simultaneous open** — both sides send SYN simultaneously; the state machine path is rarely tested.
- **RST with data in TIME_WAIT** — probe 40 sent RST+data but the connection may not have been in TIME_WAIT. Need to sequence: FIN→FIN-ACK→TIME_WAIT→RST+data.

**Test:** Expand `run_session40.py` / `tcp_fuzz_server.py` with these specific variant classes. Each malformed segment that crashes the console = kernel bug found.

---

## Theory 7: IP Options from Real Network (Bypass Output Validation)

**Priority: MEDIUM**

Probe 37 confirmed that malformed IP option lengths are rejected at `ip_output()` before reaching `ip_dooptions()` on loopback. But input-side processing (`ip_dooptions()` called from `ip_input()`) doesn't have this same pre-validation — it processes whatever arrives on the wire.

**Test:** PC sends crafted packets with malformed IP options directly to the PS5's LAN IP (10.0.0.96) using scapy. PS5-side probe just listens. Malformed option lengths (len=0, len=255, truncated options, nested LSRR) reach the input parser without output-path sanitization.

---

## Theory 8: Fragment Reassembly Queue Exhaustion

**Priority: MEDIUM**

Probe 39 confirmed `ip_reass()` handles all 7 standard fragment cases correctly. But deeper attack classes were not tested:

- **Queue exhaustion:** send 64+ distinct fragment trains (different IP IDs) without completing any. FreeBSD's `maxfragsperpacket` and `maxfrags` sysctl limits may be reachable.
- **Timeout interaction:** start reassembly, wait near the 30s timeout, send the final fragment just as the timer fires — race between reassembly completion and timeout cleanup.
- **Zero-length final fragment:** MF=0 with offset but zero payload length — edge case in reassembly termination.
- **Overlapping fragment chains with different protocols:** send fragments with proto=UDP and overlapping fragments with proto=TCP using the same IP ID — confuses protocol demux after reassembly.

**Test:** Requires either loopback RAW injection (now that bind works on port 31338) or PC-side scapy. Focus on queue exhaustion first — it's the most likely to hit an integer overflow or list corruption.

---

## Theory 9: `fstat` via `make_syscall()` for Kernel Pointer Leak

**Priority: MEDIUM**

If `fstat` (syscall 189) works through `make_syscall()` (see Theory 4), the returned `struct stat` on some FreeBSD versions contains device identifiers that encode kernel pointers or can be used to derive kernel object locations.

More importantly, `fstat` on a socket fd returns `st_ino` which in FreeBSD is derived from the socket's kernel address — this is a direct kernel pointer leak on older kernels.

**Test:** `make_syscall(189)` with a socket fd and a userland buffer. Dump the full stat structure and check `st_ino` and `st_dev` for kernel-range values.

---

## Cross-Reference: Combined Attack Chains

### Chain A: kinfo_proc → kernel R/W (Theories 1 + existing primitives)
1. Dump `kern.proc.pid` → extract `ki_paddr` (struct proc pointer)
2. Use ROP chain hijack to call sysctl with MIB targeting `kern.proc.filedesc` or read from known proc offsets
3. Walk kernel structures from proc → ucred → cr_uid = 0 (root)
4. Or: proc → p_fd → fd_ofiles → struct file → f_data → socket kernel object → arbitrary kernel R/W

### Chain B: fstat via make_syscall → kernel address leak (Theories 4+9)
1. Confirm `fstat(189)` works via make_syscall on a socket fd
2. On older FreeBSD, `st_ino` for sockets encodes the kernel socket address
3. Combine with kinfo_proc pointers to locate kernel structures
4. Use ROP chain hijack to read/write at known kernel offsets

### Chain C: thr_new bypass → race condition (Theory 4, lottery ticket)
1. If `thr_new` works via make_syscall(455), create a second thread
2. Classic TOCTOU on any kernel object (socket close vs. read, timer arm vs. fire)
3. UAF → use ROP chain to call freed object's method → kernel code execution
