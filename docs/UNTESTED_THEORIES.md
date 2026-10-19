# Untested Theories — PS5 14.10

> **Evidence scope (2026-10-18):** The 45c controls concern selected syscall-object metadata mutations, not every loader path. Later 56c/56f captures record selected CClosure redirects to existing Lua C functions with returned values and restoration. Those userland results do not establish arbitrary native calling conventions, a working ROP chain, injected-page execution, kernel R/W, or KASLR defeat. See [the evidence ledger guide](RESEARCH_EVIDENCE.md) and Findings 79/82.

> **Historical scope:** The narrative below preserves the earlier 43–53 research state; its unrun/open labels and broad execution conclusions are not current status. Later research remains in the probe index and Findings 79–82. The 2026-10-17 audits are dated snapshots, not summaries of every later result.

Potential exploit paths identified from analyzing existing probe data. Cross-referenced against all probe results to avoid duplicating tested paths.

> **Status correction (2026-10-18):** This file preserves historical hypotheses; its proposed ROP/function-call recipes are not current exploit paths. Probe 45c recorded tested syscall results persisting after specific fn_addr and chain mutations, which contradicts the earlier dependency for those calls but does not identify the loader's full dispatch implementation. AF_ROUTE 43o has no established successful delivery or response attribution, 43p is incomplete, 43a/43b are header-only, and 47b omitted offset +0. Treat the theory tables below as unvalidated until a controlled retest establishes both inputs and effects. See the evidence audit and probe index.

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

### Chain D: AIO race condition (Theories 18+19, Relapse-class)
1. Confirm AIO syscalls survive via make_syscall (probe 43p)
2. AF_ROUTE KASLR defeat for kernel base (probe 43o)
3. `aio_read(fd)` + `close(fd)` race → kernel UAF on file object
4. Heap spray replacement object into freed slot
5. Kernel dereferences controlled data → code execution
6. This is the same bug CLASS as Relapse, on the same hardware

---

# ROP Chain Hijack — Deeper Exploitation Theories

The existing ROP chain hijack (probe 41z) gives: overwrite `fn_addr` (call target) + all argument slots (rdi, rsi, rdx, rcx, r8), trigger any syscall, restore. This is equivalent to **arbitrary syscall with fully controlled arguments**. The following theories explore syscalls and techniques that have NOT been tried through this primitive.

---

## Theory 10: `kldstat` (308 / 367) via make_syscall — Kernel Module Base Leak (KASLR Defeat)

**Priority: HIGHEST**

`kldstat` returns `struct kld_file_stat` for a loaded kernel module, which includes:
- `name` — module filename
- `address` — **kernel virtual address where the module is loaded**
- `size` — module size

On FreeBSD, `kldstat(1, &stat)` returns info about the kernel itself (fileid 1 is always the kernel). The `address` field is the **kernel base address** — this defeats KASLR in one call.

**Syscall numbers:** Standard FreeBSD `syscalls.master` defines `kldstat` as **308** (306 is `kldfind`, 307 is `kldnext`, 309 is `kldfirstmod`). Probe 02 sweep table had mapped 367. Probe 43a tests both 308 and 367.

**Test:** `make_syscall(308)` and `make_syscall(367)` with fileid=1 and a buffer for `struct kld_file_stat` (256 bytes). If it returns the kernel base address, combine with known FreeBSD r230171 kernel symbol offsets to locate any kernel function or data structure.

**Why this could be the whole game:** kernel base + known offsets from the same build = addresses of `copyin`, `copyout`, `prison0`, `rootvnode`, and the credential structures. No pointer chasing needed.

---

## Theory 11: `kldsym` (337) via make_syscall — Resolve ANY Kernel Symbol

**Priority: HIGHEST**

`kldsym(fileid, KLDSYM_LOOKUP, &kld_sym_lookup)` resolves a kernel symbol by name and returns its address. This is the kernel equivalent of `dlsym()`.

**Never tested.** Not even resolved in probe 02 (it tested kldload/kldunload/kldfind/kldnext/kldstat/kldfirstmod but not kldsym).

**Test:** `make_syscall(337)` with fileid=1 (kernel), command=1 (KLDSYM_LOOKUP), and a `struct kld_sym_lookup` containing the symbol name. Try resolving:
- `prison0` — the root jail, contains kernel cred pointers
- `allproc` — linked list of all processes
- `kernel_pmap` — kernel page map for direct physical memory access
- `copyin` / `copyout` — if you know their addresses you can build a kernel R/W gadget

If this works, it gives you the address of literally anything in the kernel by name. Combined with the ROP chain hijack to call those functions, this is full kernel code execution.

---

## Theory 12: `sysarch` (165) via make_syscall — GS Base Manipulation

**Priority: HIGH**

On amd64 FreeBSD, `sysarch(AMD64_SET_GSBASE, &addr)` sets the GS segment base register. The kernel accesses `curthread` via `%gs:0` — the GS base points to the current thread's `struct thread`.

**FreeBSD constants (<machine/sysarch.h>):**
- `AMD64_GET_FSBASE = 128`
- `AMD64_SET_FSBASE = 129`
- `AMD64_GET_GSBASE = 130`
- `AMD64_SET_GSBASE = 131`
- `AMD64_GET_XFPUSTATE = 132`

**Test sequence:**
1. `sysarch(AMD64_GET_GSBASE [130], &buf)` — read current GS base (might leak a kernel thread pointer)
2. If GET works, `sysarch(AMD64_SET_GSBASE [131], &fake_addr)` — set GS base to a controlled heap address
3. With a fake `curthread` structure in the heap, any kernel code that dereferences `curthread->td_ucred` follows your controlled pointer → credential replacement → root

**Risk:** Setting GS base wrong will immediately crash the next kernel access. Calling 129 (SET_FSBASE) with 0 also crashes userland. But GET_GSBASE (130) alone (reading the value) is safe and could leak a kernel address.

---

## Theory 13: Sysctl Write Paths — `kern.securelevel` and Friends

**Priority: HIGH**

Probe 42a only tested sysctl READs. Sysctl also supports WRITES — the `newp`/`newlen` arguments to `__sysctl()`. Some writable sysctls could directly change kernel state:

| MIB | What it does |
|-----|-------------|
| `kern.securelevel` | Currently 1024 (PS5-custom). Writing -1 lowers it → enables kldload, raw disk access |
| `kern.proc.rlimit` | Resource limits for the process — could lift fd/memory caps |
| `security.bsd.unprivileged_proc_debug` | Enable ptrace on any process |
| `kern.coredump` / `kern.corefile` | Enable core dumps + set path — a crash could write kernel memory to a file |
| `debug.kdb.enter` | Enter kernel debugger (probably hangs, but tests if debug sysctls are live) |

**What was already tested:** Only reads. `kern.maxproc` read returned -1 (blocked), but the basic MIBs (version, ostype, pagesize, proc.pid) all worked.

**Test:** Call `__sysctl()` via make_syscall(202) with `newp` pointing to a buffer containing the new value and `newlen` set correctly. Start with `kern.securelevel` — if you can lower securelevel, `kldload` becomes available and you can load a kernel module.

---

## Theory 14: Sony-Specific Syscalls (538–600+) — Unexplored Surface

**Priority: MEDIUM-HIGH**

The probes have used a handful of Sony syscalls:
- 538/539: `evf_create`/`evf_delete` (event flags)
- 547–552: dmem (direct memory) allocation
- 588: munmap (Sony variant)
- 592/593: `dynlib_get_list`/`dynlib_get_info`

But the 540–600 range likely contains many more Sony-specific syscalls. On PS4 (which shares the FreeBSD base), known Sony syscalls include:
- `budget_set` / `budget_get` — process resource budgets
- `get_authinfo` — process authentication info (may contain kernel pointers)
- `randomized_path` — path randomization (may expose internal paths)
- `get_proc_type_info` — process type info (credential-adjacent)
- Various GPU/compute syscalls that manage kernel objects

**Never tested:** A systematic sweep of syscall numbers 540–620 via `make_syscall(N)` with safe arguments (e.g., 0,0,0,0,0) to see which ones return something other than -1.

**Test:** For each number, call `make_syscall(N)(0)` and record the return value. Any that return 0 or a positive value are live syscalls. Then probe each live one with real arguments. Pay special attention to any that return data buffers — they may leak kernel addresses.

---

## Theory 15: Chained ROP Hijack — Multi-Call Kernel Walkthrough

**Priority: MEDIUM (depends on Theory 1 or 10 finding a pointer)**

The current ROP hijack does one call per trigger. But since the chain is fully writable and survives restore cycles, you can chain multiple operations:

1. **Call 1:** `sysctl(kern.proc.pid)` → dump kinfo_proc → extract `ki_paddr` (kernel proc address)
2. **Call 2:** Use proc address + known offset to read `p_ucred` via sysctl with a crafted MIB
3. **Call 3:** Write new credential values (uid=0) via sysctl write or a direct kernel write gadget

Each call: overwrite arg slots → trigger syscall → read result from output buffer → overwrite for next call → trigger again.

Alternatively, if `kldsym` works (Theory 11):
1. **Call 1:** `kldsym("prison0")` → get prison0 address
2. **Call 2:** `kldsym("copyout")` → get copyout address
3. **Call 3:** Overwrite fn_addr to point at copyout → call `copyout(kernel_addr, user_buf, len)` → arbitrary kernel read
4. **Call 4:** Same with copyin → arbitrary kernel write

This doesn't need a new bug — it's pure exploitation of the existing hijack primitive.

---

## Theory 16: `kern.proc.filedesc` Sysctl — Socket Kernel Address Leak

**Priority: HIGH (if Theory 1's full dump doesn't find pointers)**

`kern.proc.filedesc` dumps the entire file descriptor table for a process, including for each fd:
- `kf_type` — file type (socket, pipe, vnode, etc.)
- `kf_vnode_type` — vnode type
- **`kf_offset`** — often contains a kernel address
- **The kernel file pointer itself** — on some FreeBSD versions, leaked directly

The MIB is `{CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid}`. The output buffer needs to be large (each fd entry is ~1kB, and the process has 20+ open fds).

**Never tested.** Probe 42a tested kern.proc.pid and kern.proc.vmmap but not kern.proc.filedesc.

**Test:** `make_syscall(202)` with MIB for KERN_PROC_FILEDESC, buffer of 64KB+. Dump and scan for kernel-range values. Since the process has many open sockets, any kernel pointer in the fd entries gives a socket kernel address → known structure layout → overwrite from there.

---

## Theory 17: `procctl` (544) via make_syscall — Process Control

**Priority: MEDIUM**

`procctl` is a FreeBSD syscall for process control operations. On PS5 it might be available via make_syscall since it's in the 500+ Sony-modified range.

Operations include:
- `PROC_REAP_ACQUIRE` — become a reaper (process reparenting)
- `PROC_TRACE_CTL` — control tracing
- `PROC_ASLR_CTL` — **control ASLR for the process** (could disable it)
- `PROC_STACKGAP_CTL` — control stack gap

Disabling ASLR (`PROC_ASLR_CTL` with `PROC_ASLR_FORCE_DISABLE`) would make kernel addresses deterministic across connections — a major simplification for exploitation.

**Never tested via make_syscall.**

---

---

## Theory 18: AF_ROUTE Socket KASLR Defeat — request delivery failed; unresolved

Probe 43o's RTM_GET write returned -1 and the read returned 108 bytes with zero detected pointers and unresolved attribution. Successful delivery and a valid disclosure test are not established. Retest 53b is prepared; no 14.10 leak or patch conclusion is established.

---

## Theory 19: AIO via make_syscall — probe output incomplete

The saved 43p output logs the sysctl canary and then the announcement for `aio_error` syscall 317, but no call result or post-call canary. Its planned later Sony scan was not reached in the saved output. This does not establish whether raw AIO is available on 14.10, and it says nothing about syscall 663. Preserve this theory as unresolved rather than dead until a complete, trustworthy result exists.

---

## Theory 20: Lua VM Allocator Exploitation

**Priority: LOW (speculative)**

The Lua 5.1 VM's internal allocator manages all objects (strings, tables, userdata, closures). JSC structured-clone pool mismatch techniques from WebKit exploits could apply to Lua's GC in concept:
- Force GC to free an object still referenced (mark phase confusion)
- String interning hash collisions leading to use-after-free
- Table rehashing with controlled allocation sizes
- Integer overflow in `string.rep` or table operations
- Metatable confusion between userdata types

However, this gives userland corruption which we **already have** via GPU mmap. Only valuable if it can reach kernel memory directly (unlikely) or provide a primitive we're missing.

**Not probed yet.** Low priority unless all kernel-direct approaches fail.

---

## Phase 10 Test Results (2026-10-16)

### TESTED — Results Summary

| Theory | Probe | Result | Status |
|--------|-------|--------|--------|
| 18: AF_ROUTE KASLR | 43o | RTM_GET write returned -1; 108-byte read with zero detected pointers; attribution unresolved | **UNRESOLVED** — successful request delivery not established; retest 53b prepared |
| 19: AIO via make_syscall | 43p | Saved output ends before result of `aio_error` 317; Sony 663 scan not reached | **UNRESOLVED** — no conclusion from truncated log |
| 10: kldstat | 43a | Header-only 145-byte log | **UNRESOLVED** — no call result or kill record; retest 53c prepared |
| 11: kldsym | 43b | Header-only 116-byte log | **UNRESOLVED** — no call result or kill record; retest 53c prepared |
| 1: kinfo_proc full dump | 43d | 1096B dumped, only `0xFFFFFFFF_00000000` sentinel | **DEAD** — no kernel pointers |
| 16: kern.proc.filedesc | 43d | ret=-1, needed=0 | **DEAD** — blocked |
| 13: sysctl writes | 43f | One securelevel-labeled write returned -1; coredump/debug/maxproc writes not reached | **PARTIAL** — other write paths not established |
| 12: sysarch GET_GSBASE | 43c | GS base = 0 | **DEAD** — no kernel pointer |
| 4/9: blocked syscall re-test | 43e | fstat works (no kptrs), ioctl=-1, dup=-1, thr_new=crash | **PARTIAL** — fstat alive but useless |
| 14: Sony syscall sweep | 43g, 46a/47a, 51a–51c | 557 return characterized as a version-dependent formula; surveys are incomplete | **No exploit evidence** |
| 2: kern.proc.vmmap | 43d | ret=-1 with 64K-256K buffers | **DEAD** — blocked |

### TESTED — New Findings (not previously theorized)

| Finding | Probe | Status |
|---------|-------|--------|
| **fn_addr + slot0 writes persist** | 43i, 45c | Writable fields and ordinary syscall results persisted after selected mutations | **No function-call primitive established; dispatch role remains unknown** |
| mtypeprotect returns 1 for RWX | 43h, 43k, 45c | Return value did not establish executable memory; no code execution path demonstrated |
| kern.msgbuf returns 8 bytes only | 43j | **DEAD** — filtered/stub |
| mincore rejects kernel VA | 43l | **DEAD** — no KASLR oracle |
| sockopt accepts large buffers | 43m | **DEAD** — kernel clamps copy, not overflow |
| /dev/hid ioctl = Sony error | 43n | **DEAD** — 0x80740004 on all ioctls |
| Syscall 620 alive | 43k | **NEEDS INVESTIGATION** |

### Current assessment

No confirmed kernel pointer leak, kernel read/write, arbitrary kernel function call, or kernel code execution is documented by these results. The surviving syscalls (including 557, 593, 596, 572, 563–566, 585, 606, 640, and 643) are observations only; their call semantics and outputs need defensible characterization before prioritizing them. The 51a/51b/51c saved logs do not represent complete coverage of the Sony syscall range.
