# Upstream State — what the tree believes on 2026-11-05

**Provenance.** Every citation below is a line in the upstream tree, read with
`git -C C:\tmp\wt-run show origin/master:docs/FILE` and line-numbered from that
exact blob. No console was contacted, no probe was sent, nothing in
`C:\PS5contrib` outside this file was written.

| item | value |
|---|---|
| upstream tip read | `ab3379c67c83c3bd64b218ad86759a46ec73f641` ("Merge pull request #163 from ng643/kernel/wx-wrap-and-ancillary", 2026-11-04 23:25:13 +0100) |
| brief's stated tip | `c7f3b000` — **not** the current `origin/master` in this clone; nothing below was read at that hash |
| docs at that tip | 225 non-binary files under `docs/` (plus `docs/dumps_13.60/*` and `docs/images/*`) |
| history available | full, 1157 commits, so withdrawals can be pinned to a commit as well as to a document |

**How to read a row.** `docs/X.md:L` is a blob line, not a rendered line. Every row
carries at least one verbatim fragment in double quotes. Where two upstream
documents contradict each other the row is written twice, once per side, and the
pair is listed again in §5 with both quotes — this document does not adjudicate
between them.

**Standing caveat the tree applies to itself**, and which every row inherits: "no verified 14.10 kernel image is present in this repository" (`docs/EVIDENCE_CORRECTIONS.md:15`). Static claims about handler bodies are 13.60 claims; only the behavioural probe results are 14.10 measurements.

---

## 1. CLOSED

Mechanism, what closed it, and the reason in one line. "Closed" here means the
tree states the path is dead, not that the underlying bug is absent from the
firmware.

| # | Mechanism | Closed by | One-line reason | Citation + quote |
|---|---|---|---|---|
| C1 | AF_ROUTE routing-socket KASLR leak (Relapse stage 1) | 43o, retest 53b (2026-10-18) | reply delivered but every payload sockaddr is zeroed | `docs/DEAD_ENDS.md:37` — "all payload is zeroed sockaddr structures — zero kernel pointers" |
| C2 | `msync(MS_INVALIDATE)` CVE-2026-49418 | 58a/58b (2026-10-22) | kernel rejects MS_INVALIDATE before the device pager | `docs/DEAD_ENDS.md:74` — "msync(65) with MS_INVALIDATE returns -1 on ALL mapping types" |
| C3 | `IPV6_MSFILTER` source-filter UAF, CVE-2026-49412, *as a removed API* | 50e2/50e3 | option 74 refuses every size — see §5 D6, the CVE dossier disagrees | `docs/DEAD_ENDS.md:75` — "All sizes (4-512) rejected uniformly" |
| C4 | KTLS page-cache overwrite CVE-2026-45257 | 50f | Sony did not ship KTLS | `docs/DEAD_ENDS.md:76` — "Sony did not include KTLS." |
| C5 | posixshm largepage UAF CVE-2026-49427/49428 | 391a-391d | `shm_open2` is absent, so no largepage object exists | `docs/DEAD_ENDS.md:151` — "shm_open2(571) is nosys, largepage shm objects cannot be created" |
| C6 | jail refcount underflow CVE-2026-49419 | 392a | whole jail family returns -1 | `docs/DEAD_ENDS.md:152` — "jail(338), jail_get(506), jail_set(507), jail_remove(508) all return -1" |
| C7 | TIOCSCTTY race CVE-2026-58093 | 58d | no tty node is reachable from the game jail | `docs/DEAD_ENDS.md:116` — "no `/dev/tty*` access from game process" |
| C8 | kqueue fork race CVE-2026-58099 | 58d | fork is -1, so the race has no second actor | `docs/DEAD_ENDS.md:117` — "kqueue works (fd=23) but `fork()` returns -1 on PS5" |
| C9 | unix-socket receive UAF CVE-2026-58090 | 58d | code path only exists in FreeBSD 15.0+ | `docs/DEAD_ENDS.md:118` — "affects FreeBSD 15.0+ only" |
| C10 | CVE-2019-5607 phantom-fd / fget refcount | 89a, 527b-527d | three socket types, real fills, zero phantom descriptors | `docs/DEAD_ENDS.md:164` — "zero phantom fds in every test" |
| C11 | netcontrol(99) netevent queue UAF (Poops/ExploitNetControlImpl) | 223a-234a, PR #69 | close-before-unregister leaks the reference instead of freeing | `docs/DEAD_ENDS.md:99` — "close-before-unregister leaks it instead of freeing" |
| C12 | `UMTX_OP_SHM` (op 25) and CVE-2024-43102 | 151a-152k | sub-ops are stubs: no fd, no vm_object, no slab | `docs/DEAD_ENDS.md:92` — "Sony stubbed out the SHM subsystem" |
| C13 | `kld*` family (307/308/337) and `sysctlbyname` (570) | 353a/353b, 710a/711a | shared `nosys` trampoline raises SIGSYS; not a hidden handler | `docs/DEAD_ENDS.md:38` — "die on touch by raising SIGSYS from the shared `nosys` trampoline" |
| C14 | W^X bypass by any syscall route | 803c-803i, 124a, 572a (Finding 95) | exec bit is sanitised at creation and cannot be re-added | `docs/STRATEGY.md:67` — "No bypass path exists." |
| C15 | `fn_addr` / ROP-chain hijack as a call primitive | 43i, 45c | tested calls returned normally after the metadata was mutated | `docs/DEAD_ENDS.md:34` — "no arbitrary function-call primitive is established" |
| C16 | `sigreturn` IOPL privilege raise | 813a-816c | IOPL bits sit inside the frame mask and are rejected | `docs/DEAD_ENDS.md:179` — "IOPL bits 12-13 are inside the mask and rejected" |
| C17 | /dev/dmem0..2 and /dev/gc, /dev/dce as a route to system RAM | 547a-547g, 563a-563k (Finding 103) | the aperture is GPU bus space with a 5.25 GB ceiling | `docs/DEAD_ENDS.md:180` — "maps a GPU bus space aperture, not system RAM" |
| C18 | GPU-pool uninitialised-page KASLR leak | 348a | the pool zeroes pages on allocation | `docs/DEAD_ENDS.md:110` — "found zero nonzero words, zero kernel-shaped values and zero strings" |
| C19 | Sysent slots 679-734 as reachable surface | 275b-275d | credential gate returns -1 even from a child thread | `docs/DEAD_ENDS.md:147` — "kernel-side credential gate, all return -1 even from child thread" |
| C20 | Measured sysent tail beyond 676 | sweep 677-707 (2026-10-20) | 31 consecutive kills read as past-the-end — but see O5 | `docs/SYSENT_PRESENCE_14_10.md:701` — "the measured sysent ends at 676 on 14.10" |
| C21 | osem waiter-wake race | 824a-846a | synchronous wake plus generation check removes the window | `docs/DEAD_ENDS.md:177` — "osem waiter wakes synchronously on destroy (10ms)" |
| C22 | IPv6 RTHDR 128-byte zone spray against AIO residue | 75a-75e | 0 overlaps because there is no underlying free | `docs/DEAD_ENDS.md:176` — "0 overlaps in any probe" |
| C23 | Object-lifetime races at native speed (7 families) | 410a-422b | descriptor reuse is real, the objects stay usable | `docs/DEAD_ENDS.md:121` — "are all clean on 14.10" |
| C24 | BSD-native syscall range 1-530 as a kernel-pointer source | 388a-392f | ~400 syscalls, no supervisor-range value anywhere | `docs/DEAD_ENDS.md:155` — "~400 syscalls tested. Zero kernel pointers" |
| C25 | Device-ioctl over-copy as an info leak | 387a/387c, 56m | 48,446 calls, no byte written past the declared length | `docs/DEAD_ENDS.md:150` — "48,446 calls across 19 … devices. Zero overcopy" |
| C26 | SysV IPC (sem/msg/shm) as a surface | 525a | entire subsystem removed | `docs/DEAD_ENDS.md:157` — "semget(221), shmget(231), msgget(225) all return -1" |
| C27 | Reading execute-only system-library text for gadgets | 377a, 712b | XOM: a read faults past `pcall` and takes the loader | `docs/THREADING_ALIVE_14_10.md:404` — "Reading the bytes at that code address kills the process" |
| C28 | `thr_create` child as a loop host (pop-rsp reset, long chain) | 882a-885a | the stub's own frame overwrites the chain below `RSP` | `docs/DEAD_ENDS.md:181` — "a child can call the loader stub … but cannot loop" |
| C29 | `sceKernelMapDirectMemory` on the main thread | 544a-545g, bypass 545h | kernel-chosen VA collides with the loader heap ~70% of runs | `docs/DEAD_ENDS.md:165` — "crashes ~70% due to kernel-chosen VA colliding with loader heap" |
| C30 | /system_tmp compositor sockets as a control channel | 361b-377a | write DoS only; protocol unrecoverable because .rodata is XO | `docs/DEAD_ENDS.md:8` — "an unprivileged DoS, no crash address and nothing reclaimed" |
| C31 | AIO 661 (`aio_submit`) as the AIO entry point | 54c/54f, 266a, resolved 353a | 661 is the `nosys` trampoline; 669 is the real entry | `docs/AIO_BATCH_14_10.md:178` — "`nosys` trampoline that raises signal 12" |
| C32 | "A kill proves the slot is absent" | 173a, 55c | a present handler that faults dies identically | `docs/SYSENT_PRESENCE_14_10.md:4` — "A kill proves less than it first appeared to" |

---

## 2. OPEN / UNTESTED

Each row: where upstream itself says the question is still open, what evidence is
missing, and whether the question can be settled by measurement on the console
(LIVE) or only by obtaining/decoding a 14.10 image (STATIC).

| # | Question | Where upstream says it is open | Evidence missing | LIVE or STATIC |
|---|---|---|---|---|
| O1 | Alternative WebKit info leak to replace blocked `IPV6_2292PKTOPTIONS` | `docs/STRATEGY.md:125` — "Alternative info leak | **NOT IDENTIFIED** — the sole remaining blocker" | any way to read a raw heap pointer as a JS number on 14.10 | LIVE |
| O2 | Browser access from the game process (or a standalone entry) | `docs/STRATEGY.md:135` — "A method to launch the browser from the game process (not currently known)" | a mechanism, or a decision to treat the User's Guide as the entry instead | LIVE |
| O3 | Real scope of the Canvas UAF write primitive | `docs/EXPLOITATION_STATUS.md:43` — "Browser-side write primitive (48B transform + properties, NOT arbitrary write)" vs `docs/STRATEGY.md:123` "bidirectional R/W" — §5 D3 | a measurement that separates an 8-byte transform from arbitrary addressing | LIVE |
| O4 | Whether a 14.10 image resolves the 677-734 tail | `docs/SYSENT_PRESENCE_14_10.md:705` — "a return value proves the 14.10 table extends past 676" (probe 275a) | 275a's result, or a 14.10 kernel image | BOTH |
| O5 | 677-707 kill because absent, or because the handlers fault | `docs/SYSENT_PRESENCE_14_10.md:705` — "includes 24 slots that are real read-only or buffer-taking handlers on 13.60" | fault-proof calls (705, 713, 733, 687, 690) with real arguments | LIVE |
| O6 | `IPV6_MSFILTER` handler lock ordering on 14.10 (CVE-2026-49412 as a live bug) | `docs/CVE-2026-49412-PS5-14.10.md:59` — "The next test needs a timing control that demonstrably places the leave operation while the filter call is in progress" | a timing control or a Sony disassembly; return codes cannot decide it | BOTH |
| O7 | The 17 OBJECT-sourced copyout candidates from `kptr_hunt.py` | `docs/STRATEGY.md:145` — "worth testing with real arguments on 14.10 if any are reachable" | reachability, then a live call with real arguments | LIVE |
| O8 | Effect of 637's stored qword on the GPU pool | `docs/OBJECT_FAMILIES_14_10.md:162` — "`346a` is the A/B that" | a fresh-process allocate-until-fail, raise-the-limit, retry run | LIVE |
| O9 | Whether the AIO class=2/3 and `cmd=2` paths behave differently | `docs/2026-10-25/README.md:184` — "**NEVER VARIED** — all 30+ probes use class=1" | a lifecycle probe at class 2/3 and a write-path probe | LIVE |
| O10 | Socket-level `SIOC*` ioctl space as an info leak | `docs/2026-10-25/README.md:73` — "Our ioctl sweep tested /dev nodes but NOT socket-level ioctls" | a sweep on socket descriptors rather than device nodes | LIVE |
| O11 | CVE-2026-45251 poll+close race on non-procdesc descriptors | `docs/2026-10-25/README.md:193` — "Untested code path (different from kevent+close which was exhaustively tested)" | a 5000-iteration poll+close probe from a child thread | LIVE |
| O12 | `thr_create` CS attribution as a single variable | `docs/THREADING_ALIVE_14_10.md:112` — "would reboot the console and has not been run" | one run that can reboot the console | LIVE (costly) |
| O13 | Which branch explains the unreachable stack-`copyin` path | `docs/THREADING_ALIVE_14_10.md:251` — "either `proc+0xc81` is zero … or the check fails before the length is even examined" | a probe that separates the two, or the 14.10 handler | BOTH |
| O14 | TLS, scheduling, affinity, signal delivery and `thr_exit` inside a `thr_create` child | `docs/THREADING_ALIVE_14_10.md:122` — "`thr_exit` from the child are untested" (:121 names "Priority, affinity, signal delivery and") | one probe per facility | LIVE |
| O15 | True semantics of 663 (`aio_multi_wait`) | `docs/AIO_GATE_14_10.md:92` — "the wait syscall rejects every shape" vs `docs/AIO_DOUBLE_FREE_14_10.md:151` "71h proved 663 blocks on pending I/O" — §5 D5 | a re-run of the 71h shape under the later register discipline | LIVE |
| O16 | Whether any AIO I/O is dispatched at all on 14.10 | `docs/AIO_GATE_14_10.md:110` — "and no I/O is ever dispatched" vs `docs/AIO_BATCH_14_10.md:46` "the copy is real" — §5 D4 | a repeat of 352f (urandom) and 926a (kernel-address destination) in one process | LIVE |
| O17 | Authenticity of the 13.60 capture everything static rests on | `docs/EVIDENCE_CORRECTIONS.md:15` — "acquisition authenticity remains unresolved" | provenance work on the dump, not a probe | STATIC |
| O18 | Whether 430's 14.10 body is the 13.60 body the offsets came from | `docs/THR_CREATE_430_CONTEXT.md:229` — "may be filtered by the loader, or may not exist" | a 14.10 image | STATIC |

---

## 3. RETRACTED / CORRECTED

Claims the tree withdrew, and what withdrew them. Where the withdrawal itself was
later qualified, both steps are recorded.

| # | Claim as once made | Withdrawn / corrected by | What replaced it | Citation + quote |
|---|---|---|---|---|
| R1 | AIO 662 is a double-free → heap spray → kernel R/W (Theory 0, top priority) | 70e/71a (2026-10-25), 882a-886a, then the 2026-10-28 banner (commit `d59956fd`, PR #187/#188) | double-STATUS; subsystem inert because a boot tunable gates submit | `docs/AIO_DOUBLE_FREE_14_10.md:3` — "**RETRACTED 2026-10-28 — not a 14.10 exploit primitive.**" |
| R2 | …and the intermediate reading that "double-success is now proven" | the same 10-28 closure, plus the earlier objection in `VERIFICATION_SESSION3.md:107` | neither "double-free" nor "proven double-success": the window does not open | `docs/2026-10-25/VERIFICATION_SESSION3.md:107` — "The "double-success" theory is presented too confidently. The truth is unresolved." |
| R3 | AIO residual-object KASLR spray (R+0x00/R+0x08 survive free) | 75a-75e + AIO closure | nothing is freed, so there is no residue to reclaim | `docs/DEAD_ENDS.md:175` — "there is no freed object to reclaim" |
| R4 | 663's waiter reaps the object before a delete can reach it (915a/916a/917a) | 919a/918a | the 663 call those captures rested on was failing instantly | `docs/AIO_GATE_14_10.md:96` — "**Withdrawal:** the earlier" (sentence continues at :97, "rested on a `663` call that was failing immediately") |
| R5 | W^X defeated (probes 44a-44d) | 45c | returns were not evidence of executable memory | `docs/CHANGELOG.md:1682` — "Probes 44a-44d — W^X DEFEATED (RETRACTED — see 45c above)" |
| R6 | Shellcode executed on an mtypeprotect'd page | 45c, 572a (Finding 95) | a writable page still cannot execute | `docs/FINDINGS.md:1519` — "A Writable Page Still Cannot Execute, Tested Through the Working Redirect" |
| R7 | `fn_addr` write → arbitrary call / redirect primitive | 45c, ledger status | writable metadata only | `docs/RESEARCH_EVIDENCE.json:7` — "Writable metadata was observed; an arbitrary function call primitive was not demonstrated." |
| R8 | Syscall 557 wrote into the struct (46a) | 46a re-read with an explicit zero baseline | probe false positive | `docs/FINDINGS.md:720` — "Syscall 557 Buffer-Modification Claim Was a Probe False Positive" |
| R9 | The "umtx" probes measured `_umtx_op(454)` | re-binding of the syscall numbers | they called 557 = `namedobj_create` | `docs/EVIDENCE_CORRECTIONS.md:14` — "The "umtx" probes called syscall 557, not `_umtx_op(454)`" |
| R10 | `thr_create` panic = missing `SEL_RPL_MASK` on CS | 189a, then the copy-map re-read | the 13.60 `set_mcontext` never reads the context CS field at all | `docs/EVIDENCE_CORRECTIONS.md:13` — "the 13.60 set_mcontext never reads the context CS field (+0xC0) at all" |
| R11 | 80a showed "CS=0x43 prevents the panic" | 156a-156d | that context failed the gate fields before CS was read | `docs/THREADING_ALIVE_14_10.md:91` — "80a's earlier "CS=0x43 prevents the panic" line was **not** a threading result" |
| R12 | `fstat(189)` kills the process | 353c/353d, confirmed 1021a | 189 is present and fills a stat record | `docs/DEAD_ENDS.md:93` — "**retracted**: 189 is present." |
| R13 | msync was tested at syscall 226 | PR #70 | 226 is a `nosys` stub; real msync is 65, so the early probes called nothing | `docs/DEAD_ENDS.md:24` — "Earlier probes called dead air." |
| R14 | sys 548: "all operation codes return ret=-1" | 803d-803f | ops 1/2/3 act; protect is clamped to the creation protection | `docs/DEAD_ENDS.md:77` — "The earlier "all operation codes return ret=-1" reading passed a descriptor in a slot the handler ignores" |
| R15 | sys 622: "every command returns 0x800E0001, no device context" | 241a-247a | the arguments were in the wrong slots; size 0x40 passes the gate | `docs/DEAD_ENDS.md:78` — "came from passing the arguments in the wrong slots" |
| R16 | sys 626 is a blocked MSR reader | 796a-796d (Finding 97) | arg1 is a command; cmds 5/6 read and write performance counters | `docs/DEAD_ENDS.md:63` — "**Corrected 2026-10-26:** arg1 is a command, not an MSR index." |
| R17 | sys 601 command labels used for auth/write claims | dispatch audit 2026-10-22 | jump table decoded; 0x0c reads kernel state, 0x10 is subvalue-gated | `docs/SYS601_1360_DISPATCH_AUDIT_2026-10-22.md:34` — "directly contradict the proposed 13.60" (:35 names the labels: `0x05` info-leak, `0x06` process-write, `0x0c` auth) |
| R18 | "Child thread C cannot call 669" (no `pop r8`) | 71g | the kernel allocated the object even with `r8` garbage | `docs/AIO_DOUBLE_FREE_14_10.md:135` — "**OVERTURNED (71g)**" |
| R19 | osem 549-556 is dead | 804a (Finding 102) | 549 creates, 550 deletes, 551 refuses; the 252a shapes never passed a name | `docs/FINDINGS.md:1828` — "`osem` works, and `ATTACK_SURFACE.md` says it does not" |
| R20 | `SCM_RIGHTS` descriptor passing does not work | 526a | probe 56q had `controllen=0` — a probe bug | `docs/DEAD_ENDS.md:141` — "probe 56q was WRONG (controllen=0 was a probe bug)" |
| R21 | WebKit `p146` leaked `.length = 81400` | p146 re-read | the value was the literal string length | `docs/WEBKIT_FINDINGS.md:80` — "**RETRACTED as false positive**" |
| R22 | "Zone isolation is structurally impossible" | 22_CONTRADICTIONS_REPORT, 22_ZONE_ISOLATION_VERIFICATION | untested at sufficient volume, not structurally closed | `docs/2026-10-25/22_CONTRADICTIONS_REPORT.md:21` — "Doc 14's "structurally impossible" claim is **too strong**" |
| R23 | sys 591 is `FatGid/setcred` and therefore absent | 22_CONTRADICTIONS_REPORT:98, then 512a/513a | 591 is `dynlib_dlsym`; it was then tested and fails for all 39 modules | `docs/2026-10-25/22_CONTRADICTIONS_REPORT.md:98` — "591 has **never been tested with valid arguments**" |
| R24 | Sony AIO 661-670 "NEVER tested on 14.10" | 43p follow-ups, 52a onward | the family was measured; see §1 C31 and §5 D4 for what the measurements disagree about | `docs/research/relapse_variant_analysis.md:122` — "The Sony AIO syscalls that Relapse actually uses have NEVER been tested on 14.10" |
| R25 | Byepervisor patch status | scene update 2026-10-19 | retracted | `docs/CHANGELOG.md:1324` — "Scene update — Byepervisor-Reborn patch status retracted" |
| R26 | "The shared-context double-free model" | superseded AIO analysis | a per-slot model | `docs/CHANGELOG.md:549` — "The earlier shared-context double-free model is retracted." |

---

## 4. PRIMITIVES

What upstream believes is actually available on 14.10 today, with the limits it
states in the same breath. This is the section to trust least from static
reading and most from the behavioural captures it cites.

| # | Primitive | What it gives | Stated limits | Citation + quote |
|---|---|---|---|---|
| P1 | Userland code execution | Lua 5.1 loader over TCP 9026 inside a PS4-compat game process, with `memory.*` R/W and `syscall.*` | userland only; the kernel surface from this entry is called exhausted | `docs/USERLAND_ENTRY.md:82` — "The game stays on a black screen while the loader runs. The Lua loader listens on TCP 9026" |
| P2 | Arbitrary *tested* syscall invocation | `make_syscall(N)` bypasses the Lua-side resolver filter | "kernel-side checks still apply" | `docs/STRATEGY.md:48` — "| Arbitrary tested syscall invocation | `make_syscall` | kernel-side checks still apply |" |
| P3 | GPU-pool heap R/W | `mmap(477)` with flags `0x1002`, 256+ pages | 384 MiB max, zeroed on allocation | `docs/STRATEGY.md:52` — "| GPU pool mapping, userland R/W | 477 with flags `0x1002` | 384 MiB max, zeroed on alloc (348a) |" |
| P4 | Threads with a full register context | `thr_create(430)` starts a ring-3 thread at attacker `RIP`/`RSP` with attacker GPRs | not a kernel primitive; lifetime ends only with the session | `docs/THREADING_ALIVE_14_10.md:12` — "The child executes our `RIP`, with our registers and our stack" (:13 continues "in ring 3, and the process survives") |
| P5 | Threads, second route | `thr_new(455)` with a real `struct thr_param` (`param_size` bounded) | zeroed param starts a thread at address 0 and dies | `docs/DEAD_ENDS.md:45` — "With a real `struct thr_param` … it returns 0 and the process survives" |
| P6 | Native syscalls from a child thread | point the child at the loader trampoline; `RAX` = syscall number, args in registers | no `syscall;ret` in eboot; the trampoline is the only way in | `docs/THREADING_ALIVE_14_10.md:288` — "marker=0xAE        <- 174, the child's pid" |
| P7 | Two concurrent syscalls without killing the process | loader `thread:new(sc):run(true)` class | spawn jitter larger than the delete window | `docs/THREADING_ALIVE_14_10.md:337` — "**two threads, both `getpid` calls returned `320`, process alive**" |
| P8 | Userland module bases | `dynlib_get_info(593)` over 39 modules | kernel ASLR is a separate problem | `docs/STRATEGY.md:60` — "| Userland module-base discovery | 593 on 39 modules | kernel ASLR is separate |" |
| P9 | Selected CClosure redirects | four `+0x20` target swaps with distinguishing output and restore | existing Lua C targets only; no arbitrary target, no register arguments | `docs/FINDINGS.md:1112` — "rawequal → rawget: `rawequal(t, "foo")` returned `"bar"`" |
| P10 | Userland register-state control via `sigreturn` | kernel installs a caller-supplied frame; cookie is RFLAGS `0x202` | IOPL rejected, so no privilege raise | `docs/STRATEGY.md:57` — "| sigreturn frame injection | 417/421 | cookie=RFLAGS(0x202), IOPL rejected (816c) |" |
| P11 | Eboot gadget catalog | pop rax/rdi/rsi/rdx/rcx/rsp, `jmp $`, `mov [rsi],rax`; count per gadget | no `mov [rdx],rax` and no `syscall` in eboot | `docs/THREADING_ALIVE_14_10.md:306` — "`mov [rdx],rax; ret` | - | **0** |" |
| P12 | POSIX shared memory | `shm_open`/`ftruncate`/`mmap MAP_SHARED` | `shm_open2(571)` is absent | `docs/EXPLOITATION_STATUS.md:38` — "POSIX shm + sendfile … named/anon shm, MAP_SHARED" |
| P13 | A fixed-offset kernel write | `637` stores a caller-chosen qword at `child+0x280` with no capability check for id 0 | fixed destination, unknown meaning, no read-back | `docs/OBJECT_FAMILIES_14_10.md:166` — "a fully caller-chosen 64-bit value written into a kernel structure" |
| P14 | VM-op counter side channel | `624` = +5 per mmap, zero jitter | cannot distinguish kernel addresses from each other | `docs/EXPLOITATION_STATUS.md:39` — "sys 624 VM-op counter | 52b: +5 per mmap, zero jitter" |
| P15 | Full process VM map | `674` returns 317 named regions with protections | every address is userland VA | `docs/DEAD_ENDS.md:80` — "317 regions enumerated with full 72-byte records. All addresses are userland VA" |
| P16 | Event / named objects | `538`/`540`/`544`-`546`, `557` handles with generation-checked ids | process-scoped; nothing outlives the process | `docs/OBJECT_FAMILIES_14_10.md:95` — "The registry is therefore scoped to the process" |
| P17 | **Kernel read** | — | none. No supervisor-range value has been produced by any live path | `docs/STRATEGY.md:68` — "No kernel pointer from Lua side" |
| P18 | **Kernel write (arbitrary)** | — | only P13's single fixed field | `docs/STRATEGY.md:71` — "No KASLR defeat — 17+ techniques tested, all dead." |
| P19 | Browser-side write primitive (not the loader) | Canvas UAF, same-type 768 B reclaim, 48 B transform + properties | no info leak, no browser access from the game process | `docs/EXPLOITATION_STATUS.md:43` — "bidirectional R/W, spray[9] alias, 7 numeric props" |

---

## 5. Where upstream disagrees with itself

Recorded, not resolved. Each item names both sides and the line that carries each.

**D1 — AIO 662: bug present but gated, versus bug absent and inert.**
The closure document says the window cannot be reached; the dead-end entry says
the guest never runs at all. Both agree it is not exploitable, and they disagree
about the mechanism.
- `docs/AIO_GATE_14_10.md:56` — "the TOCTOU window that 14.20 patches does not exist here at"
- `docs/AIO_GATE_14_10.md:109` — "objects are" (continues at :110, "created, states move, deletes are refused or accepted, and no I/O is ever dispatched")

**D2 — "A 14.10 exploit in the wild is not this bug" versus "this is the bug being exploited on 14.10".**
- `docs/AIO_GATE_14_10.md:68` — "exploit in the wild is therefore **not** this bug"
- `docs/FREEBSD_EXPLOIT_TECHNIQUES.md:80` — "This confirms our double-free is the same bug being actively exploited" (:81 continues "by the community on 14.10")

**D3 — The Canvas UAF write primitive's scope.**
- `docs/EXPLOITATION_STATUS.md:43` — "Browser-side write primitive (48B transform + properties, NOT arbitrary write)"
- `docs/STRATEGY.md:123` — "| Write primitive | Claimed in p553 (bidirectional R/W via same-type reclaim) |"
- `docs/PROLAPSE_CANVAS_UAF.md:34` — "Everything else in the chain is confirmed working."

**D4 — Does AIO move bytes on 14.10?**
Three documents, three positions, all citing saved captures.
- `docs/AIO_BATCH_14_10.md:45` — "The data is different on every" (:46 continues, "read, so the copy is real and not a stale buffer")
- `docs/AIO_14_10_LIVE_2026-10-19.md:5` — "This is direct evidence of a working read transfer through syscalls 669/664/662."
- `docs/AIO_GATE_14_10.md:110` — "created, states move, deletes are refused or accepted, and no I/O is ever dispatched"

**D5 — What 663 does.**
- `docs/AIO_DOUBLE_FREE_14_10.md:151` — "**71h proved 663 blocks on pending I/O and unblocks on completion**"
- `docs/AIO_GATE_14_10.md:92` — "the wait syscall rejects every shape"

**D6 — CVE-2026-49412 reachability.**
The dead-end list says the API is gone; the dedicated dossier says the handler ran
and accepted a 128-source list, and only the lock ordering is unknown.
- `docs/DEAD_ENDS.md:75` — "Sony removed the entire RFC 3678 multicast source filtering API"
- `docs/CVE-2026-49412-PS5-14.10.md:4` — "The `IPV6_MSFILTER` handler is reachable from the 14.10 game process with a valid source-list `copyin`"
- `docs/EXPLOITATION_STATUS.md:87` — "DEAD — RFC 3678 API removed" (sides with the dead-end list)

**D7 — CVE-2026-49418 status.**
- `docs/CVE-2026-49418-PS5-14.10.md:4` — "PS5 applicability unresolved"
- `docs/DEAD_ENDS.md:74` — "**CONFIRMED DEAD**" (the later measurement: 58a/58b)

**D8 — 637's store: does it do anything?**
- `docs/OBJECT_FAMILIES_14_10.md:162` — "no run has yet shown the value changing an outcome"
- `docs/DEAD_ENDS.md:111` — "sys 637's store is inert"

**D9 — thr_create's CS field: does it matter?**
- `docs/EVIDENCE_CORRECTIONS.md:13` — "the 13.60 set_mcontext never reads the context CS field (+0xC0) at all"
- `docs/THREADING_ALIVE_14_10.md:108` — "CS attribution is still inferential"
Both are compatible with 448a/452a (a selector that is replaced or masked), but
they attribute the mechanism differently.

**D10 — The 13.60 dump's authority over 14.10.**
- `docs/THR_CREATE_430_CONTEXT.md:5` — "no 14.10 artifact exists in this repository, and nothing"
- `docs/AIO_OBJECT_FORENSICS.md:10` — "14.10 behavioral match is strong but identical code is not proven."
- `docs/FINDINGS.md:1307` — "It is the first confirmed kernel memory corruption primitive on 14.10." (a claim the tree later withdrew; see R1)

**D11 — Documentation state against documentation content.**
The tree's own audit says several core documents are stale; the documents
themselves were not all updated afterwards.
- `docs/2026-10-25/07_DOCUMENTATION_GAPS.md:9` — "Line 85: "No threading -> no race conditions" -- directly contradicts reality."
- `docs/2026-10-25/07_DOCUMENTATION_GAPS.md:38` — "**Ends at probe 278a:**" — "All probes after that are missing from the index"
The current `PROBE_INDEX.md` is 53.8 KB and `STRATEGY.md` was rewritten on
2026-10-28, so part of that audit has since been addressed; `FINDINGS.md` still
carries Finding 92 titled "CONFIRMED" (`docs/FINDINGS.md:1292`) with no retraction
note attached to it, which is the clearest live documentation defect at this tip.

---

## 6. What a newcomer should read first

1. `docs/EXPLOITATION_STATUS.md` (116 lines) — the single-page state: what works, what is blocked, what is left.
2. `docs/AIO_GATE_14_10.md` (115 lines) — why the most-cited primitive in the tree is not one; read before any AIO idea.
3. `docs/THREADING_ALIVE_14_10.md` (370 lines) — the one capability the tree gained late, with the context layout that works.
4. `docs/DEAD_ENDS.md` (182 lines) — read in full before writing a probe; it is the accumulated cost of every repeated idea.
5. `docs/SYSENT_PRESENCE_14_10.md` first 14 lines and the section "The table ends at 676" — how to read a return value without over-reading it.
6. `docs/SYSCALL_ABSENT_VS_LETHAL.md` — the SIGSYS distinction that invalidated a whole class of earlier conclusions.
7. `docs/RESEARCH_EVIDENCE.md` plus `docs/EVIDENCE_CORRECTIONS.md` (15 lines) — the scoping rules that make a claim citable.
8. `docs/OBJECT_FAMILIES_14_10.md` — what the "-1" rows actually do, and the one real write primitive (637).
9. `docs/STRATEGY.md` sections "Walls That Are Measured" and "Relapse / Lapse / Prolapse Intelligence" — the current plan and its provenance.
10. `docs/2026-10-25/22_CONTRADICTIONS_REPORT.md` last, as a warning: the tree has already found eleven of its own contradictions.
