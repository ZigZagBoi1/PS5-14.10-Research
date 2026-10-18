# Probe Index — PS5 14.10

Probe inventory with status and key result. Entries marked PREPARED have not been sent to the PS5.

| # | Name | Status | Key Finding |
|---|------|--------|-------------|
| 01 | `identity` | OK | fw=14.10, pid=355, Lua 5.1 confirmed |
| 02 | `syscall_sweep` | OK | Mapped ~40 working syscalls out of 600+ |
| 03 | `vmmap_layout` | OK | Process memory layout, heap/stack/code ranges |
| 04 | `kernel_surface` | OK | Syscall availability matrix for kernel objects |
| 05 | `file_recon` | OK | Filesystem access: most paths blocked |
| 06 | `bug_hunt` | OK | Initial targeted bug search |
| 07 | `ipv6_leak` | OK | IPv6 socket options, extension header attempts |
| 08 | `read_offsets` | OK | Memory read primitives, offset mapping |
| 09 | `ipv6_stress` | OK | IPv6 stack stress testing |
| 10 | `umtx_stress` | OK | UMTX userland mutex kernel operations |
| 11 | `umtx_race` | PARTIAL | Race condition attempts (no threading = no races) |
| 12 | `nwake_robust` | OK | nwake syscall behavior mapping |
| 13 | `nwake_oracle` | OK | nwake as kernel state oracle |
| 14 | `device_ioctl` | OK | Device ioctl — all blocked by sandbox |
| 15 | `dmem_deep` | OK | Direct memory device deep dive |
| 16 | `dmem_mmap` | CRASH | dmem mmap attempts — crashed |
| 17 | `dmem_kptr` | OK | Searched for kernel pointers in dmem |
| 18 | `dmem_phys` | OK | Physical memory mapping attempts |
| 19 | `aio_stress` | CRASH | Historical probe summary says AIO stress caused loader crashes; consult raw logs before generalizing to every AIO entry |
| 19b | `aio_safe` | OK | Historical summary says tested AIO calls were blocked; exact tested calls/arguments are not captured in this table |
| 19c–g | `aio_*` | VARIOUS | Progressive AIO checks; scope is limited to calls/arguments in their raw records |
| 20 | `kqueue_stress` | OK | Read filters and timer filters registered; events observed; close/delete churn completed |
| 21 | `kqueue_deep` | OK | Signal/user filters registered; 2,000 knotes registered/deleted; no copy-on-fork test |
| 22 | `signal_stress` | OK | Signal handler installation works, SIG_IGN/SIG_DFL ok |
| 23 | `sigalt_exploit` | KILLED | sigaltstack + signal delivery → EFAULT, process killed |
| 24 | `sigalt_kwrite` | KILLED | Kernel write via sigaltstack — copyout() validates dest |
| 25 | `sigalt_safe` | OK | Safe sigaltstack — confirmed completely dead |
| 25b | `sigalt_ign` | OK | SIG_IGN behavior with altstack |
| 25c | `sigprocmask` | OK | **sigprocmask is a no-op** — returns 0, does nothing |
| 26 | `gadget_scan` | CRASH | Code page read → SIGBUS (XOM) |
| 26b | `ret_gadget` | CRASH | RET gadget search — XOM blocks all reads |
| 26c | `wxor_gadget` | OK | Confirmed W^X: mprotect(EXEC) always fails |
| 26d | `find_ret` | CRASH | Another code read attempt — XOM |
| 26e | `code_read` | OK | **Execute-only memory confirmed** — cannot read code pages |
| 26f | `kstack_crash` | CRASH | Kernel stack probe via crash handler |
| 27 | `thread_and_fd` | OK | **Threading fully blocked** — fork/rfork/thr_new all -1. dup/dup2 blocked. fstat blocked. |
| 28 | `ipv6_scmrights` | OK | SCM_RIGHTS works, IPv6 ext headers blocked on send |
| 29 | `rthdr_mmap` | INCOMPLETE | Last readable output: UAF test page address in PART 2, followed by a binary tail. No later call result or termination cause is established. |
| 30 | `mmap_fcntl_deep` | INCOMPLETE | Saved output ends at `mlock: rv=0`; no msync/minherit result or termination cause is recorded. |
| 30b | `fcntl_scm` | OK | **writev works** (IOV_MAX=1024), **SCM_RIGHTS validated** (5/5 correct), F_SETFL returns -1 but changes flags, pipe2 blocked |
| 30c | `fcntl_bypass` | OK | **F_SETFL is cosmetic only** — flags appear set but kernel ignores them. F_SETOWN truly blocked. poll() works. kqueue fd allocation also confirmed; see probe 20 for kevent results. |
| 31 | `sockopt_fuzz` | OK | TCP_INFO 236 bytes (no pointers), TCP_CONGESTION="newreno", IP_TTL accepts 256/-1, SO_SNDBUF/RCVBUF accept 1 |
| 31b | `tcpinfo_dump` | OK | Full TCP_INFO hex dump — all protocol metadata, **no kernel pointer leaks**. 23 SOL_SOCKET options accessible. IP_HDRINCL=8 is INP_HDRINCL flag. |
| 31c | `ps5opts_fuzz` | OK | **PS5 custom socket options** (0x2000–0x100000) are boolean flag bits in so_options. Not exploitable. |
| 32 | `bufstress` | HANG | SNDBUF=1 write blocked (F_SETFL nonblock is fake) |
| 32b | `bufstress` | HANG | Same issue — F_SETFL doesn't actually work |
| 32c | `safe_stress` | OK | SETFIB/USER_COOKIE/TS_CLOCK readable but sets blocked. **poll() works perfectly.** SO_TIMESTAMP accepted but no cmsg on UNIX. |
| 32d | `minimal` | RESET | Loader bad state after crashes |
| 32e | `ping` | OK | Minimal ping — loader alive |
| 33a | `sndbuf_step1` | OK | SNDBUF=1 + single write(1) = success (rv=1) |
| 33b | `sndbuf_step2` | HANG | Second write on full SNDBUF=1 buffer blocks (nonblock fake) |
| 33c | `nonblock_test` | HANG | O_NONBLOCK confirmed fake — read blocks on empty socket |
| 33d | `sock_nonblock` | CRASH | SOCK_NONBLOCK (0x20000000) crashes socketpair |
| 33e | `dontwait` | CRASH | **sendto(133)/recvfrom(29) crash syscall.resolve()** |
| 33f | `dontwait_safe` | OK | **MSG_DONTWAIT (0x80) is the real nonblocking mechanism.** recv(empty)=EAGAIN, send works, SNDBUF=1 partial writes correct, 100x rapid cycling clean. |
| 34 | `raw_hdrincl` | OK | **RAW socket + IP_HDRINCL WORKS.** Crafted UDP packet reached listener through kernel ip_input(). TCP SYN dropped (bad checksum). bind/connect on raw socket work. |
| 35 | `frag_fuzz` | FAIL | All 10 fragment tests: no data arrived. Root cause: **listener bind failed** (not fragment-related). |
| 35b | `frag_isolate` | FAIL | Confirmed: bind() returning -1 is the root cause. Even unfragmented UDP fails when bind fails. Need to investigate port restrictions. |
| 36 | `bind_port_sweep` | OK | **Port policy mapped: <1024 and ≥40000 blocked; 1024–32767 bind fine.** Solves the 35/35b bind mystery. |
| 37 | `ip_options` | OK | RR/TS/NOP pass; malformed lens rejected at ip_output (never reach parser); **LSRR/SSRR/TS-overflow sent but dropped on input** — option processing confirmed, need real-network delivery for input-side fuzz. |
| 38 | `untested_syscalls` | INCOMPLETE | **ktimer_create/settime WORK** (timers are live kernel objects!), memfd stub, getrandom/ppoll/cap_rights blocked. Output ends at the isolated minherit section header, before any minherit result. Termination and its cause are unresolved. |
| 39 | `frag_reass` | OK | **ip_reass fully correct on all 7 cases** (baseline, OOO, overlap, tiny-first, dup-final, 9-frag, proto-47). No crash. Deeper fuzz (timeouts, queue limits) still open. |
| 40 | `tcp_connectback` | OK | **TCP connect-back fuzz works.** Fake-IP ARP responder (`run_session40.py`) defeats host-OS RST interference. Full handshake + 26 malformed segments delivered (SACK/URG/seq-overlap/all-flags/RST+data); console stable. |
| 41c | `safe_adjacent` | OK | GPU mmap adjacency confirmed: 256+ adjacent pages accessible without guard pages |
| 41d | `heap_dump` | OK | Heap dump through GPU boundary, analyzed layout |
| 41e | `write_test` | OK | Heap write verified: read/write/restore clean |
| 41f–l | `heap_objects`/`uaf_spray` | OK | Explored heap spraying and object allocation |
| 41m | `vtable_probe` | CRASH | 0x1A3A4EE0 is **unmapped** (SIGSEGV). Crash record format decoded: magic 0x13371337, leaks module code base + heap regs = **ASLR oracle**. |
| 41n–41q | `header_chase*` | OK | Full heap scans (entire mapped heap + anchor-relative windows): **zero 0x1A3A4EE0 objects in fresh sessions** — 41k-era hits were spray artifacts. Dead end documented. |
| 41o | `heap_infoleak` | OK | `dynlib_get_info` ASLR bypass: leaks all 39 loaded module bases |
| 41r–t | `eboot_gadgets` | OK | Full ROP gadget catalog extracted from RX eboot segment |
| 41u–v | `got_dump`/`syscall_ret` | OK | Syscall return mechanisms mapped |
| 41w | `kernel_rw` | OK | Mapped eboot gadgets, confirmed sysctl works via make_syscall |
| 41z | chain_hijack | OK | Chain, fn_addr, and argument slots are writable heap data; probe 45c later recorded tested syscall results persisting after specific metadata mutations, so an execution role is not established. |
| 42a | `ktimer_deep` | OK | Clocks 0+4 usable; **validation correct** (nsec>1e9/-1/2^63 rejected); gettime/delete blocked while settime works (odd split); cap=27 timers. |
| 42a | `kernel_rw` | PARTIAL | Dense sysctl read: FreeBSD r230171, securelevel=1024, 16KB pages. Capture stops at the kenv call header; no kenv result or kill record. |
| 42b | `memfd_msync` | INCOMPLETE | memfd_create returned fd=1; output ends after the msync section prints `region @ 0x31139cee0`. No msync result or termination record; cause unresolved. |
| 42b | `kaslr_defeat` | OK | sysctl kinfo_proc +0x60 has 0xFFFFFFFF00000000 (sentinel/flag); TCB FS base is userland (0x88xxxxxxx) |
| 42c | `kaslr_deep` | OK | Dense kinfo_proc and fstat dumps confirm sentinels (0xFFFFFFFF_*); /dev/dmem0 and /dev/hid open at fd=24 |
| 42d | `dmem_kaslr` | OK | /dev/dmem0 ioctls/allocations fail; proc.filedesc and kstack blocked |
| 42e | `sysctl_enum` | OK | MIB tree walking: non-leaf node queries blocked by sandbox |
| 42f | `ps5_syscall_scan` | OK | Probed 576–619: mtypeprotect(585) ret=1, getCpuUsage(617) ret=0; memory queries fail |
| 42f | `kernel_phys_scan` | OK | /dev/dmem0 physical scan: offset 0x0 yields 0x80000000_C0012800 (GPU HW status) |
| 42f2 | `fast_phys_scan` | OK | Scanned 90 physical offsets: only phys 0 is non-zero |
| 42g | `fnaddr_dump` | OK | Dumped fn_addr target code across multiple module bases |
| 42g | `rop_kptr_leak` | PARTIAL | The original run stopped on an undefined `MB`; the declaration is fixed. Rerun remains pending with mmap-return validation and per-offset markers. |
| 42g2 | `high_phys_decode` | INCOMPLETE | Saved output ends at the STEP 1 kenv header (88 B); no call result or kill record is present. |
| 42g3 | `high_phys_only` | OK | 4GB+ physical address scan: all zeros (no CPU DRAM accessible via dmem0) |
| 42g4 | `minimal_high` | OK | Physical scan of 4GB, 4.5GB, and PS5 hardware ranges: confirms dmem0 is GPU-only |
| 42h | `code_dump` | OK | Code dump of fn_addr target |
| 42h | `rop_exploit` | OK | Located ROP chain candidate in heap relative to GPU mmap |
| 42h2 | `rop_exploit2` | OK | Identified and mapped 13 argument slots in active ROP chain; sysctl proc.all/file blocked |
| 42i | `vmquery` | OK | virtualQuery/jitCreateShared blocked; mincore works (vec=0x1F); dumped 39 module text ranges |
| 42i | chain_analysis | HISTORICAL INTERPRETATION | Mapped ROP-shaped heap metadata and a candidate gadget sequence; probe 45c later showed tested syscall results persisted after metadata mutations, so the proposed execution path is not established. |
| 42j | `thread_ptrace` | OK | thr_self works (TID=101819); procctl blocked; libkernel data scanned (no kptrs) |
| 43a | `kldstat_kaslr` | INCOMPLETE | Header-only 145 B log; no syscall result, error, or kill record. Retest 53c prepared. |
| 43b | `kldsym_resolve` | INCOMPLETE | Header-only 116 B log; no syscall result, error, or kill record. Retest 53c prepared. |
| 43c | `sysarch_gsbase` | OK | GET_GSBASE=0 (no kernel ptr). GET_FSBASE=userland TCB. GET_XFPUSTATE=ret 0. |
| 43d | `kinfo_proc_full` | OK | Full 1096B dump: only `0xFFFFFFFF_00000000` at +0x60 (sentinel). Process="boot.bin". FILEDESC blocked. VMMAP ret=-1. |
| 43e | `blocked_syscall_bypass` | PARTIAL | **fstat works** via make_syscall (no kptrs). ioctl=-1 even raw. dup/dup2=-1. **thr_new crashed** (still blocked). |
| 43f | `sysctl_write` | OK | One securelevel-labeled write returned -1. coredump/debug/maxproc reads returned -1; their conditional writes were not reached. somaxconn read returned 0/value 1024; no write test. MIB identities remain probe annotations. |
| 43g | `sony_syscall_sweep` | KILLED | **Syscall 557 returns 16901** (live Sony syscall!). Syscall 620 ret=0. Process killed mid-sweep. |
| 43h | `mtypeprotect_wxbypass` | OK | mtypeprotect returns 1 for ALL prot values (RWX, RX, X). Page still RW after call. mprotect(RX) still -1. **Execution not tested.** |
| 43i | fn_redirect | HISTORICAL CLAIM NOT ESTABLISHED | The run reported persistent fn_addr/slot writes; probe 45c found tested syscall results persisted after specific fn_addr and chain mutations. No arbitrary function-call primitive is established, and the dispatch path remains unknown. |
| 43j | `msgbuf_full_read` | OK | kern.msgbuf returns only 8 bytes (stub/filtered). boottime=0x6AD29A84. features=null UUID. No kptrs. |
| 43k | `cpuusage_deep` | KILLED | CpuUsage returns 0 with empty buffers (0-15 CPUs). mtypeprotect(585) consistently ret=1. Crashed during exec test. Syscall 620 alive. |
| 43l | `mincore_kaslr` | OK | mincore works on userland only. **All kernel VA probes return -1.** No KASLR oracle. 32GB (0x800000000) is mapped. |
| 43m | `sockopt_overflow` | OK | setsockopt accepts up to 4KB buffers but getsockopt returns correct 4B. Kernel clamps copy length. **Not an overflow.** |
| 43n | `hid_ioctl` | OK | /dev/hid opens (fd=23). All ioctls return Sony error 0x80740004. FIONREAD=0. /dev/null,zero,urandom open. /dev/bpf,crypto,pf blocked. |
| 43o | `afroute_kaslr` | INCONCLUSIVE | Socket opens, but the RTM_GET write returns -1; the read returned 108 bytes with zero detected pointers and unresolved attribution. No leak was validly tested and patch status is unknown. Retest 53b prepared. |
| 43p | `aio_bypass` | INCOMPLETE | Saved output stops immediately before the first standard AIO call, aio_error(317). Its result and the planned Sony syscall scan (including 663) are unknown. |
| 44a | mtypeprotect_exec | EXECUTION CLAIM NOT ESTABLISHED | The earlier run interpreted syscall returns as native execution; probe 45c recorded tested calls continuing after specific metadata mutations. No execution from the test page was independently demonstrated. |
| 44b | `sony557_deep` | OK | Syscall 557 returns 0x4205 only with buffer arg. Process type/sandbox query. No data in buffer. |
| 44c | `sockopt_heap_corrupt` | OK | No heap corruption. Kernel clamps copy to option size. 40 sprayed sockets unaffected. Not exploitable. |
| 44d | `kaslr_creative` | OK | NET_RT_IFLISTL returns 6.5KB (no kptrs). kern.usrstack=0x7EF5A8000. Signal handler=0x511FD8F4. All other paths blocked. |
| 45a | native_exec_kaslr | EXECUTION CLAIM NOT ESTABLISHED | No crash and an actual_len change were initially attributed to shellcode, but no controlled shellcode side effect was demonstrated; probe 45c later undermined the assumed dispatch path. |
| 45b | shellcode_write_diag | NO EXECUTION EVIDENCE | Tested return values stayed equal to the process ID and proposed shellcode writes did not land. These observations do not establish execution; probe 45c later showed tested calls persisting after metadata mutations. |
| 45c | execution_reality_check | EXECUTION THEORY CONTRADICTED FOR TESTED CALLS | Sysctl/getpid results persisted with NOP, invalid, null, or unmapped fn_addr values and after the tested chain entries were corrupted. This undermines the proposed dependency for those calls; the probe does not identify the complete dispatch implementation. Earlier native-execution and W^X interpretations are not established. |
| 46a | `sony_syscall_deep` | PARTIAL | Run 1 hit Lua 5.1's unsupported `%b` format option. Run 2 reached Section F and truncated during the 550–625 sweep; the ending call is unknown. Per-call markers and a sweep completion count are now added for a rerun. |
| 46b | loader_dispatch | PARTIAL | The log reports syscall objects sharing a metatable and a C-function __call at 0x311023aa0; it truncates at Section D. The function implementation and its relationship to the ROP-shaped metadata were not established. |
| 46d | `socket_bypass` | PARTIAL | **socketpair works via make_syscall** (ret=0). Socket creation identical between paths. SCTP still -1. TCP connect-back timed out (no server). |
| 46a | `sony_syscall_deep` (re-run) | OK | 557 struct-input returns include 1038/1039; 47a separately records a positive-version linear pattern and a special version-zero result. No 557 exploit was demonstrated; full semantics and exploitability remain unresolved. 620 returned 0 for tested inputs. Saved output truncates at the neighbor-sweep header. |
| 47a | `dispatch_deep` | PARTIAL | **Section C (CClosure write test) SKIPPED** — address parse bug (no 0x prefix). 557 version sweep: ver=0 returned 16901; tested positive versions followed 517+ver. No buffer modification. socketpair SCM_RIGHTS: cmsg zeros. LOCAL_PEERCRED: uid=1,gid=1. |
| 47b | `cclosure_hijack` | INCONCLUSIVE | Write loop covered offsets {16,24,32,40,48}; it did not test +0. The log conflicts about the +0 candidate and +16 result. Retest 53d prepared; no control-flow conclusion is established. |
| 48a | `sctp_ipv6_icmp` | OK | **★★ MASSIVE: SCTP raw socket OPEN (fd=22), IPv6 fully available (TCP/UDP/RAW/ICMPv6), 143 raw IPv4 protocols, 17 IPv6 raw protocols.** New kernel attack surface discovered. |
| 46c | `ip_options_listener` | PARTIAL | UDP listener + RAW socket on port 31338, IP_RECVOPTS set. **0 packets received** — PC-side injector not running. Needs coordinated PC+PS5 execution. |
| 48b | `sctp_loopback_fuzz` | OK | 39 SCTP chunk variants to loopback via raw IP+IP_HDRINCL. Send results and COMPLETE are recorded; input-handler processing is not independently established. INIT len=0/1/0xFFFF, SACK maxgaps, COOKIE garbage, 50 ABORTs, FWD_TSN — all survived. Deeper state-based attacks needed. |
| 48c | `ipv6_exthdr_fuzz` | OK | 83 IPv6 extension header variants to ::1. **No crashes, 0 send errors.** HBH overrun, RH Type 0 CVE, frag overlap/bomb, dest opts, 16-deep chain nesting, ICMPv6 option len=0, payload len mismatch — the log reaches COMPLETE. This does not establish complete handler coverage or general parser hardening. |
| 49a | `tcp_inject_loopback` | OK | **★★ TCP_INFO leaks SND_NXT (+108) and RCV_NXT (+112).** 182 injected TCP segments via raw IP to loopback ESTABLISHED connection. RST left the observed state ESTABLISHED; the log does not establish challenge ACK behavior. SACK, PAWS, option parser (len=0/255), URG, zero-window, FIN-data, ACK storm, SYN flood — **COMPLETE recorded**; complete handler coverage and RFC compliance are not established. Port fix: 31337 (original 44444 was ≥40000 blocked). |
| 49b | `ipv6_frag_reassembly` | OK | 280 IPv6 fragments across 12 attack categories targeting ip6_reass(). Teardrop, queue exhaustion (50 incomplete + 101-frag bomb), huge totals (65535/65592/65784), atomic frags, interleaved IDs (10 reverse-complete), ext hdr combos (HBH/RH/DO+frag, nested frag-in-frag), ICMPv6 frags — **COMPLETE recorded**; reassembly coverage and RFC 5722 compliance are not established. |
| 50a | `exotic_protocols` | OK | 86 packets across IGMP/GRE/ESP/AH/PIM/OSPF/VRRP + batch sweeps. **COMPLETE recorded.** This does not establish which protocol handler paths processed the packets or general robustness. |
| 50b | `timer_manipulation` | PARTIAL | Section A (keepalive) completed: TCP_KEEPIDLE/INTVL/CNT all blocked (ret=-1). SO_KEEPALIVE works. Write-after-peer-close ok. **Timed out after Section A** — later sections (linger, timeouts, buffer resize) not reached. |
| 50c | `resource_exhaustion` | PARTIAL | FD limit hit at 63 connections (sandbox cap). Backlog flood timed out (blocked on connect). Sections B-H not reached. |
| 50d | `cross_protocol_tunnel` | CRASH | **★ Consistently kills the loader.** 0 bytes, all subsequent probes fail until PS5 restart. Persistent loader corruption — not just per-connection crash. Needs debug. |
| 51a | `sony_syscall_survey` | PARTIAL | Tested ~55 of 110 Sony syscalls (532-676). **7 accessible: 596, 572, 624 (ret=3377!), 563-566.** Output truncated before completing range. No crashes. |
| 51b | `accessible_syscall_deep` | OK | Tested 30 call patterns. 585, 606, 643, and 640 return non-error results for supplied arguments; output buffers contain no observed kernel pointers. 624 differs by one from 51a; two samples do not establish a counter or side channel. See [cross-firmware pattern research](CROSS_FIRMWARE_PATTERN_RESEARCH.md). |
| 51c | `sony_survey_part2` | PARTIAL | Saved output records only 625 and 626 (both -1). The raw log does not show syscall 661 being called, so no kill boundary or result for 661 is established. |
| 52a | survey_627_676 | CRASH | 627-630 all PCALL-FAIL, **sys 631 killed the process**. Only 5 syscalls tested before crash. (2026-10-18) |
| 52b | 624_oracle | OK | **★★ sys 624 = VM operation counter.** +5 per mmap (size-independent), does not decrement on munmap. Zero jitter across 100 samples. Unaffected by sockets/kqueue/memory.alloc. Monotonic budget meter. (2026-10-18) |
| 53a | `aio_retest` | PREPARED — NOT RUN | Resumable per-call AIO matrix; records return values and Lua errors separately. |
| 53b | `afroute_retest` | PREPARED — NOT RUN | Rebuilds RTM_GET with three header sizes; rejects request echoes and reports failed writes as undelivered. |
| 53c | `kldstat_retest` | PREPARED — NOT RUN | Tests syscall candidates 308/367 and kldsym 337 with before/after markers and bounded output inspection. |
| 53d | `cclosure_retest` | OK | Qword offsets 0/8/16/24/32/40/48 were writable and restored successfully. +0x30 was observed holding an eboot-range pointer; the dispatch-consumed field and any control-flow effect remain unresolved. |
| 54a | `dsp_access_check` | OK | Two console runs; `/dev/null` positive control opened and closed, while `/dev/dsp`, `/dev/dsp0.0`, and `/dev/sndstat` returned all-ones failure values. No errno; absence vs denial unresolved. No mmap/ioctl/overflow test. See [CVE-2026-45258 PS5 assessment](CVE-2026-45258-PS5-14.10.md). |
| 54o | `cfunc_redirect_controlled` | INCOMPLETE | Capture stops after the `type()` C-function field write, before the redirected call returns. No post-call value, restore marker, or execution conclusion. See `results/54o_cfunc_redirect_controlled_20261018_092721.txt`. |
| 54p | `redirect_minimal` | INCOMPLETE | Clean no-watchdog retest at 09:43:26 reached the gadget address, then idled after 394 bytes; it did not reach the `write ok` marker or the redirected call. Earlier runs reset or idled before output. No execution conclusion. See the timestamped captures under `results/phase14_final_push/`. |
| 54q | `cfunc_redirect_return1` | INCOMPLETE | After a clean restart, the one-result C-function redirect reached `[B] Alternate pointer write BEFORE` and idled at 09:45:51 before the post-write marker. This isolates the current boundary to the attempted `+0x20` change; no redirected call or native-execution conclusion was recorded. |
| 54r | `cfunc_code_bytes` | OK | **★★★ All 7 C functions' +0x20 targets start with `push rbp; mov rbp, rsp` (0x55489345).** Confirms +0x20 points to real x86-64 C function code in eboot RX .text. Combined with 55g, establishes +0x20 as the dispatch pointer. (2026-10-18) |
| 55g | `cclosure_write_diagnostic` | CRASH | **★★★ BREAKTHROUGH: +0x20 IS the C function dispatch pointer.** Writing +1 to low dword caused immediate garbage output + crash (redirected execution to misaligned address). No-op writes to all offsets instant. Different-value writes to +0x00, +0x18 instant and harmless. Only +0x20 controls dispatch. CClosure lives in SceLibcHeap (prot=0x3 RW). (2026-10-18) |
