# Probe Index — PS5 14.10

Every probe sent to the PS5, with status and key result.

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
| 19 | `aio_stress` | CRASH | AIO stress — all AIO syscalls sandbox-killed |
| 19b | `aio_safe` | OK | Confirmed AIO completely blocked |
| 19c–g | `aio_*` | VARIOUS | Progressive AIO isolation (all dead) |
| 20 | `kqueue_stress` | OK | kqueue fd allocates, kevent blocked |
| 21 | `kqueue_deep` | OK | Deep kqueue — confirmed kevent always -1 |
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
| 29 | `rthdr_mmap` | CRASH | IPv6 routing header + mmap — crash (msync or shm_open) |
| 30 | `mmap_fcntl_deep` | CRASH | mmap+fcntl deep — crashed on msync or minherit |
| 30b | `fcntl_scm` | OK | **writev works** (IOV_MAX=1024), **SCM_RIGHTS validated** (5/5 correct), F_SETFL returns -1 but changes flags, pipe2 blocked |
| 30c | `fcntl_bypass` | OK | **F_SETFL is cosmetic only** — flags appear set but kernel ignores them. F_SETOWN truly blocked. poll() works. kqueue fd allocates but kevent -1. |
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
| 38 | `untested_syscalls` | CRASH | **ktimer_create/settime WORK** (timers are live kernel objects!), memfd stub, getrandom/ppoll/cap_rights blocked. Died at **minherit = probe-30 killer identified**. |
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
| 41z | `chain_hijack` | OK | **ROP chain hijack confirmed**: chain, fn_addr, and arg slots writable from heap |
| 42a | `ktimer_deep` | OK | Clocks 0+4 usable; **validation correct** (nsec>1e9/-1/2^63 rejected); gettime/delete blocked while settime works (odd split); cap=27 timers. |
| 42a | `kernel_rw` | OK | Dense sysctl read: FreeBSD r230171, securelevel=1024, 16KB pages. kenv = instant kill |
| 42b | `memfd_msync` | CRASH | memfd returns fake fd=1 (stub). **msync = instant kill** (second probe-30 killer confirmed). |
| 42b | `kaslr_defeat` | OK | sysctl kinfo_proc +0x60 has 0xFFFFFFFF00000000 (sentinel/flag); TCB FS base is userland (0x88xxxxxxx) |
| 42c | `kaslr_deep` | OK | Dense kinfo_proc and fstat dumps confirm sentinels (0xFFFFFFFF_*); /dev/dmem0 and /dev/hid open at fd=24 |
| 42d | `dmem_kaslr` | OK | /dev/dmem0 ioctls/allocations fail; proc.filedesc and kstack blocked |
| 42e | `sysctl_enum` | OK | MIB tree walking: non-leaf node queries blocked by sandbox |
| 42f | `ps5_syscall_scan` | OK | Probed 576–619: mtypeprotect(585) ret=1, getCpuUsage(617) ret=0; memory queries fail |
| 42f | `kernel_phys_scan` | OK | /dev/dmem0 physical scan: offset 0x0 yields 0x80000000_C0012800 (GPU HW status) |
| 42f2 | `fast_phys_scan` | OK | Scanned 90 physical offsets: only phys 0 is non-zero |
| 42g | `fnaddr_dump` | OK | Dumped fn_addr target code across multiple module bases |
| 42g | `rop_kptr_leak` | PARTIAL | Physical memory deep scan: failed on undefined MB variable (fixed) |
| 42g2 | `high_phys_decode` | CRASH | Called kenv (390) -> instant sandbox kill |
| 42g3 | `high_phys_only` | OK | 4GB+ physical address scan: all zeros (no CPU DRAM accessible via dmem0) |
| 42g4 | `minimal_high` | OK | Physical scan of 4GB, 4.5GB, and PS5 hardware ranges: confirms dmem0 is GPU-only |
| 42h | `code_dump` | OK | Code dump of fn_addr target |
| 42h | `rop_exploit` | OK | Located ROP chain candidate in heap relative to GPU mmap |
| 42h2 | `rop_exploit2` | OK | Identified and mapped 13 argument slots in active ROP chain; sysctl proc.all/file blocked |
| 42i | `vmquery` | OK | virtualQuery/jitCreateShared blocked; mincore works (vec=0x1F); dumped 39 module text ranges |
| 42i | `chain_analysis` | OK | **Full ROP chain decoded**: 0x300-byte structure, arg loading pattern (pop rax, deref, pop rdi, write), stack pivot at eboot+0x9A2 |
| 42j | `thread_ptrace` | OK | thr_self works (TID=101819); procctl blocked; libkernel data scanned (no kptrs) |
| 43a | `kldstat_kaslr` | KILLED | kldstat (308) = **sandbox kill**. KLD introspection blocked at kernel level. |
| 43b | `kldsym_resolve` | KILLED | kldsym (337) = **sandbox kill**. Kernel symbol resolution blocked. |
| 43c | `sysarch_gsbase` | OK | GET_GSBASE=0 (no kernel ptr). GET_FSBASE=userland TCB. GET_XFPUSTATE=ret 0. |
| 43d | `kinfo_proc_full` | OK | Full 1096B dump: only `0xFFFFFFFF_00000000` at +0x60 (sentinel). Process="boot.bin". FILEDESC blocked. VMMAP ret=-1. |
| 43e | `blocked_syscall_bypass` | PARTIAL | **fstat works** via make_syscall (no kptrs). ioctl=-1 even raw. dup/dup2=-1. **thr_new crashed** (still blocked). |
| 43f | `sysctl_write` | OK | All write paths blocked. securelevel/coredump/maxproc all ret=-1. somaxconn=1024 readable only. |
| 43g | `sony_syscall_sweep` | KILLED | **Syscall 557 returns 16901** (live Sony syscall!). Syscall 620 ret=0. Process killed mid-sweep. |
| 43h | `mtypeprotect_wxbypass` | OK | mtypeprotect returns 1 for ALL prot values (RWX, RX, X). Page still RW after call. mprotect(RX) still -1. **Execution not tested.** |
| 43i | `fn_redirect` | OK | **★ CRITICAL: fn_addr + slot0 writes PERSIST** across ROP calls. Chain does NOT rebuild them. Arbitrary function call primitive confirmed. |
| 43j | `msgbuf_full_read` | OK | kern.msgbuf returns only 8 bytes (stub/filtered). boottime=0x6AD29A84. features=null UUID. No kptrs. |
| 43k | `cpuusage_deep` | KILLED | CpuUsage returns 0 with empty buffers (0-15 CPUs). mtypeprotect(585) consistently ret=1. Crashed during exec test. Syscall 620 alive. |
| 43l | `mincore_kaslr` | OK | mincore works on userland only. **All kernel VA probes return -1.** No KASLR oracle. 32GB (0x800000000) is mapped. |
| 43m | `sockopt_overflow` | OK | setsockopt accepts up to 4KB buffers but getsockopt returns correct 4B. Kernel clamps copy length. **Not an overflow.** |
| 43n | `hid_ioctl` | OK | /dev/hid opens (fd=23). All ioctls return Sony error 0x80740004. FIONREAD=0. /dev/null,zero,urandom open. /dev/bpf,crypto,pf blocked. |
| 43o | `afroute_kaslr` | OK | AF_ROUTE socket opens (fd=22). RTM_GET returns 108B. **Zero kernel pointers — info leak patched.** Relapse KASLR technique dead on 14.10. |
| 43p | `aio_bypass` | KILLED | aio_error(317) via make_syscall = **instant kill**. AIO sandbox is kernel-level, not resolve()-side. |
| 44a | `mtypeprotect_exec` | OK | **★★★ W^X DEFEATED!** mtypeprotect(RWX) grants execute. NOP sled + direct syscall both execute from mmap'd page. Native code execution confirmed. |
| 44b | `sony557_deep` | OK | Syscall 557 returns 0x4205 only with buffer arg. Process type/sandbox query. No data in buffer. |
| 44c | `sockopt_heap_corrupt` | OK | No heap corruption. Kernel clamps copy to option size. 40 sprayed sockets unaffected. Not exploitable. |
| 44d | `kaslr_creative` | OK | NET_RT_IFLISTL returns 6.5KB (no kptrs). kern.usrstack=0x7EF5A8000. Signal handler=0x511FD8F4. All other paths blocked. |
| 45a | `native_exec_kaslr` | PARTIAL | Code executes (no crash), but buffer writes don't land — all results are sentinel. `actual_len` changed in sysctl test (syscall DID fire). Need to fix buffer address encoding in shellcode. |
| 45b | `shellcode_write_diag` | OK | **Return value is ALWAYS pid regardless of eax.** Memory writes from shellcode all fail. Register oracle returns pid for every register. Shellcode execution may be illusory — chain may not actually call our code. |
