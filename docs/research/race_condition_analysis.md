# Multi-Process Race Condition Analysis — PS5 14.10

## Premise

Each TCP connection to port 9026 spawns a **new process** with fresh ASLR. While we cannot create threads (fork/rfork/thr_new all blocked), we CAN have multiple simultaneous TCP connections, giving us **multiple concurrent processes**. These processes share the kernel's global data structures and can interact via loopback networking.

## What Two Processes Can Share

| Shared Kernel Object | How | Status |
|----------------------|-----|--------|
| TCP PCB hash table | Both processes create TCP sockets on same ports | Confirmed working |
| Routing table | AF_ROUTE sockets, connect() | Confirmed working |
| Loopback interface state | Raw socket injection, TCP/UDP | Confirmed working |
| Zone/slab allocator state | Any allocation-heavy syscall | Implicit |
| ktimer subsystem | ktimer_create (clock 0/4) | Confirmed working |
| Socket buffer pools (mbufs) | Network I/O | Implicit |
| Port binding table (in_pcbinfo) | bind()/connect() | Confirmed working |

**Cannot share:** File descriptors (no fork, no SCM_RIGHTS across process boundary without AF_UNIX bind which likely requires filesystem access), shared memory (shm_open crashes), pipes (blocked).

## Race Condition Attack Vectors

### Vector 1: TCP PCB Hash Table Race (HIGHEST PRIORITY)

**Background:** FreeBSD's TCP implementation uses a hash table (`tcbinfo.ipi_hashbase`) to look up connections by source/dest IP+port. Operations on this table (insert, remove, lookup) are protected by `INP_INFO_WLOCK`. In FreeBSD r230171 (2012-era), the locking granularity was coarser but the race windows were also wider.

**Attack:** Two processes rapidly create and destroy TCP connections on the same port pair:
- Process A: `bind(31337)` + `listen()` + tight loop of `accept()` + `close(accepted_fd)`
- Process B: tight loop of `connect(127.0.0.1:31337)` + `close()`

**Race window:** When Process B closes its socket, the kernel removes the PCB from the hash table. If Process A is simultaneously in `accept()` looking up the same PCB, it may get a reference to a PCB that is being freed. This is a classic use-after-free pattern.

**Why it might work on PS5 14.10:** 
- FreeBSD r230171 predates many TCP locking improvements from FreeBSD 11+
- The PS4-compat sandbox may not have the same locking patches as mainline
- Sony's custom socket options (0x2000, 0x10000, etc.) add code to socket paths that may not be lock-safe

**Crash indicators:** SIGSEGV in tcp_input, panic on freed memory access, corrupted PCB fields.

### Vector 2: SO_REUSEADDR Bind Race

**Attack:** Both processes try to `bind()` the same port with `SO_REUSEADDR` set simultaneously.

**Race window:** The kernel checks whether the port is in use, then inserts into the binding table. If both checks pass before either insert completes, both processes get bound to the same port. Subsequent operations (listen, accept) on the double-bound port hit unexpected state.

**Variant:** One process binds, the other connects. The connector's `close()` + FIN puts the server-side into TIME_WAIT. The server immediately unbinds and rebinds. The TIME_WAIT entry and the new binding may reference the same PCB hash bucket, creating a dangling pointer when the TIME_WAIT expires.

### Vector 3: Loopback Packet Storm + munmap Race

**Attack:** 
- Process A: maps GPU memory, starts receiving raw packets into the mapped region
- Process B: sends a flood of crafted packets to Process A
- Process A: races `munmap()` against incoming packet delivery

**Race window:** The kernel's `sosend()`/`soreceive()` path copies data to/from userspace buffers. If `munmap()` removes the mapping while the kernel is mid-`copyout()`, the kernel may write to freed page table entries.

**Why it's interesting:** We have GPU mmap which creates large (256+ page) heap regions. The kernel's `vm_fault` handler for these Sony-custom GPU mappings may have different locking than standard anonymous pages.

### Vector 4: ktimer Expiry During Syscall (LOW PRIORITY)

**Attack:** One process creates 27 ktimers (the confirmed max) all set to expire simultaneously. The other process is mid-syscall (e.g., a blocking `accept()` or `poll()`). Timer signal delivery during syscall restart is a classic source of EINTR-related bugs.

**Limitation:** Timers are per-process, so this only races within a single process. The multi-process angle would be: Process A has timers firing while Process B connects to A's listening socket, creating a three-way race between timer delivery, accept(), and the incoming SYN.

### Vector 5: accept() + RST Race (MOST PRACTICAL)

**Attack:**
- Process A: listens on port 31337
- Process B: connects to 31337, immediately sends RST (via SO_LINGER with linger=0, then close)

**Race window:** The SYN arrives, kernel creates a nascent TCB in the listen queue. The RST arrives and the kernel begins destroying the TCB. If `accept()` dequeues the TCB between the RST reception and the TCB cleanup, the returned socket fd references a partially-destroyed control block.

**This is the Probe 52b attack.** It is the simplest to implement and has the highest historical success rate on FreeBSD.

## Coordination Protocol

Since the two processes cannot share fds or memory, they coordinate via TCP timing:

1. **Setup (Process A)** starts first, binds port 31337, listens, then enters accept loop
2. **Worker (Process B)** starts ~1 second later, connects to 31337 in a tight loop
3. Coordination is implicit: B connects, A accepts. The race is in the teardown timing.
4. Both processes report results via `print()` to their respective TCP connections

## Implementation: Probe 52b

**52b_race_setup.lua** — The listener/acceptor. Creates a TCP listener on 31337, then rapidly accepts and closes connections. Also probes accepted socket state for anomalies.

**52b_race_worker.lua** — The connector/closer. Rapidly connects to 31337 with SO_LINGER(0) and immediately closes, sending RST. Also tries to read/write on sockets in various states to hit unusual kernel paths.

## Expected Outcomes

| Outcome | Meaning |
|---------|---------|
| Both probes complete normally, no anomalies | Race window too narrow, or kernel locking is sound |
| Process A crashes (SIGSEGV) | Kernel dereferences freed TCB — potential UAF |
| accept() returns fd with unexpected state | Partial TCB destruction visible from userland |
| getsockopt on accepted fd returns garbage | Kernel reading freed memory — info leak |
| Connection counter mismatch | Kernel dropped or duplicated connections — state corruption |

## FreeBSD r230171 Specific Considerations

This kernel is from 2012. Known issues in that era:
- `tcp_close()` and `in_pcbfree()` had race conditions fixed in later FreeBSD versions
- `so_pcb` was sometimes accessed without proper locking after `sofree()`
- TIME_WAIT recycling had multiple CVEs through FreeBSD 10-11 era
- The syncache (SYN cookie) implementation had bugs fixed in 2013-2014

## Risk Assessment

- **Crash risk:** MODERATE. The race targets connection teardown, not kernel panics. Worst case is the loader process crashes (not the kernel).
- **Kernel panic risk:** LOW but non-zero. If we hit a real UAF and the freed memory is reallocated to a different kernel object, we could trigger a type confusion that panics.
- **Success probability:** ~15-25%. This is a real technique but modern FreeBSD has mitigations. The PS5's 2012-era FreeBSD base is more likely to have these bugs, but Sony may have backported fixes.
