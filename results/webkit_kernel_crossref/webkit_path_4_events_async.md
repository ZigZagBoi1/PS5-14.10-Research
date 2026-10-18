# WebKit Path Analysis 4: Event Subsystem and Async/Threading Pathways

## Cross-Reference: Kernel Syscalls 669/670/558 vs WebKit Threading/Event Primitives

---

## Executive Summary

WebKit's Worker threads and event loop on PlayStation do NOT directly invoke Sony's custom event syscalls (669, 670, 558) at the WebKit source level. However, the pathway from JavaScript to kernel event vulnerabilities exists through **two indirect but exploitable routes**:

1. **POSIX threading primitives (pthread_mutex/pthread_cond) underlie all WebKit synchronization** -- on PS5's FreeBSD-derived kernel, these are implemented via `_umtx_op` syscalls which share kernel infrastructure with Sony's event subsystem
2. **IPC socket monitoring on PlayStation uses `select()` in a dedicated thread** -- this is a direct kernel event notification surface reachable from any Worker's `postMessage()` call

The critical finding: **sys 670's cross-process event manipulation (confirmed no privilege check in VERIFIED_FINDINGS.md item 12) could interfere with the WebKit process's own event state**, since the browser process's event table at `proc+0xc48` is accessible to any process that knows the PID.

---

## Part 1: Kernel-Side Event Syscalls (Summary from RE)

### sys 669 -- AIO Submission Interface
- **Role**: Asynchronous read/write request submission (`_aio_submit_cmd`)
- **Key structures**: Typed handle 0x160, queue entries, AIO contexts
- **Process binding**: Gets process from `td+0x8`, handle table from `proc+0xc48`
- **Worker threads**: Creates `SceAIO` and `SceFsstAIO` worker threads at context+0x4b0/+0x528
- **Vulnerability relevance**: AIO workers run with saved submitter credentials; credential swap at +0x31d5 means AIO requests execute as the submitting process

### sys 670 -- AIO Policy Init + Cross-Process Event Debug
- **Role**: `__aio_init` policy configuration + debug query interfaces
- **Critical sub-handler at +0x480** (`_get_aio_debug_submit_info`):
  - Takes PID as argument, performs process lookup with mode 0x15
  - Accesses `target_proc->0xc48` (event/handle namespace) directly
  - Enumerates typed 0x160 objects and copies out {id, state, class, operation} records
  - **NO privilege check, NO credential comparison** -- only validates slot_index <= target_proc->event_max
  - CONFIRMED DEFINITIVE in VERIFIED_FINDINGS.md
- **Second sub-handler at +0x7c0** (`_get_aio_debug_request_info`):
  - Similar cross-process access pattern
  - Returns FD, byte count, I/O offset for active requests
  - Can enumerate another process's file descriptors through AIO state

### sys 558 -- Event Flag / Object Deletion
- **Role**: Process-local handle/named-object deletion
- **Mechanism**: Reads 32-bit ID + 16-bit type selector from userspace, ORs type with 0x1000, performs namespace lookup at `proc+0xc48`, detaches and frees
- **No local priv_check visible** -- access control may reside in namespace lookup semantics
- **Neighbors**: High-resolution timer subsystem, HID/mouse processing (separate code, not reachable from syscall entry)

### VERIFIED_FINDINGS.md Relevant Items
- **KASLR bypass via pointer obfuscation (sys 661/662/668)**: `f(x) = x ^ (x >> 4)` -- trivially invertible, leaks kernel heap pointers
- **Stack clash (sys 661/662)**: 32-bit vs 64-bit arithmetic mismatch in stack allocation, count=0x40000001 allocates ~19 bytes but copyin writes ~4GB
- **Non-atomic refcount (sys 664/665/666)**: `decl (%rax)` WITHOUT LOCK prefix; exploitability depends on whether outer mutex serializes access
- **Cross-process event manipulation (sys 670)**: PID-based process lookup with NO privilege check to access target event table

---

## Part 2: WebKit Threading Architecture on PlayStation

### Event Loop Selection
PlayStation falls into the `USE(GENERIC_EVENT_LOOP)` path in `PlatformUse.h` (line 245):
```
// Not GLIB, not Windows, not Cocoa -> generic
#define USE_GENERIC_EVENT_LOOP 1
```

**Generic RunLoop implementation** (`RunLoopGeneric.cpp`):
- Uses `WTF::Lock` (backed by `WTF::ParkingLot`) and `WTF::Condition` for all synchronization
- `Condition::m_readyToRun` is the core wake-up mechanism
- Timer scheduling via `RedBlackTree<ScheduledTask, MonotonicTime>`
- `wakeUpWithLock()` calls `m_readyToRun.notifyOne()` -- this is the fundamental event delivery mechanism

### WTF::Lock and ParkingLot -- The Kernel Interface
**WTF::Condition** (Condition.h) delegates to **ParkingLot::parkConditionally()** for thread parking/unparking. ParkingLot itself uses:
- `WTF::Mutex` (backed by `pthread_mutex_t`)
- `WTF::ThreadCondition` (backed by `pthread_cond_t`)

**On PS5 (FreeBSD-derived)**, pthread_mutex and pthread_cond are implemented via:
- `_umtx_op()` system call (FreeBSD standard)
- This shares kernel locking infrastructure with Sony's event subsystem
- The Mutex class has a **PlayStation-specific constructor** (`PLATFORM(PLAYSTATION)` guard at ThreadingPrimitives.h:77-78), suggesting Sony may have customized mutex initialization

### Worker Thread Architecture

**Worker creation chain**:
1. JavaScript `new Worker("script.js")` -> `Worker::create()` -> `WorkerMessagingProxy::startWorkerGlobalScopeByUrl()`
2. `WorkerOrWorkletThread::start()` -> `createThread()` (creates a real OS thread via `pthread_create`)
3. Thread entry: `WorkerOrWorkletThread::workerOrWorkletThread()` -> `runEventLoop()` -> `WorkerDedicatedRunLoop::run()`

**Worker message passing** (`postMessage`):
1. Main thread: `WorkerMessagingProxy::postMessageToWorkerGlobalScope()` serializes message
2. Posts task to `WorkerDedicatedRunLoop` via `m_messageQueue.append()`
3. Worker thread wakes from `m_messageQueue.waitForMessageFilteredWithTimeout()`
4. The wake-up goes through: `MessageQueue` -> `Condition::notifyOne()` -> `ParkingLot::unparkOne()` -> `pthread_cond_signal()` -> **kernel `_umtx_op()` syscall**

**Worker -> Main thread**:
1. `WorkerMessagingProxy::postMessageToWorkerObject()` calls `m_scriptExecutionContext->postTask()`
2. This dispatches to `RunLoop::main().dispatch()` which calls `RunLoop::wakeUp()`
3. Wake-up: `m_readyToRun.notifyOne()` -> `ParkingLot` -> `pthread_cond_signal()` -> **kernel**

### WorkQueue (Generic Implementation)
On PlayStation, `WorkQueueGeneric.cpp` shows WorkQueues are built on top of `RunLoop::create()`, which creates a new thread with its own generic RunLoop. All dispatch goes through the same Lock/Condition/ParkingLot chain.

---

## Part 3: IPC and Cross-Process Communication

### PlayStation Process Architecture
WebKit on PS5 uses multi-process architecture with separate executables:
- `/app0/WebProcess.self` -- Web content (renders pages, runs JS)
- `/app0/NetworkProcess.self` -- Network I/O
- `/app0/GPUProcess.self` -- GPU operations

**Process launching** (`ProcessLauncherPlayStation.cpp`):
- Uses Unix domain sockets (`socketpair` via `IPC::createPlatformConnection()`)
- Socket type: `SOCK_STREAM` (explicitly selected for PlayStation, line 57-58)
- Buffer sizes: 32KB send/receive
- Process spawned via `PlayStation::launchProcess()` with socket FD passed

### PlayStation IPC Socket Monitoring
**Critical finding** in `ConnectionUnix.cpp` (lines 364-382):

```cpp
#if PLATFORM(PLAYSTATION)
    m_socketMonitor = Thread::create("SocketMonitor", [protectedThis] {
        {
            int fd;
            while ((fd = protectedThis->m_socketDescriptor) != -1) {
                int maxFd = fd;
                fd_set fdSet;
                FD_ZERO(&fdSet);
                FD_SET(fd, &fdSet);

                if (-1 != select(maxFd + 1, &fdSet, 0, 0, 0)) {
                    if (FD_ISSET(fd, &fdSet))
                        protectedThis->readyReadHandler();
                }
            }
        }
    });
```

PlayStation creates a **dedicated SocketMonitor thread** that blocks on `select()` waiting for IPC data. This thread:
- Runs in the WebProcess (which executes JavaScript)
- Blocks on `select()` which is a kernel event notification syscall
- On PS5's FreeBSD kernel, `select()` uses the kernel's file descriptor readiness notification infrastructure
- This is a **separate thread from Worker threads** but shares the same process event namespace at `proc+0xc48`

### Memory Allocation
PlayStation uses Sony's proprietary `memory_extra::vss` (Virtual Storage Service) for all OS-level memory allocation (`OSAllocatorPlayStation.cpp`). This is separate from the standard FreeBSD `mmap`/`munmap` and may use Sony-specific VM syscalls (potentially sys 588 DMEM).

---

## Part 4: Attack Surface Analysis

### Path 1: Worker postMessage -> Kernel Lock Primitives [INDIRECT]
**Chain**: `postMessage()` -> `MessageQueue` -> `Condition::notifyOne()` -> `ParkingLot::unparkOne()` -> `pthread_cond_signal()` -> kernel `_umtx_op()`

**Vulnerability exposure**: The non-atomic refcount bug in sys 664/665/666 (`decl (%rax)` without LOCK prefix) affects kernel event objects. If `_umtx_op` and Sony event syscalls share reference-counted kernel objects, a race between Worker thread synchronization and a concurrent event manipulation could trigger the non-atomic decrement. However, this requires concurrent access from multiple kernel paths to the same object, which Worker synchronization alone may not provide.

**Assessment**: LOW-MEDIUM. The path exists but the umtx and Sony event subsystems likely use separate refcounted objects.

### Path 2: Cross-Process Event Manipulation via sys 670 [HIGH]
**Chain**: From any process -> `sys 670` (+0x480 debug interface) -> enumerate WebProcess event handles -> read AIO state including file descriptors

**What an attacker can learn**:
- The WebProcess PID (observable, or obtainable via other syscalls)
- All typed 0x160 (AIO) objects in the WebProcess's handle table
- Active I/O operations including file descriptors, byte counts, and offsets
- Via +0x7c0: individual request details for any AIO operation

**What an attacker could do**:
- Monitor the WebProcess's AIO activity in real-time
- Detect when the browser is performing specific I/O (loading scripts, saving state)
- Combined with KASLR bypass from sys 661/662/668: correlate AIO object addresses with kernel heap layout

**Assessment**: HIGH. The debug interfaces at sys 670+0x480 and +0x7c0 provide a read primitive into another process's kernel state without privilege checks. This is directly useful for understanding the WebProcess's internal state from a compromised Worker context or from the Lua loader process.

### Path 3: IPC Socket Monitor Thread as Timing Oracle [MEDIUM]
**Chain**: Worker `postMessage()` -> IPC dispatches to NetworkProcess -> `select()` blocks/unblocks in SocketMonitor thread -> timing observable from Worker

The dedicated SocketMonitor thread on PlayStation (absent on other platforms which use GLib or generic dispatching) creates a thread whose blocking behavior on `select()` is correlated with IPC traffic. A Worker thread running a timing loop can observe:
- When the main thread sends/receives IPC messages (by observing scheduling effects)
- Network request completion timing
- GPU process synchronization

**Assessment**: MEDIUM. Useful for timing side-channels but not a direct kernel exploitation path.

### Path 4: Worker Thread + Event Object Handle Confusion [SPECULATIVE]
If Worker threads internally create kernel event objects (through pthread operations that use Sony event flags), and sys 558 allows deletion of those objects by ID without proper authorization, a crafted syscall could destroy synchronization primitives underneath active Worker threads, causing use-after-free in kernel space.

**Assessment**: SPECULATIVE. Requires confirming that pthread operations on PS5 create objects in the typed handle namespace at `proc+0xc48`, which cannot be determined from the open-source WebKit code alone.

### Path 5: AIO from Worker fetch() Operations [MEDIUM-HIGH]
When a Worker calls `fetch()`, the request travels:
1. Worker thread -> IPC to NetworkProcess
2. NetworkProcess performs actual I/O (potentially using kernel AIO via sys 669)
3. Response comes back via IPC

If the NetworkProcess uses Sony's AIO subsystem (sys 669) for disk or network I/O, then:
- sys 670 debug interfaces can enumerate NetworkProcess AIO operations
- The stack clash vulnerability in sys 661/662 could be triggered if the NetworkProcess also uses Sony event syscalls
- The credential-saving mechanism in AIO workers (identity saved at submission, restored at execution) means AIO requests carry the submitting process's credentials

**Assessment**: MEDIUM-HIGH. Requires confirming NetworkProcess uses AIO, but the AIO subsystem is designed for asynchronous I/O which is exactly what a network process needs.

---

## Part 5: Practical Exploitation Implications for p146/p203

### p146: Worker-Based Polling
The probe confirms Workers run on separate threads and can observe main thread state. From the WebKit source analysis:
- Workers use `WorkerDedicatedRunLoop` with its own `MessageQueue` backed by `Condition`/`ParkingLot`
- Worker threads are real pthreads with their own kernel scheduling state
- Workers can run tight loops without blocking the main thread
- The `WorkerSharedTimer` allows Workers to set up timed callbacks independent of the main thread

**New finding**: Worker `postMessage()` goes through `RunLoop::main().dispatch()` which touches the generic RunLoop's `m_nextIterationLock` and `m_readyToRun` condition variable. These are kernel-mediated synchronization points. A Worker doing rapid `postMessage()` calls creates rapid kernel lock/unlock cycles that could race with kernel event manipulation from another process via sys 670.

### p203: setTimeout + throw for Overflow Control
The overflow exploit uses timing control via `setTimeout`. In WebKit:
- `setTimeout` in a Worker is handled by `WorkerSharedTimer` -> `ThreadTimers`
- Timer resolution depends on the generic RunLoop's `MonotonicTime` precision
- The timer fires through the Worker's event loop: `m_sharedTimer->fire()` in `WorkerDedicatedRunLoop::runInMode()`

**Key insight**: The Worker's timer system is completely isolated from the main thread's timer system. This means timing attacks from Workers cannot be detected or throttled by the main thread's event loop.

---

## Part 6: Missing PlayStation-Specific Code

### What the Open-Source WebKit-1200 Does NOT Contain
The following are referenced but their implementations are in Sony's proprietary libraries (not in the open-source WebKit):
1. `<process-launcher.h>` -- `PlayStation::launchProcess()`, `PlayStation::terminateProcess()`
2. `<memory-extra/vss.h>` -- Sony's Virtual Storage Service (memory allocation)
3. `<EnvVarUtils.h>` -- Environment variable utilities
4. PlayStation Mutex constructor (non-default, PLATFORM(PLAYSTATION) specific)
5. Network stack implementation (likely uses libcurl or Sony proprietary)
6. The actual `select()`/`poll()` kernel implementation on PS5

### Implications
The most critical missing piece is the **pthread implementation on PS5**. If Sony's pthread library uses their custom event syscalls (669/670/558) instead of or in addition to standard FreeBSD `_umtx_op`, then EVERY WebKit Lock/Condition operation becomes a direct interface to the vulnerable event subsystem. This cannot be determined from open-source code alone and requires runtime analysis on actual PS5 hardware.

---

## Conclusions

### Direct Path: NO
WebKit source code does not directly call Sony event syscalls (669, 670, 558). No `sceKernel*Event*` APIs appear anywhere in the codebase.

### Indirect Paths: YES, Multiple

1. **sys 670 cross-process debug interface**: Can enumerate any process's AIO handle table without privilege checks. An attacker process can read the WebProcess's or NetworkProcess's kernel event state, providing information disclosure about browser I/O operations.

2. **pthread -> kernel event infrastructure**: All WebKit synchronization (Worker threads, RunLoop, WorkQueue, IPC) ultimately goes through pthread_mutex/pthread_cond which are kernel-mediated. On PS5, these may share kernel infrastructure with Sony event syscalls.

3. **PlayStation IPC SocketMonitor thread**: Creates a dedicated thread blocking on `select()` -- a kernel event notification surface that could be influenced by cross-process event manipulation.

4. **AIO in NetworkProcess**: If the NetworkProcess uses sys 669 for async I/O, all network fetches (including from Workers) indirectly generate AIO kernel objects vulnerable to the documented issues.

---

## Part 7: Cross-Agent Findings Integration

### From IPMI/IPC Agent (sys 622)
- IPMI dispatcher has explicit event/async handling with async vs sync response tables
- IPMI request marshaller includes event-kind processing with CFI-guarded callbacks
- IPMI is a SEPARATE IPC mechanism from WebKit's socket-based IPC but shares the same kernel infrastructure
- Post-exploit: attacker could subscribe to system events via IPMI that are normally handled by Sony libraries (NetworkControl, WebSecurity)

### From Process/Memory Agent (sys 601, 588, 639)
- **SharedArrayBuffer Gigacage is DISABLED on PS5** -- SAB backing stores are uncaged heap memory
- SharedArrayBuffer growth uses `mprotect` to change page permissions (PROT_NONE -> PROT_READ|PROT_WRITE)
- **Workers sharing SABs operate on regular heap memory accessible from all threads**
- Combined with non-atomic refcount (sys 664/665/666): race condition between Worker memory operations and kernel event handling
- p146 probe proves cross-allocation corruption is happening (all 14 strings corrupted)

### From GPU/Canvas Agent (sys 643, 653, 648)
- **Sony display API uses event posting/waiting**: `canvas::CanvasUtil::setPostEvent()` / `waitPostEvent()` -- these likely wrap sys 669/670 event primitives
- **VBlankMonitor**: Sony-proprietary vsync monitor (`VBlankMonitor::create()`) -- if this uses event syscalls, every composited page touches the event system
- GPU sync happens on a **DETACHED thread** (`std::thread t(...); t.detach()`) -- asynchronous GPU finish events
- **CallbackQueuePlayStation**: Async video decode event callbacks from GPU to compositor
- **EGL fence sync** via ANGLE may use kernel event primitives for GPU/CPU synchronization
- This means ANY page with compositing (which is most pages) may indirectly use Sony event syscalls through the display subsystem

### From Jail/Sandbox Agent (sys 629, 630, 593)
- **PS5 WebProcess has NO kernel-level sandbox** -- no FreeBSD jail, no capsicum, no seccomp, no syscall filter
- WebProcess can call sys 670 directly after code execution is achieved
- WebProcess knows PIDs of sibling processes (NetworkProcess, UIProcess) from IPC setup
- No sandbox prevents targeting system daemon PIDs either
- sys 630 cross-PID mount lookup (zero priv_check) can discover system daemon PIDs by scanning

### Combined Attack Scenario (Updated with Cross-Agent Findings)

Given that the WebProcess has NO sandbox and Gigacage is disabled:

1. **Stage 1**: Achieve code execution in WebProcess via WebKit vulnerability (e.g., stack clash via p203)
2. **Stage 2**: From WebProcess, directly call sys 670 (+0x480) to enumerate AIO state of ANY process (UIProcess, NetworkProcess, system daemons) -- NO privilege check
3. **Stage 3**: Use sys 661/662/668 KASLR bypass to get kernel heap layout
4. **Stage 4**: Use sys 670 cross-process enumeration + sys 593 module info leak to map target process memory layouts
5. **Stage 5**: Use sys 622 unchecked IPMI commands (95% unchecked) to interact with system services
6. **Stage 6**: Use sys 629 arg0=1 jail bypass (if any jail exists) or sys 675 global state reset to escalate
7. **Stage 7**: Workers with SharedArrayBuffers provide persistent read/write observation windows (no Gigacage!) while exploitation proceeds on other threads

---

### Priority Recommendations

1. **IMMEDIATE**: Use sys 670 debug interfaces from the Lua loader to enumerate WebProcess AIO state. This confirms whether the browser uses Sony AIO and reveals active file descriptors. **NO SANDBOX PREVENTS THIS.**

2. **HIGH**: Determine if PS5's pthread implementation uses Sony event flags (runtime test: trace syscalls during Worker postMessage). If yes, the non-atomic refcount bug in sys 664/665/666 becomes reachable from JavaScript.

3. **HIGH**: Test SharedArrayBuffer-based Worker observation -- with Gigacage disabled, SAB backing stores are vulnerable to heap corruption that Workers can detect in real-time (extends p146 findings).

4. **MEDIUM**: Test whether sys 558 (event object deletion) can destroy objects belonging to the WebProcess's pthread infrastructure, causing kernel use-after-free.

5. **MEDIUM**: Use sys 670 from WebProcess to enumerate system daemon AIO state and discover daemon PIDs. Combined with sys 622 IPMI, this provides a path to interact with privileged system services.

6. **RESEARCH**: Map the complete `proc+0xc48` handle namespace for the WebProcess to understand what typed objects (0x160 AIO, others?) are present and which are reachable from JavaScript operations.
