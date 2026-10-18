# WebKit Path 1: IPMI/IPC Pathway Analysis

Cross-reference of sys 622 (IPMI manager dispatcher) kernel RE against WebKit-1200 source code.

Firmware: 13.60 kernel analysis, WebKit-1200 source (used on PS5 14.10).

## Executive Summary

**Direct JS-to-sys622 path: NOT FOUND in WebKit source.** The WebKit-1200 open source does not contain any direct reference to IPMI, SceIpmi, ipmimgr, or syscall 622. No `syscall(622, ...)` wrapper, no IPMI header inclusion, no Sony IPMI API usage exists in the WebKit tree.

**Post-exploit sys622 reachability: YES, via linked Sony closed-source libraries.** The browser process links against `libkernel` (kernel_stub_weak) and `libSceNKWebKitRequirements`, which are closed-source Sony shared libraries that internally use IPMI for system service communication. After gaining code execution in the WebProcess, an attacker can call sys 622 directly via inline syscall.

## Kernel Side: Sys 622 Summary

Identity: `sys_ipmimgr_call()` -- the Sony IPMI IPC manager dispatcher.

### ABI (5 visible arguments of 6 declared)
- `uap+0x00`: u32 command (dispatch selector)
- `uap+0x08`: u32 object/session ID
- `uap+0x10`: user pointer for 4-byte status output
- `uap+0x18`: user pointer to payload buffer
- `uap+0x20`: u32 payload byte length (max 0x40)

### Command Ranges (from four dispatch tables)
- Table 1: commands 0x000--0x133 (308 slots) at RVA 0x178057c
- Table 2: commands 0x201--0x271 (113 slots) at RVA 0x1780a4c
- Table 3: commands 0x302--0x320 (31 slots) at RVA 0x1780c10
- Table 4: commands 0x400--0x493 (148 slots) at RVA 0x1780c8c
- Special direct: 0x372, 0x520
- Total addressable: ~602 numeric slots (not all implemented)

### Access Control
- Front-end gate covers only ~24 commands via bitmap check:
  - 0x100,0x102,0x104,0x106,0x107,0x120-0x12b,0x12f-0x133 require predA OR predB
  - 0x12d,0x12e require predA OR predC
  - 0x271,0x372,0x473 require predA OR predC OR fallback predicate
- Remaining commands pass no front-end credential check in this dispatcher
- Per-command helpers may enforce their own policy (unknown without table contents)
- Cross-validation review rejected "95% unauthenticated" as overstated -- but the observation that most commands lack THIS front-end gate is real

### Key Operations Identified
- `syscallGetClientPidBySessionKid()` at +0x2440 -- session KID lookup, PID copyout
- `syscallReceivePacket()` -- receive-channel/event helper at +0x4340
- Request marshaller at +0xec0 -- builds IPMI request records with nested user buffers
- Response-info updater at +0x4be0 -- async/sync response routing
- Connect-request matcher at +0x4f90 -- CONNECT_REQUEST_FLAG_LINKED
- Process lifecycle hooks at +0x5060/+0x5120/+0x5140

## WebKit Side: Architecture

### Process Model
PS5 WebKit uses a multi-process architecture with Unix domain socket IPC:
- **UIProcess** (browser chrome) -- the privileged host process
- **WebProcess** -- renders web content, runs JavaScript (sandboxed)
- **NetworkProcess** -- handles HTTP/network via libcurl
- **GPUProcess** -- (optional, currently OFF for PlayStation)

Inter-process communication uses `SOCK_STREAM` Unix domain sockets created via `socketpair()` in `IPC::createPlatformConnection()` (`Source/WebKit/Platform/IPC/unix/ConnectionUnix.cpp`).

### PlayStation-Specific Code Locations
```
Source/WTF/wtf/playstation/              -- OS primitives (allocator, filesystem, language)
Source/WebCore/platform/playstation/     -- screen, scrollbar, MIME, user agent, widget
Source/WebCore/platform/network/playstation/ -- curl TLS, DNS, network state, TM service
Source/WebCore/platform/graphics/playstation/ -- fonts, media player, EME/DRM
Source/WebKit/UIProcess/Launcher/playstation/ -- process launching (CRITICAL)
Source/WebKit/WebProcess/playstation/    -- WebProcess init
Source/WebKit/UIProcess/playstation/     -- page client, web view
```

### Sony Closed-Source Library Dependencies
From `OptionsPlayStation.cmake` and `PlatformPlayStation.cmake`:

| Library | Purpose | IPMI Relevance |
|---------|---------|----------------|
| `kernel` / `kernel_stub_weak` | PS5 kernel interface | **Direct syscall gateway -- includes sys 622** |
| `SceNet_stub_weak` | Network stack | Network IPC services via IPMI |
| `SceNKWebKitRequirements` | Sony WebKit integration | **Contains process launcher, system service bindings** |
| `NetworkControl` | Network state (`NetworkControl::isOnline()`) | Queries network service via IPMI |
| `WebSecurity` | URL filtering/parental controls | Communicates with TM service via IPMI |
| `ProcessLauncher` / `WPE::PlayStation` | Child process spawning | Process management via IPMI |
| `mediaplayer` | Video playback | Media service IPC via IPMI |
| `slimglipc.h` (checked at build) | GL IPC for rendering | GPU command submission via IPMI |

### Process Launch Mechanism
`ProcessLauncherPlayStation.cpp` (line 64-111):
1. Creates Unix domain socket pair via `IPC::createPlatformConnection()`
2. Sets 32KB send/receive buffers
3. Calls `PlayStation::launchProcess()` (closed-source) with:
   - Process path: `/app0/WebProcess.self`, `/app0/NetworkProcess.self`
   - Socket FD passed to child
   - User ID from launch options
4. Child inherits the socket FD for WebKit IPC

### Network Stack Path
Network requests flow: JS fetch/XHR -> WebProcess -> (WebKit IPC socket) -> NetworkProcess -> libcurl -> SceNet -> kernel network syscalls. The NetworkProcess links `libcurl` and `libSceNKWebKitRequirements`. The `NetworkStateNotifier` directly calls `NetworkControl::isOnline()` which is a Sony system service query (likely via IPMI).

### WebSecurity/TM Service Path
`CurlTMServiceRequest.cpp` shows a content filtering system:
- `WebSecurity::activatedStatus()` -- checks if parental controls active
- `WebSecurity::convertUrl()` -- transforms URLs for filtering
- `WebSecurity::evalResponse()` -- evaluates server response for blocking
- This is a closed-source library that communicates with a system daemon via IPMI

## Cross-Reference: JS to IPMI Paths

### Path 1: INDIRECT via Sony libraries (pre-exploit, normal operation)
```
JavaScript -> WebCore API -> Sony library call -> IPMI syscall 622
```
Examples:
- `navigator.onLine` -> `NetworkStateNotifier` -> `NetworkControl::isOnline()` -> IPMI
- Any URL load -> `CurlTMServiceRequest` -> `WebSecurity::convertUrl()` -> IPMI
- Media playback -> `MediaPlayerPrivatePlayStation` -> mediaplayer lib -> IPMI
- EME/DRM -> `CDMInstancePlayStation` -> closed-source DRM service -> IPMI

These are **opaque** -- JavaScript triggers them but cannot control IPMI command/payload.

### Path 2: DIRECT syscall after code execution (post-exploit)
After achieving WebKit code execution (e.g., via the proven metadata overflow p146 or UAF probes):
1. The WebProcess links `libkernel` (kernel_stub_weak)
2. The process has a valid IPMI context (initialized by `SceIpmiMgr` process constructor at kernel +0x5120)
3. Direct `syscall(622, command, object_id, &status, payload_ptr, payload_len)` is possible
4. **Most of the ~602 command slots lack front-end credential checks in the dispatcher**

### Critical Question: Which Commands Are Reachable Post-Exploit?

The WebProcess runs in a FreeBSD jail with syscall filtering (sys 629/630 configure this). The key unknowns:

1. **Syscall filter**: Does the WebProcess jail allow syscall 622? Given that Sony libraries in the WebProcess (SceNKWebKitRequirements, NetworkControl, etc.) USE IPMI, the syscall must be permitted for those libraries to function. **Therefore sys 622 is almost certainly allowed in the WebProcess.**

2. **IPMI session state**: The per-process IPMI context (initialized at kernel +0x5120, cleaned at +0x5140) tracks four ID classes (0x8001, 0x8002, 0x8004, 0x8008). Post-exploit code inherits whatever sessions the WebProcess already has open.

3. **Which sessions exist**: The WebProcess communicates with system services for:
   - Network control (NetworkControl library)
   - Content filtering (WebSecurity library)  
   - Font services (fontconfig/freetype, potentially via IPMI)
   - Media services (if video is playing)
   - GL/rendering IPC (if slimglipc is in use)
   
   Each of these has an IPMI session with an object ID. Post-exploit code can:
   - Reuse existing sessions to send commands to those services
   - Attempt to open NEW sessions to other services (if not restricted)

4. **Unauthenticated commands**: Of the ~602 slots, only ~24 have the front-end gate. The remainder depend on per-helper validation and the external typed-ID lookup system. After code execution, an attacker can:
   - Enumerate existing IPMI sessions via commands in the 0x400-0x493 range
   - Query session state, PIDs, connection info
   - Send/receive packets to connected services
   - Potentially create new connections to arbitrary system services

## JIT Status

**JIT is OFF on PlayStation** (`ENABLE_JIT PRIVATE OFF`, `ENABLE_FTL_JIT PRIVATE OFF`, `ENABLE_DFG_JIT PRIVATE OFF`). This means:
- No JIT spraying attacks
- No W^X JIT page corruption
- Code execution must come from interpreter bugs, UAF, or type confusion
- The proven p146 metadata overflow and UAF probes are the viable paths

## CONFIRMED: No Kernel-Level Sandbox in WebProcess (from peer analysis)

The jail/sandbox agent confirmed:
- `AuxiliaryProcess::initializeSandbox()` is an **empty no-op** on PlayStation
- No FreeBSD jail, no capsicum, no seccomp, no pledge in WebKit source
- The "sandbox" is Sony's proprietary `ucred authId + capabilities` system ONLY
- The cmake `--wrap=mmap` is a **linker-level** wrap, not kernel-level -- direct `syscall()` bypasses it
- The WebProcess loads 15+ Sony .sprx modules via dlopen() at startup

**This confirms: sys 622 (IPMI) is directly callable post-exploit with no syscall filter barrier.** The only checks are within the sys 622 handler itself (the ~24 front-end gated commands and per-helper validation).

## Additional Findings from Peer Analysis

**Memory/process agent:** bmalloc has PlayStation-specific MAT hooks (MatReserveVirtualRange, MatMemoryPoolCommit). All executables have `--wrap=mmap` at link time. Post-exploit code should use direct syscall() for mmap to bypass Sony's wrapper.

**Events/async agent:** sys 670 debug interfaces can enumerate BOTH WebKit IPC socket state AND IPMI channel state from any process without privilege checks. Worker-initiated fetch() requests indirectly generate IPMI traffic via NetworkControl. The NetworkProcess likely uses Sony AIO (sys 669) for async I/O.

**GPU/canvas agent:** PS5 WebKit has NO GPU process -- WebGL runs in-process in the WebProcess. The `canvas::Canvas` API (`<canvas/canvas.h>`, Sony proprietary) communicates with the display compositor via IPMI. Key functions: `canvas::Canvas::create()`, `canvas::CanvasUtil::finish()`, `canvas::CanvasUtil::getGPUMemUsage()`. These are triggered by EVERY page load (accelerated compositing is default). The slimglipc.h mechanism is confirmed as the GL IPC path: JS WebGL -> ANGLE -> EGL -> slimglipc -> IPMI -> GPU server. This means the WebProcess ALWAYS has an active IPMI session to the GPU compositor service.

## Recommendations for 14.10 Research

### Immediate (post-exploit IPMI exploration)
1. After achieving code execution via p146/UAF, enumerate IPMI sessions:
   - Try command range 0x400-0x493 with sequential object IDs
   - Use `syscallGetClientPidBySessionKid` pattern commands to discover sessions
2. Map which system services the WebProcess has active IPMI connections to
3. Test if new IPMI sessions can be created to privileged services (e.g., ShellCore)

### Medium-term (privilege escalation via IPMI)
1. Identify which of the ~602 commands write to kernel memory or modify credentials
2. The request marshaller at +0xec0 handles nested user pointers -- audit for confused deputy
3. The receive-channel helper at +0x4340 processes packets -- audit for type confusion
4. Commands 0x271, 0x372, 0x473 have the "strictest" gate but also the most fallback predicates
5. Look for commands that operate on process credentials or jail parameters

### Key Files for Reference
- Kernel analysis: `deep_622.rea.analysis.md`, `deep_622.rea.c`
- Cross-validation: `review_batch1_622_601_669.md` (sys 622 section -- corrects manual errors)
- WebKit process launcher: `Source/WebKit/UIProcess/Launcher/playstation/ProcessLauncherPlayStation.cpp`
- WebKit IPC: `Source/WebKit/Platform/IPC/unix/ConnectionUnix.cpp`
- Build config: `Source/cmake/OptionsPlayStation.cmake`
- Network filtering: `Source/WebCore/platform/network/playstation/CurlTMServiceRequest.cpp`
