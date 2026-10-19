# WebKit-to-Kernel Chain Strategy

## Current WebKit State
- OOB read via corrupted JSString `.length` (81400 vs 100000) — reads ~81KB past string boundary
- Heap corruption is in Primary/marge heap (bmalloc FastMalloc)
- `charCodeAt()` reads intact backing data + adjacent heap objects
- Workers available, fetch/XHR for beacons, no WebAssembly/SharedArrayBuffer

## Can OOB Read Reach Kernel Pointers?

**No directly.** WebKit runs in userland. The OOB read stays within the process's virtual address space — it reads adjacent heap allocations, not kernel memory. However:

1. **Vtable pointers** in adjacent JSC objects leak the WebKit module's ASLR base — defeating userland ASLR inside the browser process.
2. **JSC internal structures** (MarkedBlock headers, Structure pointers, Butterfly pointers) all contain userland heap addresses — these give the heap layout needed for arbitrary R/W.
3. If any JSC object holds a **file descriptor** or **mmap'd region pointer** related to GPU/device memory, those could bridge to kernel-relevant addresses.

## Path: OOB Read → Arbitrary R/W → Kernel

1. **OOB read leaks a JSObject vtable** → compute WebKit base address (userland ASLR defeated)
2. **Corrupt a JSObject's butterfly pointer** via the metadata overflow → point it at a controlled buffer → fake object gives arbitrary read
3. **Fake an ArrayBuffer** whose backing store pointer is attacker-controlled → arbitrary R/W in the browser process
4. **From arbitrary R/W in the browser**: call Sony syscalls (sys 626 RDMSR, sys 661 AIO, sys 629 jail bypass) to attack the kernel — the browser process has the same `make_syscall`-equivalent capability via direct `syscall` instruction if we can execute a small ROP chain or find a syscall gadget in RX memory.

## Key Insight: Two Entry Vectors, Same Kernel

The Lua loader (TCP 9026) and WebKit (User's Guide DNS redirect) run in **different processes** but hit the **same kernel**. The kernel vulnerabilities (sys 626, 629, 661, 588, 622) are reachable from both. WebKit's advantage: it has Workers (pseudo-threading for races), fetch/WebSocket (richer I/O), and a heap corruption primitive the Lua side lacks.

## What's Missing for WebKit → Kernel

The current probes extract corrupted metadata bytes but haven't yet:
1. Identified a leaked vtable/pointer in the OOB region (p156 saw all 0x41 = intact data, need to read PAST the string)
2. Built a fake object for arbitrary R/W
3. Found a `syscall` gadget in browser-accessible RX memory

## Next Probes Needed

**54g**: Extended OOB scan — read far past the 100K string boundary using the corrupted `.length=81400`, dump every 8-byte-aligned value looking for non-0x41 data (heap metadata, vtables, Structure pointers). This is the critical missing step.

**54h**: Lua-side bridge — open a TCP listener that WebKit can connect to via fetch/WebSocket. WebKit sends leaked addresses; Lua uses them for targeted syscall attacks. Combines both attack surfaces in real-time.
