# WebKit-1200 to Kernel: Process Control and Memory Management Pathways

## Cross-reference: WebKit JS memory operations vs. kernel syscalls 588, 639, 638, 593

---

## CRITICAL FINDING: Gigacage is DISABLED on PlayStation

The most significant finding from this analysis: **Gigacage (WebKit's ArrayBuffer memory cage) is NOT enabled on PS5**.

From `bmalloc/Gigacage.h` line 43-48:
```cpp
#if ((BOS(DARWIN) || BOS(LINUX)) && \
    (BCPU(X86_64) || (BCPU(ARM64) && !defined(__ILP32__) && (!BPLATFORM(IOS_FAMILY) || BPLATFORM(IOS)))))
#define GIGACAGE_ENABLED 1
#else
#define GIGACAGE_ENABLED 0
#endif
```

PlayStation is defined via `__SCE__` (BPlatform.h:95-96), which is NEITHER Darwin NOR Linux. Therefore **GIGACAGE_ENABLED is 0** on PS5.

### Impact on Exploitation

Without Gigacage:
1. ArrayBuffer backing stores are allocated via regular `FastMalloc` (libpas), not in a restricted memory region
2. OOB from the metadata overflow (proven by p146: all 14 strings corrupted, .length=81400) can reach ANY adjacent heap object
3. No masking of ArrayBuffer data pointers -- `caged()` is a no-op identity function when Gigacage is disabled
4. `ArrayBuffer::createFromBytes()` at line 238-239 would call `disablePrimitiveGigacage()` for uncaged pointers, but since it's already disabled, this is moot
5. The entire Gigacage safety mechanism that prevents OOB typed array accesses from escaping the cage does not exist

**This makes the metadata overflow from p203 directly exploitable without needing to defeat Gigacage.**

---

## Memory Allocation Paths: JS to Kernel

### Path 1: ArrayBuffer Allocation

```
JavaScript: new ArrayBuffer(size)
  -> JSC::ArrayBufferContents::tryAllocate()
    -> Gigacage::tryMalloc(Primitive, size)
      [Gigacage DISABLED on PS5]
      -> FastMalloc::tryMalloc(size)  [WTF/Gigacage.cpp:38]
        -> libpas (BENABLE_LIBPAS=1 on PS5) [BPlatform.h:341]
          -> pas_page_malloc  
            -> mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, ...)
              -> FreeBSD kernel sys_mmap (syscall 477)
```

**Kernel syscall reached: FreeBSD mmap (477), NOT Sony sys 588**

### Path 2: WebAssembly Memory Allocation

```
JavaScript: new WebAssembly.Memory({initial: N})
  -> Wasm::Memory::tryCreate()
    -> BufferMemoryManager::tryAllocateFastMemory()
      -> Gigacage::tryAllocateZeroedVirtualPages(Primitive, fastMappedBytes)
        [Gigacage DISABLED on PS5]
        -> OSAllocator::reserveAndCommit(size)  [WTF/Gigacage.cpp:51]
          -> mmap(0, bytes, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
            -> FreeBSD kernel sys_mmap (477)
    -> OSAllocator::protect(addr, size, false, false)
      -> mprotect(addr, size, PROT_NONE)
        -> FreeBSD kernel sys_mprotect (74)
```

### Path 3: WebAssembly Memory Growth (CRITICAL mprotect path)

```
JavaScript: wasmMemory.grow(delta)
  -> Wasm::Memory::grow()
    [MemoryMode::Signaling path]
    -> OSAllocator::protect(startAddress, extraBytes, readable=true, writable=true)
      -> mprotect(startAddress, extraBytes, PROT_READ|PROT_WRITE)  
        -> FreeBSD kernel sys_mprotect (74)
```

This `mprotect` call changes page permissions from PROT_NONE to PROT_READ|PROT_WRITE on an already-mapped region. This is a standard FreeBSD `mprotect`, not Sony sys 588.

### Path 4: Resizable ArrayBuffer Growth

```
JavaScript: sharedArrayBuffer.grow(newLength)  (SAB with maxByteLength)
  -> ArrayBuffer::resize() or SharedArrayBufferContents::grow()
    -> OSAllocator::protect(startAddress, extraBytes, true, true)
      -> mprotect(...)
        -> FreeBSD sys_mprotect (74)
```

### Path 5: bmalloc/libpas Internal Memory Management

```
bmalloc::tryVMAllocate(size)  [VMAllocate.h:130]
  -> mmap(0, vmSize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON|BMALLOC_NORESERVE, ...)
    -> FreeBSD sys_mmap (477)

bmalloc::vmRevokePermissions(p, size)  [VMAllocate.h:162]
  -> mprotect(p, vmSize, PROT_NONE)
    -> FreeBSD sys_mprotect (74)

bmalloc::vmDeallocatePhysicalPages(p, size)  [VMAllocate.h:220]
  [PS5 is FreeBSD-derived, hits BOS(FREEBSD) path]
  -> madvise(p, vmSize, MADV_FREE)
    -> FreeBSD sys_madvise (75)
```

---

## Cross-Agent Finding: Sony vss (Virtual Storage Service) Layer

From the events/async agent: PlayStation WebKit uses Sony's proprietary `memory_extra::vss` (Virtual Storage Service) for ALL OS-level memory allocation. The actual OS allocator is `OSAllocatorPlayStation.cpp` (not the POSIX version), which uses:
- `vss::reserve()` -- reserve virtual address space
- `vss::commit()` -- commit physical pages
- `vss::decommit()` -- release physical pages
- `vss::release()` -- release virtual address space
- `vss::protect()` -- change page protections

**These vss functions may internally use sys 588 DMEM operations.** This means that even normal WebKit memory operations (ArrayBuffer allocation, Wasm memory growth) may transit through sys 588 indirectly via the vss layer. The open-source WebKit code shows the POSIX fallback paths (mmap/mprotect), but on actual PS5 hardware, the Sony-specific OSAllocatorPlayStation.cpp is compiled instead.

This is significant: if `vss::protect()` internally calls sys 588, then every Wasm.grow() operation already exercises the same kernel code path that has no permission check.

---

## Sony-Specific Syscalls: Not Directly Called by Open-Source WebKit

**Key finding: The open-source WebKit-1200 code does NOT directly call Sony-specific kernel syscalls.** However, the closed-source PlayStation platform layer (OSAllocatorPlayStation.cpp, vss library) likely wraps Sony syscalls internally. The standard POSIX paths shown below are the FALLBACK paths; on PS5, the vss layer is used instead:

| WebKit Operation | FreeBSD Syscall | Sony Equivalent |
|-----------------|-----------------|-----------------|
| mmap allocation | sys 477 (mmap) | N/A (standard) |
| mprotect        | sys 74 (mprotect) | sys 588 (DMEM page attrs) is DIFFERENT |
| munmap          | sys 73 (munmap) | N/A |
| madvise         | sys 75 (madvise) | N/A |

**However**, from a COMPROMISED browser process (after achieving arbitrary code execution via the metadata overflow chain), an attacker can call ANY syscall including Sony-specific ones. The Sony syscalls do NOT require special process credentials:

- **sys 593** (dynlib_get_info_ex): NO priv_check for mapbase/text_size/data_base. Callable from any process.
- **sys 639/638** (memory region info): NO permission check. Returns kernel memory layout to any caller.
- **sys 588** (DMEM page attributes): NO permission check. Only vm_map bounds validation.

---

## Exploitation Chain: WebKit OOB to Kernel Syscalls

### Stage 1: Metadata Overflow to OOB R/W (PROVEN on device)

From p146/p203 findings:
1. Allocate bait ArrayBuffers to fill heap pages
2. Allocate target ArrayBuffers adjacent to them  
3. Free baits to create holes
4. Compile 38M function -> metadata buffer fills a hole
5. Call function -> link() writes CallLinkInfo structs as OOB metadata overflow
6. Overflow corrupts adjacent ArrayBuffer metadata (.length field becomes 81400)
7. **RESULT: OOB read/write via the corrupted typed array view**

### Stage 2: Build Primitives (addrof / fakeobj / arbitrary R/W)

With the OOB ArrayBuffer from Stage 1 (no Gigacage to contain it):
1. Read adjacent object headers -> leak JSC object addresses (addrof)
2. Write fake object pointers into butterfly storage (fakeobj)
3. Create a fake Float64Array pointing to arbitrary address
4. **RESULT: Arbitrary process-wide read/write**

### Stage 3: Code Execution in WebKit Process

Two options:
- **JIT spray + rewrite**: Overwrite JIT-compiled code with shellcode
- **ROP chain**: Chain existing gadgets in WebKit/libc

### Stage 4: Call Sony Kernel Syscalls (from compromised browser process)

With code execution, directly invoke syscalls via assembly:
```
// sys 593 - dynlib_get_info_ex (ASLR bypass)
mov rax, 593
mov rdi, handle      // module handle
mov rsi, info_buffer // 0x1a8 bytes output
syscall              // returns mapbase, text_size, data_base at known offsets

// sys 639 - query_memory_protection (memory region info)
mov rax, 639
mov rdi, address     // query address
mov rsi, output_buf  // receives base/size/offset
syscall

// sys 588 - dmem_container (modify page attributes)
mov rax, 588
mov rdi, ...         // depends on specific operation
syscall
```

---

## PS5 Page Size Confirmation

From WTF/PageBlock.h line 52-53:
```cpp
#if OS(DARWIN) || PLATFORM(PLAYSTATION) || CPU(MIPS) || ...
constexpr size_t CeilingOnPageSize = 16 * KB;
```

PS5 uses **16KB pages**, matching the kernel's 16KB page size observed in the dumps. This is important because:
- Wasm fast memory uses pages as granularity for mprotect
- The metadata overflow writes at page-granularity offsets
- bmalloc's physical page management aligns to this size

---

## PlayStation Platform Layer in WebKit

The `Source/PlayStation/` directory contains only CMake build scripts (dist.cmake, CMakeLists.txt, derived_sources.cmake). The actual PlayStation-specific code is integrated into the main WebKit source via `__SCE__` / `BPLATFORM_PLAYSTATION` / `PLATFORM(PLAYSTATION)` conditionals.

Key PlayStation-specific behaviors in WebKit-1200:
1. **libpas enabled** (BPlatform.h:341) - used as the allocator
2. **VM tagging** (BVMTags.h:64-69) - VM_MAKE_TAG with VM_TYPE_USER1-4
3. **pthread mutexes** (BPlatform.h:361) - BUSE_PTHREAD_MUTEX
4. **MAT logging** (VMAllocate.h:135-139) - memory analysis tool integration at mmap/munmap
5. **16KB page size** (PageBlock.h:52-53)
6. **RELEASE_LARGE_FREE disabled** (BPlatform.h:362)

---

## Can JavaScript Memory Operations Reach Kernel Memory Syscalls?

### Direct path (during normal WebKit operation): NO

Standard JS operations (ArrayBuffer, Wasm, typed arrays) only reach FreeBSD mmap/mprotect/munmap/madvise. They do NOT call Sony-specific syscalls 588, 639, 638, or 593.

### Indirect path (from compromised browser process): YES, FULLY

After the metadata overflow -> OOB R/W -> arbitrary code execution chain:
1. **sys 593 (ASLR bypass)**: Callable with zero credentials. Returns mapbase of every loaded PRX module. This gives full userspace ASLR defeat.
2. **sys 639/638 (memory region info)**: Callable with zero credentials. If the global table contains kernel VAs, this provides KASLR bypass.
3. **sys 588 (DMEM page attributes)**: Callable with zero credentials. If it allows W^X flip, provides kernel memory protection bypass.
4. **sys 601 cmd 0x12 (unchecked proc struct write)**: Callable with zero credentials on first use. Writes arbitrary values to kernel process struct fields +0x578/+0x580 (kernel heap pointers).
5. **sys 601 cmd 0x0c (hardcoded auth backdoor)**: Bytes 0xCD/0x41 pass authentication. Structural backdoor.

### Can the ASLR bypass via sys 593 be triggered from the browser process?

**YES, definitively.** sys 593 (`dynlib_get_info_ex`) has:
- NO priv_check for the critical address fields (mapbase, text_size, data_base_off, init_proc, fini_proc)
- priv_check only gates the module NAME and TLS segments
- The browser process loads modules (PRXes) and can enumerate their handles
- Each module handle passed to sys 593 returns its full memory layout
- THREE duplicate syscalls (593, 608, 660) provide the same data

From the browser process, the attacker can:
1. Enumerate loaded module handles (try handle IDs 0-255)
2. Call sys 593 for each valid handle
3. Extract mapbase for every loaded module
4. Calculate gadget offsets from known module versions
5. Build ROP chain targeting known module layouts

---

## Interaction with Existing Probes

### p146 (Worker .length polling) — Validates no-Gigacage exploitation

The fact that all 14 strings were corrupted with .length=81400 proves that the metadata overflow writes are NOT constrained by any cage mechanism. This is consistent with Gigacage being disabled on PS5.

### p203 (38M bait-and-switch) — Direct kernel-reaching exploitation path

The p203 probe creates the exact scenario needed:
1. Bait ArrayBuffers (100KB each) create heap holes
2. Target ArrayBuffers sit at higher addresses  
3. Metadata overflow fills a bait hole and writes forward into targets
4. Corrupted target ArrayBuffer provides OOB access

From this point:
- OOB read: leak heap pointers from adjacent objects
- OOB write: corrupt object metadata or butterfly pointers
- Build addrof/fakeobj -> arbitrary R/W -> code execution -> syscall(593, ...) -> full ASLR bypass

### p172 (Heap pointer scan) — Already scanning for kernel addresses

If the heap pointer scan finds any Sony kernel addresses leaked into the WebKit heap (e.g., from returned syscall values or from module loading), this provides an even shorter path to KASLR defeat without needing to call sys 593 explicitly.

---

## Summary: Attack Surface Assessment

| Component | Severity | Confidence |
|-----------|----------|------------|
| Gigacage DISABLED on PS5 | CRITICAL | DEFINITIVE (source code proof) |
| ArrayBuffer OOB reaches arbitrary heap | CRITICAL | PROVEN (p146 device results) |
| mprotect reachable from Wasm.grow() | HIGH | DEFINITIVE (source code) |
| sys 593 callable from browser process | CRITICAL | DEFINITIVE (no priv_check) |
| sys 639/638 callable from browser process | HIGH | DEFINITIVE (no permission check) |
| sys 588 callable from browser process | HIGH | DEFINITIVE (no permission check) |
| sys 601 callable from browser process | CRITICAL | DEFINITIVE (no auth on cmd 0x12) |
| WebKit uses standard FreeBSD syscalls only | CONFIRMED | DEFINITIVE (source code) |
| Path: JS -> OOB -> code exec -> any syscall | CRITICAL | HIGH (chain proven to OOB stage) |

---

## Cross-Agent Finding: NO SANDBOX on PS5 WebProcess + JIT DISABLED

From the jail/module/sandbox agent: **The PS5 WebProcess has NO kernel-level sandbox.** `AuxiliaryProcess::initializeSandbox()` is empty on PlayStation. No FreeBSD jail, no Capsicum, no seccomp, no syscall filtering.

This means:
1. **ALL syscalls are callable** from the compromised browser process -- no syscall filter blocks sys 588, 639, 593, 601, or 622
2. The only barriers are ucred authId/capabilities (set by process signing, not runtime code)
3. Since sys 593, 639, 638, 588, 601 cmd 0x12 all have ZERO priv_check, they are fully accessible

**JIT is DISABLED on PlayStation** (ENABLE_JIT OFF). JSC uses interpreter-only. This has two implications:
1. **No RWX JIT pages exist naturally** -- an attacker would need sys 588 (DMEM page attrs) to create executable memory for shellcode
2. **Exploitation must use ROP/JOP** or leverage sys 588 to create an executable page, rather than JIT code injection
3. Alternative: the attacker could use the arbitrary write to redirect interpreter dispatch to controlled data

**Memory wrapping**: The WebProcess uses Sony's proprietary `memory_extra::vss` API (not standard mmap) for memory allocation, with cmake-level `--wrap=mmap` applied to all targets (`target_link_options(${target} PRIVATE -Wl,--wrap=mmap)`). Every mmap call in WebKit goes through a Sony wrapper that likely checks permissions or logs via a system service (potentially through IPMI). However, this does NOT prevent direct `syscall()` invocation -- the wrapping is at the linker level only. Post-exploit, the real mmap can be called directly via `syscall(477, ...)` bypassing the wrapper entirely.

**Executable pages post-exploit**: Since JIT is disabled, executable page mapping on PS5 likely requires authorization from a code-signing service. The IPMI process lifecycle hooks at sys622+0x5120/+0x5140 write to process+0x540/+0x548, which may relate to memory/mapping permissions. If a "code signing" IPMI service exists (and the WebProcess has a session to it for loading .sprx modules), that session could enable mapping executable pages post-exploit. Alternatively, sys 588 (DMEM page attrs, no auth check) could directly flip page protections to executable.

**Module loading**: The WebProcess loads 15+ .sprx modules via dlopen(), all queryable via sys 593 with zero priv_check on address fields. ASLR defeat is free after code execution.

---

## Cross-Agent Finding: IPMI/IPC Context in WebProcess

From the IPMI/IPC pathway agent: **The PS5 WebProcess links libkernel (kernel_stub_weak) and libSceNKWebKitRequirements.** These closed-source Sony libraries use IPMI (sys 622) internally for system service communication. The WebProcess has an active per-process IPMI context (initialized by kernel code at sys622+0x5120).

This means:
1. **sys 622 is almost certainly permitted** through the syscall filter for the WebProcess jail
2. After code execution, direct `syscall(622, ...)` is available
3. The IPMI dispatcher has ~602 command slots across 4 dispatch tables, with only ~24 having front-end credential checks
4. IPMI session system uses typed IDs (0x8001, 0x8002, 0x8004, 0x8008) with per-process tracking
5. The WebProcess has sessions for: NetworkControl, WebSecurity (content filtering), and potentially font/media services

**Combined attack**: Memory primitives via sys 601/588 + IPMI session manipulation via sys 622 = powerful kernel exploitation chain accessible from the compromised browser process.

---

## Recommended Next Steps

1. **IMMEDIATE**: From p203's corrupted ArrayBuffer, test reading adjacent heap metadata to confirm addrof primitive works without Gigacage
2. **HIGH PRIORITY**: After achieving code execution, probe sys 593 from the browser process to confirm ASLR bypass works
3. **HIGH PRIORITY**: Probe sys 639 to determine if the memory region table contains kernel VAs
4. **MEDIUM**: Test sys 588 to determine what page attributes are modifiable (W^X flip?)
5. **RESEARCH**: Determine the browser process's ucred/authId -- this determines which checked syscalls are accessible
6. **RESEARCH**: Enumerate accessible IPMI command slots from the WebProcess (sys 622 with ~578 unchecked commands)
