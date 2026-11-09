# Research Directions -- 2026-11-09

## The Single Blocker

Every exploit primitive is in place except one: **the WebProcess text base address**.

The FontFace UAF chain on WebKit 605.1.15 has:
- 100% reclaim reliability (192B ArrayBuffer spray)
- Two-phase forge write (p656: addClient writes into forged table)
- GC destructor path (p599: ~FontFace() reads forged +0x58, decrements rc)
- Null-spray survival (p599 v4i: 7/7 = 100%, no 80B spray needed)
- KASLR defeat (fault oracle: kernel image base per boot in 33s)
- Full Lua-side infrastructure (child thread ROP, 5-arg syscalls, gadget catalog)

One address -- any code pointer inside the WebProcess binary -- unlocks vtable
forgery and completes the chain from browser UAF to kernel R/W.

## Open Angles (Prioritized)

### 1. JIT CodeBlock Heap Residue (NEW -- Highest Priority)

DFG JIT is confirmed active on PS5 14.10 (p602: 5M loop in 49ms). The DFG
compiler allocates CodeBlock objects on the regular heap, and these contain
code pointers (instruction start, slow path entries, inline cache stubs).

When a CodeBlock is destroyed (function goes cold, GC collects), the heap
memory is freed but may not be zeroed. If we can:
- Force DFG compilation of a known function (loop 100K+ iterations)
- Let the function go cold and get GC'd (drop all refs, trigger GC)
- Spray ArrayBuffers of the same size class to reclaim the freed memory
- Read the ArrayBuffer contents for residual code pointers

This is a classic heap feng shui info leak. The key question is whether
bmalloc zeros freed pages. WebKit's bmalloc documentation says it does NOT
zero on free (only on initial allocation from the OS via mmap). If the
CodeBlock's size class matches an ArrayBuffer size we can spray, residual
JIT code pointers survive in the reclaimed buffer.

**Size estimation:** A minimal CodeBlock for a simple function is ~256-512B
(header + inline caches + constant pool). ArrayBuffer(256) or ArrayBuffer(512)
could reclaim the slot.

**Risk:** bmalloc's IsoHeap may isolate CodeBlock allocations. JSC puts
CodeBlocks in a dedicated allocator on some platforms. Need to test empirically.

**Probe design:** Create a tight loop function, run it 200K times to force DFG,
null all refs, GC aggressively, spray ArrayBuffers, scan for high addresses
(code pointers will be in the JIT region, which is a distinct VA range from
the heap).

### 2. JIT Region Detection via Timing

DFG-compiled code lives in executable pages allocated via mmap(PROT_EXEC).
The JIT region's VA range is distinct from the heap. If we can detect the
JIT region's location, we can infer the WebProcess memory layout.

p603 attempted JIT region detection but used an indirect approach. A more
direct method: measure the timing of accessing JIT-compiled function objects
vs interpreted ones. The CPU's instruction cache behavior differs for code
pages vs data pages. With enough iterations and BigInt arithmetic for
high-resolution timing, a side channel may emerge.

**Status:** Speculative. clock_gettime overhead (~90us on PS5) drowns
sub-microsecond signals, and performance.now() is heavily quantized (p630).
This angle is worth one more attempt with SharedArrayBuffer absent, but
expectations are low.

### 3. Error Object Backtrace Detail (Firmware-Specific)

p630 confirmed Error.stack has url:line:col only, no native addresses. But
this was tested on the standard Error object. Some WebKit builds include
extended stack trace information in internal error objects that surface
through specific code paths:

- Promise rejection with native callback (the rejection reason may carry
  internal trace data on debug-enabled builds)
- DFG OSR exit with bail-out reason (the bail-out metadata is accessible
  through the Error stack on some Safari versions)
- WebCore exception with extended info (DOM exceptions thrown from native
  code sometimes include the faulting address on non-release builds)

PS5's WebKit build may have debug traces enabled (Sony's build flags are
unknown). A targeted probe that triggers these specific paths and inspects
the resulting error objects could reveal addresses.

**Status:** Low probability but cheap to test. One probe covers all three.

### 4. CSS Font Loading Timing Oracle

FontFace loading involves system font enumeration, which touches kernel
font services. The timing of `document.fonts.load()` for different font
family names could vary based on:
- Whether the font exists in the system font list (hit vs miss)
- The position in the font enumeration table
- Internal hash table lookup patterns

If the timing is address-dependent (hash of font name uses address bits),
this becomes a KASLR oracle for the font service address space. This is
a long shot but novel -- no public research covers PS5 font service layout.

**Status:** Speculative. Requires high-resolution timing (blocked by
quantization). Worth documenting but not prioritizing.

### 5. Crash Backtrace Capture (Community Action Required)

CE-108262-9 error codes carry zero fault-type info (confirmed). But the
PS5 error history may contain extended crash data in a format we have not
captured. Specifically:

- The "Send Error Report" dialog may transmit backtrace frames to Sony
- The error history in Settings > System > Error History may show detail
  when accessed through a specific navigation path
- A USB debug log capture (if the PS5 writes to USB on crash) could
  contain module-relative addresses

**Community ask:** Anyone who can trigger a WebProcess crash on 14.10 and
capture the FULL error report (screenshot every screen of the error dialog,
check USB for log files, capture network traffic during "Send Report")
should share the results. One backtrace frame = game over.

### 6. Cross-Process Heap Spray via IPC

The game process (Lua loader) and WebProcess share the same kernel. If we
can predict WebProcess heap layout from the game process, or influence it
through shared resources:

- Shared memory objects created by the game process (shm_open works) may
  be mappable by WebProcess if they share a namespace
- File descriptors passed through Unix sockets could bridge process boundaries
  (SCM_RIGHTS is stripped in the game jail per p56q, but the WebProcess
  may be in a different jail)
- The GPU device (/dev/gc) is opened by both processes; shared GPU state
  could leak VA information

**Status:** Requires testing the bridge between Lua loader and WebProcess.
The browser entry infrastructure exists (docs/BROWSER_ENTRY_INFRA_2026-10-19.md).
This is the most architecturally promising direction after JIT residue.

## What the Community Can Contribute

Ranked by impact:

1. **Decrypted 14.00/14.10 WebProcess binary** -- one address unlocks everything
2. **Crash backtrace with module addresses** -- see angle #5 above
3. **WebKit 605.1.15 0-day** -- any info-leak in the 605.1.15 branch that
   discloses a code pointer (JIT address, vtable, return address)
4. **14.10 kernel dump** -- would reveal exact handler implementations, zone
   layouts, and verify the Debug Settings offset (DATA_BASE + 0x0DA4064)
5. **Independent bench testing** -- anyone with a 14.10 console can run
   probes from the `probes/phase13_webkit/` directory via the browser runner

## GTA 6 Timeline Pressure

GTA 6 launches holiday 2026. A 14.10 jailbreak before launch means:
- Homebrew/backup support on current firmware
- Modding potential for the biggest game release in years
- Massive community interest and contribution momentum

The exploit chain is 95% complete. One code pointer is the remaining 5%.
Every dollar donated to AI research credits directly accelerates the CVE
triage and probe generation that can find that pointer.

**Current goal: $150 for AI research credits.**
