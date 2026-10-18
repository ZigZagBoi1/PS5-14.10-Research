# GPU DMA as a Kernel R/W Primitive on PS5

**Date:** 2026-10-18
**Target:** PS5 firmware 14.10, AMD RDNA2 (Oberon SoC), FreeBSD r230171 kernel

---

## Executive Summary

GPU DMA is a **proven technique** for kernel memory writes on PS5 firmware 6.00-7.61, disclosed by flat_z in early 2025 and integrated into PS5-JAR-Loader by Hammer-83. The technique exploits the fact that **GPU DMA transfers bypass the CPU's memory protection mechanisms** (SMAP, hypervisor stage-2 page tables), allowing writes to kernel `.data` sections that the CPU itself cannot perform after firmware 6.00's hypervisor protections. However, this technique has significant prerequisites that we likely cannot meet on firmware 14.10 from our current position.

**Bottom line: GPU DMA kernel writes are real and proven on PS5, but require either (a) a kernel exploit to get the physical addresses to target, or (b) access to GNM command buffer submission APIs which are not available from our Lua loader.**

---

## 1. How GPU DMA Works on PS5

### 1.1 AMD GPUVM Architecture

The PS5's RDNA2 GPU has its own MMU called **GPUVM** (GPU Virtual Memory). Key facts:

- The GPU operates in its own virtual address space, separate from the CPU's
- **GPUVM page tables** map GPU virtual addresses to physical addresses
- The kernel driver sets up these mappings when allocating GPU memory
- Each process gets its own GPUVM address space (identified by a VMID)
- GPU page table entries contain physical addresses, valid bits, read/write/execute permissions, and cache control bits

### 1.2 The DMA Bypass Principle

On ARM (Samsung/Qualcomm) and x86 (PS5), the key insight is:

1. **CPU writes** go through the CPU's MMU and (on PS5) the hypervisor's stage-2 translation. The hypervisor marks kernel `.data` as read-only at stage-2, so CPU writes panic.
2. **GPU DMA writes** go through the GPU's own GPUVM page tables but **do NOT go through the CPU's stage-2 translation**. If the GPU page table maps a physical address that corresponds to kernel memory, the GPU can write there even though the CPU cannot.

This is the same principle exploited in:
- **PS5 firmware 6.00-7.61** (flat_z, 2025): GPU DMA to write kernel `.data`
- **Samsung/Qualcomm Android** (Jamf Threat Labs, CVE-2025-21479, 2026): GPU command submission to bypass Samsung RKP/KDP hypervisor protections
- **3DS** (smealum "gspwn", 2015): GPU DMA to overwrite read-only executable pages

### 1.3 What's Needed

To use GPU DMA for kernel writes, you need:

1. **Target physical address**: Know which physical address corresponds to the kernel data you want to modify. This requires either:
   - A KASLR defeat + knowledge of kernel virtual-to-physical mapping
   - A separate kernel info leak that reveals physical addresses
   - A brute-force/oracle approach

2. **GPU command buffer submission**: Ability to submit GPU commands that perform a DMA copy from a buffer you control to the target physical address. On PS5 this means:
   - Access to `sceGnmSubmitCommandBuffers` / `sceGnmSubmitDone` from `libSceGnmDriverForNeoMode.sprx`
   - OR direct ioctl to the GPU kernel driver
   - OR crafting PM4 command packets and getting them into the GPU command ring

3. **GPU page table manipulation**: Either:
   - The GPU driver willingly maps the target physical address (unlikely for kernel pages)
   - You can corrupt GPU page table entries to point at arbitrary physical addresses
   - You can submit PM4 commands that directly reference physical addresses (some packet types allow this)

---

## 2. PS5-Specific GPU DMA Research

### 2.1 Confirmed: GPU DMA Kernel Writes Work on PS5

The PS5 Developer Wiki documents this clearly:
- From firmware 6.00+, the hypervisor protects kernel `.data` from CPU writes (panic on write)
- **The GPU can still write to kernel `.data` via DMA** because GPU DMA bypasses the hypervisor's stage-2 translation
- Kernel `.text` CANNOT be written even by GPU DMA (execute-only memory / XOM protection operates at a different level)
- The technique was used in exploit chains for firmware 6.00-7.61

### 2.2 Known Entry Points for GPU Command Submission

From the PS5 Developer Wiki and community research:

| Entry Point | Access Method | Our Status |
|-------------|--------------|------------|
| `sceGnmSubmitCommandBuffers` | Via `libSceGnmDriverForNeoMode.sprx` | **NOT LOADED** in Lua loader process |
| BD-J Java GNM utils | `Java.sun.awt.GnmUtils.copyPlanesBackgroundToPrimary` | **NOT AVAILABLE** (not a BD-J app) |
| Direct GPU driver ioctl | Unknown ioctl number on `/dev/gc` or similar | **UNTESTED** |
| PM4 packet injection | Would need ring buffer address or submit path | **NO KNOWN PATH** |

### 2.3 The IOMMU Question

The PS5 hypervisor manages the IOMMU (AMD-Vi). The PS5 Dev Wiki confirms:
- The hypervisor exposes hypercalls for IOMMU configuration
- This means the IOMMU exists and is active on PS5
- However, the GPU DMA bypass works because **the IOMMU is configured to allow GPU access to the physical pages the GPU driver has mapped** — the protection is at the CPU's hypervisor level, not the IOMMU level

The critical distinction:
- **IOMMU** restricts which physical pages the GPU can access (device-level isolation)
- **Hypervisor stage-2** restricts which physical pages the CPU can write (CPU-level protection)
- GPU DMA bypasses the latter but not the former

So even with GPU command submission, we can only write to physical pages the IOMMU permits the GPU to access. This likely includes:
- GPU VRAM
- Shared memory regions mapped by the GPU driver
- Possibly kernel `.data` pages if the GPU driver has them mapped (this is what flat_z exploited)

---

## 3. Feasibility Assessment for Our Situation

### 3.1 What We Have

| Primitive | Relevant? |
|-----------|-----------|
| `make_syscall(N)` — arbitrary syscall | Yes, could try GPU ioctls |
| GPU mmap (syscall 477, anonymous) | Gives us R/W heap pages, NOT GPU command submission |
| Heap R/W (256+ pages) | Could corrupt GPU-related structures if we find them |
| Userland ASLR bypass | Helps find GNM library if loaded |
| `dynlib_get_info(593)` | Can check if GPU libraries are loaded |

### 3.2 Critical Gaps

**Gap 1: No GPU command submission path**

Our GPU mmap (syscall 477 with fd=0xFFFFFFFF) creates **anonymous memory mappings**, not GPU command buffers. To submit GPU commands, we would need:

- The GNM driver library loaded in our process (check with `dynlib_get_info`)
- Access to the GPU device node (likely `/dev/gc` or `/dev/dce` — untested)
- The specific ioctl numbers for command buffer submission (proprietary, not publicly documented)

**Gap 2: No KASLR defeat**

Even if we could submit GPU commands, we need to know **which physical address** to target. We have no kernel pointer leaks and no KASLR defeat. The kernel virtual addresses are unknown, and the virtual-to-physical mapping requires kernel page table access.

**Gap 3: No GPU page table access**

To make the GPU write to an arbitrary physical address, we would need to either:
- Corrupt a GPU page table entry (requires knowing where they are in physical memory)
- Use a PM4 packet that takes a raw physical address (some exist, but submission path is missing)
- Convince the GPU driver to map a target physical address into our GPUVM (unlikely without kernel R/W)

### 3.3 Possible Approaches (Ranked)

**Approach A: Find GPU driver ioctl for command submission (MEDIUM priority)**

1. Check if GPU-related device nodes are accessible: `/dev/gc`, `/dev/dce`, `/dev/gpu0`, etc.
2. Use `make_syscall(5)` (open) to try opening them
3. If accessible, try known AMD GPU ioctl numbers via `make_syscall(54)` (ioctl)
4. On Linux amdgpu, command submission is `DRM_IOCTL_AMDGPU_CS` — PS5 will be different but conceptually similar

**Approach B: Check if GNM libraries are loaded (HIGH priority, easy test)**

1. Use `dynlib_get_info(593)` to enumerate all 39 modules
2. Look for anything GNM/GPU related in the loaded module list
3. If `libSceGnmDriverForNeoMode.sprx` or similar is loaded, find its function exports

**Approach C: GPU mmap as physical memory window (SPECULATIVE)**

Our current GPU mmap (syscall 477) maps anonymous pages. But:
- What if we mmap with a real GPU device fd instead of 0xFFFFFFFF?
- What if specific offset values to mmap correspond to physical addresses?
- The `/dev/dmem0` path was tested and found to be GPU-only (no kernel memory access)

**Approach D: Corrupt GPU page tables via heap spray (HIGHLY SPECULATIVE)**

1. GPU page tables are somewhere in physical memory
2. If they're in the same region as our heap allocations, adjacent GPU mmap pages might overlap with GPU page table pages
3. Modifying a GPU PTE to point at a kernel physical page would give GPU access to kernel memory
4. This requires finding GPU PTEs in the heap, which is a needle-in-a-haystack problem without kernel info

---

## 4. Analogous Research on Other Platforms

### 4.1 Samsung/Android GPU DMA (Jamf, 2026)

The most detailed public write-up of GPU DMA kernel bypass:
- Exploits Qualcomm Adreno GPU driver flaw (CVE-2025-21479)
- GPU DMA does not go through CPU's Stage 2 translation
- Uses a self-referencing page table trick
- Bypasses Samsung RKP, KDP, DEFEX, and JOPP/ROPP protections
- Achieves full root + SELinux disable + code injection

Key takeaway: Even with IOMMU active, if the GPU driver has kernel pages mapped, GPU DMA can write them.

### 4.2 GPUBreach (2026, arXiv)

Academic research on NVIDIA GPU Rowhammer:
- Compromised GPU corrupts GPU page table entries via Rowhammer
- Reaches CPU memory through corrupted PTEs
- IOMMU limits access to driver-shared buffers, not arbitrary physical memory
- Shows that GPU-side attacks are a real category even with IOMMU

### 4.3 3DS gspwn (smealum, 2015)

- GPU DMA writes bypass CPU MMU entirely (no IOMMU on 3DS)
- Overwrites read-only executable pages
- Simplest case: no IOMMU, no hypervisor, direct physical access

---

## 5. Recommended Next Steps

### Immediate (can test with current primitives):

1. **Probe: Enumerate GPU device nodes**
   ```lua
   -- Try opening /dev/gc, /dev/dce, /dev/gpu0, /dev/submitdone, etc.
   local sc_open = make_syscall(5)
   for _, dev in ipairs({"/dev/gc", "/dev/dce", "/dev/gpu0"}) do
       local buf = memory.alloc(32)
       -- write device path string, try open
   end
   ```

2. **Probe: Check loaded GPU libraries**
   - Scan all 39 module handles for GNM/GPU-related names
   - If any GPU library is loaded, dump its export table

3. **Probe: mmap with GPU device fd**
   - If `/dev/gc` opens successfully, try mmap with that fd
   - Different offsets may map different physical regions

### Medium-term (requires new info):

4. **Reverse engineer GPU ioctl interface** — If we can open a GPU device, send known AMD ioctl numbers
5. **Side-channel via syscall 624** — The live VM counter might reveal information about GPU page table operations
6. **Physical address oracle** — Look for any syscall that reveals physical address mappings

### Long-term / speculative:

7. **Heap-adjacent GPU PTE corruption** — If GPU page tables are allocated near our GPU mmap region
8. **DMA_BUF or similar** — Check if FreeBSD's DMA buffer sharing mechanisms are accessible

---

## 6. Key Risks and Limitations

1. **Firmware 14.10 is much newer** than the 6.00-7.61 range where GPU DMA was proven. Sony may have added IOMMU restrictions that prevent GPU access to kernel physical pages.

2. **No public documentation** exists for PS5 GPU driver ioctls. Everything must be discovered through probing or reverse engineering.

3. **GPU page tables are likely kernel-managed** and not accessible from userland, creating a chicken-and-egg problem (need kernel R/W to manipulate GPU PTEs, need GPU DMA to get kernel R/W).

4. **Crash risk is HIGH** for GPU-related probing — incorrect GPU commands or page table corruption can hang the GPU or panic the kernel.

5. **The Lua loader process may not have GPU access** at all — it depends on whether the process has a GPU context and relevant device file descriptors.

---

## Sources

- [PS5 Developer Wiki - Vulnerabilities](https://www.psdevwiki.com/ps5/Vulnerabilities)
- [PS5 Developer Wiki - Hypervisor](https://playstationdev.wiki/ps5devwiki/index.php/Hypervisor)
- [PS5-JAR-Loader with GPU DMA kernel R/W (Wololo)](https://wololo.net/2025/02/12/ps5-firmwares-6-00-to-7-61-are-getting-kernel-read-write-ps5-jar-loader-released-with-kernel-r-w-support-for-6-00-to-7-61/)
- [Samsung Kernel Protections Bypassed via GPU DMA (Jamf)](https://www.jamf.com/blog/samsung-kernel-protections-gpu-dma-bypass/)
- [GPUBreach: Privilege Escalation via GPU Rowhammer (arXiv)](https://arxiv.org/pdf/2605.03812)
- [PS5 IPv6 Kernel Exploit (Cryptogenic)](https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit)
- [AMDGPU Driver Documentation (kernel.org)](https://docs.kernel.org/6.2/gpu/amdgpu/amdgpu-glossary.html)
- [ps5-hen GPU DMA implementation (cragson)](https://github.com/cragson/ps5-hen/blob/master/gpu_dma.h)
- [Byepervisor - PS5 HV exploit](https://github.com/PS5Dev/Byepervisor)
- [CVE-2025-21479 - Qualcomm GPU vulnerability (NVD)](https://nvd.nist.gov/vuln/detail/cve-2025-21479)
- [IOMMU Protection Against I/O Attacks (Springer)](https://link.springer.com/article/10.1186/s13173-017-0066-7)
- [DMA Attack (Wikipedia)](https://en.wikipedia.org/wiki/DMA_attack)
- [Gateway Ultra / gspwn GPU DMA technique](https://yifan.lu/2015/01/12/reversing-gateway-ultra-first-stage-part-2/)
