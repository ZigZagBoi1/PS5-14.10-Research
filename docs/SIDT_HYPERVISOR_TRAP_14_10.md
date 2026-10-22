# SIDT/SGDT Hypervisor Trap on PS5 14.10

## Finding
The PS5 hypervisor traps SIDT and SGDT instructions, killing the process that executes them.

## Evidence

### Probe 144a (2026-10-22)
Two-phase diagnostic:

**Test A — Thread ROP without SIDT:**
- Thread created via thr_create(430), getcontext+modify pattern
- ROP chain: nanosleep(50ms) → write marker 0xAAAA1111 → long sleep
- Result: `DONE_A=0xAAAA1111` — **thread ROP works perfectly**

**Test B — Thread executes SIDT gadget:**
- Same infrastructure, plus: pop_rax → rbuf+0x73, pop_rcx → 0, SIDT gadget
- SIDT gadget at eboot+0x1C29F9: `sidt [rax-0x73]; add [r8+0x29],ecx; ret`
- R8 set in thread context to writable scratch memory
- Result: `THR_B=0x0` (thread started), then process crashed immediately

### SIDT gadget verification (143z scan)
- Gadget bytes confirmed at runtime: `0F 01 48 8D 41 01 48 29 C3`
- ModRM decode: mod=01, reg=001 (SIDT), r/m=000 (RAX), disp8=0x8D (-115)
- Full sequence: `sidt [rax-0x73]; add dword [r8+0x29], ecx; ret`

## Mechanism
The PS5 hypervisor has "Descriptor-table exiting" enabled in the VMCS. This traps:
- SGDT (Store Global Descriptor Table)
- SIDT (Store Interrupt Descriptor Table)
- LGDT (Load GDT)
- LIDT (Load IDT)

When a game process executes SIDT, the hypervisor intercepts and kills the process.

## Impact
SIDT/SGDT-based KASLR defeat is impossible on PS5 14.10. Both instructions would store kernel virtual addresses (IDT/GDT base), but the hypervisor prevents their execution.

## What's still possible
- SLDT/STR are controlled by a different VMCS field and may not be trapped (but they only store selectors, not addresses, so they don't help with KASLR)
- SMSW stores CR0 flags, not addresses
- CPUID is unlikely to be trapped but doesn't leak addresses
- Prefetch timing is ineffective on AMD Zen 2 (no user-mode page table walk)

## Conclusion
Instruction-based KASLR defeat is dead on PS5 14.10. Alternative approaches required: kernel info leak bugs, GPU DMA, or kernel R/W without KASLR.
