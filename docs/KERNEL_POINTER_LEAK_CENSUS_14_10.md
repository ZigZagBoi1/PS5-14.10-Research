# Kernel pointer leak census - 13.60 kernel image (PS5 14.10 research)

Image: docs/dumps_13.60/kernel_text.bin, 0xE6E5C0 bytes, base VA 0xffffffff8a9c0000, file offset == RVA.
Sysent: docs/dumps_13.60/sysent_index.json (679 records, 301 distinct sy_call_off).
copyout: RVA 0x2591d0 (rdi = kernel source, rsi = user destination, rdx = length). copyin: 0x259280.
Scope: static only. No probe was run and nothing here is dynamically confirmed.

## Verdict

Four copyout sites copy a stack record whose first qword is a kernel data address:
0x8f6424 (sysent body 0x8f6120, syscall 397, 0x1d8 bytes) and 0xabc9f1 (sysent body
0xabc710, syscall 607, 0x88 bytes), plus 0x3c1d93 and 0x3c2093 in functions that have no
direct callers at all. The value stored is a lea of an image-relative static object,
resolving to 0xffffffff8c49cdc8 (base+0x1adcdc8) or 0xffffffff8c49a7f8 (base+0x1ada7f8) at
offset 0 of the copied record. If the record is not rewritten by a callee before the
copyout, each call returns a full kernel pointer and defeats KASLR for the data segment.

On the other 535 sites the copied bytes are the handler's own stack frame, a kernel object
field copied verbatim, or a call return value. No site stores an in-image 64-bit pointer
constant (count 0), and no site stores a value that was freshly loaded from a kernel object
into the copied stack range (count 0 with traced displacements). Class D of the earlier
syscall-only pass stays empty; the four sites above are a different shape: a static
kernel-data address written into an outbound record.

## Method

1. One byte pass over the whole image (numpy, no disassembly): every 0xE8 with rel32
   resolving to 0x2591d0. Result 539 sites, matching .local/allcopy_sites.json.
2. All 301 sysent entries are 8-byte trampolines: jmp <body> followed by int3 padding
   (verified: 0 of 301 start with anything but 0xE9). The bodies are the jmp targets,
   not the sy_call_off values, so the earlier "inside a syscall body" attribution has to
   use the target. With targets resolved, 205 of the 539 sites sit in sysent-reachable
   code, 166 in functions with no direct caller, 168 elsewhere.
3. Function map: 24039 plausible prologues (55 48 89 e5 preceded by ret/int3/nop or being
   a call target). Capstone was used only on windows decoded forward from a prologue, in
   0x400-byte slices, never on the whole image.
4. Source classification: backward slice of rdi from the call, following mov/lea/add
   chains, max 8 hops, within the enclosing body.

Class counts over 539 sites: stack 359, field (mov rdi,[reg+disp]) 67, call-returned 39,
global (lea rdi,[rip+d]) 25, object address (lea rdi,[reg+d]) 15, stack pop 10, immediate 3,
other 3, unresolved 16, undecoded 2.

## Sites that can carry a kernel pointer

| site RVA | enclosing function | how the value is obtained | copyout len | reachability | what the caller sees |
|---|---|---|---|---|---|
| 0x8f6424 | 0x8f6120, sysent body, syscall 397 (narg 2) | lea rax,[rip+0x11e6b83] -> 0x1adcdc8 at 0x8f623e, then mov qword ptr [rbp-0x3f0],rax at 0x8f624c; copyout source lea rdi,[rbp-0x3f0] | 0x1d8 (mov edx,0x1d8) | direct syscall | first 8 bytes = 0xffffffff8c49cdc8, rest of a 472-byte record |
| 0xabc9f1 | 0xabc710, sysent body, syscall 607 (narg 2) | lea rcx,[rip+0x101dff4] -> 0x1ada7f8 at 0xabc7fd, mov qword ptr [rbp-0x1a0],rcx at 0xabc80e; copyout source lea rdi,[rbp-0x1a0] | 0x88 (mov edx,0x88) | direct syscall | first 8 bytes = 0xffffffff8c49a7f8, rest of a 136-byte record |
| 0x3c1d93 | 0x3c1ab0, no direct callers | lea rcx,[rip+0x171b260] -> 0x1adcdc8 stored at 0x3c1b76; lea r9,[rip+0x1719915] -> 0x1adb4f8 stored at 0x3c1be3; both to [rbp-0x430] | r14 (variable) | indirect dispatch only | head of the buffer = 0xffffffff8c49cdc8 or 0xffffffff8c49b4f8 |
| 0x3c2093 | 0x3c1e10, no direct callers | same two constants, stores at 0x3c1ed4 and 0x3c1f4b into [rbp-0x430] | r12 (variable) | indirect dispatch only | as above |

Checked and rejected: 0x6432a3 (function 0x642410) stores the same 0x1adcdc8 at
[rbp-0x5c0] but the copyout reads [rbp-0x5c4] with length 4, so the pointer is outside the
copied range.

Residual risk on all four rows: the linear window shows no later store to the same slot,
but a called helper can rewrite the record through a pointer it was handed, and the
windows contain jump-table bytes (the stream decodes as garbage between 0x3c1b84 and
0x3c1d60), so the store-to-copyout path is not proven for those two rows.

## Sites that cannot carry a kernel pointer (one line per class)

- stack, 355 remaining sites: the source is the function's own frame and the only stores
  into the copied range are immediates or locally computed scalars; no lea of a kernel
  address lands in the range.
- field, 67 sites: rdi is a load from a kernel object, so the copied bytes are that
  object's own contents; none is a pointer field at offset 0 of a nonzero-length copy.
- call-returned, 39 sites: rdi is rax after a call (allocator or fill helper); the window
  contains no store of a kernel address into the buffer before the copy.
- global, 25 sites: rdi is the address of a static table or string with lengths 1 to 3464;
  a static object can only hold a relocated pointer, and the corresponding data page is
  not in the retained dump, so this class is unverified rather than cleared.
- object address, 15 sites: rdi is a field address inside a kernel object, same argument
  as the field class.
- stack pop, 10 sites: rdi is popped from the frame, i.e. a saved register, not a pointer
  source.
- immediate, 3 sites: rdi is a small constant.
- other/unresolved/undecoded, 21 sites: no definition found in the window; no kernel
  address observed.

## Secondary detectors (the shapes that would have shown a pointer landing in a record)

- mov rax,[reg+disp] followed by mov [rbp-disp],rax into a copied stack slot: 0 sites
  after slot reconciliation (a first pass without traced displacements reported 335, all
  of them slot-attribution artifacts; the true count is 0).
- movabs or mov of an immediate in 0xffffffff8a000000-0xffffffff8b900000 into a copied
  slot: 0 sites.
- lea reg,[rip+d] stored into a copied stack slot: 7 stores in 5 functions, of which 4
  overlap the copied range (the table above) and 1 does not (0x6432a3). The remaining 2
  belong to the same 0x3c1ab0 / 0x3c1e10 rows.

## Ranked shortlist of interfaces to call first

1. syscall 607, handler 0xabc710, copyout 0xabc9f1, fixed 0x88 bytes, first qword
   0x1ada7f8. Shape: arg2 is dereferenced as a pointer (mov r12,[rsi]) and a 0x400-byte
   copyin follows from that pointer, so pass arg2 = pointer to a qword holding a user
   buffer:
   b = memory.alloc(0x1000); pp = memory.alloc(0x10); memory.write_qword(pp, b);
   make_syscall(607)(uint64(0), uint64(pp)); then scan b[0..0x1000] for any qword in
   0xffffffff8a000000-0xffffffff8d000000. Strongest candidate: fixed length, direct
   syscall, record built on the stack immediately before the copy.
2. syscall 397, handler 0x8f6120, copyout 0x8f6424, fixed 0x1d8 bytes, first qword
   0x1adcdc8. Shape: the handler reads a dword from arg2 (mov r15d,[r12]) and builds the
   record at [rbp-0x3f0]; pass arg2 = pointer to a zeroed dword and a user buffer as
   arg1, then scan the returned 0x1d8 bytes for 0xffffffff8c49cdc8. Second only because
   the destination chain is indirect ([rbp-0x3f8]+8).
3. 0x3c1ab0 copyout 0x3c1d93, variable length in r14, first qword 0x1adcdc8 or 0x1adb4f8.
   No direct caller, so it has to be located through a method table first; call it with a
   buffer whose length argument is at least 16 and read the first qword.
4. 0x3c1e10 copyout 0x3c2093, same constants, variable length in r12, same prerequisite.
5. Follow-up, not a call: the 25 global-source sites copy static objects out; dumping the
   kernel data page at 0xffffffff8c000000-0xffffffff8c9fffff would settle whether any
   static struct in that range holds a relocated pointer that is copied verbatim.

## What this does not prove

- No runtime confirmation. Every row is a static store-to-copyout observation inside a
  window; a callee may overwrite the record.
- The 0x8c49cdc8 / 0x8c49a7f8 targets are image-relative offsets (0x1adcdc8, 0x1ada7f8),
  i.e. inside the kernel data segment, but the object they point at is not in the retained
  dump, so the leak, if it lands, is a data-segment pointer, not a text pointer.
- The two 0x3c1* functions are only reachable through indirect dispatch; no call site to
  them exists in the image, so their userland entry interface is unknown from static code.
