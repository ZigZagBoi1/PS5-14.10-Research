# syscall 393 (sendfile): present and working on 14.10; static decode of the 13.60 body

## Why this was opened

The offline suite has carried one unexplained failure for two sessions:

    tools/test_remaining_cve_triage.py::CorpusAbsenceTests::test_no_sendfile_in_the_corpus

The test asserts that sendfile does not appear in the corpus and it fails, so somewhere a claim of
absence was made and the corpus disagrees. The 13.60 sysent index settles that half of it:
entry 393 exists with `narg = 7` and a real handler thunk (`sy_call_off 0x265b88`), not the shared
nosys target `0x265760`. No probe in this repository has ever called 393 on 14.10 and the
dead-end list in CLAUDE.md never mentions it, so its 14.10 status is genuinely unknown.

## The body

`0x265b88  e9 53 e5 5c 00` tail-jumps to body `0x8340e0`; a full-image scan finds exactly one
reference to that body, so it is not shared. Decoded argument slots (uap is `rsi`, `rdi` is
`struct thread *`):

| uap slot | meaning | first use |
|---|---|---|
| +0x00 | `int fd` | `8341b8 mov r15d,[rbx]` |
| +0x08 | `int s` | `8341ee mov esi,[rbx+8]` |
| +0x10 | `off_t offset` | `834103 cmp qword [rsi+0x10],0 / 834108 js 0x834289` -> EINVAL 0x16 |
| +0x18 | `size_t nbytes` | `8341fd mov r9,[rbx+0x18]` |
| +0x20 | `struct sf_hdtr *hdtr` | `83412c mov r15,[rsi+0x20]` |
| +0x28 | `off_t *sbytes` | `8341f9 mov r8,[rbx+0x10]` (see note) |
| +0x30 | `int flags` | `834201 mov r13d,[rbx+0x30]` |

Note on the two pointer slots: the body hands `[rbx+0x10]` (the *offset* slot) and `[rbx+0x18]`
(the *nbytes* slot) to the file-type call, because `kern_sendfile` takes both by pointer and writes
the residual back through them; `[rbx+0x28]` (sbytes) is the separate user pointer.

The hdtr path:

    834158  call 0x259280           ; copyin(hdtr, &kbuf, 0x20)   fixed size
    834165  mov rdi,[rbp-0x60]      ; kb.headers
    834169  test rdi,rdi / je skip
    83416e  mov esi,[rbp-0x58]      ; kb.hdr_cnt
    834175  call 0x7828a0           ; copyinuio(headers, hdr_cnt, &hdr_uio)
    834182  mov rdi,[rbp-0x50]      ; kb.trailers
    83418b  mov esi,[rbp-0x48]      ; kb.trl_cnt
    834192  call 0x7828a0           ; copyinuio(trailers, trl_cnt, &trl_uio)

Then the descriptor is resolved and the file-type method is called:

    8341cf  call 0x2bc220           ; capability/rights check on fd
    8341e1  call 0x72e180           ; fget -> [rbp-0x78] = struct file *
    834205  mov rax,[rdi+8] / 834209 mov r15,[rax+0x50]   ; fp->f_ops->fo_?? at +0x50
    83420d  lea rax,[rip-0x5c22a4] / sub rax,r15 / ror rax,3 / cmp rax,2 / ja reject
    834229  lea rax,[rbp-0x80] / push r14 / push r13 / push rax / call r15
    83423d  mov edx,0xffffffff / lock xadd [rcx+0x28],edx   ; refcount drop
    834256  call 0x72b380           ; fdrop

The call passes nine arguments, three of them on the stack: `(td, fp, s, &offset, &nbytes,
hdr_uio, trl_uio, flags, sbytes)`. The `ror rax,3 ; cmp rax,2` test is the same fixed-set CFI
membership test seen elsewhere in this kernel, so the callee is one of a small whitelist of file
operation tables, not a caller-controlled pointer.

## What this does and does not give

Every user-controlled length in the body is fixed or bounded by a callee that is itself audited in
this repository: the hdtr struct is 0x20 bytes, and `copyinuio` is the standard FreeBSD helper
that rejects `iovcnt > IOV_MAX` before copying. There is no caller-controlled copyin length and no
caller-controlled copyout length anywhere in `kern_sendfile`. So if 393 is present on 14.10, the
argument marshalling is not the surface; the surface would be a bug inside the vnode
`fo_*` method, which is a different and much larger body of code with no sysent anchor.

The 7th argument is worth a note for anyone running this: it cannot be set from this loader, because
the loader's stub only fills the six SysV argument registers and the kernel takes arg 6 from the
user stack. FreeBSD rejects unknown `SF_*` bits with EINVAL, so the garbage value cannot do damage.

## Measurement status: MEASURED, present and working

Probe `probes/phase17_new_vectors/1241a_sendfile_presence.lua` now has a result: the slot exists,
`rv = 0`, `sbytes = 256`, and 256 bytes of `eboot.bin` arrived on the peer socket. See the runtime
section at the end of this document. The first attempt at this probe was sent while the loader was
still wedged from the earlier `read()`-with-flags probe (connect accepted, 0 bytes, IDLE_TIMEOUT
30.03 s), which is why the capability was recorded as untested for a while.

## Reproduce

    python .local/dis_sendfile.py

reads `docs/dumps_13.60/kernel_text.bin` at file offset 0x8340e0 (offset == RVA in this capture)
and prints the body with copyin/copyout/bzero/memcpy call targets annotated.

## 14.10 runtime result: 393 is present and it works

Probe `probes/phase17_new_vectors/1241a_sendfile_presence.lua`, run after the loader was relaunched
(result `results/phase17_new_vectors/1241a_sendfile_presence_20261105_135444.txt`):

    [id] pid=101
    [setup] open(/app0/eboot.bin) -> 22
    [setup] socketpair rv=0 fds=23,24
    [call] 393(fd=22, s=24, off=0, nbytes=0x100, hdtr=NULL, sbytes=&out)
    [call] rv=0 sbytes=256
    [recv] n=256

So the slot exists on 14.10, it is callable with six arguments, and it performed a real transfer:
256 bytes of `eboot.bin` arrived on the socketpair peer. That settles the question the probe was
written for, and it retires the assumption in the older triage note that `sendfile` is absent from
this image (the pytest corpus-absence test was already signalling that the absence claim was wrong).

The probe then died in its own formatting code (`bad argument #2 to format` on a uint64 returned by
`memory.read_byte`), which is a probe defect, not a kernel result; the fix (wrap in the numeric
coercion helper) is in the committed probe.

What this changes: the syscall layer is the part that is safe (fixed 0x20 `sf_hdtr` copyin,
`copyinuio` bounded at 0x400 iovecs - see below), so any value in 393 now lies in the socket
`fo_sendfile` implementation it hands off to, which is ordinary FreeBSD socket-buffer code. That is a
new live path on a firmware where most of the interesting ones are gated, and it is worth a pass
before anything else in the socket family.

### copyinuio is bounded (static, 0x7828a0)

    mov eax,0x16 ; mov qword [rdx],0 ; cmp esi,0x400 ; ja EINVAL
    shl r12d,4 ; lea rax,[r12+0x30] ; call 0x8b5c8b50(malloc)
    copyin(iov, buf+0x30, iovcnt*16)
    loop: mov r12,[r15] ; call 0x8aeabfb0 ; cmp r12,rax ; ja EINVAL ; add [r14+0x18],[r15]

iovcnt is capped at 0x400 before the multiply, the allocation is `cnt*16+0x30`, the copyin is exactly
`cnt*16`, and each iov_base is checked against a limit from 0x8aeabfb0. No overflow, no uninitialised
slot in the uio it builds.
