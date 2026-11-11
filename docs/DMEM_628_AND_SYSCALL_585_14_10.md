# dmem 628 fully mapped, and syscall 585 is not mprotect

Date: 2026-11-05.  Static decode of docs/dumps_13.60/kernel_text.bin (base
0xffffffff8a9c0000, file offset == RVA).  Probes written: 1247a, 1248a.

## 1. Why this document exists

Two things were believed and are now corrected:

1. That mmap_dmem (628) takes (address, length, prot, flags, ...) and that only the
   flags value 0xffffffff skips the container lookup.  The real order puts the
   **container index in arg2** and the flags in arg3, and the "lookup" turned out
   to be a 6-instruction function that does not look at the process at all.
2. That mtypeprotect(585) sets a page executable and that probe 44a proved it.
   585's body does not touch its arguments.

## 2. Syscall 585 (upstream name is_in_sandbox) - exact body

Thunk 0x265DF8 -> body 0x8FC610:

    8FC610 push rbp / mov rbp,rsp / push r15 / push r14 / push rbx / push rax
    8FC61A mov rax,[rdi+8]              ; proc
    8FC627 mov r15,[rax+0x48]           ; object referenced by the proc
    8FC62B lea r14,[r15+0x40]
    8FC632 call 0xc4bb20                ; lock
    8FC637 mov rax,[r15+0x10]
    8FC63D cmp rax,[rip+0x350eecc]      ; against a fixed global identity
    8FC647 setne cl
    8FC64E mov [rbx+0x408],rcx          ; td+0x408 = (object != global) ? 1 : 0
    8FC655 call 0xc4c4b0                ; unlock
    8FC65A xor eax,eax / ret

Facts:

- **rsi is never read.**  The handler takes no argument.  Whatever the caller passes
  as (page, length, prot) is discarded.
- The return value is always 0.  It cannot report success or failure per argument.
- The only effect is a boolean store at td+0x408.

So 585 is a sandbox-membership predicate, exactly the name in
docs/sysent-names-13.60.csv.  It cannot change a page's protection, and the
probe-44a conclusion ("mtypeprotect made the page executable, NOP sled survived")
does not follow from it.  The most likely explanation of 44a is the one 44a itself
noticed: the test call went through the loader's syscall stub, which reloads rax
from the syscall, so the observed "0x41414141 test returned the pid" is the stub's
behaviour, not the sled's.

Combined with the direct measurement in probe 1245a - an anonymous prot=7 page is
mapped, readable, writable, and fcall into it faults with RIP = the page and
CS = 0x43 - the state of the question is: **no executable user page is known to
exist**, therefore no ring-3 shellcode (and no Spectre gadget) is reachable yet.

docs/SPECULATION_READ_14_10.md section 4 depended on 44a.  It now carries a
correction pointing here.

## 3. Syscall 628 (mmap_dmem) - real argument layout

Body 0xABD540.  rdi = struct thread *td, rsi = struct syscall_args *uap.

| uap | meaning | where it goes |
|---|---|---|
| 0x00 | physical offset / address | r12, later [rbp-0x38] (also the in/out slot) |
| 0x08 | length | [rbp-0x48] |
| 0x10 | **container index** (dword) | rbx, saved at [rbp-0x4c] |
| 0x18 | **flags/prot** (dword) | eax, clamped to AL unless proc+0x5d4 >= 0x3000000 |
| 0x20 | extra bits (dword) | [rbp-0x60], later r11 |
| 0x28 | extra address (qword) | [rbp-0x58] |

Sequence:

- 0xABD593 mov rdi,[rdi+0x140] (cred) then **three capability helpers**:
  0xABD5AA call 0x609560, 0xABD5D7 call 0x6095a0, 0xABD5EB call 0x6092d0.
  Any nonzero result returns 1.  Measured probes got 16/22, never 1, so a level-2
  user passes all three.
- 0xABD62C mov rax,r12 ; mov ecx,0x16 ; shl rax,0x32 ; jne error -> arg0 < 2^50.
- 0xABD642 test esi,0x3fff ; setne al  and  cmp rsi,0x4000 ; setb dl -> length must
  be >= 0x4000 and 0x4000-aligned.
- 0xABD660 cmp r13d,-1 ; je 0xABD698 -> **arg2 == 0xffffffff skips the lookup**.
- 0xABD671 call 0x3c33e0 (see below); a 0 result is EINVAL.
- 0xABD68C and eax,0xfffffc0c ; je -> flags may only use bits 0x3f3.
- 0xABD6AF test edi,0x9fdf2f -> arg4 may only use bits 0x6020d0.
- 0xABD6D0, when arg4 bit 6 is set: length must be <= 0x4000 and flags & 3 must be nonzero.
- 0xABD6F0, when arg4 bit 0x200000 is set: call 0xb24300(proc) - a privileged predicate.
- 0xABD70F..0xABD73D: call 0xab8320(proc), movabs rdx,0xfffffff810000000,
  lea rdi,[r15+0x10000001] with r15 = 0x7efffffff, then cmp ebx,0x40 ; jb ok
  and cmp byte [proc+0xc81],0 ; je EINVAL - the devkit gate on high flag bits.
- 0xABD83D lea rdx,[rbp-0x38] (the in/out address), then the 9-argument call to the
  worker 0x3CB450.

## 4. The container lookup is a bounds check with no process in it

    3C33E0 push rbp / mov rbp,rsp / xor eax,eax
    3C33E6 cmp edi,0x15
    3C33E9 setb al / pop rbp / ret

Return idx < 0x15.  The rsi argument (proc) is unused.  Therefore **21 container
indices reach the worker for any user**, and the entire decision is made by the
worker's descriptor walk.  (An earlier note said the table had at most 5 entries,
from 586's cmp r14d,4; 586 is the *setter* of proc+0x5c4 and has its own narrower
bound.  The table itself is indexed up to 0x14 here.)

## 5. Worker 0x3CB450 - what decides success

Registers: rdi = td, rsi = vmspace, rdx = &addr, rcx = container index,
r8 = physical address, r9 = length.

    3CB499 mov r14,r8 ; shr r14,0x24 ; cmp r14d,4 ; ja error      ; r8 < 0x5000000000
    3CB4A6 movabs r14,0x4fffffffff ; sub r14,r8 ; inc r14
    3CB4BA cmp r14,r13 ; jb error                                 ; len <= 0x5000000000 - r8
    3CB4D0 lea r14,[rip+0x3105979]                                ; container table base
    3CB506 imul rdx,r11,0x138 ; add r14,rdx                       ; entry = base + idx*0x138
    3CB510 test eax,eax ; je 0x3CB52D                             ; eax = the 9th argument
    3CB52D mov rdi,[rdi+8] ; mov rsi,r14 ; mov edx,1 ; call 0x3c3740   ; take a reference
    3CB545 mov rax,[r14+0x40] ; lea rdi,[r14+0x18] ; call 0x4c6a00     ; lock entry+0x18
    3CB56B mov rax,[r14+0x50]                                        ; thread list head
    3CB61B mov rsi,[r14+0x48] ; call 0x3c3ff0(r8, r14)               ; descriptor lookup
    3CB638 mov [r14+0x48],rax
    3CB63C cmp byte [rax+0x69],0xfe ; jne 0x3cb683                   ; state byte must be 0xfe
    3CB642 cmp [rax+0x48],rbx ; jg 0x3cb683                          ; desc.lo <= phys
    3CB648 mov rcx,[rax+0x50] ; cmp rbx,rcx ; jge 0x3cb683           ; phys < desc.hi
    3CB651 cmp rcx,[rbp-0xb0] ; jge 0x3cbbaa                         ; desc.hi >= phys+len

So a mapping succeeds only when some descriptor of the selected container has
state byte 0xfe and covers [phys, phys+len).  Three failure classes are therefore
distinguishable at runtime: EINVAL from the entry check, EACCES (0xd, loaded into
r15d at 0x3CB472 and 0x3CB61F) from the descriptor walk, EBUSY from the reference
or lock helper.

The container table sits at RVA ~0x34D0E50, past the end of the 15.1 MB dump, so
the descriptor contents cannot be read statically.  Probe 1247a sweeps all 21
indices at physical 0 and 0x100000 and prints the errno plus, on success, the first
32 bytes of the mapping.

### 5.1 The idx = -1 path is a kernel OOB write, not a probe

With arg2 = 0xffffffff the lookup is skipped, but the worker still computes
base + (-1)*0x138, i.e. 0x138 bytes **before** the container table, then:

    3CB5F9 mov rax,gs:[0] ; cmp rbx,rax ; je skip
    3CB607 mov [r14+0x50],rax          ; curthread stored at table-0xE8

and afterwards calls the splay-tree descriptor lookup 0x3C3FF0 with that
out-of-bounds "container" as the tree root holder.  Probe 1247a therefore does not
call idx = -1.  It is a fixed-address 8-byte kernel store of a thread pointer,
which is a write primitive at a fixed address, not a read; it is also the fastest
way known to panic the console, so it stays documented and unexecuted.

## 6. Descriptor lookup 0x3C3FF0

A splay-tree walk keyed on the physical address: cmp rdi,[rax+0x48] and
cmp rdi,[rax+0x50] decide left/right, and each hop rewrites the parent/child links
([rax+0x38], [rax+0x40]) - the standard splay.  [rax+0x48] and [rax+0x50] are the
descriptor's [lo, hi) range and byte [rax+0x69] its state.  Nothing in it takes a
user pointer; it is only interesting because the caller can be made to hand it a
bogus root via idx = -1.

## 7. What this changes

- 628 is not closed by privilege: the capability stage passes and the index check
  admits 0..0x14.  It is closed only if no container has a 0xfe descriptor at the
  physical addresses we want.  Probe 1247a answers that.
- The executable-page question is open again but with a different candidate: a
  file-backed MAP_PRIVATE mapping (probe 1248a).  PROT_EXEC being dropped for
  anonymous memory does not imply it is dropped for vnode objects, and a COW
  mapping of eboot.bin would be writable and, if X survives, executable.
- The Spectre route (docs/SPECULATION_READ_14_10.md) is gated on 1248a and must not
  be run before it: the probe's own step [4] calls into a page that 1245a showed is
  not executable, which kills the loader and wastes the relaunch.

## 8. Reproduce

    python .local/dis_628b.py     # 628 body and the worker
    python .local/dis_628c.py     # 3c33e0, ab8320, 3c3ff0
    python .local/dis_585.py      # 585 thunk -> body 0x8FC610
    python tools/send_probe.py probes/phase17_new_vectors/1247a_mmap_dmem_wildcard.lua --ip 192.168.1.121 --save
    python tools/send_probe.py probes/phase17_new_vectors/1248a_exec_page_hunt.lua --ip 192.168.1.121 --save
