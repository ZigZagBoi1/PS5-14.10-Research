# Sony Syscall Cluster — 14.10 Read-Surface Decode

Static source: `C:\PS5contrib\docs\dumps_13.60\kernel_text.bin` (13.60 .text, base `0xffffffff8a9c0000`, len `0xE6E5C0`, file offset == RVA).
RVA = VA − 0xffffffff8a9c0000. Every address below is an RVA unless prefixed `VA`.
Bodies were located through `docs/dumps_13.60/sysent_index.json` trampolines (`e9 rel32`; body = off+5+rel32). All 18 numbers present in that index matched the RVAs supplied; 733/734/727/728/705/721/717/724 are absent from the 13.60 index (it stops at 678) and were decoded at the given RVAs. **308's given RVA does not match the index**: index 308 → sy_call 0xffffffff8ac25760 (RVA 0x265760, narg 0) → body 0x5620e0; task supplies 0x552cb0. 0x552cb0 was decoded as instructed; it is a 20-instruction stub.

Verified helper semantics used throughout (disassembled, not assumed):
- `copyout` @0x2591d0(kaddr=rdi, uaddr=rsi, len=rdx); masks rsi with `0x7fffffffffff`; `rep movsq [rdi]<-[rsi]` ⇒ **source is arg1**.
- `copyin` @0x259280(uaddr=rdi, kaddr=rsi, len=rdx); onfault `gs:[0x20]+0x108`; masks src.
- `copyinstr` @0x259900; unguarded kernel copystr @0x2599f0.
- `suword32` @0x259790(uaddr=rdi, val=esi); `suword64` @0x259720.
- `uiomove` @0x782520(kbuf, len, struct uio*).
- Kernel malloc @0x8b4eac60(size, type), free @0x8b4e4250(ptr, size, type).
- 0xc1a3e0 = conditional debug logger (reads `[td+0x138]`/`[td+0xec]`, calls 0x8ac1d410); it appears before almost every copy site and moves no data.

---

## 1. Shape table

| # | body RVA | shape in one line | user copy | kernel-ptr in output? |
|---|---|---|---|---|
| 646 | 0xabe1c0 | cap-gated; copies a **bzero'd** 0x3f8 stack buffer to uap->arg0 | copyout 0x3f8 from stack (all zeros) | no |
| 647 | 0xabe7b0 | cap-gated; helper 0xabe260(td,arg0,4,&local) then stores local in td_retval[0] | none | no |
| 642 | 0xabdad0 | enumerate list into caller array; record = name string only | copyout 0x68 stack record → arg2+idx*0x68; copyout 4 (index) → arg3 | no |
| 618 | 0xabd0f0 | byte-indexed jump table on `[obj+0x9d]` (≤8), builds 0x128-stride record, writes index to user | suword64(arg?, idx*0x128+base) | no |
| 624 | 0xabd4f0 | no uap use; returns `[[curproc+0x200]+0x1c4]` VM counter | none | no |
| 733 | 0xabd000 | selector 0/0xa → 0xabccc0 stats, two 8-byte outputs | 2 × copyout 8 from stack | no (counts) |
| 734 | 0xfc890 | **int3 padding — not a function start** | — | — |
| 727 | 0x3b3090 | 5 scalar args + indexed walk of an array, writes into a kernel buffer | none | no |
| 728 | 0xabb660 | state/parameter mutation, no copies at all | none | no |
| 671 | 0xabe8b0 | budget query (sel/mode) → two 32-bit values | 2 × suword32 | no |
| 675 | 0x2d36f0 | 8 instructions: writes 3 globals, returns 0 | none | no |
| 705 | 0x2d3730 | capability gate 0x609940, 0x8ed710(obj) → 8-byte value, LSB tested | copyout 8 from stack | no |
| 721 | 0x6444d0 | cmd 1..5; requires arg2==8; copies **4 bytes of a static global** to an attacker-chosen user address | copyin 8 then copyout 4 | no (dst only) |
| 611 | 0xa36bc0 | cap-gated thread enumerator; uiomove of {pid,tid,qword,qword} records | uiomove → arg0, suword64(arg2,total) | **candidate** (+0x540/+0x538) |
| 612 | 0x34ce50 | copyin 8 (=0x10), 8 capability bits, 0x10-byte struct out | copyin 8, copyout 0x10 | no |
| 613 | 0xabca10 | cap-gated; sums page counts of a proc object | 2 × copyout 8 | no |
| 615 | 0xabcc00 | stats 0xabccc0(td,mode) then two 8-byte outputs | 2 × copyout 8 | no |
| 604 | 0x4f7370 | triple gate; find object by pid, then list node by key; copies node buffer [sub+0x88] | copyout len from [sub+0x88], copyout 4 | **yes — kernel object bytes** |
| 607 | 0xabc710 | namei(path) then **copyout 0x88 bytes of a VFS struct containing a static .data pointer** | copyinstr 0x400, copyout 0x88 | **YES** |
| 608 | 0x34bdc0 | id lookup; mallocs 0x1a8, fills from kernel object, copyout, frees | copyin 8 (==0x1a8), copyout 0x1a8 | **yes** |
| 641 | 0x4a2de0 | cap-gated; microsecond accounting loop | 2 × copyout 0x38 | no (scalars) |
| 667 | 0x4a31a0 | accounting sibling; scalar to user | suword32 | no |
| 717 | 0x4f7250 | gate triple; dispatches to 0x4f6b70 → **copyout 0xa58 of raw kernel object fields** | copyin 0x20, copyout 0xa58 | **YES** |
| 724 | 0x4f7940 | gate triple; dispatches to 0xb2c8e0 (cmd 1/2) | copyin 8, copyout 8 | no |
| 627 | 0x4a2850 | cap-gated accounting; scalar to user | 2 × suword32 | no |
| 308 | 0x552cb0 | 0xb07920(td) gate → tail jmp 0x27880, else ENOSYS 0x4e | none | no |

`uap` = rsi (second body argument). "cap-gated" = a call through the 0x608f90 / 0x608fb0 / 0x609080 / 0x6091d0 / 0x609620 / 0x609750 / 0x609270 / 0x608ff0 family.

---

## 2. Per-call detail

### 646 @0xabe1c0 — dead (zeroed buffer)
40 instructions, frame 0x408.
- Gate: `mov rdi,[rdi+0x140]` (0xabe1f7 region) → `call 0x8afc8f90` (cap helper); `test eax,eax; je` → `mov eax,1` (EPERM at 0xabe231).
- Args: only `mov rbx,rsi` then `mov rsi,rbx` at the copy ⇒ **one argument, the user destination pointer**, taken as uap+0.
- Data: `lea r14,[rbp-0x418]`; `mov esi,0x3f8; mov rdi,r14; call 0x8ac18ff0` (bzero). Nothing else ever writes r14 before `mov edx,0x3f8; mov rdi,r14; mov rsi,rbx; call 0x8ac191d0` (0xabe22a) ⇒ 0x3f8 **zeros** to user. Returns copyout's result.
- **The documented pointer-table lead is a misattribution.** `lea r12,[rip+0x3137f24] ; mov rdi,[r12+rdx*8] ; memcpy` lives at RVA 0xabef05 inside function 0xabee20, not in 646. It reached `results/kernel_handlers/asm/sys_646.asm` only because that file concatenates a 4096-byte window starting at trampoline page 0x265f40 with a "tail target 0xabe1c0" listing. Function 0xabee20(idx,buf,len) is called only from 0x3b733e (function 0x3b7200), with idx=loop counter 0..4 and buf=a freshly bzero'd kernel heap buffer; the table at 0x3BF6E30 is outside the dump. Killing instruction for the lead: `mov rdi,[r12+rdx*8] ; mov rsi,r15 ; mov rdx,r14 ; call 0x2590b0` at 0xabef05 — memcpy(table[idx], kernel_buf, len), a bounded kernel *write*, index and length kernel-derived, data not uap.

### 647 @0xabe7b0 — retval writer
36 instructions. Same cap gate as 646 (`mov rdi,[rdi+0x140] ; call 0x8afc8f90`).
- `mov dword [rbp-0x24],0`; `call 0xabe260(td, uap->arg0, 4, &[rbp-0x24])`; `movsxd rcx,[rbp-0x24] ; mov [rbx+0x408],rcx` → td_retval[0]. No copyout. Returns helper status.

### 642 @0xabdad0 — enumerator, name-only record (dead as a leak)
- Gate: `mov rdi,[rdi+0x140] ; call 0x8afc8f90` (0xabdafc) → `je` → 0x4e path; then `mov edi,[r14] ; call 0x8aefc170` (pid → proc); NULL → `mov eax,2` (ESRCH); `test eax,0x2000` at [proc+0xb0] → error; `inc dword [proc+0x358]`.
- Args: `r14 = rsi = uap`; `mov edi,dword [r14]` = uap+0 (pid, dword); uap+8 = count (used at `cmp r14d,[rax+8]`); uap+0x10 = user array base (`mov rbx,[rax+0x10]`); uap+0x18 = 4-byte out pointer.
- Loop: walks the list at `[proc+0x200]` (`mov r15,[r13+8]`; `cmp r15,r13`), skips `word [r15+0x66]==0` and `byte [r15+0x60]&2`, then per record: `mov esi,0x68 ; lea rdi,[rbp-0x98] ; call 0x8ac18ff0` (bzero) and `lea rsi,[r15+0x150] ; mov edx,0x20 ; lea rdi,[rbp-0x98] ; call 0x8b317b70` (strlcpy of a 0x20 name).
- Copy: `mov edx,0x68 ; lea rdi,[rbp-0x98] ; mov rsi,rbx ; call 0x8ac191d0` (0xabe0b3) → dst = uap->arg2 + idx*0x68 (`imul rax,r14,0x68 ; add rbx,rax`), src = the stack record. Index is the **internal counter** `[rbp-0x9c]`, bounded by uap->arg1 (`cmp r14d,[rax+8] ; jge <exit>`), so no attacker index and no OOB. Second copy at 0xabe155 moves the 4-byte index to `[r14+0x18]`.
- **Killing fact for the leak hypothesis: the record is bzero'd immediately before the strlcpy, and nothing else writes it.** Output = a 0x20-byte kernel name string plus zeros.

### 618 @0xabd0f0 — byte-indexed jump table, bounded
- `movzx ecx,byte [r12+0x9d] ; cmp rcx,8 ; ja` (0xabd2b2–0xabd2b6) then `lea rsi,[rip+0xe1eca5] ; movsxd rcx,dword [rsi+rcx*4] ; add rcx,rsi ; jmp rcx` — a 9-entry relative table at 0x19BBF68 (outside the dump). Index comes from a kernel object byte and is range-checked; not attacker-controlled.
- Body writes a 0x128-stride record (`imul r14,rdx,0x128 ; add r14,[rbp-0x80]`) with `byte [r14+0x24]` state and a `strlcpy` of `[r12+0x160]` / `0x8aff22c0(r12)` — name text.
- Copy: `mov rdi,[rax+0x10] ; mov rsi,r14 ; call 0x259720` (suword64, 0xabd3e6) — a scalar index to a user pointer. Return 0 / 0xe.

### 624 @0xabd4f0 — VM operation counter (no uap)
`mov rax,[rdi+8] ; mov r14,[rax+0x200]`; lock 0x2c6820; `mov eax,[r14+0x1c4] ; mov [rbx+0x408],rax`; unlock; `xor eax,eax`. No copyout; value is a counter.

### 733 @0xabd000 — stats by selector
Args: `dword [rsi]` = selector, `dword [rsi+8]` = mode (must be 0 or 0xa, else 0x16), `qword [rsi+0x10]`, `qword [rsi+0x18]` = two out pointers.
`call 0xabccc0(td,mode)` fills a 0xb0 stack struct; then `mov edx,8 ; mov rdi,r14 ; mov rsi,r15 ; call 0x2591d0` twice (0xabd081, 0xabd0c0). Struct builder 0xabccc0 is `bzero(out,0xb0)` plus a vm_map walk: `movsx r14,byte [rax+0x14c] ; shl r14,4 ; add [rdx+r14+8],rcx` and `inc qword [r14]` ⇒ page/object counts indexed by a kernel field. Returns copyout status.

### 734 @0xfc890 — not a function
Byte at 0xfc890 is `0xCC` (int3). Linear and recursive sweeps agree: entry is padding. The 734 body is elsewhere (the 13.60 index has no 734). **Unresolved — see §5.**

### 727 @0x3b3090 — array walker, no user copy
Args: `dword [rsi]` (r15d), `dword [rsi+8]` (edi), `qword [rsi+0x10]` (r14), `dword [rsi+0x18]` (edx), `qword [rsi+0x20]` (r12).
Indexed reads: `mov r8d,dword [rsi+rdi*8+0x20]` (0x3b333a), `mov r8,qword [rsi+rdi*8+8]` (0x3b3343), `mov rsi,qword [rsi+rdi*8]` (0x3b334d) with `cmp edx,r10d ; jge` bounding the walk (`inc edx` at 0x3b3317). The loaded triples are stored into a kernel buffer at `[r11+r9*8]`. **No copyin/copyout anywhere in 231 instructions** ⇒ nothing reaches userland; the indexed uap reads stay inside the kernel-side copy of uap (they are still a kernel-stack OOB read *if* r10d can exceed uap's real size — untested, and the values die in kernel memory).

### 728 @0xabb660 — mutation, no copies
217 instructions, zero calls to any copy helper. Reads `r13=rsi` and mutates global/object state. Shape only; semantics undecoded (§5).

### 671 @0xabe8b0 — budget query
Args: `dword [rsi]` sel, `dword [rsi+8]` mode, `qword [rsi+0x10]` out1, `qword [rsi+0x18]` out2.
Gate: `call 0xacce9a0(0)` + `cmp dword [proc+0x5d4],0x5000000`; `sel==-1` → inherit `[proc+0x5c0]`, else cap helper 0x608f90 → EPERM 1; bound `cmp r12d,0xa ; ja` → 0x16. Mode 1 → 0x8ed4e0, mode 2 → 0x9e3650. Copies: `andn esi,ecx,eax ; call 0x259790` twice (suword32, 0xabe9c4 and 0xabe9df). Returns 0 or 0xe.

### 675 @0x2d36f0 — global reset
`mov dword [rip+0x17c2be2],1` / `mov qword [rip+0x2a8dfbf],-1` / `mov qword [rip+0x2a8c8f4],0` / `xor eax,eax ; ret`. No args read.

### 705 @0x2d3730 — capability check + 8-byte value
Args: `[rsi]` arg0 (must be non-zero), `[rsi+8]` arg1 = out pointer. Gate `call 0x609940(td)`; `je` → 1. `rdi=[r14+8] → [+0x200] → [+0x1d8]`; lock 0x4c6a00 / unlock 0x4c6fa0; `call 0x8ed710(obj,arg0,&[rbp-0x38])`; `test r14b,1` (LSB of result) zero → 0x16. Copy: `lea rdi,[rbp-0x38] ; mov edx,8 ; mov rsi,rbx ; call 0x2591d0`. Value is a scalar/enum.

### 721 @0x6444d0 — writes a static global to a user address
`mov eax,[rsi] ; dec eax ; cmp eax,4 ; ja <0x16>` then `lea rcx,[rip+0x10e033e] ; movsxd rax,dword [rcx+rax*4] ; add rax,rcx ; jmp rax` — 5-entry table at 0x1725844, outside the dump.
`mov r14,[rsi+8]` arg1, `mov r12,[rsi+0x10]` arg2. `cmp r12,8 ; jne <0x16>` (arg2 must be 8; else panic path 0x25d410 line 0x79f). `copyin(rdi=r14, rsi=&[rbp-0x48], 8)` reads a *destination address* from the user; then `lea rdi,[rip+0x31a170f]` (0x644582 → VA 0xffffffff8e1a5c98, a static global) `; mov edx,4 ; mov rsi,rbx ; call 0x2591d0` writes 4 bytes of that global to it.
Direction check: copyout's source is rdi = the global, destination rsi = the user value, which copyout masks to user space. So this is *not* an arbitrary kernel read; it is an attacker-addressed 4-byte user write of a static value, and the destination cannot leave user space.

### 611 @0xa36bc0 — thread enumerator (candidate leak)
Gate: `mov rdi,[td+0x140] ; call 0x8afc8f90` → zero ⇒ `mov ebx,1` (EPERM).
Args: `qword [r12]` = arg0 (out buffer), `dword [r12+8]` = arg1 (length), `qword [r12+0x10]` = arg2 (bytes-written out).
Builds `struct uio` at rbp-0x60: `[rbp-0x70]=arg0` (iov_base), `[rbp-0x68]=arg1` (iov_len), `[rbp-0x60]=&iov`, `[rbp-0x58]=1`, `[rbp-0x48]=arg1` (resid), `[rbp-0x38]=td`.
Walks the global proc list under lock 0xc4b350; per proc: `cmp dword [r14+0xb8],1` (PRS_NORMAL), `movsxd rbx,dword [r14+0xb48]` then `0x8b5c8b50(count*24,0x102)` (malloc). Per thread (`r15=[r14+0x10]`, `[r15+0x10]` chain), skipping `[r15+0x400]==0`:
`mov [rbx],dword [r14+0xbc]` (pid) · `mov [rbx+4],dword [r15+0x9c]` (tid) · `mov rax,[r15+0x540] ; mov [rbx+8],rax` · `mov rax,[r15+0x538] ; mov [rbx+0x10],rax`.
Then `cmovb rbx,rax` clamps to arg1, `mov rdi,r13 ; mov esi,ebx ; lea rdx,[rbp-0x60] ; call 0x782520` (uiomove ⇒ copyout to arg0), and `mov rdi,[r12+0x10] ; mov rsi,rbx ; call 0x259720` (suword64 of the total). Return 0 / 0xe.
**Why it is a candidate:** the two qwords at td+0x540 and td+0x538 are undiscovered fields. td_tid at +0x9c matches FreeBSD `struct thread`; +0x538/+0x540 are far past the fields this corpus has mapped and are plausibly pointer- or time-valued. Not proven — needs an offset map.

### 612 @0x34ce50 — capability bitmap (no pointers)
`copyin(rdi=arg0, rsi=&[rbp-0x38], 8)`; `cmp qword [rbp-0x38],0x10 ; jne <0x16>`; bzero 0x10 at [rbp-0x30]; `[rbp-0x30]=0x10`; `call 0x5a6c70` → dword at [rbp-0x28]; eight tests 0x6095c0/0x609620/0x6091f0/0x609230/0x609750/0x609270/0x6096b0/0x609890([proc+0x40]) each `or byte [rbp-0x24],1|2|4|8|0x10|0x20|0x40|0x80`; `copyout(&[rbp-0x30],arg0,0x10)`. Bits only.

### 613 @0xabca10 — page accounting
Args `dword [rsi]` pid, `[rsi+8]` out1, `[rsi+0x10]` out2. Gate 0x608f90 → EPERM 1; `0x53c170(pid)` → NULL ⇒ 3 (ESRCH); `[proc+0xb0]&0x2000` ⇒ 3; `inc [proc+0x358]`; lock `[proc+0x148]`; `[rbp-0x40]=0x2c6e90([proc+0x200])`; walk with `mov rdx,[rax+0x28] ; sub rdx,[rax+0x20] ; shr rdx,0xe ; add rcx,rdx` ⇒ page-count sum in [rbp-0x38]; `copyout(&[rbp-0x40],arg1,8)`, `copyout(&[rbp-0x38],arg2,8)`. Counts only.

### 615 @0xabcc00 — stats, index 0
`mov esi,dword [rsi]` → `call 0xabccc0(td,mode)`; `copyout(&[rbp-0xd0],arg1,8)`, `copyout(&[rbp-0xc8],arg2,8)`. Same builder as 733 ⇒ counts.

### 604 @0x4f7370 — kernel-object buffer by (id, key) (leak)
Args: `dword [rsi]` arg0, `qword [rsi+8]` arg1, `qword [rsi+0x10]` arg2, `dword [rsi+0x18]` arg3, `qword [rsi+0x20]` arg4.
Gate: `call 0x26d0a8(proc)` **or** `0x609040(proc)` **or** `0x609110(proc)`; all zero ⇒ `mov r12d,1` (EPERM).
`call 0x4f6700(td,arg0,&[rbp-0x38])` → object (pid lookup + 0x609890([proc+0x40])). `rdi=[obj+0x3e8]`; 0 ⇒ 0x2d. `add rdi,0x70 ; call 0xc4bb20` (lock). Walk `mov r12,[r12]` matching `cmp qword [r12+0x28],r13` (key = arg1); node+0x148 = sub. `mov r12,[rax+0x88]` (data), `mov rax,[rax+0x90]` (len); `mov r13d,0xffffffff ; cmp rax,r13 ; cmovb r13,rax`.
If `arg3 < len`: `copyout(&[rbp-0x34],arg4,4)` (returns the required length), status 0xc.
Else: `mov rdi,r12 ; mov rsi,r15 ; mov rdx,r13 ; call 0x2591d0` (0x4f757f) — **copyout of len bytes from a kernel-object buffer to attacker arg2**, then `copyout(&[rbp-0x34],arg4,4)`.
Source provenance: kernel object reached by (pid, key) — not an attacker address. Bounded at 0xffffffff bytes but practically [sub+0x90].

### 607 @0xabc710 — **static .data pointer + kernel heap pointer to user** (top leak)
Args: `mov r12,qword [rsi]` = arg0 (path string pointer); arg1 = `[uap+8]` recovered at 0xabc9c0 (`mov rax,[rbp-0x1d8] ; mov rbx,[rax+8]`).
Path: `mov edx,0x400 ; mov rdi,r12 ; mov rsi,r14 ; xor ecx,ecx ; call 0xac19900` (copyinstr arg0 → 0x400 kernel buffer r14). Then a 7-argument VFS lookup `call 0xafba6e0` with `r8=r14`, `r9d=0xffffff9c` (AT_FDCWD) and three stack args, followed by 0xafb8c20 / 0xafba780(…,0xc). Failure paths return 0xc or 8.
State gate: `cmp dword [r12+0x1d4],1 ; mov r13d,0x16 ; jne` (0xabc7e5) — EINVAL unless the resolved object carries 1 at +0x1d4. **There is no priv_check and no capability-helper call in this body.**
Struct build (0xabc7f6):
```
mov  rax,[rbx+0x140]              ; td_proc
mov  qword [rbp-0x1a0],rcx        ; rcx = lea rcx,[rip+0x101dff4]  -> VA 0xffffffff8c4da7f8 (kernel .data)
mov  qword [rbp-0x198],r12        ; kernel object pointer from the lookup
mov  dword [rbp-0x190],1
mov  qword [rbp-0x188],rax        ; proc pointer
mov  qword [rbp-0x180],rbx        ; td pointer
mov  qword [rbp-0x178],0
```
second variant at 0xabc923 rebuilds the same 0x88 block with `lea rcx,[rip+0x101dfc7]` → VA 0xffffffff8c4da8f8 and `[rbp-0x198]=r12`, `[rbp-0x1a8]=r15`.
Copy: `lea rdi,[rbp-0x1a0] ; mov edx,0x88 ; mov rsi,rbx ; call 0x2591d0` (0xabc9f1) with rbx = uap->arg1.
**This hands userland (1) a fixed pointer into the kernel's static data — an immediate KASLR-defeating anchor — and (2) a live kernel heap object pointer, in one 0x88-byte copy, with no privilege check.** Return 0 / r13d (1, 0xc, 8).

### 608 @0x34bdc0 — id lookup, 0x1a8-byte object dump (leak)
Args: `dword [rsi]` r12d (id), `dword [rsi+8]` → [rbp-0x3c] (flags word), `qword [rsi+0x10]` r14 (out pointer).
`copyin(rdi=r14, rsi=&[rbp-0x38], 8)`; `cmp qword [rbp-0x38],0x1a8 ; jne <0x16>` — the caller must pass 0x1a8 as the size word.
`mov edi,0x1a8 ; mov esi,0xa ; call 0x8b4eac60` (malloc) → r14 = kernel buffer; `[rbp-0x50]=r14(user out ptr)` saved first at 0x34be67. Walk global list (`mov r15,[r15]`, `cmp r12d,[r15+0x28]`), bzero the buffer, then fill from the matched object r15:
```
[r14+8]      strlcpy([r15+8] or 0x8ac32200([r15+8])+1, 0x100)      ; name, '/' or '\\' separator chosen by byte compare 0x2f 0x68 0x6f 0x73 0x74 0x2f
[r14+0x108]  dword [r15+0x28]
[r14+0x10c]  word  [r15+0x70]  | bits from [r15+0x11c]
[r14+0x110]  qword [r15+0x78]            <- raw qword
[r14+0x118..0x124] dwords [r15+0x80..0x98]
[r14+0x128]  qword [r15+0xe8]            <- raw qword
[r14+0x130]  qword [r15+0xf0]            <- raw qword
[r14+0x148]  qword [r15+0xf8]            <- raw qword
[r14+0x150]  qword [r15+0x108]           <- raw qword
[r14+0x160]  qword [[r15+0x50]+8]        <- dereference
[r14+0x170]  qword [[r15+0x60]+8]        <- dereference
[r14+0x16c..] 0x18-stride array from [r15+0x40]: qword [entry+8], dword [entry+0x10], flags from dword [[entry]+0xc]&7
[r14+0x1a0]  count (min(dword [r15+0x48],4))
```
Copy: `mov rsi,[rbp-0x50] ; mov edx,0x1a8 ; mov rdi,r14 ; call 0x2591d0` (0x34c25d), then `0x8b4e4250(r14,0x1a8,0xa)` (free) and return the copyout status (0 / 0xe). Not-found path returns 3.
Raw qwords at +0x78/+0xe8/+0xf0/+0xf8/+0x108 and the two dereferences are plausible pointers; this is the second-strongest leak candidate.

### 641 @0x4a2de0 — accounting record (scalars)
Gate `mov rdi,[rdi+0x140] ; call 0xafc8f90` → `mov eax,0x4e` (ENOSYS) when zero. Args `dword [r13]` (pid at uap+0) and `[r13+8]` (uap+8, out pointer).
Walks `[r14+0x10]` chains with a `mulx rax,rax,0x431bde82d7b634db ; shr rax,0x12 ; imul rax,rax,0xf4240` seconds/microseconds reduction.
Record at [rbp-0x68] (bzero'd 0x38 at entry): `mov eax,[rbx+0xbc] ; mov [rbp-0x68],eax` (pid), `mov eax,[r13] ; mov [rbp-0x64],eax`, plus `[rbp-0x40]`/`[rbp-0x38]` microsecond quotients. Copy: `lea rdi,[rbp-0x68] ; mov edx,0x38 ; mov rsi,rbx ; call 0x2591d0` at 0x4a30ba and 0x4a316a. Scalars only.

### 667 @0x4a31a0 — accounting sibling
Same gate/paths as 641. Copy: `mov rax,[rbp-0x88] ; mov rsi,[rbp-0x80] ; mov rdi,[rax+8] ; call 0x259790` (suword32 of a computed dword). No kernel source beyond scalars.

### 717 @0x4f7250 → 0x4f6b70 — 0xa58-byte object dump (leak)
Entry args: `dword [rsi]` pid, `dword [rsi+8]`, `qword [rsi+0x10]` key, `qword [rsi+0x18]` out buffer.
Gate: (0x26d0a8 || 0x609040 || 0x609110)(proc) **or** (`0xb07920(td)!=0` and curproc pid == arg0, else 0x16; if 0xb07920==0 → 1). Then `0x4f6700` object; `0x9fcf00(obj,&d)`; unless (eax==2 or (d&~1)==2) release and return 0x23. Then `mov edx,[r14+8] ; mov rcx,[r14+0x10] ; mov r8,[r14+0x18] ; call 0x4f6b70(td,obj,edx,rcx,r8)`.
Worker 0x4f6b70 (frame 0xae8): list walk `cmp qword [r12+0x28],rbx` keyed by arg2; `copyin(rdi=rbx(user), rsi=&[rbp-0xaa8], 0x20)`; `cmp dword [rbp-0xaa0],0x3c13f4bf ; jne` (magic at user+8); `mov eax,[rbp-0xa9c] ; cmp eax,2 ; jb` (version at user+0xc).
Record at rbp-0xa88 (0xa58 bytes): qwords `[r12+0x20]`, `[r12+0x118]`, `[r12+0xe8]`, `[r12+0xf0]`, `[r12+0xf8]`, `[r12+0x100]`, `[r12+0x108]`, `[r12+0x110]`; a 0x18-stride array from `[r12+0x40]` (two qwords + flags `[ptr+0xc]&1|2|4`); up to 0x80 qwords from the `[r12+0xd0]` list via `0x8b4eb340` lookups (`-1` when absent); name strings via `0x8b344440(…,0x80/0x400)` and `0x8b317b70`.
Copy: `lea rdi,[rbp-0xa88] ; mov rsi,[rbp-0xb08] ; mov edx,0xa58 ; call 0x2591d0` (0x4f71e0). Return 0 / 0xe. This is the largest raw kernel-object field dump in the cluster.

### 724 @0x4f7940 → 0xb2c8e0 — cmd 1/2 dispatcher
Args: `dword [rsi]` pid, `dword [rsi+8]`, `word [rsi+0x10]`, `qword [rsi+0x18]`, `[rsi+0x20]`, `[rsi+0x28]`, `dword [rsi+0x30]` = cmd.
Gate triple then `0x609890([proc+0x40])` else 3 (ESRCH); `inc [proc+0x358]`; lock `[proc+0x148]`; `call 0xb2c8e0([proc+0x3e8], arg1, arg2w, arg3, arg4, arg5, cmd_on_stack)`.
Worker: `lea r10d,[rbx-3] ; cmp r10d,-2 ; jb error` ⇒ cmd ∈ {1,2}. cmd==2: `copyin(rdi=r14=arg4, rsi=&[rbp-0x48], 8)`, then `copyout(rdi=&[rbp-0x38], rsi=r14, 8)` writing `0x8b1f27a0()+1` back to the same pointer, then `cmp rdx,[rbp-0x48] ; ja error`; the follow-up `call 0x4ecb50(r15,[rbp-0x60])` / `0x4ecb50(&[rbp-0x40],[rbp-0x58],8)` moves a qword built as `dword [rbx+0xc]<<16 | word [rbx+0x10]`. Scalars only.

### 627 @0x4a2850 — accounting triple (scalars)
Gate `0xafc8f90`, then `0xaefc170` pid lookup, `0xb142a40`, allocations 0x8b5c8b50/0x8b5c8df0. Copies: `mov rdi,[r13+8] ; mov esi,ebx ; call 0x259790` (0x4a2c58) and `mov rax,[rbp-0x120] ; mov rsi,[rbp-0x108] ; mov rdi,[rax+8] ; call 0x259790` (0x4a2c94). Dwords only.

### 308 @0x552cb0 — stub
`call 0xb07920(td) ; test eax,eax ; je <ENOSYS>` then `mov rdi,r14 ; jmp 0x27880` (tail call inside .text); ENOSYS path returns 0x4e. No uap read, no copy.

---

## 3. Ranking — probability of returning kernel memory content to userland

1. **607 @0xabc710 — very high.** It copies a 0x88-byte structure that *starts with a kernel static .data address* (`lea rcx,[rip+0x101dff4]` → VA 0xffffffff8c4da7f8) and stores a live kernel object pointer at +8. No privilege check: the only gate is `cmp dword [r12+0x1d4],1`. Output goes to uap->arg1. Even if the VFS calls overwrite the block, the two pointer slots are written at 0xabc804/0xabc815 immediately before the VFS use and re-established at 0xabc938/0xabc93f for the second variant.
2. **717 @0x4f7250 — high, needs one user-supplied magic.** 0xa58 bytes of raw kernel-object fields (eight qwords from the node, a 0x18-stride array, up to 0x80 list entries). Gate needs a matching key, `0x3c13f4bf` at user+8, and version ≥ 2 — all attacker-supplied.
3. **608 @0x34bdc0 — high.** 0x1a8 bytes of a matched kernel object, including five raw qwords and two dereferences of `[obj+0x50]/[obj+0x60]`; requires knowing the id and passing a size word of 0x1a8.
4. **604 @0x4f7370 — moderate.** Copies [node+0x88] for min(len,0xffffffff) bytes; content is kernel-object data whose type is decided by the pid/key pair (0x4f6700), so the leak is real but the object is chosen by the kernel, not by the caller.
5. **611 @0xa36bc0 — moderate/low.** Thread records expose two unmapped td fields (+0x538/+0x540); if either is a pointer this is a per-thread pointer leak, otherwise it is boilerplate.
6. 642/641/667/627/613/615/733/671/705/721/612/646 — low. 642's record is bzero'd then strlcpy'd (name only); 641/667/627 are microsecond scalars; 613/615/733/671 copy counts; 705 copies one enum; 721 writes a static 4-byte value *to* a user address; 612 returns a capability bitmap; 646 returns 0x3f8 zeros.
7. 647/624/675/727/728/308 — none. No user copy at all (727/728 have zero copy helpers in 231/217 instructions).

---

## 4. Top three next steps

1. **607 first — it is a KASLR oracle that needs no privilege.**
   Probe shape: `sc607("/app0/eboot.bin", outbuf, 0x88)` (arg0 path pointer, arg1 out pointer). Dump the 0x88 bytes and test every qword against the kernel VA range. Expected: qword0 constant across boots modulo slide, qword1 changing per boot. If qword0 varies only with the slide, compute `slide = qword0 - 0xffffffff8c4da7f8` and that alone defeats KASLR for 14.10. Then vary the path (a directory, a non-existent path, `/dev/`-style nodes) to see which branch (0xabc804 vs 0xabc938) fires and whether the +0x1d4 gate is per-object. Nothing here touches the console yet — this is a decode followed by one probe.
2. **717 second — 0xa58 bytes is the widest window, but it needs a valid (pid, key) and a 0x20-byte user struct with magic 0x3c13f4bf, version ≥ 2.** Enumerate candidate keys by passing key=0 and reading the returned error (0xc vs 0x23 vs status) to distinguish "no node" from "gate rejected". Once a record comes back, scan all 0xa58 bytes for values ≥ 0xffff800000000000 and classify by stability across two boots.
3. **608 third — the cheapest struct to reach.** The size word must be exactly 0x1a8 (`cmp qword [rbp-0x38],0x1a8`), so the call is `*(u64*)user = 0x1a8; sc608(id, flags, outptr)`. Sweep id over the plausible small range and watch for return 0 (found) vs 3 (not found); on success classify the qwords at +0x110/+0x128/+0x130/+0x148/+0x150 and the two dereferenced entries at +0x160/+0x170.

For all three, the decisive question is the same: whether the qword is inside the dumped .text/data range (a fixed offset → slide once, use forever) or a heap address (changing per boot, useful only as a heap pointer).

---

## 5. What remains undecoded

- **734 @0xfc890**: the byte at this RVA is `0xCC` (int3). Both a linear sweep and a recursive-descent walk from the given entry decode it as padding, and the surrounding region is not a function prologue. The 13.60 sysent index has no entry 734, so no trampoline exists in this corpus to relocate it. A real body would have to come from a 14.10 image or from the loader's dispatch table.
- **727 @0x3b3090** and **728 @0xabb660**: argument reads and the absence of any user copy are established; the semantics (what object each mutates, what 0x3b3090's indexed triples mean) are not. Neither can leak by construction, so they were not pursued further.
- **618**: the 9-entry relative table at 0x19BBF68 and the exact meaning of each `byte [r14+0x24]` state (0, 1, 3, 4 observed) are outside the dump.
- **721**: the 5-entry table at 0x1725844 is outside the dump; only the cmd==1 case (the copyin/copyout pair at 0x64455a/0x644591) is decoded. The panic path 0x25d410 (line 0x79f) and the other four cases are unread.
- **604**: the object type returned by 0x4f6700 and the meaning of node+0x88/+0x90 are not established; the copy itself is.
- **607**: the callee 0xafba6e0 (7-argument VFS lookup) and 0xafc9c00 (operating on `[td+0x140]+0x58`) are not decoded; whether they rewrite the 0x88 block or leave the pointer slots intact is the one open question that affects whether the leak is exact or merely probable.
- **608**: the two preambles (0x34bdee/0x34be00) that decide which list is searched are read but the helper 0x8afc8f90's capability bit is unmapped; the identity of the id space (arg0) is unknown.
- **717**: 0x4eb340 (lookup), 0x4eba90, 0x8ad0c290/0x8ad0c2f0/0x8ad0c320 (name formatting) are not decoded; the record layout is.
- **308**: the given RVA disagrees with the 13.60 index (0x5620e0 there). Both were checked; 0x552cb0 is a 20-instruction stub whose tail jumps to 0x27880, and 0x5620e0 was not decoded in this pass.
