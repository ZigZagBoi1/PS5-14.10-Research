# Kernel indexed-store census — 13.60 sysent table (read as a 14.10 research asset)

Scope: static analysis of the 301 distinct syscall handler bodies reachable from the 679-entry
13.60 sysent capture. Question: **is there any array store whose index or base is tainted by
caller-supplied data and whose bound check does not cover it** — a kernel write that can be
steered out of bounds? This is the write-side twin of KERNEL_READ_SEARCH_14_10.md.

Inputs (unchanged):

- `docs/dumps_13.60/kernel_text.bin`, 0xE6E5C0 bytes, image base 0xffffffff8a9c0000, file offset == RVA, so VA = base + RVA.
- `docs/dumps_13.60/sysent_index.json`, key `entries`, 679 records of {num, narg, sy_call, sy_call_off}.
- Helper RVAs treated as opaque: copyin 0x259280 (rdi=user_src, rsi=kdst, rdx=len), copyout 0x2591d0,
  bzero 0x258ff0, memcpy 0x2590b0.

Reproduce script: `.local/ixstore_census.py`. Machine output of the run quoted here: `.local/ix_run.txt`
(JSON: bodies, scanned, candidates).

---

## 1. Verdict

**No.** Across the 301 handler bodies (39346 instructions, 157909 bytes of text) there are 2691
memory-destination stores. Exactly 30 of them have a base or an index that is tainted by caller
data; 28 classify **C** (a constant compare that matches the array's real capacity dominates the
store), 2 classify **W** (the bound is the fd table's runtime high-water mark, which is the array's
own capacity, and both stores write kernel-computed values), and **0 classify U** — not one store
in the corpus reaches memory with a caller-derived index that no check covers. No store writes
through a raw caller pointer either: a separate linear pass that treats `[rsi+N]` (N <= 0x28) as a
uap slot and follows the destination register finds 0 of 2691 stores whose base still holds one,
once the pass also drops `rsi` itself when the body reassigns it;
its only hit before that correction, 0x91c849 in sys 629, reads `[rsi+0x10]` at 0x91c82f where
`rsi` had been reset to a list element at 0x91c820 (false-positive class 10).

The four handlers that do write caller-controlled *values* into kernel arrays — sigaction (416),
565, 566 and the setgroups-shaped 83 — clamp the *index* with an explicit compare against the
array width (`cmp r9d,0x7f`, `cmp r12,6`, `lea eax,[r13-6]; cmp eax,-7`, `cmp r12,2`) and every
cited compare dominates every store it is paired with below. The write side of this syscall table
is closed on the same evidence standard as the read side: there is no survivor to promote into a
probe.

What would overturn this: a store whose index register is not a copy of a value the script
modelled, or a handler whose real bound lives in a callee. Both gaps are bounded in section 6 and
neither is reachable from the 30 rows in this document.

---

## 2. Method

### 2.1 The entry ABI in the task brief is wrong, and following it manufactures rows

The brief states that at body entry `rdi` is `struct syscall_args *`. The disassembly says
otherwise: `rdi` is `struct thread *td` and `rsi` is `struct syscall_args *uap`. sys 20 (getpid),
body 0x2a8ae0, is short enough to read whole:

     002a8ae0  push rbp
     002a8ae1  mov rbp, rsp
     002a8ae4  mov rax, qword ptr [rdi + 8]         ; td->td_proc
     002a8ae8  movsxd rax, dword ptr [rax + 0xbc]   ; p_pid
     002a8aef  mov qword ptr [rdi + 0x408], rax    ; td_retval[0]
     002a8af6  xor eax, eax
     002a8af8  pop rbp
     002a8af9  ret

`[rdi+0x408]` is `td_retval[0]`; a uap has six slots at +0x00..+0x28 and nothing at +0x408.
Independent confirmation from the other side: sys 4 (write), body 0x4ec560, loads its third
argument with `mov rcx, qword ptr [rsi + 0x10]` — uap slot 2. Taint therefore starts at `rsi`.
Starting at `rdi` taints every `td` field load and turns the ordinary
`mov qword ptr [rdi+0x408],rax` return-value store in dozens of handlers into a fabricated
"caller-tainted write".

### 2.2 Function extents

A body is decoded from its thunk-resolved start (body = thunk_rva + 5 + rel32) and stopped by the
first of: ret/retf/ud2/int3/hlt followed by nop/int3 padding and then an endbr64 or a new prologue
(113 bodies); ret followed by padding (151); an 8-byte padding run (19); a tail jmp that leaves the
extent (18). The 13.60 image packs whole functions back-to-back and often separates them with
**two** nop bytes, so a fixed 0x400/0x1000/0x1200 window — what the three older scripts in
`.local` do — walks into the next function. Extent-correct decoding cut the analysed text from
228432 to 157909 bytes and deleted the 475/476 rows outright (6.3).

### 2.3 Taint

Lattice per register and per stack slot: 0 clean; 1 the uap pointer itself (with the byte offset
it points at, so `mov rbx,rsi` then `[rbx+8]` is still uap slot 1); 2 the value of a uap slot
(caller scalar or pointer); 3 tainted by arithmetic/shift/lea/phi on a level-2 or level-3 value, by
a load through a tainted index, or by a reload from a stack region that copyin filled. Stack slots
are tracked by canonical rbp-relative displacement and by width: `mov dword ptr [rbp-0x44],r9d`
writes a 4-byte slot and does not taint the neighbouring qword. copyin(rdi=user, rsi=kdst, rdx=len)
marks [kdst, kdst+len) level 3; bzero clears it; memcpy propagates it. Values returned by calls are
opaque (ret@RVA) and never tainted.

### 2.4 Control flow

Each extent is split into basic blocks at branch targets, after conditional branches, after calls
and at the extent end; a worklist fixpoint executes each block from the merged in-state (per-register
join keeping the highest level) until no state changes, and a second pass re-executes every block
recording the state at each instruction — the store rows are read from that pass. Store forms
collected: mov, RMW atomics (lock xadd, lock cmpxchg, lock add/sub/and/or, inc, dec, imul, shl,
setne) and string stores (rep movs). Mnemonics are matched after stripping lock/rep prefixes:
capstone keeps the prefix inside insn.mnemonic, and matching the raw mnemonic silently loses 181
atomic stores.

### 2.5 Guard location and dominance

For every tainted store the script reports up to three candidate checks within 80 instructions
behind it, tracking which registers carry a copy of the index or base through mov/movzx/lea/add/sub,
with the conditional branch that consumes the flags and a `dominates` flag from the block dominator
tree. The locator is a pointer, not an oracle: it does not follow the index through a third
register and it does not know which compare is semantically the bound. Every row below was read by
hand and cites the exact compare text.

### 2.6 Classification

- **C** — a compare against a constant equal to the array's real capacity dominates the store.
- **W** — the covering compare is against a variable, and that variable is the array's own capacity.
- **U** — no check found over the tainted index or base.
- **N** — the index/base is not actually caller-tainted on that path (false positive).

---

## 3. Results

     679 sysent entries -> 301 distinct bodies
     301 bodies, 39346 instructions, 157909 bytes, 2691 memory-destination stores
     45 bodies contain no store at all; largest body 10011 bytes (0x6e2c40, 220 stores)
     store mnemonics: mov 2367, lock* 148, or 87, and 40, inc 28, dec 10, add 4,
                      setne 2, sub 2, imul 1, rep* 1, shl 1
     tainted-base-or-index rows: 30 in 5 bodies -> C 28, W 2, U 0

### 3.1 U and W rows (the rows the question is about)

| RVA | body | syscall | store instruction | bound-check instruction text | stored value | class |
|---|---|---|---|---|---|---|
| 0x72c03b | 0x72bf00 | 6 | mov qword ptr [r12], 0 | 0x72bfb2 test r14d,r14d ; 0x72bfb5 js 0x8b0ec0ad ; 0x72bfbb cmp r14d,dword ptr [r15+0x28] ; 0x72bfbf jg 0x8b0ec0ad ; 0x72bfcb lea r13,[rcx+rcx*2] ; 0x72bfcf shl r13,4 | constant 0 | W |
| 0x72c058 | 0x72bf00 | 6 | and qword ptr [rdx + rcx*8], rax | same two fd checks ; 0x72c055 shr ecx,6 ; no compare on rcx itself | rax = rol(0xfffffffffffffffe, fd&63), kernel-computed mask | W |

Both W rows, in full:

     0072bfb2  test r14d, r14d
     0072bfb5  js 0xffffffff8b0ec0ad             ; negative fd -> EBADF
     0072bfbb  cmp r14d, dword ptr [r15 + 0x28] ; fd_lastfile
     0072bfbf  jg 0xffffffff8b0ec0ad             ; fd > high-water mark -> EBADF
     0072bfc5  mov ecx, r14d
     0072bfc8  mov rax, qword ptr [r15]          ; fd_ofiles
     0072bfcb  lea r13, [rcx + rcx*2]
     0072bfcf  shl r13, 4                        ; 24-byte fd entry stride
     0072bfd3  mov rax, qword ptr [rax + r13 + 8]
     0072bfdb  je 0xffffffff8b0ec0ad             ; fd not open -> EBADF
     0072bffe  mov rax, qword ptr [r15]
     0072c001  lea r12, [rax + r13 + 8]
     0072c02c  lea rdi, [r12 + 8]
     0072c031  mov esi, 0x20
     0072c036  call 0xffffffff8ac18ff0           ; bzero(entry+8, 0x20)
     0072c03b  mov qword ptr [r12], 0            ; clear the entry's first qword

     0072c043  mov rcx, qword ptr [rbp - 0x30]  ; fd
     0072c04e  mov rdx, qword ptr [r15 + 0x20]  ; fd bitmap
     0072c052  rol rax, cl
     0072c055  shr ecx, 6
     0072c058  and qword ptr [rdx + rcx*8], rax ; clear the fd's bit

Both are W and not C because the covering compare is against a field, not a constant. Both stay
in bounds because that field *is* the table's capacity — the high-water mark of the same array the
store addresses, and the bitmap at [r15+0x20] is sized for that array when the descriptor is
built. Neither stored value is caller data: one is the immediate 0, the other a rotate of a kernel
constant. The caller chooses which slot is cleared, not what is written, and a slot past the mark
is rejected before the store. If a later pass finds a path that raises fd_lastfile past the bitmap
allocation these rows become interesting; nothing in this body does that.

### 3.2 C rows (28) — every bound read by hand

| RVA | body | syscall | store instruction | index bound | stored value | class |
|---|---|---|---|---|---|---|
| 0x55d2e9 | 0x55d0c0 | 416 | mov qword ptr [r15 + rcx + 0x400], rdx | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d2f7 | 0x55d0c0 | 416 | mov qword ptr [r15 + rcx + 0x408], r8 | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d2ff | 0x55d0c0 | 416 | mov dword ptr [r15 + rcx + 0x400], edx | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d311 | 0x55d0c0 | 416 | mov qword ptr [r15 + rax*8], rdx | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d33a | 0x55d0c0 | 416 | and dword ptr [r15 + rdx*4 + 0xc40], ecx | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d34a | 0x55d0c0 | 416 | or dword ptr [r15 + rcx*4 + 0xc40], r14d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d364 | 0x55d0c0 | 416 | or dword ptr [r15 + rcx*4 + 0xc10], r14d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d378 | 0x55d0c0 | 416 | or dword ptr [r15 + rcx*4 + 0xc00], r14d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d38c | 0x55d0c0 | 416 | or dword ptr [r15 + rcx*4 + 0xc20], r14d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d3a0 | 0x55d0c0 | 416 | or dword ptr [r15 + rcx*4 + 0xc30], r14d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d3d0 | 0x55d0c0 | 416 | and dword ptr [r15 + rcx*4 + 0xc10], r12d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d3e9 | 0x55d0c0 | 416 | and dword ptr [r15 + rdx*4 + 0xc00], ecx | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d402 | 0x55d0c0 | 416 | and dword ptr [r15 + rdx*4 + 0xc20], ecx | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d41b | 0x55d0c0 | 416 | and dword ptr [r15 + rdx*4 + 0xc30], ecx | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d4c4 | 0x55d0c0 | 416 | and dword ptr [r15 + r13*4 + 0xc50], r12d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d4f2 | 0x55d0c0 | 416 | or dword ptr [r15 + r13*4 + 0xc50], r14d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d4fa | 0x55d0c0 | 416 | and dword ptr [r15 + r13*4 + 0xc60], r12d | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x55d50b | 0x55d0c0 | 416 | mov dword ptr [r15 + r13*4 + 0xc60], eax | signum-1 in [0,0x7f] | copyin struct qwords; 1<<idx masks | C |
| 0x603608 | 0x6034e0 | 565 | mov qword ptr [rbx + r12*8 + 0x160], r13 | arg1 in [0,5] | arg2 qword from uap | C |
| 0x603653 | 0x6034e0 | 565 | mov qword ptr [r15 + r12*8 + 0x160], r13 | arg1 in [0,5] | arg2 qword from uap | C |
| 0x603690 | 0x6034e0 | 565 | mov qword ptr [r15 + r12*8 + 0x160], rbx | arg1 in [0,5] | arg2 qword from uap | C |
| 0x6036cb | 0x6034e0 | 565 | mov qword ptr [rbx + r12*8 + 0x160], r13 | arg1 in [0,5] | arg2 qword from uap | C |
| 0x6037e5 | 0x603710 | 566 | mov qword ptr [r15 + r13*8 + 0x190], r12 | arg1 = -1 or 0..5 | arg2 qword from uap+0x10 | C |
| 0x603874 | 0x603710 | 566 | mov qword ptr [rbx + r13*8 + 0x190], r12 | arg1 = -1 or 0..5 | arg2 qword from uap+0x10 | C |
| 0x6bcf29 | 0x6bccc0 | 83 | mov qword ptr [rax + r12 + 0x98], rdx | count in [0,2] | copyin group qwords | C |
| 0x6bcf31 | 0x6bccc0 | 83 | mov qword ptr [rax + r12 + 0x90], rcx | count in [0,2] | copyin group qwords | C |
| 0x6bcf3f | 0x6bccc0 | 83 | mov qword ptr [rax + r12 + 0xa0], rcx | count in [0,2] | copyin group qwords | C |
| 0x6bcf4b | 0x6bccc0 | 83 | mov qword ptr [rax + r12 + 0xa8], rcx | count in [0,2] | copyin group qwords | C |

## 4. Why each body is C — disassembly a human can check

### 4.1 syscall 416, sigaction — body 0x55d0c0, 1247 bytes, 18 rows

     0055d0d8  mov rbx, rsi                    ; rbx = uap
     0055d0f8  mov r14, qword ptr [rbx + 8]    ; act pointer
     0055d135  mov r13d, dword ptr [rbx]       ; signum (uap slot 0)
     0055d13d  lea r9d, [r13 - 1]              ; act != NULL path
     0055d141  cmp r9d, 0x7f
     0055d145  ja 0xffffffff8af1d57f           ; signum not in [1,0x80] -> EINVAL
     0055d14b  cmp qword ptr [rbp - 0x50], 2   ; act == NULL path
     0055d15e  mov r13d, dword ptr [rbx]
     0055d166  lea r9d, [r13 - 1]
     0055d16a  cmp r9d, 0x80
     0055d171  jae 0xffffffff8af1d57f          ; signum not in [1,0x80]
     0055d18b  mov rbx, r9                     ; rbx = signum - 1
     0055d1cc  mov r13, rbx                    ; live index = signum - 1 in [0,0x7f]
     0055d1a5  mov r15, qword ptr [r15 + 0xa8]  ; r15 = proc->p_sigacts

Both entry paths converge at 0x55d177, so every store below is dominated by one of the two
compares. The live index is signum-1, not signum; the array widths agree with that:

     0055d1d8  mov eax, r13d
     0055d1de  shl rcx, 4                     ; 16-byte stride
     0055d1e2  mov rdx, qword ptr [r15 + rcx + 0x400]
     0055d1ea  mov rcx, qword ptr [r15 + rcx + 0x408]
     0055d1f6  mov ecx, r13d
     0055d209  shr ecx, 5                     ; mask word index = idx >> 5, in [0,3]
     0055d20c  shlx edx, edx, r13d            ; bit = 1 << idx
     0055d2e9  mov qword ptr [r15 + rcx + 0x400], rdx
     0055d2f7  mov qword ptr [r15 + rcx + 0x408], r8
     0055d2ff  mov dword ptr [r15 + rcx + 0x400], edx
     0055d311  mov qword ptr [r15 + rax*8], rdx     ; 0x80 pointers = 0x400 bytes
     0055d33a  and dword ptr [r15 + rdx*4 + 0xc40], ecx
     0055d34a  or dword ptr [r15 + rcx*4 + 0xc40], r14d
     0055d364  or dword ptr [r15 + rcx*4 + 0xc10], r14d
     0055d378  or dword ptr [r15 + rcx*4 + 0xc00], r14d
     0055d38c  or dword ptr [r15 + rcx*4 + 0xc20], r14d
     0055d3a0  or dword ptr [r15 + rcx*4 + 0xc30], r14d
     0055d3d0  and dword ptr [r15 + rcx*4 + 0xc10], r12d
     0055d3e9  and dword ptr [r15 + rdx*4 + 0xc00], ecx
     0055d402  and dword ptr [r15 + rdx*4 + 0xc20], ecx
     0055d41b  and dword ptr [r15 + rdx*4 + 0xc30], ecx
     0055d4c0  shr r13d, 5
     0055d4c4  and dword ptr [r15 + r13*4 + 0xc50], r12d
     0055d4f2  or dword ptr [r15 + r13*4 + 0xc50], r14d
     0055d4fa  and dword ptr [r15 + r13*4 + 0xc60], r12d
     0055d50b  mov dword ptr [r15 + r13*4 + 0xc60], eax

Capacity arithmetic: 0x80 entries x 16 bytes = 0x800 bytes, which is exactly the 0x400..0xc00
window the code uses; the pointer array at +0 takes 0x80 x 8 = 0x400; each mask array at
0xc00/0xc10/0xc20/0xc30/0xc40 is 0x10 bytes = 128 bits = 0x80 signals, and idx>>5 in [0,3] keeps
every mask store inside its own 4-dword array; 0xc50 and 0xc60 are reached with r13 already
shifted right by 5. Class C. Note the values stored are caller data (qwords reloaded from the
copyin'd sigaction at [rbp-0x44]/[rbp-0x3c]/[rbp-0x50]) — this is a row where a caller controls
*what* lands in a kernel object, and the reason it is not a finding is that the index is
clamped, not the value.

### 4.2 syscall 565 — body 0x6034e0, 554 bytes, 4 rows

     006034ee  mov r12d, dword ptr [rsi + 8]    ; arg1
     006034f2  mov r13, qword ptr [rsi + 0x10]  ; arg2
     00603506  cmp r12, 6
     0060350a  setae al
     0060350d  test r13, rcx
     00603510  setne cl
     00603513  or cl, al
     00603515  jne 0xffffffff8afc36f8           ; arg1 > 5 (or bad arg2 bits) -> EINVAL
     006035cd  mov rbx, qword ptr [rax + 0x3f8] ; per-proc array object
     00603608  mov qword ptr [rbx + r12*8 + 0x160], r13
     00603653  mov qword ptr [r15 + r12*8 + 0x160], r13
     00603690  mov qword ptr [r15 + r12*8 + 0x160], rbx
     006036cb  mov qword ptr [rbx + r12*8 + 0x160], r13

Six qwords at +0x160..0x190 (0x30 bytes) and a bound of 6: capacity and compare agree. Class C.

### 4.3 syscall 566 — body 0x603710, 691 bytes, 2 rows

     0060371e  mov r13d, dword ptr [rsi + 8]
     00603728  lea eax, [r13 - 6]
     0060372c  cmp eax, -7
     0060372f  jb 0xffffffff8afc39b1           ; accept only r13-6 in [0xfffffff9,0xffffffff]
     006037db  cmp r13d, -1
     006037df  je 0xffffffff8afc3925           ; sentinel: write all six slots
     006037e5  mov qword ptr [r15 + r13*8 + 0x190], r12
     00603874  mov qword ptr [rbx + r13*8 + 0x190], r12
     0060392c  mov qword ptr [rax + 0x190], r12   ; +0x198,0x1a0,0x1a8,0x1b0,0x1b8 follow,
     00603972  mov qword ptr [rax + 0x1b8], r12   ;  six explicit stores for r13 = -1

The unsigned compare admits exactly {-1, 0, 1, 2, 3, 4, 5}; -1 is diverted to the six explicit
stores, so the indexed form runs with r13 in [0,5] over a six-qword array at +0x190. Class C.
The guard locator's nearest hit for these rows, `cmp r13d,-1`, is the sentinel test, not the
bound — a good reminder that the machine-reported guard is not the answer.

### 4.4 syscall 83 — body 0x6bccc0, 1320 bytes, 4 rows

     006bccd8  mov rbx, rsi
     006bcce6  mov r15, qword ptr [rsi + 8]      ; arg1 = source pointer
     006bcd0a  lea rsi, [rbp - 0x60]
     006bcd0e  mov edx, 0x20
     006bcd13  mov rdi, r15
     006bcd16  call 0xffffffff8ac19280           ; copyin(arg1, &kbuf, 0x20)
     006bcd23  mov r12d, dword ptr [rbx]         ; arg0 = count
     006bcd26  cmp r12, 2
     006bcd2a  ja 0xffffffff8b07cd7a            ; count > 2 -> EINVAL (0x16)
     006bcee0  mov rax, qword ptr [r15 + 0x58]
     006bcee4  shl r12, 5                        ; 32-byte stride
     006bcf29  mov qword ptr [rax + r12 + 0x98], rdx
     006bcf31  mov qword ptr [rax + r12 + 0x90], rcx
     006bcf3f  mov qword ptr [rax + r12 + 0xa0], rcx
     006bcf4b  mov qword ptr [rax + r12 + 0xa8], rcx

count in [0,2], stride 0x20, four qwords per slot from +0x90: three slots of 0x20 bytes.
Class C. The stored values come from the copyin'd 0x20-byte group at [rbp-0x60] — again caller
data into a kernel object with a clamped index.

### 4.5 syscall 6 — body 0x72bf00, 1218 bytes, 2 rows

Covered in 3.1. The body opens as a marshalling stub — 0x72bf04 `mov esi, dword ptr [rsi]` then
0x72bf07 `jmp 0xffffffff8b0ebf10` — but that target lies inside the same extent, and the extent ends
at 0x72c136 `jmp 0xffffffff8b0eb8e0` into a shared epilogue, so the whole 1218-byte function is one
body. Class W for both rows.

---

## 5. False-positive classes ruled out

1. **Wrong entry ABI (rdi as uap).** Taints `td` field loads and reports the `td_retval[0]` store
   present in most handlers as a steered write. Ruled out by the getpid body in 2.1.
2. **Table-load class: a kernel pointer fetched through a validated index.** sys 237 (0x6bdfb0) and
   sys 238 (0x6be1d0) each produce `inc/dec dword ptr [r13+0x9c]` where r13 = [[rax+r13*8+0x20]]
   under `cmp r13,3` / `cmp r13d,0x20`. That is a refcount bump on an object selected by the
   index, not a store into an array at the index. Fix: a load through a tainted index taints the
   value only when the base is tainted, not when only the index is. Both rows disappeared and no
   other row changed.
3. **Adjacent function inside the extent.** The image separates neighbouring functions with two
   nop bytes, so "stop at ret + 8 bytes of padding" analyses the next function. sys 475/476 rows
   (`lock xadd dword ptr [rdx+0x28],ecx`) were the next function's object-pointer RMW, where the
   pointer came from a helper return. Fixed by the prologue rule in 2.2; the analysed text fell
   from 228432 to 157909 bytes and the rows vanished.
4. **Prefix inside the mnemonic.** capstone reports `lock xadd`, `lock cmpxchg`, `rep movsq`.
   Matching the raw mnemonic skips 181 atomic stores in this corpus, including every refcount
   decrement. Store detection now strips lock/rep/repe/repne/xacquire/xrelease.
5. **Stack-slot width alias.** `mov dword ptr [rbp-0x44], r9d` was recorded as an 8-byte slot,
   tainting the qword at [rbp-0x40]; that produced a fake row in sys 654
   (`mov byte ptr [rcx+0x117],0` with rcx = td). Slots are now stored with the operand's real
   size and looked up only when fully covered. 31 -> 30 rows.
6. **Machine guard hits that are not bounds.** For the 18 sigaction rows the locator's nearest
   hits are `test al,1` / `test al,2` — flag tests on a byte of the copied-in struct. For sys 566
   the nearest hit is the `cmp r13d,-1` sentinel test. Accepting the locator's first hit without
   reading it would have produced two wrong C citations.
7. **Register destinations counted as stores.** The first pass tested only "operand 0 exists", so
   every register-to-register mov — `mov rbp,rsp`, `mov rbx,rsi`, 11966 of them — was counted as a
   store. Requiring operand 0 to be memory keeps the 2367 real memory-destination movs.
8. **Tail jumps into a different function.** 18 bodies end in a `jmp` out of the extent. 17 of them
   are 17..1026-byte stubs whose target is one of 13 real functions that are *not* sysent entries
   (each begins `push rbp; mov rbp,rsp; push r15..rbx; sub rsp,N` — a full prologue, not a shared
   epilogue); the 18th, body 0x531720 (sys 135), does its own work and then tail-calls the copyout
   helper 0x2591d0 with `add rsp,8; pop rbx; pop r14; pop r15; pop rbp; jmp copyout`. Stopping at the
   jump is correct in both shapes: continuing past it attributes another function's stores to this
   body, and the callee's ABI (arguments in r14/r15 set by the stub) is not the entry ABI.
9. **Stores whose base register is literally `rsi`.** 18 such stores exist and every one of them has a
   `rsi` that the body itself overwrote; none writes through the caller's argument array:
   sys 59 (0x6e4b14/0x6e4b29) sets `rsi = r12 = [td+8]` (the proc) and flips `p_flag` bits at +0xb0/+0xb4;
   sys 92 (0x72aa69) has `rsi = [rbp-0x2a0] = td` (0x729dde/0x729fa9) and writes `td_retval[0]` at +0x408,
   and 0x72b121 has `rsi = [rbp-0x2a8] = rbx`, a file object reloaded from a call return (0x729fb6);
   sys 629 (0x91c8a6..0x91c8c1) splices a list element — `rsi` is reloaded from `rdi` at 0x91c820 while
   walking a list; body 0x409790 writes `mov word ptr [rsi],2` into a global table at
   `lea rdx,[rip+0x30eb1d1]` with `rcx` a constant (0x11 or 0x1c); sys 80 (0x2a9d40, 0x2a9d70) is an insertion sort over
   `[proc+0x118]` whose index is the loop counter bounded by the element count it loaded from the same
   object (`cmp rax,rbx` at 0x2a9d43, `cmp rdx,1 / jg` at 0x2a9d76). So the "base is a uap slot" class is empty after provenance
   tracing, not merely unclassified.
10. **`rsi` reassigned inside the body.** A heuristic that keys on the literal text `[rsi+N]` keeps
   treating uap slot N as live after the body has overwritten `rsi`. In sys 629 that produces one
   apparent hit, `mov qword ptr [rcx+8],rax` at 0x91c849 with `rcx = [rsi+0x10]` — but `rsi` was set
   to a list element at 0x91c820 (`mov rsi,rdi`) and to a format string at 0x91c65b before that. The
   entry ABI holds for exactly as long as nothing writes `rsi`; the CFG dataflow tracks that, a
   textual scan does not.

---

## 6. Limits — what this census cannot see

- **The sysent boundary.** 18 of 301 bodies (6.0%) end in a tail jmp out of the extent: 17 are
  17..1026-byte stubs into 13 shared implementations that are not sysent entries, and one
  (0x531720, sys 135) tail-calls copyout. Those implementations are outside the 301-body set and are
  not classified here. Appendix A lists them with store counts. Several carry indexed stores (up to
  17 per function) and are the obvious next pass.
- **Opaque call returns.** A value returned by a helper and used as an index is level 0. Any bound
  that lives inside a callee is invisible.
- **Stored-value provenance beyond one hop.** A value classified "caller" here is one that was
  reloaded from a copyin region or read from a uap slot; deeper laundering is not followed.
- **Dominance is computed on this script's block graph**, not on a decompiler's CFG. The dominates
  flag is a convenience; every row above is justified by the quoted compare and its branch target.
- **13.60 is not 14.10.** The image is the 13.60 capture; the 14.10 kernel is not in this repo. The
  census answers a question about that capture. A 14.10 image would need the same run.

---

## 7. Appendix A — beyond the sysent boundary (unclassified leads)

The 17 stubs that jump into a shared implementation, and their 13 targets (the eighteenth tail
jump, body 0x531720 for sys 135, goes into copyout and is not a handler):

| target RVA | reachable from syscalls | size | stores | indexed stores |
|---|---|---|---|---|
| 0x34b540 | 592 | 578 | 9 | 1 |
| 0x3af920 | 661, 662, 668 | 2248 | 47 | 17 |
| 0x3b0fd0 | 664 | 1683 | 35 | 7 |
| 0x3b16a0 | 665, 666 | 2489 | 67 | 16 |
| 0x4ecdd0 | 480 | 354 | 4 | 0 |
| 0x729ac0 | 41 | 691 | 19 | 1 |
| 0x83dac0 | 487 | 922 | 15 | 0 |
| 0x8f8570 | 10 | 647 | 8 | 0 |
| 0x8fa330 | 138 | 442 | 7 | 0 |
| 0x8fb900 | 136 | 636 | 12 | 0 |
| 0x8f8870 | 137 | 574 | 8 | 0 |
| 0xab9480 | 203 | 247 | 2 | 0 |
| 0xc43190 | 402, 403 | 602 | 14 | 0 |

The 0x3af920 / 0x3b0fd0 / 0x3b16a0 cluster is the Sony asynchronous-I/O implementation (its
error words 0x80020001/0x80020003/0x80020010 are written into caller-shaped arrays). Example
sites: `mov dword ptr [rdx + r13*4], 0x80020003` at 0x3afb90, `mov qword ptr [rdi + rcx*8 + 8], rax`
at 0x3afd5a, `mov dword ptr [r8 + r14*4 + 0x160], 0` at 0x3b1e14. The element count is validated at
0x3af9f7 (r15 = [rbx+0x48]) with `lea eax,[r15-0x81]; cmp eax,0xffffff7f; ja error` — an unsigned
range test whose upper end (0x10000000) is far larger than any plausible array, and the loop at
0x3afba1 (`cmp r13, rdi`) walks that count. Whether the destination arrays are allocated with the
same count is the question; the sizes are computed at 0x3afb06 (`lea rax,[r14*8]; lea rdi,[rax+rax*2]`
= count*24) while the status array at [rbx+8] is written with a 4-byte stride. **This is a lead, not
a finding** — it is outside the 301-body scope, the stub ABI has not been modelled, and the 14.10
behaviour of 661-670 in this repo's probe logs is lethal-on-call rather than observable.

---

## 8. Reproduce

     python .local/ixstore_census.py > .local/ix_run.txt

The script prints one JSON object: `bodies` (301), `scanned` (301) and `candidates` — one record
per tainted store with `site` (RVA), `text`, `func`, `base`/`index`/`disp`/`scale`, the taint
levels and descriptions for base, index and stored value, `onstack`, the body RVA with its extent
and termination reason, `syscalls` (every sysent number that resolves to that body), and the guard
locator's `cmp`/`br`/`br_target`/`dominates` hits.

To check any row by hand, decode the body with the same helper and read the cited RVAs:

     import importlib.util
     spec = importlib.util.spec_from_file_location('ix', '.local/ixstore_census.py')
     ix = importlib.util.module_from_spec(spec); spec.loader.exec_module(ix)
     size, why = ix.extent(0x72bf00)
     for i in ix.decode(0x72bf00, size):
         print('%08x  %s' % (i.a - ix.BASE, i.text))

Counting what the verdict is based on:

     for b in ix.BODIES:                       # 301
         size, why = ix.extent(b)
         ins = ix.decode(b, size)              # 39346 total
         stores = [i for i in ins if i.ops and i.ops[0].type == 2 and ix.store_kind(i)]

`.local/ix_v6.json` is the candidate snapshot used for the tables above; `.local/ix_run.txt` is the
same run in full.
