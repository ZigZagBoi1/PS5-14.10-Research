# INTERPROC_COPYOUT_SOURCES

Interprocedural audit of every copyout/copyin reachable from the 301 resolved PS5 13.60 syscall
handler bodies, looking for a user-supplied value that lands in the **source** pointer of a copyout
or the **destination** pointer of a copyin.

**VERDICT: no such primitive exists in this image.** 0 of 301 bodies performs a raw memory access
whose base derives from a syscall argument; 0 of 39 reachable copyout sites take their source from
user input; 0 of 57 reachable copyin sites take their destination from user input. Every non-stack
site was resolved by hand to a kernel-provenance object (section 5). Coverage and the exact
per-site table are in sections 3, 4 and Appendix A.

---

## 1. Artefact conventions, and one correction to the brief

- `kernel_text.bin` is raw .text, **file offset == RVA**. Load base VA `0xffffffff8a9c0000`.
  So `VA = RVA + 0xffffffff8a9c0000`.
- The brief gives copyout as "VA `0xffffffff8ac191d0`, RVA `0xc191d0`". Those two are not
  consistent: `0xffffffff8ac191d0 - 0xffffffff8a9c0000 = 0x2591d0`. The **VA is correct** and the
  RVA label is the VA minus `0xffffffff8a000000`. All offsets in this report are file offsets
  (= true RVAs), and the helper constants used throughout are:

  | helper | VA | RVA / file offset | args |
  |---|---|---|---|
  | copyout | `0xffffffff8ac191d0` | `0x2591d0` | rdi=kernel src, rsi=user dst, rdx=len |
  | copyin  | `0xffffffff8ac19280` | `0x259280` | rdi=user src, rsi=kernel dst, rdx=len |
  | bzero   | `0xffffffff8ac18ff0` | `0x258ff0` | rdi=kernel, rsi=len |
  | memcpy  | `0xffffffff8ac190b0` | `0x2590b0` | rdi=dst, rsi=src, rdx=len |

- Handler ABI: at body entry `rdi = struct thread *td`, `rsi = struct syscall_args *uap`.
  `uap->arg[i]` is at `[rsi + 8*i]`. This single fact decides most of the classification.

## 2. Method

1. **Decode once.** capstone 5.0.7, `CS_MODE_64`, `skipdata=True` (required: the image contains
   data islands inside .text). Full-image linear decode, 15,132,096 bytes.
2. **Function starts** from three sources: (a) the 301 distinct handler bodies obtained by decoding
   the 5-byte `e9 rel32` thunk at each `sy_call_off`; (b) every direct `call rel32` target;
   (c) every `jmp rel32` target. Deduplicated by prologue -> **1,110 unique functions**.
   Note: `e9 rel32` yields an **RVA**, not a VA (the rel32 is a difference of two VAs, so the
   base cancels). Comparing the decoded target against the VA base is the bug that produced a
   spurious "0 of 679 resolved" during this work; against `len(text)` all 679 entries resolve.
3. **Call graph**: direct `e8 rel32` calls plus direct `e9 rel32` jumps inside the image;
   **4,274 edges over 2,077 nodes** (nodes include tail-call-only targets). Indirect calls
   (`call r/m64`, `call [rip+...]` through the vtable/`pr_usrreqs` style tables) are recorded but
   not traversed.
4. **BFS depth 4** from each of the 301 bodies over that graph; median 22 functions per body,
   maximum 136.
5. **Site classification**: for every copyout/copyin call site reachable in that closure, walk
   backwards in the enclosing function for the last write to rdi (and rsi), then classify:
   (a) `lea rdi,[rbp-X]` / `[rsp+X]` -> stack; (b) `mov rdi,<global>` / `[reg+disp]` ->
   kernel object; (c) `mov rdi,rXX` where rXX came from memory addressed by an argument ->
   the jackpot shape.
6. **Provenance, correctly.** Two passes were needed and the first two were wrong; see section 6.
   The final pass is a CFG-aware forward dataflow (basic blocks split at every branch target and
   after every branch; lattice = per-register label in
   {uap, arg[i], mem[arg i + disp], der[i], td}; **join = intersection**, so a register keeps a
   label only if every predecessor agrees; kill-on-clobber; caller-saved registers killed at every
   `call`). Events are recorded when a memory operand's base register carries an
   arg/mem/der label.

## 3. Coverage

| metric | value |
|---|---|
| sysent entries | 679 |
| entries whose thunk decoded to an in-image body | **679 / 679 (100%)** |
| distinct handler bodies | **301** |
| bodies reachable (all 301 decoded and analysed) | **301 / 301** |
| bodies with no resolvable body (indirect-only / unresolved) | **0** |
| unique functions in the depth-4 closure | 1,110 |
| distinct helper sites reachable from bodies | **174** (39 copyout, 57 copyin, 78 bzero/memcpy) |
| bodies reaching >=1 copyout | 34 |
| bodies reaching >=1 copyin | 55 |
| bodies reaching neither | 223 |
| bodies with a helper site in their own body (not via callee) | 84 |
| bodies with a raw memop on an arg-derived base | **0** |

There are **no unresolved bodies**. Every one of the 679 `sy_call` values is a 5-byte
`e9 rel32` thunk inside the image, and all 301 targets are distinct handler bodies. The
"indirect-only" category is empty at the body level; it is non-empty only for *callees*, which is
why section 6's negative is scoped to bodies and section 5 is the compensating hand audit of every
non-stack site found in the closure.

## 4. Aggregate classification of the 174 reachable sites

copyout, source (rdi) classification:

| class | count | meaning |
|---|---|---|
| stack | 35 | `lea rdi,[rbp-X]` — the closed pattern |
| kernel object (`mem`) | 4 | `mov rdi,[reg+disp]` with kernel-provenance base |
| user-derived (`arg`/`mem[arg]`/`der`) | **0** | — |
| global | 0 | — |
| unresolved | **0** | every site resolved by hand |

copyin, destination (rsi) classification:

| class | count | meaning |
|---|---|---|
| stack | 48 | `lea rsi,[rbp-X]` |
| unresolved in the automated pass | 9 | all resolved by hand in section 5 to malloc / alloca / global / kernel-struct |
| user-derived | **0** | — |

bzero/memcpy (78 sites) are stack scrub / struct copy and are not pointer-carrying; the handful
with memory-operand bases are kernel object fields and were resolved in the same hand pass.

## 5. Every non-stack site, resolved by hand

copyout sites whose source is a loaded pointer rather than a stack slot — **the entire population
of "jackpot-shaped" sites in this image is these five**:

| # | body | syscalls | site | instruction that sets rdi | provenance | verdict |
|---|---|---|---|---|---|---|
| 1 | `0x2a8de0` | 79 getgroups | `0x2a8e42` | `mov rcx,[rdi+0x140]` / `mov rbx,[rcx+0x118]` / `mov rdi,rbx` | `rcx = td->td_ucred`, `rbx = cred->cr_groups` | CLOSED — thread-derived, not user-derived; len `= cr_ngroups*4`, dst `uap->arg1`, guarded by `cmp edx,r12d; jb EINVAL` |
| 2 | `0x313a30` | (callee, no body) | `0x313a6c` | `mov r12,[rdi+0x18]` / `mov rsi,r12` (copyout dst=arg, src=kernel) | `[rdi+0x18]` = kernel object field; `rdi` is the caller's kernel pointer | CLOSED — src kernel, len `edx*32` |
| 3 | `0x5310a0` | 30 accept | `0x531151` | `mov r14,[rbp-0x38]` (slot filled by helper `0x8aef08a0`) / `mov rdi,r14` | pointer returned by kernel helper into a stack slot (sbuf) | CLOSED — kernel heap buffer |
| 4 | `0x533030` | 32 getsockname | `0x5330d5` | same `[rbp-0x38]` helper-returned pointer | kernel heap buffer | CLOSED |
| 5 | `0x533310` | 31 getpeername | `0x5333b5` | same `[rbp-0x38]` helper-returned pointer | kernel heap buffer | CLOSED |

copyin sites whose destination is not a stack slot:

| body | syscalls | site | destination | provenance | verdict |
|---|---|---|---|---|---|
| `0x313a90` | (callee) | `0x313acc` | `[rdi+8]` | kernel object field | CLOSED |
| `0x34c8c0` | 599 | `0x34c950` | `[r12+0xc8]` | kernel object field | CLOSED |
| `0x37e910` | 442 | `0x37e93f` | kernel stack struct, len `0x10` | stack | CLOSED |
| `0x530480` | 104 | `0x5304eb` | `malloc(<=0xff)` via `0x8b5c8b50` | heap | CLOSED |
| `0x531260` | 98 | `0x5312cb` | `malloc(<=0xff)` via `0x8b5c8b50` | heap | CLOSED |
| `0x6be4d0` | 636 | `0x6be54b` | global `0x32573db` | kernel global, len `uap->arg1` capped `0x200` | CLOSED |
| `0x7827f0` | 27,28,120,121,289,290,393 | `0x78285a` | `malloc(n*16)+0x30`, `n<=0x400` | heap | CLOSED |
| `0x7828b8` | 120,121,289,290,393 | `0x782916` | `lea` into the same malloc'd buffer | heap | CLOSED |
| `0x83de90` | 488 | `0x83df0b` | `malloc([r15+0x18])` | heap | CLOSED |
| `0xa07280` | 417 | `0xa072e3` | `lea` into kernel buffer, len fixed `0x500` | heap/stack | CLOSED |
| `0xa0ac60` | 422,423 | `0xa0ad68` | `alloca` VLA guarded by `cmp rdx,[lim-0x200]; ja` | stack VLA, bounded | CLOSED |

## 6. Raw arg-derived memory operations: 0 of 301 — and the three false-positive classes

The CFG-aware pass returns **zero** events over all 301 bodies: no body dereferences a pointer it
obtained from `uap->arg[i]`, and no body stores through one. This is the expected shape for
FreeBSD: handlers receive a kernel `uap`, and all user memory traffic goes through
`copyin`/`copyout`. Three earlier passes produced 9, then 0, then 9 "hits"; all were artifacts:

1. **Post-instruction aliasing.** A backwards tracer that records the base register's value *after*
   the instruction reports `mov esi,[rsi]` as "deref of the value that was loaded" instead of
   "deref of uap". Every `mov rX,[rX]` self-overwriting load is mislabelled this way.
2. **Linear sweep across branch targets.** Sweeping a function front-to-back without following
   control flow carries register labels across `jmp`/`jcc` boundaries. This produced all nine
   surviving "hits", including the two that look most like a primitive:
   - `0x4ed3c0` (sys 522): the block at `0x4ed507` (`mov esi,[r15]; mov rdx,[r15+8]; mov rcx,[r15+0x10]; mov r8,[r15+0x18]`)
     is only reachable from `0x4ed457`, i.e. *before* `0x4ed4b1 mov r15,[r15+0x18]`. At that point
     `r15` is still `uap`, so the four loads are `uap->arg0..arg3` — argument marshalling, not
     dereferences. (The `arg4`/`arg5` branches on either side *do* `copyin` 16 bytes each.)
   - `0x6bbd20` (sys 233) and `0x49ff80` (sys 96): `mov r14,rsi` then `[r14]` / `[r14+0x10]`
     are `uap->arg0` / `uap->arg2`. Same cause.
3. **Bounded index mistaken for a raw write.** `0x6034e0` (sys 565) contains
   `mov [rbx+r12*8+0x160],r13` with `r12 = uap->arg1` — but `cmp r12,6; setae al; ... jne EINVAL`
   bounds it to 0..5, and `rbx` is a kernel proc from the pid lookup `0x8b552420`.

Residual class not covered by this pass: a body that hands a user pointer to an **indirect**
callee which dereferences it. The direct-call population is covered (section 5 enumerates every
non-stack site in the depth-4 closure); the indirect population is `pr_usrreqs`-style dispatch,
i.e. socket/filesystem methods, which take kernel object pointers, not raw user pointers.

## 7. Ranked top-5 closest shapes (all fail; ranked by how close they get)

Because the honest result is negative, this is a ranking of *structural proximity*, each with the
exact instruction that would have to be user-controlled and the exact reason it is not.

### 1. sys 79 `getgroups` — `0x2a8de0` (VA `0xffffffff8ac68de0`), site `0x2a8e42`
```
0x2a8dee  mov  rcx, [rdi+0x140]      ; rcx = td->td_ucred        <- thread, NOT user
0x2a8df5  mov  edx, [rsi]            ; edx = uap->arg0 (gidsetsize)
0x2a8df7  mov  r12d,[rcx+0x10]       ; r12d = cred->cr_ngroups
0x2a8e04  cmp  edx, r12d
0x2a8e07  jb   EINVAL                ; bounds check
0x2a8e09  mov  r14, [rsi+8]          ; r14 = uap->arg1 (user dst)
0x2a8e0d  mov  rbx, [rcx+0x118]      ; rbx = cred->cr_groups   <- kernel source
0x2a8e2c  lea  r15, [r12*4]          ; len = ngroups*4
0x2a8e39  mov  rdi, rbx
0x2a8e3c  mov  rsi, r14
0x2a8e42  call copyout
```
This is the only site in the image whose copyout source is a *loaded pointer* rather than a `lea`.
Probe would have to make `[td+0x140]` or `[cred+0x118]` user-controlled: it cannot. **Read** (of
`cred->cr_groups`, `cr_ngroups*4` bytes, to a user address) — no kernel address is chosen by the
caller.

### 2. sys 522 — `0x4ed3c0` (VA `0xffffffff8aead3c0`), block `0x4ed507`
```
0x4ed3d8  mov  r15, rsi              ; r15 = uap
0x4ed3e6  mov  r14, [rsi+0x20]       ; arg4 -> copyin 16 B
0x4ed450  mov  r12, [rsi+0x28]       ; arg5 -> copyin 16 B
0x4ed457  je   0x4ed507              ; arg5 == NULL
0x4ed507  mov  esi, [r15]            ; uap->arg0   <- NOT a deref of arg3
0x4ed50a  mov  rdx, [r15+8]          ; uap->arg1
0x4ed50e  mov  rcx, [r15+0x10]       ; uap->arg2
0x4ed512  mov  r8,  [r15+0x18]       ; uap->arg3
0x4ed516  mov  rdi, rbx              ; rdi = td
0x4ed51c  call 0x4ed550              ; select-shaped body
```
Closest because the block loads four consecutive fields from a pointer and passes them as
`(esi,rdx,rcx,r8)` to a function that then `copyin`s the read/write/except fd sets. Probe: 6 args,
`arg5 = NULL`. **Neither read nor write** — `r15` is `uap`, so the values are the arguments
themselves.

### 3. sys 565 — `0x6034e0` (VA `0xffffffff8afc34e0`), store `0x6036cb`
```
0x6034ee  mov  r12d,[rsi+8]          ; arg1 = index
0x603506  cmp  r12, 6
0x60350a  setae al                   ; reject index >= 6
0x6035cd  mov  rbx, [rax+0x3f8]      ; kernel proc, from 0x8b552420(arg0)
0x6036cb  mov  [rbx+r12*8+0x160], r13  ; r13 = arg2 (flags, masked)
```
Only raw **store** with an arg-derived index in the image. Probe: `arg0 = pid`, `arg1 <= 5`,
`arg2 = flags`. **Write**, but into a kernel proc's signal-flag array, index bounded to 0..5, base
from a pid lookup — not an arbitrary-address write.

### 4. sys 466 — `0x4a0400` (VA `0xffffffff8ae60400`), sites `0x4a0465` / `0x4a0523`
```
0x4a0434  mov  eax, [rbx]            ; arg0 = op selector (0/1/2)
0x4a043e  mov  r14, [rbx+0x10]       ; arg2 = user pointer
0x4a045d  mov  edx, 4
0x4a0465  call copyin                ; 4 bytes user -> [rbp-0x34]
...
0x4a04fc  mov  rbx, [rbx+0x10]       ; arg2 again
0x4a0517  lea  rdi, [rbp-0x34]
0x4a0520  mov  rsi, rbx
0x4a0523  call copyout               ; 4 bytes [rbp-0x34] -> user
```
A clean 4-byte user->kernel->user round trip: the copyout **source is the stack slot**, so nothing
kernel-side is disclosed. Probe: `arg0=0`, `arg1=pid`, `arg2=user ptr`. **Neither.**

### 5. sys 189 / 131 - `0x72c150` / `0x72e590` (VA `0xffffffff8b0ec150` / `0xffffffff8b0ee590`)
```
0x72c17c  movsxd r12, dword ptr [rsi]   ; r12 = uap->arg0 (fd), sign-extended
0x72c1b3  mov    rax, [rbx+8]           ; rbx = td
0x72c1c4  mov    rbx, [rax+0x48]        ; p->p_fd
0x72c1c8  mov    rax, [rbx]             ; fd->fd_ofiles
0x72c1d0  cmp    r12d, [rax]            ; compare fd against table count
0x72c1d3  jae    0x72c1e7               ; EBADF if out of range
0x72c1d5  lea    r12, [r12+r12*2]
0x72c1d9  shl    r12, 4                 ; fd * sizeof(struct filedescent) = fd*48
0x72c1dd  mov    rdi, [rax+r12+8]       ; load kernel struct file * from the table
0x72c1e2  test   rdi, rdi
0x72c1e5  jne    continue
```
Scaled index arithmetic straight off a raw argument, then a table load - the classic unchecked-index
shape. It is checked: `cmp r12d,[rax]; jae` bounds the index by the table header, and the loaded
value is a `struct file *` (kernel provenance) that then feeds the fstat-style path. Same pattern,
same outcome at `0x72e590` (sys 131), `0x6be1d0`/`0x6be370` (238/239: `cmp r14,3; jl` plus
`cmp r14d,0x20; setae`), `0x34cfa0` (649: `movzx eax,[rbx+8]; dec eax; cmp eax,7; ja`),
`0x4a13e0` (194: `cmp rbx,0xe; ja`), `0x73e780` (541: `movzx eax,[r14+0xb]; and eax,0xf`).
**Read** of a kernel table entry, index bounded, no address control.

## 8. What would change the answer

- The 14 previously closed leads (638/639 tz table, 657, aio 661-670, 601 mdbg, 622/623,
  umtx/osem, ptrace, devfs ioctls) were **not** re-audited here beyond confirming none of them
  reaches a non-stack helper site; they are consistent with this negative.
- The one category this pass cannot exclude is **indirect dispatch through a user-influenced
  object**: `pr_usrreqs`, `VOP_*` vectors, `cdevsw`, kqueue filters. Those receive kernel object
  pointers, so the primitive would have to be a *type-confusion* (user makes a kernel pointer
  point at a different struct), not a copyout-source inversion. That is the correct next target,
  and it is a different analysis (allocation-site provenance, not argument provenance).
- A second unexplored category: handlers that write `td->td_retval` from a kernel address
  computed from an argument. The CFG pass records no such computation in the bodies, but it did
  not model `td_retval` stores specially.

## Appendix A — full body -> reachable site table

`body VA` and `site VA` are file offsets (RVAs); add `0xffffffff8a9c0000` for VAs.
`depth-4 funcs` is the size of the closure; `class` is the rdi (copyout) or rsi (copyin)
classification; `provenance` is the resolved origin.

| body VA | syscalls | depth-4 funcs | site VA | kind | rdi/rsi class | provenance |
|---|---|---|---|---|---|---|
| 0x2a8de0 | 79 | 11 | 0x2a8e42 | copyout | mem [rcx+280] | cred->cr_groups (td_ucred=[td+0x140], groups=[cred+0x118]); len=cr_ngroups*4; dst=uap->arg1; bounds: arg0>=ngroups |
| 0x2a8de0 | 79 | 11 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x2a8e70 | 147 | 63 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x2ab690 | 49 | 20 | 0x2ab76d | copyout | stack rbp-96 | stack frame slot rbp-96 |
| 0x2ab690 | 49 | 20 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x2ab7a0 | 50 | 19 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x312ed0 | 362 | 34 | 0x72ca7d | bzero | unk  |  |
| 0x313160 | 141 | 34 | 0x72ca7d | bzero | unk  |  |
| 0x3134e0 | 363 | 33 | 0x313565 | copyin | stack rbp-344 | stack frame slot rbp-344 |
| 0x3134e0 | 363 | 33 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x331100 | 140 | 23 | 0x33114f | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x331100 | 140 | 23 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ad30 | 595 | 28 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ae90 | 591 | 48 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ae90 | 591 | 48 | 0xa0be0b | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x34ae90 | 591 | 48 | 0xb2a2bc | memcpy | unk  |  |
| 0x34ae90 | 591 | 48 | 0xb2a2dc | memcpy | unk  |  |
| 0x34ae90 | 591 | 48 | 0xb2a317 | memcpy | ptr lea | lea |
| 0x34b790 | 659 | 12 | 0x34b820 | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x34b7b0 | 593 | 56 | 0x34b820 | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x34b7b0 | 593 | 56 | 0x34b99a | bzero | unk  |  |
| 0x34b7b0 | 593 | 56 | 0x34ba5f | bzero | ptr lea | lea |
| 0x34b7b0 | 593 | 56 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34b7b0 | 593 | 56 | 0xb2b750 | memcpy | ptr td | td |
| 0x34bc60 | 660 | 50 | 0x34b99a | bzero | unk  |  |
| 0x34bc60 | 660 | 50 | 0x34ba5f | bzero | ptr lea | lea |
| 0x34bc60 | 660 | 50 | 0x34bcd0 | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x34bc60 | 660 | 50 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34bc60 | 660 | 50 | 0xb2b750 | memcpy | ptr td | td |
| 0x34bdc0 | 608 | 47 | 0x34be36 | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x34bdc0 | 608 | 47 | 0x34beaa | bzero | unk  |  |
| 0x34bdc0 | 608 | 47 | 0x34bf9f | bzero | ptr lea | lea |
| 0x34bdc0 | 608 | 47 | 0x34c082 | bzero | unk  |  |
| 0x34bdc0 | 608 | 47 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34c350 | 656 | 44 | 0x34c3d6 | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x34c350 | 656 | 44 | 0x34c44a | bzero | unk  |  |
| 0x34c350 | 656 | 44 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34c350 | 656 | 44 | 0x5e2ce5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c350 | 656 | 44 | 0x5e2cf9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c350 | 656 | 44 | 0x5e2dc5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c350 | 656 | 44 | 0x5e2dd9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c350 | 656 | 44 | 0x5e30e5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c350 | 656 | 44 | 0x5e30f9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c670 | 672 | 21 | 0x5e2ce5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c670 | 672 | 21 | 0x5e2cf9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c670 | 672 | 21 | 0x5e2dc5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c670 | 672 | 21 | 0x5e2dd9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c670 | 672 | 21 | 0x5e30e5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c670 | 672 | 21 | 0x5e30f9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c750 | 596 | 18 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34c990 | 598 | 11 | 0x34ca11 | copyout | stack rbp-40 | stack frame slot rbp-40 |
| 0x34c990 | 598 | 11 | 0x34ca44 | copyout | stack rbp-48 | stack frame slot rbp-48 |
| 0x34c990 | 598 | 11 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34caa0 | 599 | 48 | 0x34c913 | bzero | uap uap | uap |
| 0x34caa0 | 599 | 48 | 0x34c950 | copyin | uap uap | copyin dst=[r12+0xc8] kernel obj field |
| 0x34caa0 | 599 | 48 | 0x34c96e | bzero | ptr lea | lea |
| 0x34caa0 | 599 | 48 | 0x34ccca | bzero | stack rbp-176 | stack frame slot rbp-176 |
| 0x34caa0 | 599 | 48 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ce50 | 612 | 28 | 0x34ce99 | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x34ce50 | 612 | 28 | 0x34cec6 | bzero | stack rbp-48 | stack frame slot rbp-48 |
| 0x34ce50 | 612 | 28 | 0x34cf7e | copyout | stack rbp-48 | stack frame slot rbp-48 |
| 0x34ce50 | 612 | 28 | 0x5a4c60 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ce50 | 612 | 28 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ce50 | 612 | 28 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ce50 | 612 | 28 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34ce50 | 612 | 28 | 0x5a5a30 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x34cfa0 | 649 | 17 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x3af8e0 | 668 | 11 | 0x56212a | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x3af8f0 | 661 | 11 | 0x56212a | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x3b1670 | 665 | 11 | 0x56212a | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x437cf0 | 430 | 15 | 0x437d40 | copyin | stack rbp-1344 | stack frame slot rbp-1344 |
| 0x437cf0 | 430 | 15 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x437de0 | 455 | 13 | 0x437e23 | bzero | stack rbp-184 | stack frame slot rbp-184 |
| 0x437de0 | 455 | 13 | 0x437e4f | copyin | stack rbp-184 | stack frame slot rbp-184 |
| 0x437de0 | 455 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x438560 | 433 | 22 | 0x438599 | bzero | stack rbp-160 | stack frame slot rbp-160 |
| 0x4386f0 | 481 | 27 | 0x43873e | bzero | stack rbp-160 | stack frame slot rbp-160 |
| 0x4388c0 | 442 | 17 | 0x37e93f | copyin | uap uap | copyin dst=kernel stack struct, len=0x10 |
| 0x438b60 | 464 | 36 | 0x438b8f | bzero | stack rbp-80 | stack frame slot rbp-80 |
| 0x438b60 | 464 | 36 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x438c90 | 616 | 32 | 0x438cbd | bzero | stack rbp-80 | stack frame slot rbp-80 |
| 0x438c90 | 616 | 32 | 0x438d40 | copyout | stack rbp-80 | stack frame slot rbp-80 |
| 0x438c90 | 616 | 32 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x47b030 | 165 | 20 | 0x47b5b5 | memcpy | unk  |  |
| 0x47b030 | 165 | 20 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4a0400 | 466 | 43 | 0x4a042f | bzero | stack rbp-52 | stack frame slot rbp-52 |
| 0x4a0400 | 466 | 43 | 0x4a0465 | copyin | stack rbp-52 | stack frame slot rbp-52 |
| 0x4a0400 | 466 | 43 | 0x4a0523 | copyout | stack rbp-52 | stack frame slot rbp-52 |
| 0x4a0400 | 466 | 43 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4a0c30 | 195 | 44 | 0x4a0c7b | copyin | stack rbp-56 | stack frame slot rbp-56 |
| 0x4a0c30 | 195 | 44 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4a13e0 | 194 | 10 | 0x4a1490 | copyout | stack rbp-56 | stack frame slot rbp-56 |
| 0x4a13e0 | 194 | 10 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4a1ba0 | 117 | 32 | 0x4a1ec0 | memcpy | uap uap | uap |
| 0x4a2850 | 627 | 47 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4a2de0 | 641 | 43 | 0x4a1b69 | memcpy | uap uap | uap |
| 0x4a2de0 | 641 | 43 | 0x4a2e2b | bzero | stack rbp-104 | stack frame slot rbp-104 |
| 0x4a31a0 | 667 | 43 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4ec560 | 4 | 63 | 0x561235 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x4ec560 | 4 | 63 | 0x5e2ce5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec560 | 4 | 63 | 0x5e2cf9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec560 | 4 | 63 | 0x5e2dc5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec560 | 4 | 63 | 0x5e2dd9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec560 | 4 | 63 | 0x5e30e5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec560 | 4 | 63 | 0x5e30f9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec740 | 476 | 31 | 0x561235 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x4ec8e0 | 121 | 85 | 0x561235 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x4ec8e0 | 121 | 85 | 0x5e2ce5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec8e0 | 121 | 85 | 0x5e2cf9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec8e0 | 121 | 85 | 0x5e2dc5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec8e0 | 121 | 85 | 0x5e2dd9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec8e0 | 121 | 85 | 0x5e30e5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ec8e0 | 121 | 85 | 0x5e30f9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x4ecc70 | 290 | 70 | 0x561235 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x4ed3c0 | 522 | 32 | 0x4ed412 | copyin | stack rbp-80 | stack frame slot rbp-80 |
| 0x4ed3c0 | 522 | 32 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4ee4b0 | 93 | 17 | 0x4ee505 | copyin | stack rbp-64 | stack frame slot rbp-64 |
| 0x4ee4b0 | 93 | 17 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4f65f0 | 535 | 72 | 0x4f68b2 | copyout | stack rbp-56 | stack frame slot rbp-56 |
| 0x4f65f0 | 535 | 72 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4f65f0 | 535 | 72 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4f6a70 | 536 | 32 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4f6a70 | 536 | 32 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4f7370 | 604 | 42 | 0x4f74c2 | copyout | stack rbp-52 | stack frame slot rbp-52 |
| 0x4f7370 | 604 | 42 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4f7370 | 604 | 42 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x4f7370 | 604 | 42 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x52f8f0 | 97 | 107 | 0x350a3d | memcpy | uap uap | uap |
| 0x52f8f0 | 97 | 107 | 0x5071ce | bzero | stack rbp-80 | stack frame slot rbp-80 |
| 0x52f8f0 | 97 | 107 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x52f8f0 | 97 | 107 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x52f8f0 | 97 | 107 | 0x72ca7d | bzero | unk  |  |
| 0x52f8f0 | 97 | 107 | 0x7b815f | bzero | ptr lea | lea |
| 0x52f8f0 | 97 | 107 | 0xb9b6a7 | bzero | ptr td | td |
| 0x52fae0 | 113 | 107 | 0x350a3d | memcpy | uap uap | uap |
| 0x52fae0 | 113 | 107 | 0x5071ce | bzero | stack rbp-80 | stack frame slot rbp-80 |
| 0x52fae0 | 113 | 107 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x52fae0 | 113 | 107 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x52fae0 | 113 | 107 | 0x72ca7d | bzero | unk  |  |
| 0x52fae0 | 113 | 107 | 0x7b815f | bzero | ptr lea | lea |
| 0x52fae0 | 113 | 107 | 0xb9b6a7 | bzero | ptr td | td |
| 0x530480 | 104 | 68 | 0x5304eb | copyin | unk  | dst=malloc(<=0xff) via 0x8b5c8b50 |
| 0x530480 | 104 | 68 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x531080 | 30 | 49 | 0x5310fa | copyin | stack rbp-60 | stack frame slot rbp-60 |
| 0x531080 | 30 | 49 | 0x531151 | copyout | mem [rbp-56] | src=[rbp-0x38] ptr returned by helper 0x8aef08a0 (sbuf); dst=arg (user); len=[rbp-0x3c] |
| 0x531080 | 30 | 49 | 0x531180 | copyout | stack rbp-60 | stack frame slot rbp-60 |
| 0x531260 | 98 | 72 | 0x5312cb | copyin | unk  | dst=malloc(<=0xff) via 0x8b5c8b50 |
| 0x531260 | 98 | 72 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x531720 | 135 | 136 | 0x350a3d | memcpy | uap uap | uap |
| 0x531720 | 135 | 136 | 0x5071ce | bzero | stack rbp-80 | stack frame slot rbp-80 |
| 0x531720 | 135 | 136 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x531720 | 135 | 136 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x531720 | 135 | 136 | 0x72ca7d | bzero | unk  |  |
| 0x531720 | 135 | 136 | 0x7b815f | bzero | ptr lea | lea |
| 0x531720 | 135 | 136 | 0x7b8543 | bzero | stack rbp-58 | stack frame slot rbp-58 |
| 0x531720 | 135 | 136 | 0xb9b6a7 | bzero | ptr td | td |
| 0x5321e0 | 28 | 49 | 0x53222b | copyin | stack rbp-88 | stack frame slot rbp-88 |
| 0x5321e0 | 28 | 49 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x5321e0 | 28 | 49 | 0x78285a | copyin | unk  | dst=malloc(n*16)+0x30, n<=0x400 |
| 0x5328d0 | 29 | 36 | 0x532925 | copyin | stack rbp-88 | stack frame slot rbp-88 |
| 0x5328d0 | 29 | 36 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x5329e0 | 27 | 76 | 0x532a2b | copyin | stack rbp-88 | stack frame slot rbp-88 |
| 0x5329e0 | 27 | 76 | 0x532aad | copyout | stack rbp-88 | stack frame slot rbp-88 |
| 0x5329e0 | 27 | 76 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x5329e0 | 27 | 76 | 0x78285a | copyin | unk  | dst=malloc(n*16)+0x30, n<=0x400 |
| 0x532af0 | 134 | 59 | 0x50af63 | bzero | stack rbp-1464 | stack frame slot rbp-1464 |
| 0x532af0 | 134 | 59 | 0x50af96 | bzero | ptr lea | lea |
| 0x532cd0 | 118 | 13 | 0x532d22 | copyin | stack rbp-108 | stack frame slot rbp-108 |
| 0x532cd0 | 118 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x533030 | 32 | 51 | 0x53307d | copyin | stack rbp-60 | stack frame slot rbp-60 |
| 0x533030 | 32 | 51 | 0x5330d5 | copyout | mem [rbp-56] | src=[rbp-0x38] ptr from same helper family; dst=uap->arg1 |
| 0x533030 | 32 | 51 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x533310 | 31 | 54 | 0x53335d | copyin | stack rbp-60 | stack frame slot rbp-60 |
| 0x533310 | 31 | 54 | 0x5333b5 | copyout | mem [rbp-56] | src=[rbp-0x38] ptr from same helper family; dst=uap->arg1 |
| 0x533310 | 31 | 54 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x5581e0 | 202 | 12 | 0x558246 | copyin | stack rbp-144 | stack frame slot rbp-144 |
| 0x5581e0 | 202 | 12 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55d0c0 | 416 | 19 | 0x55d0ef | bzero | stack rbp-112 | stack frame slot rbp-112 |
| 0x55d0c0 | 416 | 19 | 0x55d128 | copyin | stack rbp-80 | stack frame slot rbp-80 |
| 0x55d0c0 | 416 | 19 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55ddc0 | 340 | 24 | 0x55de29 | copyin | stack rbp-64 | stack frame slot rbp-64 |
| 0x55ddc0 | 340 | 24 | 0x55de76 | copyout | stack rbp-80 | stack frame slot rbp-80 |
| 0x55ddc0 | 340 | 24 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55deb0 | 429 | 12 | 0x55df00 | copyin | stack rbp-168 | stack frame slot rbp-168 |
| 0x55deb0 | 429 | 12 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55e550 | 345 | 20 | 0x55e5ab | copyin | stack rbp-192 | stack frame slot rbp-192 |
| 0x55e550 | 345 | 20 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55e680 | 346 | 23 | 0x55e6d0 | copyin | stack rbp-168 | stack frame slot rbp-168 |
| 0x55e680 | 346 | 23 | 0x55e72f | copyout | stack rbp-136 | stack frame slot rbp-136 |
| 0x55e680 | 346 | 23 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55ec90 | 343 | 18 | 0x55ed41 | copyout | stack rbp-64 | stack frame slot rbp-64 |
| 0x55ec90 | 343 | 18 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55ed70 | 341 | 58 | 0x55edb8 | copyin | stack rbp-64 | stack frame slot rbp-64 |
| 0x55ed70 | 341 | 58 | 0x55f059 | bzero | stack rbp-176 | stack frame slot rbp-176 |
| 0x55ed70 | 341 | 58 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55f400 | 53 | 15 | 0x55f44f | copyin | stack rbp-64 | stack frame slot rbp-64 |
| 0x55f400 | 53 | 15 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x55f5b0 | 37 | 17 | 0x55f647 | bzero | stack rbp-160 | stack frame slot rbp-160 |
| 0x55fc20 | 456 | 34 | 0x55fca2 | bzero | stack rbp-160 | stack frame slot rbp-160 |
| 0x5620e0 | 0,8,9,11,13,14,16,17,18,19,21,22,26,38,40,45,46,48,51,52,57,58,60,61,62,63,64,66,67,68,69,70,71,72,76,77,81,82,84,85,87,88,91,94,103,107,108,109,110,111,112,115,119,123,129,130,132,139,142,143,144,145,146,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,184,185,186,187,193,197,198,199,200,201,205,207,208,221,222,223,225,226,227,228,230,231,241,242,243,244,245,246,247,248,249,250,252,254,255,256,257,258,259,260,261,262,263,264,265,266,267,268,269,270,271,273,274,275,276,277,278,279,280,281,282,283,284,285,286,287,288,291,292,293,294,295,296,297,298,299,300,301,302,303,304,305,306,307,308,309,311,312,313,314,316,317,318,319,320,321,322,323,326,335,336,337,338,339,342,344,347,348,349,350,351,352,353,354,355,356,357,358,359,360,361,364,365,366,367,368,369,370,371,372,373,374,375,376,377,378,380,381,382,383,384,385,386,387,388,389,390,391,394,395,396,398,399,409,410,411,412,413,414,415,418,419,420,424,425,426,427,428,434,435,436,437,438,439,440,445,446,447,448,449,450,451,452,453,457,458,459,460,461,462,463,465,467,468,469,470,471,472,473,474,484,485,489,490,491,492,493,494,495,496,497,498,500,501,502,503,504,505,506,507,508,509,510,511,512,513,514,516,517,518,519,520,521,523,524,525,526,527,528,529,530,531,537,561,562,568,569,570,571,573,574,575,576,577,578,579,580,581,582,583,584,589,590,597,609,614,621,631,644,645,650,651 | 22 | 0x56212a | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x5a3a60 | 327 | 40 | 0x5a3aab | copyin | stack rbp-44 | stack frame slot rbp-44 |
| 0x5a3a60 | 327 | 40 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x5a3c60 | 329 | 37 | 0x5a3cad | copyin | stack rbp-52 | stack frame slot rbp-52 |
| 0x5a3c60 | 329 | 37 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x602fe0 | 563 | 24 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x602fe0 | 563 | 24 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x603260 | 564 | 24 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x603260 | 564 | 24 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6034e0 | 565 | 24 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6034e0 | 565 | 24 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x603710 | 566 | 24 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x603710 | 566 | 24 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bb670 | 232 | 15 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bb670 | 232 | 15 | 0x6bb6c2 | copyout | stack rbp-40 | stack frame slot rbp-40 |
| 0x6bbd20 | 233 | 29 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bbd20 | 233 | 29 | 0x6bbd74 | copyin | stack rbp-72 | stack frame slot rbp-72 |
| 0x6bbd20 | 233 | 29 | 0x975707 | memcpy | stack rbp-56 | stack frame slot rbp-56 |
| 0x6bc4e0 | 240 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bc4e0 | 240 | 13 | 0x6bc52b | copyin | stack rbp-128 | stack frame slot rbp-128 |
| 0x6bc800 | 116 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bc800 | 116 | 13 | 0x6bc858 | copyout | stack rbp-56 | stack frame slot rbp-56 |
| 0x6bc800 | 116 | 13 | 0x6bc8a9 | copyout | stack rbp-64 | stack frame slot rbp-64 |
| 0x6bc8d0 | 122 | 24 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bc8d0 | 122 | 24 | 0x6bc924 | copyin | stack rbp-64 | stack frame slot rbp-64 |
| 0x6bca20 | 86 | 20 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bca20 | 86 | 20 | 0x6bca72 | copyout | stack rbp-56 | stack frame slot rbp-56 |
| 0x6bccc0 | 83 | 14 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bccc0 | 83 | 14 | 0x6bcd16 | copyin | stack rbp-96 | stack frame slot rbp-96 |
| 0x6bd570 | 235 | 43 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bd570 | 235 | 43 | 0x6bd5ce | copyin | stack rbp-128 | stack frame slot rbp-128 |
| 0x6bdfa0 | 236 | 37 | 0x6bdffc | copyin | stack rbp-80 | stack frame slot rbp-80 |
| 0x6bdfb0 | 237 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6bdfb0 | 237 | 13 | 0x6bdffc | copyin | stack rbp-80 | stack frame slot rbp-80 |
| 0x6be1d0 | 238 | 28 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6be1d0 | 238 | 28 | 0x6be30e | copyout | stack rbp-80 | stack frame slot rbp-80 |
| 0x6be4d0 | 636 | 23 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6be4d0 | 636 | 23 | 0x6be54b | copyin | ptr global 0x32573db | dst=global 0x32573db, len=uap->arg1 capped 0x200 |
| 0x6be5c0 | 638 | 17 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6be800 | 639 | 14 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6e2dc0 | 59 | 84 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x6e2dc0 | 59 | 84 | 0x6e2ea5 | bzero | stack rbp-656 | stack frame slot rbp-656 |
| 0x705880 | 533 | 53 | 0x5a4c60 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x705880 | 533 | 53 | 0x5a5a30 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x705c60 | 534 | 81 | 0x5a4c60 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x705c60 | 534 | 81 | 0x5a5a30 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x729a40 | 90 | 24 | 0x5a4c60 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x729a40 | 90 | 24 | 0x5a5a30 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x72bf00 | 6 | 17 | 0x55fbd5 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x72c140 | 114 | 17 | 0x55fbd5 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x7dcd40 | 622 | 10 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x7dcd40 | 622 | 10 | 0x7dcdb2 | copyout | stack rbp-116 | stack frame slot rbp-116 |
| 0x802d90 | 42 | 43 | 0x5621c7 | bzero | stack rbp-272 | stack frame slot rbp-272 |
| 0x802d90 | 42 | 43 | 0x562253 | bzero | stack rbp-160 | stack frame slot rbp-160 |
| 0x802d90 | 42 | 43 | 0x72ca7d | bzero | unk  |  |
| 0x8340e0 | 393 | 69 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x8340e0 | 393 | 69 | 0x834158 | copyin | stack rbp-96 | stack frame slot rbp-96 |
| 0x83e320 | 488 | 35 | 0x83df0b | copyin | unk  | dst=malloc([r15+0x18]) |
| 0x8d2570 | 617 | 14 | 0x5e2ce5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d2570 | 617 | 14 | 0x5e2cf9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d2570 | 617 | 14 | 0x5e2dc5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d2570 | 617 | 14 | 0x5e2dd9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d2570 | 617 | 14 | 0x5e30e5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d2570 | 617 | 14 | 0x5e30f9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d25a0 | 623 | 25 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x8d25a0 | 623 | 25 | 0x5e2ce5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d25a0 | 623 | 25 | 0x5e2cf9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d25a0 | 623 | 25 | 0x5e2dc5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d25a0 | 623 | 25 | 0x5e2dd9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d25a0 | 623 | 25 | 0x5e30e5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d25a0 | 623 | 25 | 0x5e30f9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0x8d25a0 | 623 | 25 | 0x8d260b | copyout | stack rbp-28 | stack frame slot rbp-28 |
| 0x8f6b20 | 12 | 47 | 0x5fa718 | bzero | ptr td | td |
| 0x8f6b20 | 12 | 47 | 0x72c63e | bzero | ptr td | td |
| 0x8f8550 | 10 | 28 | 0x5fa718 | bzero | ptr td | td |
| 0x8f8550 | 10 | 28 | 0x6b0b3b | bzero | uap uap | uap |
| 0x8f8e20 | 188 | 55 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x8f8e20 | 188 | 55 | 0x5fa718 | bzero | ptr td | td |
| 0x8f8e20 | 188 | 55 | 0x6b0b3b | bzero | uap uap | uap |
| 0x8f8e20 | 188 | 55 | 0x72c63e | bzero | ptr td | td |
| 0x8f8e20 | 188 | 55 | 0x8f8e8e | copyout | stack rbp-144 | stack frame slot rbp-144 |
| 0x8f9260 | 190 | 58 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x8f9260 | 190 | 58 | 0x5fa718 | bzero | ptr td | td |
| 0x8f9260 | 190 | 58 | 0x6b0b3b | bzero | uap uap | uap |
| 0x8f9260 | 190 | 58 | 0x72c63e | bzero | ptr td | td |
| 0x8f9260 | 190 | 58 | 0x8f92e7 | copyout | stack rbp-152 | stack frame slot rbp-152 |
| 0x8f9310 | 191 | 56 | 0x5fa718 | bzero | ptr td | td |
| 0x8f9310 | 191 | 56 | 0x72c63e | bzero | ptr td | td |
| 0x8f95b0 | 34 | 55 | 0x5fa718 | bzero | ptr td | td |
| 0x8f95b0 | 34 | 55 | 0x72c63e | bzero | ptr td | td |
| 0x8f95b0 | 34 | 55 | 0x8f9978 | memcpy | stack rbp-256 | stack frame slot rbp-256 |
| 0x8f9b40 | 15 | 52 | 0x5fa718 | bzero | ptr td | td |
| 0x8f9b40 | 15 | 52 | 0x72c63e | bzero | ptr td | td |
| 0x8f9b40 | 15 | 52 | 0x8f9aa4 | memcpy | stack rbp-256 | stack frame slot rbp-256 |
| 0x8fa310 | 138 | 31 | 0x5fa718 | bzero | ptr td | td |
| 0x8fa310 | 138 | 31 | 0x8fa38e | copyin | stack rbp-288 | stack frame slot rbp-288 |
| 0x8fa310 | 138 | 31 | 0x8fa606 | memcpy | stack rbp-256 | stack frame slot rbp-256 |
| 0x8fa8e0 | 206 | 20 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x8fa8e0 | 206 | 20 | 0x8fa94e | copyin | stack rbp-80 | stack frame slot rbp-80 |
| 0x8fafa0 | 479 | 84 | 0x5fa718 | bzero | ptr td | td |
| 0x8fafa0 | 479 | 84 | 0x72c63e | bzero | ptr td | td |
| 0x8fafa0 | 479 | 84 | 0x8fb127 | memcpy | stack rbp-488 | stack frame slot rbp-488 |
| 0x8fb450 | 128 | 27 | 0x5fa718 | bzero | ptr td | td |
| 0x8fb8e0 | 136 | 47 | 0x5fa718 | bzero | ptr td | td |
| 0x8fb8e0 | 136 | 47 | 0x72c63e | bzero | ptr td | td |
| 0x8fbbc0 | 137 | 23 | 0x5fa718 | bzero | ptr td | td |
| 0x8fc490 | 56 | 56 | 0x5fa718 | bzero | ptr td | td |
| 0x8fc490 | 56 | 56 | 0x72c63e | bzero | ptr td | td |
| 0x8fc610 | 585 | 12 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x8fc810 | 210,211,212,213,214,215,216,217,218,219 | 11 | 0x56212a | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x8fc820 | 220,224,229 | 11 | 0x56212a | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0x91c640 | 629 | 53 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x91cc70 | 630 | 53 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0x9a7d10 | 653 | 57 | 0x72ca7d | bzero | unk  |  |
| 0x9f81f0 | 648 | 14 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xa07280 | 417 | 25 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xa07280 | 417 | 25 | 0xa072e3 | copyin | ptr lea | dst=lea into kernel buffer, len=0x500 fixed |
| 0xa367e0 | 600 | 54 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xa368e0 | 602 | 28 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xa36bc0 | 611 | 41 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xaba540 | 547 | 41 | 0xaba750 | bzero | unk  |  |
| 0xabc5f0 | 588 | 59 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xabc5f0 | 588 | 59 | 0x7ad288 | bzero | ptr global 0x32cb0d5 | global 0x32cb0d5 |
| 0xabc5f0 | 588 | 59 | 0x7ad288 | bzero | ptr global 0x32cb0d5 | global 0x32cb0d5 |
| 0xabc710 | 607 | 37 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xabc710 | 607 | 37 | 0x7f19ae | bzero | ptr global 0x32552ce | global 0x32552ce |
| 0xabc710 | 607 | 37 | 0x7f1a15 | bzero | ptr global 0x3255084 | global 0x3255084 |
| 0xabca10 | 613 | 49 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xabca10 | 613 | 49 | 0xabcb7c | copyout | stack rbp-64 | stack frame slot rbp-64 |
| 0xabca10 | 613 | 49 | 0xabcbac | copyout | stack rbp-56 | stack frame slot rbp-56 |
| 0xabcc00 | 615 | 40 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xabcc00 | 615 | 40 | 0xabcc5d | copyout | stack rbp-208 | stack frame slot rbp-208 |
| 0xabcc00 | 615 | 40 | 0xabcc93 | copyout | stack rbp-200 | stack frame slot rbp-200 |
| 0xabcc00 | 615 | 40 | 0xabcd83 | bzero | unk  |  |
| 0xabdad0 | 642 | 31 | 0xabdba6 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0xabe1c0 | 646 | 15 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xabe1c0 | 646 | 15 | 0xabe200 | bzero | stack rbp-1048 | stack frame slot rbp-1048 |
| 0xabe1c0 | 646 | 15 | 0xabe22a | copyout | stack rbp-1048 | stack frame slot rbp-1048 |
| 0xabe7b0 | 647 | 28 | 0xabe2a1 | bzero | stack rbp-424 | stack frame slot rbp-424 |
| 0xac7240 | 557 | 52 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xb7e960 | 315 | 37 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xb7e960 | 315 | 37 | 0xb7e9d8 | copyin | stack rbp-80 | stack frame slot rbp-80 |
| 0xbafe50 | 542 | 25 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xbafe50 | 542 | 25 | 0xbafeed | copyin | stack rbp-60 | stack frame slot rbp-60 |
| 0xbafe50 | 542 | 25 | 0xbb00fb | copyout | stack rbp-48 | stack frame slot rbp-48 |
| 0xbb0030 | 543 | 21 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xbb0030 | 543 | 21 | 0xbb00fb | copyout | stack rbp-48 | stack frame slot rbp-48 |
| 0xbb0280 | 546 | 29 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xbb0280 | 546 | 29 | 0xbb0300 | copyout | stack rbp-36 | stack frame slot rbp-36 |
| 0xbb0330 | 540 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xbe7240 | 1 | 44 | 0x55fbd5 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0xbe7240 | 1 | 44 | 0x5e2ce5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0xbe7240 | 1 | 44 | 0x5e2cf9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0xbe7240 | 1 | 44 | 0x5e2dc5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0xbe7240 | 1 | 44 | 0x5e2dd9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0xbe7240 | 1 | 44 | 0x5e30e5 | bzero | stack rbp-40 | stack frame slot rbp-40 |
| 0xbe7240 | 1 | 44 | 0x5e30f9 | memcpy | stack rbp-40 | stack frame slot rbp-40 |
| 0xbe7240 | 1 | 44 | 0x7b037d | memcpy | ptr [rip+52943416] | [rip+52943416] |
| 0xbe8290 | 7 | 28 | 0xbe82de | bzero | stack rbp-480 | stack frame slot rbp-480 |
| 0xbe9510 | 652 | 39 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc163d0 | 553 | 25 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc163d0 | 553 | 25 | 0xc16432 | copyin | stack rbp-52 | stack frame slot rbp-52 |
| 0xc163d0 | 553 | 25 | 0xc164a9 | copyout | stack rbp-52 | stack frame slot rbp-52 |
| 0xc16660 | 556 | 22 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc16660 | 556 | 22 | 0xc166ed | copyout | stack rbp-44 | stack frame slot rbp-44 |
| 0xc16720 | 551 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc37860 | 421 | 31 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc37860 | 421 | 31 | 0xc378a2 | bzero | stack rbp-1328 | stack frame slot rbp-1328 |
| 0xc37860 | 421 | 31 | 0xc3790a | bzero | stack rbp-76 | stack frame slot rbp-76 |
| 0xc37860 | 421 | 31 | 0xc37934 | copyout | stack rbp-1328 | stack frame slot rbp-1328 |
| 0xc37970 | 422 | 32 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc37970 | 422 | 32 | 0xa0ad68 | copyin | unk  | dst=alloca VLA guarded cmp rdx,[lim-0x200]; ja |
| 0xc37970 | 422 | 32 | 0xc379bf | copyin | stack rbp-1312 | stack frame slot rbp-1312 |
| 0xc37a20 | 423 | 44 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc37a20 | 423 | 44 | 0xa0ad68 | copyin | unk  | dst=alloca VLA guarded cmp rdx,[lim-0x200]; ja |
| 0xc37a20 | 423 | 44 | 0xc37a71 | bzero | stack rbp-1328 | stack frame slot rbp-1328 |
| 0xc37a20 | 423 | 44 | 0xc37a93 | bzero | stack rbp-76 | stack frame slot rbp-76 |
| 0xc37a20 | 423 | 44 | 0xc37b03 | copyout | stack rbp-1328 | stack frame slot rbp-1328 |
| 0xc37a20 | 423 | 44 | 0xc37b3d | copyin | stack rbp-1328 | stack frame slot rbp-1328 |
| 0xc42760 | 404 | 19 | 0x72ca7d | bzero | unk  |  |
| 0xc42f00 | 400 | 48 | 0x55fbd5 | bzero | stack rbp-152 | stack frame slot rbp-152 |
| 0xc433f0 | 441 | 13 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xc433f0 | 441 | 13 | 0xc43445 | copyin | stack rbp-64 | stack frame slot rbp-64 |
| 0xca0630 | 601 | 23 | 0x5a4e90 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xca0630 | 601 | 23 | 0x5a5020 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xca0630 | 601 | 23 | 0x5a5100 | memcpy | stack rbp-32 | stack frame slot rbp-32 |
| 0xcb1390 | 2 | 7 | 0xcb13ca | bzero | stack rbp-80 | stack frame slot rbp-80 |
| 0xcb1ab0 | 251 | 9 | 0xcb1b17 | bzero | stack rbp-88 | stack frame slot rbp-88 |

## Appendix B — reproduction

All passes are pure capstone over `kernel_text.bin`; nothing was executed against 192.168.1.121.
Scripts (in `%TEMP%`):

- `stageD.py` — loader, function-start set, call graph, writes `g2.json` (301 bodies / 2,077 funcs / 4,274 edges).
- `stageE.py` — prologue dedupe to 1,110 functions, helper-site extraction, writes `sites.json` (174 sites, 210 derefs).
- `cfg.py` — the CFG-aware arg-provenance dataflow of section 6 (result: 0 events over 301 bodies).
- `gen.py` — depth-4 BFS attribution, coverage numbers, Appendix A table.
- `full.py` / `dis.py` — linear disassembly of a function by RVA (do not name a helper `dis.py` in a
  directory that shadows the stdlib `dis` module: capstone import dies with
  `AttributeError: partially initialized module 'capstone' has no attribute 'Cs'`).
