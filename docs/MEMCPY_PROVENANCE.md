# MEMCPY_PROVENANCE

Static provenance of every call site of the unchecked `memcpy` at **RVA 0x2590b0** in the PS5
13.60 kernel `.text`. Everything below is derived from the dump alone; no code was run on any
console and no network target was contacted.

---
## 0. Artefact

| item | value |
|---|---|
| file | `docs/dumps_13.60/kernel_text.bin` |
| size | 15,132,096 bytes (0x0E6E5C0) |
| base VA | 0xffffffff8a9c0000 |
| mapping | **file offset == RVA** |
| syscall table | `docs/dumps_13.60/sysent_index.json`, 679 entries |

All 679 `sy_call` values are full 64-bit VAs of 5-byte `E9 rel32` thunks; subtract 0xffffffff8a9c0000,
and every one of the 679 offsets decodes as a `jmp` whose target is again a plausible x86-64
function prologue. The thunks resolve to **301 distinct handler bodies**, every one landing on an
instruction boundary of the swept stream. That is the evidence for `file offset == RVA` and it is
also the ground truth for the reachability model in 3.6.

---
## 1. Correction: the RVA in the brief is wrong

The brief names VA 0xffffffff8ac190b0 and calls its RVA 0xc190b0. It is not:

<code>
  0xffffffff8ac190b0  (target VA)
- 0xffffffff8a9c0000  (image base)
------------------
  0x00000000002590b0  (RVA)
</code>

So RVA = **0x2590b0**, VA = 0xffffffff8ac190b0. Two independent checks:
1. the bytes at 0x2590b0 are exactly the function described in the brief (`55 48 89 e5 49 89 fa` ...
   ending `f3 a4 5d c3`), and
2. scanning the whole image for `E8 rel32` edges resolving to 0xc190b0 yields **zero** hits; the
   same scan against 0x2590b0 yields 3,418.

Nothing is called from 0xc190b0; something very busy is called at 0x2590b0. Every RVA below is
relative to 0xffffffff8a9c0000; a VA is 0xffffffff8a9c0000 + RVA.

---
## 2. What the gadget actually validates

Verbatim bytes and decode at 0x2590b0:

<code>
2590b0  55              push rbp
2590b1  4889e5          mov  rbp, rsp
2590b4  4989fa          mov  r10, rdi          ; r10 = dst
2590b7  4901d2          add  r10, rdx          ; r10 = dst + len
2590ba  7219            jb   2590d5            ; 64-bit wrap -> #UD stub
2590bc  4939e2          cmp  r10, rsp
2590bf  7619            jbe  2590da            ; dst+len <= rsp      -> copy
2590c1  4c8d5510        lea  r10, [rbp+0x10]
2590c5  4c39d7          cmp  rdi, r10
2590c8  7d10            jge  2590da            ; dst >= rbp+0x10     -> copy
2590ca  4889ff          mov  rdi, rdi
2590cd  4889d6          mov  rsi, rdx
2590d0  e8fbfeffff      call 258fd0            ; fail stub #1 (ud2)
2590d5  e806ffffff      call 258fe0            ; fail stub #2 (ud2)
2590da  4889f8          mov  rax, rdi          ; return dst
2590dd  4889d1          mov  rcx, rdx
2590e0  48c1e903        shr  rcx, 3
2590e4  fc              cld
2590e5  f348a5          rep movsq
2590e8  4889d1          mov  rcx, rdx
2590eb  4883e107        and  rcx, 7
2590ef  f3a4            rep movsb
2590f1  5d              pop  rbp
2590f2  c3              ret
</code>

Both failure arms are `push rbp; mov rbp,rsp; ud2; pop rbp; ret` stubs at 0x258fd0 and 0x258fe0)
-- they trap, they are not a fallback path.

The guard checks **exactly two things**: 64-bit wraparound of `dst+len`, and whether the
destination range overlaps the live stack. It does **not**:

* test whether `rdi` is a user address (there is no canonical/UACCESS_MAX comparison),
* test whether `rsi` is a user address,
* test general src/dst overlap (only the stack window),
* contain `stac`/`clac` anywhere in or around the function, so a real user pointer with AC=0
  faults instead of copying -- this is a kernel-to-kernel primitive by construction,
* check `rdx` against any destination capacity -- there is no length field consulted, ever.

Therefore: a user-influenced **rdi** is an arbitrary kernel write of attacker-chosen length with
no destination-size validation; a user-influenced **rdx** is an overflow of whatever object rdi
points at; a user-influenced **rsi** is a read/info-leak primitive (and normally a fault).

Neighbouring family emitted from the same header, useful because it shows the compiler inlined
all of them with the same blind trust:

<code>
258ff0  memset(rdi, rsi)         rep stosq, length in rsi
259040  bzero fixed 0x4000
259080  bcmp                     repe cmpsq
2590b0  memcpy                   <-- target
259100  page copy 0x4000         rsi -> rdi, movnti
</code>

---
## 3. Method

### 3.1 Decode

Capstone 5.0.7, x86-64, `skipdata=True`, one linear sweep over all 15,132,096 bytes: **6,134,149
instructions**, mean length 2.47 bytes, 100.0% coverage to EOF. `skipdata` is not optional here --
the image has data islands (jump tables, string tables, the magic-number switch at 0x9fd1d0) that
a strict sweep desynchronises on permanently.

### 3.2 Call-site discovery

Direct edges are taken from the decoded stream: 199,857 `E8 rel32` and 56,671 `E9 rel32`. Of the
256,528 edges, **254,658 land inside the image on an instruction start**; the rest leave the image
or land mid-instruction and are dropped.

Result: **3418 sites -- 3384 `call` and 34 `jmp`**. The 34 `jmp` are tail calls and four of them are the interesting ones, because the copy happens with the enclosing functions registers still live. This is one call per ~4.4 KB of `.text`.

### 3.3 Enclosing-function model (two of them, deliberately)

**Boundary model** (`func_rva`): a boundary is (a) the instruction after an unconditional
terminator (`C3 C2 E9 EB F4 0F0B`, plus `FF /4` and `FF /5` in memory form), or (b) an `E8`/`E9`
target whose first bytes match one of the compiler prologue signatures (`55 48 89 e5`, `F3 0F 1E FA`,
`48 83 EC`, `48 81 EC`, `48 89 5C/6C/7C 24`, `48 8D 64 24`, `41 54/55/56/57`, `53/56/57`, `55`), or
(c) a sysent handler body start.

> **Pitfall, recorded because it cost a full re-run.** `0xCC` is 2,458,216 of the 6,134,149
> instruction starts (40%) -- it is `int3` alignment filler, not code. Treating `0xCC` as a
> terminator makes the preceding-instruction rule fire on 46% of all instructions (2,834,852
> boundaries) and destroys the model. With `CC 90 0F1F 6690` classified as *filler* the numbers
> become sane: 150,486 unconditional terminators, 408,844 preceding-instruction boundaries,
> **408,961 boundaries total**.

**Seed-ownership model** (`owner_idx`): the owner of an address is the nearest preceding `E8` target.
This is what the reverse call graph uses, because it is stable across data islands. `E9` targets are
deliberately **not** seeds: they include every jump-table entry in the image, and seeding on them
fuses unrelated functions together. That is the real mechanism behind the false-positive mode the
brief warns about -- it is `e9` jump tables, not address-range containment.

The two models name the same start for **746 of 3418 sites (21.8%)**. Where they differ the seed owner is usually an interior E8 target (a nested entry point or an ICF-merged tail) and the boundary start is the true entry -- or the reverse, after a data island re-synchronises. Both columns are in the appendix; section 6 does not depend on either column alone, every candidate there is anchored by hand.

### 3.4 Backward dataflow

For each site the enclosing window is disassembled from a genuine function start (seed owner
first, boundary start second, 400-instruction cap) and a backward walk runs from the site:

* `mov/add/sub/lea/and/or/xor/shl/shr/imul/movsx/movzx/inc/dec` with a resolvable source -> the
  definition becomes the new root; `lea` records `base + index*scale + disp`.
* a call clobbers the caller-saved set -> class **CALLRET** (return value), walk stops rather than
  guessing.
* a memory read with no incoming store in the walk -> **DEREF_** of whatever pointer the base
  register holds, recursively; the number of `DEREF_` prefixes is the dereference depth.
* reaching the function start with the value live in an argument register -> **USERARG**.
* `[reg+disp]` where `reg` traces to an argument register -> **USERFIELD** (disp recorded).
* a stack slot established in the prologue -> **STACK** / **STACKADDR**.
* anything else -> **UNKNOWN**.

**No site is unclassified.** Unknown is a class, not a gap: 3,418 of 3,418 sites produced a class
with zero decode failures and zero window-alignment failures.

**Level-2 pass.** For interesting destinations the enclosing functions callers are re-sliced,
resolving the **source register of the `mov` that fed the copy** rather than `rdi` itself. This
matters: a `jmp` tail site has no `mov rdi` in its own body, and the first version of this pass
produced nonsense by assuming one. The one-hop caller view is what converts `USERARG` into a
verdict -- `memcpy(arg2,...)` is harmless when every caller passes `lea [rbp-0xc0]` and dangerous
when a caller passes a field of a user structure.

### 3.5 Class vocabulary

`STACK`, `STACKADDR` (address of a local), `STACKVAL` (value loaded from a local), `GLOBAL`,
`CONST`, `TLS`, `USERARG` (raw syscall argument), `USERFIELD` (`[argN+disp]`), `USER_PTR`
(arithmetic on a raw argument), the `DEREF_`-prefixed variants at each pointer hop, `CALLRET`
(return value of a call), `DERIVED` (arithmetic on a non-storage source) and `UNKNOWN`.

### 3.6 Reachability

Reverse call graph: nodes = the 17,809 distinct `E8` targets, edges = 100,411, plus the 301 handler
bodies as roots. For each site `owner_idx` is walked up the reverse edges and the reported
`syscall@depth` pairs are the sysent numbers that reach it within depth 6. Depth 6 is a reporting
cap, not a claim that nothing further away matters -- past 6 hops "reachable from this syscall"
stops being useful for triage.

---
## 4. Coverage

| metric | value |
|---|---:|
| bytes decoded | 15,132,096 (100%) |
| instructions | 6,134,149 |
| in-image direct edges landing on instruction starts | 254,658 |
| **call sites found** | **3418** |
| of which `call` / `jmp` | 3384 / 34 |
| distinct owner functions (seed model) | 1524 |
| distinct enclosing functions (boundary model) | 2527 |
| sites whose window decoded and aligned | 3418 (100%) |
| rdi resolved to concrete storage | 1401 |
| rdi is a call result (indirect) | 1044 |
| **rdi user-flavoured** | **175** |
| rdi unresolved | 798 |
| sites inside a sysent handler body | 0 |
| **reachable from a handler, depth <= 6** | **579** |
| ... of those, user-flavoured rdi | **23** |
| ... of those, rdi AND rdx user-flavoured | 4 |
| constant compile-time length | 2452 (71.7%) |
| ... constant length > 0x400 | 126 |

Depth histogram of the 579 reachable sites: depth 1: 62, depth 2: 102, depth 3: 78, depth 4: 119, depth 5: 103, depth 6: 115.

**Zero sites are inside a sysent handler body.** Every reachable site is at least one call deep; the
shortest routes are depth 1 (handler -> helper -> memcpy). There is no single-hop
`memcpy(handler_argument, ...)` anywhere in this image.

---
## 5. Where the destinations come from

rdi, all 3418 sites:

| class | sites | share |
|---|---:|---:|
| STACKADDR | 917 | 26.8% |
| CALLRET | 521 | 15.2% |
| DEREF_CALLRET | 492 | 14.4% |
| DERIVED | 355 | 10.4% |
| UNKNOWN | 233 | 6.8% |
| GLOBAL | 204 | 6.0% |
| DEREF_UNKNOWN | 179 | 5.2% |
| STACK | 147 | 4.3% |
| USERARG | 99 | 2.9% |
| DEREF_STACK | 56 | 1.6% |
| USERFIELD | 55 | 1.6% |
| DEREF_GLOBAL | 32 | 0.9% |
| DEREF_DEREF_CALLRET | 29 | 0.8% |
| _other (14 classes)_ | 99 | 2.9% |

Grouped: **1401 resolved to concrete storage**, **1044 are call results**, **175 user-flavoured**, **798 unresolved**. Stack dominates: `STACKADDR` 917 + `STACK` 147 + the other stack forms are ~32% of the image, i.e. this routine is overwhelmingly copying into local buffers, which is what a compiler intrinsic should look like.

rsi, all 3418 sites:

| class | sites | share |
|---|---:|---:|
| CALLRET | 650 | 19.0% |
| STACKADDR | 497 | 14.5% |
| DERIVED | 465 | 13.6% |
| GLOBAL | 440 | 12.9% |
| DEREF_CALLRET | 369 | 10.8% |
| UNKNOWN | 263 | 7.7% |
| STACK | 186 | 5.4% |
| DEREF_UNKNOWN | 147 | 4.3% |
| USERARG | 128 | 3.7% |
| DEREF_STACK | 81 | 2.4% |
| USERFIELD | 54 | 1.6% |
| DEREF_DEREF_CALLRET | 26 | 0.8% |
| DEREF_GLOBAL | 25 | 0.7% |
| _other (14 classes)_ | 87 | 2.5% |

rdx, all 3418 sites:

| class | sites | share |
|---|---:|---:|
| CONST | 2452 | 71.7% |
| CALLRET | 249 | 7.3% |
| DERIVED | 220 | 6.4% |
| UNKNOWN | 118 | 3.5% |
| DEREF_CALLRET | 99 | 2.9% |
| STACK | 82 | 2.4% |
| USERARG | 72 | 2.1% |
| DEREF_UNKNOWN | 35 | 1.0% |
| DEREF_STACK | 21 | 0.6% |
| DEREF_DEREF_CALLRET | 17 | 0.5% |
| DEREF_DERIVED | 12 | 0.4% |
| USERFIELD | 8 | 0.2% |
| DEREF_DEREF_UNKNOWN | 8 | 0.2% |
| _other (8 classes)_ | 25 | 0.7% |

**72% of all lengths are compile-time constants**, which removes three quarters of the site space as an overflow primitive: only the destination object is wrong, never the size. The 175 user-flavoured destinations break down as USERARG 99, USERFIELD 55, USER_PTR 16, DEREF_USER_PTR 5 plus deeper DEREF_USER* forms; **23** of them are syscall-reachable.

---
## 6. Candidates

Ranked by *exploitability shape*, not by reachability alone: a user-flavoured destination with a
non-constant length from a shallow syscall is worth more than a deep site with a fixed length.
Every chain below was printed from a real function start and read by hand; the anchoring matters
because the linear sweep is locally wrong inside data regions (see C4).

**72** sites in the image have both a user-flavoured destination and a non-constant length, and **7** of them are syscall-reachable: 0x004ef6e6, 0x00aed19e, 0x004c66f2, 0x00659122, 0x00b32ba6, 0x0070322d, 0x007b00e5. Everything else in this section is a hand-verified example drawn from those two sets.

### C1 -- 0x70322d: `memcpy(arg2+0x20, arg3, arg4)`, no capacity check, syscalls 93/522

<code>
703210  push rbp
703211  mov  rbp, rsp
703214  push r15
703216  push r14
703218  push rbx
703219  push rax
70321a  mov  r15, rsi                 ; r15 = arg2 (object)
70321d  lea  rdi, [rsi + 0x20]        ; dst = arg2 + 0x20
703221  mov  rsi, rdx                 ; src = arg3
703224  mov  rdx, rcx                 ; len = arg4
703227  mov  ebx, r8d                 ; 32-bit extra arg
70322a  mov  r14, rcx
70322d  call 0x2590b0                 ; memcpy(arg2+0x20, arg3, arg4)
703232  movsxd rax, ebx
703235  mov  byte ptr [r15 + 0x38], r14b   ; payload length recorded as a BYTE
703239  lea  rax, [r15 + rax + 0x20]
70323e  mov  qword ptr [r15 + 0xa0], rax   ; end-of-payload pointer
703245  or   byte ptr [r15 + 0x70], 8
70324a  or   byte ptr [r15 + 0x3c], 1
70324f  add  rsp, 8
703253  pop  rbx
703254  pop  r14
703256  pop  r15
703258  pop  rbp
703259  ret
</code>

This is a record builder: fixed header 0x20 bytes, payload inline at +0x20, payload length stored
as a **single byte** at +0x38, end pointer at +0xa0, then two flag bits. Between the prologue and
the call there is **no comparison of arg4 against any capacity field and no branch at all** -- the
twelve instructions are straight-line. The source and the length are the raw arg3/arg4 of the function;
the destination is a fixed offset into a caller-supplied object.

Why this ranks first: the shape `build_record(dst, user_ptr, user_len)` with a byte-sized length
field is exactly how an object-relative linear overflow happens. If `arg4` can exceed the payload
capacity of the allocation behind `arg2`, the copy walks past +0x20+cap into the next object and
the recorded length byte is silently truncated mod 256, so the corruption is not even
self-describing.

Level-2 (all four callers, source register resolved):

| call site | caller | class of arg2 | note |
|---|---|---|---|
| 0x6b4743 | 0x6b3820 | CALLRET | `mov rsi, rax` |
| 0x95a4f8 | 0x95a2c0 | CALLRET | `mov rsi, r13` |
| 0x9c5ab6 | 0x9c55c0 | CONST | `mov rsi, r15` with `xor r15, r15` after the use |
| 0xa875b4 | 0xa87280 | CALLRET | `mov rsi, r14` |

Every caller passes a pointer that came out of a call -- never a stack buffer. So the question is
not "is this a temp" but "what size did the allocator give the object behind arg2", and that is one
more hop up. **Probe syscalls 93 and 522 at depth 6.**

### C2 -- 0x4ef6e6: `memcpy(*(arg2+0x10), src, len)`, syscalls 93/522 at depth 2

<code>
        mov  rax, qword ptr [rsi + 0x10]   ; payload buffer pointer stored in the object
        mov  r12, rdi
        mov  rbx, rsi
        mov  rsi, r14                       ; src
        mov  r14, rdx
        mov  rdx, r15                       ; len
        mov  rdi, rax                       ; dst = *(arg2 + 0x10)
4ef6e6  call 0x2590b0                       ; the seven instructions above it, in order
</code>

The enclosing function (0x4ef290, seed and boundary models agree) opens by unlinking a node from a
hash chain (`mov rcx,[rdi]; cmp rcx,rsi; ... mov rcx,[rcx]; mov [rax],rcx`) and then does an
atomic refcount drop (`lock xadd dword ptr [rbx+0x38], eax`) -- i.e. this is an object-lifecycle
routine, and the copy fills the object payload buffer at +0x10 with `len` bytes supplied by the
caller. There is no size field consulted before the copy.

Depth 2 is the shallowest user-flavoured route in the image: two calls from a sysent handler.

| call site | caller | class of arg2 (level-2) |
|---|---|---|
| 0x4edfec | 0x4ed550 | DEREF_DEREF_STACK (`mov rcx,[rax+104]` after `mov rax,[rbp-360]`) |
| 0x4ee296 | 0x4ed550 | DEREF_DEREF_STACK (`mov rbx,[rax+104]`) |
| 0x4eebea | 0x4eead4 | DEREF_CALLRET |
| 0x4eecc6 | 0x4eead4 | DEREF_DEREF_STACK (`[rcx+104]`) |

Both level-2 classes are "a field of a pointer that came out of a call / a local" -- consistent
with a kernel object fetched by lookup, not with a user pointer. Ranked second because the length is
still caller-controlled and the destination is an interior buffer pointer.

### C3 -- 0x659122: clamped length, huge syscall fan (0, 101-105, ...)

<code>
        mov  rax, qword ptr [rdi + 0xe0]
        cmp  rsi, rdx
        cmovl rdx, rsi
        cmp  rsi, rcx
        cmovl rdx, rsi
        mov  rsi, qword ptr [rbx + 0x400]
        mov  rbx, rdi
        mov  rdi, rax
659122  call 0x2590b0                  ; memcpy(*(obj+0xe0), *(obj+0x400), min(rsi,rdx,rcx))
</code>

Listed for completeness, not as a candidate: the length is clamped by two `cmovl` before the call,
so this is the "correct" pattern in this binary and it shows the compiler does emit checks where the
source had one. Destination is an interior field of the same object the source field belongs to.

### C4 -- 0x9fdc94: `memcpy([[arg3+0xc0]] + r15 - 0x44, ?, 0x25)`, syscall 59 (execve), depth 1

<code>
9fdc83  mov  rax, qword ptr [rdx + 0xc0]
9fdc8a  mov  edx, 0x25
9fdc8f  lea  rdi, [rax + r15 - 0x44]
9fdc94  call 0x2590b0                 ; 37 bytes into *(arg3+0xc0) + r15 - 0x44
</code>

**Attribution warning.** The enclosing-function model puts this inside 0x9fd1d0, and 0x9fd1d0 is a
magic-number dispatch switch (`cmp edi,0x200ff ... lea rax,[rip+...]`) that clearly does not contain
this code; the linear sweep is desynchronised for the ~0x10 bytes before 0x9fdc83 (the instruction
printed immediately before is `test dword ptr [rax-1], ecx`, which is not real code). The four
instructions above are nevertheless contiguous, aligned and semantically coherent, and the `call`
itself is a real `E8` whose target decodes as the memcpy prologue. Treat this as **needs dynamic
confirmation**, not as an established site: if it is real, it is the only depth-1 site inside an
execve path that writes through a pointer field of its third argument with a variable index.

### C5 -- 0xb2b750: two level-2 callers pass derived pointers, depth 1 (341/345/346/417/429/431)

<code>
b2b750  call 0x2590b0     ; memcpy(arg1, src, const)
</code>

Destination class USERARG (`rdi` live at entry), length CONST, depth 1. On its own that is a
caller-supplied scratch buffer, which is normal. What makes it worth listing is the caller mix:

| call site | caller | class of rdi at that caller |
|---|---|---|
| 0x34bb68 | 0x34b950 | DERIVED (`mov rdi,r14; add r14,...`) |
| 0x34c613 | 0x34c350 | DERIVED (`mov rdi,r15` then `add rdi,...`) |
| 0x4f70ca | 0x4f6b70 | STACKADDR (`lea [rbp-1240]`) |
| 0x7a6397 | 0x7a3d80 | STACKADDR (`lea [rbp-376]`) |
| 0xc9e472 / 0xc9e9a9 / 0xc9ea29 | 0xc9e350 | CALLRET |

The two DERIVED callers walk a pointer across a structure; if the walk is over a user-supplied
count and the base is not bounds-checked, the write lands outside the intended field. Chase
0x34b950 and 0x34c350 first.

### C6 -- 0x4a1ec0, the negative control (why level-2 matters)

<code>
4a1ea0  push rbp
4a1ea1  mov  rbp, rsp
4a1ea4  push r15
4a1ea6  push r14
4a1ea8  push r12
4a1eaa  push rbx
4a1eab  mov  rbx, rsi
4a1eae  mov  r14, rdi
4a1eb1  lea  rsi, qword ptr [rdi + 0x230]
4a1eb8  mov  edx, 0x90
4a1ebd  mov  rdi, rbx                  ; dst = arg2
4a1ec0  call 0x2590b0                  ; memcpy(arg2, arg1+0x230, 0x90)
</code>

At the function level this is the scariest signature in the list: destination is a bare argument,
length is a fixed 0x90, source reads +0x230 into the *other* argument -- a textbook struct copy
into caller storage. Every resolved caller passes a stack buffer:

| call site | caller | class of arg2 |
|---|---|---|
| 0x4a1c1f | 0x4a1ba0 | STACKADDR (`lea [rbp-192]`) |
| 0x4a1d85 | 0x4a1d50 | CALLRET |
| 0x537116 | 0x536460 | CALLRET |
| 0x53d89a | 0x53d4d0 | STACKADDR (`lea [rbp-528]`) |
| 0x6bb89e / 0x6bbc4d | 0x6bb6e0 | STACKADDR (`lea [rbp-192]`) |

This is the concrete reason the report carries two attribution models and a level-2 pass: judged
only by the callee this site is a false positive, and any ranking that stops at "rdi == USERARG"
would have put it near the top.

### Also noted

* **0x2c7135** (`jmp` tail call, 34-jump family): `mov rdi,r8; ...; jmp 0x2590b0` -- the copy
  destination is the **fifth** argument, forwarded from the caller. Single level-2 caller 0x9a92f1
  passes `mov r8,[rbp+32]`, i.e. stack. Length 0x20 constant. Syscalls 341/431/547/572/674 at
  depth 3. Fixed-size 32-byte block copy; not an overflow primitive.
* **0x4c66f2** (`jmp` tail): `mov rdi,esi` -- a pointer-sized destination built from a 32-bit
  register without an explicit zero-extend test at the site. Every level-2 caller passes small
  constants in `rsi` (0x28, 2, 0xa, 8, 0), so this is a size/enum, not a pointer; recorded as a
  false positive of the `mov rdi,reg` heuristic.
* **0xaed19e** (`rdi` USERARG, `rdx` USERARG, depth 2, syscall 532) is the only site where both the
  destination *and* the length are raw arguments; its level-2 callers are mostly `mov rdi,0x1`
  constants, which is inconsistent with a pointer argument and suggests the class is an artifact of
  an inlined/ICF-merged body. Worth one manual look at 0xae6f90 and 0xae77a0.

---
## 7. What this rules out

This is the part that is actually proven, and it is worth stating in numbers:

1. **No sysent handler body contains a call to this routine.** 0 of 679 handlers, 0 of 301 distinct
   bodies. There is no single-hop `memcpy(handler_arg, ...)` in the image -- every user-flavoured
   destination is at least one call deep, and the shallowest are depth 1 (62 sites) of which only a
   handful are user-flavoured at all.
2. **72% of all lengths are compile-time constants** (2452 of 3418). For those sites the only attacker-influenceable quantity is *which object* the destination field points at, not the size, so they cannot produce a length-driven overflow; at worst they produce a fixed-size corruption of a wrong object. 126 of the constants exceed 0x400 bytes, so the fixed size is not always small.
3. **3346 of 3418 sites (97.9%) are excluded by the two cheap filters together** -- either the destination is not user-flavoured, or the length is constant. That leaves **72 sites** as the whole population worth manual work; the 7 of them that are also syscall-reachable are listed by RVA at the top of section 6, and every appendix row can be filtered on the two columns.
4. **No destination is a direct user pointer at depth <= 1.** The `USER_PTR` class (16 sites) is
   pointer arithmetic on an argument, and the only depth-1 member (0x9fdc94) is the desynchronised
   execve site. Every other user-flavoured destination is a field of a kernel object (`USERFIELD`),
   which means an attacker who controls it already controls a kernel pointer stored in that object.
5. **rsi being user-flavoured (197 sites) is not, by itself, a leak primitive**: with no stac, rep movsq from a user address with AC=0 raises a fault rather than returning data. It becomes relevant only combined with a caller that has already done stac for its own reasons, which is not visible at these sites.
6. **The function really is the C library primitive, not a bespoke routine.** Its neighbours are
   memset/bzero/bcmp and a 0x4000-byte page copy, all with the same calling convention and the same
   total absence of validation. The lack of a check is a property of this build, not of one caller.

What is *not* ruled out, stated plainly: the three sites C1, C2 and C5 have a caller-controlled
length into an interior field of a kernel object, and this static pass cannot see the allocation
size of those objects. That question needs either the allocator call sites for those object types or
a dynamic run.

---
## 8. Reproduce

Pipeline, all scripts outside the repo (temp dir), all deterministic from the dump:
<code>
stageA.py   capstone sweep -> starts.npy / sizes.npy (6,134,149 instructions)
stageC.py   boundary model + E8/E9 edge scan -> bnd2.npy, func_of2.npy, sites2.json
stageG.py   reverse call graph (E8 targets as seeds) -> owner_e8.npy, handlers2.json
slicer.py   backward slicer: classify_at(insns, pos, reg) -> class/arg/disp/chain
stageD.py   per-site dataflow -> df4.json (3,418 rows: rdi/rsi/rdx + reach)
stageI.py   level-2 caller pass with the correct source register -> cand2.json
gen1.py/gen2.py  this document
</code>

The one input that must not be changed: the base VA 0xffffffff8a9c0000. Every RVA in this document
is worthless without it, and the `0xc190b0` in the original brief is off by 0x9c0000 -- see
section 1.

---
## Appendix A -- every call site

3418 rows, sorted by site RVA. Columns: site (call/jmp to 0x2590b0), kind, owner function (nearest preceding E8 target), rdi class, rsi class, rdx class, syscall reachability as num@depth (max three shown, +n = more).

| site | kind | owner | rdi | rsi | rdx | syscall@depth |
|---|---|---|---|---|---|---|
| 0x0026b850 | JMP | 0x0026b588 | USERARG | USERARG | USERARG | - |
| 0x00272782 | CALL | 0x00272550 | DERIVED | DEREF_UNKNOWN | CONST | - |
| 0x00272a18 | CALL | 0x00272830 | DEREF_UNKNOWN | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x00273157 | CALL | 0x00273100 | STACKADDR | DERIVED | CONST | - |
| 0x002732d7 | CALL | 0x00273280 | STACKADDR | DERIVED | CONST | - |
| 0x002734df | CALL | 0x00273410 | UNKNOWN | CALLRET | DEREF_CALLRET | - |
| 0x00275016 | CALL | 0x00274ec0 | CALLRET | UNKNOWN | CALLRET | - |
| 0x00275cb4 | CALL | 0x00275c10 | DEREF_CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00275cdc | CALL | 0x00275c10 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00276d17 | CALL | 0x00276b70 | DEREF_CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00276f05 | CALL | 0x00276b70 | DEREF_CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x002771cd | CALL | 0x00277030 | STACK | CALLRET | DEREF_CALLRET | - |
| 0x002773a7 | CALL | 0x00277030 | STACK | CALLRET | DEREF_CALLRET | - |
| 0x0027e5f9 | CALL | 0x0027e5b0 | GLOBAL | GLOBAL | CONST | - |
| 0x00287326 | CALL | 0x00286ee0 | STACKADDR | STACKADDR | CONST | 601@6 |
| 0x002874c7 | CALL | 0x00286ee0 | STACKADDR | STACKADDR | CONST | 601@6 |
| 0x00287e92 | CALL | 0x00287ae0 | STACK | GLOBAL | CONST | - |
| 0x00287ea6 | CALL | 0x00287ae0 | STACK | CALLRET | CONST | - |
| 0x002880aa | CALL | 0x00288020 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x002880c1 | CALL | 0x00288020 | DEREF_CALLRET | STACK | CONST | - |
| 0x00288555 | CALL | 0x00288400 | STACKADDR | DEREF_DEREF_UNKNOWN | CONST | - |
| 0x0028863e | CALL | 0x00288400 | STACKADDR | CALLRET | CONST | - |
| 0x002889bb | CALL | 0x002888e0 | STACKADDR | USERARG | CONST | - |
| 0x00288adc | CALL | 0x002889f0 | GLOBAL | CALLRET | CALLRET | 601@4 |
| 0x00288b51 | CALL | 0x002889f0 | CALLRET | GLOBAL | CALLRET | 601@4 |
| 0x00288e09 | CALL | 0x00288bb0 | GLOBAL | CALLRET | CONST | - |
| 0x00288e3f | CALL | 0x00288bb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00289047 | CALL | 0x00288fc0 | GLOBAL | CALLRET | CONST | - |
| 0x00289214 | CALL | 0x00288fc0 | STACK | STACKADDR | CONST | - |
| 0x002895f8 | CALL | 0x00288fc0 | GLOBAL | CALLRET | CONST | - |
| 0x00289889 | CALL | 0x00288fc0 | STACKADDR | CALLRET | CONST | - |
| 0x00289a87 | CALL | 0x00288fc0 | STACKADDR | GLOBAL | CONST | - |
| 0x00289b2d | CALL | 0x00288fc0 | STACKADDR | CALLRET | CONST | - |
| 0x00289b95 | CALL | 0x00288fc0 | STACKADDR | CALLRET | CONST | - |
| 0x00289c1c | CALL | 0x00288fc0 | CALLRET | STACKADDR | CONST | - |
| 0x00289c68 | CALL | 0x00288fc0 | GLOBAL | CALLRET | CONST | - |
| 0x00289c9a | CALL | 0x00288fc0 | STACKADDR | CALLRET | CONST | - |
| 0x00289fc2 | CALL | 0x00288fc0 | GLOBAL | STACKADDR | CONST | - |
| 0x0028b9d8 | CALL | 0x0028b980 | GLOBAL | CALLRET | DERIVED | - |
| 0x0028c13e | CALL | 0x0028b980 | STACKADDR | UNKNOWN | CONST | - |
| 0x0029327a | CALL | 0x00292ee0 | DEREF_CALLRET | CALLRET | CALLRET | 59@4,594@6,607@2+1 |
| 0x002954b0 | CALL | 0x00295370 | DERIVED | CALLRET | CONST | - |
| 0x00295536 | CALL | 0x002954f0 | CALLRET | STACKADDR | CONST | - |
| 0x002955fb | CALL | 0x00295560 | CALLRET | STACKADDR | CONST | - |
| 0x0029562e | CALL | 0x00295560 | CALLRET | STACKADDR | CONST | - |
| 0x002956ae | CALL | 0x00295560 | UNKNOWN | STACKADDR | CONST | - |
| 0x002957c3 | CALL | 0x00295560 | CALLRET | CALLRET | CONST | - |
| 0x002957f7 | CALL | 0x00295560 | CALLRET | CALLRET | CONST | - |
| 0x0029582b | CALL | 0x00295560 | CALLRET | CALLRET | CONST | - |
| 0x0029585f | CALL | 0x00295560 | CALLRET | CALLRET | CONST | - |
| 0x00295a91 | CALL | 0x002959d0 | CALLRET | STACKADDR | CONST | - |
| 0x00295d0e | CALL | 0x00295c30 | CALLRET | STACKADDR | CONST | - |
| 0x00295d49 | CALL | 0x00295c30 | CALLRET | STACKADDR | CONST | - |
| 0x00295d7a | CALL | 0x00295c30 | CALLRET | STACKADDR | CONST | - |
| 0x00295dab | CALL | 0x00295c30 | CALLRET | STACKADDR | CONST | - |
| 0x002961d2 | CALL | 0x00296160 | CALLRET | DERIVED | CONST | - |
| 0x0029623e | CALL | 0x002961e0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x002963db | CALL | 0x00296360 | CALLRET | CALLRET | CALLRET | - |
| 0x00296410 | CALL | 0x00296360 | CALLRET | STACKADDR | CONST | - |
| 0x002964c7 | CALL | 0x00296450 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00296ff7 | CALL | 0x00296f20 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x0029be57 | CALL | 0x0029bae0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0029becf | CALL | 0x0029bae0 | DERIVED | UNKNOWN | CONST | - |
| 0x0029bf77 | CALL | 0x0029bae0 | STACKADDR | DEREF_STACK | DERIVED | - |
| 0x0029bffc | CALL | 0x0029bae0 | DEREF_UNKNOWN | STACKADDR | STACK | - |
| 0x0029c3b8 | CALL | 0x0029c050 | STACK | STACKADDR | DERIVED | - |
| 0x0029c510 | CALL | 0x0029c050 | CALLRET | CALLRET | CONST | - |
| 0x0029c537 | CALL | 0x0029c050 | STACKADDR | STACKADDR | STACK | - |
| 0x0029c565 | CALL | 0x0029c050 | STACK | STACKADDR | DERIVED | - |
| 0x0029c626 | CALL | 0x0029c050 | STACKADDR | STACK | CONST | - |
| 0x0029c640 | CALL | 0x0029c050 | STACKADDR | STACKADDR | STACK | - |
| 0x0029c6c6 | CALL | 0x0029c050 | STACKADDR | STACKADDR | DERIVED | - |
| 0x0029c99a | CALL | 0x0029c050 | CALLRET | CALLRET | CONST | - |
| 0x0029cce2 | CALL | 0x0029cae0 | CALLRET | UNKNOWN | CALLRET | - |
| 0x002a1e91 | CALL | 0x002a16d0 | DERIVED | STACK | CONST | - |
| 0x002a4430 | CALL | 0x002a39e0 | STACKADDR | UNKNOWN | CONST | - |
| 0x002a452f | CALL | 0x002a39e0 | STACKADDR | DERIVED | CONST | - |
| 0x002a4b92 | CALL | 0x002a39e0 | STACK | STACKADDR | CONST | - |
| 0x002a5c2a | CALL | 0x002a55f0 | CALLRET | CALLRET | DERIVED | - |
| 0x002a5c8b | CALL | 0x002a55f0 | UNKNOWN | GLOBAL | DERIVED | - |
| 0x002a5e73 | CALL | 0x002a55f0 | UNKNOWN | STACKADDR | DERIVED | - |
| 0x002a5f09 | CALL | 0x002a55f0 | STACKADDR | STACKADDR | CONST | - |
| 0x002a5f22 | CALL | 0x002a55f0 | CALLRET | STACKADDR | DERIVED | - |
| 0x002a69a4 | CALL | 0x002a6850 | DERIVED | DERIVED | CONST | - |
| 0x002a6a5b | CALL | 0x002a6850 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x002a727e | CALL | 0x002a7220 | CALLRET | CALLRET | CALLRET | - |
| 0x002a7302 | CALL | 0x002a72b0 | DEREF_USER_PTR | DEREF_DERIVED | DEREF_DERIVED | - |
| 0x002ac9ce | CALL | 0x002ac690 | STACKADDR | CALLRET | CONST | - |
| 0x002ac9f2 | CALL | 0x002ac690 | STACKADDR | CALLRET | CONST | - |
| 0x002aca16 | CALL | 0x002ac690 | STACKADDR | CALLRET | CONST | - |
| 0x002aca3a | CALL | 0x002ac690 | STACKADDR | CALLRET | CONST | - |
| 0x002af618 | CALL | 0x002af4c0 | DEREF_DERIVED | UNKNOWN | UNKNOWN | - |
| 0x002b05b8 | CALL | 0x002af920 | CONST | DEREF_DEREF_UNKNOWN | USERARG | - |
| 0x002bbe19 | CALL | 0x002bbdd0 | GLOBAL | UNKNOWN | USERARG | - |
| 0x002c7135 | JMP | 0x002c70a0 | USERARG | DERIVED | CONST | 341@6,431@6,547@3+2 |
| 0x002cb667 | CALL | 0x002cb4e0 | CALLRET | CALLRET | CONST | 1@3,2@5,5@6+79 |
| 0x002cb906 | CALL | 0x002cb770 | CALLRET | CALLRET | CONST | 1@3,2@5,5@6+79 |
| 0x002d03db | CALL | 0x002d0300 | DEREF_CALLRET | DEREF_CALLRET | CONST | 1@3,2@5,37@6+35 |
| 0x002d0d35 | CALL | 0x002d07f0 | CALLRET | CALLRET | CONST | 2@2,251@2,315@6+6 |
| 0x002d0e56 | CALL | 0x002d07f0 | CALLRET | CALLRET | CONST | 2@2,251@2,315@6+6 |
| 0x002d8491 | CALL | 0x002d8470 | CALLRET | DERIVED | CONST | - |
| 0x002d8dd1 | CALL | 0x002d8d60 | STACKADDR | CALLRET | CONST | - |
| 0x002d901d | CALL | 0x002d8f90 | STACKADDR | CALLRET | CONST | - |
| 0x002d9b3a | CALL | 0x002d9240 | STACKADDR | UNKNOWN | CONST | - |
| 0x002db339 | CALL | 0x002daff0 | STACKADDR | STACKADDR | CONST | - |
| 0x002dc675 | CALL | 0x002dbf50 | STACKADDR | UNKNOWN | CONST | - |
| 0x002f2c60 | CALL | 0x002f2bb0 | CALLRET | UNKNOWN | DEREF_STACK | - |
| 0x002f2ce9 | CALL | 0x002f2bb0 | UNKNOWN | DEREF_STACK | DEREF_STACK | - |
| 0x002f3933 | CALL | 0x002f3820 | DEREF_UNKNOWN | CALLRET | CALLRET | - |
| 0x002fed00 | CALL | 0x002fec80 | DERIVED | CALLRET | CALLRET | - |
| 0x002ff32c | CALL | 0x002fee80 | DEREF_DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | 601@6 |
| 0x002ff376 | CALL | 0x002fee80 | DEREF_CALLRET | DEREF_DEREF_CALLRET | CONST | 601@6 |
| 0x002ff3ec | CALL | 0x002fee80 | STACKADDR | GLOBAL | CONST | 601@6 |
| 0x00311e49 | CALL | 0x00311b00 | DEREF_CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x00318d7d | CALL | 0x00318c20 | STACKADDR | STACKADDR | STACK | - |
| 0x00318fc6 | CALL | 0x00318de0 | STACKADDR | STACKADDR | STACK | - |
| 0x00319000 | CALL | 0x00318de0 | STACKADDR | DERIVED | CONST | - |
| 0x0031918f | CALL | 0x00319120 | STACKADDR | CALLRET | CALLRET | - |
| 0x003191b9 | CALL | 0x00319120 | STACKADDR | CALLRET | CONST | - |
| 0x00319263 | CALL | 0x00319200 | STACKADDR | CALLRET | CALLRET | - |
| 0x00319321 | CALL | 0x003192b0 | STACKADDR | CALLRET | CONST | - |
| 0x00319345 | CALL | 0x003192b0 | STACKADDR | CALLRET | CALLRET | - |
| 0x0031999e | CALL | 0x00319900 | CALLRET | STACK | CALLRET | - |
| 0x00319b72 | CALL | 0x00319900 | STACKADDR | DEREF_STACK | CONST | - |
| 0x00319b87 | CALL | 0x00319900 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00319b98 | CALL | 0x00319900 | CALLRET | STACKADDR | CONST | - |
| 0x00319c93 | CALL | 0x00319be0 | CALLRET | CALLRET | CALLRET | - |
| 0x00319d4c | CALL | 0x00319be0 | DEREF_STACK | STACKADDR | UNKNOWN | - |
| 0x00319d69 | CALL | 0x00319be0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00319d7e | CALL | 0x00319be0 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00319d8f | CALL | 0x00319be0 | CALLRET | STACKADDR | CONST | - |
| 0x00319e61 | CALL | 0x00319be0 | STACK | CALLRET | CALLRET | - |
| 0x0031a1ed | CALL | 0x0031a0a0 | UNKNOWN | USERARG | UNKNOWN | - |
| 0x0031b337 | CALL | 0x0031ae10 | STACKADDR | DERIVED | CALLRET | - |
| 0x0031b35c | CALL | 0x0031ae10 | STACKADDR | DERIVED | CALLRET | - |
| 0x0031b650 | CALL | 0x0031ae10 | STACKADDR | STACKADDR | CONST | - |
| 0x0031fb0b | CALL | 0x0031f6e0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0031fc2c | CALL | 0x0031f6e0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x0031ffd0 | CALL | 0x0031f6e0 | STACKADDR | STACKADDR | CONST | - |
| 0x0032016c | CALL | 0x0031f6e0 | STACKADDR | STACKADDR | CONST | - |
| 0x0032018d | CALL | 0x0031f6e0 | STACKADDR | STACKADDR | CONST | - |
| 0x003201d8 | CALL | 0x0031f6e0 | STACKADDR | STACKADDR | CONST | - |
| 0x003201f3 | CALL | 0x0031f6e0 | STACKADDR | STACKADDR | CONST | - |
| 0x0032030a | CALL | 0x0031f6e0 | STACKADDR | DEREF_UNKNOWN | USERARG | - |
| 0x0032038e | CALL | 0x00320320 | GLOBAL | DEREF_DEREF_DERIVED | CONST | - |
| 0x00320579 | CALL | 0x00320430 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x0032058e | CALL | 0x00320430 | STACKADDR | DERIVED | CONST | - |
| 0x00320e95 | CALL | 0x00320d30 | UNKNOWN | DERIVED | CONST | - |
| 0x003228f0 | CALL | 0x003224e0 | STACKADDR | GLOBAL | CONST | - |
| 0x00322a23 | CALL | 0x003224e0 | STACKADDR | GLOBAL | CONST | - |
| 0x00322b53 | CALL | 0x00322af0 | STACKADDR | GLOBAL | CONST | - |
| 0x00322d3e | CALL | 0x00322af0 | DERIVED | DERIVED | STACK | - |
| 0x00322daa | CALL | 0x00322af0 | DERIVED | DERIVED | CALLRET | - |
| 0x00322f61 | CALL | 0x00322e20 | DERIVED | DERIVED | STACK | - |
| 0x00322fca | CALL | 0x00322e20 | DERIVED | DERIVED | CALLRET | - |
| 0x003237b2 | CALL | 0x00322e20 | DERIVED | UNKNOWN | CONST | - |
| 0x0032396d | CALL | 0x00323830 | UNKNOWN | DERIVED | CONST | - |
| 0x00326b65 | CALL | 0x00326af0 | CALLRET | GLOBAL | CALLRET | - |
| 0x003275ea | CALL | 0x00327550 | USERARG | GLOBAL | CONST | 341@6,431@6 |
| 0x00327747 | CALL | 0x00327640 | STACKADDR | GLOBAL | CONST | 341@6,431@6 |
| 0x0032b5ab | CALL | 0x0032b560 | DEREF_CALLRET | DERIVED | GLOBAL | 97@6,113@6,135@6 |
| 0x0032de91 | CALL | 0x0032de60 | USERARG | DERIVED | CONST | - |
| 0x0032dffc | CALL | 0x0032de60 | STACKADDR | GLOBAL | CONST | - |
| 0x0032e1bf | CALL | 0x0032de60 | STACKADDR | GLOBAL | CONST | - |
| 0x0032e39f | CALL | 0x0032e230 | CALLRET | GLOBAL | CONST | - |
| 0x00330422 | CALL | 0x0032f0c0 | STACKADDR | GLOBAL | CONST | - |
| 0x00330490 | CALL | 0x0032f0c0 | STACKADDR | GLOBAL | CONST | - |
| 0x00336de6 | CALL | 0x00336cb0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x003375ec | CALL | 0x003370c0 | DEREF_CALLRET | DERIVED | DEREF_DEREF_DERIVED | - |
| 0x0033772e | CALL | 0x003370c0 | CALLRET | DERIVED | CONST | - |
| 0x00337e80 | CALL | 0x00337da0 | CALLRET | CALLRET | CONST | - |
| 0x00337f6a | CALL | 0x00337da0 | UNKNOWN | DERIVED | CONST | - |
| 0x003388e5 | CALL | 0x00338880 | STACK | UNKNOWN | DERIVED | - |
| 0x00338904 | CALL | 0x00338880 | DEREF_STACK | STACK | DERIVED | - |
| 0x003389ad | CALL | 0x00338880 | STACKADDR | CALLRET | CONST | - |
| 0x003389c3 | CALL | 0x00338880 | STACKADDR | CALLRET | CONST | - |
| 0x00339082 | CALL | 0x00338f40 | DERIVED | DERIVED | STACK | - |
| 0x003390a4 | CALL | 0x00338f40 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00339102 | CALL | 0x00338f40 | DERIVED | USERARG | CONST | - |
| 0x00339518 | CALL | 0x00338f40 | DERIVED | UNKNOWN | CONST | - |
| 0x0033af10 | CALL | 0x0033add0 | DEREF_STACK | UNKNOWN | CONST | - |
| 0x0033d082 | CALL | 0x0033d000 | UNKNOWN | CALLRET | CONST | - |
| 0x00345086 | CALL | 0x00344630 | DEREF_UNKNOWN | GLOBAL | CONST | 532@1 |
| 0x0034629e | CALL | 0x00345c10 | DEREF_CALLRET | GLOBAL | CONST | 532@1 |
| 0x0034ec82 | CALL | 0x0034ebd0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x0034ef31 | JMP | 0x0034ef20 | USERARG | GLOBAL | CONST | - |
| 0x0034ef51 | JMP | 0x0034ef40 | USERARG | GLOBAL | CONST | - |
| 0x0034f181 | CALL | 0x0034f0d0 | STACKADDR | GLOBAL | CONST | 0@6,2@6,3@6+562 |
| 0x0034f70c | CALL | 0x0034f270 | GLOBAL | STACK | CONST | - |
| 0x0034f7a7 | CALL | 0x0034f270 | DERIVED | CALLRET | CONST | - |
| 0x0034f854 | CALL | 0x0034f270 | UNKNOWN | STACK | CONST | - |
| 0x0034f8ad | CALL | 0x0034f270 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0034f97d | CALL | 0x0034f8f0 | DERIVED | CALLRET | CONST | - |
| 0x0035096d | CALL | 0x00350790 | UNKNOWN | DERIVED | CONST | - |
| 0x00350a3d | CALL | 0x003509c0 | CALLRET | DERIVED | CONST | 97@2,113@2,135@2 |
| 0x0035b283 | CALL | 0x0035b1a0 | STACKADDR | USERARG | CONST | - |
| 0x0035c6dc | CALL | 0x0035c5c0 | STACKADDR | CALLRET | CONST | - |
| 0x00361de4 | CALL | 0x00361a70 | DERIVED | STACK | CONST | - |
| 0x003633e9 | CALL | 0x00362200 | DEREF_UNKNOWN | USERFIELD | CONST | 601@5 |
| 0x00364ce4 | CALL | 0x00364940 | UNKNOWN | DERIVED | DEREF_CALLRET | - |
| 0x00364e83 | CALL | 0x00364940 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x0036841c | CALL | 0x003680e0 | DERIVED | DERIVED | USERARG | - |
| 0x0036859e | CALL | 0x003680e0 | STACK | UNKNOWN | STACK | - |
| 0x0036975c | CALL | 0x00368b80 | STACK | STACKADDR | CONST | 601@5 |
| 0x00369957 | CALL | 0x00368b80 | CALLRET | STACK | CONST | 601@5 |
| 0x00369c9b | CALL | 0x00368b80 | DERIVED | STACKADDR | STACK | 601@5 |
| 0x00369ce3 | CALL | 0x00368b80 | STACKADDR | STACKADDR | CONST | 601@5 |
| 0x00369e1a | CALL | 0x00368b80 | UNKNOWN | STACK | CONST | 601@5 |
| 0x0036aa85 | CALL | 0x0036a600 | CALLRET | DEREF_CALLRET | CALLRET | 601@5 |
| 0x0036adaa | CALL | 0x0036a600 | DEREF_DEREF_DEREF_STACK | UNKNOWN | CONST | 601@5 |
| 0x0036b3a8 | CALL | 0x0036b350 | CALLRET | DEREF_CALLRET | CALLRET | 601@5 |
| 0x0036cc42 | CALL | 0x0036c8a0 | UNKNOWN | DERIVED | DEREF_UNKNOWN | - |
| 0x0036d4ed | CALL | 0x0036ce90 | UNKNOWN | DERIVED | UNKNOWN | - |
| 0x0036df7f | CALL | 0x0036dd70 | UNKNOWN | GLOBAL | CONST | - |
| 0x0036ea2b | CALL | 0x0036e920 | CALLRET | DERIVED | CALLRET | - |
| 0x0036f046 | CALL | 0x0036eed0 | STACK | DERIVED | DERIVED | - |
| 0x003705b8 | CALL | 0x00370250 | STACKADDR | STACK | CONST | - |
| 0x003711f5 | CALL | 0x003710f0 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00371759 | CALL | 0x00371540 | STACK | DERIVED | CONST | 601@6 |
| 0x003718c2 | CALL | 0x00371540 | DEREF_UNKNOWN | UNKNOWN | CONST | 601@6 |
| 0x00371953 | CALL | 0x00371540 | UNKNOWN | DERIVED | CONST | 601@6 |
| 0x00371ab9 | CALL | 0x00371a60 | DEREF_CALLRET | DEREF_CALLRET | CONST | 601@6 |
| 0x00371ade | CALL | 0x00371a60 | CALLRET | CALLRET | CONST | 601@6 |
| 0x00371bde | CALL | 0x00371b60 | DEREF_CALLRET | DEREF_CALLRET | CONST | 601@6 |
| 0x00371c15 | CALL | 0x00371b60 | DEREF_CALLRET | CALLRET | CONST | 601@6 |
| 0x0037216e | CALL | 0x00371f80 | DERIVED | DERIVED | CONST | 601@6 |
| 0x003721a8 | CALL | 0x00371f80 | DERIVED | DEREF_STACK | DERIVED | 601@6 |
| 0x003723d0 | CALL | 0x003721f0 | UNKNOWN | DERIVED | CONST | 601@6 |
| 0x0037240b | CALL | 0x003721f0 | DERIVED | DEREF_STACK | DERIVED | 601@6 |
| 0x00372520 | CALL | 0x00372440 | CALLRET | DERIVED | CALLRET | - |
| 0x0037263b | CALL | 0x00372580 | CALLRET | UNKNOWN | CALLRET | - |
| 0x00372cbd | CALL | 0x00372b00 | UNKNOWN | UNKNOWN | DERIVED | 601@6 |
| 0x00372d33 | CALL | 0x00372b00 | CALLRET | DEREF_STACK | CALLRET | 601@6 |
| 0x00372d60 | CALL | 0x00372b00 | UNKNOWN | DERIVED | CONST | 601@6 |
| 0x00372d77 | CALL | 0x00372b00 | UNKNOWN | UNKNOWN | UNKNOWN | 601@6 |
| 0x003731ce | CALL | 0x00372f50 | STACK | UNKNOWN | DERIVED | 601@6 |
| 0x003732b5 | CALL | 0x00372f50 | STACK | DEREF_CALLRET | DERIVED | 601@6 |
| 0x00374ffb | CALL | 0x003748d0 | DEREF_CALLRET | STACK | CONST | 601@6 |
| 0x003759a8 | CALL | 0x003748d0 | UNKNOWN | STACK | STACK | 601@6 |
| 0x00375a0e | CALL | 0x003748d0 | UNKNOWN | STACK | USERARG | 601@6 |
| 0x00375c0a | CALL | 0x003748d0 | DERIVED | DERIVED | USERARG | 601@6 |
| 0x00375d8d | CALL | 0x003748d0 | CALLRET | UNKNOWN | STACK | 601@6 |
| 0x003766ed | CALL | 0x003764a0 | UNKNOWN | USERFIELD | UNKNOWN | - |
| 0x00376d41 | CALL | 0x00376cf0 | DERIVED | USERFIELD | UNKNOWN | - |
| 0x00377500 | CALL | 0x00377440 | CALLRET | CALLRET | CALLRET | - |
| 0x0037784e | CALL | 0x003777b0 | UNKNOWN | UNKNOWN | DERIVED | - |
| 0x003778ab | CALL | 0x003777b0 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00377a7b | CALL | 0x00377980 | STACK | CALLRET | DERIVED | - |
| 0x00378aeb | CALL | 0x00378a60 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | 601@6 |
| 0x00378b4e | CALL | 0x00378a60 | CALLRET | DEREF_CALLRET | CALLRET | 601@6 |
| 0x00379371 | CALL | 0x003791a0 | DEREF_CALLRET | DEREF_STACK | CALLRET | - |
| 0x00389c92 | CALL | 0x00389b60 | STACK | UNKNOWN | UNKNOWN | - |
| 0x00389dc3 | CALL | 0x00389b60 | STACK | STACK | CALLRET | - |
| 0x0038ec28 | CALL | 0x0038eb00 | CALLRET | UNKNOWN | DERIVED | 59@4,594@6 |
| 0x0038ecc0 | CALL | 0x0038eb00 | CALLRET | DERIVED | CONST | 59@4,594@6 |
| 0x0038ed5d | CALL | 0x0038eb00 | CALLRET | DERIVED | CALLRET | 59@4,594@6 |
| 0x00390961 | CALL | 0x003905c0 | UNKNOWN | STACKADDR | UNKNOWN | 59@3 |
| 0x003918b1 | JMP | 0x003918a0 | DERIVED | USERARG | CONST | - |
| 0x00391d0d | CALL | 0x00391b40 | DERIVED | DERIVED | CONST | - |
| 0x00392868 | CALL | 0x00392710 | CALLRET | CALLRET | CONST | - |
| 0x003976c1 | CALL | 0x00397610 | STACKADDR | DEREF_DEREF_UNKNOWN | CONST | 622@1 |
| 0x0039b2e2 | CALL | 0x0039b270 | STACKADDR | CALLRET | CALLRET | - |
| 0x0039b305 | CALL | 0x0039b270 | CALLRET | CALLRET | STACK | - |
| 0x0039b5b3 | CALL | 0x0039b3c0 | UNKNOWN | USERARG | USERARG | - |
| 0x0039b957 | CALL | 0x0039b890 | USER_PTR | UNKNOWN | USER_PTR | - |
| 0x0039bb16 | CALL | 0x0039b890 | UNKNOWN | STACKADDR | CONST | - |
| 0x0039bb3d | CALL | 0x0039b890 | USERFIELD | STACKADDR | CONST | - |
| 0x0039bb7e | CALL | 0x0039b890 | UNKNOWN | CALLRET | STACK | - |
| 0x0039bbbd | CALL | 0x0039b890 | UNKNOWN | UNKNOWN | STACK | - |
| 0x0039be22 | CALL | 0x0039b890 | UNKNOWN | STACKADDR | CONST | - |
| 0x0039be48 | CALL | 0x0039b890 | USERFIELD | STACKADDR | CONST | - |
| 0x0039be89 | CALL | 0x0039b890 | UNKNOWN | CALLRET | STACK | - |
| 0x0039bed1 | CALL | 0x0039b890 | UNKNOWN | UNKNOWN | STACK | - |
| 0x0039bf01 | CALL | 0x0039b890 | USERFIELD | UNKNOWN | UNKNOWN | - |
| 0x0039bfc9 | CALL | 0x0039b890 | UNKNOWN | UNKNOWN | CONST | - |
| 0x0039c08d | CALL | 0x0039b890 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0039c507 | CALL | 0x0039c3f0 | UNKNOWN | DEREF_CALLRET | CALLRET | - |
| 0x0039c64c | CALL | 0x0039c3f0 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x0039c7d2 | CALL | 0x0039c3f0 | DEREF_DEREF_UNKNOWN | DEREF_UNKNOWN | UNKNOWN | - |
| 0x0039cb55 | CALL | 0x0039cb20 | USER_PTR | USERFIELD | USERARG | - |
| 0x0039cb7e | CALL | 0x0039cb20 | USERARG | USERARG | UNKNOWN | - |
| 0x0039cffa | CALL | 0x0039ce50 | STACKADDR | STACKADDR | CONST | - |
| 0x0039d01c | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d03e | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d060 | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d082 | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d0a4 | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d0c6 | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d0e8 | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d0fc | CALL | 0x0039ce50 | STACKADDR | CALLRET | CONST | - |
| 0x0039d53e | CALL | 0x0039d3f0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039d58c | CALL | 0x0039d3f0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039d5da | CALL | 0x0039d3f0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039d976 | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039d9c4 | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039da12 | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039da60 | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039daae | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039dafc | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039db4a | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039db98 | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039dbe6 | CALL | 0x0039d6d0 | STACKADDR | CALLRET | CONST | 55@6,334@3,601@6+2 |
| 0x0039dc34 | CALL | 0x0039d6d0 | STACKADDR | STACKADDR | CONST | 55@6,334@3,601@6+2 |
| 0x0039dc82 | CALL | 0x0039d6d0 | STACKADDR | STACKADDR | CONST | 55@6,334@3,601@6+2 |
| 0x0039dcd0 | CALL | 0x0039d6d0 | STACKADDR | STACKADDR | CONST | 55@6,334@3,601@6+2 |
| 0x0039dd1e | CALL | 0x0039d6d0 | STACKADDR | STACKADDR | CONST | 55@6,334@3,601@6+2 |
| 0x0039f228 | CALL | 0x0039f150 | UNKNOWN | STACK | UNKNOWN | 622@2 |
| 0x0039f24f | CALL | 0x0039f150 | DEREF_UNKNOWN | DEREF_STACK | UNKNOWN | 622@2 |
| 0x0039f3e8 | CALL | 0x0039f310 | STACK | UNKNOWN | UNKNOWN | 622@2 |
| 0x0039f40f | CALL | 0x0039f310 | DEREF_STACK | DEREF_UNKNOWN | UNKNOWN | 622@2 |
| 0x003a1e84 | CALL | 0x003a1e20 | DEREF_CALLRET | CALLRET | DERIVED | - |
| 0x003a1efd | CALL | 0x003a1e20 | DEREF_CALLRET | DERIVED | DERIVED | - |
| 0x003a24ae | CALL | 0x003a2490 | USERARG | GLOBAL | CONST | - |
| 0x003a2f57 | CALL | 0x003a2f40 | GLOBAL | USERFIELD | CONST | - |
| 0x003a3272 | CALL | 0x003a2fc0 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x003a3efb | CALL | 0x003a3950 | DERIVED | UNKNOWN | CONST | - |
| 0x003a42fc | CALL | 0x003a4100 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x003a4860 | CALL | 0x003a4790 | UNKNOWN | UNKNOWN | DERIVED | - |
| 0x003a4f13 | CALL | 0x003a4d40 | CALLRET | GLOBAL | CONST | - |
| 0x003a6715 | CALL | 0x003a6370 | CALLRET | STACK | DERIVED | - |
| 0x003a686b | CALL | 0x003a6370 | DEREF_STACK | STACKADDR | CONST | - |
| 0x003a6b30 | CALL | 0x003a6aa0 | CALLRET | CALLRET | CONST | - |
| 0x003a6bf1 | CALL | 0x003a6b50 | CALLRET | CALLRET | CONST | - |
| 0x003a6ecf | CALL | 0x003a6cf0 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x003a7350 | CALL | 0x003a7220 | CALLRET | CALLRET | CONST | - |
| 0x003a77d7 | CALL | 0x003a7730 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x003a939a | CALL | 0x003a8c80 | DEREF_CALLRET | DEREF_DEREF_CALLRET | CALLRET | - |
| 0x003aa826 | CALL | 0x003aa780 | DEREF_USER_PTR | DEREF_USER_PTR | DERIVED | - |
| 0x003aa84b | CALL | 0x003aa780 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x003aa86a | CALL | 0x003aa780 | CALLRET | DERIVED | DERIVED | - |
| 0x003aa938 | CALL | 0x003aa8a0 | STACK | DEREF_DEREF_CALLRET | DERIVED | - |
| 0x003ba67a | CALL | 0x003b9b70 | CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x003c31c3 | CALL | 0x003c2ec0 | STACKADDR | GLOBAL | CONST | - |
| 0x003c3235 | CALL | 0x003c2ec0 | STACKADDR | GLOBAL | CONST | - |
| 0x003c32b0 | CALL | 0x003c2ec0 | USERFIELD | GLOBAL | CONST | - |
| 0x003c339d | CALL | 0x003c32f0 | STACKADDR | GLOBAL | CONST | - |
| 0x003c6195 | CALL | 0x003c60f0 | CALLRET | CALLRET | CONST | 37@5,65@6,75@6+4 |
| 0x003d71df | CALL | 0x003d7110 | UNKNOWN | DERIVED | DERIVED | - |
| 0x003d7298 | CALL | 0x003d7230 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x003d765b | CALL | 0x003d7560 | UNKNOWN | DERIVED | DERIVED | - |
| 0x003d76e4 | CALL | 0x003d76b0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x003d892c | CALL | 0x003d88b0 | UNKNOWN | DERIVED | CONST | - |
| 0x003da047 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003da1a5 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003da285 | CALL | 0x003d8f20 | GLOBAL | DEREF_DEREF_CALLRET | CONST | - |
| 0x003db31b | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dbb1e | CALL | 0x003d8f20 | STACKADDR | STACKADDR | DERIVED | - |
| 0x003dbb8b | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dbd60 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dc05a | CALL | 0x003d8f20 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x003dc1ec | CALL | 0x003d8f20 | CALLRET | STACKADDR | DERIVED | - |
| 0x003dc254 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dc2c7 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dc4a7 | CALL | 0x003d8f20 | STACKADDR | CALLRET | DERIVED | - |
| 0x003dc529 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dc652 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dc84a | CALL | 0x003d8f20 | STACKADDR | STACKADDR | DERIVED | - |
| 0x003dc8cc | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dc984 | CALL | 0x003d8f20 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x003dca50 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dcb5c | CALL | 0x003d8f20 | CALLRET | STACKADDR | DERIVED | - |
| 0x003dcbcc | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dcc47 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dcd78 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dce9d | CALL | 0x003d8f20 | CALLRET | STACKADDR | DERIVED | - |
| 0x003dcf07 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dcf8d | CALL | 0x003d8f20 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x003dd005 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dd087 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dd331 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dd3ad | CALL | 0x003d8f20 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x003dd3ee | CALL | 0x003d8f20 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x003dd434 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dd4af | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dda26 | CALL | 0x003d8f20 | CALLRET | STACKADDR | CONST | - |
| 0x003ddacf | CALL | 0x003d8f20 | CALLRET | STACKADDR | CONST | - |
| 0x003ddbbf | CALL | 0x003d8f20 | STACKADDR | STACKADDR | CONST | - |
| 0x003ddccc | CALL | 0x003d8f20 | CALLRET | STACKADDR | CONST | - |
| 0x003dde08 | CALL | 0x003d8f20 | STACKADDR | CALLRET | CONST | - |
| 0x003dde2b | CALL | 0x003d8f20 | STACKADDR | STACKADDR | CONST | - |
| 0x003e3203 | CALL | 0x003e31f0 | GLOBAL | USERARG | CONST | - |
| 0x003e3233 | CALL | 0x003e3220 | GLOBAL | USERARG | CONST | - |
| 0x003e3388 | CALL | 0x003e3220 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x003e33eb | CALL | 0x003e3220 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x003e407a | CALL | 0x003e3f40 | GLOBAL | CALLRET | CONST | - |
| 0x003e446d | CALL | 0x003e4120 | DEREF_GLOBAL | DEREF_GLOBAL | CONST | - |
| 0x003e449e | CALL | 0x003e4120 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x003e44d7 | CALL | 0x003e4120 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x003e4510 | CALL | 0x003e4120 | STACKADDR | CALLRET | CONST | - |
| 0x003e4576 | CALL | 0x003e4120 | USERARG | DEREF_UNKNOWN | CONST | - |
| 0x003e45a7 | CALL | 0x003e4120 | STACKADDR | CALLRET | CONST | - |
| 0x003e45cf | CALL | 0x003e4120 | USERARG | USERARG | CONST | - |
| 0x003e45db | CALL | 0x003e4120 | CALLRET | CALLRET | CONST | - |
| 0x003e45eb | CALL | 0x003e4120 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x003e4621 | CALL | 0x003e4120 | DEREF_CALLRET | STACKADDR | DEREF_CALLRET | - |
| 0x003e4945 | CALL | 0x003e4690 | CALLRET | UNKNOWN | CONST | - |
| 0x003e5035 | CALL | 0x003e4fa0 | CALLRET | CALLRET | CONST | - |
| 0x003e52c4 | CALL | 0x003e5100 | STACK | CALLRET | CONST | - |
| 0x003e5376 | CALL | 0x003e5100 | CALLRET | STACKADDR | CONST | - |
| 0x003e54b4 | CALL | 0x003e5100 | CALLRET | CALLRET | CONST | - |
| 0x003e554a | CALL | 0x003e5100 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x003e55a6 | CALL | 0x003e5100 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x003e580e | CALL | 0x003e5100 | DEREF_UNKNOWN | DEREF_STACK | CONST | - |
| 0x003e5824 | CALL | 0x003e5100 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x003e5857 | CALL | 0x003e5100 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x003e58ad | CALL | 0x003e5100 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x003e830c | CALL | 0x003e8230 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x003e8598 | CALL | 0x003e84d0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x003e86fc | CALL | 0x003e8670 | DERIVED | UNKNOWN | CONST | - |
| 0x003e96b3 | CALL | 0x003e95f0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x003e987f | CALL | 0x003e97c0 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x003e9a09 | CALL | 0x003e9910 | USER_PTR | DERIVED | USERFIELD | - |
| 0x003eb08a | CALL | 0x003e9d30 | STACKADDR | STACKADDR | CONST | - |
| 0x003eb0a8 | CALL | 0x003e9d30 | USERARG | USERARG | CONST | - |
| 0x003eb394 | CALL | 0x003e9d30 | STACKADDR | STACKADDR | CONST | - |
| 0x003eb3ac | CALL | 0x003e9d30 | STACKADDR | STACKADDR | CONST | - |
| 0x003eb42a | CALL | 0x003e9d30 | STACKADDR | STACKADDR | CONST | - |
| 0x003f22a8 | CALL | 0x003f21e0 | DEREF_CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | 93@6,522@6 |
| 0x003f22e4 | CALL | 0x003f21e0 | DEREF_CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | 93@6,522@6 |
| 0x003f2327 | CALL | 0x003f21e0 | DEREF_CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | 93@6,522@6 |
| 0x003f5a72 | CALL | 0x003f5a20 | CALLRET | CALLRET | DERIVED | - |
| 0x004040d2 | CALL | 0x003ff9c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x0040413c | CALL | 0x003ff9c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00404349 | CALL | 0x003ff9c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x004045bc | CALL | 0x003ff9c0 | DEREF_STACK | GLOBAL | CONST | - |
| 0x004046f3 | CALL | 0x003ff9c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00404a36 | CALL | 0x003ff9c0 | DEREF_DERIVED | GLOBAL | CONST | - |
| 0x00404b35 | CALL | 0x003ff9c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x0040d3ef | CALL | 0x0040cb70 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x004157cd | CALL | 0x00415070 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00425f14 | CALL | 0x00425e30 | CALLRET | CALLRET | CONST | - |
| 0x00427199 | CALL | 0x00426fa0 | USERARG | USERARG | CONST | - |
| 0x0042b8a8 | CALL | 0x0042b840 | DEREF_UNKNOWN | USERARG | DERIVED | - |
| 0x0042c4b3 | CALL | 0x0042c450 | GLOBAL | USERFIELD | CONST | - |
| 0x0042cff9 | CALL | 0x0042cf90 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x0042d0a3 | CALL | 0x0042d030 | CALLRET | CALLRET | CALLRET | - |
| 0x0042e6bd | CALL | 0x0042e620 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x0042e73f | CALL | 0x0042e620 | DERIVED | STACKADDR | CONST | - |
| 0x0042e833 | CALL | 0x0042e7d0 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x0042e893 | CALL | 0x0042e860 | USERARG | STACKADDR | CONST | - |
| 0x0043007d | CALL | 0x0042fd20 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x004300f0 | CALL | 0x0042fd20 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x0043019c | CALL | 0x0042fd20 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x0043045e | CALL | 0x0042fd20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00430477 | CALL | 0x0042fd20 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x004327c5 | CALL | 0x00432530 | GLOBAL | DEREF_DEREF_GLOBAL | CONST | - |
| 0x004327dd | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x004327f5 | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x004328e2 | CALL | 0x00432530 | GLOBAL | DEREF_STACK | CONST | - |
| 0x004328fa | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x00432912 | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x0043292a | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x00432942 | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x0043295a | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x00432972 | CALL | 0x00432530 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x0043298f | CALL | 0x00432530 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x004329ac | CALL | 0x00432530 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x004329c9 | CALL | 0x00432530 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x004329e6 | CALL | 0x00432530 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x00432a03 | CALL | 0x00432530 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x00432a20 | CALL | 0x00432530 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x00432a40 | CALL | 0x00432530 | UNKNOWN | DERIVED | CONST | - |
| 0x00432c6a | CALL | 0x00432af0 | DEREF_DEREF_GLOBAL | GLOBAL | CONST | - |
| 0x00432c82 | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432c9a | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432d93 | CALL | 0x00432af0 | DEREF_STACK | GLOBAL | CONST | - |
| 0x00432dab | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432dc3 | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432ddb | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432df3 | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432e0b | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432e23 | CALL | 0x00432af0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00432e40 | CALL | 0x00432af0 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x00432e5d | CALL | 0x00432af0 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x00432e7a | CALL | 0x00432af0 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x00432e97 | CALL | 0x00432af0 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x00432eb4 | CALL | 0x00432af0 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x00432ed1 | CALL | 0x00432af0 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x00432ef1 | CALL | 0x00432af0 | DERIVED | UNKNOWN | CONST | - |
| 0x00432f2d | CALL | 0x00432af0 | DEREF_GLOBAL | DERIVED | CONST | - |
| 0x00433c57 | CALL | 0x00433bc0 | DEREF_CALLRET | STACK | CALLRET | - |
| 0x00433d31 | CALL | 0x00433c70 | DEREF_CALLRET | STACK | CALLRET | - |
| 0x00433ec5 | CALL | 0x00433e70 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00433f3c | CALL | 0x00433ee0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x004340ec | CALL | 0x00434080 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x0043417c | CALL | 0x00434110 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x004342e8 | CALL | 0x004341a0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00434301 | CALL | 0x004341a0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00434313 | CALL | 0x004341a0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0043432b | CALL | 0x004341a0 | DERIVED | DERIVED | CONST | - |
| 0x00434554 | CALL | 0x004344d0 | CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x004345d6 | CALL | 0x00434570 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x004345ee | CALL | 0x00434570 | DERIVED | DERIVED | CONST | - |
| 0x0043473a | CALL | 0x00434610 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x004348b8 | CALL | 0x00434760 | DEREF_CALLRET | DERIVED | DERIVED | - |
| 0x00434975 | CALL | 0x004348d0 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x00434a35 | CALL | 0x00434990 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x00434abc | CALL | 0x00434a50 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x00434ca8 | CALL | 0x00434bd0 | DEREF_CALLRET | DERIVED | DERIVED | - |
| 0x00435967 | CALL | 0x00435840 | CALLRET | STACK | CONST | 37@6,334@4,588@6+2 |
| 0x00435980 | CALL | 0x00435840 | DEREF_CALLRET | STACK | DEREF_CALLRET | 37@6,334@4,588@6+2 |
| 0x004360c4 | CALL | 0x00436010 | DEREF_GLOBAL | CALLRET | CONST | - |
| 0x004360db | CALL | 0x00436010 | DEREF_CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00436206 | CALL | 0x00436010 | STACK | STACK | DEREF_CALLRET | - |
| 0x004363ee | CALL | 0x00436240 | STACK | UNKNOWN | CONST | 677@1 |
| 0x00436405 | CALL | 0x00436240 | DEREF_CALLRET | CALLRET | DEREF_CALLRET | 677@1 |
| 0x00436587 | CALL | 0x00436240 | STACK | UNKNOWN | DEREF_UNKNOWN | 677@1 |
| 0x00437536 | CALL | 0x004372f0 | DEREF_GLOBAL | GLOBAL | CONST | 677@1,678@1 |
| 0x00437cb4 | CALL | 0x00437c30 | DERIVED | UNKNOWN | UNKNOWN | 588@4 |
| 0x00439489 | CALL | 0x004393b0 | DEREF_DEREF_CONST | DEREF_UNKNOWN | UNKNOWN | - |
| 0x0043957e | CALL | 0x004394c0 | CALLRET | STACK | STACK | - |
| 0x00442130 | CALL | 0x00441930 | STACKADDR | CALLRET | CONST | - |
| 0x00445128 | CALL | 0x00444ee0 | DEREF_GLOBAL | DERIVED | CONST | - |
| 0x00445182 | CALL | 0x00444ee0 | DEREF_GLOBAL | DERIVED | DEREF_GLOBAL | - |
| 0x0044568a | CALL | 0x004451d0 | DEREF_GLOBAL | DERIVED | CONST | - |
| 0x00445d12 | CALL | 0x004451d0 | STACKADDR | DERIVED | CONST | - |
| 0x00445dc9 | CALL | 0x004451d0 | DEREF_GLOBAL | DERIVED | CONST | - |
| 0x00445e50 | CALL | 0x00445e00 | STACKADDR | GLOBAL | CONST | - |
| 0x00446f46 | CALL | 0x00446f00 | DERIVED | UNKNOWN | DERIVED | 0@3,2@3,3@3+562 |
| 0x00447106 | CALL | 0x004470c0 | UNKNOWN | DERIVED | DERIVED | 0@3,2@3,3@3+562 |
| 0x004493b7 | CALL | 0x00448bf0 | STACK | DEREF_CALLRET | DEREF_DEREF_CALLRET | 0@5,2@5,3@5+562 |
| 0x004493c7 | CALL | 0x00448bf0 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | 0@5,2@5,3@5+562 |
| 0x00449b3a | CALL | 0x004497a0 | USERARG | USERARG | DEREF_UNKNOWN | - |
| 0x0044faac | CALL | 0x0044fa50 | DERIVED | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | - |
| 0x004511f0 | CALL | 0x00450f30 | STACKADDR | DEREF_UNKNOWN | CONST | 676@6 |
| 0x00451201 | CALL | 0x00450f30 | STACKADDR | CALLRET | CONST | 676@6 |
| 0x0045354e | CALL | 0x004532f0 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x00455298 | CALL | 0x00453740 | DERIVED | STACK | CONST | - |
| 0x00456e72 | CALL | 0x00456e50 | USERFIELD | UNKNOWN | CONST | - |
| 0x00457976 | CALL | 0x00457170 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0045836f | CALL | 0x00458280 | CALLRET | DERIVED | CALLRET | 93@6,522@6,532@5 |
| 0x00465e28 | CALL | 0x00465dc0 | UNKNOWN | UNKNOWN | USERARG | - |
| 0x00465ea8 | CALL | 0x00465e40 | UNKNOWN | UNKNOWN | USERARG | - |
| 0x0046e6ea | CALL | 0x0046e600 | STACKADDR | DEREF_DEREF_CALLRET | UNKNOWN | - |
| 0x0046e93d | CALL | 0x0046e890 | USER_PTR | USERARG | DERIVED | - |
| 0x0046fb72 | CALL | 0x0046f9b0 | GLOBAL | DEREF_GLOBAL | DEREF_GLOBAL | - |
| 0x004705c3 | CALL | 0x00470550 | DEREF_DERIVED | USERARG | DERIVED | - |
| 0x00470638 | CALL | 0x00470550 | DERIVED | DERIVED | DERIVED | - |
| 0x00470642 | CALL | 0x00470550 | USERARG | USERARG | UNKNOWN | - |
| 0x00471d57 | CALL | 0x004708c0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00471db9 | CALL | 0x004708c0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00471f15 | CALL | 0x004708c0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x004728db | CALL | 0x004708c0 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x004728f7 | CALL | 0x004708c0 | STACK | UNKNOWN | CONST | - |
| 0x00472dce | CALL | 0x004708c0 | DEREF_UNKNOWN | USERARG | CONST | - |
| 0x00473357 | CALL | 0x004708c0 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00473410 | CALL | 0x004708c0 | USERFIELD | USERFIELD | DERIVED | - |
| 0x004734ee | CALL | 0x004708c0 | USERFIELD | USERFIELD | CONST | - |
| 0x00473713 | CALL | 0x004708c0 | CALLRET | CALLRET | CONST | - |
| 0x0047390f | CALL | 0x004708c0 | USERFIELD | USERFIELD | DERIVED | - |
| 0x004747d0 | CALL | 0x004708c0 | UNKNOWN | STACKADDR | CONST | - |
| 0x00474a81 | CALL | 0x004708c0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00474d1b | CALL | 0x00474c50 | STACKADDR | CALLRET | CONST | - |
| 0x00474ef5 | CALL | 0x00474e30 | USERFIELD | USERFIELD | CONST | - |
| 0x0047509a | CALL | 0x00474e30 | STACKADDR | USERARG | DERIVED | - |
| 0x00475201 | CALL | 0x00474e30 | STACKADDR | USERARG | CONST | - |
| 0x0047534b | CALL | 0x004752a0 | USERFIELD | USERFIELD | CONST | - |
| 0x00475590 | CALL | 0x004752a0 | CALLRET | STACKADDR | CONST | - |
| 0x00477787 | CALL | 0x004773c0 | CALLRET | STACK | CONST | - |
| 0x0047b5b5 | CALL | 0x0047b4e0 | CALLRET | DERIVED | CONST | 165@1 |
| 0x0047bc7b | CALL | 0x0047bad0 | DERIVED | CALLRET | CALLRET | - |
| 0x0047bccd | CALL | 0x0047bad0 | DEREF_UNKNOWN | DERIVED | USERARG | - |
| 0x0047c191 | CALL | 0x0047bad0 | STACK | DEREF_UNKNOWN | CONST | - |
| 0x0047c1bb | CALL | 0x0047bad0 | STACK | DEREF_UNKNOWN | CONST | - |
| 0x0047e2f3 | CALL | 0x0047e200 | UNKNOWN | DERIVED | DERIVED | - |
| 0x0047f469 | CALL | 0x0047f360 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x004807db | CALL | 0x0047ffa0 | DEREF_DEREF_STACK | DEREF_STACK | CONST | - |
| 0x004809bd | CALL | 0x0047ffa0 | STACKADDR | DEREF_STACK | CONST | - |
| 0x00480a31 | CALL | 0x0047ffa0 | CALLRET | DEREF_STACK | STACK | - |
| 0x00481581 | CALL | 0x004814b0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x004815dd | CALL | 0x004814b0 | DEREF_DERIVED | DERIVED | CONST | - |
| 0x00481f8a | CALL | 0x00481ca0 | DERIVED | STACKADDR | CONST | - |
| 0x004853c6 | CALL | 0x00484810 | UNKNOWN | USERARG | CONST | - |
| 0x004857eb | CALL | 0x004853e0 | CALLRET | CALLRET | CONST | - |
| 0x00486c6f | CALL | 0x00485ba0 | CALLRET | DERIVED | CALLRET | - |
| 0x004880f9 | CALL | 0x00485ba0 | DEREF_STACK | STACK | CONST | - |
| 0x00488747 | CALL | 0x00485ba0 | DEREF_STACK | STACK | CONST | - |
| 0x00489fe1 | CALL | 0x00489aa0 | UNKNOWN | STACKADDR | CONST | - |
| 0x004903e2 | CALL | 0x0048f070 | USERFIELD | STACKADDR | CONST | - |
| 0x00490401 | CALL | 0x0048f070 | DERIVED | DEREF_CALLRET | DERIVED | - |
| 0x00490632 | CALL | 0x00490480 | CALLRET | CALLRET | CONST | - |
| 0x00490e5d | CALL | 0x00490480 | CALLRET | CALLRET | CONST | - |
| 0x004934e5 | CALL | 0x00493410 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00493641 | CALL | 0x00493410 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00494b16 | CALL | 0x00494a80 | USERARG | DERIVED | CONST | - |
| 0x004a1b69 | CALL | 0x004a1a20 | CALLRET | DERIVED | CONST | 117@1,627@1,641@1 |
| 0x004a1cab | CALL | 0x004a1ba0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x004a1ec0 | CALL | 0x004a1ea0 | USERARG | USERFIELD | CONST | 1@6,59@6,117@1+3 |
| 0x004a411f | CALL | 0x004a3fc0 | STACKADDR | UNKNOWN | CONST | - |
| 0x004a52cf | CALL | 0x004a4a40 | STACKADDR | CALLRET | CONST | - |
| 0x004a53c8 | CALL | 0x004a4a40 | STACKADDR | UNKNOWN | CONST | - |
| 0x004a580e | CALL | 0x004a4a40 | UNKNOWN | STACKADDR | CONST | - |
| 0x004a858a | CALL | 0x004a7f40 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x004a8897 | CALL | 0x004a7f40 | DERIVED | DERIVED | CONST | - |
| 0x004a89a1 | CALL | 0x004a7f40 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x004b4a69 | CALL | 0x004b2570 | STACKADDR | DERIVED | CONST | - |
| 0x004bf1ba | CALL | 0x004beb20 | STACKADDR | CALLRET | DEREF_CALLRET | - |
| 0x004c0531 | CALL | 0x004c04a0 | CALLRET | GLOBAL | DERIVED | 93@5,522@5 |
| 0x004c66f2 | JMP | 0x004c66e0 | USERARG | DERIVED | USERARG | 532@3 |
| 0x004c671f | CALL | 0x004c6700 | CALLRET | DERIVED | CONST | 532@4 |
| 0x004c6768 | JMP | 0x004c6750 | DERIVED | USERARG | USERARG | 532@3 |
| 0x004c6788 | JMP | 0x004c6770 | DERIVED | USERARG | USERARG | 532@3 |
| 0x004c67a8 | JMP | 0x004c6790 | GLOBAL | GLOBAL | CONST | 532@6 |
| 0x004c6802 | CALL | 0x004c67b0 | GLOBAL | CALLRET | CONST | 532@4 |
| 0x004c68d5 | CALL | 0x004c68b0 | USERARG | GLOBAL | CONST | 532@4 |
| 0x004c691f | CALL | 0x004c68e0 | GLOBAL | CALLRET | CONST | 532@2 |
| 0x004c8204 | CALL | 0x004c81d0 | USERARG | GLOBAL | DERIVED | - |
| 0x004c8637 | CALL | 0x004c85e0 | DERIVED | UNKNOWN | UNKNOWN | - |
| 0x004c9448 | CALL | 0x004c93a0 | USERFIELD | DERIVED | CONST | - |
| 0x004cc504 | CALL | 0x004cb7b0 | STACKADDR | CALLRET | CONST | - |
| 0x004cc64b | CALL | 0x004cb7b0 | CALLRET | STACKADDR | CONST | - |
| 0x004cc8cd | CALL | 0x004cb7b0 | CALLRET | CALLRET | CONST | - |
| 0x004cd84c | CALL | 0x004cb7b0 | CALLRET | CALLRET | CONST | - |
| 0x004d7053 | CALL | 0x004d6e7d | UNKNOWN | DERIVED | CONST | - |
| 0x004d8ec1 | CALL | 0x004d8e30 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x004d8f78 | CALL | 0x004d8e30 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x004d9d73 | CALL | 0x004d9d30 | UNKNOWN | USERARG | CONST | - |
| 0x004da07b | CALL | 0x004d9fe4 | DEREF_STACK | CALLRET | CONST | - |
| 0x004da103 | CALL | 0x004d9fe4 | USERARG | UNKNOWN | CONST | - |
| 0x004da211 | CALL | 0x004d9fe4 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x004da24d | CALL | 0x004d9fe4 | CALLRET | GLOBAL | CONST | - |
| 0x004da48b | CALL | 0x004da420 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x004db44e | CALL | 0x004db2b0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x004db4ff | CALL | 0x004db2b0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x004df835 | CALL | 0x004df7a0 | DERIVED | USER_PTR | DERIVED | - |
| 0x004df92d | CALL | 0x004df8e0 | DEREF_STACK | UNKNOWN | DERIVED | - |
| 0x004dfa1d | CALL | 0x004df9b0 | DEREF_GLOBAL | UNKNOWN | DERIVED | - |
| 0x004e1b81 | CALL | 0x004e1a70 | STACKADDR | USERARG | CONST | - |
| 0x004e3112 | CALL | 0x004e2db0 | USERFIELD | STACKADDR | CONST | - |
| 0x004e4f3c | CALL | 0x004e4cf8 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x004e4fe0 | CALL | 0x004e4cf8 | STACKADDR | CALLRET | DEREF_STACK | - |
| 0x004e503c | CALL | 0x004e4cf8 | STACK | CALLRET | CALLRET | - |
| 0x004e50ca | CALL | 0x004e4cf8 | STACK | STACK | STACK | - |
| 0x004e6685 | CALL | 0x004e6380 | STACK | STACKADDR | CONST | - |
| 0x004e681c | CALL | 0x004e66a0 | STACK | STACKADDR | CONST | - |
| 0x004ea0aa | CALL | 0x004e9f60 | DEREF_CALLRET | DEREF_DEREF_CALLRET | DEREF_DEREF_CALLRET | - |
| 0x004ef6e6 | CALL | 0x004ef290 | USERFIELD | UNKNOWN | UNKNOWN | 93@2,522@2 |
| 0x004ef7fc | CALL | 0x004ef290 | STACKADDR | STACKADDR | CONST | 93@2,522@2 |
| 0x004ef820 | CALL | 0x004ef290 | STACKADDR | DEREF_DEREF_DEREF_CALLRET | CONST | 93@2,522@2 |
| 0x004ef831 | CALL | 0x004ef290 | STACKADDR | CALLRET | CONST | 93@2,522@2 |
| 0x004ef978 | CALL | 0x004ef843 | STACKADDR | USERFIELD | CONST | - |
| 0x004ef992 | CALL | 0x004ef843 | STACKADDR | STACKADDR | CONST | - |
| 0x004ef9b3 | CALL | 0x004ef843 | STACKADDR | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x004f00f7 | CALL | 0x004efc80 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x004f0107 | CALL | 0x004efc80 | CALLRET | CALLRET | CONST | - |
| 0x004f012b | CALL | 0x004efc80 | DERIVED | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x004f0d69 | CALL | 0x004f0d00 | USERARG | USERARG | CONST | - |
| 0x004f1aa9 | JMP | 0x004f19e0 | STACK | CALLRET | DERIVED | - |
| 0x004f2296 | CALL | 0x004f2277 | STACKADDR | UNKNOWN | CONST | - |
| 0x004f5d3a | JMP | 0x004f5d30 | CALLRET | CALLRET | CONST | - |
| 0x004f834d | CALL | 0x004f8140 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x004f9699 | CALL | 0x004f9670 | DERIVED | USERARG | CONST | 1@5,2@5,23@6+64 |
| 0x004fe478 | CALL | 0x004fe240 | STACKADDR | STACKADDR | CONST | - |
| 0x004fe4c6 | CALL | 0x004fe240 | STACKADDR | STACKADDR | CONST | - |
| 0x00500015 | CALL | 0x004fff60 | UNKNOWN | STACKADDR | CONST | - |
| 0x005000bc | CALL | 0x00500050 | CALLRET | CALLRET | CONST | - |
| 0x00500178 | CALL | 0x00500130 | UNKNOWN | DERIVED | CONST | - |
| 0x0050026e | CALL | 0x005001c0 | CALLRET | STACKADDR | CONST | - |
| 0x0050039f | CALL | 0x005002a0 | CALLRET | CALLRET | CONST | - |
| 0x00500461 | CALL | 0x005003e0 | CALLRET | CALLRET | CONST | - |
| 0x00500596 | CALL | 0x00500510 | CALLRET | CALLRET | CONST | - |
| 0x005006c4 | CALL | 0x00500640 | CALLRET | CALLRET | CONST | - |
| 0x0050076b | CALL | 0x00500640 | CALLRET | CALLRET | CONST | - |
| 0x0050077f | CALL | 0x00500640 | CALLRET | STACKADDR | CONST | - |
| 0x00500793 | CALL | 0x00500640 | STACK | CALLRET | CONST | - |
| 0x005043d1 | CALL | 0x005043a0 | STACKADDR | GLOBAL | CONST | - |
| 0x005078b2 | CALL | 0x00507700 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0051189e | CALL | 0x00511880 | GLOBAL | GLOBAL | CONST | - |
| 0x0051219c | CALL | 0x00511b58 | USERFIELD | UNKNOWN | USERARG | - |
| 0x005131b4 | CALL | 0x00512dd0 | STACK | DERIVED | DERIVED | - |
| 0x005138df | CALL | 0x005136f0 | DERIVED | STACK | STACK | - |
| 0x005138f6 | CALL | 0x005136f0 | DERIVED | STACK | USERARG | - |
| 0x00513b91 | CALL | 0x00513980 | CALLRET | DERIVED | DERIVED | - |
| 0x00513bfc | CALL | 0x00513980 | DERIVED | STACK | UNKNOWN | - |
| 0x00513d42 | CALL | 0x00513980 | DERIVED | UNKNOWN | DERIVED | - |
| 0x00514494 | CALL | 0x00514050 | DEREF_UNKNOWN | USERARG | USERARG | - |
| 0x00516ff7 | CALL | 0x00516e10 | DERIVED | CALLRET | STACK | - |
| 0x005173d3 | CALL | 0x00517280 | DEREF_CALLRET | STACK | CONST | - |
| 0x005173fa | CALL | 0x00517280 | DERIVED | STACK | CALLRET | - |
| 0x00517bdb | CALL | 0x00517a90 | DERIVED | DERIVED | CONST | - |
| 0x00517d59 | CALL | 0x00517c30 | DEREF_DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00517d6b | CALL | 0x00517c30 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00518015 | CALL | 0x00517c30 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00518048 | CALL | 0x00517c30 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x005181bf | CALL | 0x005180c0 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005184a0 | CALL | 0x00518380 | DEREF_DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x005184bd | CALL | 0x00518380 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x005185b1 | CALL | 0x00518380 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00518785 | CALL | 0x00518600 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00518968 | CALL | 0x00518850 | DEREF_DEREF_CALLRET | DERIVED | CONST | - |
| 0x00518a05 | CALL | 0x00518850 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00518b09 | CALL | 0x00518850 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00518b23 | CALL | 0x00518850 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00518b3d | CALL | 0x00518850 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00518b57 | CALL | 0x00518850 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00518cc9 | CALL | 0x00518bc0 | DEREF_DEREF_CALLRET | DERIVED | CONST | - |
| 0x00518ece | CALL | 0x00518db0 | DEREF_DEREF_CALLRET | CALLRET | CONST | - |
| 0x00519579 | CALL | 0x00519440 | DEREF_DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00519e6f | CALL | 0x00519d30 | DERIVED | STACK | CALLRET | - |
| 0x0051a00d | CALL | 0x00519eb0 | STACKADDR | STACKADDR | STACK | - |
| 0x0051a1fa | CALL | 0x0051a15e | STACKADDR | STACKADDR | STACK | - |
| 0x0051a233 | CALL | 0x0051a15e | STACKADDR | DERIVED | CONST | - |
| 0x0051a59d | CALL | 0x0051a470 | DERIVED | STACK | CALLRET | - |
| 0x0051a82f | CALL | 0x0051a710 | DERIVED | STACK | CONST | - |
| 0x0051aa4e | CALL | 0x0051a900 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x0051aabd | CALL | 0x0051a900 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0051adeb | CALL | 0x0051a900 | DERIVED | UNKNOWN | CONST | - |
| 0x0051af3d | CALL | 0x0051a900 | DEREF_CALLRET | DEREF_STACK | CONST | - |
| 0x0051b110 | CALL | 0x0051a900 | DEREF_UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x0051b1a8 | CALL | 0x0051a900 | DERIVED | CALLRET | CALLRET | - |
| 0x0051b448 | CALL | 0x0051a900 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x0051b55e | CALL | 0x0051a900 | DEREF_CALLRET | STACK | STACK | - |
| 0x0051b5e1 | CALL | 0x0051a900 | DEREF_CALLRET | STACK | STACK | - |
| 0x0051bfeb | CALL | 0x0051bd60 | UNKNOWN | STACK | CALLRET | - |
| 0x0051c060 | CALL | 0x0051bd60 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0051c153 | CALL | 0x0051bd60 | USER_PTR | USERFIELD | UNKNOWN | - |
| 0x0051c4a7 | CALL | 0x0051c1e0 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x0051cc3a | CALL | 0x0051c1e0 | USERARG | DEREF_UNKNOWN | CONST | - |
| 0x0051cc9b | CALL | 0x0051c1e0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0051ce29 | CALL | 0x0051c1e0 | UNKNOWN | UNKNOWN | USERARG | - |
| 0x0051ce76 | CALL | 0x0051c1e0 | DEREF_DERIVED | DERIVED | DEREF_DERIVED | - |
| 0x0051d3e5 | CALL | 0x0051c1e0 | UNKNOWN | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | - |
| 0x0051d831 | CALL | 0x0051d797 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0051d927 | CALL | 0x0051d797 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x0051e18e | CALL | 0x0051dfc7 | STACK | STACK | CONST | - |
| 0x0051e2dc | CALL | 0x0051dfc7 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x0051e2f5 | CALL | 0x0051dfc7 | STACKADDR | DERIVED | CONST | - |
| 0x0051e306 | CALL | 0x0051dfc7 | STACKADDR | CALLRET | CONST | - |
| 0x0051e65e | CALL | 0x0051dfc7 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x0051eafb | CALL | 0x0051dfc7 | CALLRET | CALLRET | CALLRET | - |
| 0x0051ebcf | CALL | 0x0051dfc7 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0051ec59 | CALL | 0x0051dfc7 | STACKADDR | GLOBAL | CONST | - |
| 0x0051ec72 | CALL | 0x0051dfc7 | STACKADDR | DERIVED | CONST | - |
| 0x0051ec8b | CALL | 0x0051dfc7 | STACKADDR | DERIVED | CONST | - |
| 0x0051ef93 | CALL | 0x0051dfc7 | DEREF_CONST | DERIVED | CONST | - |
| 0x0051f211 | CALL | 0x0051dfc7 | STACKADDR | DERIVED | CONST | - |
| 0x0051f4fe | CALL | 0x0051f493 | DERIVED | DERIVED | STACK | - |
| 0x005204e9 | CALL | 0x00520480 | CALLRET | CALLRET | CALLRET | - |
| 0x0052054d | CALL | 0x00520480 | STACKADDR | DERIVED | DEREF_CALLRET | - |
| 0x0052098e | CALL | 0x00520940 | STACKADDR | DERIVED | CONST | - |
| 0x005209ab | CALL | 0x00520940 | STACKADDR | DERIVED | CONST | - |
| 0x005209bc | CALL | 0x00520940 | STACKADDR | CALLRET | CONST | - |
| 0x00520baf | CALL | 0x00520b00 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00520bd3 | CALL | 0x00520b00 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00520be4 | CALL | 0x00520b00 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0052112a | CALL | 0x00520b00 | STACK | STACK | STACK | - |
| 0x005212bd | CALL | 0x00520b00 | DERIVED | CALLRET | DERIVED | - |
| 0x0052192a | CALL | 0x00521880 | STACKADDR | DERIVED | CONST | - |
| 0x00521968 | CALL | 0x00521880 | STACKADDR | STACKADDR | CONST | - |
| 0x00521ad7 | CALL | 0x00521a70 | DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x00521b86 | CALL | 0x00521b60 | USERARG | GLOBAL | CONST | - |
| 0x00521bb5 | CALL | 0x00521b60 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00521bd6 | CALL | 0x00521b60 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00521bf5 | CALL | 0x00521b60 | DERIVED | GLOBAL | CONST | - |
| 0x00521c52 | CALL | 0x00521c10 | USERFIELD | DERIVED | CONST | - |
| 0x00521c73 | CALL | 0x00521c10 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00521ca3 | CALL | 0x00521c10 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00521cfc | CALL | 0x00521cd0 | USERFIELD | GLOBAL | CONST | - |
| 0x00521d14 | CALL | 0x00521cd0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00521d30 | CALL | 0x00521cd0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00522194 | CALL | 0x00522000 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x005221b5 | CALL | 0x00522000 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00522ddb | CALL | 0x00522c60 | DERIVED | CALLRET | CONST | - |
| 0x005235dc | CALL | 0x00523273 | STACKADDR | STACK | CONST | - |
| 0x0052368d | CALL | 0x00523273 | STACKADDR | DEREF_CALLRET | DERIVED | - |
| 0x0052374b | CALL | 0x00523273 | STACKADDR | CALLRET | DERIVED | - |
| 0x0052383b | CALL | 0x00523273 | STACKADDR | STACKADDR | CONST | - |
| 0x00523857 | CALL | 0x00523273 | STACKADDR | DERIVED | CONST | - |
| 0x00523873 | CALL | 0x00523273 | STACKADDR | DERIVED | CONST | - |
| 0x005239bf | CALL | 0x00523273 | STACKADDR | STACK | CONST | - |
| 0x00523a5e | CALL | 0x00523273 | STACKADDR | CALLRET | STACK | - |
| 0x00523cf6 | CALL | 0x00523a9b | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00523dbc | CALL | 0x00523a9b | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00523dd4 | CALL | 0x00523a9b | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00524059 | CALL | 0x00523a9b | DEREF_DEREF_CALLRET | STACK | CONST | - |
| 0x005241bc | CALL | 0x00523a9b | STACKADDR | CALLRET | CONST | - |
| 0x005241e9 | CALL | 0x00523a9b | STACKADDR | STACK | STACK | - |
| 0x0052425b | CALL | 0x00523a9b | STACKADDR | STACK | STACK | - |
| 0x00524284 | CALL | 0x00523a9b | STACKADDR | STACKADDR | CONST | - |
| 0x00524387 | CALL | 0x00523a9b | STACKADDR | STACK | CONST | - |
| 0x005244a9 | CALL | 0x00523a9b | DEREF_DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00524cec | CALL | 0x00524533 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00525dd1 | CALL | 0x005258d0 | DEREF_UNKNOWN | STACKADDR | USERARG | - |
| 0x005260fe | CALL | 0x005258d0 | DERIVED | UNKNOWN | CONST | - |
| 0x0052611a | CALL | 0x005258d0 | DERIVED | CALLRET | CONST | - |
| 0x005265bd | CALL | 0x00526460 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00526a29 | CALL | 0x00526630 | UNKNOWN | DEREF_DERIVED | CONST | - |
| 0x0052811f | CALL | 0x005273e0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005282a0 | CALL | 0x005273e0 | DEREF_CALLRET | DEREF_STACK | CONST | - |
| 0x00528341 | CALL | 0x005273e0 | DERIVED | DERIVED | DERIVED | - |
| 0x0052844c | CALL | 0x005273e0 | DEREF_UNKNOWN | DEREF_GLOBAL | DEREF_GLOBAL | - |
| 0x005285e8 | CALL | 0x005273e0 | DERIVED | CALLRET | CALLRET | - |
| 0x005286db | CALL | 0x00528630 | STACKADDR | STACK | CONST | - |
| 0x005286f7 | CALL | 0x00528630 | STACKADDR | DERIVED | CONST | - |
| 0x00528716 | CALL | 0x00528630 | STACKADDR | DERIVED | CONST | - |
| 0x00529dd7 | CALL | 0x005299d0 | DEREF_STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00529e0f | CALL | 0x005299d0 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x0052a0ac | CALL | 0x005299d0 | STACKADDR | STACKADDR | CONST | - |
| 0x0052a0da | CALL | 0x005299d0 | STACKADDR | STACKADDR | CONST | - |
| 0x0052a391 | CALL | 0x005299d0 | GLOBAL | CALLRET | CALLRET | - |
| 0x0052a3bd | CALL | 0x005299d0 | STACKADDR | CALLRET | CONST | - |
| 0x0052a3fd | CALL | 0x005299d0 | CALLRET | GLOBAL | CALLRET | - |
| 0x0052a411 | CALL | 0x005299d0 | CALLRET | STACKADDR | CONST | - |
| 0x0052ae24 | CALL | 0x0052adb0 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x00538c47 | CALL | 0x00538840 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00538fb5 | CALL | 0x00538e60 | DEREF_DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x00539084 | JMP | 0x00539070 | GLOBAL | USERARG | CONST | - |
| 0x00539275 | CALL | 0x00539220 | GLOBAL | GLOBAL | CONST | - |
| 0x005392f4 | CALL | 0x00539220 | DEREF_CALLRET | STACK | CONST | - |
| 0x00539f64 | CALL | 0x00539b60 | GLOBAL | GLOBAL | CONST | - |
| 0x0053f2ea | CALL | 0x0053f280 | STACKADDR | USERARG | CONST | 37@4,59@2,588@4+4 |
| 0x00540e38 | CALL | 0x005402e6 | STACK | STACKADDR | CONST | - |
| 0x005412e3 | CALL | 0x00540f70 | STACKADDR | USERARG | CONST | - |
| 0x0054148d | CALL | 0x00540f70 | STACKADDR | USERARG | CONST | - |
| 0x005416f3 | CALL | 0x005414ec | STACKADDR | USERARG | CONST | - |
| 0x005419db | CALL | 0x005414ec | STACKADDR | USERARG | CONST | - |
| 0x00541cd0 | CALL | 0x005414ec | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00541ea7 | CALL | 0x005414ec | STACKADDR | CALLRET | CONST | - |
| 0x00541f75 | CALL | 0x00541f07 | STACKADDR | CALLRET | CONST | - |
| 0x005420c0 | CALL | 0x00541f07 | CALLRET | CALLRET | CALLRET | - |
| 0x005446dc | CALL | 0x00544300 | CALLRET | STACKADDR | CONST | - |
| 0x005446ee | CALL | 0x00544300 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x005447fb | CALL | 0x00544300 | STACK | STACKADDR | CONST | - |
| 0x00544810 | CALL | 0x00544300 | STACK | STACKADDR | CONST | - |
| 0x00544825 | CALL | 0x00544300 | STACK | STACKADDR | CONST | - |
| 0x00544836 | CALL | 0x00544300 | CALLRET | STACKADDR | CONST | - |
| 0x005448ef | CALL | 0x00544860 | CALLRET | STACKADDR | CONST | - |
| 0x0054495a | CALL | 0x00544860 | CALLRET | STACKADDR | CONST | - |
| 0x005449ee | CALL | 0x005449a0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00544a05 | CALL | 0x005449a0 | CALLRET | STACKADDR | CONST | - |
| 0x00544a3b | CALL | 0x005449a0 | CALLRET | STACKADDR | CONST | - |
| 0x00544a52 | CALL | 0x005449a0 | CALLRET | STACKADDR | CONST | - |
| 0x00544a80 | CALL | 0x005449a0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00544a97 | CALL | 0x005449a0 | CALLRET | STACKADDR | CONST | - |
| 0x00544b06 | CALL | 0x00544afe | DERIVED | STACKADDR | CONST | - |
| 0x0054562f | CALL | 0x005454d0 | STACKADDR | DEREF_GLOBAL | USERARG | - |
| 0x0054565c | CALL | 0x005454d0 | CALLRET | STACKADDR | DEREF_CALLRET | - |
| 0x005458a4 | CALL | 0x00545702 | STACK | UNKNOWN | DERIVED | - |
| 0x0054594d | CALL | 0x00545702 | STACK | DEREF_STACK | DERIVED | - |
| 0x00556a2c | CALL | 0x005567c0 | STACKADDR | DEREF_CALLRET | CALLRET | 59@5,92@5,202@3+12 |
| 0x005578be | CALL | 0x00557310 | CALLRET | CALLRET | CALLRET | 2@6,5@6,12@6+71 |
| 0x0055a091 | CALL | 0x00559e03 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0055a1c1 | CALL | 0x00559e03 | DEREF_UNKNOWN | STACK | DEREF_UNKNOWN | - |
| 0x0055b3bd | CALL | 0x0055b2b0 | CALLRET | STACKADDR | CONST | - |
| 0x0055b43e | CALL | 0x0055b2b0 | CALLRET | CALLRET | CONST | - |
| 0x0055b44e | CALL | 0x0055b2b0 | CALLRET | CALLRET | CONST | - |
| 0x00564054 | CALL | 0x00563fd0 | CALLRET | CALLRET | CONST | 334@4 |
| 0x005640d6 | CALL | 0x00563fd0 | STACK | DEREF_UNKNOWN | CONST | 334@4 |
| 0x005641a4 | CALL | 0x00564120 | CALLRET | CALLRET | CONST | 334@5 |
| 0x00564226 | CALL | 0x00564120 | STACK | DEREF_UNKNOWN | CONST | 334@5 |
| 0x00564626 | CALL | 0x00564520 | STACKADDR | STACKADDR | CONST | - |
| 0x00564638 | CALL | 0x00564520 | STACKADDR | CALLRET | CALLRET | - |
| 0x0056489b | CALL | 0x005646e0 | STACKADDR | CALLRET | CONST | - |
| 0x00564934 | CALL | 0x005646e0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00564bc1 | CALL | 0x005649c0 | STACKADDR | DEREF_CALLRET | UNKNOWN | - |
| 0x00564f9b | CALL | 0x00564f40 | DERIVED | DERIVED | CONST | - |
| 0x00564fad | CALL | 0x00564f40 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0056540d | CALL | 0x00565390 | STACKADDR | CALLRET | CONST | - |
| 0x00565b4d | CALL | 0x00565ae0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00565c14 | CALL | 0x00565ba0 | DERIVED | DERIVED | CONST | - |
| 0x00566743 | CALL | 0x005666d0 | GLOBAL | USERARG | CONST | - |
| 0x00566e65 | CALL | 0x00566bd0 | STACKADDR | UNKNOWN | CONST | 334@3 |
| 0x00566eb5 | CALL | 0x00566bd0 | STACKADDR | STACKADDR | CONST | 334@3 |
| 0x00566f46 | CALL | 0x00566f35 | STACKADDR | UNKNOWN | CONST | - |
| 0x00569256 | CALL | 0x00568d10 | STACKADDR | DERIVED | UNKNOWN | - |
| 0x0056a445 | CALL | 0x0056a3e0 | DEREF_GLOBAL | DERIVED | DERIVED | 532@5 |
| 0x0056a4ce | CALL | 0x0056a470 | DERIVED | UNKNOWN | DERIVED | 532@6 |
| 0x0056aab1 | CALL | 0x0056a730 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0056c0eb | CALL | 0x0056b400 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x005702d0 | CALL | 0x0056f5c2 | STACKADDR | UNKNOWN | CONST | - |
| 0x005702f1 | CALL | 0x0056f5c2 | STACKADDR | UNKNOWN | CONST | - |
| 0x0057db35 | CALL | 0x0057da60 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0057db5e | CALL | 0x0057da60 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00580e33 | CALL | 0x00580af4 | USERFIELD | DEREF_UNKNOWN | DERIVED | - |
| 0x00580ed6 | CALL | 0x00580af4 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00582f62 | CALL | 0x00582ca0 | USER_PTR | USER_PTR | CONST | - |
| 0x00582fba | CALL | 0x00582ca0 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x0058339d | CALL | 0x00583126 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x0058411b | CALL | 0x00583126 | UNKNOWN | GLOBAL | CONST | - |
| 0x005862ef | CALL | 0x00585940 | DERIVED | DEREF_STACK | DERIVED | - |
| 0x0058997e | CALL | 0x00589960 | UNKNOWN | USERARG | CONST | - |
| 0x005938c4 | CALL | 0x00593800 | UNKNOWN | UNKNOWN | CONST | - |
| 0x0059398b | CALL | 0x00593910 | CALLRET | CALLRET | CALLRET | - |
| 0x00595ca8 | CALL | 0x00595b80 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x00595f73 | CALL | 0x00595b80 | STACKADDR | CALLRET | CONST | - |
| 0x00596b93 | CALL | 0x005966b1 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00596c03 | CALL | 0x005966b1 | DEREF_CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | - |
| 0x00596c4a | CALL | 0x005966b1 | DEREF_UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00596ed1 | CALL | 0x005966b1 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00596f30 | CALL | 0x005966b1 | DEREF_CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | - |
| 0x00596f7d | CALL | 0x005966b1 | USERFIELD | UNKNOWN | UNKNOWN | - |
| 0x00596fe6 | CALL | 0x005966b1 | DERIVED | DEREF_UNKNOWN | CONST | - |
| 0x00597058 | CALL | 0x005966b1 | DEREF_CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | - |
| 0x005970a6 | CALL | 0x005966b1 | DEREF_UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00597138 | CALL | 0x005966b1 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00597218 | CALL | 0x005966b1 | DERIVED | GLOBAL | CONST | - |
| 0x005972d4 | CALL | 0x005966b1 | DERIVED | GLOBAL | CONST | - |
| 0x0059761c | CALL | 0x005966b1 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x005976ba | CALL | 0x005966b1 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00597831 | CALL | 0x005966b1 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00597988 | CALL | 0x005966b1 | DEREF_STACK | DEREF_CALLRET | CONST | - |
| 0x00598019 | CALL | 0x005966b1 | DERIVED | USERFIELD | UNKNOWN | - |
| 0x0059806d | CALL | 0x005966b1 | DERIVED | DEREF_STACK | CALLRET | - |
| 0x005980c9 | CALL | 0x005966b1 | DERIVED | DEREF_STACK | CALLRET | - |
| 0x005982fe | CALL | 0x005966b1 | STACKADDR | DEREF_STACK | CONST | - |
| 0x00598368 | CALL | 0x005966b1 | STACKADDR | DEREF_STACK | CONST | - |
| 0x00598524 | CALL | 0x005966b1 | DEREF_CALLRET | STACK | CONST | - |
| 0x005985b3 | CALL | 0x005966b1 | DERIVED | STACK | USERARG | - |
| 0x00598a8c | CALL | 0x005966b1 | DERIVED | STACKADDR | DERIVED | - |
| 0x00598b8a | CALL | 0x005966b1 | DERIVED | GLOBAL | CONST | - |
| 0x00598f0f | CALL | 0x005966b1 | DERIVED | STACKADDR | CONST | - |
| 0x00598f5c | CALL | 0x005966b1 | DERIVED | STACKADDR | CONST | - |
| 0x00598fed | CALL | 0x005966b1 | DERIVED | STACKADDR | CONST | - |
| 0x00599023 | CALL | 0x005966b1 | DERIVED | STACKADDR | CONST | - |
| 0x0059916b | CALL | 0x005966b1 | DERIVED | STACKADDR | CONST | - |
| 0x0059948b | CALL | 0x005966b1 | DERIVED | DEREF_STACK | UNKNOWN | - |
| 0x005995cf | CALL | 0x005966b1 | STACK | CALLRET | CONST | - |
| 0x00599b31 | CALL | 0x005966b1 | DERIVED | DEREF_STACK | CONST | - |
| 0x00599b89 | CALL | 0x005966b1 | DERIVED | DEREF_STACK | DEREF_STACK | - |
| 0x00599d94 | CALL | 0x005966b1 | DERIVED | GLOBAL | CONST | - |
| 0x0059a0ca | CALL | 0x005966b1 | DERIVED | CONST | CONST | - |
| 0x0059a410 | CALL | 0x005966b1 | USERFIELD | DERIVED | CONST | - |
| 0x0059a64f | CALL | 0x005966b1 | STACKADDR | DERIVED | CONST | - |
| 0x0059a945 | CALL | 0x005966b1 | DEREF_CALLRET | CALLRET | STACK | - |
| 0x0059aa2b | CALL | 0x005966b1 | UNKNOWN | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x0059abf0 | CALL | 0x005966b1 | STACKADDR | USERFIELD | CONST | - |
| 0x0059ac02 | CALL | 0x005966b1 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x0059ac14 | CALL | 0x005966b1 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x0059b6cf | CALL | 0x0059b2a0 | STACKADDR | DERIVED | CONST | - |
| 0x0059b8dc | CALL | 0x0059b2a0 | UNKNOWN | DEREF_STACK | DEREF_STACK | - |
| 0x0059b9ea | CALL | 0x0059b2a0 | STACKADDR | DEREF_STACK | CONST | - |
| 0x0059bc6a | CALL | 0x0059bac1 | STACKADDR | DEREF_STACK | CONST | - |
| 0x0059bd31 | CALL | 0x0059bac1 | DEREF_UNKNOWN | DEREF_STACK | CONST | - |
| 0x0059bdf5 | CALL | 0x0059bdc4 | STACKADDR | DERIVED | CONST | - |
| 0x0059bf3d | CALL | 0x0059bdc4 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0059cdd0 | CALL | 0x0059cc50 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0059d2b8 | CALL | 0x0059d1a0 | DERIVED | DERIVED | USERARG | - |
| 0x0059d343 | CALL | 0x0059d1a0 | DERIVED | DERIVED | CONST | - |
| 0x0059d507 | CALL | 0x0059d400 | DERIVED | DERIVED | UNKNOWN | - |
| 0x0059d797 | CALL | 0x0059d6d0 | DEREF_CALLRET | STACK | CONST | - |
| 0x0059d8fd | CALL | 0x0059d810 | DERIVED | STACK | CONST | - |
| 0x0059dc9f | CALL | 0x0059dbf0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0059dd66 | CALL | 0x0059dd20 | DERIVED | CONST | USERARG | - |
| 0x0059de3b | CALL | 0x0059dd80 | DEREF_CALLRET | STACK | CONST | - |
| 0x0059def6 | CALL | 0x0059deb0 | DERIVED | USERARG | USERARG | - |
| 0x0059df56 | CALL | 0x0059df10 | DERIVED | USERARG | USERARG | - |
| 0x0059dfb6 | CALL | 0x0059df70 | DERIVED | USERARG | USERARG | - |
| 0x0059e03b | CALL | 0x0059dfd0 | DEREF_USER_PTR | STACKADDR | CONST | - |
| 0x0059e4a4 | CALL | 0x0059e420 | DERIVED | CALLRET | CALLRET | - |
| 0x0059e625 | CALL | 0x0059e5a0 | DERIVED | CALLRET | CALLRET | - |
| 0x0059e673 | CALL | 0x0059e5a0 | DERIVED | CALLRET | CALLRET | - |
| 0x005a0072 | CALL | 0x0059ff80 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005a0084 | CALL | 0x0059ff80 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005a0099 | CALL | 0x0059ff80 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x005a0c2d | CALL | 0x005a09d6 | STACKADDR | STACK | CONST | - |
| 0x005a0dc2 | CALL | 0x005a09d6 | DEREF_CALLRET | STACK | CONST | - |
| 0x005a0e3b | CALL | 0x005a09d6 | STACKADDR | STACK | CONST | - |
| 0x005a23e4 | CALL | 0x005a1f20 | DEREF_STACK | DEREF_DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | - |
| 0x005a2594 | CALL | 0x005a1f20 | DERIVED | DEREF_UNKNOWN | USERARG | - |
| 0x005a2900 | CALL | 0x005a1f20 | DEREF_STACK | UNKNOWN | CONST | - |
| 0x005a338a | CALL | 0x005a32a0 | STACK | DERIVED | CONST | - |
| 0x005a35a6 | CALL | 0x005a34f0 | DEREF_CALLRET | STACK | CONST | - |
| 0x005a3715 | CALL | 0x005a3650 | DEREF_CALLRET | STACK | CONST | - |
| 0x005a424d | CALL | 0x005a4200 | STACKADDR | CALLRET | CONST | 55@5,334@2,532@6+2 |
| 0x005a4c60 | CALL | 0x005a4c20 | STACKADDR | GLOBAL | CONST | 1@6,2@4,5@4+47 |
| 0x005a4cd0 | CALL | 0x005a4c90 | STACKADDR | GLOBAL | CONST | 4@5,5@4,30@5+30 |
| 0x005a4d40 | CALL | 0x005a4d00 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x005a4db0 | CALL | 0x005a4d70 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x005a4e20 | CALL | 0x005a4de0 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x005a4e90 | CALL | 0x005a4e50 | STACKADDR | GLOBAL | CONST | 0@5,1@4,2@5+613 |
| 0x005a4f01 | CALL | 0x005a4ec0 | STACKADDR | GLOBAL | CONST | 232@2,431@4 |
| 0x005a4f36 | CALL | 0x005a4ec0 | STACKADDR | GLOBAL | CONST | 232@2,431@4 |
| 0x005a4fb0 | CALL | 0x005a4f70 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x005a5020 | CALL | 0x005a4fe0 | STACKADDR | GLOBAL | CONST | 5@6,42@6,59@2+26 |
| 0x005a5090 | CALL | 0x005a5050 | STACKADDR | GLOBAL | CONST | - |
| 0x005a5100 | CALL | 0x005a50c0 | STACKADDR | GLOBAL | CONST | 5@6,42@6,59@2+26 |
| 0x005a5170 | CALL | 0x005a5130 | STACKADDR | GLOBAL | CONST | 59@3 |
| 0x005a51e0 | CALL | 0x005a51a0 | STACKADDR | GLOBAL | CONST | 59@4 |
| 0x005a5250 | CALL | 0x005a5210 | STACKADDR | GLOBAL | CONST | - |
| 0x005a52c0 | CALL | 0x005a5280 | STACKADDR | GLOBAL | CONST | - |
| 0x005a5339 | CALL | 0x005a52f0 | STACKADDR | GLOBAL | CONST | - |
| 0x005a53c2 | CALL | 0x005a52f0 | STACKADDR | GLOBAL | CONST | - |
| 0x005a5430 | CALL | 0x005a53f0 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x005a54a0 | CALL | 0x005a5460 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x005a5510 | CALL | 0x005a54d0 | STACKADDR | GLOBAL | CONST | - |
| 0x005a5590 | CALL | 0x005a5550 | STACKADDR | GLOBAL | CONST | 2@6,23@6,54@6+58 |
| 0x005a5600 | CALL | 0x005a5550 | STACKADDR | GLOBAL | CONST | 2@6,23@6,54@6+58 |
| 0x005a5670 | CALL | 0x005a5630 | STACKADDR | GLOBAL | CONST | - |
| 0x005a56e0 | CALL | 0x005a56a0 | STACKADDR | GLOBAL | CONST | - |
| 0x005a5750 | CALL | 0x005a5710 | STACKADDR | GLOBAL | CONST | 59@4 |
| 0x005a57c0 | CALL | 0x005a5780 | STACKADDR | GLOBAL | CONST | 532@6 |
| 0x005a5830 | CALL | 0x005a57f0 | STACKADDR | GLOBAL | CONST | 90@1 |
| 0x005a58a0 | CALL | 0x005a5860 | STACKADDR | GLOBAL | CONST | 1@5,37@6,59@4+34 |
| 0x005a5910 | CALL | 0x005a58d0 | STACKADDR | GLOBAL | CONST | 0@5,2@5,3@5+564 |
| 0x005a59c0 | CALL | 0x005a5980 | STACKADDR | GLOBAL | CONST | - |
| 0x005a5a30 | CALL | 0x005a59f0 | STACKADDR | GLOBAL | CONST | 1@6,2@4,5@4+47 |
| 0x005a5aa0 | CALL | 0x005a5a60 | STACKADDR | GLOBAL | CONST | - |
| 0x005a5b10 | CALL | 0x005a5ad0 | STACKADDR | GLOBAL | CONST | 532@5 |
| 0x005a5e4e | CALL | 0x005a5d80 | DERIVED | DERIVED | CONST | 37@2,652@2 |
| 0x005a614f | CALL | 0x005a60d0 | DERIVED | DERIVED | CONST | 37@2,652@2 |
| 0x005ab736 | CALL | 0x005ab430 | UNKNOWN | STACK | DERIVED | - |
| 0x005abbd6 | CALL | 0x005abb00 | STACKADDR | GLOBAL | CONST | - |
| 0x005afc63 | CALL | 0x005afa70 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005afd7f | CALL | 0x005afa70 | DEREF_DERIVED | STACKADDR | CONST | - |
| 0x005b3c38 | CALL | 0x005b39a0 | STACKADDR | GLOBAL | CONST | - |
| 0x005b3cdf | CALL | 0x005b39a0 | STACKADDR | GLOBAL | CONST | - |
| 0x005b3d84 | CALL | 0x005b39a0 | STACKADDR | GLOBAL | CONST | - |
| 0x005b3e69 | CALL | 0x005b39a0 | CALLRET | DERIVED | CONST | - |
| 0x005b3ebc | CALL | 0x005b39a0 | STACKADDR | GLOBAL | CONST | - |
| 0x005b4265 | CALL | 0x005b4200 | DEREF_STACK | CALLRET | CONST | - |
| 0x005b6214 | CALL | 0x005b61c0 | STACKADDR | GLOBAL | CONST | - |
| 0x005b63ff | CALL | 0x005b63c0 | USERARG | DERIVED | CONST | - |
| 0x005b6455 | CALL | 0x005b6440 | USERARG | GLOBAL | CONST | - |
| 0x005b6485 | CALL | 0x005b6470 | USERARG | GLOBAL | CONST | - |
| 0x005b64b5 | CALL | 0x005b64a0 | USERARG | GLOBAL | CONST | - |
| 0x005bc797 | CALL | 0x005bc77f | STACKADDR | GLOBAL | CONST | - |
| 0x005c8fab | CALL | 0x005c8e90 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005cd6a1 | CALL | 0x005cd20e | UNKNOWN | GLOBAL | DERIVED | - |
| 0x005cfd63 | CALL | 0x005cf91c | DERIVED | CALLRET | CONST | - |
| 0x005d0031 | CALL | 0x005cf91c | DERIVED | CALLRET | CONST | - |
| 0x005d0c1f | CALL | 0x005d0b80 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005d0d0d | CALL | 0x005d0c60 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005d2cea | CALL | 0x005d2b60 | STACK | DEREF_UNKNOWN | USERARG | - |
| 0x005d318e | CALL | 0x005d2d50 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x005d3203 | CALL | 0x005d2d50 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x005d3b75 | CALL | 0x005d38d0 | DEREF_CALLRET | DERIVED | CALLRET | - |
| 0x005d3d91 | CALL | 0x005d38d0 | STACKADDR | DERIVED | CONST | - |
| 0x005d45ac | CALL | 0x005d4470 | DERIVED | STACK | CALLRET | - |
| 0x005e13ea | CALL | 0x005e13a0 | CALLRET | CALLRET | CONST | 36@1,42@4,92@1+3 |
| 0x005e2cf9 | CALL | 0x005e2cc0 | CALLRET | GLOBAL | CONST | 1@2,4@3,5@4+59 |
| 0x005e2d69 | CALL | 0x005e2d30 | CALLRET | GLOBAL | CONST | 532@6 |
| 0x005e2dd9 | CALL | 0x005e2da0 | CALLRET | GLOBAL | CONST | 1@2,4@3,5@4+57 |
| 0x005e2e49 | CALL | 0x005e2e10 | CALLRET | GLOBAL | CONST | - |
| 0x005e2eb9 | CALL | 0x005e2e80 | CALLRET | GLOBAL | CONST | 532@4,601@2 |
| 0x005e2f39 | CALL | 0x005e2f00 | CALLRET | GLOBAL | CONST | - |
| 0x005e2fb9 | CALL | 0x005e2f80 | CALLRET | GLOBAL | CONST | 532@4 |
| 0x005e3019 | CALL | 0x005e2fe0 | CALLRET | GLOBAL | CONST | - |
| 0x005e3089 | CALL | 0x005e3050 | CALLRET | GLOBAL | CONST | 588@6 |
| 0x005e30f9 | CALL | 0x005e30c0 | CALLRET | GLOBAL | CONST | 1@2,4@3,5@4+57 |
| 0x005e3b1c | CALL | 0x005e30c0 | UNKNOWN | DEREF_UNKNOWN | CONST | 1@2,4@3,5@4+57 |
| 0x005e3c76 | CALL | 0x005e30c0 | STACKADDR | DEREF_CALLRET | CONST | 1@2,4@3,5@4+57 |
| 0x005e4288 | CALL | 0x005e30c0 | STACKADDR | USERFIELD | CONST | 1@2,4@3,5@4+57 |
| 0x005e4393 | CALL | 0x005e30c0 | STACKADDR | DEREF_UNKNOWN | CONST | 1@2,4@3,5@4+57 |
| 0x005e5727 | CALL | 0x005e4f10 | DEREF_UNKNOWN | STACKADDR | CONST | 1@3,4@4,5@5+40 |
| 0x005e573b | CALL | 0x005e4f10 | CALLRET | STACKADDR | CONST | 1@3,4@4,5@5+40 |
| 0x005e5779 | CALL | 0x005e4f10 | STACKADDR | STACK | CONST | 1@3,4@4,5@5+40 |
| 0x005e5951 | CALL | 0x005e5850 | DERIVED | STACKADDR | CONST | 1@3,4@4,5@5+40 |
| 0x005e5a15 | CALL | 0x005e5850 | STACKADDR | CALLRET | CONST | 1@3,4@4,5@5+40 |
| 0x005e81fd | CALL | 0x005e8190 | STACKADDR | CALLRET | CONST | 334@3 |
| 0x005e832d | CALL | 0x005e8260 | STACKADDR | CALLRET | CONST | - |
| 0x005f1654 | CALL | 0x005f12c0 | GLOBAL | GLOBAL | CONST | - |
| 0x005f17c0 | CALL | 0x005f12c0 | DERIVED | STACKADDR | CONST | - |
| 0x005f6f89 | CALL | 0x005f6e90 | CALLRET | STACK | CALLRET | - |
| 0x005f7077 | CALL | 0x005f6e90 | DEREF_CONST | DEREF_DEREF_CONST | DEREF_DEREF_CONST | - |
| 0x005f7216 | CALL | 0x005f6e90 | CALLRET | STACK | CALLRET | - |
| 0x005f729f | CALL | 0x005f6e90 | USERFIELD | USER_PTR | USER_PTR | - |
| 0x005fea1e | CALL | 0x005fe9b0 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x005feb74 | CALL | 0x005feaa0 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x005fee11 | CALL | 0x005feaa0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x005fef63 | CALL | 0x005fef10 | STACKADDR | CALLRET | DEREF_CALLRET | - |
| 0x005ffced | CALL | 0x005ff860 | STACKADDR | CALLRET | CONST | - |
| 0x006001b7 | CALL | 0x005ff860 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00600215 | CALL | 0x005ff860 | DERIVED | DERIVED | CONST | - |
| 0x00600267 | CALL | 0x005ff860 | STACKADDR | CALLRET | CONST | - |
| 0x006002b2 | CALL | 0x005ff860 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x006003f3 | CALL | 0x005ff860 | UNKNOWN | DERIVED | CONST | - |
| 0x006006f0 | CALL | 0x005ff860 | CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | - |
| 0x006009d0 | CALL | 0x005ff860 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x00600d22 | CALL | 0x005ff860 | DERIVED | STACK | CONST | - |
| 0x00601a27 | CALL | 0x006019b0 | CALLRET | CALLRET | CONST | - |
| 0x00601ad2 | CALL | 0x006019b0 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00606266 | CALL | 0x00605ec0 | GLOBAL | USERARG | UNKNOWN | - |
| 0x0060a1c0 | JMP | 0x0060a150 | USERARG | USERARG | USERARG | - |
| 0x0060b510 | CALL | 0x0060b250 | STACKADDR | STACK | CONST | - |
| 0x0060b528 | CALL | 0x0060b250 | STACKADDR | STACK | CONST | - |
| 0x0060bee2 | CALL | 0x0060bc80 | STACKADDR | STACK | CONST | - |
| 0x0060befa | CALL | 0x0060bc80 | STACKADDR | STACK | CONST | - |
| 0x0060c6f6 | CALL | 0x0060c4a0 | UNKNOWN | DEREF_DEREF_STACK | CONST | - |
| 0x0060c717 | CALL | 0x0060c4a0 | STACKADDR | UNKNOWN | CONST | - |
| 0x0060c736 | CALL | 0x0060c4a0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x0060c948 | CALL | 0x0060c4a0 | STACKADDR | DERIVED | CONST | - |
| 0x0060cca8 | CALL | 0x0060cc70 | CALLRET | CALLRET | CONST | - |
| 0x0060cd24 | CALL | 0x0060ccf0 | CALLRET | CALLRET | CONST | - |
| 0x0060cf33 | CALL | 0x0060cd90 | STACKADDR | STACK | CONST | - |
| 0x0060cf4b | CALL | 0x0060cd90 | STACKADDR | STACK | CONST | - |
| 0x0060d254 | CALL | 0x0060cd90 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0060d2ae | CALL | 0x0060cd90 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0060d2d5 | CALL | 0x0060cd90 | STACKADDR | DERIVED | CONST | - |
| 0x0060d7a8 | CALL | 0x0060d500 | STACKADDR | STACK | CONST | - |
| 0x0060d7c0 | CALL | 0x0060d500 | STACKADDR | STACK | CONST | - |
| 0x0060dc6b | CALL | 0x0060d500 | STACK | STACKADDR | CONST | - |
| 0x0060dd21 | CALL | 0x0060d500 | CALLRET | STACKADDR | CONST | - |
| 0x0060ddb3 | CALL | 0x0060d500 | STACK | STACKADDR | CONST | - |
| 0x0060e208 | CALL | 0x0060e030 | CALLRET | CALLRET | CONST | - |
| 0x0060e29e | CALL | 0x0060e030 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0060e303 | CALL | 0x0060e030 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0060e32a | CALL | 0x0060e030 | STACKADDR | DERIVED | CONST | - |
| 0x0060f14d | CALL | 0x0060f080 | CALLRET | CALLRET | CALLRET | 2@5,5@5,12@4+24 |
| 0x0060f83c | CALL | 0x0060f1e0 | CALLRET | CALLRET | CONST | - |
| 0x0060f8a8 | CALL | 0x0060f1e0 | CALLRET | GLOBAL | CONST | - |
| 0x0060f913 | CALL | 0x0060f1e0 | CALLRET | GLOBAL | CONST | - |
| 0x0060f97e | CALL | 0x0060f1e0 | CALLRET | GLOBAL | CONST | - |
| 0x00611902 | CALL | 0x006118f5 | DEREF_USER_PTR | DEREF_USER_PTR | DERIVED | - |
| 0x00611942 | CALL | 0x006118f5 | USER_PTR | USER_PTR | USERARG | - |
| 0x00612a44 | CALL | 0x00612500 | CALLRET | GLOBAL | CONST | - |
| 0x00614a1a | CALL | 0x006149e0 | DERIVED | USERARG | DERIVED | - |
| 0x00614a87 | CALL | 0x006149e0 | DERIVED | DERIVED | DERIVED | - |
| 0x00617b02 | CALL | 0x006179e0 | DEREF_UNKNOWN | STACKADDR | USERARG | - |
| 0x00617c76 | CALL | 0x00617b20 | DERIVED | DERIVED | CONST | - |
| 0x00617dd3 | CALL | 0x00617cc0 | DERIVED | STACK | CONST | - |
| 0x006182a9 | CALL | 0x006180b0 | DEREF_STACKVAL | DERIVED | CONST | - |
| 0x0061844c | CALL | 0x00618300 | DEREF_DEREF_STACK | STACK | CONST | - |
| 0x006185dc | CALL | 0x00618300 | DEREF_DEREF_STACK | DEREF_CALLRET | CONST | - |
| 0x006185f6 | CALL | 0x00618300 | DERIVED | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00618776 | CALL | 0x00618300 | DEREF_DEREF_STACK | DEREF_STACK | CONST | - |
| 0x006189dc | CALL | 0x00618300 | DEREF_UNKNOWN | DEREF_STACK | DEREF_STACK | - |
| 0x00618ba7 | CALL | 0x00618300 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00618eed | CALL | 0x00618dd0 | DEREF_DEREF_STACK | DEREF_CALLRET | CONST | - |
| 0x0061916a | CALL | 0x00618dd0 | DEREF_UNKNOWN | USERFIELD | USERFIELD | - |
| 0x0061926e | CALL | 0x00618dd0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00619687 | CALL | 0x00619480 | DEREF_DEREF_STACK | DERIVED | CONST | - |
| 0x0061993d | CALL | 0x00619480 | DEREF_DEREF_STACK | DERIVED | CONST | - |
| 0x00619a50 | CALL | 0x00619480 | DEREF_DERIVED | DERIVED | DEREF_CALLRET | - |
| 0x00619af2 | CALL | 0x00619480 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00619c7b | CALL | 0x00619480 | DEREF_DEREF_STACK | DERIVED | CONST | - |
| 0x00619df4 | CALL | 0x00619480 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00619ff6 | CALL | 0x00619480 | DEREF_DEREF_STACK | DERIVED | CONST | - |
| 0x0061a0aa | CALL | 0x00619480 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x0061a0c1 | CALL | 0x00619480 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061a204 | CALL | 0x00619480 | DEREF_DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x0061a2dd | CALL | 0x00619480 | DEREF_DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x0061a2f7 | CALL | 0x00619480 | DEREF_STACK | DERIVED | CONST | - |
| 0x0061a311 | CALL | 0x00619480 | DEREF_STACK | DERIVED | CONST | - |
| 0x0061a32b | CALL | 0x00619480 | DEREF_STACK | DERIVED | CONST | - |
| 0x0061a350 | CALL | 0x00619480 | DEREF_STACK | DERIVED | CONST | - |
| 0x0061a3b0 | CALL | 0x00619480 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061a5e0 | CALL | 0x0061a460 | DEREF_DEREF_STACK | DEREF_STACK | CONST | - |
| 0x0061a688 | CALL | 0x0061a460 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x0061a69f | CALL | 0x0061a460 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061a783 | CALL | 0x0061a460 | DEREF_DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061a87a | CALL | 0x0061a460 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061a88c | CALL | 0x0061a460 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061a89e | CALL | 0x0061a460 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061a8b0 | CALL | 0x0061a460 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061a8d2 | CALL | 0x0061a460 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061a92c | CALL | 0x0061a460 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061aaca | CALL | 0x0061a460 | DEREF_DEREF_STACK | DERIVED | CONST | - |
| 0x0061acca | CALL | 0x0061abc0 | DEREF_DEREF_STACK | DERIVED | CONST | - |
| 0x0061aec7 | CALL | 0x0061abc0 | DEREF_DEREF_STACK | CALLRET | CONST | - |
| 0x0061b0bb | CALL | 0x0061abc0 | DEREF_DEREF_STACK | CALLRET | CONST | - |
| 0x0061b16a | CALL | 0x0061abc0 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061b17f | CALL | 0x0061abc0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061b3db | CALL | 0x0061abc0 | DEREF_DEREF_STACK | CALLRET | CONST | - |
| 0x0061b48a | CALL | 0x0061abc0 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061b49f | CALL | 0x0061abc0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061b83c | CALL | 0x0061abc0 | DEREF_DEREF_STACK | DERIVED | CONST | - |
| 0x0061b953 | CALL | 0x0061abc0 | DEREF_DERIVED | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x0061b9f6 | CALL | 0x0061abc0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061c0e3 | CALL | 0x0061bfa0 | DEREF_DEREF_STACK | STACK | CONST | - |
| 0x0061c118 | CALL | 0x0061bfa0 | DERIVED | STACK | DERIVED | - |
| 0x0061c2cd | CALL | 0x0061c170 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061c315 | CALL | 0x0061c170 | DERIVED | DERIVED | DERIVED | - |
| 0x0061c4af | CALL | 0x0061c360 | DEREF_DEREF_STACK | STACK | CONST | - |
| 0x0061c4f4 | CALL | 0x0061c360 | DERIVED | DERIVED | DERIVED | - |
| 0x0061c669 | CALL | 0x0061c540 | DEREF_DEREF_STACK | DEREF_CALLRET | CONST | - |
| 0x0061c6fe | CALL | 0x0061c540 | DERIVED | DERIVED | DERIVED | - |
| 0x0061d202 | CALL | 0x0061cf50 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x0061d225 | CALL | 0x0061cf50 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x0061da4f | CALL | 0x0061d630 | DEREF_UNKNOWN | DERIVED | DEREF_DERIVED | - |
| 0x0061ed8b | CALL | 0x0061ec50 | DERIVED | CALLRET | CONST | - |
| 0x0061ef1e | CALL | 0x0061eef4 | STACK | DERIVED | CONST | - |
| 0x0061f777 | CALL | 0x0061f670 | DERIVED | STACK | CALLRET | - |
| 0x0061fa46 | CALL | 0x0061f930 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x0061fc3f | CALL | 0x0061f930 | DERIVED | DERIVED | DEREF_CALLRET | - |
| 0x0061fdbd | CALL | 0x0061f930 | DEREF_DEREF_STACK | STACK | CONST | - |
| 0x0061fdd2 | CALL | 0x0061f930 | DERIVED | STACK | CONST | - |
| 0x0061ff1b | CALL | 0x0061fe20 | DEREF_DEREF_STACK | STACK | CONST | - |
| 0x0061ff3d | CALL | 0x0061fe20 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0061ff72 | CALL | 0x0061fe20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061ff88 | CALL | 0x0061fe20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0061ffc9 | CALL | 0x0061fe20 | DERIVED | DERIVED | CONST | - |
| 0x00620106 | CALL | 0x00620010 | DEREF_DEREF_STACK | CALLRET | CONST | - |
| 0x0062028f | CALL | 0x00620160 | DERIVED | DEREF_STACK | CALLRET | - |
| 0x00621125 | CALL | 0x00620d3f | DERIVED | DERIVED | CONST | - |
| 0x00621145 | CALL | 0x00620d3f | DERIVED | CALLRET | CONST | - |
| 0x006215d5 | CALL | 0x00621510 | DERIVED | CALLRET | CALLRET | - |
| 0x00623e07 | CALL | 0x00623aa0 | DEREF_GLOBAL | STACKADDR | DERIVED | - |
| 0x0062485c | CALL | 0x0062463f | DEREF_STACK | STACKADDR | DERIVED | - |
| 0x0062d7fc | CALL | 0x0062d6e0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x0062f230 | CALL | 0x0062e8e0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00639cbc | CALL | 0x00639c60 | STACKADDR | GLOBAL | CONST | - |
| 0x00639ce2 | CALL | 0x00639c60 | CALLRET | CALLRET | CONST | - |
| 0x00639e74 | CALL | 0x00639e00 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00639e9e | CALL | 0x00639e00 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00639eb6 | CALL | 0x00639e00 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00639ef5 | CALL | 0x00639e00 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00639f31 | CALL | 0x00639e00 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00639f5f | CALL | 0x00639e00 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00639f9a | JMP | 0x00639e00 | DERIVED | DERIVED | CONST | - |
| 0x0063a289 | CALL | 0x0063a150 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x0063a301 | CALL | 0x0063a150 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0063a332 | CALL | 0x0063a150 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0063a34a | CALL | 0x0063a150 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0063a37b | CALL | 0x0063a150 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0063a3ba | CALL | 0x0063a150 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0063a3eb | CALL | 0x0063a150 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0063a728 | CALL | 0x0063a470 | STACKADDR | USERFIELD | CONST | - |
| 0x0063a740 | CALL | 0x0063a470 | STACKADDR | STACKADDR | CONST | - |
| 0x0063aab4 | CALL | 0x0063a470 | STACKADDR | GLOBAL | CONST | - |
| 0x0063aada | CALL | 0x0063a470 | CALLRET | CALLRET | CONST | - |
| 0x0063acba | CALL | 0x0063a470 | STACKADDR | GLOBAL | CONST | - |
| 0x0063ace0 | CALL | 0x0063a470 | CALLRET | CALLRET | CONST | - |
| 0x0063af62 | CALL | 0x0063aec0 | STACKADDR | USERFIELD | CONST | - |
| 0x0063af77 | CALL | 0x0063aec0 | STACKADDR | STACKADDR | CONST | - |
| 0x0063b290 | CALL | 0x0063b1a0 | STACKADDR | GLOBAL | CONST | - |
| 0x0063b2b6 | CALL | 0x0063b1a0 | CALLRET | CALLRET | CONST | - |
| 0x0063b377 | CALL | 0x0063b1a0 | STACKADDR | CALLRET | CONST | - |
| 0x0063b42e | CALL | 0x0063b1a0 | STACKADDR | CALLRET | CONST | - |
| 0x0063b50a | CALL | 0x0063b1a0 | STACKADDR | CALLRET | CONST | - |
| 0x0063b5d9 | CALL | 0x0063b1a0 | STACKADDR | CALLRET | CONST | - |
| 0x0063b63c | CALL | 0x0063b1a0 | STACKADDR | STACK | CONST | - |
| 0x0063b6b0 | CALL | 0x0063b1a0 | STACKADDR | CALLRET | CONST | - |
| 0x0063bbbb | CALL | 0x0063ba70 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0063bbcf | CALL | 0x0063ba70 | STACKADDR | CALLRET | CONST | - |
| 0x0063bc2e | CALL | 0x0063ba70 | STACKADDR | CALLRET | CONST | - |
| 0x0063bd33 | CALL | 0x0063ba70 | STACKADDR | CALLRET | CONST | - |
| 0x0063bd76 | CALL | 0x0063ba70 | STACKADDR | STACK | CONST | - |
| 0x0063bde7 | CALL | 0x0063ba70 | STACKADDR | CALLRET | CONST | - |
| 0x0063beb1 | CALL | 0x0063ba70 | CALLRET | CALLRET | CONST | - |
| 0x0063bf57 | CALL | 0x0063ba70 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0063bf6b | CALL | 0x0063ba70 | STACKADDR | CALLRET | CONST | - |
| 0x0063bfca | CALL | 0x0063ba70 | STACKADDR | CALLRET | CONST | - |
| 0x0063c1d9 | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063c202 | CALL | 0x0063c090 | CALLRET | CALLRET | CONST | - |
| 0x0063c24d | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063c26f | CALL | 0x0063c090 | STACK | CALLRET | CONST | - |
| 0x0063c33f | CALL | 0x0063c090 | DEREF_CALLRET | DEREF_STACK | CONST | - |
| 0x0063c35a | CALL | 0x0063c090 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0063c456 | CALL | 0x0063c090 | USERFIELD | UNKNOWN | CONST | - |
| 0x0063c519 | CALL | 0x0063c090 | USERFIELD | UNKNOWN | CONST | - |
| 0x0063c5cc | CALL | 0x0063c090 | DERIVED | USERFIELD | CONST | - |
| 0x0063c5e4 | CALL | 0x0063c090 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x0063c6ae | CALL | 0x0063c090 | DERIVED | UNKNOWN | CONST | - |
| 0x0063c6da | CALL | 0x0063c090 | DERIVED | UNKNOWN | CONST | - |
| 0x0063c78d | CALL | 0x0063c090 | DERIVED | DERIVED | CONST | - |
| 0x0063c9d0 | CALL | 0x0063c090 | STACKADDR | USERFIELD | CONST | - |
| 0x0063c9e8 | CALL | 0x0063c090 | STACKADDR | STACKADDR | CONST | - |
| 0x0063cb5d | CALL | 0x0063c090 | USERFIELD | UNKNOWN | CONST | - |
| 0x0063cc91 | CALL | 0x0063c090 | STACKADDR | STACK | CONST | - |
| 0x0063cca9 | CALL | 0x0063c090 | STACKADDR | STACKADDR | CONST | - |
| 0x0063cf23 | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063cf50 | CALL | 0x0063c090 | STACKADDR | CALLRET | CONST | - |
| 0x0063d085 | CALL | 0x0063c090 | UNKNOWN | UNKNOWN | CONST | - |
| 0x0063d121 | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063d147 | CALL | 0x0063c090 | CALLRET | CALLRET | CONST | - |
| 0x0063d554 | CALL | 0x0063c090 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x0063d568 | CALL | 0x0063c090 | STACKADDR | CALLRET | CONST | - |
| 0x0063d5c3 | CALL | 0x0063c090 | STACKADDR | CALLRET | CONST | - |
| 0x0063d7a6 | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063d7cc | CALL | 0x0063c090 | CALLRET | CALLRET | CONST | - |
| 0x0063d864 | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063d88a | CALL | 0x0063c090 | CALLRET | CALLRET | CONST | - |
| 0x0063dcd6 | CALL | 0x0063c090 | DEREF_UNKNOWN | USERARG | CONST | - |
| 0x0063dcf1 | CALL | 0x0063c090 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x0063dde6 | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063de13 | CALL | 0x0063c090 | STACKADDR | CALLRET | CONST | - |
| 0x0063e01e | CALL | 0x0063c090 | DEREF_UNKNOWN | USERARG | CONST | - |
| 0x0063e08c | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063e0b9 | CALL | 0x0063c090 | STACKADDR | CALLRET | CONST | - |
| 0x0063e1fb | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063e224 | CALL | 0x0063c090 | CALLRET | CALLRET | CONST | - |
| 0x0063e272 | CALL | 0x0063c090 | STACKADDR | GLOBAL | CONST | - |
| 0x0063e294 | CALL | 0x0063c090 | STACK | CALLRET | CONST | - |
| 0x0063eb50 | CALL | 0x0063e9f0 | STACKADDR | CALLRET | CONST | - |
| 0x0063ec53 | CALL | 0x0063e9f0 | STACKADDR | CALLRET | CONST | - |
| 0x0063ef72 | CALL | 0x0063eed0 | STACKADDR | GLOBAL | CONST | - |
| 0x00641212 | CALL | 0x00641040 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x006417c1 | CALL | 0x00641229 | STACKADDR | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x006417d9 | CALL | 0x00641229 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00641f90 | CALL | 0x00641a00 | USERARG | UNKNOWN | DEREF_UNKNOWN | - |
| 0x00644a3a | CALL | 0x006449f2 | DEREF_GLOBAL | STACKADDR | CONST | - |
| 0x00657a3f | CALL | 0x00657529 | STACKADDR | USERARG | CONST | - |
| 0x00658720 | CALL | 0x006586c0 | STACKADDR | DERIVED | CONST | 622@4 |
| 0x006587bd | CALL | 0x00658760 | STACKADDR | DERIVED | CONST | - |
| 0x00659122 | CALL | 0x00658d90 | USERFIELD | DEREF_UNKNOWN | DERIVED | 0@6,2@5,3@6+585 |
| 0x00659249 | CALL | 0x00659246 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0065ba94 | CALL | 0x0065ba00 | UNKNOWN | DEREF_CALLRET | CONST | - |
| 0x0065c029 | CALL | 0x0065ba00 | DEREF_UNKNOWN | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x0065c08c | CALL | 0x0065ba00 | DEREF_UNKNOWN | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x0065c14e | CALL | 0x0065c0c3 | DEREF_UNKNOWN | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x0065c1b1 | CALL | 0x0065c0c3 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0065c274 | CALL | 0x0065c0c3 | DEREF_DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x0065dbd6 | CALL | 0x0065db57 | STACKADDR | STACK | CONST | - |
| 0x0065dbf2 | CALL | 0x0065db57 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x0065dc06 | CALL | 0x0065db57 | CALLRET | STACKADDR | CONST | - |
| 0x0065ed0b | CALL | 0x0065e9e0 | CALLRET | DEREF_STACK | DEREF_STACK | - |
| 0x0065f240 | CALL | 0x0065f1e0 | CALLRET | CALLRET | CALLRET | - |
| 0x0065fe58 | CALL | 0x0065fd40 | STACKADDR | STACKADDR | CONST | - |
| 0x0066017e | CALL | 0x00660130 | CALLRET | STACKADDR | CONST | - |
| 0x0066022b | CALL | 0x006601b0 | CALLRET | STACKADDR | CONST | - |
| 0x006602d0 | CALL | 0x00660260 | STACKADDR | CALLRET | CONST | - |
| 0x006602f5 | CALL | 0x00660260 | CALLRET | STACKADDR | CONST | - |
| 0x006604ce | CALL | 0x00660440 | STACKADDR | CALLRET | CALLRET | - |
| 0x0066064d | CALL | 0x00660590 | CALLRET | STACKADDR | CALLRET | - |
| 0x006609f9 | CALL | 0x00660960 | STACKADDR | CALLRET | CALLRET | - |
| 0x00660ad8 | CALL | 0x00660a34 | CALLRET | STACKADDR | CALLRET | - |
| 0x00660e3d | CALL | 0x00660b80 | CALLRET | STACKADDR | CONST | - |
| 0x00660fa4 | CALL | 0x00660b80 | STACKADDR | CALLRET | CALLRET | - |
| 0x00661303 | CALL | 0x00660b80 | CALLRET | STACKADDR | CALLRET | - |
| 0x00661461 | CALL | 0x00660b80 | CALLRET | STACKADDR | CONST | - |
| 0x006619a2 | CALL | 0x00660b80 | CALLRET | STACKADDR | CONST | - |
| 0x00661c1c | CALL | 0x00660b80 | DERIVED | STACKADDR | STACK | - |
| 0x0066344e | CALL | 0x00663030 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x006635c5 | CALL | 0x00663030 | STACKADDR | CALLRET | CONST | - |
| 0x00663603 | CALL | 0x00663030 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00663619 | CALL | 0x00663030 | CALLRET | CALLRET | CONST | - |
| 0x00663683 | CALL | 0x00663030 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x0066388a | CALL | 0x00663030 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00663aae | CALL | 0x00663030 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00663ad7 | CALL | 0x00663030 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00663d83 | CALL | 0x00663cb0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00663d9f | CALL | 0x00663cb0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x0066401c | CALL | 0x00663dab | STACKADDR | CALLRET | CONST | - |
| 0x00664056 | CALL | 0x00663dab | CALLRET | DERIVED | CONST | - |
| 0x00664106 | CALL | 0x00663dab | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00664171 | CALL | 0x00663dab | DERIVED | DERIVED | CONST | - |
| 0x00664447 | CALL | 0x00663dab | DEREF_UNKNOWN | USERFIELD | CONST | - |
| 0x0066457e | CALL | 0x00663dab | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x006645a9 | CALL | 0x00663dab | STACKADDR | CALLRET | CONST | - |
| 0x00664751 | CALL | 0x006646a0 | CALLRET | STACKADDR | CONST | 341@6,431@6,539@6+8 |
| 0x00664762 | CALL | 0x006646a0 | CALLRET | STACKADDR | CONST | 341@6,431@6,539@6+8 |
| 0x00666f30 | CALL | 0x00666ee0 | CALLRET | GLOBAL | CONST | - |
| 0x00666f48 | CALL | 0x00666ee0 | DERIVED | GLOBAL | CONST | - |
| 0x00666f5c | CALL | 0x00666ee0 | CALLRET | GLOBAL | CONST | - |
| 0x00666f74 | CALL | 0x00666ee0 | DERIVED | GLOBAL | CONST | - |
| 0x00667008 | CALL | 0x00666fa0 | CALLRET | GLOBAL | CONST | - |
| 0x0066701c | CALL | 0x00666fa0 | CALLRET | GLOBAL | CONST | - |
| 0x00667034 | CALL | 0x00666fa0 | DERIVED | GLOBAL | CONST | - |
| 0x00667048 | CALL | 0x00666fa0 | CALLRET | GLOBAL | CONST | - |
| 0x00667060 | CALL | 0x00666fa0 | DERIVED | GLOBAL | CONST | - |
| 0x00667074 | CALL | 0x00666fa0 | CALLRET | GLOBAL | CONST | - |
| 0x0066708c | CALL | 0x00666fa0 | DERIVED | GLOBAL | CONST | - |
| 0x00667119 | CALL | 0x006670c0 | DEREF_GLOBAL | DEREF_GLOBAL | DEREF_GLOBAL | - |
| 0x00667132 | CALL | 0x006670c0 | DEREF_GLOBAL | DEREF_GLOBAL | DEREF_GLOBAL | - |
| 0x00667875 | CALL | 0x00667680 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00667921 | CALL | 0x00667906 | USERARG | USERARG | DERIVED | - |
| 0x00667970 | CALL | 0x00667906 | STACK | STACK | DERIVED | - |
| 0x0066d119 | CALL | 0x0066cdc0 | DERIVED | STACKADDR | CONST | - |
| 0x0066d3f2 | CALL | 0x0066d197 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x0066d62b | CALL | 0x0066d197 | GLOBAL | DERIVED | CONST | - |
| 0x0066e376 | CALL | 0x0066dcdc | STACKADDR | GLOBAL | CONST | - |
| 0x0066eb4c | CALL | 0x0066e5e0 | GLOBAL | DEREF_DERIVED | CONST | - |
| 0x0066eba0 | CALL | 0x0066e5e0 | STACKADDR | GLOBAL | CONST | - |
| 0x00672e26 | CALL | 0x00672db0 | CALLRET | CALLRET | CONST | - |
| 0x0067461a | CALL | 0x006745a0 | USERARG | DEREF_STACK | CONST | - |
| 0x00674656 | CALL | 0x006745a0 | CALLRET | CALLRET | CONST | - |
| 0x0067cedf | CALL | 0x0067ce40 | UNKNOWN | GLOBAL | DERIVED | - |
| 0x0067cf00 | CALL | 0x0067ce40 | DERIVED | STACK | DERIVED | - |
| 0x0067d228 | CALL | 0x0067d180 | UNKNOWN | GLOBAL | DEREF_DERIVED | - |
| 0x0067d248 | CALL | 0x0067d180 | DEREF_CALLRET | STACK | DEREF_DERIVED | - |
| 0x0067e36a | CALL | 0x0067d88f | DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x0067eaf9 | CALL | 0x0067eaa0 | DEREF_STACK | DEREF_CONST | DERIVED | - |
| 0x0067f863 | CALL | 0x0067f142 | DERIVED | DERIVED | DERIVED | - |
| 0x0067fd81 | CALL | 0x0067f142 | DERIVED | DERIVED | DERIVED | - |
| 0x00681868 | CALL | 0x00681703 | STACKADDR | UNKNOWN | CONST | - |
| 0x006818ac | CALL | 0x00681703 | STACKADDR | UNKNOWN | CONST | - |
| 0x006818c3 | CALL | 0x00681703 | CALLRET | STACKADDR | CONST | - |
| 0x00681ff8 | CALL | 0x00681fc0 | STACKADDR | USERFIELD | CONST | - |
| 0x00682013 | CALL | 0x00681fc0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00682050 | CALL | 0x00681fc0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00683025 | CALL | 0x00682fd0 | USER_PTR | DERIVED | DERIVED | - |
| 0x00683514 | CALL | 0x006834a0 | UNKNOWN | STACKADDR | CONST | 125@2 |
| 0x006841fc | CALL | 0x00683ff0 | STACKADDR | DEREF_DEREF_DERIVED | DEREF_DEREF_DERIVED | - |
| 0x00688242 | CALL | 0x00686cda | GLOBAL | UNKNOWN | CONST | - |
| 0x0068f270 | CALL | 0x0068f086 | STACKADDR | DEREF_STACK | DERIVED | - |
| 0x0068fe2c | CALL | 0x0068f4d8 | STACKADDR | DERIVED | CONST | - |
| 0x0068fe54 | CALL | 0x0068f4d8 | STACKADDR | DERIVED | CONST | - |
| 0x006944ed | CALL | 0x00694450 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x0069456f | CALL | 0x00694450 | DERIVED | STACKADDR | CONST | - |
| 0x00694663 | CALL | 0x00694600 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x006946c3 | CALL | 0x00694690 | USERARG | STACKADDR | CONST | - |
| 0x006a0bb1 | CALL | 0x006a01e0 | STACKADDR | CALLRET | CONST | - |
| 0x006a0c5b | CALL | 0x006a01e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x006a0c73 | CALL | 0x006a01e0 | DERIVED | STACKADDR | CONST | - |
| 0x006a11ed | CALL | 0x006a01e0 | DERIVED | DEREF_UNKNOWN | CONST | - |
| 0x006a16d4 | CALL | 0x006a01e0 | CALLRET | DEREF_STACK | CONST | - |
| 0x006a1755 | CALL | 0x006a01e0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x006a17cd | CALL | 0x006a01e0 | CALLRET | STACKADDR | CONST | - |
| 0x006aa0f3 | CALL | 0x006aa020 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x006aa107 | CALL | 0x006aa020 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x006aa118 | CALL | 0x006aa020 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x006aa14b | CALL | 0x006aa020 | STACK | GLOBAL | CONST | 601@6,622@4 |
| 0x006abade | CALL | 0x006ab410 | GLOBAL | CALLRET | CONST | - |
| 0x006abda3 | CALL | 0x006abcd0 | UNKNOWN | STACKADDR | CONST | - |
| 0x006ae15a | CALL | 0x006ada20 | STACKADDR | GLOBAL | CONST | - |
| 0x006af27b | CALL | 0x006af150 | STACKADDR | GLOBAL | CONST | - |
| 0x006b3479 | CALL | 0x006b31d0 | USERARG | USERFIELD | CONST | - |
| 0x006b4138 | CALL | 0x006b3820 | STACKADDR | DERIVED | CONST | - |
| 0x006b4168 | CALL | 0x006b3820 | STACKADDR | DERIVED | CONST | - |
| 0x006b487b | CALL | 0x006b3820 | DERIVED | STACK | DEREF_STACK | - |
| 0x006b488f | CALL | 0x006b3820 | CALLRET | STACK | DEREF_CALLRET | - |
| 0x006b493a | CALL | 0x006b3820 | DERIVED | STACK | DEREF_STACK | - |
| 0x006b494f | CALL | 0x006b3820 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x006b49c8 | CALL | 0x006b3820 | DERIVED | DERIVED | DEREF_STACK | - |
| 0x006b49e1 | CALL | 0x006b3820 | DERIVED | STACKADDR | DEREF_CALLRET | - |
| 0x006b87ff | CALL | 0x006b8520 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x006bfd58 | CALL | 0x006bfcb0 | GLOBAL | CALLRET | CALLRET | - |
| 0x006c0389 | CALL | 0x006bff20 | CALLRET | GLOBAL | CONST | - |
| 0x006c03a9 | CALL | 0x006bff20 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x006c04da | CALL | 0x006bff20 | GLOBAL | CALLRET | STACK | - |
| 0x006c050b | CALL | 0x006bff20 | DEREF_STACK | CALLRET | STACK | - |
| 0x006c0589 | CALL | 0x006bff20 | STACKADDR | GLOBAL | CONST | - |
| 0x006c05a1 | CALL | 0x006bff20 | STACKADDR | GLOBAL | CONST | - |
| 0x006c0626 | CALL | 0x006bff20 | GLOBAL | GLOBAL | DERIVED | - |
| 0x006c0720 | CALL | 0x006bff20 | STACKADDR | GLOBAL | CONST | - |
| 0x006c0738 | CALL | 0x006bff20 | STACKADDR | GLOBAL | CONST | - |
| 0x006c0ab2 | CALL | 0x006bff20 | GLOBAL | GLOBAL | CONST | - |
| 0x006c0f7e | CALL | 0x006bff20 | UNKNOWN | GLOBAL | CONST | - |
| 0x006c0f96 | CALL | 0x006bff20 | STACKADDR | GLOBAL | CONST | - |
| 0x006c0fae | CALL | 0x006bff20 | STACKADDR | GLOBAL | CONST | - |
| 0x006c0ff2 | CALL | 0x006bff20 | GLOBAL | CALLRET | CONST | - |
| 0x006c11e8 | CALL | 0x006bff20 | GLOBAL | STACKADDR | STACK | - |
| 0x006c1209 | CALL | 0x006bff20 | DEREF_STACK | STACKADDR | CONST | - |
| 0x006c1222 | CALL | 0x006bff20 | DEREF_STACK | CALLRET | CONST | - |
| 0x006c15e8 | CALL | 0x006bff20 | GLOBAL | STACKADDR | CONST | - |
| 0x006c1600 | CALL | 0x006bff20 | GLOBAL | STACKADDR | CONST | - |
| 0x006c2c88 | CALL | 0x006c2c50 | STACKADDR | USERARG | CONST | - |
| 0x006c33b2 | CALL | 0x006c32b0 | DERIVED | GLOBAL | CONST | - |
| 0x006c346b | CALL | 0x006c32b0 | DEREF_DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x006c353c | CALL | 0x006c32b0 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x006c3595 | CALL | 0x006c32b0 | GLOBAL | DEREF_UNKNOWN | DERIVED | - |
| 0x006c35b0 | CALL | 0x006c32b0 | GLOBAL | DERIVED | CONST | - |
| 0x006c3616 | CALL | 0x006c32b0 | DEREF_DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x006c3677 | CALL | 0x006c32b0 | USERARG | GLOBAL | CONST | - |
| 0x006c368f | CALL | 0x006c32b0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x006c370b | CALL | 0x006c32b0 | GLOBAL | DERIVED | CONST | - |
| 0x006c3785 | CALL | 0x006c32b0 | DEREF_DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x006c37a7 | CALL | 0x006c32b0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x006c381a | CALL | 0x006c32b0 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x006c3832 | CALL | 0x006c32b0 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x006c384d | CALL | 0x006c32b0 | GLOBAL | DERIVED | CONST | - |
| 0x006c38cb | CALL | 0x006c32b0 | GLOBAL | UNKNOWN | CONST | - |
| 0x006c38f5 | CALL | 0x006c32b0 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x006c3917 | CALL | 0x006c32b0 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x006c392f | CALL | 0x006c32b0 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x006c3963 | CALL | 0x006c32b0 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x006c397b | CALL | 0x006c32b0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x006c3998 | CALL | 0x006c32b0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x006c39b1 | CALL | 0x006c32b0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x006c3a59 | CALL | 0x006c32b0 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x006c3a7a | CALL | 0x006c32b0 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x006c3a97 | CALL | 0x006c32b0 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x006c3ab2 | CALL | 0x006c32b0 | GLOBAL | DERIVED | CONST | - |
| 0x006c51a1 | CALL | 0x006c5100 | CALLRET | STACKADDR | CONST | - |
| 0x006c5290 | CALL | 0x006c5100 | UNKNOWN | DERIVED | CONST | - |
| 0x006c53ea | CALL | 0x006c5300 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x006c5737 | CALL | 0x006c5520 | DERIVED | DERIVED | CONST | - |
| 0x006c594d | CALL | 0x006c58e0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x006c5cbe | CALL | 0x006c5c20 | STACKADDR | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x006c5ce0 | CALL | 0x006c5c20 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x006c5cfb | CALL | 0x006c5c20 | STACKADDR | DERIVED | CONST | - |
| 0x006c5e96 | CALL | 0x006c5c20 | STACKADDR | DEREF_DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | - |
| 0x006c61cc | CALL | 0x006c5ef0 | DEREF_DEREF_CALLRET | CALLRET | CONST | - |
| 0x006c6471 | CALL | 0x006c63a0 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x006c6b0b | CALL | 0x006c6960 | DEREF_CALLRET | DERIVED | CALLRET | - |
| 0x006c706a | CALL | 0x006c6f90 | CALLRET | CALLRET | CALLRET | - |
| 0x006c72d2 | CALL | 0x006c71f0 | DEREF_CALLRET | DEREF_STACK | CALLRET | - |
| 0x006c7a0b | CALL | 0x006c7610 | DERIVED | UNKNOWN | CONST | - |
| 0x006c7ce6 | CALL | 0x006c7b70 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x006c7cff | CALL | 0x006c7b70 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x006c7e0a | CALL | 0x006c7b70 | DEREF_UNKNOWN | DERIVED | UNKNOWN | - |
| 0x006c824e | CALL | 0x006c7b70 | DERIVED | DERIVED | CALLRET | - |
| 0x006c852e | CALL | 0x006c8470 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x006c8734 | CALL | 0x006c8670 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x006c8b8d | CALL | 0x006c8670 | DEREF_CALLRET | DERIVED | DEREF_CALLRET | - |
| 0x006cacfb | CALL | 0x006cace0 | GLOBAL | USERARG | USERARG | - |
| 0x006cd530 | CALL | 0x006cd3c0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x006cd54b | CALL | 0x006cd3c0 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x006cde95 | CALL | 0x006cdd80 | DEREF_UNKNOWN | USERARG | DEREF_UNKNOWN | - |
| 0x006cdefd | CALL | 0x006cdd80 | CALLRET | CALLRET | CALLRET | - |
| 0x006cdf5a | CALL | 0x006cdf30 | UNKNOWN | USERARG | UNKNOWN | - |
| 0x006cdf7f | CALL | 0x006cdf30 | CALLRET | CALLRET | CALLRET | - |
| 0x006cebc8 | CALL | 0x006cea80 | UNKNOWN | USERARG | CONST | - |
| 0x006cec89 | CALL | 0x006cea80 | UNKNOWN | USERARG | CONST | - |
| 0x006ceccc | CALL | 0x006cea80 | STACK | CALLRET | CONST | - |
| 0x006cf16c | CALL | 0x006cf020 | DERIVED | UNKNOWN | CONST | - |
| 0x006cf649 | CALL | 0x006cf1c0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x006cf75e | CALL | 0x006cf6e0 | DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x006d040d | CALL | 0x006cfba0 | STACKADDR | UNKNOWN | CONST | - |
| 0x006d2aa1 | CALL | 0x006d2970 | DEREF_CALLRET | CALLRET | STACK | 0@5,2@5,3@5+562 |
| 0x006d2ac8 | CALL | 0x006d2970 | UNKNOWN | UNKNOWN | STACK | 0@5,2@5,3@5+562 |
| 0x006d3511 | CALL | 0x006d34b0 | DEREF_DERIVED | STACKADDR | DERIVED | - |
| 0x006d3606 | CALL | 0x006d3530 | UNKNOWN | USERARG | UNKNOWN | - |
| 0x006d36ae | CALL | 0x006d3610 | UNKNOWN | CALLRET | CALLRET | - |
| 0x006d378a | CALL | 0x006d36d0 | UNKNOWN | USERARG | GLOBAL | - |
| 0x006d3c8b | CALL | 0x006d3960 | CALLRET | CALLRET | CONST | - |
| 0x006d3ca8 | CALL | 0x006d3960 | CALLRET | CALLRET | CONST | - |
| 0x006d3de4 | CALL | 0x006d3960 | DEREF_UNKNOWN | DEREF_DERIVED | CONST | - |
| 0x006d3e1b | CALL | 0x006d3960 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x006d3fac | CALL | 0x006d3960 | DEREF_CALLRET | UNKNOWN | DERIVED | - |
| 0x006d414c | CALL | 0x006d3960 | DEREF_UNKNOWN | UNKNOWN | DERIVED | - |
| 0x006d65d1 | CALL | 0x006d6310 | GLOBAL | DERIVED | CONST | - |
| 0x006d6a40 | CALL | 0x006d6980 | DEREF_DEREF_CALLRET | UNKNOWN | CONST | - |
| 0x006d6afd | CALL | 0x006d6980 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x006d6c4a | CALL | 0x006d6980 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x006d6cb8 | CALL | 0x006d6980 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x006d6cd0 | CALL | 0x006d6980 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x006d70a1 | CALL | 0x006d6980 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x006d7b05 | CALL | 0x006d6980 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x006d7be2 | CALL | 0x006d6980 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x006d7bf8 | CALL | 0x006d6980 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x006d9fd0 | CALL | 0x006d9fa0 | USERARG | DERIVED | USERARG | - |
| 0x006d9ff5 | CALL | 0x006d9fe0 | USERARG | GLOBAL | CONST | 626@6 |
| 0x006da0de | JMP | 0x006da0b0 | USERARG | DERIVED | CONST | - |
| 0x006da207 | CALL | 0x006da1e0 | STACKADDR | GLOBAL | CONST | - |
| 0x006da2c7 | CALL | 0x006da2a0 | STACKADDR | GLOBAL | CONST | - |
| 0x006da366 | CALL | 0x006da300 | STACKADDR | GLOBAL | CONST | 341@6,431@6 |
| 0x006da3c9 | CALL | 0x006da390 | STACKADDR | GLOBAL | CONST | - |
| 0x006da516 | CALL | 0x006da400 | GLOBAL | DERIVED | CONST | - |
| 0x006da534 | CALL | 0x006da400 | GLOBAL | DERIVED | CONST | - |
| 0x006da552 | CALL | 0x006da400 | GLOBAL | DERIVED | CONST | - |
| 0x006da570 | CALL | 0x006da400 | GLOBAL | DERIVED | CONST | - |
| 0x006da58e | CALL | 0x006da400 | GLOBAL | DERIVED | CONST | - |
| 0x006da5ac | CALL | 0x006da400 | GLOBAL | DERIVED | CONST | - |
| 0x006da5c4 | CALL | 0x006da400 | GLOBAL | GLOBAL | CONST | - |
| 0x006da707 | CALL | 0x006da6e0 | STACKADDR | GLOBAL | CONST | - |
| 0x006da847 | CALL | 0x006da820 | STACKADDR | GLOBAL | CONST | - |
| 0x006da8e9 | CALL | 0x006da8c0 | STACKADDR | GLOBAL | CONST | - |
| 0x006da907 | CALL | 0x006da8c0 | STACKADDR | GLOBAL | CONST | - |
| 0x006da918 | CALL | 0x006da8c0 | STACKADDR | CALLRET | CONST | - |
| 0x006da987 | CALL | 0x006da960 | STACKADDR | GLOBAL | CONST | - |
| 0x006dae66 | CALL | 0x006daa10 | STACKADDR | GLOBAL | CONST | - |
| 0x006daf31 | CALL | 0x006daa10 | STACKADDR | GLOBAL | CONST | - |
| 0x006dafd1 | CALL | 0x006daa10 | STACKADDR | GLOBAL | CONST | - |
| 0x006db154 | CALL | 0x006daa10 | STACKADDR | GLOBAL | CONST | - |
| 0x006db2f4 | CALL | 0x006daa10 | STACKADDR | GLOBAL | CONST | - |
| 0x006db904 | CALL | 0x006db5c0 | DEREF_CALLRET | CALLRET | CONST | 59@6,73@6,482@5+5 |
| 0x006dba01 | CALL | 0x006db5c0 | UNKNOWN | DERIVED | CONST | 59@6,73@6,482@5+5 |
| 0x006dbb78 | CALL | 0x006dba70 | DERIVED | CALLRET | CONST | 482@6 |
| 0x006def98 | CALL | 0x006dedb0 | CALLRET | CALLRET | CONST | 0@3,2@3,3@3+562 |
| 0x006e012d | CALL | 0x006dfcb0 | STACK | DEREF_STACK | CONST | 0@4,2@4,3@4+563 |
| 0x006e081c | CALL | 0x006e07a0 | CALLRET | GLOBAL | CONST | 0@4,2@4,3@4+562 |
| 0x006e083c | CALL | 0x006e07a0 | DERIVED | CALLRET | DERIVED | 0@4,2@4,3@4+562 |
| 0x006e2c9f | CALL | 0x006e2c20 | CALLRET | STACKADDR | CONST | 59@3 |
| 0x006e2ce6 | CALL | 0x006e2c20 | DERIVED | GLOBAL | CONST | 59@3 |
| 0x006e2d69 | CALL | 0x006e2d10 | CALLRET | STACKADDR | CONST | 42@5,59@5,477@5+1 |
| 0x006e3e15 | CALL | 0x006e2dc0 | DERIVED | STACK | CONST | - |
| 0x006e4690 | CALL | 0x006e2dc0 | CALLRET | STACKADDR | CONST | - |
| 0x006e473e | CALL | 0x006e2dc0 | CALLRET | STACKADDR | CONST | - |
| 0x006e4993 | CALL | 0x006e2dc0 | DERIVED | STACK | CONST | - |
| 0x006e570d | CALL | 0x006e54e0 | CALLRET | STACKADDR | CONST | 59@3 |
| 0x006eb084 | CALL | 0x006eae70 | DEREF_GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x006eb160 | CALL | 0x006eae70 | UNKNOWN | DEREF_GLOBAL | STACK | - |
| 0x006eb1dc | CALL | 0x006eae70 | UNKNOWN | USERFIELD | DERIVED | - |
| 0x006eb3c9 | CALL | 0x006eae70 | DEREF_UNKNOWN | UNKNOWN | USERARG | - |
| 0x006eba8b | CALL | 0x006eb7f0 | DEREF_UNKNOWN | UNKNOWN | USERARG | - |
| 0x006f3785 | CALL | 0x006f36d0 | UNKNOWN | STACKADDR | CONST | - |
| 0x006f384b | CALL | 0x006f37c0 | CALLRET | CALLRET | CONST | - |
| 0x006f38db | CALL | 0x006f37c0 | STACK | STACKADDR | CONST | - |
| 0x006f39dd | CALL | 0x006f3930 | UNKNOWN | STACKADDR | CONST | - |
| 0x006f3ac4 | CALL | 0x006f3a10 | UNKNOWN | STACKADDR | CONST | - |
| 0x006f3b6f | CALL | 0x006f3b00 | CALLRET | CALLRET | CALLRET | - |
| 0x006f3c2c | CALL | 0x006f3b00 | STACK | STACKADDR | CONST | - |
| 0x006f3d38 | CALL | 0x006f3c80 | UNKNOWN | STACKADDR | CONST | - |
| 0x006f3e45 | CALL | 0x006f3d70 | STACK | STACKADDR | CONST | - |
| 0x006f3ee3 | CALL | 0x006f3e80 | STACKADDR | CALLRET | CONST | - |
| 0x006f459a | CALL | 0x006f4280 | DEREF_DERIVED | STACKADDR | CONST | - |
| 0x006f56b5 | CALL | 0x006f5560 | DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x006fc244 | CALL | 0x006fbd50 | DERIVED | DERIVED | DEREF_UNKNOWN | 676@6 |
| 0x006fe689 | CALL | 0x006fe550 | STACK | STACKADDR | CALLRET | 0@2,2@2,3@2+562 |
| 0x006fed00 | CALL | 0x006fe550 | STACK | DEREF_CALLRET | STACK | 0@2,2@2,3@2+562 |
| 0x006fef1b | CALL | 0x006fe550 | DEREF_CALLRET | CALLRET | STACK | 0@2,2@2,3@2+562 |
| 0x006ff1f0 | CALL | 0x006fe550 | DEREF_CALLRET | CALLRET | STACK | 0@2,2@2,3@2+562 |
| 0x006ffefd | CALL | 0x006ffe60 | CALLRET | CALLRET | CONST | - |
| 0x00700b4f | CALL | 0x00700b00 | STACKADDR | GLOBAL | CONST | - |
| 0x007030d9 | CALL | 0x00702fe0 | UNKNOWN | UNKNOWN | STACK | - |
| 0x0070322d | CALL | 0x00703210 | USERFIELD | CONST | USERARG | 93@6,522@6 |
| 0x007032c6 | CALL | 0x00703260 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x007035f9 | CALL | 0x00703470 | DERIVED | STACKADDR | STACK | - |
| 0x00704406 | CALL | 0x007041f0 | DEREF_STACK | STACKADDR | STACK | - |
| 0x0070e8b1 | CALL | 0x0070e850 | CALLRET | CALLRET | CALLRET | - |
| 0x0070eacf | JMP | 0x0070eac0 | GLOBAL | USERARG | USERARG | - |
| 0x00716172 | CALL | 0x00715400 | CALLRET | CALLRET | CONST | - |
| 0x007161ac | CALL | 0x00715400 | CALLRET | STACK | CONST | - |
| 0x007164a4 | CALL | 0x00715400 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00716545 | CALL | 0x00715400 | UNKNOWN | DERIVED | CONST | - |
| 0x007166fa | CALL | 0x00715400 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00716bd9 | CALL | 0x00716a28 | UNKNOWN | UNKNOWN | CONST | - |
| 0x007179b4 | CALL | 0x00717970 | CALLRET | CALLRET | CONST | - |
| 0x0071e50d | CALL | 0x0071e400 | DEREF_UNKNOWN | DEREF_DEREF_DEREF_UNKNOWN | CONST | - |
| 0x0071e534 | CALL | 0x0071e400 | DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x0071e55b | CALL | 0x0071e400 | DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x0071e582 | CALL | 0x0071e400 | DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x0071e5a9 | CALL | 0x0071e400 | DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x0071e5d0 | CALL | 0x0071e400 | DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x0071e5f7 | CALL | 0x0071e400 | DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x0071e621 | CALL | 0x0071e400 | DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | CONST | - |
| 0x0071e8a2 | CALL | 0x0071e770 | DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x0071e8e4 | CALL | 0x0071e770 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x0071ea08 | CALL | 0x0071e930 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0071ea3d | CALL | 0x0071e930 | DERIVED | DERIVED | DERIVED | - |
| 0x0071ea66 | CALL | 0x0071e930 | UNKNOWN | DERIVED | DERIVED | - |
| 0x007250da | CALL | 0x00724f83 | UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x007255e4 | CALL | 0x00724f83 | DERIVED | CALLRET | CALLRET | - |
| 0x00729c9d | CALL | 0x00729ac0 | CALLRET | STACK | CONST | 59@2,92@1 |
| 0x0072cfb9 | CALL | 0x0072cf40 | DEREF_CALLRET | DERIVED | DEREF_DERIVED | 2@3,5@4,30@5+23 |
| 0x0072d002 | CALL | 0x0072cf40 | CALLRET | STACK | DERIVED | 2@3,5@4,30@5+23 |
| 0x0072e92a | CALL | 0x0072e800 | DEREF_DEREF_STACK | DEREF_DEREF_STACK | CONST | 5@2,59@4,499@2 |
| 0x0072e9c1 | CALL | 0x0072e800 | DEREF_DEREF_STACK | DEREF_DEREF_STACK | CONST | 5@2,59@4,499@2 |
| 0x0072ef07 | CALL | 0x0072ecc0 | STACK | CALLRET | CONST | - |
| 0x0072fb98 | CALL | 0x0072fad0 | DEREF_CALLRET | CALLRET | CALLRET | 5@2,59@4,499@2 |
| 0x0072fc22 | CALL | 0x0072fad0 | DEREF_CALLRET | CALLRET | STACK | 5@2,59@4,499@2 |
| 0x00730cf5 | CALL | 0x00730cd0 | DEREF_DERIVED | USERARG | CONST | - |
| 0x00732f08 | CALL | 0x00732bc0 | CALLRET | CALLRET | CONST | - |
| 0x007330c7 | CALL | 0x00732bc0 | UNKNOWN | STACKVAL | DERIVED | - |
| 0x007331c2 | CALL | 0x00732bc0 | UNKNOWN | UNKNOWN | CONST | - |
| 0x0073336d | CALL | 0x00732bc0 | UNKNOWN | UNKNOWN | CONST | - |
| 0x007333bf | CALL | 0x00732bc0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00733413 | CALL | 0x00732bc0 | DEREF_CALLRET | DEREF_DEREF_STACK | CONST | - |
| 0x00733473 | CALL | 0x00732bc0 | DEREF_CALLRET | DEREF_STACK | CONST | - |
| 0x007334d2 | CALL | 0x00732bc0 | DERIVED | DEREF_DEREF_STACK | CONST | - |
| 0x00733bac | CALL | 0x00733a00 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x00733c81 | CALL | 0x00733a00 | DEREF_STACKADDR | DEREF_STACK | DEREF_DERIVED | - |
| 0x00733ce6 | CALL | 0x00733a00 | STACKADDR | UNKNOWN | CONST | - |
| 0x00733d41 | CALL | 0x00733a00 | STACKADDR | UNKNOWN | DERIVED | - |
| 0x00733d6e | CALL | 0x00733a00 | STACKADDR | UNKNOWN | CONST | - |
| 0x00733deb | CALL | 0x00733a00 | STACK | STACKADDR | DEREF_CALLRET | - |
| 0x0073447a | CALL | 0x007341b0 | GLOBAL | STACK | CONST | - |
| 0x00734693 | CALL | 0x007341b0 | GLOBAL | STACK | CONST | - |
| 0x00734883 | CALL | 0x007341b0 | GLOBAL | STACK | CONST | - |
| 0x00734ee2 | CALL | 0x007341b0 | CALLRET | STACK | CONST | - |
| 0x00736bee | CALL | 0x007369a0 | CONST | USERARG | CONST | - |
| 0x0073cba8 | CALL | 0x0073c9c0 | UNKNOWN | STACK | DEREF_DERIVED | 622@2 |
| 0x0073d1d9 | CALL | 0x0073d1c0 | USERARG | GLOBAL | CONST | - |
| 0x0073d209 | CALL | 0x0073d1f0 | USERARG | GLOBAL | CONST | 539@6,550@6,622@6+6 |
| 0x0073d231 | JMP | 0x0073d220 | USERARG | GLOBAL | CONST | - |
| 0x0073d251 | JMP | 0x0073d240 | USERARG | GLOBAL | CONST | - |
| 0x00742b36 | CALL | 0x00742570 | GLOBAL | STACK | UNKNOWN | - |
| 0x007479a5 | CALL | 0x00742570 | DEREF_CALLRET | DEREF_CALLRET | STACK | - |
| 0x0074e64e | CALL | 0x0074d550 | GLOBAL | STACKADDR | CONST | - |
| 0x0074f6db | CALL | 0x0074f3e0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00751a37 | CALL | 0x0074f3e0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0075230a | CALL | 0x0074f3e0 | DERIVED | CALLRET | CONST | - |
| 0x00752341 | CALL | 0x0074f3e0 | DERIVED | CALLRET | CONST | - |
| 0x007525e4 | CALL | 0x0074f3e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x0075261c | CALL | 0x0074f3e0 | UNKNOWN | STACKADDR | CONST | - |
| 0x00752829 | CALL | 0x0074f3e0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0075289a | CALL | 0x0074f3e0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x007529d6 | CALL | 0x0074f3e0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x007535f6 | CALL | 0x00753570 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00753c6a | CALL | 0x00753a70 | DEREF_CALLRET | DERIVED | DEREF_CALLRET | - |
| 0x007568b2 | CALL | 0x00756820 | STACKADDR | USERARG | USERARG | - |
| 0x00756988 | CALL | 0x00756820 | STACKADDR | UNKNOWN | USERARG | - |
| 0x00758a34 | CALL | 0x00757450 | DEREF_UNKNOWN | USERARG | DERIVED | - |
| 0x00758bee | CALL | 0x00757450 | DEREF_UNKNOWN | USERARG | DERIVED | - |
| 0x0075a6e0 | CALL | 0x0075a640 | STACK | CALLRET | CALLRET | - |
| 0x0075a795 | CALL | 0x0075a640 | STACK | CALLRET | CALLRET | - |
| 0x0075bd89 | CALL | 0x0075bc10 | STACKADDR | GLOBAL | CONST | - |
| 0x0075c24e | CALL | 0x0075bc10 | STACK | DERIVED | DEREF_UNKNOWN | - |
| 0x0075ca21 | CALL | 0x0075bc10 | STACK | STACK | STACK | - |
| 0x0075cfbc | CALL | 0x0075cf10 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0075d248 | CALL | 0x0075d1c0 | DERIVED | DERIVED | CONST | - |
| 0x0075dca5 | CALL | 0x0075dad0 | STACK | DEREF_CALLRET | CONST | - |
| 0x0075dcd3 | CALL | 0x0075dad0 | DERIVED | CALLRET | CONST | - |
| 0x0075dcec | CALL | 0x0075dad0 | DERIVED | DERIVED | CONST | - |
| 0x0075ddd9 | CALL | 0x0075dad0 | GLOBAL | CALLRET | CONST | - |
| 0x0075e4d6 | CALL | 0x0075e480 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0075e4fb | CALL | 0x0075e480 | CALLRET | CALLRET | CONST | - |
| 0x0075e510 | CALL | 0x0075e480 | STACK | DERIVED | CONST | - |
| 0x0075ec7c | CALL | 0x0075eb30 | STACK | UNKNOWN | DERIVED | - |
| 0x0075ed24 | CALL | 0x0075eb30 | STACK | DEREF_STACK | DERIVED | - |
| 0x0075eec2 | CALL | 0x0075ed60 | UNKNOWN | CALLRET | STACK | - |
| 0x0075efd0 | CALL | 0x0075ed60 | DEREF_STACK | STACK | CALLRET | - |
| 0x0075f3ab | CALL | 0x0075f260 | UNKNOWN | UNKNOWN | CONST | - |
| 0x007628b0 | CALL | 0x007624c0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00762e22 | CALL | 0x00762bf0 | USERFIELD | GLOBAL | CONST | - |
| 0x00762f1a | CALL | 0x00762bf0 | UNKNOWN | GLOBAL | CONST | - |
| 0x0076733b | CALL | 0x00766c10 | UNKNOWN | STACKADDR | CONST | - |
| 0x0076735d | CALL | 0x00766c10 | DERIVED | STACKADDR | CONST | - |
| 0x00770b60 | CALL | 0x00770a70 | UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00773ed2 | CALL | 0x00773e40 | UNKNOWN | DERIVED | CONST | - |
| 0x00773f24 | CALL | 0x00773e40 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00774e8a | CALL | 0x00774240 | UNKNOWN | UNKNOWN | CONST | - |
| 0x0077e968 | CALL | 0x0077e830 | DERIVED | STACK | DEREF_STACK | - |
| 0x0077e986 | CALL | 0x0077e830 | DEREF_CALLRET | CALLRET | DERIVED | - |
| 0x00787e5e | CALL | 0x00787bf0 | DEREF_CALLRET | STACKADDR | CONST | 515@5,629@5 |
| 0x00787e70 | CALL | 0x00787bf0 | DEREF_CALLRET | STACKADDR | CONST | 515@5,629@5 |
| 0x00787e82 | CALL | 0x00787bf0 | DEREF_CALLRET | STACKADDR | CONST | 515@5,629@5 |
| 0x00787e93 | CALL | 0x00787bf0 | DEREF_CALLRET | CALLRET | CONST | 515@5,629@5 |
| 0x00787ea5 | CALL | 0x00787bf0 | DEREF_CALLRET | STACKADDR | CONST | 515@5,629@5 |
| 0x0078860f | CALL | 0x00788490 | STACKADDR | CALLRET | CONST | 515@5,629@5 |
| 0x00788918 | CALL | 0x007887b0 | UNKNOWN | CALLRET | CONST | - |
| 0x00788c8b | CALL | 0x00788a20 | STACKADDR | CALLRET | CONST | 515@6,629@6 |
| 0x00788f21 | CALL | 0x00788dd0 | UNKNOWN | CALLRET | CONST | - |
| 0x0078903d | CALL | 0x00788dd0 | DERIVED | UNKNOWN | CONST | - |
| 0x007892f6 | CALL | 0x00789110 | STACKADDR | UNKNOWN | CONST | 515@6,629@6 |
| 0x0078d2ec | CALL | 0x0078d280 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x0078d303 | CALL | 0x0078d280 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x0078d321 | CALL | 0x0078d280 | DEREF_CALLRET | UNKNOWN | STACK | - |
| 0x0078d34a | CALL | 0x0078d280 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x0078d363 | CALL | 0x0078d280 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0078d380 | CALL | 0x0078d280 | DEREF_CALLRET | UNKNOWN | CALLRET | - |
| 0x0078d3b7 | JMP | 0x0078d280 | DERIVED | UNKNOWN | DERIVED | - |
| 0x0079353f | CALL | 0x007932d0 | DERIVED | DERIVED | DEREF_UNKNOWN | 5@6,12@5,15@5+22 |
| 0x007937d8 | CALL | 0x00793760 | UNKNOWN | DERIVED | DERIVED | 59@1 |
| 0x0079422d | CALL | 0x00793f90 | STACK | GLOBAL | CONST | - |
| 0x00794245 | CALL | 0x00793f90 | STACK | STACKADDR | CONST | - |
| 0x007942be | CALL | 0x00793f90 | GLOBAL | STACK | CONST | - |
| 0x00794627 | CALL | 0x00794410 | GLOBAL | CALLRET | CONST | - |
| 0x007946d2 | CALL | 0x00794410 | STACK | STACKADDR | CONST | - |
| 0x00794743 | CALL | 0x00794410 | GLOBAL | CALLRET | CONST | - |
| 0x00794aa4 | CALL | 0x00794930 | CALLRET | CALLRET | CONST | - |
| 0x00794afb | CALL | 0x00794930 | CALLRET | STACKADDR | CONST | - |
| 0x007953d1 | CALL | 0x00795260 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x007953e5 | CALL | 0x00795260 | DERIVED | STACK | CALLRET | - |
| 0x00795ce4 | CALL | 0x007958f0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0079638d | CALL | 0x007960e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x007963a9 | CALL | 0x007960e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x0079660e | CALL | 0x007960e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00796631 | CALL | 0x007960e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00796aa8 | CALL | 0x007960e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00796ac7 | CALL | 0x007960e0 | DERIVED | STACKADDR | CONST | - |
| 0x00797536 | CALL | 0x00797250 | STACKADDR | CALLRET | CONST | - |
| 0x00797718 | CALL | 0x00797250 | CALLRET | STACKADDR | CONST | - |
| 0x0079813e | CALL | 0x00797ff0 | USERARG | DERIVED | CONST | - |
| 0x007985bd | CALL | 0x00798310 | GLOBAL | GLOBAL | CONST | 532@4 |
| 0x007990d6 | CALL | 0x00798d00 | STACKADDR | GLOBAL | CONST | 532@5 |
| 0x0079969e | CALL | 0x00798d00 | GLOBAL | GLOBAL | CONST | 532@5 |
| 0x0079976f | CALL | 0x00798d00 | GLOBAL | GLOBAL | CONST | 532@5 |
| 0x007997ad | CALL | 0x00798d00 | STACKADDR | GLOBAL | CONST | 532@5 |
| 0x0079990e | CALL | 0x00798d00 | GLOBAL | GLOBAL | CONST | 532@5 |
| 0x00799a3e | CALL | 0x00798d00 | GLOBAL | GLOBAL | CONST | 532@5 |
| 0x0079b479 | CALL | 0x0079add0 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x0079b624 | CALL | 0x0079add0 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0079ef1b | CALL | 0x0079ecf0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0079efaa | CALL | 0x0079ecf0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0079f8df | CALL | 0x0079f890 | USER_PTR | USERARG | CONST | - |
| 0x007a159b | CALL | 0x007a0fe0 | DERIVED | STACK | UNKNOWN | - |
| 0x007a2b2a | CALL | 0x007a24d0 | GLOBAL | STACKADDR | CONST | - |
| 0x007a31a6 | CALL | 0x007a3040 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x007a4949 | CALL | 0x007a3d80 | CALLRET | STACKADDR | CONST | 1@6,59@6,341@4+7 |
| 0x007a632b | CALL | 0x007a3d80 | STACKADDR | DEREF_DEREF_UNKNOWN | CONST | 1@6,59@6,341@4+7 |
| 0x007a6351 | CALL | 0x007a3d80 | STACKADDR | DERIVED | CONST | 1@6,59@6,341@4+7 |
| 0x007a6b4c | CALL | 0x007a3d80 | STACKADDR | DEREF_STACK | CONST | 1@6,59@6,341@4+7 |
| 0x007a7321 | CALL | 0x007a3d80 | DEREF_CALLRET | DEREF_CALLRET | CONST | 1@6,59@6,341@4+7 |
| 0x007a7435 | CALL | 0x007a3d80 | DEREF_CALLRET | DEREF_CALLRET | CONST | 1@6,59@6,341@4+7 |
| 0x007a7b01 | CALL | 0x007a3d80 | DEREF_CALLRET | DEREF_CALLRET | CONST | 1@6,59@6,341@4+7 |
| 0x007ac1a5 | CALL | 0x007ac000 | STACK | DEREF_CALLRET | DEREF_CALLRET | 341@5,345@6,346@6+3 |
| 0x007aff4b | CALL | 0x007afd10 | DEREF_GLOBAL | STACKADDR | CONST | 341@5,345@6,346@6+3 |
| 0x007b00e5 | CALL | 0x007b0060 | USERARG | DERIVED | DERIVED | 341@6,431@6 |
| 0x007b00fe | JMP | 0x007b0060 | DERIVED | CALLRET | CALLRET | 341@6,431@6 |
| 0x007b037d | CALL | 0x007b0300 | DERIVED | CALLRET | DERIVED | 1@3,2@6,23@6+89 |
| 0x007b039f | CALL | 0x007b0300 | DERIVED | UNKNOWN | UNKNOWN | 1@3,2@6,23@6+89 |
| 0x007b0468 | CALL | 0x007b03e0 | DERIVED | CALLRET | DERIVED | - |
| 0x007b047c | CALL | 0x007b03e0 | CALLRET | DERIVED | CALLRET | - |
| 0x007b049d | CALL | 0x007b03e0 | DERIVED | UNKNOWN | USERARG | - |
| 0x007b0884 | CALL | 0x007b0850 | CALLRET | GLOBAL | CONST | 341@5,345@6,346@6+3 |
| 0x007b0904 | CALL | 0x007b08d0 | CALLRET | GLOBAL | CONST | 341@5,345@6,346@6+3 |
| 0x007b09a2 | CALL | 0x007b08d0 | CALLRET | GLOBAL | CONST | 341@5,345@6,346@6+3 |
| 0x007b1036 | CALL | 0x007b0c70 | STACK | DERIVED | USERARG | 37@5,55@6,334@3+6 |
| 0x007b7241 | CALL | 0x007b71e0 | DERIVED | CALLRET | CALLRET | 135@3 |
| 0x007b79b1 | CALL | 0x007b7890 | STACKADDR | DEREF_UNKNOWN | CONST | 0@6,2@6,3@6+562 |
| 0x007b8724 | CALL | 0x007b84e0 | STACKADDR | DEREF_STACK | CONST | 135@2 |
| 0x007b9621 | CALL | 0x007b9540 | STACKADDR | STACKADDR | CONST | - |
| 0x007b9662 | CALL | 0x007b9540 | CALLRET | STACKADDR | CONST | - |
| 0x007bc405 | CALL | 0x007bc190 | GLOBAL | UNKNOWN | CONST | - |
| 0x007bc45f | CALL | 0x007bc190 | GLOBAL | UNKNOWN | CONST | - |
| 0x007bcbdf | CALL | 0x007bcb80 | DERIVED | CALLRET | CONST | - |
| 0x007bcc9f | CALL | 0x007bcc40 | DERIVED | CALLRET | CONST | - |
| 0x007bd209 | CALL | 0x007bcd00 | GLOBAL | USERARG | UNKNOWN | - |
| 0x007c2a53 | CALL | 0x007c26c0 | USERARG | USERARG | DERIVED | - |
| 0x007c42aa | CALL | 0x007c4160 | UNKNOWN | USERARG | DEREF_DEREF_UNKNOWN | - |
| 0x007c42ce | CALL | 0x007c4160 | DEREF_CALLRET | STACK | DEREF_DERIVED | - |
| 0x007c5f83 | CALL | 0x007c5990 | DERIVED | UNKNOWN | STACK | - |
| 0x007c63d7 | CALL | 0x007c62c0 | STACK | DERIVED | STACK | - |
| 0x007c7963 | CALL | 0x007c76c0 | DERIVED | UNKNOWN | DERIVED | - |
| 0x007c80b1 | CALL | 0x007c7fe0 | CALLRET | STACKADDR | CONST | - |
| 0x007c846c | CALL | 0x007c83c0 | CALLRET | STACKADDR | CONST | - |
| 0x007c8545 | CALL | 0x007c8500 | STACKADDR | USERARG | CONST | - |
| 0x007c8679 | CALL | 0x007c8500 | CALLRET | STACKADDR | CONST | - |
| 0x007c868a | CALL | 0x007c8500 | CALLRET | STACKADDR | CONST | - |
| 0x007c8813 | CALL | 0x007c86f0 | STACKADDR | STACK | CONST | - |
| 0x007c8866 | CALL | 0x007c86f0 | CALLRET | STACKADDR | CONST | - |
| 0x007c887b | CALL | 0x007c86f0 | STACK | STACKADDR | CONST | - |
| 0x007e1d59 | CALL | 0x007e1cd0 | CONST | DEREF_DEREF_UNKNOWN | CONST | 622@2 |
| 0x007e4632 | CALL | 0x007e45e0 | UNKNOWN | USERARG | CONST | 1@4,4@5,5@6+29 |
| 0x007e476c | CALL | 0x007e4740 | USERARG | UNKNOWN | CONST | 1@3,4@4,5@5+40 |
| 0x007e5390 | CALL | 0x007e4f90 | GLOBAL | GLOBAL | CONST | 59@6,73@6,482@5+4 |
| 0x007e5d9f | CALL | 0x007e5ab0 | DEREF_CALLRET | GLOBAL | CONST | 482@6 |
| 0x007e6309 | CALL | 0x007e6270 | UNKNOWN | USERARG | UNKNOWN | - |
| 0x007e63c7 | CALL | 0x007e6270 | UNKNOWN | STACK | UNKNOWN | - |
| 0x007e81e1 | CALL | 0x007e78c0 | STACKADDR | DERIVED | CONST | 588@6 |
| 0x007e920b | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007e9223 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007e98f2 | CALL | 0x007e8bd0 | DEREF_UNKNOWN | USERFIELD | CONST | - |
| 0x007e99a1 | CALL | 0x007e8bd0 | STACKADDR | CALLRET | UNKNOWN | - |
| 0x007e99cb | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007e99e1 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CALLRET | - |
| 0x007ea95a | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007ea972 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007ea9e0 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eaa0c | CALL | 0x007e8bd0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x007eab5a | CALL | 0x007e8bd0 | STACKADDR | DERIVED | CONST | - |
| 0x007eabd7 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eabeb | CALL | 0x007e8bd0 | STACKADDR | CALLRET | CONST | - |
| 0x007eac67 | CALL | 0x007e8bd0 | STACKADDR | DERIVED | CONST | - |
| 0x007eace4 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eacfc | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eb113 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eb1f6 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eb2d0 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eb30f | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eb32d | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | DERIVED | - |
| 0x007eb3ca | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eb3fb | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | CONST | - |
| 0x007eb419 | CALL | 0x007e8bd0 | STACKADDR | STACKADDR | DERIVED | - |
| 0x007ec26f | CALL | 0x007eb950 | STACKADDR | DERIVED | CONST | - |
| 0x007ec31e | CALL | 0x007eb950 | CALLRET | DERIVED | DEREF_CALLRET | - |
| 0x007ec3de | CALL | 0x007eb950 | STACKADDR | DERIVED | CONST | - |
| 0x007ec56e | CALL | 0x007eb950 | DEREF_UNKNOWN | DERIVED | UNKNOWN | - |
| 0x007ed71f | CALL | 0x007eb950 | STACKADDR | DEREF_UNKNOWN | DERIVED | - |
| 0x007ee024 | CALL | 0x007edf40 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x007ee1ec | CALL | 0x007ee190 | CALLRET | DERIVED | CONST | - |
| 0x007ee69f | CALL | 0x007ee630 | STACKADDR | STACKADDR | CONST | - |
| 0x007ee80b | CALL | 0x007ee730 | STACKADDR | DERIVED | DERIVED | - |
| 0x007ee8b5 | CALL | 0x007ee730 | DEREF_UNKNOWN | USERARG | CONST | - |
| 0x007ef069 | CALL | 0x007ef020 | USERFIELD | USERFIELD | CONST | - |
| 0x007ef1be | CALL | 0x007ef140 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x007ef1d4 | CALL | 0x007ef140 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x007ef1e7 | CALL | 0x007ef140 | DEREF_CALLRET | STACK | CONST | - |
| 0x007f0b59 | CALL | 0x007f0af0 | GLOBAL | GLOBAL | CONST | 0@6,1@6,2@6+608 |
| 0x007f0b85 | CALL | 0x007f0af0 | CALLRET | GLOBAL | CONST | 0@6,1@6,2@6+608 |
| 0x007f0b9d | CALL | 0x007f0af0 | GLOBAL | STACKADDR | CONST | 0@6,1@6,2@6+608 |
| 0x007f0bf4 | CALL | 0x007f0af0 | CALLRET | GLOBAL | CONST | 0@6,1@6,2@6+608 |
| 0x007f0c4d | CALL | 0x007f0af0 | GLOBAL | GLOBAL | CONST | 0@6,1@6,2@6+608 |
| 0x007f0c88 | CALL | 0x007f0af0 | CALLRET | CALLRET | CONST | 0@6,1@6,2@6+608 |
| 0x007f0ca5 | CALL | 0x007f0af0 | CALLRET | CALLRET | CONST | 0@6,1@6,2@6+608 |
| 0x007f0cbd | CALL | 0x007f0af0 | GLOBAL | GLOBAL | CONST | 0@6,1@6,2@6+608 |
| 0x007f6e34 | CALL | 0x007f6dd0 | STACKADDR | USERARG | CONST | - |
| 0x007fa102 | CALL | 0x007f9e70 | DERIVED | DERIVED | CONST | - |
| 0x007fa7db | CALL | 0x007fa790 | STACKADDR | CALLRET | CONST | - |
| 0x007fa7ec | CALL | 0x007fa790 | STACKADDR | CALLRET | CONST | - |
| 0x007fa8cc | CALL | 0x007fa870 | GLOBAL | GLOBAL | CONST | 539@6,550@6,622@6+6 |
| 0x007fa907 | CALL | 0x007fa870 | GLOBAL | CALLRET | CONST | 539@6,550@6,622@6+6 |
| 0x007fa9fa | CALL | 0x007fa970 | CALLRET | GLOBAL | CONST | - |
| 0x007faa0a | CALL | 0x007fa970 | CALLRET | CALLRET | CONST | - |
| 0x007faae2 | CALL | 0x007fa970 | GLOBAL | GLOBAL | CONST | - |
| 0x007fab1d | CALL | 0x007fa970 | GLOBAL | CALLRET | CONST | - |
| 0x0080576e | CALL | 0x00805340 | CALLRET | DERIVED | CONST | - |
| 0x0080be2f | CALL | 0x0080bda0 | STACKADDR | GLOBAL | CONST | - |
| 0x0080bfb2 | CALL | 0x0080bda0 | STACKADDR | GLOBAL | CONST | - |
| 0x0080e131 | CALL | 0x0080df50 | UNKNOWN | USERARG | CONST | 92@1 |
| 0x0080e4f6 | CALL | 0x0080e290 | CALLRET | CALLRET | CALLRET | - |
| 0x0080e537 | CALL | 0x0080e290 | CALLRET | CALLRET | CALLRET | - |
| 0x0080e6e7 | CALL | 0x0080e680 | DEREF_USER_PTR | USER_PTR | USERARG | - |
| 0x0080e7ab | CALL | 0x0080e680 | CALLRET | CALLRET | CALLRET | - |
| 0x0080e872 | CALL | 0x0080e680 | DEREF_STACK | CALLRET | CALLRET | - |
| 0x0080ea78 | CALL | 0x0080e980 | USERARG | USERFIELD | UNKNOWN | - |
| 0x0080eaf0 | CALL | 0x0080e980 | DEREF_UNKNOWN | DERIVED | UNKNOWN | - |
| 0x00812faf | CALL | 0x00812560 | STACKADDR | DEREF_DEREF_CALLRET | DERIVED | - |
| 0x00814a9d | CALL | 0x00814800 | DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x00814eab | CALL | 0x00814800 | UNKNOWN | USER_PTR | USER_PTR | - |
| 0x00816097 | CALL | 0x00815ea0 | DEREF_CALLRET | STACK | CALLRET | - |
| 0x008161c7 | CALL | 0x00816170 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x0081683d | CALL | 0x008163e0 | CALLRET | DEREF_DEREF_CALLRET | DERIVED | - |
| 0x0081713a | CALL | 0x008163e0 | STACKADDR | DEREF_DEREF_CALLRET | DERIVED | - |
| 0x00817a2d | CALL | 0x00817910 | DERIVED | CALLRET | CALLRET | - |
| 0x00817b66 | CALL | 0x00817910 | STACK | UNKNOWN | CONST | - |
| 0x00817d28 | CALL | 0x00817910 | DEREF_STACK | CALLRET | DERIVED | - |
| 0x00817f7e | CALL | 0x00817910 | DEREF_STACK | STACK | DERIVED | - |
| 0x0081bc48 | CALL | 0x0081bbc0 | STACKADDR | CALLRET | CALLRET | - |
| 0x0081bd13 | CALL | 0x0081bc80 | CALLRET | STACKADDR | CALLRET | - |
| 0x0081c4ec | CALL | 0x0081c240 | CALLRET | STACKADDR | CONST | - |
| 0x0082658d | CALL | 0x00826520 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x00827f83 | CALL | 0x00827940 | DERIVED | UNKNOWN | UNKNOWN | - |
| 0x00828557 | CALL | 0x00828440 | STACK | DERIVED | STACK | - |
| 0x0082b533 | CALL | 0x0082b4b0 | CALLRET | CALLRET | CALLRET | - |
| 0x00830306 | CALL | 0x0082fb60 | USERFIELD | USERARG | DERIVED | - |
| 0x00830326 | CALL | 0x0082fb60 | STACKADDR | DEREF_UNKNOWN | DERIVED | - |
| 0x008303b4 | CALL | 0x00830390 | UNKNOWN | USERARG | CONST | - |
| 0x008304ba | CALL | 0x00830390 | STACKADDR | UNKNOWN | CONST | - |
| 0x008304cb | CALL | 0x00830390 | STACKADDR | CALLRET | CONST | - |
| 0x0083052b | CALL | 0x00830390 | STACKADDR | CALLRET | CONST | - |
| 0x0083053c | CALL | 0x00830390 | STACKADDR | CALLRET | CONST | - |
| 0x00830591 | CALL | 0x00830390 | STACKADDR | UNKNOWN | CONST | - |
| 0x008319e0 | CALL | 0x00831850 | DEREF_DEREF_UNKNOWN | DEREF_UNKNOWN | UNKNOWN | 1@4,4@5,5@6+33 |
| 0x00836191 | CALL | 0x00836100 | STACKADDR | GLOBAL | CONST | - |
| 0x0083638b | CALL | 0x00836100 | STACK | UNKNOWN | CONST | - |
| 0x00836766 | CALL | 0x00836100 | DEREF_DEREF_STACK | UNKNOWN | DEREF_CALLRET | - |
| 0x00837828 | CALL | 0x00837600 | DEREF_STACK | DERIVED | CONST | - |
| 0x008379f4 | CALL | 0x00837600 | DEREF_UNKNOWN | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | - |
| 0x00837b6b | CALL | 0x00837600 | UNKNOWN | UNKNOWN | CONST | - |
| 0x0083855b | CALL | 0x00837c80 | STACK | STACK | CONST | - |
| 0x008386da | CALL | 0x008385b0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00838c45 | CALL | 0x00838b50 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00838c55 | CALL | 0x00838b50 | CALLRET | CALLRET | CONST | - |
| 0x00838e6f | CALL | 0x00838d30 | STACKADDR | UNKNOWN | CONST | - |
| 0x00838f09 | CALL | 0x00838d30 | STACKADDR | DERIVED | CONST | - |
| 0x00838f9c | CALL | 0x00838d30 | STACKADDR | UNKNOWN | CONST | - |
| 0x00839164 | CALL | 0x00839020 | STACK | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x0083938a | CALL | 0x00839020 | STACK | DEREF_UNKNOWN | UNKNOWN | - |
| 0x0083951d | CALL | 0x00839020 | STACK | UNKNOWN | DERIVED | - |
| 0x00839b2a | CALL | 0x00839ae0 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00839bb8 | CALL | 0x00839ae0 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0083b143 | CALL | 0x0083b0d0 | DEREF_GLOBAL | DEREF_CALLRET | DERIVED | - |
| 0x0083b1e0 | CALL | 0x0083b0d0 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x0084410d | CALL | 0x00843cb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00844269 | CALL | 0x00843cb0 | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | CONST | - |
| 0x00844286 | CALL | 0x00843cb0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00844422 | CALL | 0x00843cb0 | STACKADDR | GLOBAL | CONST | - |
| 0x008445aa | CALL | 0x00843cb0 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00844836 | CALL | 0x00843cb0 | STACKADDR | DEREF_UNKNOWN | UNKNOWN | - |
| 0x00844af4 | CALL | 0x00843cb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00844bb2 | CALL | 0x00843cb0 | STACKADDR | DERIVED | CONST | - |
| 0x00844bf0 | CALL | 0x00843cb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00844c01 | CALL | 0x00843cb0 | STACKADDR | CALLRET | CONST | - |
| 0x0084591e | CALL | 0x00845590 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00845ac9 | CALL | 0x00845590 | STACKADDR | DERIVED | CONST | - |
| 0x00845b72 | CALL | 0x00845590 | STACKADDR | GLOBAL | CONST | - |
| 0x00845c0a | CALL | 0x00845590 | STACKADDR | GLOBAL | CONST | - |
| 0x00845d74 | CALL | 0x00845590 | STACKADDR | GLOBAL | CONST | - |
| 0x00845db7 | CALL | 0x00845590 | STACKADDR | GLOBAL | CONST | - |
| 0x00845e52 | CALL | 0x00845590 | STACKADDR | GLOBAL | CONST | - |
| 0x008460e8 | CALL | 0x00845590 | CALLRET | DERIVED | DEREF_CALLRET | - |
| 0x008461ea | CALL | 0x00845590 | DEREF_CALLRET | DERIVED | UNKNOWN | - |
| 0x00846281 | CALL | 0x00845590 | DEREF_STACK | DERIVED | UNKNOWN | - |
| 0x008463d7 | CALL | 0x00845590 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00846658 | CALL | 0x00845590 | DERIVED | DERIVED | DERIVED | - |
| 0x00847628 | CALL | 0x008473c0 | DEREF_UNKNOWN | DEREF_UNKNOWN | USERARG | - |
| 0x00847b09 | CALL | 0x008473c0 | CALLRET | STACKADDR | CONST | - |
| 0x00847b1a | CALL | 0x008473c0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00847b2b | CALL | 0x008473c0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00847b3d | CALL | 0x008473c0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00847b52 | CALL | 0x008473c0 | DERIVED | STACKADDR | CONST | - |
| 0x00847e74 | CALL | 0x008473c0 | STACKADDR | GLOBAL | CONST | - |
| 0x00849016 | CALL | 0x00848490 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00849044 | CALL | 0x00848490 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x0084b37d | CALL | 0x0084acd0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x0084b395 | CALL | 0x0084acd0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0084b3f8 | CALL | 0x0084acd0 | DEREF_DEREF_CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x0084b433 | CALL | 0x0084acd0 | DERIVED | DERIVED | CONST | - |
| 0x0084c720 | CALL | 0x0084c4c0 | GLOBAL | GLOBAL | USERARG | - |
| 0x0084d8f9 | CALL | 0x0084d7c0 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x0084d964 | CALL | 0x0084d7c0 | UNKNOWN | DERIVED | CONST | - |
| 0x0084dca4 | CALL | 0x0084d7c0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x0084ec20 | CALL | 0x0084ea70 | STACKADDR | DERIVED | CONST | - |
| 0x0084fa88 | CALL | 0x0084f9a0 | DERIVED | USERARG | USERARG | - |
| 0x0085a319 | CALL | 0x0085a210 | UNKNOWN | CALLRET | CALLRET | - |
| 0x0085c506 | CALL | 0x0085c3a0 | STACKADDR | STACK | CONST | - |
| 0x0085c535 | CALL | 0x0085c3a0 | DERIVED | DERIVED | CONST | - |
| 0x0085c5e9 | CALL | 0x0085c3a0 | STACK | DERIVED | CONST | - |
| 0x0085c62e | CALL | 0x0085c3a0 | DERIVED | STACKADDR | CONST | - |
| 0x0085c64a | CALL | 0x0085c3a0 | STACKADDR | USERARG | CONST | - |
| 0x0085c685 | CALL | 0x0085c3a0 | DERIVED | STACKADDR | CONST | - |
| 0x0085c8e8 | CALL | 0x0085c810 | DERIVED | UNKNOWN | CONST | - |
| 0x00861d7a | CALL | 0x008619f0 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00861e4b | CALL | 0x008619f0 | CALLRET | CALLRET | DERIVED | - |
| 0x00861f71 | CALL | 0x008619f0 | STACKADDR | UNKNOWN | CONST | - |
| 0x0086270c | CALL | 0x008620e0 | CALLRET | STACK | DEREF_CALLRET | - |
| 0x008644f7 | CALL | 0x00864370 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00864537 | CALL | 0x00864370 | DEREF_CALLRET | DEREF_CALLRET | GLOBAL | - |
| 0x00864550 | CALL | 0x00864370 | DERIVED | DERIVED | GLOBAL | - |
| 0x00864707 | CALL | 0x00864680 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00864719 | CALL | 0x00864680 | DERIVED | DEREF_CALLRET | CALLRET | - |
| 0x00865045 | CALL | 0x00865020 | DERIVED | USERARG | CONST | - |
| 0x0086e0cd | CALL | 0x0086e010 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x0086e17d | CALL | 0x0086e100 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0086ec9e | JMP | 0x0086ebf0 | DERIVED | DERIVED | CONST | - |
| 0x0086f6ba | CALL | 0x0086ecc0 | DEREF_STACK | DEREF_UNKNOWN | CONST | - |
| 0x0086fed2 | CALL | 0x0086fe50 | CALLRET | DEREF_DERIVED | CONST | - |
| 0x0086ff46 | CALL | 0x0086ff10 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x008703a4 | CALL | 0x00870060 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00870421 | CALL | 0x00870060 | CALLRET | GLOBAL | CONST | - |
| 0x0087262b | CALL | 0x00870b50 | CALLRET | DEREF_DEREF_STACK | DEREF_DEREF_STACK | - |
| 0x008763d8 | CALL | 0x008762b0 | UNKNOWN | STACKADDR | CONST | - |
| 0x0087e58d | CALL | 0x0087e1f0 | STACKADDR | GLOBAL | CONST | - |
| 0x0089704c | CALL | 0x008967a0 | CALLRET | DERIVED | CONST | 102@2,315@5 |
| 0x0089707d | CALL | 0x008967a0 | STACK | CALLRET | CONST | 102@2,315@5 |
| 0x00897349 | CALL | 0x008971d0 | CALLRET | DEREF_STACK | CONST | 102@3,315@6 |
| 0x00897752 | CALL | 0x008971d0 | USERFIELD | UNKNOWN | CONST | 102@3,315@6 |
| 0x0089a773 | CALL | 0x0089a6c0 | CALLRET | CALLRET | DERIVED | 341@6,431@6,601@5+1 |
| 0x0089aa60 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089aa86 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089aaac | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089aad9 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089ab15 | CALL | 0x0089a7c0 | DEREF_UNKNOWN | STACKADDR | CONST | 601@6,622@4 |
| 0x0089ab30 | CALL | 0x0089a7c0 | DEREF_CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089ab4b | CALL | 0x0089a7c0 | DEREF_CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089ab66 | CALL | 0x0089a7c0 | DEREF_CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089ab81 | CALL | 0x0089a7c0 | DEREF_CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089ab9c | CALL | 0x0089a7c0 | DEREF_CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089abb7 | CALL | 0x0089a7c0 | DEREF_CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089abd2 | CALL | 0x0089a7c0 | DEREF_CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089ad88 | CALL | 0x0089a7c0 | STACKADDR | STACKADDR | CONST | 601@6,622@4 |
| 0x0089ada2 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089adbc | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089add6 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089adf1 | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089ae0c | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089ae27 | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089ae42 | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089af47 | CALL | 0x0089a7c0 | STACKADDR | STACKADDR | CONST | 601@6,622@4 |
| 0x0089af64 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089af81 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089afa9 | CALL | 0x0089a7c0 | STACKADDR | STACKADDR | CONST | 601@6,622@4 |
| 0x0089afc6 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089afe3 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089b041 | CALL | 0x0089a7c0 | GLOBAL | STACKADDR | CONST | 601@6,622@4 |
| 0x0089b055 | CALL | 0x0089a7c0 | GLOBAL | CALLRET | CONST | 601@6,622@4 |
| 0x0089b0ba | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089b0d8 | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089b0f6 | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089b113 | CALL | 0x0089a7c0 | CALLRET | CALLRET | CONST | 601@6,622@4 |
| 0x0089b131 | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089b14f | CALL | 0x0089a7c0 | STACKADDR | CALLRET | CONST | 601@6,622@4 |
| 0x0089b1a2 | CALL | 0x0089a7c0 | GLOBAL | CALLRET | CONST | 601@6,622@4 |
| 0x0089b1b6 | CALL | 0x0089a7c0 | GLOBAL | CALLRET | CONST | 601@6,622@4 |
| 0x0089b2f2 | CALL | 0x0089a7c0 | STACKADDR | STACKADDR | CONST | 601@6,622@4 |
| 0x0089b328 | CALL | 0x0089a7c0 | DEREF_STACK | CALLRET | DERIVED | 601@6,622@4 |
| 0x0089e1ef | CALL | 0x0089e040 | STACKADDR | UNKNOWN | CONST | - |
| 0x0089e209 | CALL | 0x0089e040 | STACKADDR | STACK | CONST | - |
| 0x0089e248 | CALL | 0x0089e040 | STACKADDR | DEREF_STACK | CONST | - |
| 0x008a887c | CALL | 0x008a85a0 | STACKADDR | DERIVED | CONST | - |
| 0x008a896a | CALL | 0x008a85a0 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x008a8ac4 | CALL | 0x008a85a0 | STACKADDR | DERIVED | USERARG | - |
| 0x008a8b01 | CALL | 0x008a85a0 | STACKADDR | DERIVED | USERARG | - |
| 0x008aa8ec | CALL | 0x008aa810 | STACKADDR | DERIVED | CONST | - |
| 0x008aad10 | CALL | 0x008aabe0 | GLOBAL | STACKADDR | CONST | - |
| 0x008abef6 | CALL | 0x008ab5f0 | UNKNOWN | UNKNOWN | CONST | - |
| 0x008be7b5 | CALL | 0x008be690 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | 5@5,12@5,15@5+33 |
| 0x008be812 | CALL | 0x008be690 | UNKNOWN | CALLRET | DERIVED | 5@5,12@5,15@5+33 |
| 0x008bf64c | CALL | 0x008bf600 | CALLRET | CALLRET | CONST | - |
| 0x008bfa71 | CALL | 0x008bf920 | CALLRET | GLOBAL | GLOBAL | - |
| 0x008bfbce | CALL | 0x008bf920 | CALLRET | GLOBAL | GLOBAL | - |
| 0x008bfc2a | CALL | 0x008bf920 | STACKADDR | STACKADDR | CONST | - |
| 0x008bfc3b | CALL | 0x008bf920 | CALLRET | STACKADDR | CONST | - |
| 0x008c11c1 | CALL | 0x008c1140 | DERIVED | CALLRET | CALLRET | - |
| 0x008c1724 | CALL | 0x008c1500 | STACKADDR | USERARG | CONST | 334@4,607@6 |
| 0x008c183f | CALL | 0x008c17f0 | CALLRET | CALLRET | CALLRET | - |
| 0x008c1890 | JMP | 0x008c17f0 | CALLRET | DERIVED | DERIVED | - |
| 0x008c18fb | CALL | 0x008c18a0 | STACKADDR | USERARG | CONST | - |
| 0x008c2678 | CALL | 0x008c2640 | USERFIELD | GLOBAL | DERIVED | - |
| 0x008c268e | CALL | 0x008c2640 | USERARG | GLOBAL | DERIVED | - |
| 0x008c810e | CALL | 0x008c7bc0 | UNKNOWN | GLOBAL | CONST | 676@4 |
| 0x008d08f3 | CALL | 0x008cf6d0 | USERFIELD | USERFIELD | CONST | - |
| 0x008d2109 | CALL | 0x008d20c0 | CALLRET | CALLRET | CONST | - |
| 0x008d35bb | CALL | 0x008d2fc0 | STACK | STACK | CONST | - |
| 0x008d3e45 | CALL | 0x008d3df0 | DERIVED | CALLRET | CONST | - |
| 0x008d5998 | CALL | 0x008d4a80 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x008d8075 | CALL | 0x008d8030 | USERARG | CONST | UNKNOWN | - |
| 0x008d80e3 | CALL | 0x008d8090 | DERIVED | CALLRET | CALLRET | - |
| 0x008d8680 | CALL | 0x008d8090 | STACKADDR | CALLRET | CONST | - |
| 0x008d9a9d | CALL | 0x008d8090 | CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | - |
| 0x008d9d8a | CALL | 0x008d8090 | STACKADDR | CALLRET | CONST | - |
| 0x008da514 | CALL | 0x008d8090 | CALLRET | DEREF_CALLRET | DEREF_DEREF_CALLRET | - |
| 0x008dc153 | CALL | 0x008dbf50 | GLOBAL | CALLRET | CONST | - |
| 0x008f456f | CALL | 0x008f42b0 | STACKADDR | DERIVED | UNKNOWN | 5@4,12@3,15@3+16 |
| 0x008f539f | CALL | 0x008f4ce0 | DEREF_UNKNOWN | STACK | CONST | 5@5,12@4,15@4+15 |
| 0x008f5ac1 | CALL | 0x008f59c0 | CALLRET | CALLRET | CALLRET | 5@6,12@5,15@5+15 |
| 0x008f60b9 | CALL | 0x008f5d20 | STACKADDR | STACK | CONST | - |
| 0x008f63ea | CALL | 0x008f6120 | STACKADDR | CALLRET | CONST | - |
| 0x008f7683 | CALL | 0x008f6ea0 | STACKADDR | GLOBAL | CONST | 5@1,59@3,499@1 |
| 0x008f7a29 | CALL | 0x008f6ea0 | STACKADDR | GLOBAL | CONST | 5@1,59@3,499@1 |
| 0x008f83e7 | CALL | 0x008f80f0 | STACKADDR | GLOBAL | CONST | 5@2,59@4,499@2+1 |
| 0x008f9978 | CALL | 0x008f98f0 | STACKADDR | GLOBAL | CONST | 34@1,35@1 |
| 0x008f9aa4 | CALL | 0x008f9a30 | STACKADDR | GLOBAL | CONST | 15@1 |
| 0x008f9ee4 | CALL | 0x008f9e70 | STACKADDR | GLOBAL | CONST | - |
| 0x008fa606 | CALL | 0x008fa530 | STACKADDR | GLOBAL | CONST | 138@1,206@1 |
| 0x008fa66d | CALL | 0x008fa530 | STACKADDR | GLOBAL | CONST | 138@1,206@1 |
| 0x008fb127 | CALL | 0x008fafa0 | STACKADDR | GLOBAL | CONST | - |
| 0x008fba79 | CALL | 0x008fb900 | STACKADDR | GLOBAL | CONST | 532@5 |
| 0x008fd2f8 | CALL | 0x008fd2a0 | GLOBAL | CALLRET | CALLRET | - |
| 0x008fd3b1 | CALL | 0x008fd360 | GLOBAL | CALLRET | CALLRET | - |
| 0x008fd3e9 | CALL | 0x008fd360 | CALLRET | GLOBAL | STACK | - |
| 0x008fd488 | CALL | 0x008fd430 | GLOBAL | STACK | CALLRET | - |
| 0x008fd4c0 | CALL | 0x008fd430 | STACK | GLOBAL | STACK | - |
| 0x009027bb | CALL | 0x009026a0 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | 482@6 |
| 0x0090394a | CALL | 0x00903910 | UNKNOWN | GLOBAL | CALLRET | - |
| 0x0090454c | CALL | 0x00903ee0 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00904583 | CALL | 0x00903ee0 | UNKNOWN | STACKADDR | CONST | - |
| 0x0090527b | CALL | 0x00904e80 | UNKNOWN | STACKADDR | CONST | - |
| 0x0090535b | CALL | 0x00904e80 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x009066d3 | CALL | 0x009065d0 | DEREF_CALLRET | STACK | CONST | - |
| 0x00906858 | CALL | 0x00906780 | DERIVED | DERIVED | CONST | - |
| 0x00906920 | CALL | 0x009068c0 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x00906972 | CALL | 0x009068c0 | DERIVED | DERIVED | CONST | - |
| 0x00906fb0 | CALL | 0x00906f10 | STACK | DEREF_DERIVED | DEREF_DERIVED | 532@6 |
| 0x00907274 | CALL | 0x00907020 | DEREF_CALLRET | STACK | STACK | 532@6 |
| 0x0090852f | CALL | 0x00908360 | CALLRET | CALLRET | CALLRET | 97@5,113@5,135@5 |
| 0x00910f12 | CALL | 0x00910f00 | USERARG | USERARG | CONST | - |
| 0x00912e39 | CALL | 0x00912bc0 | DERIVED | DEREF_STACK | DEREF_STACK | 515@4,532@6,629@4+1 |
| 0x00912e82 | CALL | 0x00912bc0 | UNKNOWN | DEREF_STACK | DEREF_STACK | 515@4,532@6,629@4+1 |
| 0x00912eee | CALL | 0x00912bc0 | DERIVED | DEREF_STACK | DEREF_STACK | 515@4,532@6,629@4+1 |
| 0x00912f29 | CALL | 0x00912bc0 | UNKNOWN | DEREF_STACK | DEREF_STACK | 515@4,532@6,629@4+1 |
| 0x009157c3 | CALL | 0x00914d30 | STACKADDR | GLOBAL | CONST | - |
| 0x0091e5a6 | CALL | 0x0091e450 | GLOBAL | CALLRET | CONST | - |
| 0x0091e7e3 | CALL | 0x0091e450 | STACK | DERIVED | STACK | - |
| 0x009204dd | CALL | 0x009203c0 | CALLRET | CALLRET | CALLRET | 12@6,15@6,34@6+7 |
| 0x00922959 | CALL | 0x009226b0 | CALLRET | CALLRET | CONST | - |
| 0x009275d0 | CALL | 0x00927320 | DEREF_CALLRET | STACK | CALLRET | - |
| 0x0092a7c2 | CALL | 0x0092a2b0 | STACK | DEREF_STACK | STACK | 601@4 |
| 0x0092a7d8 | CALL | 0x0092a2b0 | CALLRET | DEREF_STACK | CALLRET | 601@4 |
| 0x0092b684 | CALL | 0x0092b540 | STACK | DEREF_STACK | STACK | - |
| 0x0092c2ac | CALL | 0x0092bdc0 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x0092c468 | CALL | 0x0092bdc0 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x0093722a | CALL | 0x009364e0 | UNKNOWN | STACK | DEREF_UNKNOWN | - |
| 0x00937bb4 | CALL | 0x009364e0 | DEREF_CALLRET | DEREF_STACK | DEREF_DEREF_CALLRET | - |
| 0x00937d43 | CALL | 0x009364e0 | DEREF_CALLRET | DEREF_STACK | DEREF_DEREF_CALLRET | - |
| 0x00937e93 | CALL | 0x009364e0 | UNKNOWN | UNKNOWN | DEREF_STACK | - |
| 0x00937ef1 | CALL | 0x009364e0 | UNKNOWN | STACK | DEREF_STACK | - |
| 0x00938062 | CALL | 0x009364e0 | STACK | STACKADDR | CONST | - |
| 0x009381b8 | CALL | 0x009364e0 | DERIVED | STACKADDR | CONST | - |
| 0x00938262 | CALL | 0x009364e0 | UNKNOWN | STACK | DEREF_STACK | - |
| 0x0093a43a | CALL | 0x00939ec0 | STACK | UNKNOWN | DEREF_UNKNOWN | - |
| 0x0093b0aa | CALL | 0x0093ac70 | USERFIELD | UNKNOWN | UNKNOWN | - |
| 0x0093b250 | CALL | 0x0093ac70 | CALLRET | DEREF_STACK | CALLRET | - |
| 0x0093bbfb | CALL | 0x0093ac70 | STACKADDR | UNKNOWN | CONST | - |
| 0x0093cf6c | CALL | 0x0093ac70 | STACKADDR | STACKADDR | CONST | - |
| 0x0093fe7a | CALL | 0x0093f8e0 | DEREF_CALLRET | DEREF_STACK | DEREF_DEREF_CALLRET | - |
| 0x0093ff4a | CALL | 0x0093f8e0 | USERARG | STACKADDR | CONST | - |
| 0x00940198 | CALL | 0x0093f8e0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x009435ef | CALL | 0x009434f0 | UNKNOWN | STACKADDR | CONST | 601@5 |
| 0x00945986 | CALL | 0x00945760 | DEREF_CALLRET | STACK | UNKNOWN | 601@4 |
| 0x00945cc0 | CALL | 0x00945c10 | UNKNOWN | DEREF_STACK | UNKNOWN | 601@5 |
| 0x00946ca4 | CALL | 0x00946930 | DERIVED | STACK | CONST | - |
| 0x00948544 | CALL | 0x009482c0 | DEREF_CALLRET | CALLRET | CALLRET | 601@4 |
| 0x0094855a | CALL | 0x009482c0 | DEREF_UNKNOWN | USERARG | CONST | 601@4 |
| 0x00949bf9 | CALL | 0x009488a0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0094ff3f | CALL | 0x0094e7b0 | STACKADDR | STACKADDR | CONST | - |
| 0x009501d3 | CALL | 0x0094e7b0 | STACKADDR | STACKADDR | CONST | - |
| 0x009512ea | CALL | 0x00951040 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00951a22 | CALL | 0x009517e0 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00951ce5 | CALL | 0x00951b70 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00951cff | CALL | 0x00951b70 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00951d10 | CALL | 0x00951b70 | STACK | CALLRET | CONST | - |
| 0x00951da3 | CALL | 0x00951b70 | DERIVED | DEREF_UNKNOWN | CONST | - |
| 0x00951ed9 | CALL | 0x00951e60 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x009527a4 | CALL | 0x00952310 | DEREF_CALLRET | DEREF_STACK | DEREF_DEREF_CALLRET | - |
| 0x00952a4c | CALL | 0x00952310 | DEREF_CALLRET | DEREF_STACK | DEREF_DEREF_CALLRET | - |
| 0x00952b49 | CALL | 0x00952310 | UNKNOWN | UNKNOWN | DEREF_STACK | - |
| 0x00952c95 | CALL | 0x00952310 | STACK | STACKADDR | CONST | - |
| 0x00953114 | CALL | 0x00952310 | DERIVED | STACKADDR | CONST | - |
| 0x009536b9 | CALL | 0x00953330 | DEREF_CALLRET | DEREF_STACK | DEREF_DEREF_CALLRET | - |
| 0x00953786 | CALL | 0x00953330 | UNKNOWN | UNKNOWN | DEREF_UNKNOWN | - |
| 0x00953899 | CALL | 0x009537d0 | UNKNOWN | UNKNOWN | DEREF_STACK | - |
| 0x009539c6 | CALL | 0x009537d0 | DERIVED | STACKADDR | CONST | - |
| 0x00954428 | JMP | 0x009543e0 | USERARG | USERFIELD | DEREF_USER_PTR | - |
| 0x00955f78 | CALL | 0x00955ab0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00956509 | CALL | 0x00956190 | CALLRET | CALLRET | CONST | - |
| 0x00956613 | CALL | 0x00956190 | STACKADDR | DEREF_CALLRET | DERIVED | - |
| 0x0095674e | CALL | 0x00956710 | STACKADDR | USERFIELD | CONST | - |
| 0x00956f92 | CALL | 0x00956ee0 | CALLRET | CALLRET | CALLRET | - |
| 0x00957025 | CALL | 0x00956ee0 | STACK | DEREF_CALLRET | STACK | - |
| 0x00957166 | CALL | 0x00957090 | UNKNOWN | STACKADDR | CONST | - |
| 0x00957276 | CALL | 0x009571a0 | UNKNOWN | STACKADDR | CONST | - |
| 0x00957386 | CALL | 0x009572b0 | UNKNOWN | STACKADDR | CONST | - |
| 0x0095742e | CALL | 0x009573c0 | CALLRET | CALLRET | CONST | - |
| 0x0095767e | CALL | 0x00957610 | CALLRET | CALLRET | CONST | - |
| 0x009577f5 | CALL | 0x00957760 | CALLRET | CALLRET | CONST | - |
| 0x009578b9 | CALL | 0x00957760 | USERARG | DERIVED | CONST | - |
| 0x0095797d | CALL | 0x00957900 | CALLRET | CALLRET | CONST | - |
| 0x00957abd | CALL | 0x00957a40 | CALLRET | CALLRET | CONST | - |
| 0x0095b863 | CALL | 0x0095b830 | STACKADDR | USERFIELD | CONST | 125@6 |
| 0x0095b87b | CALL | 0x0095b830 | STACKADDR | DERIVED | CONST | 125@6 |
| 0x0095f946 | CALL | 0x0095f730 | STACK | CALLRET | CALLRET | 28@6,133@6 |
| 0x0095fa35 | CALL | 0x0095f9f0 | GLOBAL | CALLRET | CALLRET | - |
| 0x0095faa0 | CALL | 0x0095fa60 | GLOBAL | CALLRET | CALLRET | 341@5,345@6,346@6+3 |
| 0x0095fbb9 | CALL | 0x0095fac0 | CALLRET | GLOBAL | CALLRET | 1@6,59@6,341@4+7 |
| 0x00963641 | CALL | 0x009629c0 | DERIVED | STACKADDR | CONST | - |
| 0x00964cf9 | CALL | 0x00964ca0 | CALLRET | CALLRET | CONST | - |
| 0x00964d7f | CALL | 0x00964d30 | CALLRET | CALLRET | CONST | - |
| 0x00964dd6 | JMP | 0x00964db0 | USERFIELD | USERARG | DERIVED | - |
| 0x00964e61 | CALL | 0x00964e20 | CALLRET | CALLRET | CONST | - |
| 0x00965acc | CALL | 0x009659e0 | STACKADDR | UNKNOWN | USERARG | 0@3,2@3,3@3+562 |
| 0x009666ad | CALL | 0x009659e0 | STACKADDR | DEREF_UNKNOWN | CONST | 0@3,2@3,3@3+562 |
| 0x009666d0 | CALL | 0x009659e0 | STACKADDR | DERIVED | CONST | 0@3,2@3,3@3+562 |
| 0x00968790 | CALL | 0x009684f0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00969d18 | CALL | 0x009699e0 | GLOBAL | DERIVED | CONST | - |
| 0x0096a28d | CALL | 0x0096a200 | GLOBAL | STACKADDR | CONST | 588@6 |
| 0x0096a2b4 | CALL | 0x0096a200 | GLOBAL | CALLRET | CONST | 588@6 |
| 0x0096a2db | CALL | 0x0096a200 | GLOBAL | CALLRET | CONST | 588@6 |
| 0x0096cbb0 | CALL | 0x0096cb40 | USERARG | DERIVED | DEREF_UNKNOWN | - |
| 0x0096cc21 | CALL | 0x0096cbc0 | USERARG | DERIVED | USERFIELD | - |
| 0x0096cc91 | CALL | 0x0096cc30 | USERARG | DERIVED | USERFIELD | - |
| 0x0096cd76 | CALL | 0x0096cce0 | STACKADDR | DERIVED | USER_PTR | - |
| 0x0096cde6 | CALL | 0x0096cce0 | STACK | STACKADDR | CALLRET | - |
| 0x0096ce70 | CALL | 0x0096ce20 | DERIVED | USERARG | USERARG | - |
| 0x0096d2b6 | CALL | 0x0096d0b0 | GLOBAL | GLOBAL | DERIVED | - |
| 0x0096e687 | CALL | 0x0096e610 | DERIVED | DERIVED | CONST | - |
| 0x0096e788 | CALL | 0x0096e6e0 | GLOBAL | DEREF_CALLRET | DERIVED | - |
| 0x0096e844 | JMP | 0x0096e6e0 | GLOBAL | DEREF_UNKNOWN | DERIVED | - |
| 0x0096e859 | CALL | 0x0096e6e0 | STACKADDR | GLOBAL | CONST | - |
| 0x0096f52b | CALL | 0x0096f160 | STACK | CALLRET | CALLRET | - |
| 0x0096fa84 | CALL | 0x0096f160 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x009700b5 | CALL | 0x0096f160 | STACKADDR | GLOBAL | CONST | - |
| 0x009700e3 | CALL | 0x0096f160 | CALLRET | CALLRET | CONST | - |
| 0x00970422 | CALL | 0x0096f160 | UNKNOWN | STACKADDR | CONST | - |
| 0x009705f5 | CALL | 0x0096f160 | USERARG | GLOBAL | CONST | - |
| 0x00970844 | CALL | 0x00970760 | USERARG | GLOBAL | CONST | - |
| 0x009708be | CALL | 0x00970760 | STACKADDR | STACKADDR | CONST | - |
| 0x009708d6 | CALL | 0x00970760 | STACKADDR | STACKADDR | CONST | - |
| 0x009754fa | CALL | 0x00975470 | STACKADDR | STACKADDR | CONST | 233@1 |
| 0x00975707 | CALL | 0x009755d0 | STACKADDR | STACKADDR | CONST | 233@1 |
| 0x00975894 | CALL | 0x00975780 | STACKADDR | STACKADDR | CONST | 232@2,431@4 |
| 0x009759c2 | CALL | 0x00975780 | STACKADDR | STACKADDR | CONST | 232@2,431@4 |
| 0x009759d4 | CALL | 0x00975780 | STACKADDR | STACKADDR | CONST | 232@2,431@4 |
| 0x00975aae | CALL | 0x00975780 | CALLRET | STACKADDR | CONST | 232@2,431@4 |
| 0x00975af0 | CALL | 0x00975780 | CALLRET | STACKADDR | CONST | 232@2,431@4 |
| 0x00975b32 | CALL | 0x00975780 | CALLRET | STACKADDR | CONST | 232@2,431@4 |
| 0x00976043 | CALL | 0x00975780 | CALLRET | STACKADDR | CONST | 232@2,431@4 |
| 0x00976085 | CALL | 0x00975780 | CALLRET | STACKADDR | CONST | 232@2,431@4 |
| 0x009760c7 | CALL | 0x00975780 | CALLRET | STACKADDR | CONST | 232@2,431@4 |
| 0x0097619c | CALL | 0x00975780 | STACKADDR | STACKADDR | CONST | 232@2,431@4 |
| 0x00976296 | CALL | 0x00975780 | STACKADDR | STACKADDR | CONST | 232@2,431@4 |
| 0x009779b3 | CALL | 0x00977630 | DEREF_CALLRET | DERIVED | DEREF_CALLRET | - |
| 0x00977b32 | CALL | 0x00977630 | DEREF_CALLRET | DERIVED | CALLRET | - |
| 0x00978c96 | CALL | 0x00978ac0 | STACK | DERIVED | DERIVED | - |
| 0x0097cd53 | CALL | 0x0097c180 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00980335 | CALL | 0x00980300 | STACKADDR | STACKADDR | CONST | 626@5 |
| 0x009812a4 | CALL | 0x00980cd0 | CALLRET | GLOBAL | CONST | - |
| 0x009814b4 | CALL | 0x00980cd0 | CALLRET | GLOBAL | CONST | - |
| 0x00982dcf | CALL | 0x00982b30 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00982deb | CALL | 0x00982b30 | DERIVED | DEREF_STACK | UNKNOWN | - |
| 0x00982e88 | CALL | 0x00982b30 | DERIVED | STACKADDR | CONST | - |
| 0x00982ea5 | CALL | 0x00982b30 | DEREF_DEREF_CALLRET | DEREF_STACK | UNKNOWN | - |
| 0x00982eda | CALL | 0x00982b30 | DERIVED | STACKADDR | CONST | - |
| 0x00982efa | CALL | 0x00982b30 | DEREF_CALLRET | DEREF_STACK | UNKNOWN | - |
| 0x00982f24 | CALL | 0x00982b30 | DEREF_DERIVED | STACK | CALLRET | - |
| 0x009838b9 | CALL | 0x00983620 | DEREF_DERIVED | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x0098562c | CALL | 0x009855c0 | USERFIELD | USERARG | DEREF_UNKNOWN | - |
| 0x00986fe7 | CALL | 0x009855c0 | DEREF_UNKNOWN | UNKNOWN | DERIVED | - |
| 0x00987451 | CALL | 0x009873f0 | DEREF_UNKNOWN | UNKNOWN | DERIVED | - |
| 0x0098b904 | CALL | 0x0098b8d0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0098eaa3 | CALL | 0x0098c7f0 | STACKADDR | GLOBAL | CONST | 12@6,15@6,34@6+7 |
| 0x0098f228 | CALL | 0x0098ee00 | DEREF_STACK | DEREF_CALLRET | CONST | - |
| 0x009914a4 | CALL | 0x00991400 | UNKNOWN | STACKADDR | USERARG | - |
| 0x0099152e | CALL | 0x009914d0 | STACKADDR | CALLRET | CALLRET | - |
| 0x00991674 | CALL | 0x009915d0 | UNKNOWN | STACKADDR | USERARG | - |
| 0x009916fe | CALL | 0x009916a0 | STACKADDR | CALLRET | CALLRET | - |
| 0x00992870 | CALL | 0x00992780 | DERIVED | USERFIELD | CONST | - |
| 0x009928cb | JMP | 0x00992780 | DERIVED | CALLRET | CONST | - |
| 0x00992998 | CALL | 0x00992910 | DERIVED | USERFIELD | CONST | - |
| 0x00996ca0 | CALL | 0x009969b0 | CALLRET | DERIVED | DERIVED | - |
| 0x00996e83 | CALL | 0x009969b0 | DERIVED | STACKADDR | DERIVED | - |
| 0x00999871 | CALL | 0x00999660 | CALLRET | CALLRET | CONST | - |
| 0x00999f35 | CALL | 0x00999c60 | DEREF_CALLRET | DERIVED | CALLRET | - |
| 0x0099a131 | CALL | 0x00999c60 | STACKADDR | DERIVED | CONST | - |
| 0x0099a7ed | CALL | 0x0099a5e0 | STACK | DEREF_UNKNOWN | USERARG | - |
| 0x0099ac56 | CALL | 0x0099aab0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x0099acc9 | CALL | 0x0099aab0 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x0099d648 | CALL | 0x0099c400 | UNKNOWN | USERARG | DEREF_UNKNOWN | 622@2 |
| 0x0099d6db | CALL | 0x0099c400 | UNKNOWN | UNKNOWN | UNKNOWN | 622@2 |
| 0x0099d6fc | CALL | 0x0099c400 | UNKNOWN | USERARG | UNKNOWN | 622@2 |
| 0x0099d759 | CALL | 0x0099c400 | UNKNOWN | USERARG | UNKNOWN | 622@2 |
| 0x009a297a | CALL | 0x009a2640 | DEREF_STACK | DEREF_STACK | CONST | - |
| 0x009a2f68 | CALL | 0x009a2640 | DEREF_STACK | DEREF_STACK | CONST | - |
| 0x009aef40 | CALL | 0x009ae2c0 | STACKADDR | STACKADDR | CONST | - |
| 0x009af033 | CALL | 0x009ae2c0 | STACKADDR | STACKADDR | CONST | - |
| 0x009af36c | CALL | 0x009ae2c0 | STACKADDR | STACKADDR | CONST | - |
| 0x009afd96 | CALL | 0x009ae2c0 | STACKADDR | STACKADDR | CONST | - |
| 0x009b0397 | CALL | 0x009ae2c0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x009b03ad | CALL | 0x009ae2c0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x009b03c2 | CALL | 0x009ae2c0 | STACKADDR | DERIVED | CONST | - |
| 0x009b20d8 | CALL | 0x009b2090 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x009b2519 | CALL | 0x009b2410 | CALLRET | CALLRET | CALLRET | - |
| 0x009b27a6 | CALL | 0x009b2690 | DEREF_DEREF_DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x009b29a4 | CALL | 0x009b2690 | DEREF_DEREF_DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x009b2d56 | CALL | 0x009b2690 | DEREF_UNKNOWN | DERIVED | DEREF_UNKNOWN | - |
| 0x009b3296 | CALL | 0x009b31c0 | STACKADDR | USER_PTR | CONST | - |
| 0x009b97ec | CALL | 0x009b94f0 | DERIVED | STACK | CONST | - |
| 0x009b97fd | CALL | 0x009b94f0 | STACK | CALLRET | CONST | - |
| 0x009b980f | CALL | 0x009b94f0 | STACK | STACK | CONST | - |
| 0x009b9824 | CALL | 0x009b94f0 | STACK | STACK | CONST | - |
| 0x009baf5a | CALL | 0x009bad40 | USERARG | UNKNOWN | CONST | - |
| 0x009baf72 | CALL | 0x009bad40 | DEREF_CALLRET | STACK | CONST | - |
| 0x009bb635 | CALL | 0x009bb3f0 | CALLRET | CALLRET | CONST | - |
| 0x009c07ed | CALL | 0x009c0730 | UNKNOWN | STACKADDR | CONST | - |
| 0x009c0d04 | CALL | 0x009c0c60 | UNKNOWN | STACKADDR | CONST | - |
| 0x009c2000 | CALL | 0x009c1c90 | UNKNOWN | UNKNOWN | CONST | - |
| 0x009c215b | CALL | 0x009c1c90 | UNKNOWN | STACK | USERARG | - |
| 0x009c2981 | CALL | 0x009c26a0 | STACKADDR | UNKNOWN | CONST | 647@5 |
| 0x009c29bf | CALL | 0x009c26a0 | STACKADDR | DEREF_DERIVED | CONST | 647@5 |
| 0x009c2b64 | CALL | 0x009c2a40 | STACK | DERIVED | CONST | 647@6 |
| 0x009c2b97 | CALL | 0x009c2a40 | STACK | DEREF_UNKNOWN | CONST | 647@6 |
| 0x009c2f02 | CALL | 0x009c2c10 | STACKADDR | DERIVED | CONST | 647@5 |
| 0x009c6b81 | CALL | 0x009c6a40 | UNKNOWN | STACKADDR | CONST | - |
| 0x009c7400 | CALL | 0x009c7230 | GLOBAL | GLOBAL | CALLRET | - |
| 0x009c771c | CALL | 0x009c7620 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x009c836e | CALL | 0x009c8320 | CALLRET | CALLRET | CONST | - |
| 0x009cdf2d | CALL | 0x009cb390 | DERIVED | DERIVED | CONST | - |
| 0x009cef5d | CALL | 0x009cef00 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x009cf594 | CALL | 0x009cf100 | DERIVED | STACK | UNKNOWN | - |
| 0x009cfb7c | CALL | 0x009cf100 | CALLRET | CALLRET | CONST | - |
| 0x009cfdee | CALL | 0x009cf100 | CALLRET | CALLRET | CALLRET | - |
| 0x009d050a | CALL | 0x009d0430 | GLOBAL | CALLRET | CONST | - |
| 0x009d0c66 | CALL | 0x009d0850 | DERIVED | USERARG | USERARG | - |
| 0x009d0c7e | CALL | 0x009d0850 | USERFIELD | USERARG | USERARG | - |
| 0x009d0ce8 | CALL | 0x009d0850 | CALLRET | DEREF_GLOBAL | CALLRET | - |
| 0x009d0d73 | CALL | 0x009d0850 | CALLRET | CALLRET | CALLRET | - |
| 0x009d0d8d | CALL | 0x009d0850 | UNKNOWN | USERARG | UNKNOWN | - |
| 0x009d0df5 | CALL | 0x009d0850 | DEREF_DEREF_GLOBAL | DEREF_GLOBAL | UNKNOWN | - |
| 0x009d12b1 | CALL | 0x009d0850 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x009d29db | CALL | 0x009d1bb0 | USERFIELD | USERFIELD | DERIVED | - |
| 0x009d2e46 | CALL | 0x009d2d50 | USERFIELD | DEREF_GLOBAL | USERFIELD | - |
| 0x009d38bb | CALL | 0x009d2d50 | DEREF_UNKNOWN | USERFIELD | USERARG | - |
| 0x009d395f | CALL | 0x009d2d50 | DERIVED | CALLRET | DERIVED | - |
| 0x009d3f22 | CALL | 0x009d3e60 | UNKNOWN | UNKNOWN | CONST | - |
| 0x009d4024 | CALL | 0x009d3ff0 | GLOBAL | USERARG | CONST | - |
| 0x009d4566 | CALL | 0x009d42a0 | DEREF_GLOBAL | CALLRET | CONST | - |
| 0x009d5fab | CALL | 0x009d5aa0 | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | CONST | - |
| 0x009d5fc3 | CALL | 0x009d5aa0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x009d7a12 | CALL | 0x009d7760 | CALLRET | CALLRET | CALLRET | 0@6,2@5,3@6+585 |
| 0x009dedfc | CALL | 0x009debf0 | STACKADDR | GLOBAL | CONST | - |
| 0x009dee79 | CALL | 0x009debf0 | UNKNOWN | GLOBAL | CONST | - |
| 0x009deeed | CALL | 0x009debf0 | STACKADDR | GLOBAL | CONST | - |
| 0x009def29 | CALL | 0x009debf0 | CALLRET | STACKADDR | CONST | - |
| 0x009defb9 | CALL | 0x009debf0 | STACKADDR | GLOBAL | CONST | - |
| 0x009defcd | CALL | 0x009debf0 | STACKADDR | CALLRET | CONST | - |
| 0x009df05f | CALL | 0x009debf0 | STACKADDR | GLOBAL | CONST | - |
| 0x009df1e8 | CALL | 0x009df130 | CALLRET | STACKADDR | CONST | - |
| 0x009dfbd6 | CALL | 0x009df830 | GLOBAL | USERARG | UNKNOWN | - |
| 0x009dff1e | CALL | 0x009dfdf0 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x009e0781 | CALL | 0x009dfdf0 | CALLRET | STACKADDR | CONST | - |
| 0x009e2956 | CALL | 0x009e2920 | CALLRET | CALLRET | CONST | - |
| 0x009e2998 | CALL | 0x009e2970 | CALLRET | GLOBAL | CONST | - |
| 0x009e2a84 | CALL | 0x009e2a40 | USERARG | DEREF_GLOBAL | DERIVED | - |
| 0x009e2a9a | CALL | 0x009e2a40 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x009e2afa | CALL | 0x009e2ab0 | USERARG | DEREF_DEREF_GLOBAL | DERIVED | - |
| 0x009e2b4b | CALL | 0x009e2b10 | USERARG | DEREF_DEREF_GLOBAL | DERIVED | - |
| 0x009eb01a | CALL | 0x009eadd0 | CALLRET | CALLRET | CONST | 37@3,652@3 |
| 0x009eb02f | CALL | 0x009eadd0 | DEREF_CALLRET | DEREF_CALLRET | CONST | 37@3,652@3 |
| 0x009eb420 | CALL | 0x009eb210 | DEREF_GLOBAL | UNKNOWN | CONST | 37@2,652@2 |
| 0x009eb44b | CALL | 0x009eb210 | CALLRET | DEREF_CALLRET | CONST | 37@2,652@2 |
| 0x009f8d2f | CALL | 0x009f8ce0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x009fdc94 | CALL | 0x009fd1d0 | USER_PTR | STACKADDR | CONST | 59@1 |
| 0x009fdcb8 | CALL | 0x009fd1d0 | DEREF_DEREF_STACK | STACKADDR | CONST | 59@1 |
| 0x009fdcda | CALL | 0x009fd1d0 | DERIVED | STACKADDR | CONST | 59@1 |
| 0x009fdcfe | CALL | 0x009fd1d0 | DEREF_DEREF_STACK | STACKADDR | CONST | 59@1 |
| 0x009fe088 | CALL | 0x009fd1d0 | STACKADDR | DEREF_DEREF_CALLRET | CONST | 59@1 |
| 0x009fe0a5 | CALL | 0x009fd1d0 | STACKADDR | DEREF_DEREF_CALLRET | CONST | 59@1 |
| 0x009fe0c0 | CALL | 0x009fd1d0 | STACKADDR | DERIVED | CONST | 59@1 |
| 0x009fe0dd | CALL | 0x009fd1d0 | STACKADDR | DEREF_DEREF_CALLRET | CONST | 59@1 |
| 0x009fe40b | CALL | 0x009fd1d0 | DEREF_DEREF_UNKNOWN | STACKADDR | CONST | 59@1 |
| 0x009fe428 | CALL | 0x009fd1d0 | DEREF_DEREF_CALLRET | STACKADDR | CONST | 59@1 |
| 0x009fe445 | CALL | 0x009fd1d0 | DEREF_DEREF_CALLRET | STACKADDR | CONST | 59@1 |
| 0x009fe462 | CALL | 0x009fd1d0 | DEREF_DEREF_CALLRET | STACKADDR | CONST | 59@1 |
| 0x009fe7c6 | CALL | 0x009fd1d0 | STACKADDR | DERIVED | CONST | 59@1 |
| 0x009fe7e2 | CALL | 0x009fd1d0 | STACKADDR | DERIVED | CONST | 59@1 |
| 0x009fe7fe | CALL | 0x009fd1d0 | STACKADDR | DERIVED | CONST | 59@1 |
| 0x009fe816 | CALL | 0x009fd1d0 | CALLRET | DERIVED | CONST | 59@1 |
| 0x009fe8d7 | CALL | 0x009fd1d0 | CALLRET | DERIVED | CONST | 59@1 |
| 0x009fe8f4 | CALL | 0x009fd1d0 | STACKADDR | UNKNOWN | CONST | 59@1 |
| 0x009fe911 | CALL | 0x009fd1d0 | STACKADDR | UNKNOWN | CONST | 59@1 |
| 0x009fe92e | CALL | 0x009fd1d0 | STACKADDR | UNKNOWN | CONST | 59@1 |
| 0x009feb8c | CALL | 0x009feaa0 | DEREF_CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x009fed16 | CALL | 0x009feaa0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x009fed2e | CALL | 0x009feaa0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x009fed46 | CALL | 0x009feaa0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x009fed5e | CALL | 0x009feaa0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x009feecc | CALL | 0x009feaa0 | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | CONST | - |
| 0x009feee7 | CALL | 0x009feaa0 | DEREF_CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x009fef00 | CALL | 0x009feaa0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x009fef1b | CALL | 0x009feaa0 | DEREF_CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x00a0095c | CALL | 0x00a008e0 | CALLRET | DERIVED | CONST | - |
| 0x00a00aaa | CALL | 0x00a009c0 | CALLRET | UNKNOWN | CONST | - |
| 0x00a04859 | CALL | 0x00a04430 | CALLRET | STACKADDR | CONST | 37@6,652@6 |
| 0x00a05304 | CALL | 0x00a04430 | STACKADDR | DEREF_CALLRET | DEREF_CALLRET | 37@6,652@6 |
| 0x00a053f4 | CALL | 0x00a04430 | DERIVED | STACKADDR | DEREF_CALLRET | 37@6,652@6 |
| 0x00a058a6 | CALL | 0x00a04430 | STACKADDR | DEREF_UNKNOWN | CONST | 37@6,652@6 |
| 0x00a058be | CALL | 0x00a04430 | STACKADDR | DEREF_CALLRET | CONST | 37@6,652@6 |
| 0x00a058d6 | CALL | 0x00a04430 | STACKADDR | DEREF_CALLRET | CONST | 37@6,652@6 |
| 0x00a058ee | CALL | 0x00a04430 | STACKADDR | DEREF_CALLRET | CONST | 37@6,652@6 |
| 0x00a05a23 | CALL | 0x00a04430 | DEREF_CALLRET | STACKADDR | CONST | 37@6,652@6 |
| 0x00a05a3b | CALL | 0x00a04430 | DEREF_CALLRET | STACKADDR | CONST | 37@6,652@6 |
| 0x00a05a53 | CALL | 0x00a04430 | DEREF_CALLRET | STACKADDR | CONST | 37@6,652@6 |
| 0x00a05a6e | CALL | 0x00a04430 | DERIVED | STACKADDR | CONST | 37@6,652@6 |
| 0x00a05b93 | CALL | 0x00a04430 | STACKADDR | DERIVED | CONST | 37@6,652@6 |
| 0x00a0c1b9 | CALL | 0x00a0c0b0 | UNKNOWN | STACKADDR | UNKNOWN | 2@6,5@6,12@5+24 |
| 0x00a10c73 | CALL | 0x00a10b30 | STACKADDR | GLOBAL | CONST | - |
| 0x00a1282e | CALL | 0x00a127c0 | STACKADDR | GLOBAL | CONST | - |
| 0x00a12b87 | CALL | 0x00a12940 | STACKADDR | GLOBAL | CONST | - |
| 0x00a12d9b | CALL | 0x00a12cf0 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00a12e16 | CALL | 0x00a12cf0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a12e48 | CALL | 0x00a12cf0 | STACKADDR | CALLRET | CONST | - |
| 0x00a12e75 | CALL | 0x00a12cf0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a12e8c | CALL | 0x00a12cf0 | CALLRET | DERIVED | CONST | - |
| 0x00a130e0 | CALL | 0x00a13020 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00a1318b | CALL | 0x00a13020 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00a1324b | CALL | 0x00a13210 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00a13e75 | CALL | 0x00a13680 | STACK | DEREF_CALLRET | CALLRET | - |
| 0x00a159de | CALL | 0x00a14130 | CALLRET | STACKADDR | CONST | - |
| 0x00a15d7f | CALL | 0x00a14130 | STACKADDR | CALLRET | CONST | - |
| 0x00a16162 | CALL | 0x00a14130 | STACK | STACKADDR | CONST | - |
| 0x00a161fd | CALL | 0x00a14130 | STACKADDR | USERARG | CONST | - |
| 0x00a16b0f | CALL | 0x00a14130 | STACKADDR | USERARG | CONST | - |
| 0x00a16cdb | CALL | 0x00a14130 | STACKADDR | USERARG | CONST | - |
| 0x00a16f0d | CALL | 0x00a14130 | STACKADDR | CALLRET | CONST | - |
| 0x00a16fef | CALL | 0x00a14130 | STACKADDR | CALLRET | CONST | - |
| 0x00a175a5 | CALL | 0x00a14130 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00a175eb | CALL | 0x00a14130 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00a175ff | CALL | 0x00a14130 | CALLRET | STACKADDR | CONST | - |
| 0x00a1bfc0 | CALL | 0x00a1bd30 | DEREF_UNKNOWN | UNKNOWN | DEREF_UNKNOWN | - |
| 0x00a1c0b3 | CALL | 0x00a1bfe0 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00a1c42f | CALL | 0x00a1c2a0 | DERIVED | UNKNOWN | CALLRET | - |
| 0x00a1c4d4 | CALL | 0x00a1c2a0 | UNKNOWN | DEREF_STACK | CALLRET | - |
| 0x00a1ce70 | CALL | 0x00a1caf0 | DERIVED | DERIVED | DERIVED | - |
| 0x00a1d013 | CALL | 0x00a1caf0 | DERIVED | DERIVED | DERIVED | - |
| 0x00a1d056 | CALL | 0x00a1caf0 | UNKNOWN | STACK | USERARG | - |
| 0x00a1ecc8 | CALL | 0x00a1e7c0 | DEREF_STACK | STACK | UNKNOWN | - |
| 0x00a2405b | CALL | 0x00a1f6f0 | STACK | DEREF_STACK | DERIVED | - |
| 0x00a2408b | CALL | 0x00a1f6f0 | DERIVED | DERIVED | STACK | - |
| 0x00a242b8 | CALL | 0x00a1f6f0 | STACK | DEREF_STACK | STACK | - |
| 0x00a2fb32 | CALL | 0x00a2f8f0 | STACK | CALLRET | CONST | - |
| 0x00a2fd79 | CALL | 0x00a2fba0 | STACK | CALLRET | CONST | - |
| 0x00a2fdfb | CALL | 0x00a2fd90 | CALLRET | CALLRET | CONST | - |
| 0x00a2fe93 | CALL | 0x00a2fd90 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00a30041 | CALL | 0x00a2ff10 | STACK | DEREF_UNKNOWN | CONST | - |
| 0x00a303be | CALL | 0x00a30350 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x00a308c9 | CALL | 0x00a30420 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00a308e5 | CALL | 0x00a30420 | DERIVED | DERIVED | CONST | - |
| 0x00a3090c | CALL | 0x00a30420 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00a30968 | CALL | 0x00a30420 | DEREF_STACK | DERIVED | CONST | - |
| 0x00a31237 | CALL | 0x00a31150 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x00a3152e | CALL | 0x00a31150 | DEREF_STACK | DERIVED | CONST | - |
| 0x00a31df0 | CALL | 0x00a31c20 | STACK | USERFIELD | CONST | - |
| 0x00a32721 | CALL | 0x00a324e0 | STACKADDR | CALLRET | CONST | - |
| 0x00a32a84 | CALL | 0x00a324e0 | DERIVED | DERIVED | CONST | - |
| 0x00a32af8 | CALL | 0x00a324e0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00a32b38 | CALL | 0x00a324e0 | STACKADDR | CALLRET | CONST | - |
| 0x00a32c0e | CALL | 0x00a324e0 | DERIVED | DERIVED | CONST | - |
| 0x00a331ab | CALL | 0x00a324e0 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x00a335f8 | CALL | 0x00a324e0 | DERIVED | STACK | CONST | - |
| 0x00a338a3 | CALL | 0x00a337e0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00a338b5 | CALL | 0x00a337e0 | STACKADDR | STACK | CONST | - |
| 0x00a33b9c | CALL | 0x00a33af0 | DEREF_GLOBAL | DEREF_GLOBAL | CONST | - |
| 0x00a33cfb | CALL | 0x00a33c70 | CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x00a3b74b | CALL | 0x00a397b0 | CALLRET | STACK | CONST | 601@4 |
| 0x00a3e279 | CALL | 0x00a3e010 | DEREF_UNKNOWN | DERIVED | CONST | 601@5 |
| 0x00a3fead | CALL | 0x00a3f4f0 | STACK | UNKNOWN | DERIVED | - |
| 0x00a4063d | CALL | 0x00a3ff80 | STACK | UNKNOWN | DERIVED | - |
| 0x00a40e5e | CALL | 0x00a40db0 | DERIVED | CALLRET | CALLRET | 532@6 |
| 0x00a40eb9 | CALL | 0x00a40db0 | STACK | DERIVED | STACK | 532@6 |
| 0x00a42eaa | CALL | 0x00a42a40 | STACKADDR | STACKADDR | CONST | - |
| 0x00a42fca | CALL | 0x00a42a40 | STACKADDR | STACKADDR | CONST | - |
| 0x00a4328d | CALL | 0x00a42a40 | STACKADDR | STACKADDR | CONST | - |
| 0x00a44caa | CALL | 0x00a44c10 | CALLRET | CALLRET | CALLRET | - |
| 0x00a4550b | CALL | 0x00a45390 | STACK | STACK | UNKNOWN | - |
| 0x00a455af | CALL | 0x00a45390 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00a45660 | CALL | 0x00a45390 | CALLRET | STACK | CALLRET | - |
| 0x00a4752c | CALL | 0x00a47390 | STACKADDR | STACKADDR | CONST | - |
| 0x00a4753e | CALL | 0x00a47390 | STACKADDR | STACKADDR | CONST | - |
| 0x00a4792b | CALL | 0x00a475b0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a4793d | CALL | 0x00a475b0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a47a93 | CALL | 0x00a479c0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a47aa5 | CALL | 0x00a479c0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a47ee6 | CALL | 0x00a47c10 | GLOBAL | STACKADDR | CONST | - |
| 0x00a48186 | CALL | 0x00a47c10 | CALLRET | GLOBAL | CONST | - |
| 0x00a48a64 | CALL | 0x00a47c10 | GLOBAL | STACKADDR | CONST | - |
| 0x00a48b97 | CALL | 0x00a47c10 | GLOBAL | STACKADDR | CONST | - |
| 0x00a491b2 | CALL | 0x00a47c10 | GLOBAL | STACKADDR | CONST | - |
| 0x00a49968 | CALL | 0x00a49900 | GLOBAL | STACKADDR | CONST | - |
| 0x00a4ac66 | CALL | 0x00a4ac40 | USERARG | GLOBAL | CONST | - |
| 0x00a4adb1 | CALL | 0x00a4ad40 | CALLRET | GLOBAL | CONST | - |
| 0x00a4bd57 | CALL | 0x00a4bc90 | CALLRET | GLOBAL | CONST | - |
| 0x00a4f6e5 | CALL | 0x00a4f1d0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00a4f719 | CALL | 0x00a4f1d0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a4f87c | CALL | 0x00a4f1d0 | STACKADDR | DEREF_DEREF_UNKNOWN | CONST | - |
| 0x00a4f95a | CALL | 0x00a4f1d0 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x00a4fac4 | CALL | 0x00a4f1d0 | DEREF_DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00a4fbaf | CALL | 0x00a4f1d0 | DEREF_DERIVED | STACKADDR | CONST | - |
| 0x00a5044b | CALL | 0x00a50280 | GLOBAL | DEREF_CALLRET | CONST | - |
| 0x00a504ec | CALL | 0x00a50280 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x00a50572 | CALL | 0x00a50280 | DERIVED | STACK | CONST | - |
| 0x00a505ae | CALL | 0x00a50280 | DERIVED | STACK | CONST | - |
| 0x00a50890 | CALL | 0x00a50280 | DEREF_DERIVED | DEREF_CALLRET | CONST | - |
| 0x00a508d7 | CALL | 0x00a50280 | GLOBAL | CALLRET | CONST | - |
| 0x00a51b7d | CALL | 0x00a51940 | DERIVED | USERARG | CONST | - |
| 0x00a548fa | CALL | 0x00a53db0 | STACKADDR | CALLRET | CONST | - |
| 0x00a54942 | CALL | 0x00a53db0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a5498d | CALL | 0x00a53db0 | STACKADDR | CALLRET | CONST | - |
| 0x00a549d8 | CALL | 0x00a53db0 | STACKADDR | CALLRET | CONST | - |
| 0x00a5fb78 | CALL | 0x00a5fb30 | DERIVED | CALLRET | CONST | - |
| 0x00a605a8 | CALL | 0x00a60500 | STACKADDR | CALLRET | CONST | - |
| 0x00a61c56 | CALL | 0x00a61c10 | CALLRET | DERIVED | CONST | - |
| 0x00a62dc7 | CALL | 0x00a62c00 | STACKADDR | STACKADDR | CONST | - |
| 0x00a66041 | CALL | 0x00a65ce0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00a66075 | CALL | 0x00a65ce0 | DERIVED | STACKADDR | CONST | - |
| 0x00a6a63a | CALL | 0x00a6a4a0 | STACKADDR | CALLRET | DERIVED | - |
| 0x00a721bf | CALL | 0x00a71e90 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00a721fd | CALL | 0x00a71e90 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00a743ed | CALL | 0x00a743b0 | STACKADDR | USERARG | CONST | - |
| 0x00a744c2 | CALL | 0x00a743b0 | STACKADDR | UNKNOWN | CONST | - |
| 0x00a744d6 | CALL | 0x00a743b0 | STACKADDR | CALLRET | CONST | - |
| 0x00a7944c | CALL | 0x00a743b0 | USERARG | STACKADDR | CONST | - |
| 0x00a7946b | CALL | 0x00a743b0 | CALLRET | STACKADDR | CONST | - |
| 0x00a80e66 | CALL | 0x00a80cb0 | STACKADDR | USERARG | CONST | - |
| 0x00a81903 | CALL | 0x00a80cb0 | STACK | STACKADDR | CONST | - |
| 0x00a82433 | CALL | 0x00a82190 | CALLRET | DEREF_DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | - |
| 0x00a8245d | CALL | 0x00a82190 | STACK | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00a82a5b | CALL | 0x00a82790 | STACKADDR | CALLRET | CONST | - |
| 0x00a8399e | CALL | 0x00a83930 | STACKADDR | DEREF_CALLRET | CONST | 0@6,2@6,3@6+562 |
| 0x00a839b6 | CALL | 0x00a83930 | STACKADDR | DEREF_CALLRET | CONST | 0@6,2@6,3@6+562 |
| 0x00a89059 | CALL | 0x00a88eb0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00a892ec | CALL | 0x00a88eb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a89321 | CALL | 0x00a88eb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a899e7 | CALL | 0x00a88eb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00a89a2b | CALL | 0x00a88eb0 | STACKADDR | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00a89a41 | CALL | 0x00a88eb0 | STACKADDR | STACKADDR | CALLRET | - |
| 0x00a89bdb | CALL | 0x00a88eb0 | STACKADDR | DERIVED | CONST | - |
| 0x00a8a0bd | CALL | 0x00a89e40 | DEREF_STACKVAL | DERIVED | UNKNOWN | - |
| 0x00a90b09 | CALL | 0x00a90ab0 | CALLRET | CALLRET | CONST | - |
| 0x00a90b8f | CALL | 0x00a90b40 | CALLRET | CALLRET | CONST | - |
| 0x00a90be6 | JMP | 0x00a90bc0 | USERFIELD | USERARG | DERIVED | - |
| 0x00a90c71 | CALL | 0x00a90c30 | CALLRET | CALLRET | CONST | - |
| 0x00a92825 | CALL | 0x00a92640 | CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00a92b39 | CALL | 0x00a92ae0 | DEREF_UNKNOWN | USERARG | CONST | - |
| 0x00a92c01 | CALL | 0x00a92b50 | UNKNOWN | STACKVAL | UNKNOWN | - |
| 0x00a933ef | CALL | 0x00a93290 | UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00a93924 | CALL | 0x00a93580 | CALLRET | CALLRET | CONST | - |
| 0x00a949b8 | CALL | 0x00a94600 | UNKNOWN | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x00a94c6e | CALL | 0x00a94bc0 | UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00a99323 | CALL | 0x00a96440 | CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00a9933e | CALL | 0x00a96440 | DEREF_DEREF_CALLRET | DEREF_DEREF_DEREF_CALLRET | DERIVED | - |
| 0x00aa155c | CALL | 0x00aa1400 | DEREF_CALLRET | DEREF_CALLRET | CONST | 315@6 |
| 0x00aa1576 | CALL | 0x00aa1400 | DERIVED | UNKNOWN | CONST | 315@6 |
| 0x00aa520f | CALL | 0x00aa50d0 | STACKADDR | GLOBAL | CONST | - |
| 0x00aa523a | CALL | 0x00aa50d0 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00aa5c05 | CALL | 0x00aa5bd0 | STACKADDR | USERARG | CONST | - |
| 0x00aa5d99 | CALL | 0x00aa5cc0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00aa5daf | CALL | 0x00aa5cc0 | STACKADDR | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00aa5f75 | CALL | 0x00aa5cc0 | DEREF_CALLRET | STACKADDR | DEREF_CALLRET | - |
| 0x00aa601c | CALL | 0x00aa5fe0 | DEREF_DERIVED | CALLRET | CONST | - |
| 0x00aa6e54 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa6e68 | CALL | 0x00aa6cd0 | GLOBAL | CALLRET | CONST | - |
| 0x00aa6e7c | CALL | 0x00aa6cd0 | GLOBAL | CALLRET | CONST | - |
| 0x00aa8468 | CALL | 0x00aa6cd0 | STACKADDR | USERFIELD | CONST | - |
| 0x00aa8b16 | CALL | 0x00aa6cd0 | DERIVED | CALLRET | CONST | - |
| 0x00aa8b26 | CALL | 0x00aa6cd0 | CALLRET | CALLRET | CONST | - |
| 0x00aa8b3d | CALL | 0x00aa6cd0 | CALLRET | CALLRET | CONST | - |
| 0x00aa8cc1 | CALL | 0x00aa6cd0 | STACKADDR | GLOBAL | CONST | - |
| 0x00aa91b6 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9c2a | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9c42 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9c5a | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9c72 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9c8a | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9ca2 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9cba | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9cd2 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9cea | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9d02 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9d85 | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aa9d9d | CALL | 0x00aa6cd0 | GLOBAL | GLOBAL | CONST | - |
| 0x00aab7a0 | CALL | 0x00aa6cd0 | DEREF_UNKNOWN | STACK | UNKNOWN | - |
| 0x00aaf121 | CALL | 0x00aaeab0 | STACKADDR | CALLRET | CONST | - |
| 0x00aaf513 | CALL | 0x00aaeab0 | STACKADDR | GLOBAL | CONST | - |
| 0x00ab001a | CALL | 0x00aaeab0 | STACKADDR | GLOBAL | CONST | - |
| 0x00ab08af | CALL | 0x00aaeab0 | USERFIELD | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x00ab0b8f | CALL | 0x00aaeab0 | DEREF_UNKNOWN | DEREF_STACK | USERARG | - |
| 0x00ab0c7c | CALL | 0x00aaeab0 | STACKADDR | GLOBAL | CONST | - |
| 0x00ab0edf | CALL | 0x00aaeab0 | GLOBAL | STACKADDR | CONST | - |
| 0x00ab1fce | CALL | 0x00ab1e50 | GLOBAL | STACKADDR | CONST | - |
| 0x00ab75ed | CALL | 0x00ab7410 | CALLRET | CALLRET | CALLRET | - |
| 0x00ab7ffa | CALL | 0x00ab7fa0 | STACKADDR | CALLRET | CONST | 334@2 |
| 0x00ab8023 | CALL | 0x00ab7fa0 | UNKNOWN | UNKNOWN | CONST | 334@2 |
| 0x00ab81b6 | CALL | 0x00ab7fa0 | STACKADDR | UNKNOWN | CONST | 334@2 |
| 0x00abef19 | CALL | 0x00abee20 | DEREF_GLOBAL | UNKNOWN | UNKNOWN | 532@3 |
| 0x00abef40 | CALL | 0x00abee20 | DEREF_GLOBAL | UNKNOWN | UNKNOWN | 532@3 |
| 0x00abf0ab | CALL | 0x00abf000 | CALLRET | DEREF_GLOBAL | CALLRET | 532@4 |
| 0x00abf0d1 | CALL | 0x00abf000 | UNKNOWN | DEREF_GLOBAL | UNKNOWN | 532@4 |
| 0x00ac9f88 | CALL | 0x00ac9e10 | GLOBAL | GLOBAL | CONST | - |
| 0x00ac9f9c | CALL | 0x00ac9e10 | GLOBAL | CALLRET | CONST | - |
| 0x00acace6 | CALL | 0x00acacb0 | USERARG | DERIVED | CONST | - |
| 0x00acad16 | CALL | 0x00acacb0 | CALLRET | DERIVED | CONST | - |
| 0x00accaae | CALL | 0x00acc9e0 | CALLRET | GLOBAL | CONST | 532@4 |
| 0x00accb8a | CALL | 0x00accb10 | STACKADDR | DERIVED | CONST | 532@5 |
| 0x00accd48 | CALL | 0x00accc40 | GLOBAL | STACKADDR | CONST | 532@3 |
| 0x00accdce | CALL | 0x00accc40 | GLOBAL | CALLRET | CONST | 532@3 |
| 0x00acceac | CALL | 0x00acce90 | GLOBAL | GLOBAL | CONST | - |
| 0x00accec0 | CALL | 0x00acce90 | GLOBAL | CALLRET | CONST | - |
| 0x00accf92 | CALL | 0x00acce90 | GLOBAL | GLOBAL | CONST | - |
| 0x00acd774 | CALL | 0x00acd6b0 | CALLRET | GLOBAL | CONST | - |
| 0x00acdd19 | CALL | 0x00acdb50 | CALLRET | CALLRET | CALLRET | - |
| 0x00acdf0c | CALL | 0x00acdd50 | UNKNOWN | STACKADDR | DERIVED | - |
| 0x00acdf9e | CALL | 0x00acdd50 | CALLRET | CALLRET | CALLRET | - |
| 0x00ace03c | CALL | 0x00acdfe0 | CALLRET | CALLRET | CALLRET | - |
| 0x00ace0e4 | CALL | 0x00acdfe0 | STACKADDR | USERARG | DERIVED | - |
| 0x00ace1da | CALL | 0x00acdfe0 | STACKADDR | UNKNOWN | DERIVED | - |
| 0x00ace26f | CALL | 0x00acdfe0 | STACKADDR | DEREF_STACK | DERIVED | - |
| 0x00ad2910 | CALL | 0x00ad23a0 | GLOBAL | CALLRET | CALLRET | - |
| 0x00ad37e3 | CALL | 0x00ad2a10 | DEREF_UNKNOWN | DERIVED | DEREF_DERIVED | - |
| 0x00ad622f | CALL | 0x00ad5160 | STACKADDR | GLOBAL | CONST | 601@5 |
| 0x00ad63c4 | CALL | 0x00ad5160 | DEREF_DEREF_DEREF_DERIVED | DEREF_DEREF_DERIVED | CONST | 601@5 |
| 0x00ad644b | CALL | 0x00ad5160 | DEREF_DEREF_DEREF_DERIVED | DEREF_DEREF_DERIVED | CONST | 601@5 |
| 0x00ad8bed | CALL | 0x00ad8ac0 | UNKNOWN | STACKADDR | CONST | - |
| 0x00ad8d6c | CALL | 0x00ad8c20 | DEREF_UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00ad9019 | CALL | 0x00ad8fc0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00ad9a69 | CALL | 0x00ad9150 | USERFIELD | DERIVED | CONST | - |
| 0x00ada104 | CALL | 0x00ad9df0 | CALLRET | CALLRET | CONST | - |
| 0x00ada245 | CALL | 0x00ad9df0 | STACKADDR | DEREF_CALLRET | DERIVED | - |
| 0x00adf583 | CALL | 0x00ade270 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | 1@6,2@6,59@5+13 |
| 0x00adf6c3 | CALL | 0x00ade270 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | 1@6,2@6,59@5+13 |
| 0x00ae082a | CALL | 0x00ae0770 | CALLRET | CALLRET | DEREF_CALLRET | 125@6 |
| 0x00ae098f | CALL | 0x00ae0950 | CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00ae0a4e | CALL | 0x00ae09b0 | CALLRET | CALLRET | DEREF_CALLRET | 125@6 |
| 0x00ae1365 | CALL | 0x00ae1130 | CALLRET | CALLRET | DEREF_CALLRET | 93@6,522@6 |
| 0x00ae18ef | CALL | 0x00ae1740 | DEREF_DEREF_CALLRET | STACKADDR | CONST | 93@6,522@6 |
| 0x00ae1931 | CALL | 0x00ae1740 | DEREF_UNKNOWN | STACKADDR | CONST | 93@6,522@6 |
| 0x00ae1a11 | CALL | 0x00ae1740 | CALLRET | CALLRET | DEREF_CALLRET | 93@6,522@6 |
| 0x00ae42c5 | CALL | 0x00ae42b0 | USERARG | GLOBAL | CONST | - |
| 0x00ae5054 | CALL | 0x00ae4fd0 | DERIVED | UNKNOWN | UNKNOWN | - |
| 0x00ae76e2 | CALL | 0x00ae7450 | CALLRET | CALLRET | CALLRET | 532@1 |
| 0x00ae7769 | CALL | 0x00ae7450 | STACK | UNKNOWN | DEREF_UNKNOWN | 532@1 |
| 0x00ae7b00 | CALL | 0x00ae79a0 | CALLRET | CALLRET | CALLRET | 532@1 |
| 0x00ae7fa5 | CALL | 0x00ae7d60 | CALLRET | CALLRET | CALLRET | 532@1 |
| 0x00ae8016 | CALL | 0x00ae7d60 | STACK | UNKNOWN | USERFIELD | 532@1 |
| 0x00ae8184 | CALL | 0x00ae8030 | CALLRET | CALLRET | CALLRET | 532@1 |
| 0x00ae8f3c | CALL | 0x00ae8e70 | STACK | UNKNOWN | CONST | 532@1 |
| 0x00ae9070 | CALL | 0x00ae9020 | USERARG | UNKNOWN | CONST | 532@6 |
| 0x00ae933a | CALL | 0x00ae92f0 | UNKNOWN | UNKNOWN | DEREF_UNKNOWN | 532@2 |
| 0x00ae9410 | CALL | 0x00ae9350 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x00ae9550 | CALL | 0x00ae9350 | STACKADDR | GLOBAL | CONST | 532@4 |
| 0x00aea001 | CALL | 0x00ae9350 | GLOBAL | GLOBAL | CALLRET | 532@4 |
| 0x00aea075 | CALL | 0x00ae9350 | GLOBAL | GLOBAL | UNKNOWN | 532@4 |
| 0x00aea5a9 | CALL | 0x00ae9350 | UNKNOWN | UNKNOWN | DEREF_UNKNOWN | 532@4 |
| 0x00aea8ed | CALL | 0x00ae9350 | UNKNOWN | UNKNOWN | UNKNOWN | 532@4 |
| 0x00aea8ff | CALL | 0x00ae9350 | UNKNOWN | UNKNOWN | DEREF_UNKNOWN | 532@4 |
| 0x00aeac9d | CALL | 0x00aeac50 | CALLRET | CALLRET | CALLRET | 532@5 |
| 0x00aeae31 | CALL | 0x00aeac50 | UNKNOWN | UNKNOWN | DEREF_UNKNOWN | 532@5 |
| 0x00aeb3c5 | CALL | 0x00aeae70 | STACKADDR | STACK | DEREF_CALLRET | - |
| 0x00aebf5e | CALL | 0x00aebd50 | CALLRET | STACK | DEREF_CALLRET | - |
| 0x00aec1c6 | CALL | 0x00aec070 | CALLRET | STACK | DEREF_CALLRET | 532@2 |
| 0x00aec2e2 | CALL | 0x00aec070 | UNKNOWN | UNKNOWN | USERARG | 532@2 |
| 0x00aec320 | CALL | 0x00aec070 | UNKNOWN | UNKNOWN | USERFIELD | 532@2 |
| 0x00aec8dc | CALL | 0x00aec7e0 | STACKADDR | UNKNOWN | CONST | 532@4 |
| 0x00aecd40 | JMP | 0x00aecd10 | GLOBAL | USERARG | CONST | 532@4 |
| 0x00aed19e | CALL | 0x00aecd70 | USERARG | USERARG | USERARG | 532@2 |
| 0x00aed22a | CALL | 0x00aecd70 | CALLRET | CALLRET | CALLRET | 532@2 |
| 0x00aedad4 | CALL | 0x00aed770 | STACKADDR | STACK | STACK | 532@3 |
| 0x00aee09a | CALL | 0x00aeddb0 | CALLRET | STACKADDR | CALLRET | - |
| 0x00aee2df | CALL | 0x00aee1b0 | STACK | UNKNOWN | UNKNOWN | 532@4 |
| 0x00aee2f4 | CALL | 0x00aee1b0 | STACK | UNKNOWN | DEREF_UNKNOWN | 532@4 |
| 0x00aee870 | CALL | 0x00aee830 | STACKADDR | GLOBAL | CONST | 532@5 |
| 0x00aee996 | CALL | 0x00aee830 | STACKADDR | CALLRET | CONST | 532@5 |
| 0x00aef332 | CALL | 0x00aef140 | STACKADDR | GLOBAL | CONST | 532@5 |
| 0x00aef72e | CALL | 0x00aef140 | STACKADDR | DERIVED | DEREF_STACK | 532@5 |
| 0x00aef773 | CALL | 0x00aef140 | STACKADDR | CALLRET | CONST | 532@5 |
| 0x00aef90e | CALL | 0x00aef140 | STACKADDR | USERARG | USERARG | 532@5 |
| 0x00aef92d | CALL | 0x00aef140 | STACKADDR | CALLRET | CONST | 532@5 |
| 0x00aefdd2 | CALL | 0x00aefd50 | STACKADDR | GLOBAL | CONST | 532@2 |
| 0x00aeff2d | CALL | 0x00aefeb0 | STACKADDR | GLOBAL | CONST | 532@2 |
| 0x00af17ef | CALL | 0x00af13e0 | CALLRET | CALLRET | CALLRET | 532@1 |
| 0x00af1a27 | CALL | 0x00af1960 | CALLRET | STACK | CALLRET | 532@2 |
| 0x00af1b47 | CALL | 0x00af1a90 | STACK | STACK | CALLRET | 532@2 |
| 0x00af1d72 | CALL | 0x00af1d00 | GLOBAL | GLOBAL | UNKNOWN | 532@5 |
| 0x00af2115 | CALL | 0x00af20c0 | GLOBAL | USERARG | UNKNOWN | 532@6 |
| 0x00af21ca | CALL | 0x00af2140 | GLOBAL | USERARG | UNKNOWN | 532@5 |
| 0x00af23cf | CALL | 0x00af2140 | GLOBAL | USERARG | UNKNOWN | 532@5 |
| 0x00af2583 | CALL | 0x00af2140 | GLOBAL | USERARG | UNKNOWN | 532@5 |
| 0x00af289e | CALL | 0x00af2140 | GLOBAL | USERARG | UNKNOWN | 532@5 |
| 0x00af2a2d | CALL | 0x00af2140 | GLOBAL | USERARG | UNKNOWN | 532@5 |
| 0x00af34bf | CALL | 0x00af2140 | GLOBAL | CALLRET | CALLRET | 532@5 |
| 0x00af377a | CALL | 0x00af2140 | UNKNOWN | GLOBAL | STACK | 532@5 |
| 0x00af3e42 | CALL | 0x00af3860 | USERARG | UNKNOWN | CONST | 532@3 |
| 0x00af3eec | CALL | 0x00af3860 | USERARG | UNKNOWN | CONST | 532@3 |
| 0x00af4015 | CALL | 0x00af3860 | USERARG | UNKNOWN | CONST | 532@3 |
| 0x00afe448 | CALL | 0x00afe290 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00b0976a | CALL | 0x00b07960 | DERIVED | DEREF_CALLRET | CONST | 532@4 |
| 0x00b09832 | CALL | 0x00b07960 | DEREF_CALLRET | DEREF_CALLRET | CONST | 532@4 |
| 0x00b0a3a7 | CALL | 0x00b0a1a0 | STACKADDR | CALLRET | CALLRET | 532@5 |
| 0x00b0be09 | CALL | 0x00b0bd70 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00b0caf2 | CALL | 0x00b0ca40 | CALLRET | CALLRET | DERIVED | - |
| 0x00b0e5ca | CALL | 0x00b0e0f0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b0e7a9 | CALL | 0x00b0e0f0 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b0e7c5 | CALL | 0x00b0e0f0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b0e917 | CALL | 0x00b0e0f0 | DERIVED | GLOBAL | CONST | - |
| 0x00b0e948 | CALL | 0x00b0e0f0 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b0eaa9 | CALL | 0x00b0e0f0 | DERIVED | GLOBAL | CONST | - |
| 0x00b0f47b | CALL | 0x00b0e0f0 | DERIVED | DERIVED | USERARG | - |
| 0x00b0f4db | CALL | 0x00b0e0f0 | DERIVED | DEREF_UNKNOWN | UNKNOWN | - |
| 0x00b0f662 | CALL | 0x00b0e0f0 | DERIVED | GLOBAL | CONST | - |
| 0x00b10053 | CALL | 0x00b0faa0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00b102a2 | CALL | 0x00b0faa0 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b10390 | CALL | 0x00b0faa0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00b103af | CALL | 0x00b0faa0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00b11077 | CALL | 0x00b10cb0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00b111c9 | CALL | 0x00b10cb0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00b11289 | CALL | 0x00b10cb0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00b11d4d | CALL | 0x00b11bb0 | CALLRET | CALLRET | CONST | - |
| 0x00b12086 | CALL | 0x00b11fb0 | GLOBAL | STACKADDR | CONST | - |
| 0x00b12114 | CALL | 0x00b11fb0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00b12266 | CALL | 0x00b12170 | DERIVED | STACKADDR | CONST | - |
| 0x00b122a3 | CALL | 0x00b12170 | STACKADDR | CALLRET | CONST | - |
| 0x00b12357 | CALL | 0x00b12310 | GLOBAL | CALLRET | CONST | - |
| 0x00b12383 | CALL | 0x00b12310 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00b12406 | CALL | 0x00b123c0 | GLOBAL | STACKADDR | CONST | - |
| 0x00b1248e | CALL | 0x00b12440 | STACKADDR | GLOBAL | CONST | - |
| 0x00b12843 | CALL | 0x00b127d0 | GLOBAL | STACKADDR | CONST | - |
| 0x00b12877 | CALL | 0x00b127d0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00b12d7c | CALL | 0x00b12c00 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x00b13563 | CALL | 0x00b13430 | GLOBAL | CALLRET | CONST | - |
| 0x00b135dd | CALL | 0x00b13430 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00b139a8 | CALL | 0x00b13910 | CALLRET | GLOBAL | GLOBAL | - |
| 0x00b13b14 | CALL | 0x00b13a80 | STACKADDR | GLOBAL | CONST | - |
| 0x00b13c14 | CALL | 0x00b13b80 | STACKADDR | GLOBAL | CONST | - |
| 0x00b13cdf | CALL | 0x00b13c80 | STACKADDR | GLOBAL | CONST | - |
| 0x00b13e14 | CALL | 0x00b13d80 | STACKADDR | GLOBAL | CONST | - |
| 0x00b1432c | CALL | 0x00b14280 | STACKADDR | GLOBAL | CONST | - |
| 0x00b144b0 | CALL | 0x00b14480 | STACKADDR | STACKADDR | CONST | - |
| 0x00b1454d | CALL | 0x00b14480 | GLOBAL | CALLRET | CONST | - |
| 0x00b1455b | CALL | 0x00b14480 | USERARG | USERARG | USERARG | - |
| 0x00b14591 | CALL | 0x00b14480 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b1476e | CALL | 0x00b14720 | STACKADDR | GLOBAL | CONST | - |
| 0x00b14815 | CALL | 0x00b147e0 | STACKADDR | STACKADDR | CONST | - |
| 0x00b14854 | CALL | 0x00b147e0 | GLOBAL | CALLRET | CONST | - |
| 0x00b14871 | CALL | 0x00b147e0 | GLOBAL | UNKNOWN | CONST | - |
| 0x00b14878 | CALL | 0x00b147e0 | USERARG | CONST | USERARG | - |
| 0x00b148ae | CALL | 0x00b147e0 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b15271 | CALL | 0x00b15150 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b153be | CALL | 0x00b15150 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b155f1 | CALL | 0x00b15550 | STACKADDR | GLOBAL | CONST | - |
| 0x00b15606 | CALL | 0x00b15550 | STACKADDR | GLOBAL | CONST | - |
| 0x00b15b6b | CALL | 0x00b15b10 | STACKADDR | GLOBAL | CONST | - |
| 0x00b15ffb | CALL | 0x00b15e90 | DEREF_GLOBAL | GLOBAL | CALLRET | - |
| 0x00b1643f | CALL | 0x00b16380 | STACKADDR | DEREF_DEREF_DERIVED | DEREF_DEREF_DERIVED | - |
| 0x00b175d6 | CALL | 0x00b17370 | DEREF_DERIVED | DERIVED | CONST | - |
| 0x00b17787 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b177c9 | CALL | 0x00b17370 | GLOBAL | DEREF_UNKNOWN | CONST | - |
| 0x00b17848 | CALL | 0x00b17370 | STACKADDR | GLOBAL | CONST | - |
| 0x00b178cd | CALL | 0x00b17370 | DERIVED | GLOBAL | CONST | - |
| 0x00b178e9 | CALL | 0x00b17370 | DERIVED | GLOBAL | CONST | - |
| 0x00b17905 | CALL | 0x00b17370 | DERIVED | GLOBAL | CONST | - |
| 0x00b17938 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b17bc9 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b17c28 | CALL | 0x00b17370 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00b17c9c | CALL | 0x00b17370 | CALLRET | STACKADDR | CONST | - |
| 0x00b17e13 | CALL | 0x00b17370 | DERIVED | GLOBAL | CONST | - |
| 0x00b17e2f | CALL | 0x00b17370 | DERIVED | GLOBAL | CONST | - |
| 0x00b17e4b | CALL | 0x00b17370 | DERIVED | GLOBAL | CONST | - |
| 0x00b17ecf | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b17f36 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b17f83 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b17fd0 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b1801d | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b180c8 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b18115 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b18162 | CALL | 0x00b17370 | GLOBAL | DERIVED | CONST | - |
| 0x00b181b6 | CALL | 0x00b17370 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b1820d | CALL | 0x00b17370 | GLOBAL | CALLRET | CONST | - |
| 0x00b18254 | CALL | 0x00b17370 | STACKADDR | GLOBAL | CONST | - |
| 0x00b18406 | CALL | 0x00b17370 | STACKADDR | GLOBAL | CONST | - |
| 0x00b184d6 | CALL | 0x00b17370 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b18526 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b18576 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b185c6 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b18616 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b18666 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b186b6 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b18706 | CALL | 0x00b17370 | DEREF_UNKNOWN | GLOBAL | CONST | - |
| 0x00b23b7b | CALL | 0x00b23600 | DEREF_CALLRET | STACKADDR | CONST | 59@4,594@5 |
| 0x00b23f06 | CALL | 0x00b23600 | DEREF_UNKNOWN | STACKADDR | CONST | 59@4,594@5 |
| 0x00b23f4a | CALL | 0x00b23600 | DERIVED | STACKADDR | CONST | 59@4,594@5 |
| 0x00b240d0 | CALL | 0x00b23600 | DEREF_CALLRET | STACKADDR | CONST | 59@4,594@5 |
| 0x00b2410e | CALL | 0x00b23600 | DEREF_CALLRET | STACKADDR | CONST | 59@4,594@5 |
| 0x00b2597d | CALL | 0x00b248b0 | STACK | DERIVED | CONST | 59@4,594@4 |
| 0x00b25e3e | CALL | 0x00b248b0 | DEREF_UNKNOWN | STACK | CONST | 59@4,594@4 |
| 0x00b2a2bc | CALL | 0x00b2a250 | DERIVED | CALLRET | CALLRET | 59@3,591@2 |
| 0x00b2a2dc | CALL | 0x00b2a250 | CALLRET | CALLRET | CALLRET | 59@3,591@2 |
| 0x00b2a317 | CALL | 0x00b2a250 | DEREF_CALLRET | CALLRET | CONST | 59@3,591@2 |
| 0x00b2b750 | CALL | 0x00b2b740 | USERARG | DERIVED | CONST | 341@5,345@6,346@6+7 |
| 0x00b2c268 | CALL | 0x00b2c190 | STACKADDR | CALLRET | CONST | - |
| 0x00b2c476 | CALL | 0x00b2c3b0 | DEREF_DEREF_CALLRET | STACK | CONST | - |
| 0x00b2c557 | CALL | 0x00b2c4c0 | STACKADDR | STACKADDR | CONST | - |
| 0x00b31e95 | CALL | 0x00b31de0 | UNKNOWN | UNKNOWN | CONST | 59@5,594@6 |
| 0x00b32ba6 | CALL | 0x00b32b40 | USERARG | USERARG | USERFIELD | 59@5,594@6 |
| 0x00b32bc6 | CALL | 0x00b32b40 | UNKNOWN | UNKNOWN | DERIVED | 59@5,594@6 |
| 0x00b32c14 | CALL | 0x00b32b40 | DERIVED | DERIVED | CONST | 59@5,594@6 |
| 0x00b38a6c | CALL | 0x00b35a50 | STACK | CALLRET | CONST | - |
| 0x00b3ac40 | CALL | 0x00b3abb0 | STACKADDR | CALLRET | CONST | 97@5,113@5,135@5 |
| 0x00b3ae4c | CALL | 0x00b3abb0 | STACKADDR | DEREF_UNKNOWN | CONST | 97@5,113@5,135@5 |
| 0x00b3be7a | CALL | 0x00b3bb50 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00b3c4d6 | CALL | 0x00b3c100 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00b3ecdd | CALL | 0x00b3ec30 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b3ef6c | CALL | 0x00b3ee40 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b40c60 | CALL | 0x00b40b80 | DEREF_STACK | DEREF_DERIVED | CONST | - |
| 0x00b40cfd | CALL | 0x00b40c90 | CALLRET | CALLRET | CALLRET | - |
| 0x00b455d8 | CALL | 0x00b45130 | DEREF_GLOBAL | GLOBAL | CONST | - |
| 0x00b455f0 | CALL | 0x00b45130 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b457bc | CALL | 0x00b45130 | CALLRET | GLOBAL | CONST | - |
| 0x00b457d4 | CALL | 0x00b45130 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b457ec | CALL | 0x00b45130 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b45842 | CALL | 0x00b45130 | UNKNOWN | GLOBAL | CONST | - |
| 0x00b45860 | CALL | 0x00b45130 | DERIVED | DERIVED | CALLRET | - |
| 0x00b45bcf | CALL | 0x00b45130 | DERIVED | UNKNOWN | UNKNOWN | - |
| 0x00b4640f | CALL | 0x00b45130 | UNKNOWN | UNKNOWN | USERARG | - |
| 0x00b4665d | CALL | 0x00b45130 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00b46d1d | CALL | 0x00b46940 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00b47db7 | CALL | 0x00b47d30 | CALLRET | DERIVED | CONST | - |
| 0x00b48019 | CALL | 0x00b47d30 | STACKADDR | DEREF_DEREF_CALLRET | CONST | - |
| 0x00b480e1 | CALL | 0x00b47d30 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00b481d7 | CALL | 0x00b47d30 | DEREF_STACK | STACKADDR | CONST | - |
| 0x00b49a7d | CALL | 0x00b49580 | STACKADDR | STACKADDR | CONST | - |
| 0x00b49b93 | CALL | 0x00b49580 | STACKADDR | STACKADDR | CONST | - |
| 0x00b49bab | CALL | 0x00b49580 | STACKADDR | STACKADDR | CONST | - |
| 0x00b49e84 | CALL | 0x00b49d40 | STACKADDR | DERIVED | CONST | - |
| 0x00b4bfa7 | CALL | 0x00b4be20 | DEREF_CALLRET | DEREF_STACK | CONST | - |
| 0x00b4c134 | CALL | 0x00b4be20 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x00b4c1a3 | CALL | 0x00b4be20 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b4c4bd | CALL | 0x00b4be20 | DERIVED | UNKNOWN | CONST | - |
| 0x00b4c619 | CALL | 0x00b4be20 | DEREF_UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00b4c7f8 | CALL | 0x00b4be20 | DERIVED | CALLRET | CALLRET | - |
| 0x00b4ca98 | CALL | 0x00b4be20 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00b4cbae | CALL | 0x00b4be20 | DEREF_CALLRET | STACK | STACK | - |
| 0x00b4cc31 | CALL | 0x00b4be20 | DEREF_CALLRET | STACK | STACK | - |
| 0x00b4d5ed | CALL | 0x00b4d490 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00b4d8eb | CALL | 0x00b4d660 | UNKNOWN | STACK | CALLRET | - |
| 0x00b4d960 | CALL | 0x00b4d660 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b4da53 | CALL | 0x00b4d660 | USER_PTR | USERFIELD | UNKNOWN | - |
| 0x00b4dcd6 | CALL | 0x00b4dae0 | DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00b4e5e2 | CALL | 0x00b4e260 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b4e62b | CALL | 0x00b4e260 | DEREF_CALLRET | DEREF_STACK | CONST | - |
| 0x00b4e783 | CALL | 0x00b4e260 | STACK | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | - |
| 0x00b4ea7c | CALL | 0x00b4e260 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b4ec86 | CALL | 0x00b4e260 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b4edd9 | CALL | 0x00b4e260 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b4ee02 | CALL | 0x00b4e260 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00b4ee3a | CALL | 0x00b4e260 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00b4eeb9 | CALL | 0x00b4e260 | DEREF_CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x00b4ef3f | CALL | 0x00b4e260 | STACKADDR | DERIVED | CONST | - |
| 0x00b4efa0 | CALL | 0x00b4e260 | STACKADDR | DERIVED | CONST | - |
| 0x00b4efe9 | CALL | 0x00b4e260 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00b4f01d | CALL | 0x00b4e260 | DEREF_CALLRET | DEREF_STACK | CONST | - |
| 0x00b4f03c | CALL | 0x00b4e260 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b4f076 | CALL | 0x00b4e260 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b4f0b3 | CALL | 0x00b4e260 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00b4f0f6 | CALL | 0x00b4e260 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00b4f121 | CALL | 0x00b4e260 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00b4f15c | CALL | 0x00b4e260 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00b4f1b1 | CALL | 0x00b4e260 | UNKNOWN | STACKADDR | CONST | - |
| 0x00b4fd34 | CALL | 0x00b4e260 | STACK | STACK | CONST | - |
| 0x00b4ff3c | CALL | 0x00b4e260 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00b4ff55 | CALL | 0x00b4e260 | STACKADDR | DERIVED | CONST | - |
| 0x00b4ff66 | CALL | 0x00b4e260 | STACKADDR | CALLRET | CONST | - |
| 0x00b50548 | CALL | 0x00b4e260 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00b50b12 | CALL | 0x00b4e260 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00b50ba6 | CALL | 0x00b4e260 | STACKADDR | GLOBAL | CONST | - |
| 0x00b50bbf | CALL | 0x00b4e260 | STACKADDR | DERIVED | CONST | - |
| 0x00b50bd8 | CALL | 0x00b4e260 | STACKADDR | DERIVED | CONST | - |
| 0x00b50f43 | CALL | 0x00b4e260 | USERFIELD | DERIVED | CONST | - |
| 0x00b51138 | CALL | 0x00b4e260 | CALLRET | STACKADDR | CONST | - |
| 0x00b51859 | CALL | 0x00b517f0 | CALLRET | CALLRET | CALLRET | - |
| 0x00b518bd | CALL | 0x00b517f0 | STACKADDR | DERIVED | DEREF_CALLRET | - |
| 0x00b51a85 | CALL | 0x00b51900 | STACKADDR | DEREF_CALLRET | DERIVED | - |
| 0x00b51bb6 | CALL | 0x00b51900 | STACKADDR | STACK | DERIVED | - |
| 0x00b51d8d | CALL | 0x00b51d40 | STACKADDR | DERIVED | CONST | - |
| 0x00b51dad | CALL | 0x00b51d40 | STACKADDR | DERIVED | CONST | - |
| 0x00b51dbe | CALL | 0x00b51d40 | STACKADDR | CALLRET | CONST | - |
| 0x00b51fd7 | CALL | 0x00b51f50 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b51ffb | CALL | 0x00b51f50 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b5200c | CALL | 0x00b51f50 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00b5269f | CALL | 0x00b51f50 | STACK | STACK | STACK | - |
| 0x00b528a9 | CALL | 0x00b51f50 | DERIVED | STACK | DERIVED | - |
| 0x00b52aec | CALL | 0x00b52a50 | STACKADDR | DERIVED | CONST | - |
| 0x00b52bb6 | CALL | 0x00b52b90 | USERARG | GLOBAL | CONST | - |
| 0x00b52be5 | CALL | 0x00b52b90 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b52c06 | CALL | 0x00b52b90 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b52c25 | CALL | 0x00b52b90 | DERIVED | GLOBAL | CONST | - |
| 0x00b52c82 | CALL | 0x00b52c40 | USERFIELD | DERIVED | CONST | - |
| 0x00b52ca3 | CALL | 0x00b52c40 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b52cd3 | CALL | 0x00b52c40 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b52d2c | CALL | 0x00b52d00 | USERFIELD | GLOBAL | CONST | - |
| 0x00b52d44 | CALL | 0x00b52d00 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00b52d60 | CALL | 0x00b52d00 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b53a2b | CALL | 0x00b530c0 | CALLRET | STACK | CONST | - |
| 0x00b53ad6 | CALL | 0x00b530c0 | STACKADDR | DEREF_CALLRET | DERIVED | - |
| 0x00b53b90 | CALL | 0x00b530c0 | STACKADDR | STACK | DERIVED | - |
| 0x00b53c67 | CALL | 0x00b530c0 | STACKADDR | STACKADDR | CONST | - |
| 0x00b53c83 | CALL | 0x00b530c0 | STACKADDR | DERIVED | CONST | - |
| 0x00b53c9f | CALL | 0x00b530c0 | STACKADDR | DERIVED | CONST | - |
| 0x00b53dfc | CALL | 0x00b530c0 | STACKADDR | STACK | CONST | - |
| 0x00b53e8f | CALL | 0x00b530c0 | STACKADDR | STACK | STACK | - |
| 0x00b542f7 | CALL | 0x00b530c0 | STACKADDR | STACK | CONST | - |
| 0x00b5476d | CALL | 0x00b530c0 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b559db | CALL | 0x00b55940 | STACKADDR | CALLRET | CONST | - |
| 0x00b559f7 | CALL | 0x00b55940 | STACKADDR | DERIVED | CONST | - |
| 0x00b55a17 | CALL | 0x00b55940 | STACKADDR | DERIVED | CONST | - |
| 0x00b55ed4 | CALL | 0x00b55e20 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b57405 | CALL | 0x00b56f90 | GLOBAL | DEREF_GLOBAL | DERIVED | - |
| 0x00b584a5 | CALL | 0x00b58380 | DERIVED | DERIVED | DEREF_CALLRET | - |
| 0x00b5e686 | CALL | 0x00b5e620 | CALLRET | STACKADDR | CONST | 601@5 |
| 0x00b5e69a | CALL | 0x00b5e620 | CALLRET | STACKADDR | CONST | 601@5 |
| 0x00b5e6db | CALL | 0x00b5e620 | CALLRET | STACKADDR | CONST | 601@5 |
| 0x00b5e6ef | CALL | 0x00b5e620 | CALLRET | STACKADDR | CONST | 601@5 |
| 0x00b5ea61 | CALL | 0x00b5e9e0 | STACKADDR | STACKADDR | CONST | 601@4 |
| 0x00b5ead1 | CALL | 0x00b5e9e0 | STACKADDR | STACKADDR | CONST | 601@4 |
| 0x00b5f52e | CALL | 0x00b5f520 | CALLRET | CALLRET | CONST | - |
| 0x00b6043c | CALL | 0x00b602a0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00b63873 | CALL | 0x00b63720 | DERIVED | STACK | STACK | - |
| 0x00b639ce | CALL | 0x00b63720 | DEREF_DEREF_STACK | UNKNOWN | UNKNOWN | - |
| 0x00b63b01 | CALL | 0x00b63720 | USERARG | USERARG | USERARG | - |
| 0x00b63cae | CALL | 0x00b63c60 | DEREF_CALLRET | UNKNOWN | UNKNOWN | - |
| 0x00b64140 | CALL | 0x00b63de0 | DEREF_UNKNOWN | STACK | STACK | - |
| 0x00b64b0d | CALL | 0x00b64ad0 | USER_PTR | USER_PTR | DERIVED | - |
| 0x00b64bbc | CALL | 0x00b64b50 | CALLRET | STACKADDR | CONST | - |
| 0x00b665c0 | CALL | 0x00b664e0 | STACKADDR | CALLRET | CALLRET | 532@6 |
| 0x00b66710 | CALL | 0x00b66630 | STACKADDR | CALLRET | CALLRET | - |
| 0x00b6686f | CALL | 0x00b66780 | CALLRET | STACKADDR | CALLRET | 232@3,431@5,532@5 |
| 0x00b68354 | CALL | 0x00b68250 | UNKNOWN | DEREF_UNKNOWN | UNKNOWN | 515@6,532@6,622@6+1 |
| 0x00b6843c | CALL | 0x00b683a0 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | 515@5,532@5,622@5+1 |
| 0x00b68518 | CALL | 0x00b683a0 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | 515@5,532@5,622@5+1 |
| 0x00b6869f | CALL | 0x00b68670 | USERARG | USERARG | DERIVED | - |
| 0x00b6874d | CALL | 0x00b68670 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b6a8ec | CALL | 0x00b6a810 | STACK | DEREF_UNKNOWN | DERIVED | - |
| 0x00b6afaa | CALL | 0x00b6af40 | CALLRET | CALLRET | CALLRET | - |
| 0x00b6da6d | CALL | 0x00b6d7f0 | DERIVED | DERIVED | CONST | - |
| 0x00b6de19 | CALL | 0x00b6dd40 | STACKADDR | CALLRET | CONST | - |
| 0x00b6e0b2 | CALL | 0x00b6dd40 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b6e391 | CALL | 0x00b6dd40 | DERIVED | GLOBAL | CONST | - |
| 0x00b6e470 | CALL | 0x00b6dd40 | DERIVED | DERIVED | CONST | - |
| 0x00b6e804 | CALL | 0x00b6e7a0 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00b6e979 | CALL | 0x00b6e8c0 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00b6e9b4 | CALL | 0x00b6e8c0 | CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00b6e9d8 | CALL | 0x00b6e8c0 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00b6eae9 | CALL | 0x00b6e8c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b6eba9 | CALL | 0x00b6e8c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b6ed55 | CALL | 0x00b6e8c0 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b6f02f | CALL | 0x00b6ef80 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CALLRET | - |
| 0x00b6f064 | CALL | 0x00b6ef80 | DERIVED | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b6f098 | CALL | 0x00b6ef80 | DERIVED | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b6f0ba | CALL | 0x00b6ef80 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00b6f434 | CALL | 0x00b6ef80 | CALLRET | DERIVED | CONST | - |
| 0x00b6f843 | CALL | 0x00b6ef80 | DEREF_CALLRET | GLOBAL | CONST | - |
| 0x00b6faa8 | CALL | 0x00b6ef80 | CALLRET | UNKNOWN | CONST | - |
| 0x00b6fe0b | CALL | 0x00b6ef80 | CALLRET | STACK | CALLRET | - |
| 0x00b6fe66 | CALL | 0x00b6ef80 | CALLRET | STACK | CALLRET | - |
| 0x00b6fe86 | CALL | 0x00b6ef80 | DEREF_STACK | DERIVED | CONST | - |
| 0x00b6fff5 | CALL | 0x00b6ef80 | CALLRET | UNKNOWN | DERIVED | - |
| 0x00b7178b | CALL | 0x00b6ef80 | USERARG | DERIVED | CONST | - |
| 0x00b7180b | CALL | 0x00b6ef80 | USERARG | DERIVED | CONST | - |
| 0x00b7188b | CALL | 0x00b6ef80 | USERARG | DERIVED | CONST | - |
| 0x00b7190b | CALL | 0x00b6ef80 | USERARG | DERIVED | CONST | - |
| 0x00b71981 | CALL | 0x00b6ef80 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b719f1 | CALL | 0x00b6ef80 | GLOBAL | USERFIELD | CONST | - |
| 0x00b71a61 | CALL | 0x00b6ef80 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00b71ad1 | CALL | 0x00b6ef80 | USERARG | USERFIELD | CONST | - |
| 0x00b71bbf | CALL | 0x00b71b20 | DERIVED | UNKNOWN | UNKNOWN | - |
| 0x00b71c4c | CALL | 0x00b71bd0 | UNKNOWN | USERFIELD | USERARG | - |
| 0x00b71c99 | CALL | 0x00b71c70 | USERFIELD | UNKNOWN | USERARG | - |
| 0x00b72818 | CALL | 0x00b72220 | CALLRET | DERIVED | CONST | - |
| 0x00b72a77 | CALL | 0x00b72220 | CALLRET | DERIVED | CONST | - |
| 0x00b7546c | CALL | 0x00b751c0 | USERFIELD | USERFIELD | CONST | - |
| 0x00b754ca | CALL | 0x00b751c0 | USERFIELD | USERFIELD | CONST | - |
| 0x00b75526 | CALL | 0x00b751c0 | DERIVED | DERIVED | CONST | - |
| 0x00b75ef1 | CALL | 0x00b75ea0 | DERIVED | CALLRET | CONST | - |
| 0x00b7647e | CALL | 0x00b76430 | DERIVED | CALLRET | CONST | - |
| 0x00b76540 | CALL | 0x00b76510 | CALLRET | DERIVED | CONST | - |
| 0x00b7663c | CALL | 0x00b765b0 | DERIVED | CALLRET | CONST | - |
| 0x00b76749 | CALL | 0x00b766b0 | DERIVED | STACKADDR | CONST | - |
| 0x00b7683b | CALL | 0x00b76800 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00b7685a | CALL | 0x00b76800 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00b76902 | CALL | 0x00b768d0 | CALLRET | DERIVED | CONST | - |
| 0x00b795ac | CALL | 0x00b79100 | DEREF_UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00b79782 | CALL | 0x00b79100 | UNKNOWN | CONST | UNKNOWN | - |
| 0x00b7cdff | CALL | 0x00b7cd80 | STACKADDR | GLOBAL | CONST | - |
| 0x00b8aa1a | CALL | 0x00b8a7b0 | DEREF_GLOBAL | UNKNOWN | UNKNOWN | 0@6,1@6,2@5+587 |
| 0x00b8aae5 | CALL | 0x00b8a7b0 | DEREF_GLOBAL | DEREF_GLOBAL | DERIVED | 0@6,1@6,2@5+587 |
| 0x00b8de3b | CALL | 0x00b8d900 | CALLRET | CALLRET | CONST | 59@5,482@6,620@6 |
| 0x00b94cb2 | CALL | 0x00b94aa0 | GLOBAL | USERARG | UNKNOWN | - |
| 0x00b94fff | CALL | 0x00b94aa0 | DEREF_STACK | STACKADDR | CONST | - |
| 0x00b9516b | CALL | 0x00b95060 | CALLRET | DERIVED | CALLRET | - |
| 0x00b952cb | CALL | 0x00b951c0 | DERIVED | CALLRET | CALLRET | - |
| 0x00b95abe | CALL | 0x00b95610 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00b95bf1 | CALL | 0x00b95610 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00b95eba | CALL | 0x00b95610 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00b95f05 | CALL | 0x00b95610 | STACKADDR | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00b95f1d | CALL | 0x00b95610 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00b95f35 | CALL | 0x00b95610 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00b9604e | CALL | 0x00b95fe0 | GLOBAL | DEREF_DEREF_DERIVED | CONST | - |
| 0x00b96a83 | CALL | 0x00b96900 | UNKNOWN | DERIVED | CONST | - |
| 0x00b9702e | CALL | 0x00b96f60 | DERIVED | CALLRET | STACK | 55@5 |
| 0x00b9709a | CALL | 0x00b96f60 | DERIVED | CALLRET | STACK | 55@5 |
| 0x00b974f7 | CALL | 0x00b96f60 | DEREF_GLOBAL | DERIVED | DERIVED | 55@5 |
| 0x00b9c87c | CALL | 0x00b9c460 | DEREF_CALLRET | CALLRET | CALLRET | - |
| 0x00b9d7f2 | CALL | 0x00b9d1b0 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00b9d81b | CALL | 0x00b9d1b0 | DERIVED | DERIVED | CALLRET | - |
| 0x00b9e638 | CALL | 0x00b9dc30 | STACKADDR | DERIVED | CONST | - |
| 0x00b9e681 | CALL | 0x00b9dc30 | STACKADDR | CALLRET | CONST | - |
| 0x00b9e75c | CALL | 0x00b9dc30 | STACKADDR | STACKADDR | CONST | - |
| 0x00b9e800 | CALL | 0x00b9dc30 | STACKADDR | STACKADDR | CONST | - |
| 0x00b9e8d2 | CALL | 0x00b9dc30 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00b9e924 | CALL | 0x00b9dc30 | STACKADDR | STACKADDR | CONST | - |
| 0x00b9e93c | CALL | 0x00b9dc30 | STACKADDR | STACKADDR | CONST | - |
| 0x00b9f11b | CALL | 0x00b9dc30 | STACKADDR | CALLRET | CONST | - |
| 0x00b9f2ae | CALL | 0x00b9dc30 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00b9f3a3 | CALL | 0x00b9dc30 | STACKADDR | STACKADDR | CONST | - |
| 0x00b9f95a | CALL | 0x00b9f7d0 | CALLRET | CALLRET | CONST | - |
| 0x00b9fe08 | CALL | 0x00b9f9e0 | STACKADDR | DERIVED | CONST | - |
| 0x00b9fee0 | CALL | 0x00b9f9e0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00b9ff8c | CALL | 0x00b9f9e0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00ba0194 | CALL | 0x00b9f9e0 | STACKADDR | DERIVED | CONST | - |
| 0x00ba01ac | CALL | 0x00b9f9e0 | STACKADDR | DERIVED | CONST | - |
| 0x00ba01bc | CALL | 0x00b9f9e0 | CALLRET | CALLRET | CONST | - |
| 0x00ba0307 | CALL | 0x00b9f9e0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00ba0401 | CALL | 0x00b9f9e0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00ba0442 | CALL | 0x00b9f9e0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00ba06aa | CALL | 0x00b9f9e0 | CALLRET | DERIVED | DEREF_CALLRET | - |
| 0x00ba076d | CALL | 0x00b9f9e0 | DERIVED | DERIVED | UNKNOWN | - |
| 0x00ba07e2 | CALL | 0x00b9f9e0 | DERIVED | DERIVED | UNKNOWN | - |
| 0x00ba0c3c | CALL | 0x00b9f9e0 | STACKADDR | CALLRET | CONST | - |
| 0x00ba0d93 | CALL | 0x00ba0cb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00ba0da5 | CALL | 0x00ba0cb0 | STACKADDR | STACKADDR | CONST | - |
| 0x00ba0e53 | CALL | 0x00ba0cb0 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00ba0e6f | CALL | 0x00ba0cb0 | STACKADDR | DERIVED | CALLRET | - |
| 0x00ba0ec3 | CALL | 0x00ba0cb0 | CALLRET | STACKADDR | CONST | - |
| 0x00ba0ed5 | CALL | 0x00ba0cb0 | STACK | STACKADDR | CONST | - |
| 0x00ba10a9 | CALL | 0x00ba0f10 | STACKADDR | STACKADDR | CONST | - |
| 0x00ba10fc | CALL | 0x00ba0f10 | STACKADDR | DERIVED | CONST | - |
| 0x00ba1324 | CALL | 0x00ba1180 | STACKADDR | STACKADDR | CONST | - |
| 0x00ba1370 | CALL | 0x00ba1180 | STACKADDR | DERIVED | CONST | - |
| 0x00ba1534 | CALL | 0x00ba1420 | STACKADDR | STACKADDR | CONST | - |
| 0x00ba157a | CALL | 0x00ba1420 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00ba1654 | CALL | 0x00ba1420 | DERIVED | STACKADDR | CONST | - |
| 0x00ba3551 | CALL | 0x00ba3370 | STACK | STACK | STACK | 0@3,2@3,3@3+562 |
| 0x00bb531e | CALL | 0x00bb4e80 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bb5343 | CALL | 0x00bb4e80 | STACKADDR | CALLRET | CONST | - |
| 0x00bb56df | CALL | 0x00bb4e80 | STACKADDR | STACKADDR | CONST | - |
| 0x00bb57e3 | CALL | 0x00bb4e80 | STACKADDR | STACKADDR | CONST | - |
| 0x00bb57fe | CALL | 0x00bb4e80 | STACKADDR | STACKADDR | CONST | - |
| 0x00bb58bc | CALL | 0x00bb4e80 | STACKADDR | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x00bb5a07 | CALL | 0x00bb58f0 | STACKADDR | STACKADDR | CONST | - |
| 0x00bb5cc2 | CALL | 0x00bb5b70 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00bb60c2 | CALL | 0x00bb5b70 | USERFIELD | DERIVED | UNKNOWN | - |
| 0x00bb61cd | CALL | 0x00bb5b70 | STACKADDR | DERIVED | CONST | - |
| 0x00bb621a | CALL | 0x00bb5b70 | STACKADDR | DERIVED | CONST | - |
| 0x00bb8198 | CALL | 0x00bb7f20 | USERARG | DERIVED | CONST | - |
| 0x00bb81c3 | JMP | 0x00bb7f20 | DERIVED | CALLRET | CONST | - |
| 0x00bb8358 | CALL | 0x00bb7f20 | DERIVED | CALLRET | CONST | - |
| 0x00bb844e | CALL | 0x00bb7f20 | USERARG | DERIVED | CONST | - |
| 0x00bba49d | CALL | 0x00bba430 | STACKADDR | CALLRET | CONST | - |
| 0x00bbdfcb | CALL | 0x00bbdb70 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00bbe129 | CALL | 0x00bbe020 | STACKADDR | USER_PTR | CONST | - |
| 0x00bbe13e | CALL | 0x00bbe020 | STACKADDR | DERIVED | CONST | - |
| 0x00bbe421 | CALL | 0x00bbe020 | STACKADDR | DERIVED | CONST | - |
| 0x00bbf6ee | JMP | 0x00bbf690 | DERIVED | CALLRET | DERIVED | - |
| 0x00bc0128 | CALL | 0x00bc0070 | STACKADDR | USER_PTR | CONST | - |
| 0x00bc013d | CALL | 0x00bc0070 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00bc0184 | CALL | 0x00bc0070 | STACKADDR | CALLRET | CONST | - |
| 0x00bc01b3 | CALL | 0x00bc0070 | STACKADDR | CALLRET | CONST | - |
| 0x00bc02c8 | CALL | 0x00bc0070 | STACKADDR | USER_PTR | CONST | - |
| 0x00bc02dd | CALL | 0x00bc0070 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00bc0324 | CALL | 0x00bc0070 | STACKADDR | CALLRET | CONST | - |
| 0x00bc0353 | CALL | 0x00bc0070 | STACKADDR | CALLRET | CONST | - |
| 0x00bc062d | CALL | 0x00bc0470 | STACKADDR | CALLRET | CONST | - |
| 0x00bc0685 | CALL | 0x00bc0470 | STACKADDR | UNKNOWN | CONST | - |
| 0x00bc08ca | CALL | 0x00bc0470 | UNKNOWN | STACKADDR | CONST | - |
| 0x00bc210f | CALL | 0x00bc1540 | STACKADDR | DEREF_DERIVED | CONST | - |
| 0x00bc2962 | CALL | 0x00bc24f0 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00bc2f13 | CALL | 0x00bc2b90 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00bc3420 | CALL | 0x00bc32b0 | DERIVED | DERIVED | CONST | - |
| 0x00bc36b9 | CALL | 0x00bc3460 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bc36d8 | CALL | 0x00bc3460 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00bc3981 | CALL | 0x00bc3880 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bc4906 | CALL | 0x00bc3be0 | DEREF_STACK | DERIVED | CONST | - |
| 0x00bc4a94 | CALL | 0x00bc3be0 | DEREF_STACK | DERIVED | CONST | - |
| 0x00bc4ab4 | CALL | 0x00bc3be0 | DERIVED | DERIVED | CONST | - |
| 0x00bc5965 | CALL | 0x00bc53e0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00bc5980 | CALL | 0x00bc53e0 | DERIVED | DERIVED | CONST | - |
| 0x00bc5c09 | CALL | 0x00bc53e0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00bc6c2b | CALL | 0x00bc6990 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00bc6cca | CALL | 0x00bc6990 | CALLRET | STACKADDR | CONST | - |
| 0x00bc6fe9 | CALL | 0x00bc6990 | STACKADDR | UNKNOWN | CONST | - |
| 0x00bc7006 | CALL | 0x00bc6990 | USERARG | UNKNOWN | CONST | - |
| 0x00bc7508 | CALL | 0x00bc6990 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00bc75c0 | CALL | 0x00bc6990 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00bc76c8 | CALL | 0x00bc6990 | UNKNOWN | USERARG | CONST | - |
| 0x00bcaf17 | CALL | 0x00bcae80 | DERIVED | DERIVED | CONST | - |
| 0x00bcb68f | CALL | 0x00bcb630 | CALLRET | UNKNOWN | CONST | - |
| 0x00bcb8c3 | CALL | 0x00bcb850 | CALLRET | CALLRET | CONST | - |
| 0x00bcc6f3 | CALL | 0x00bcc550 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bccce5 | CALL | 0x00bccc20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bccd0f | CALL | 0x00bccc20 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00bccdf1 | CALL | 0x00bccd90 | USER_PTR | USERFIELD | CONST | - |
| 0x00bcce32 | JMP | 0x00bccd90 | DERIVED | DERIVED | CONST | - |
| 0x00bcceee | CALL | 0x00bccd90 | DEREF_UNKNOWN | USERFIELD | CONST | - |
| 0x00bcd3f7 | CALL | 0x00bcd220 | STACKADDR | DEREF_DEREF_DEREF_STACK | DERIVED | - |
| 0x00bcd769 | CALL | 0x00bcd650 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00bcd8a7 | CALL | 0x00bcd650 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00bcf3dc | CALL | 0x00bcf080 | DERIVED | UNKNOWN | DEREF_DEREF_DERIVED | - |
| 0x00bcfa1c | CALL | 0x00bcf9c0 | CALLRET | UNKNOWN | CONST | - |
| 0x00bcffe5 | CALL | 0x00bcfd90 | UNKNOWN | CALLRET | DEREF_DEREF_DEREF_CALLRET | - |
| 0x00bd1173 | CALL | 0x00bd10a0 | DERIVED | DERIVED | DEREF_DERIVED | - |
| 0x00bd11f0 | CALL | 0x00bd11a0 | CALLRET | UNKNOWN | CONST | - |
| 0x00bd19f7 | CALL | 0x00bd1990 | USER_PTR | USERARG | CONST | - |
| 0x00bd1a0c | CALL | 0x00bd1990 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd1a6b | CALL | 0x00bd1990 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd1d66 | CALL | 0x00bd1d50 | GLOBAL | USERARG | CONST | - |
| 0x00bd1d93 | CALL | 0x00bd1d70 | CALLRET | GLOBAL | CONST | - |
| 0x00bd3470 | CALL | 0x00bd31f0 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00bd3608 | CALL | 0x00bd3560 | CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x00bd3705 | CALL | 0x00bd3630 | UNKNOWN | DEREF_DERIVED | CONST | - |
| 0x00bd37d5 | CALL | 0x00bd3720 | CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x00bd37ee | CALL | 0x00bd3720 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00bd385c | CALL | 0x00bd3720 | UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00bd3875 | CALL | 0x00bd3720 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00bd42b3 | CALL | 0x00bd3ff0 | USERARG | UNKNOWN | CONST | - |
| 0x00bd4430 | CALL | 0x00bd43b0 | CALLRET | DEREF_DEREF_CALLRET | CONST | - |
| 0x00bd45c3 | CALL | 0x00bd4450 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00bd45df | CALL | 0x00bd4450 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00bd45fb | CALL | 0x00bd4450 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00bd4e1e | CALL | 0x00bd4bd0 | USERFIELD | DERIVED | CONST | - |
| 0x00bd5cd4 | CALL | 0x00bd4bd0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00bd5dbc | CALL | 0x00bd5d90 | USERARG | USERFIELD | CONST | - |
| 0x00bd5dce | CALL | 0x00bd5d90 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd5e29 | CALL | 0x00bd5d90 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00bd6079 | CALL | 0x00bd6000 | STACKADDR | CALLRET | CALLRET | - |
| 0x00bd6e4c | CALL | 0x00bd6e20 | USERARG | USERFIELD | CONST | - |
| 0x00bd6e5e | CALL | 0x00bd6e20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd6eb3 | CALL | 0x00bd6e20 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00bd6fda | CALL | 0x00bd6e20 | DEREF_DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd6fef | CALL | 0x00bd6e20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd705b | CALL | 0x00bd6e20 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00bd7889 | CALL | 0x00bd6e20 | DEREF_DEREF_GLOBAL | DEREF_CALLRET | CONST | - |
| 0x00bd78a5 | CALL | 0x00bd6e20 | DEREF_STACK | DEREF_CALLRET | CONST | - |
| 0x00bd793f | CALL | 0x00bd6e20 | DEREF_STACK | DEREF_CALLRET | CONST | - |
| 0x00bd8121 | CALL | 0x00bd6e20 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00bd8136 | CALL | 0x00bd6e20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd8ba2 | CALL | 0x00bd6e20 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00bd8bb7 | CALL | 0x00bd6e20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bd8c86 | CALL | 0x00bd6e20 | USERARG | DEREF_UNKNOWN | CONST | - |
| 0x00bd8c9b | CALL | 0x00bd6e20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00bdc2e6 | CALL | 0x00bdc0c0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00bdc30e | JMP | 0x00bdc0c0 | DERIVED | DERIVED | CONST | - |
| 0x00bdc376 | CALL | 0x00bdc0c0 | DEREF_UNKNOWN | DERIVED | CONST | - |
| 0x00bdc9fa | CALL | 0x00bdc980 | USERFIELD | USERARG | UNKNOWN | - |
| 0x00bdcab5 | CALL | 0x00bdca10 | USERARG | UNKNOWN | DERIVED | - |
| 0x00bdcbfc | CALL | 0x00bdcbc0 | USER_PTR | USERARG | CONST | - |
| 0x00bdcfa8 | CALL | 0x00bdcbc0 | CALLRET | GLOBAL | CONST | - |
| 0x00bdd528 | CALL | 0x00bdd270 | USERFIELD | STACKADDR | CONST | - |
| 0x00bdd920 | CALL | 0x00bdd690 | DERIVED | GLOBAL | CONST | - |
| 0x00bdda70 | CALL | 0x00bdd990 | DERIVED | GLOBAL | CONST | - |
| 0x00bddef8 | CALL | 0x00bddd30 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00bde054 | CALL | 0x00bddd30 | GLOBAL | STACKADDR | CONST | - |
| 0x00bde3c1 | CALL | 0x00bde220 | UNKNOWN | GLOBAL | CONST | - |
| 0x00bde92d | CALL | 0x00bde8d0 | STACKADDR | DERIVED | CONST | - |
| 0x00bdeda3 | CALL | 0x00bded30 | STACKADDR | DEREF_GLOBAL | CONST | - |
| 0x00bdf01d | CALL | 0x00bdefd0 | STACKADDR | CALLRET | CALLRET | - |
| 0x00bdf07b | CALL | 0x00bdefd0 | DEREF_GLOBAL | STACKADDR | CONST | - |
| 0x00bdf09b | CALL | 0x00bdefd0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00bdf25d | CALL | 0x00bdf210 | STACKADDR | CALLRET | CALLRET | - |
| 0x00bdf2bb | CALL | 0x00bdf210 | DEREF_GLOBAL | STACKADDR | CONST | - |
| 0x00bdf2db | CALL | 0x00bdf210 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00bdf50d | CALL | 0x00bdf4c0 | STACKADDR | CALLRET | CALLRET | - |
| 0x00bdf56b | CALL | 0x00bdf4c0 | DEREF_GLOBAL | STACKADDR | CONST | - |
| 0x00bdf58b | CALL | 0x00bdf4c0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00bdf79f | CALL | 0x00bdf6c0 | DERIVED | UNKNOWN | CONST | - |
| 0x00bdf86b | CALL | 0x00bdf800 | STACKADDR | DERIVED | CONST | - |
| 0x00bdf93e | CALL | 0x00bdf8f0 | STACKADDR | STACKADDR | CONST | - |
| 0x00bdfb71 | CALL | 0x00bdfb00 | STACKADDR | DERIVED | CONST | - |
| 0x00bdfd09 | CALL | 0x00bdfbe0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00bdfd43 | CALL | 0x00bdfbe0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00bdfea1 | CALL | 0x00bdfdc0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00bdfec4 | CALL | 0x00bdfdc0 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00be0f0e | CALL | 0x00be0ec0 | STACKADDR | STACKADDR | CONST | - |
| 0x00be1364 | CALL | 0x00be12d0 | STACKADDR | STACKADDR | CONST | - |
| 0x00be13b5 | CALL | 0x00be12d0 | STACKADDR | STACKADDR | CONST | - |
| 0x00be1bc3 | CALL | 0x00be1a90 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00be1be3 | CALL | 0x00be1a90 | DEREF_UNKNOWN | STACKADDR | CONST | - |
| 0x00be1c1e | CALL | 0x00be1a90 | DERIVED | GLOBAL | CONST | - |
| 0x00be1d0c | CALL | 0x00be1cc0 | STACKADDR | GLOBAL | CONST | - |
| 0x00be1e74 | CALL | 0x00be1de0 | STACKADDR | CALLRET | CONST | - |
| 0x00be2832 | CALL | 0x00be1fc0 | GLOBAL | STACKADDR | CONST | - |
| 0x00be2ed8 | CALL | 0x00be2b10 | CALLRET | CALLRET | CONST | - |
| 0x00be2f35 | CALL | 0x00be2b10 | STACKADDR | GLOBAL | CONST | - |
| 0x00be304e | CALL | 0x00be2b10 | USERARG | DERIVED | CONST | - |
| 0x00be30b0 | CALL | 0x00be2b10 | CALLRET | CALLRET | CONST | - |
| 0x00be3242 | CALL | 0x00be2b10 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00be3331 | CALL | 0x00be2b10 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00be33b2 | CALL | 0x00be2b10 | DERIVED | DEREF_UNKNOWN | CONST | - |
| 0x00be33cf | CALL | 0x00be2b10 | DERIVED | CALLRET | CONST | - |
| 0x00be3528 | CALL | 0x00be2b10 | DERIVED | CALLRET | CONST | - |
| 0x00be3665 | CALL | 0x00be2b10 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00be36a3 | CALL | 0x00be2b10 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00be8379 | CALL | 0x00be8290 | STACKADDR | CALLRET | CONST | - |
| 0x00be9410 | CALL | 0x00be9250 | UNKNOWN | DEREF_UNKNOWN | CONST | 7@2,652@2 |
| 0x00be945c | CALL | 0x00be9250 | DEREF_CALLRET | DEREF_CALLRET | CONST | 7@2,652@2 |
| 0x00beb907 | CALL | 0x00beb810 | DEREF_STACK | STACK | DERIVED | - |
| 0x00befa39 | CALL | 0x00bef990 | USERARG | DEREF_UNKNOWN | DEREF_DEREF_UNKNOWN | - |
| 0x00bf96ba | CALL | 0x00bf9600 | STACKADDR | UNKNOWN | CONST | - |
| 0x00bf9990 | CALL | 0x00bf9820 | USER_PTR | DERIVED | CONST | - |
| 0x00bf9e6c | CALL | 0x00bf9d30 | DEREF_UNKNOWN | DERIVED | STACK | - |
| 0x00bfa3d1 | CALL | 0x00bfa180 | DEREF_DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x00bfc52a | CALL | 0x00bfc250 | STACKADDR | STACKADDR | CONST | - |
| 0x00bfc5b2 | CALL | 0x00bfc250 | STACKADDR | STACKADDR | CONST | - |
| 0x00bfc6ea | CALL | 0x00bfc250 | STACKADDR | STACKADDR | CONST | - |
| 0x00bff573 | CALL | 0x00bff500 | CALLRET | CALLRET | CONST | - |
| 0x00bff5b5 | CALL | 0x00bff500 | CALLRET | DEREF_DEREF_CALLRET | CALLRET | - |
| 0x00bffadc | CALL | 0x00bff9d0 | DEREF_DERIVED | STACK | CONST | 622@2 |
| 0x00c00c78 | CALL | 0x00c00be0 | CALLRET | GLOBAL | DERIVED | 622@2 |
| 0x00c019ae | CALL | 0x00c015a0 | UNKNOWN | DEREF_UNKNOWN | CONST | 622@2 |
| 0x00c02845 | CALL | 0x00c02680 | UNKNOWN | STACKADDR | CONST | 622@3 |
| 0x00c02dbe | CALL | 0x00c02b70 | STACK | STACKADDR | CONST | 622@2 |
| 0x00c02f95 | CALL | 0x00c02e10 | DEREF_STACK | STACK | STACK | 622@1 |
| 0x00c0313d | CALL | 0x00c02e10 | DEREF_UNKNOWN | STACK | CONST | 622@1 |
| 0x00c03225 | CALL | 0x00c02e10 | DEREF_UNKNOWN | STACKADDR | CONST | 622@1 |
| 0x00c0328a | CALL | 0x00c02e10 | DEREF_CALLRET | CALLRET | CONST | 622@1 |
| 0x00c03384 | CALL | 0x00c02e10 | DEREF_CALLRET | STACK | CONST | 622@1 |
| 0x00c034c7 | CALL | 0x00c02e10 | DEREF_UNKNOWN | USERARG | CONST | 622@1 |
| 0x00c035d2 | CALL | 0x00c02e10 | STACK | GLOBAL | CONST | 622@1 |
| 0x00c0374a | CALL | 0x00c02e10 | DEREF_STACK | STACKADDR | CONST | 622@1 |
| 0x00c03759 | CALL | 0x00c02e10 | DEREF_CALLRET | CALLRET | CALLRET | 622@1 |
| 0x00c04de3 | CALL | 0x00c04c80 | USERFIELD | DERIVED | DERIVED | - |
| 0x00c04e58 | CALL | 0x00c04c80 | DERIVED | DERIVED | DERIVED | - |
| 0x00c04e62 | CALL | 0x00c04c80 | USERARG | USERARG | UNKNOWN | - |
| 0x00c0bfe8 | CALL | 0x00c0bb70 | CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00c0d8a1 | CALL | 0x00c0d370 | STACKADDR | STACKADDR | CONST | - |
| 0x00c0d8c5 | CALL | 0x00c0d370 | STACKADDR | CALLRET | CONST | - |
| 0x00c0d8e9 | CALL | 0x00c0d370 | STACKADDR | CALLRET | CONST | - |
| 0x00c11489 | CALL | 0x00c11020 | DEREF_STACK | DEREF_STACK | CONST | - |
| 0x00c1175a | CALL | 0x00c116e0 | USERFIELD | USERFIELD | CONST | - |
| 0x00c1203c | CALL | 0x00c11fc0 | DERIVED | UNKNOWN | CONST | - |
| 0x00c13d24 | CALL | 0x00c136f0 | UNKNOWN | DEREF_STACK | DERIVED | - |
| 0x00c13ebe | CALL | 0x00c136f0 | DERIVED | DEREF_DERIVED | UNKNOWN | - |
| 0x00c13f27 | CALL | 0x00c136f0 | DERIVED | DEREF_DERIVED | UNKNOWN | - |
| 0x00c1410e | CALL | 0x00c136f0 | DERIVED | DERIVED | DEREF_CALLRET | - |
| 0x00c192f5 | CALL | 0x00c18f80 | USERARG | UNKNOWN | UNKNOWN | - |
| 0x00c1967d | CALL | 0x00c19330 | CALLRET | CALLRET | CALLRET | 2@6,251@6 |
| 0x00c1972b | CALL | 0x00c19330 | DEREF_UNKNOWN | USER_PTR | UNKNOWN | 2@6,251@6 |
| 0x00c1984b | CALL | 0x00c19330 | UNKNOWN | USER_PTR | UNKNOWN | 2@6,251@6 |
| 0x00c19e20 | CALL | 0x00c19dc0 | USERARG | UNKNOWN | DERIVED | - |
| 0x00c19e40 | CALL | 0x00c19dc0 | DERIVED | DEREF_CALLRET | DERIVED | - |
| 0x00c1d614 | CALL | 0x00c1d460 | DEREF_CALLRET | CALLRET | STACK | - |
| 0x00c20035 | CALL | 0x00c20020 | USERARG | UNKNOWN | CONST | 588@3 |
| 0x00c2a631 | CALL | 0x00c29010 | DEREF_UNKNOWN | DEREF_UNKNOWN | DEREF_UNKNOWN | - |
| 0x00c2c229 | CALL | 0x00c29010 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00c2c378 | CALL | 0x00c29010 | DEREF_DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00c2cc1c | CALL | 0x00c29010 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00c2cd87 | CALL | 0x00c29010 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00c2cdad | CALL | 0x00c29010 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00c2ceb9 | CALL | 0x00c29010 | DEREF_CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00c2cf6d | CALL | 0x00c29010 | DEREF_CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00c2d021 | CALL | 0x00c29010 | DEREF_CALLRET | DEREF_CALLRET | DEREF_CALLRET | - |
| 0x00c32fe1 | CALL | 0x00c32f70 | STACKADDR | USERARG | DERIVED | 588@3 |
| 0x00c33220 | CALL | 0x00c330d0 | STACK | STACKADDR | CALLRET | 588@3 |
| 0x00c37fe0 | CALL | 0x00c37f50 | STACKADDR | CALLRET | CONST | - |
| 0x00c380db | CALL | 0x00c38060 | STACKADDR | DERIVED | CONST | - |
| 0x00c3817d | CALL | 0x00c38060 | STACKADDR | CALLRET | CONST | - |
| 0x00c381ae | CALL | 0x00c38060 | CALLRET | STACKADDR | CONST | - |
| 0x00c386a4 | CALL | 0x00c385a0 | DERIVED | DERIVED | CALLRET | - |
| 0x00c388f9 | CALL | 0x00c38820 | DERIVED | CALLRET | CALLRET | - |
| 0x00c38b41 | CALL | 0x00c38820 | UNKNOWN | UNKNOWN | USERARG | - |
| 0x00c38cbb | CALL | 0x00c38b60 | DERIVED | STACKADDR | DERIVED | - |
| 0x00c38dad | CALL | 0x00c38d00 | DERIVED | CALLRET | CALLRET | - |
| 0x00c38eca | CALL | 0x00c38dd0 | UNKNOWN | UNKNOWN | USERARG | - |
| 0x00c398ab | CALL | 0x00c39850 | USERFIELD | USERFIELD | DERIVED | - |
| 0x00c398c3 | CALL | 0x00c39850 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00c398db | CALL | 0x00c39850 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00c398ec | CALL | 0x00c39850 | CALLRET | STACKADDR | CONST | - |
| 0x00c39aad | CALL | 0x00c39850 | CALLRET | STACKADDR | CALLRET | - |
| 0x00c3bbd3 | CALL | 0x00c3b200 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00c3bbf0 | CALL | 0x00c3b200 | DEREF_CALLRET | CALLRET | CONST | - |
| 0x00c49f86 | CALL | 0x00c49d60 | CALLRET | CALLRET | CONST | - |
| 0x00c4a84f | CALL | 0x00c4a790 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00c4a8e5 | CALL | 0x00c4a790 | DEREF_UNKNOWN | UNKNOWN | CONST | - |
| 0x00c4a90d | CALL | 0x00c4a790 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00c4a954 | CALL | 0x00c4a790 | STACKADDR | UNKNOWN | CONST | - |
| 0x00c4a9e2 | CALL | 0x00c4a790 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00c4dd3c | CALL | 0x00c4dc60 | STACKADDR | CALLRET | CONST | - |
| 0x00c4eb6b | CALL | 0x00c4e950 | DEREF_DEREF_STACK | DEREF_STACK | CONST | - |
| 0x00c4ed4d | CALL | 0x00c4e950 | STACKADDR | DEREF_STACK | CONST | - |
| 0x00c4edc1 | CALL | 0x00c4e950 | CALLRET | DEREF_STACK | STACK | - |
| 0x00c4f911 | CALL | 0x00c4f840 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00c4f96d | CALL | 0x00c4f840 | DEREF_DERIVED | DERIVED | CONST | - |
| 0x00c5031a | CALL | 0x00c50030 | DERIVED | STACKADDR | CONST | - |
| 0x00c53796 | CALL | 0x00c536b0 | UNKNOWN | USERARG | CONST | - |
| 0x00c53bbb | CALL | 0x00c53900 | CALLRET | CALLRET | CONST | - |
| 0x00c550cf | CALL | 0x00c541b0 | CALLRET | DERIVED | CALLRET | - |
| 0x00c5655d | CALL | 0x00c541b0 | DEREF_STACK | STACK | CONST | - |
| 0x00c56bab | CALL | 0x00c541b0 | DEREF_STACK | STACK | CONST | - |
| 0x00c58f41 | CALL | 0x00c58ab0 | UNKNOWN | STACKADDR | CONST | - |
| 0x00c59e30 | CALL | 0x00c59c10 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00c6062d | CALL | 0x00c5fbf0 | DEREF_CALLRET | UNKNOWN | DEREF_CALLRET | - |
| 0x00c614e3 | CALL | 0x00c5fbf0 | DEREF_STACK | STACKADDR | CONST | - |
| 0x00c61506 | CALL | 0x00c5fbf0 | DERIVED | DEREF_STACK | DERIVED | - |
| 0x00c6238a | CALL | 0x00c622d0 | DERIVED | STACKADDR | CONST | - |
| 0x00c623a9 | CALL | 0x00c622d0 | DEREF_CALLRET | DEREF_CALLRET | DERIVED | - |
| 0x00c623c7 | CALL | 0x00c622d0 | DERIVED | STACK | STACK | - |
| 0x00c63002 | CALL | 0x00c622d0 | USERFIELD | STACKADDR | CONST | - |
| 0x00c63021 | CALL | 0x00c622d0 | DERIVED | DEREF_CALLRET | DERIVED | - |
| 0x00c63252 | CALL | 0x00c630a0 | CALLRET | CALLRET | CONST | - |
| 0x00c63a7d | CALL | 0x00c630a0 | CALLRET | CALLRET | CONST | - |
| 0x00c7e63f | CALL | 0x00c7d730 | DEREF_UNKNOWN | UNKNOWN | DERIVED | - |
| 0x00c7e73f | CALL | 0x00c7d730 | DEREF_UNKNOWN | UNKNOWN | DERIVED | - |
| 0x00c8095e | CALL | 0x00c804d0 | STACKADDR | USERARG | CONST | - |
| 0x00c809f6 | CALL | 0x00c804d0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00c80a13 | CALL | 0x00c804d0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00c80e23 | CALL | 0x00c804d0 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00c81737 | CALL | 0x00c81670 | CALLRET | DEREF_STACK | CONST | - |
| 0x00c817f3 | CALL | 0x00c81770 | STACKADDR | DEREF_CALLRET | CONST | - |
| 0x00c8186b | CALL | 0x00c81770 | CALLRET | STACKADDR | CONST | - |
| 0x00c8490a | CALL | 0x00c848d0 | USERARG | UNKNOWN | USERARG | - |
| 0x00c8602c | CALL | 0x00c85fc0 | CALLRET | CALLRET | CALLRET | - |
| 0x00c87238 | CALL | 0x00c87090 | CALLRET | STACK | STACK | - |
| 0x00c872c5 | CALL | 0x00c87090 | CALLRET | STACK | STACK | - |
| 0x00c87b63 | CALL | 0x00c87b30 | DERIVED | USERFIELD | CONST | - |
| 0x00c87b97 | CALL | 0x00c87b30 | UNKNOWN | DERIVED | CONST | - |
| 0x00c87bdf | CALL | 0x00c87b30 | UNKNOWN | DERIVED | DERIVED | - |
| 0x00c89226 | CALL | 0x00c88c50 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00c89282 | CALL | 0x00c88c50 | CALLRET | STACKADDR | CONST | - |
| 0x00c8933a | CALL | 0x00c88c50 | STACKADDR | DEREF_UNKNOWN | CONST | - |
| 0x00c8934e | CALL | 0x00c88c50 | STACKADDR | CALLRET | CONST | - |
| 0x00c8a907 | CALL | 0x00c89d00 | CALLRET | CALLRET | CONST | - |
| 0x00c8a955 | CALL | 0x00c89d00 | CALLRET | CALLRET | CONST | - |
| 0x00c8a98c | CALL | 0x00c89d00 | STACKADDR | STACKADDR | CONST | - |
| 0x00c8a9d1 | CALL | 0x00c89d00 | CALLRET | STACKADDR | CONST | - |
| 0x00c8abe7 | CALL | 0x00c89d00 | CALLRET | GLOBAL | CONST | - |
| 0x00c8ac9a | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8ad27 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8adbf | CALL | 0x00c89d00 | CALLRET | GLOBAL | CONST | - |
| 0x00c8b004 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b0b4 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b177 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b224 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b2f7 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b3d7 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b484 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b544 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b604 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b6c4 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b784 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b844 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b904 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8b9c8 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8bad4 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8bb74 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8bc24 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8bce4 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8bda4 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8be64 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8bf24 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8bfe4 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c0a4 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c164 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c212 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c2a2 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c332 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c3c2 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c451 | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c8c51a | CALL | 0x00c89d00 | STACKADDR | GLOBAL | CONST | - |
| 0x00c91536 | CALL | 0x00c91490 | DEREF_UNKNOWN | USERFIELD | CONST | - |
| 0x00c91548 | CALL | 0x00c91490 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00c916a6 | CALL | 0x00c91600 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00c916b8 | CALL | 0x00c91600 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00c93835 | CALL | 0x00c937c0 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00c93847 | CALL | 0x00c937c0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00c94bde | CALL | 0x00c93f70 | CALLRET | CALLRET | DEREF_CALLRET | - |
| 0x00c960aa | CALL | 0x00c95d80 | CALLRET | DEREF_DEREF_CALLRET | CALLRET | 5@3,12@2,15@2+21 |
| 0x00c97391 | JMP | 0x00c97380 | USERARG | GLOBAL | CONST | 539@6,550@6,622@6+6 |
| 0x00c9763d | CALL | 0x00c97380 | DEREF_GLOBAL | STACKADDR | CONST | 539@6,550@6,622@6+6 |
| 0x00c97bfb | CALL | 0x00c977e0 | DEREF_GLOBAL | STACKADDR | CONST | - |
| 0x00c97c14 | CALL | 0x00c977e0 | DEREF_CALLRET | STACKADDR | CONST | - |
| 0x00c9819d | CALL | 0x00c97fc0 | CALLRET | DEREF_CALLRET | CONST | - |
| 0x00c981ba | CALL | 0x00c97fc0 | CALLRET | CALLRET | CONST | - |
| 0x00c98480 | CALL | 0x00c97fc0 | DEREF_STACK | UNKNOWN | DERIVED | - |
| 0x00c9864d | CALL | 0x00c97fc0 | DEREF_UNKNOWN | DEREF_DERIVED | CONST | - |
| 0x00c9867b | CALL | 0x00c97fc0 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00c98805 | CALL | 0x00c97fc0 | DEREF_STACK | UNKNOWN | DERIVED | - |
| 0x00c9a3dd | CALL | 0x00c9a1a0 | CALLRET | STACKADDR | CONST | - |
| 0x00c9a526 | CALL | 0x00c9a410 | STACKADDR | USERARG | CONST | - |
| 0x00c9a536 | CALL | 0x00c9a410 | CALLRET | CALLRET | CONST | - |
| 0x00c9a68c | CALL | 0x00c9a410 | CALLRET | CALLRET | CONST | - |
| 0x00c9a6a0 | CALL | 0x00c9a410 | CALLRET | STACKADDR | CONST | - |
| 0x00c9a6b8 | CALL | 0x00c9a410 | STACK | STACKADDR | CONST | - |
| 0x00c9a6d0 | CALL | 0x00c9a410 | STACK | STACKADDR | CONST | - |
| 0x00c9a7a3 | CALL | 0x00c9a710 | CALLRET | CALLRET | CALLRET | - |
| 0x00c9a81f | CALL | 0x00c9a710 | CALLRET | CALLRET | CALLRET | - |
| 0x00c9aaea | CALL | 0x00c9aa90 | CALLRET | CALLRET | CALLRET | 1@4,37@3,39@6+47 |
| 0x00c9ad66 | CALL | 0x00c9ac10 | UNKNOWN | USERFIELD | DERIVED | 341@6,431@6 |
| 0x00c9bb1c | CALL | 0x00c9ba30 | STACK | GLOBAL | CONST | 341@6,431@6 |
| 0x00c9beef | CALL | 0x00c9ba30 | UNKNOWN | STACKADDR | CONST | 341@6,431@6 |
| 0x00c9bf0e | CALL | 0x00c9ba30 | DERIVED | STACK | CALLRET | 341@6,431@6 |
| 0x00c9c068 | CALL | 0x00c9ba30 | UNKNOWN | STACKADDR | CONST | 341@6,431@6 |
| 0x00c9c087 | CALL | 0x00c9ba30 | DERIVED | STACK | CALLRET | 341@6,431@6 |
| 0x00c9e896 | CALL | 0x00c9e350 | STACKADDR | CALLRET | CONST | 341@6,431@6 |
| 0x00c9f019 | CALL | 0x00c9ef60 | STACK | DEREF_CALLRET | CALLRET | 341@5,345@6,346@6+3 |
| 0x00c9f1c4 | CALL | 0x00c9ef60 | STACK | DEREF_UNKNOWN | DERIVED | 341@5,345@6,346@6+3 |
| 0x00ca1c8c | CALL | 0x00ca0630 | CALLRET | CALLRET | STACK | - |
| 0x00ca295f | CALL | 0x00ca0630 | UNKNOWN | UNKNOWN | UNKNOWN | - |
| 0x00ca33b0 | CALL | 0x00ca3060 | DERIVED | DERIVED | CALLRET | 59@3 |
| 0x00ca342d | CALL | 0x00ca3060 | STACK | USERARG | UNKNOWN | 59@3 |
| 0x00cad424 | CALL | 0x00cad330 | DEREF_UNKNOWN | DEREF_UNKNOWN | CONST | - |
| 0x00cad43c | CALL | 0x00cad330 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00cad457 | CALL | 0x00cad330 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00cad48b | CALL | 0x00cad330 | CALLRET | CALLRET | CONST | - |
| 0x00caee98 | CALL | 0x00cae160 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00caef9c | CALL | 0x00cae160 | DEREF_CALLRET | DERIVED | CONST | - |
| 0x00cafadd | CALL | 0x00cafa20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00cafb98 | CALL | 0x00cafa20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00cafbcf | CALL | 0x00cafa20 | DEREF_CALLRET | DEREF_CALLRET | CONST | - |
| 0x00cafbea | CALL | 0x00cafa20 | DERIVED | DEREF_CALLRET | CONST | - |
| 0x00cb0857 | CALL | 0x00cb07b0 | DERIVED | CALLRET | CALLRET | - |
| 0x00cb090e | CALL | 0x00cb08a0 | STACKADDR | USERARG | DERIVED | 2@6,5@6,12@6+71 |
| 0x00cb0b84 | CALL | 0x00cb08a0 | STACKADDR | STACKADDR | DERIVED | 2@6,5@6,12@6+71 |
| 0x00cb0c98 | CALL | 0x00cb08a0 | CALLRET | DEREF_DERIVED | CONST | 2@6,5@6,12@6+71 |
| 0x00cb122e | CALL | 0x00cb08a0 | STACKADDR | DEREF_CALLRET | CONST | 2@6,5@6,12@6+71 |
| 0x00cb4bc0 | CALL | 0x00cb4af0 | STACKADDR | STACKADDR | CONST | - |
| 0x00cb4fad | CALL | 0x00cb4f50 | STACKADDR | CALLRET | CONST | - |
| 0x00cb5239 | CALL | 0x00cb4fe0 | DERIVED | STACKADDR | CONST | - |
| 0x00cb5943 | CALL | 0x00cb5880 | UNKNOWN | STACKADDR | CONST | - |
| 0x00cb59fb | CALL | 0x00cb5880 | DERIVED | STACKADDR | CONST | - |
| 0x00cb5f16 | CALL | 0x00cb5e30 | UNKNOWN | UNKNOWN | CONST | - |
| 0x00cb603c | CALL | 0x00cb5f60 | UNKNOWN | UNKNOWN | CONST | 588@4 |
| 0x00cb60e2 | CALL | 0x00cb6090 | STACKADDR | CALLRET | CONST | 588@4 |
| 0x00cb6a82 | CALL | 0x00cb69b0 | UNKNOWN | STACKADDR | CONST | - |
| 0x00cb840e | CALL | 0x00cb83b0 | DEREF_UNKNOWN | UNKNOWN | UNKNOWN | 125@6 |
| 0x00cb8477 | JMP | 0x00cb83b0 | DEREF_UNKNOWN | DERIVED | DERIVED | 125@6 |
| 0x00cb84cd | CALL | 0x00cb8480 | STACKADDR | CALLRET | CONST | - |
| 0x00cb8d24 | CALL | 0x00cb8cf0 | STACKADDR | DERIVED | CONST | 125@6 |
| 0x00cb8d6e | CALL | 0x00cb8cf0 | CALLRET | CALLRET | CONST | 125@6 |
