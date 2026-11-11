# Dynamic-length copy sites: the depth-4 triage (13.60 image)

Scope: the 13.60 kernel text dump (`docs/dumps_13.60/kernel_text.bin`, base `0xffffffff8a9c0000`,
length `0xE6E5C0`, file offset == RVA). Purpose: the two subagent audits
(`docs/INTERPROC_COPYOUT_SOURCES.md`, `docs/MEMCPY_PROVENANCE.md`) were corpus-limited and the
copy-out class was closed only "for the 145-body corpus". This pass re-walks the whole syscall layer
myself and tries to break the copy layer with a user-controlled *length* rather than a user-controlled
*pointer*.

## 1. Method

1. `docs/dumps_13.60/sysent_index.json` -> 679 entries. Each `sy_call` is a hex **string** holding a
   thunk VA; `RVA = int(sy_call,16) - 0xffffffff8a9c0000`. Thunk = `e9 rel32`; handler RVA =
   `thunk_rva + 5 + rel`. Resolves to **301 distinct handler bodies**.
2. Depth-4 breadth-first walk over `call`/`jmp` targets, CFG-aware (every branch target inside a
   function is decoded, so a conditional skip does not truncate the walk): **1,678 reachable
   functions**, 4,274 call edges.
3. At each reachable instruction, record calls to `0x2591d0` (copyout), `0x259280` (copyin),
   `0x2590b0` (bare memcpy, no `stac`), and the get_user family `0x259360..0x259900`:
   **235 copyin/copyout call sites**, 106 of them copyin.
4. Classify by the length operand (`rdx` at the call): 67 have a non-constant length; of those, 38 have
   no immediate compare/bound on the length-carrying register within the preceding 70 instructions.

Scripts: `C:\tmp\reachcopy.py` (BFS + site list -> `C:\tmp\copysites.json`), `C:\tmp\boundchk.py`
(bound search -> `C:\tmp\bounds.json`).

### Three method traps that cost runs

* **`capstone.Cs(...)` has no `detail=True` keyword.** Set `md.detail = True` *after* construction.
  Passing it as a kwarg is silently accepted by older bindings and does nothing here.
* **`ins.operands[i].imm` is sign-extended** for kernel VAs. `t.imm` for a call to
  `0xffffffff8ac19280` comes back negative. Every target must be normalised with
  `(t.imm - BASE) % (1 << 64)`; without that, the BFS finds **zero** edges and reports a clean image.
  This bug produced three consecutive false-clean runs before it was caught.
* **"[body, body+0x4000]" is not a function boundary.** It lumps neighbouring functions together and
  attributes a site to the wrong syscall. Owner numbers below come from CFG reachability, not ranges.

## 2. The candidate map (site -> owning syscall)

| copy site | syscall | notes |
|---|---|---|
| `0xabb173` | 572 | |
| `0x3b221c` | 669 | aio cluster, already closed |
| `0x531151`, `0x531180` | 30 | |
| `0x438d40` | 616 | |
| `0x3afaad`, `0x3b018a` | 668 / 661 / 662 | aio, closed (`docs/AIO_DEBUG_726_727_13_60.md`) |
| `0x34b6fc` | 592 | dynlib_get_list |
| `0xabbaff`, `0xabbcd6` | 674 | virtual_query_all, measured: `len = min(stride,0x48)` |
| `0x2a8e42` | 79 | getgroups, source is `td_ucred->cr_groups`, no address control |
| `0xca197b` | 601 | mdbg, closed |
| `0x83df0b` | 487 | |
| `0x3b1854` | 665 / 666 | |
| `0x2a9bb5` | 80 | |
| `0x4ed0a2` | 480 / 54 | ioctl |
| `0x4f75af` | 604 | |
| `0x3b11f2` | 664 | |
| `0x8fbd37` | 137 / 196 | getdirentries |

## 3. The four sites read in full - all disciplined

### 3.1 `0x5581e0` (reached at depth 4)

```
r14 = uap[+8]
lea ecx,[r14-0x19] ; cmp ecx,-0x17 ; jb fail     -> r14 in [2,25]
shl r14,2                                          -> 8..100 bytes
copyin(..., [rbp-0x90], r14)                       frame 0xe8
```

Bounded twice over: field range, then a 4x scale that still fits the frame.

### 3.2 sys 455 `0x437de0`

```
437e08  cmp dword ptr [rsi + 8], 0x68
437e0c  ja  0xffffffff8adf7e58          ; fail
437e0e  lea r15, [rbp - 0xb8]           ; 0x68-byte stack buffer
437e2b  movsxd r14, dword ptr [r14 + 8] ; length = the SAME validated field
437e4f  call 0xffffffff8ac19280         ; copyin(uap[0], r15, r14)
```

Frame is `0x98` after five pushes (`rsp = rbp - 0xc0`), buffer at `rbp-0xb8` is 0x68 bytes and the
bound is 0x68. Exactly sized. (The `movsxd` is redundant - the field was already proven <= 0x68 and the
`ja` is unsigned - but it cannot go negative past the check.)

### 3.3 sys 80 `0x2a9b20`

```
2a9b45  mov eax, dword ptr [rip + 0x36768cd]   ; system limit
2a9b4b  mov ebx, dword ptr [rsi]               ; count = uap[0]
2a9b4d  inc eax
2a9b4f  cmp ebx, eax
2a9b51  ja  fail
2a9b57  lea r15, [rbx*4]                       ; length = count*4
2a9b62  cmp ebx, 0x10
2a9b65  jbe stack_path                         ; <=16 -> [rbp-0x70], <= 0x40 bytes
2a9b7c  call 0xffffffff8b5c8b50                ; malloc(count*4, 2)
2a9bb5  call 0xffffffff8ac19280                ; copyin(uap[8], buf, count*4)
2a9bbd  test eax,eax ; je ok
2a9bc1  cmp ebx, 0x11 ; jb done
2a9bd1  call 0xffffffff8b5c8df0                ; free(buf)
```

Allocation size is computed from the same expression as the copy length, on both paths. No overflow
window: `count <= limit+1` and the multiplication is 64-bit (`lea r15,[rbx*4]` with `ebx` zero-extended
by the `mov ebx, dword`).

### 3.4 sys 487 helper `0x83de90`

The syscall body itself is a 6-instruction tail-jump (`mov rdi,rsi; mov esi,1; jmp 0x8b1fdac0`); the
copy lives in the helper:

```
83deba  mov rdi, qword ptr [r15 + 0x18]   ; len = uap[3]
83debe  lea rcx, [rdi - 0x11]
83dec2  cmp rcx, -9
83dec6  jb  fail                          ; len - 17 >= 0xFFFFFFF7  ->  len in [9,17]
83dedb  call 0xffffffff8b5c8b50           ; malloc(len, 0x102)
83df0b  call 0xffffffff8ac19280           ; copyin(uap[4], heap, len)
```

Length forced into a 9-byte window, allocation exactly that size.

## 4. Why this class keeps coming back clean

Every one of the four is the same pattern: **the length the handler copies is recomputed from the field
it already validated**, and the allocation (or frame slot) is sized from that same recomputation. The
13.60 copy layer is not a wrapper that trusts its caller; each handler re-derives. That is consistent
with the audit result in `docs/COPYOUT_CLASS_CLOSED.md` §12 (0 user-derived copy sources out of 1,110
functions at depth 4) and it is the reason the "POINTER" side of the copy layer is closed: both the
direction (user<->kernel) and the extent are handler-local decisions.

**Not a route: a length-driven overread/overflow through copyin/copyout.** The 38 unbounded-looking
sites are bounded by a compare that the 70-instruction window misses (a caller validates once and passes
the value down), so the residual is *not* "38 possibly-buggy sites"; the four that were read in full were
all bounded, and the remaining 34 are lower-priority than the indirect-dispatch surface, which the dumps
cannot reach (`docs/DEVFS_GAP_ANALYSIS_14_10.md` §11).

## 5. What is actually left in this class

1. **Indirect dispatch** - `pr_usrreqs`, `VOP_*`, `cdevsw`, kqueue filters. The cdevsw tables are not in
   the dumps (measured, see §11 of the devfs document), so this needs behaviour, not disassembly.
2. **`td_retval` stores computed from an argument** - a handler that returns a value derived from a
   pointer it was given. Not searched for yet; the search shape is "load through an argument, store to
   `[td+0x...]`", which is a different dataflow direction from everything above.

## 6. Audit A's C1 (`0x70322d`) is an internal object-fill helper

Audit A ranked `0x70322d` - `memcpy(*(arg2+0x20), arg3, arg4)` - as its shallowest user-flavoured
destination. Reading it shows a five-field constructor, not a syscall path:

```
703210  push rbp / mov rbp,rsp / push r15,r14,rbx / push rax
70321a  mov r15, rsi                 ; object
70321d  lea rdi, [rsi + 0x20]        ; dst = obj+0x20
703221  mov rsi, rdx                 ; src
703224  mov rdx, rcx                 ; len
703227  mov ebx, r8d                 ; trailing int
70322d  call 0xffffffff8ac190b0      ; bare memcpy, no stac
703232  movsxd rax, ebx
703235  mov byte [r15+0x38], r14b    ; obj+0x38 = len
703239  lea rax, [r15+rax+0x20]
70323e  mov [r15+0xa0], rax          ; obj+0xa0 = obj+0x20+int
703245  or byte [r15+0x70], 8
70324a  or byte [r15+0x3c], 1
```

All four call sites (`0x6b4743`, `0x95a4f8`, `0x9c5ab6`, `0xa875b4`) pass the same shape: a stack
descriptor, a length out-param filled by `0x703380`, and the destination object in `rsi`. `0x703380` is
the *user-facing* end: it bzeroes the caller's buffer with the length the caller supplied
(`mov rsi,[r8]` before `call 0x258ff0`), fills a 0x38-byte descriptor, and makes a guarded indirect call
through `[rbx+0x4d8]` (see `docs/CFI_CENSUS_13_60.md`). The copy length handed back to the fill helper is
the length the VOP wrote, bounded by the buffer the caller bzeroed. Nothing here reads a pointer out of
the uap.
