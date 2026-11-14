# The function-pointer whitelist: a census (13.60)

Prior art: `docs/THR_CREATE_430_CONTEXT.md` documented the check at `0x4380a7` in `thr_create`'s
worker (`lea rax,[rip-0x1d10a6]` -> `0x267008`, `sub rax,r13; ror rax,3; cmp rax,0x3a5; ja fail`)
and correctly read it as a whitelist over the 934 stubs in `[0x2652E0, 0x267008)`. This document does
not re-derive the semantics; it measures **how much of the kernel's indirect-call surface carries the
check**, because that number decides whether a future write primitive can be turned into control flow.

## 1. The idiom (recap, with the exact encoding)

```
mov  rXX, [table + idx*8]      ; load a candidate function pointer
lea  rax, [rip + K]            ; K = top of an 8-byte-stride stub block
sub  rax, rXX
ror  rax, 3
cmp  rax, N
ja   fail                      ; reject
call rXX
```

`ror rax,3` is not a shift: it rotates the low three bits into the top of the register. A pointer that
is not exactly `8*i` bytes below `K` produces a value near `2^61` and fails the compare. So the check
admits exactly `N+1` values, the 8-byte-aligned slots `K, K-8, ... K-8N`. Every stub block in the image
has that 8-byte stride (5-byte `e9 rel32` plus three `cc`), which is what makes the arithmetic work;
the 5-byte packing quoted for the sysent thunks in earlier notes is the *dense* form, while the blocks
used as validation targets are padded to 8.

Three instances, resolved by hand:

| check site | `K` | `N` | admitted stubs |
|---|---|---|---|
| `0x4380a7` (thr_create worker, documented earlier) | `0x267008` | `0x3a5` | 934, `[0x2652E0, 0x267008]` |
| `0x272ad3` (table load at `0x272acf`) | `0x26C670` | `0x22` | 35, `[0x26C560, 0x26C670]` |
| `0x54FB13` | `0x269338` | `3` | 4, `[0x269320, 0x269338]` |

All three `K` values land inside the same stub vector area (`0x265xxx`-`0x267xxx`), which is the
kernel's dispatch-stub arena; the qwords there decode as `e9 rel32; cc cc cc`.

## 2. Census

Whole-image scan of `docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`, 15,132,096 bytes):

| item | count |
|---|---|
| `ror rax,3` (`48 c1 c8 03`) occurrences | **5,676** |
| indirect `call reg` / `call [mem]` sites | **16,396** |
| indirect `jmp reg` / `jmp [mem]` sites | **13,710** |
| indirect call sites with a `ror rax,3` within the preceding 0x60 bytes | **4,794** (29.2%) |
| indirect call sites with no such check in that window | **11,602** |

The 0x60-byte window is generous (the three examples place the `ror` 10-30 bytes before the `call`), so
4,794 is a *lower* bound on guarded calls and the 11,602 are the sites where a target-validation check
is not locally visible.

## 3. What the residual 11,602 are (and are not)

They are not 11,602 exploitable calls. Spot-reading the unguarded sample (`0x259b8a`, `0x27322a`,
`0x29310e`, `0x299de7`, `0x29d190`...) shows the common shapes:

* calls through a **constant** table (`call qword ptr [rip+0x...]`), where the pointer is not writable
  by any code path we have found - the load is a constant-address memory operand, not an indexed one;
* calls to a pointer that was produced by a helper that *already* validated it (the check sits in the
  caller, the call in the callee);
* calls whose target came from a struct field that is only ever written at object construction.

The last shape is the interesting one and it is exactly what the devfs/ops-vector class would need.
Verifying it requires struct-field write provenance per call site, which is a much larger analysis than
this census and has not been done.

## 4. Why this matters for the objective

Any primitive that ends in "write a chosen 8 bytes into a kernel function-pointer slot" now has a second
half: the written value must be one of the stubs admitted by whichever check guards the call site. The
stubs are `e9 rel32` trampolines into real handlers, so the practical result of a hijack is "call a
different legitimate handler with the hijacked call's arguments", not "jump to a ROP gadget or to a
userland mapping". That is a materially weaker outcome, and it means a control-flow hijack is not a
substitute for a data-only primitive (arbitrary kernel read/write), which remains the objective.

## 5. Corollary: the 8-byte stride is load-bearing

The stub arena is padded to 8 bytes specifically so the whitelist can be expressed as a shift-and-compare
instead of a loop or a bitmap. Any table whose entries are 5-byte packed cannot be validated this way,
which is why the `sysent` table's own thunks (dense) never appear as the target of a `ror` check while
the dispatch stubs (padded) do.
