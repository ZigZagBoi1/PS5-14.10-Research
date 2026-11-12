# Sys 341's indexed load at 0x55f0cb is an id-table iteration, not a syscall argument

Closes the single "unknown" row of `docs/KERNEL_INDEXED_LOAD_CENSUS_14_10.md` (line 137). Static work
only; no probe was sent and the console was off.

## What the census recorded

> 0x55ed70 / 0x55f0cb (sys 341), `mov rax, qword ptr [rbx + rax*8]` with 0x55f0b8 `lea eax, [r14 - 1];
> cdqe` and r14 = [uap]: no compare on r14 is visible in the body, but the block lies after a `ret`

Two things in that sentence are artefacts of linear disassembly from the body start 0x55ed70.

## Correction 1: 0x55f0cb is not in body 0x55ed70

`0x55f010` is a function of its own — `55 48 89 e5` prologue, `push r15/r14/r13/r12/rbx`,
`sub rsp, 0xb8`, and a stack canary load at 0x55f024/0x55f03d/0x55f040. A linear sweep started at
0x55ed70 therefore crossed a `ret` and attributed the block to the wrong function. Everything below is
decoded from 0x55f010 onward.

## Correction 2: the index is not `[uap]`

In 0x55f010 the index register is filled from the function's own argument, not from user memory:

```
0x55f032  mov r14d, edi              ; r14d = the ARGUMENT of 0x55f010
0x55f0b8  lea eax, [r14 - 1]        ; index = arg - 1
0x55f0c2  cdqe
0x55f0cb  mov rax, [rbx + rax*8]    ; rbx = [proc+0xa8] (0x55f051: rbx = [r12+0xa8], r12 = [gs:0 + 8])
```

The body 0x55ed70 does execute `mov r14, [rsi]` at 0x55ed94 (`rsi` = uap), but that r14 is dead by the
time 0x55f010 is called: 0x55ef69 `mov r14, r13` overwrites it, and the call site passes a different
value:

```
0x55ef5d  mov rdi, rbx              ; rbx = td (0x55ed88: mov rbx, rdi)
0x55ef60  call 0x55f1c920           ; RVA 0x55c920
0x55ef65  test eax, eax
0x55ef67  je   ...
0x55ef70  mov edi, eax              ; <-- the argument to 0x55f010
0x55ef72  call 0x55f010
0x55ef7d  call 0x55f1c920           ; loop: next id
```

`0x55f010` has exactly two `e8` callers in the image, and the other one is the same shape:

```
0x4ea5a3  call 0x55f1c920
0x4ea5a8  test eax, eax
0x4ea5ac  mov edi, eax
0x4ea5ae  call 0x55f010
```

No absolute qword reference to `0xffffffff8af1f010` exists anywhere in the image (byte scan for the
8-byte little-endian constant, zero hits), so there is no stored function pointer either.

## What 0x55f1c920 (RVA 0x55c920) returns

It is the iterator over the same id table that 0x55f010 resolves against. Head:

```
0x55c93f  mov rax, [rdi]                 ; dead, overwritten
0x55c942  mov eax, [rdi + 0xa0]
0x55c948  test eax, eax
0x55c94a  jne  0x55c967
0x55c94c  cmp dword [rdi + 0xa4], 0
0x55c953  jne  0x55c967
0x55c955  cmp dword [rdi + 0xa8], 0
0x55c95c  jne  0x55c967
0x55c95e  cmp dword [rdi + 0xac], 0
0x55c965  je   0x55c9b3                 ; no bits set in the first 128 ids -> nothing to return
0x55c967  mov ecx, [rdi + 0x3b0]
0x55c96d  andn eax, ecx, eax            ; exclusion mask 1
0x55c978  mov eax, [rdi + 0x3b4]
0x55c97e  andn eax, eax, [rdi + 0xa4]   ; exclusion mask 2
0x55c98d  mov eax, [rdi + 0x3b8]
0x55c993  andn eax, eax, [rdi + 0xa8]   ; exclusion mask 3
```

`[rdi+0xa0]` is the bitmap word that the resolver 0x55e770 itself reads
(`0x55e787 lea ecx,[r9-1]; 0x55e78b sar eax,5; 0x55e793 mov eax,[rbx+rdi*4]`), so 0x55c920 walks the
id bitmap, skips the ids named by the three exclusion masks at `+0x3b0/+0x3b4/+0x3b8`, and returns the
next present id. The value handed to 0x55f010 is therefore an id the kernel put in the table, never a
number the caller supplied.

## Verdict

The row is closed as a linear-sweep artefact. The indexed-load census stands at 176 sites, every one
bounded or gated, with no unknown remaining.

Caveat, stated rather than hidden: a relative jump table could reach 0x55f010 without an `e8`. The
table is at `0x1a51160` and outside `kernel_text.bin`, so this pass cannot exclude that; it found no
`e8` caller beyond the two above and no absolute pointer.

## Not needed for the closure, recorded for the next reader

`[proc+0xa8]` is indexed as a qword array by the resolved id. The constant `0xcc0` travels with the same
field in the neighbouring function 0x4ea300 (`0x4ea57b mov rdi,[r15+0xa8]; 0x4ea582 mov r13d,0xcc0;
0x4ea58e add rdi,r13`) and at `0x55ef89 mov eax,0xcc0`, consistent with a 0xcc0-byte per-process object
whose first 0xcc0/8 = 408 qwords are an id-indexed table. The id is kernel-derived, so the size is not
a primitive.
