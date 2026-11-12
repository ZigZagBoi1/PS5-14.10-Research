# Kernel Indexed-Load Census, 13.60 Image

## Verdict

The census finds exactly one unchecked indexed load whose index comes from a syscall argument and whose result reaches userland: syscall 532, body 0xaf0040, instruction 0xaf06d9, `movzx eax, word ptr [rax + rcx*2 + 4]`. The handler copies up to 8 bytes from uap->arg3 into a stack slot (call at 0xaf0651, a local wrapper that tail-jumps to copyin at 0x259280), takes the first dword as a signed 32-bit index (0xaf065e, 0xaf06d2), selects one of seven kernel table pointers with arg1-0x10 (0xaf06b7..0xaf06d5), and loads 2 bytes at table + index*2 + 4 with no bound on the index. The zero-extended value is written to [rbp-0x858] and copied out 4 bytes to uap->arg2 at 0xaf121e. The unchecked path is taken only when the process byte at [proc+0xc81] is nonzero (0xaf00b3/0xaf00bb sets r12b = (byte == 0); r12b == 0 skips the clamp to edi = 2 at 0xaf0673). That makes it a conditional out-of-bounds kernel read of up to 4 GB in either direction from each of seven kernel tables, with the value returned to the caller, but not a primitive that a caller can reach unconditionally. No other indexed load in the 300 analysable syscall bodies was found unchecked: 24 load sites are bounded by immediates consistent with their tables, 11 by variable count checks that are semantically sound, 140 are kernel-computed indices or over-taint, and one further site (sys 341, 0x55f0cb) is left as unknown because the block sits across a function boundary.

## Scope

- Image: C:\PS5contrib\docs\dumps_13.60\kernel_text.bin, virtual base 0xffffffff8a9c0000, length 0xE6E5C0, file offset == RVA.
- Sysent: C:\PS5contrib\docs\dumps_13.60\sysent_index.json, key "entries", 679 entries. sy_call_off points at a 5-byte `jmp rel32` thunk; the body is the thunk target. 301 distinct bodies; 0x5620e0 is the shared absent-slot target for 368 syscalls and is excluded, leaving 300 analysable bodies.
- 40319 instructions decoded across the 300 bodies under the boundary rules below.

## Totals

| class | meaning | load sites |
|---|---|---|
| C | index bounded by an immediate check consistent with the table | 24 |
| W | index bounded by a variable count check that was reviewed and is sound | 11 |
| U | no dominating bound on a caller-derived index | 1 |
| N | index not caller-derived (kernel-computed, or over-taint) | 140 |
| total load sites | 164 with an explicit index register, plus 12 pre-scaled forms | 176 |

Of the 176 load sites, 37 carried a caller-derived index (36 flagged by the nearest-def taint pass, 1 more found by reading the branches) and every one of them was adjudicated by hand; the remaining 139 are kernel-computed and were only sampled. Class N above is 139 + 1 over-taint row (0x6be28a), see the dismissed-sites section. The 12 pre-scaled forms are loads whose base register is an index already scaled by shl or imul (for example 0x72ef1f, `movzx eax, byte ptr [r12 + 0x28]` with r12 = array + idx*48 + 8).

## Class definitions

- C: a dominating `cmp index, imm` / `ja`/`jbe`/`jae` (or an equivalent `and` mask or range pair) precedes the load, and the compared register is the index or the value the index was derived from by `dec`/`lea`/`movsxd` only.
- W: the dominating check compares the index against a value loaded from memory (a count stored in the same array object), usually `cmp idxd, dword ptr [array]` / `jae`, or a signed variant. These are correct only if the count really describes the array; each one was reviewed for what the array is and what the count is.
- U: no dominating compare at all between the taint source and the load, and the loaded value is copied out, dereferenced, or compared.
- N: the index is computed by the kernel from a kernel object (not caller bytes), or the row is an artefact of over-tainting.

## The U site: syscall 532, body 0xaf0040, insn 0xaf06d9

Only one syscall number resolves to body 0xaf0040: 532.

Taint chain (RVA and disassembly):

| RVA | instruction | role |
|---|---|---|
| 0xaf0070 | mov r14d, dword ptr [rsi] | uap->arg0, must equal 0x31 at 0xaf0688 |
| 0xaf0069 | mov eax, dword ptr [rsi + 8] | uap->arg1, stored to [rbp-0x864] at 0xaf0082 |
| 0xaf0065 | mov rcx, qword ptr [rsi + 0x18] | uap->arg3, stored to [rbp-0x870] at 0xaf0077 |
| 0xaf008f | mov qword ptr [rbp - 0x860], rcx | uap->arg2 (from [rsi+0x10]), the copyout destination |
| 0xaf063e | mov rdi, qword ptr [rbp - 0x870] | user pointer, arg3 |
| 0xaf0645 | lea rsi, [rbp - 0x850] | 8-byte kernel destination |
| 0xaf064c | mov edx, 8 | length |
| 0xaf0651 | call 0xaf1340 | wrapper: lock, then `jmp 0x8ac19280` = copyin at 0x259280 |
| 0xaf065e | mov edi, dword ptr [rbp - 0x850] | the caller dword becomes the index |
| 0xaf066b | test r12b, r12b | process-state gate |
| 0xaf066e | je 0xaf067e | taken when [proc+0xc81] != 0: the clamp is skipped |
| 0xaf0670 | cmp edi, 1 | only on the other path |
| 0xaf0673 | mov edi, 2 | clamp applied when [proc+0xc81] == 0 |
| 0xaf0678 | jne 0xaf0c75 | rejects user dword != 1 on the clamped path |
| 0xaf0688 | cmp r14d, 0x31 | subcommand selector |
| 0xaf0694 | cmp dword ptr [rip + 0x3207565], 0 | global flag, je to 0xaf11f2 |
| 0xaf06a1 | cmp dword ptr [rip + 0x320755c], 0 | global flag, je to 0xaf06b7 |
| 0xaf06aa | cmp dword ptr [rip + 0x320750f], 1 | jne to 0xaf11f2 |
| 0xaf06b7 | mov ecx, dword ptr [rbp - 0x864] | arg1 |
| 0xaf06bd | add ecx, -0x10 | selector bias |
| 0xaf06c0 | cmp ecx, 6 | bounds the table selector, not the index |
| 0xaf06c3 | ja 0xaf11f2 | reject arg1 outside 0x10..0x16 |
| 0xaf06c9 | mov eax, ecx | selector |
| 0xaf06cb | lea rdx, [rip + 0x3a1376] | table of 7 pointers, RVA 0xe91a48 (outside the dump) |
| 0xaf06d2 | movsxd rcx, edi | sign-extends the caller dword: negative indices accepted |
| 0xaf06d5 | mov rax, qword ptr [rdx + rax*8] | pointer to the selected kernel table |
| 0xaf06d9 | movzx eax, word ptr [rax + rcx*2 + 4] | the unchecked load |
| 0xaf06de | mov dword ptr [rbp - 0x858], eax | zero-extended result |
| 0xaf06e4 | jmp 0xaf11f8 | common exit |
| 0xaf121e | call 0x2591d0 | copyout(dst=arg2, src=[rbp-0x858], 4) |

Bound check: none on the index. 0xaf06c0 `cmp ecx, 6` bounds the index of the pointer table at 0xaf06d5, not the offset applied at 0xaf06d9; the two use different registers (ecx versus rcx = sign-extended edi).

What the loaded value is used for: it is zero-extended into eax, stored as a 4-byte status word, and copied out to the caller's arg2. It is not dereferenced and not used as an address, so the primitive is a read-and-disclose, not a read-what-where.

Gate analysis: r12b is set at 0xaf00b3 from `cmp byte ptr [r13 + 0xc81], 0; sete r12b` with r13 = [rdi+8]. A linear sweep of the whole image finds 69 accesses to displacement 0xc81 and exactly one writer: 0x38f7bf `mov byte ptr [rax + 0xc81], cl`, inside a function beginning at 0x38f3a0, where cl is 0 or 1 selected by the mode argument (cl = 1 on the `cmp r12d, 2` / `jne` path at 0x38f7a6..0x38f7b7). That function is reached through the stub at 0x25da60, which tail-jumps to 0x38f390 (`mov esi, 2; pop rbp; jmp 0x38f3a0`), i.e. the mode-2 entry point that sets the byte to 1. The stub has no direct callers in the image, so it is dispatched indirectly and the syscall that drives it could not be named statically. Reachability of the unchecked path is therefore conditional on process state, not on the arguments of 532 itself.

Impact: with the gate open, 532 (arg0 = 0x31, arg1 = 0x10..0x16, arg3 -> 8 caller bytes, arg2 -> 4-byte output) reads 2 bytes at signed-offset index*2 from any of seven kernel tables and returns them zero-extended. Negative indices reach below the table. The tables themselves are outside the retained dump (0xe91a48 and beyond), so their contents and capacity are not known; the 4-byte header offset (+4) and the 2-byte element stride are the only layout facts the code shows.

## Full table: U and W sites

Index scale column: "1 (pre)" means the load has no index register and the base register already holds index*stride; the scaling instruction is given.

| # | cls | syscalls | body | insn | load | index/scale | scaling | taint chain (RVA: instruction) | bound check | consumer |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | U | 532 | 0xaf0040 | 0xaf06d9 | movzx eax, word ptr [rax + rcx*2 + 4] | rcx, 2 | 0xaf06d2 movsxd rcx, edi | 0xaf0070 mov r14d,[rsi]; 0xaf0069 mov eax,[rsi+8]; 0xaf008f mov [rbp-0x860],rcx; 0xaf063e mov rdi,[rbp-0x870]; 0xaf0651 call copyin wrapper; 0xaf065e mov edi,[rbp-0x850]; 0xaf06d2 movsxd rcx,edi | none on the index; 0xaf06c0 cmp ecx,6 bounds the table selector only | copyout 4 bytes to uap->arg2 at 0xaf121e |
| 2 | W | 92 | 0x729dc0 | 0x72a03e | mov rdi, qword ptr [rax + rbx + 8] | rbx, 1 (pre) | 0x72a036 lea rbx,[rcx+rcx*2]; 0x72a03a shl rbx,4 | 0x729de6 mov ebx,[rsi]; 0x729ec0 mov rcx,[rbp-0x2b0]; 0x729ed6 movsxd r14,ecx; 0x72a028 mov rcx,[rbp-0x2d0]; 0x72a036 lea; 0x72a03a shl | 0x729fa6 test rbx,rbx; cmp ebx, dword ptr [rax] / jae (count at [array+0]) | test rdi,rdi at 0x72a043, then refcount cmpxchg |
| 3 | W | 92 | 0x729dc0 | 0x72a08c | mov rdi, qword ptr [r12 + rbx + 8] | rbx, 1 (pre) | as row 2 | as row 2 | as row 2 | test rdi,rdi at 0x72a091 |
| 4 | W | 92 | 0x729dc0 | 0x72a09e | mov rdi, qword ptr [r12 + rbx + 8] | rbx, 1 (pre) | as row 2 | as row 2 | as row 2 | test rdi,rdi at 0x72a0a3 |
| 5 | W | 92 | 0x729dc0 | 0x72a0f6 | movzx edx, byte ptr [rax + rcx + 0x30] | rcx, 1 (pre) | 0x72a0e2 lea rcx,[rcx+rcx*2]; 0x72a0e6 shl rcx,4 | 0x729f2e mov rdx,[rbp-0x298]; 0x72a0d7 mov rcx,[rbp-0x2b0]; 0x72a0e2 lea; 0x72a0e6 shl | same fd-table count check | and dl,0xfe at 0x72a103, stored back into the entry |
| 6 | W | 6 | 0x72bf00 | 0x72bfd3 | mov rax, qword ptr [rax + r13 + 8] | r13, 1 (pre) | 0x72bfcb lea r13,[rcx+rcx*2]; 0x72bfcf shl r13,4 | 0x72bf04 mov esi,[rsi]; 0x72bf21 mov r14d,esi; 0x72bfc5 mov ecx,r14d; 0x72bfcb lea; 0x72bfcf shl | 0x72bfb2 test r14d,r14d / js; 0x72bfbb cmp r14d,[r15+0x28] / jg | test rax,rax at 0x72bfd8 |
| 7 | W | 6 | 0x72bf00 | 0x72c006 | mov rdi, qword ptr [rax + r13 + 0x20] | r13, 1 (pre) | as row 6 | as row 6 | as row 6 | cmp rdi,rax at 0x72c01b |
| 8 | W | 189 | 0x72c150 | 0x72c1dd | mov rdi, qword ptr [rax + r12 + 8] | r12, 1 (pre) | 0x72c1d5 lea r12,[r12+r12*2]; 0x72c1d9 shl r12,4 | 0x72c17c movsxd r12,[rsi]; 0x72c1d5 lea; 0x72c1d9 shl | 0x72c1d0 cmp r12d, dword ptr [rax] / jae | test rdi,rdi at 0x72c1e2, then refcount cmpxchg |
| 9 | W | 192 | 0x72c3e0 | 0x72c47b | mov rdi, qword ptr [rax + r13 + 8] | r13, 1 (pre) | 0x72c473 lea r13,[r15+r15*2]; 0x72c477 shl r13,4 | 0x72c43b movsxd r15,[r15]; 0x72c473 lea; 0x72c477 shl | 0x72c46e cmp r15d, dword ptr [rax] / jae | test rdi,rdi at 0x72c480 |
| 10 | W | 131 | 0x72e590 | 0x72e5fc | mov rdi, qword ptr [rax + r13 + 8] | r13, 1 (pre) | 0x72e5f4 lea r13,[rbx+rbx*2]; 0x72e5f8 shl r13,4 | 0x72e5c6 movsxd rbx,[rsi]; 0x72e5f4 lea; 0x72e5f8 shl | 0x72e5f0 cmp ebx, dword ptr [rax] / jae | test rdi,rdi at 0x72e601 |
| 11 | W | 603 | 0x72ecc0 | 0x72ed93 | mov rax, qword ptr [rcx + r12 + 8] | r12, 1 (pre) | 0x72ed8b lea r12,[r12+r12*2]; 0x72ed8f shl r12,4 | 0x72ed17 movsxd r12,[rbx+8]; 0x72ed8b lea; 0x72ed8f shl | 0x72ed1b test r12,r12 / js; 0x72ed82 cmp r12d,[rcx] / jge | test rax,rax at 0x72ed98 |
| 12 | W | 603 | 0x72ecc0 | 0x72ef1f | movzx eax, byte ptr [r12 + 0x28] | r12, 1 (pre) | 0x72ed8b lea; 0x72ed8f shl; 0x72eecb lea r12,[rax+r12+8] | 0x72ed17 movsxd r12,[rbx+8]; ...; 0x72eecb lea | index already checked at 0x72ed82 (row 11); +0x28 is a field of the checked entry | and al,0xfe at 0x72ef31; stored at 0x72ef33 |

Rows 2-5 and 8-10 are the same fd-table pattern: the array pointer lives at [object+0x48], the element count is the first dword of the array object, elements are 48 bytes with an 8-byte header, and the loaded qword is a refcounted file/descriptor pointer. Every one of them reloads the array after the cmpxchg and compares the entry pointer, which is the standard fget/refcount idiom. They are class W only because the bound is a variable; semantically they are correct.

Row 12 is the interesting one among the W rows. The load is at [r12+0x28] where r12 = array + index*48 + 8 (0x72eecb). The same pointer is the source of a 0x2c-byte memcpy at 0x72ef07 (`mov edx, 0x2c; mov rsi, r12; call 0x2590b0`). If the element stride really is 48 and the payload starts at +8, a 0x2c-byte copy from +8 ends 4 bytes past the element, so the last element of the array would be over-read by 4 bytes, and 0x72ef1f would read a byte at +0x30 relative to the element start. The stride is inferred from 0x72ed8b/0x72ed8f and the element layout is not recoverable from the retained image; this is recorded as an observation, not counted as a U site.

## C sites (bounded by an immediate)

| syscalls | body | insn | load | check |
|---|---|---|---|---|
| 649 | 0x34cfa0 | 0x34d025 | movsxd rax, dword ptr [rcx + rax*4] | 0x34d019 cmp eax,7 / ja (8-entry rel32 table) |
| 454 | 0x37ec40 | 0x37ec50 | mov rcx, qword ptr [rcx + rax*8] | 0x37ec43 cmp rax,0x1b / ja (28 pointer entries) |
| 165 | 0x47b030 | 0x47b16f | movsxd rax, dword ptr [rcx + rax*4] | 0x47b163 lea eax,[rdi-3]; cmp eax,8 / ja |
| 194 | 0x4a13e0 | 0x4a1420 | mov rdi, qword ptr [rcx + rdx] | 0x4a1404 cmp rbx,0xe / ja (15 entries x 16B) |
| 194 | 0x4a13e0 | 0x4a1424 | mov rcx, qword ptr [rcx + rdx + 8] | as above |
| 416 | 0x55d0c0 | 0x55d1e2 | mov rdx, qword ptr [r15 + rcx + 0x400] | 0x55d141/0x55d16a lea r9d,[r13-1]; cmp r9d,0x80 / jae (128 slots x 16B at proc+0x400) |
| 416 | 0x55d0c0 | 0x55d1ea | mov rcx, qword ptr [r15 + rcx + 0x408] | as above |
| 416 | 0x55d0c0 | 0x55d211 | mov r8d, dword ptr [r15 + rcx*4 + 0xc00] | as above; bit array at proc+0xc00, index r13>>5 |
| 416 | 0x55d0c0 | 0x55d274 | mov rax, qword ptr [r15 + rax*8] | as above |
| 416 | 0x55d0c0 | 0x55d3ad | mov rcx, qword ptr [r15 + rax*8] | entry check dominates; 0x55d3bb cmp r13d,0x1e is an unrelated special case |
| 416 | 0x55d0c0 | 0x55d47c | mov rcx, qword ptr [r15 + rax*8] | as above |
| 416 | 0x55d0c0 | 0x55d4d1 | mov eax, dword ptr [r15 + r13*4 + 0xc60] | as above; word index r13>>5 into proc+0xc60 |
| 567 | 0x6039d0 | 0x603bc8 | mov rax, qword ptr [rax + r13*8 + 0x190] | 0x6039f9 cmp r13,5 / ja (dominating, 0x1cf bytes earlier, outside the 90-insn window; 6 qwords) |
| 625 | 0x603c90 | 0x603cbe | movsxd rax, dword ptr [rcx + rax*4] | 0x603ca5 cmp eax,0x16 / ja |
| 626 | 0x604cf0 | 0x604e66 | movsxd rcx, dword ptr [rdx + rcx*4] | 0x604e51 cmp ecx,5 / ja |
| 234 | 0x6bc030 | 0x6bc06e | movsxd rdx, dword ptr [rax + rcx*4] | 0x6bc05d cmp rcx,0x15 / ja |
| 237 | 0x6bdfb0 | 0x6be065 | mov r13, qword ptr [rax + r13*8 + 0x20] | 0x6be03f cmp r13,3 / jl; 0x6be056 cmp r13d,0x20 / jne (32 entries of 8B) |
| 238 | 0x6be1d0 | 0x6be235 | mov r15, qword ptr [rax + r14*8 + 0x20] | 0x6be20f / 0x6be226, same shape |
| 239 | 0x6be370 | 0x6be3c1 | mov r13, qword ptr [rax + r12*8 + 0x20] | 0x6be3a3 / 0x6be3b6, same shape |
| 532 | 0xaf0040 | 0xaf02eb | movsxd rcx, dword ptr [rax + r15*4] | 0xaf02da cmp r14d,0x46 / ja (0x47 rel32 entries) |
| 532 | 0xaf0040 | 0xaf0363 | movsxd rcx, dword ptr [rax + r15*4] | 0xaf02fb cmp rcx,0x801 / jb; 0xaf030d cmp rcx,0x819 / jb |
| 532 | 0xaf0040 | 0xaf06d5 | mov rax, qword ptr [rdx + rax*8] | 0xaf06c0 cmp ecx,6 / ja (7 pointers); the pointer is bounded, its dereference is the U row |
| 601 | 0xca0630 | 0xca0676 | movsxd rdx, dword ptr [rcx + rax*4] | 0xca065a cmp rax,0x27 / ja (40 entries; table RVA 0x1a51160) |
| 622 | 0x9a9f40 | 0x9aa0cb | movsxd rax, dword ptr [rcx + rax*4] | 0x9aa0bb dec eax; cmp eax,4 / ja (5 rel32 entries) |

The 601 row matches the earlier handler audit (40-entry relative jump table, `cmp rax, 0x27`, default ENOSYS), which is an independent confirmation that the body resolution and the sweep reach the same code the manual audit did.

## Sites examined and dismissed

- 0x6be1d0 / 0x6be28a, `mov r12, qword ptr [rcx + rax*8 + 0x18]` (sys 238): the index rax comes from 0x6be1a0 `movsxd rax, dword ptr [r15 + 0xa8]`, a field of a kernel object, not of the uap. The value is CFI-checked (`sub`/`ror rax,3; cmp rax,0x3a5; ja`) and then called at 0x6be2b0. Classified N: over-taint from treating [rdi+8]-derived pointers as caller data.
- 0x4ee550 / 0x4eec09, `mov rdi, qword ptr [rax + rcx + 8]` (sys 209): present in an earlier boundary variant with no check, but the body ends at 0x4ee6xx (ret + padding, a separate function follows) and the block is not reachable from the handler. It disappears under the final boundary rule and is not counted. This is the exact false-positive mode the tail-jmp/padding rule exists to prevent.
- 0x55ed70 / 0x55f0cb (sys 341), `mov rax, qword ptr [rbx + rax*8]` with 0x55f0b8 `lea eax, [r14 - 1]; cdqe` and r14 = [uap]: no compare on r14 is visible in the body, but the block lies after a `ret` at 0x55eff1 and a `ud2` at 0x55eff7 that are crossed only because later code branches into the cold region, the base rbx is reloaded at 0x55f051 from [r12+0xa8], and two calls (0x55f086, 0x55f0b3) intervene that may validate the value. Per the boundary rule this is marked unknown, not U. It is the strongest remaining lead and the first thing a follow-up should resolve.
- 0x9a9f40 / 0x9aa0cb was initially flagged by copyin-destination taint; on review the index is decremented and compared against 4 before the table load, so it is C (listed above).
- 139 further load sites were not tainted by the nearest-def walk. A sample of 20 was checked by hand (bodies 0x3af900, 0x3b01f0, 0x6bccc0, 0x6e2dc0, 0x72bf00, 0x9a9f40, 0xcb1ab0) and their index registers trace to kernel fields (for example `movzx edx, byte ptr [r12]`, `mov rdx, qword ptr [rbx+0x30]`) or to loop counters the handler itself initialises.

## Method and limits

Body extraction. Bodies are resolved from the thunks, then decoded from body start to the next body start, capped at 0x8000 bytes. Decoding stops at a `ret`/`retn` when the following three bytes are 0x90/0xcc, and at `ud2` unconditionally, unless the next RVA is a direct branch target seen earlier in the body (cold blocks reached by jcc), in which case decoding continues. A `jmp` ends the body only when its target falls outside [start, next start); intra-body jumps are followed linearly. That last rule matters: body 0xcb1ab0 contains `jmp 0xffffffff8b671b58` at 0xcb1b51, which is RVA 0xcb1b58, seven bytes ahead inside the same function; stopping at every jmp truncated it to 42 instructions and cut the rest of the handler. Sensitivity: a looser rule (ret/padding only) finds 173 indexed loads, a tighter one (no cold-block continuation) finds 152; the final rule finds 164 explicit-index sites (plus the 12 pre-scaled forms = 176). The differences are all in the four largest bodies, and the U site is unaffected by the choice.

Detector. A load is any `mov`/`movzx`/`movsx`/`movsxd` whose source is a memory operand with an index register, plus the case where there is no index register but the base register is proved to be a pre-scaled index by its nearest definition (`lea rX,[rY+rY*2]`, `shl rX,4`, `imul rX,rX,S`). Scales seen in use: 1, 2, 4, 8 and 0x10 via the pre-scaled form. Indexed stores, cmp-form indexed reads and `nop word ptr cs:[rax+rax]` (112 instances) are not loads and are excluded.

Taint. Sources are the uap register rsi, every register assigned from rsi, and registers assigned from [rdi+8] (the object pointer the handlers load from the dispatch argument; treated as a source per the brief, which is why [proc+...] fields can surface as arg). Destinations of copyin calls (targets 0x259280 and 0x259240, resolved through `lea rsi,[rbp/rsp+disp]`) are added as user-data stack slots. The walk goes backwards over nearest definitions to depth 6, treats the destination of a read-modify-write instruction (add/sub/and/or/xor/shl/shr/sar/imul/inc/dec/neg/not) as an implicit source, and follows stack spill/reload pairs. Not following the RMW destination was a real bug in the first pass: `shl r12,4` followed by `lea r12,[r12+r12*2]` returned no taint and the pass reported 14 candidates instead of 36.

Checks. From the load, the 90 preceding instructions are scanned for `cmp`/`test` on the index register (or on any register appearing in the taint chain), with the jcc taken within the next three instructions. `and rX, imm` is also recorded. This window is a heuristic: the 567 row's check sits 0x1cf bytes (about 460 bytes) earlier and is outside it, which is why that row reads "checks=NONE" in the machine output and "C" in this document after manual review.

Consumer. Forward from the load, 50 instructions: a call to copyout/copyin/bzero/memcpy is named, a dereference, store, compare, arithmetic or overwrite through the loaded register is recorded, and a `ret` ends the walk.

False-positive modes:
1. Path-insensitive nearest-def taint. It follows the textually closest write, so a clamp on the other side of a branch hides the user value. The U site is exactly this: 0xaf0673 `mov edi, 2` sits closer to the load than 0xaf065e `mov edi, [rbp-0x850]`, so the automatic pass returned N and the site was found by reading the branch structure. Expect more of these in any body where a bounds clamp and an unchecked path converge.
2. Union-of-defs may-taint. A variant that unions all definitions (run_may.py) flags 137 of the 164 explicit-index loads, because reading a user buffer with a user index (`mov edi, [rsi + rdx*4 - 4]`) is indistinguishable from reading a kernel array out of bounds when the only question asked is "is any bit user-derived". It is useful for finding sites, useless for classifying them.
3. Over-taint from [rdi+8]. Because the dispatch object pointer is treated as caller data, kernel struct fields reached through it surface as tainted. One row (0x6be28a) is this artefact.
4. Table capacity is not in the image. All the RIP-relative table bases (0x37ec40's 28 pointers, 0xaf06cb's 7 pointers, 0xca0630's 0x1a51160) land outside the retained dump, so a C classification says "the immediate matches the entry count the code uses", not "the array really has that many entries". The exception is the 416 signal array, where the 128 x 16-byte slots at proc+0x400 end exactly where the bit arrays at proc+0xc00 begin.
5. Function-boundary leakage. A window can still include a following function that is reached by a fallthrough without padding, which is how 0x4eec09 produced a phantom row in an earlier pass. Cross-boundary blocks are marked unknown.
6. The index register is not always the checked register. 0x55d0c0 shows a `cmp r13d, 0x1e` that looks like a bound but is a special-case branch; the real check is the entry `cmp r9d, 0x80`. Every W and C row in this census was read by hand for that reason.

## Reproduce

Python: C:\Users\box12\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe (3.12.14, capstone 5.0.7).

- .local/il_census/resolve.py - thunk to body resolution, prints the 301 bodies and their sharing counts.
- .local/il_census/heads.py - prologue dump and prologue-pattern histogram used to calibrate the uap convention.
- .local/il_census/il_census3.py, il_census4.py, il_census5.py, il_census6.py - detector iterations; 6 is the boundary-rule predecessor of the final script.
- .local/il_census/il_census_final.py - the final detector plus the 37-row adjudication table; writes census_final.json and prints the class totals and the U/W table.
- .local/il_census/count_final3.py - independent counter for the universe (no adjudication table): 164 explicit-index loads, 12 pre-scaled, 35 + 1 tainted.
- .local/il_census/run_may.py - union-of-defs may-taint variant, writes allrows_may.json.
- .local/il_census/scan_c81.py - full-image sweep for displacement 0xc81 (69 accesses, 1 writer).
- .local/il_census/callers.py, callers2.py, callers3.py, callers4.py - caller/stub tracing for the gate writer.
- .local/il_census/ctx*.py - context dumps used for the manual adjudication of each U/W row.
- Outputs: rows.json (nearest-def rows), allrows.json (all 164 explicit-index loads), allrows_may.json, census_final.json.

Reproduce with: `python il_census_final.py` from .local/il_census. The script asserts that every tainted row is covered by the adjudication table and prints "unadjudicated 0" when the table is complete.

Capstone notes that cost time and are worth keeping: `md.detail = True` must be set after construction (the kwarg raises CS_ERR_DETAIL); branch immediates arrive as signed c_int64 and must be masked with 0xFFFFFFFFFFFFFFFF before comparing to the base, or every `jmp` target turns negative and a whole pass silently yields zero.

## Provenance

All findings are static, from the 13.60 image named above; no probe was run and no live target was touched. Syscall numbers are the 13.60 sysent numbers and the target firmware is 14.10, so numbering and code may differ. The image is a retained 13.60 dump whose acquisition authenticity the repository records as unresolved; treat the 532 finding as a strong static candidate for a 14.10 check, not as a 14.10 result.


## Resolution of the one unknown row (2026-11-05)

The 0x55f0cb row is closed as a linear-sweep artefact: the block belongs to the separate function
0x55f010, whose index argument is the return value of the id-table iterator 0x55c920 at both of its
call sites (0x55ef72 in body 0x55ed70, 0x4ea5ae in function 0x4ea300), not `[uap]`. The body's
`mov r14,[rsi]` at 0x55ed94 is dead by 0x55ef69. No absolute pointer to 0x55f010 exists in the image.
Detail and the instruction listings: `docs/SYS341_INDEXED_LOAD_CLOSURE_14_10.md`.
