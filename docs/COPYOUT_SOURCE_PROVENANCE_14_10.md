# Copyout source provenance in the 13.60 syscall handler set

Static census of every copyout() call site inside the distinct syscall handler
bodies of the retained 13.60 kernel image, asking whether any copyout source
pointer is derived from a user-supplied syscall argument. That shape, a kernel
copy from an address the caller chose into a buffer the caller can read, is an
arbitrary kernel read.

- Image: docs/dumps_13.60/kernel_text.bin, 0xE6E5C0 bytes, virtual base 0xffffffff8a9c0000, file offset == RVA
- Sysent table: docs/dumps_13.60/sysent_index.json (key entries, 679 records)
- copyout: RVA 0x2591d0, rdi = kernel source, rsi = user destination, rdx = length
- Date: 2026-11-05

## Verdict

Negative. No syscall handler in the retained 13.60 image calls copyout() with a
source pointer derived from a user-supplied syscall argument.

All 93 copyout call sites that lie inside the 300 distinct handler bodies
resolve to one of three origins: the handler's own stack frame (82 sites, every
one a `lea rdi,[rbp-X]` or a register fed by one, and every displacement
negative); a field of a kernel object or a fresh kernel allocation (10 sites,
each chain hand-verified down to an allocator return or a kernel-object load);
or a null source with a zero length (1 site, which cannot copy anything). The
class D count is 0.

The empty D list is a resolved result, not a walk that bailed. The same
resolver, run over the same 300 windows against copyin (0x259280), classifies
47 of its 60 source arguments as direct loads from the uap array, and at the
copyout sites themselves the destination argument resolves to a uap load at 35
of 93. Every one of the 93 source chains terminated in a concrete definition
(2 to 43 steps), no chain required arithmetic folding, no branch targets any of
the 93 call instructions, and no handler window contains an inlined stac. The
one automatic classification that stayed unresolved is a zero-length call with
a null source.

## 1. Question and classes

Class definitions, applied to the resolved origin of rdi at the copyout call:

| class | meaning |
|-------|---------|
| A | kernel global: `lea reg,[rip+X]` or an absolute address constant |
| B | the handler's own stack frame (`[rbp-X]`, `[rsp+X]`, or the saved uap block itself) |
| C | a field of a kernel object reached through a kernel pointer, or a kernel allocation |
| D | derived from a uap slot: the value originated in a load from `[rsi+off]` where rsi is the syscall argument array pointer |
| E | unresolved, or resolved to something that is not a usable pointer |

D is the class under test. E is not a finding and is reported separately.

## 2. Census arithmetic

- 679 sysent entries. 368 of them point at the shared/absent-slot target 0x5620e0 and are excluded. The remaining 311 syscalls resolve through their thunk rel32 to 300 distinct handler bodies. (The 301 figure in the task counts 0x5620e0 as a body.)
- 74 of the 300 bodies contain at least one copyout call: 93 sites. The other 226 bodies, covering 237 syscall numbers, contain no copyout call at all.
- Image-wide there are 539 direct E8 calls to 0x2591d0. 93 of them (17.3 percent) fall inside the walked handler windows; 446 are in ordinary kernel functions outside the handler set.
- The project figure of 616 call sites is accounted for by the three copyout-family entry points: 539 at 0x2591d0, 74 at 0x259900 and 3 at 0x2599f0. Only 0x2591d0 has the kernel-to-user direction; see Appendix B.
- Copy-family calls inside the 300 windows: copyout 93, copyin (0x259280) 60, copyinstr (0x259900) 23, bzero (0x258ff0) 41, memcpy (0x2590b0) 10. The page fast-copy variant 0x259100 and the string variant 0x2599f0 are called 0 times inside handler bodies.
- Window stop reasons: ret followed by 0x90/0xcc padding 222, tail jmp followed by padding 36, tail jmp outside the body range 23, indirect jmp 18, clipped at the next body start 1. Window length: min 8 bytes, median 259, max 9994.
- 17 stac instructions (0f 01 cb) exist image-wide; 0 of them lie inside a handler window. No handler performs an inlined SMAP copy.

## 3. Classification table

| class | automatic pass | after adjudication |
|-------|----------------|--------------------|
| A | 0 | 0 |
| B | 80 | 82 |
| C | 2 | 10 |
| D | 0 | **0** |
| E | 11 | 1 |
| total | 93 | 93 |

Automatic rdi kinds were: stkaddr 80, kobj 1, callret 1, const 1, unk 10. The
11 automatic E sites were each re-examined by hand; none of them moved into D.
Section 4 gives the chain for every one of them.

## 4. The eleven sites that did not classify automatically

Each entry gives body RVA, call-site RVA, the syscall number sharing the body,
and the instruction chain that fixes the origin. Addresses are RVAs; the full
listing is in Appendix A.

### 4.1 Class C, eight sites

1. 0x2a8de0 / 0x2a8e42, syscall 79. Automatic C.
   Chain: `002a8dee mov rcx,[rdi+0x140]` (a field of the thread structure),
   `002a8e0d mov rbx,[rcx+0x118]`, `002a8e39 mov rdi,rbx`. The length comes from
   `002a8e2c lea r15,[r12*4]` (count times 4); the destination is
   `002a8e09 mov r14,[rsi+8]` = uap[1]. Reading: the handler copies 4*N bytes
   out of a kernel object field into the caller's buffer. No user value reaches rdi.

2. 0x409790 / 0x409809, syscall 392. Automatic C.
   Chain: `004097d3 call 0xc08b50` (kernel allocator), `004097de mov r13,rax`,
   `00409800 mov rdi,r13`; length `00409806 mov rdx,r12` with
   `004097c9 shl r12,4`. Reading: copies a 16*N byte record from a fresh kernel
   allocation back to the caller.

3. 0x34b7b0 / 0x34b8e2, syscall 593. Automatic E, adjudicated C.
   Chain: `0034b7f9 mov rbx,[rsi+8]` (uap[1], destination),
   `0034b83f mov edi,0x160`, `0034b849 call 0xb2ac60`, `0034b85c mov r12,rax`,
   then on the success arm `0034b8d7 mov edx,0x160`, `0034b8dc mov rdi,r12`,
   `0034b8df mov rsi,rbx`, copyout. Reading: fills a 0x160-byte kernel record
   and copies it to the caller's buffer. The automatic pass stopped at the
   path boundary at 0x34b8bf.

4. 0x34bc60 / 0x34bd8e, syscall 660. Automatic E, adjudicated C.
   Chain: `0034bca9 mov rbx,[rsi+8]` (destination), `0034bcd0 call 0x8ac19280`
   (copyin of the user's 8-byte length into `[rbp-0x38]`),
   `0034bce0 cmp qword [rbp-0x38],0x160`, `0034bcf9 call 0xb2ac60`,
   `0034bd09 mov r15,rax`, fill via 0x34b950, then `0034bd83 mov edx,0x160`,
   `0034bd88 mov rdi,r15`, copyout. The source is the allocation.

5. 0x34bdc0 / 0x34c25d, syscall 608. Automatic E, adjudicated C.
   Chain: `0034be0c mov r14,[rsi+0x10]` loads arg3, a user pointer;
   `0034be33 mov rdi,r14` with `0034be36 call 0x8ac19280` copies from it, then
   `0034be67 mov [rbp-0x50],r14` saves that pointer, `0034be6b call 0xb2ac60`
   allocates 0x1a8 bytes and `0034be74 mov r14,rax` overwrites r14 with the
   allocation. At the call: `0034c251 mov rsi,[rbp-0x50]` (the saved user
   pointer, destination), `0034c25a mov rdi,r14` (the allocation, source),
   `0034c25d call copyout`, length 0x1a8. Reading: copies a 0x1a8-byte kernel
   structure to the user pointer in arg3. The automatic pass reported E because
   the reload of r14 sits after the path boundary at 0x34c1d0.

6. 0x34c350 / 0x34c647, syscall 656. Automatic E, adjudicated C.
   Chain: `0034c377 mov rbx,[rsi+8]` (destination), copyin at `0034c3d6`,
   size check `0034c3ea cmp qword [rbp-0x38],0x160`, `0034c407 call 0xb2ac60`,
   `0034c410 mov r15,rax`, then `0034c63c mov edx,0x160`, `0034c641 mov rdi,r15`,
   copyout. Source is the allocation.

7. 0x533030 / 0x5330d5, syscall 32. Automatic E (out-parameter slot), adjudicated C.
   Chain: `0053304b mov rbx,rsi` (uap), `00533090 lea rcx,[rbp-0x3c]`,
   `00533096 call 0x532e60` which fills `[rbp-0x3c]` with the address length and
   `[rbp-0x38]` with a kernel sockaddr pointer; then
   `005330a8 mov r15,[rbp-0x38]`, `005330a4 mov r14d,[rbp-0x3c]`,
   `005330cc mov rdi,r15`, destination `005330b1 mov r12,[rbx+8]` = uap[1],
   length r14. Reading: returns a getsockname/getpeername result.

8. 0x533310 / 0x5333b5, syscall 31. Automatic E, adjudicated C.
   Same shape as site 7 with the sibling filler 0x533160.

Two more C sites were classified automatically and need no correction: the
sites at 0x2a8de0 and 0x409790 above.

### 4.2 Class B, two sites

9. 0x5328d0 / 0x5329b2, syscall 29. Automatic E, adjudicated B.
   Chain: `005328eb lea rbx,[rbp-0x58]` (the source), `0053293e mov dword [rbp-0x58],0`;
   at the call `005329ac mov rdi,rbx`, destination `00532932 mov r15,[r14+0x28]`
   (r14 is the uap block), length 4. Reading: reads 4 bytes from the user
   (copyin at 0x532925), then writes a 4-byte stack value back. The automatic
   pass lost the def behind the jump over the error path.

10. 0xabb980 / 0xabbaff, syscall 674. Automatic E, adjudicated B.
    Chain: `00abba4f lea r15,[rbp-0x78]` (the source buffer),
    `00abbaeb mov rdi,r15`, `00abbaf5 mov rdx,[rbp-0x108]` (length clamped to
    0x48 at 0xabba53/0xabba65), destination `00abbaee mov r15,[rbp-0xd8]`.
    Reading: returns one 0x48-byte VM map record from a stack buffer.

### 4.3 Class E, one site

11. 0x4f7370 / 0x4f757f, syscall 604.
    Chain: `004f7549 xor r12d,r12d`, `004f755c xor r13d,r13d`,
    `004f7576 mov rdi,r12`, `004f757c mov rdx,r13`, then copyout. The call is
    copyout(NULL, dest, 0). With a zero length, copyout returns at its
    `test rdx,rdx; je` before touching any address. There is no source to
    classify; the site cannot read anything. The same body has two other
    copyout calls, 0x4f74c2 and 0x4f75af, both of which take `lea rdi,[rbp-0x34]`
    and are class B.

## 5. Why the empty D list is a resolved result

Six independent checks, all reproducible with the scripts in section 7:

1. Positive control. The same resolver over the same 300 windows, targeting
   copyin at 0x259280 instead of copyout, finds 60 call sites and classifies 47
   of their source arguments as uapval (78 percent), 13 unknown. Copyin's source
   is the user pointer, so a resolver that could not see uap loads would fail
   this control. It does not.
2. The resolver sees uap loads at the copyout sites themselves: rsi, the
   destination argument, resolves to a uap value at 35 of the 93 sites (for
   example `002a8e09 mov r14,[rsi+8]` at site 1 above). The uap array is
   therefore being tracked correctly at these very call sites.
3. All 93 rdi chains terminate in a concrete definition. Trace length is 2 to
   43 steps (median 2); the hop limit is 6 and the step budget 60000, and
   neither was reached at any site. Of the 82 class B sites, 67 define rdi with
   a direct \`lea rdi,[rbp-X]\` and the other 15 with \`mov rdi,reg\` where that
   register was itself set by \`lea reg,[rbp-X]\`; no B source is an rsp-relative
   address and no displacement is positive. 15 sites have their defining instruction
   more than 8 instructions before the call; the audit pass re-checked each.
4. No rdi chain contains arithmetic that would need value folding: no add, sub,
   imul, or, and, shl or non-self xor reaches rdi in any of the 93 traces. The
   only arithmetic in a source chain is `lea` of a stack address. The
   resolver's lack of arithmetic evaluation therefore never mattered.
5. No shared-tail entry. A scan for any direct jmp/jcc target equal to one of
   the 93 copyout call instructions returns 0, so the linear predecessor that
   the backward walk follows is the only path into each call.
6. No inlined copy path. stac appears 17 times in the image and never inside a
   handler window, so every user copy in a handler goes through a call to one
   of the copy helpers, and all of those calls were enumerated: the walk finds
   every raw E8-to-0x2591d0 byte inside its windows (93 of 93, no misses).

The sibling sweep does not change the answer. 0x259900 is a copyin-direction
string copy, not a copyout: it exchanges rdi and rsi at 0x259930 and applies
the 0x7fffffffffff mask to rsi after the exchange (0x259979), so arg1 is the
user source. Its 23 in-body sites show the intended shape, for example
0x2ab7a0 / 0x2ab802 syscall 50: `lea rsi,[rbp-0x50]; mov edx,0x21; mov rdi,r14`
with r14 loaded from the uap array, `xor ecx,ecx; call 0x259900`, that is
copyinstr(user_string, stack_buffer, 0x21, NULL). The 13 uap-derived arguments
the slice reports for it are the user-source convention of a copyin, not an
arbitrary read. 0x2599f0 and 0x259100 have no call sites inside handler bodies.

## 6. Method and limits

### 6.1 Heuristics used

H1. Body resolution. For each sysent entry, the thunk at sy_call_off is read as
E8 rel32 and the body is sy_call_off + 5 + signed rel32. Entries are grouped by
body; 0x5620e0 is dropped.

H2. Window rule. A body is walked from its start until (a) a ret or ud2 or int3
followed by 0x90/0xcc padding, (b) a tail jmp whose target is outside
[start, start+0x20000], is followed by padding, or lands on another known body
start, or (c) an indirect jmp, or (d) the next body start, whichever comes
first. A window never spans two bodies.

H3. Backward def-use. At each call, the last instruction that writes rdi is
located and followed: registers by name, memory by base register, stack slots
keyed by rbp/rsp displacement with the rsp delta accumulated over push, pop and
sub/add rsp. Hop limit 6, step budget 60000.

H4. Call modelling. Capstone does not report the implicit rax write of a call.
The scan therefore treats rax as the call's return value and any other
caller-saved register as clobbered. Without this rule a call was silently
skipped and an earlier instruction misread as the definition; that produced a
false D at 0x8fbbe0 before the fix.

H5. Store detection. A memory operand counts as a store only when it is operand
0 of a store-capable mnemonic. Treating every memory operand as a store made
reads look like definitions.

H6. Path-boundary guard. The walk stops with unk(path-boundary:...) at ret, jmp,
ud2, int3, hlt and iret instead of scanning across the boundary. This favours E
over a wrong classification. It cost destination resolution at 57 sites (they
report unk) and produced the 11 E sites of section 4, of which 10 were resolved
by hand.

H7. Class mapping. A for lea rip-relative and absolute constants, B for rbp/rsp
addresses, C for object-field loads and call returns, D for loads from the uap
array or addresses computed from one, E otherwise.

### 6.2 What would make a D site a false positive

- Path merge. The backward walk follows the single linear predecessor. If a
  register holds a uap-derived pointer on one arm of a branch and a kernel
  value on the arm that actually reaches the copyout, a classifier without path
  sensitivity can report D wrongly. The path-boundary guard makes the opposite
  error (E) more likely, but it cannot prove a merge is safe.
- Implicit writes. String operations advance rdi/rsi, mul/idiv write rdx:rax,
  cpuid, xchg, push/pop, cmov and movsxd all write registers without an
  ordinary mov. A scan that does not model them attributes a stale uap value to
  rdi. The script models mov, lea, add, sub, xor, pop and the call return, and
  the four remaining unk chains were inspected by hand.
- Stack-slot aliasing after an rsp change the walk does not track (a dynamic
  sub rsp, or an unbalanced push/pop) could bind a slot to the wrong store.
- A register value that was stored into a kernel object and reloaded later is
  classified by the object field, not by the original value, so this produces an
  under-report (false negative) rather than a false positive. The converse, a
  kernel object field overwritten with a user-chosen pointer and then used as a
  copyout source, would be a genuine D.
- A callee-filled out-parameter slot is invisible to a backward walk (it saw no
  store) and yields E; sites 7 and 8 in section 4 are that case and were
  resolved by reading the callee.

### 6.3 Coverage limits

- Bodies are not contiguous. Three of the 74 copyout-bearing windows stop
  before their next body start: 0x6bb670 and 0x7dcd40 at an indirect jmp (a
  switch dispatch), and 0x531720 at an out-of-range tail jmp. Code beyond those
  boundaries is not attributed to the handler. The copyout calls that sit in
  those gaps (0x6bc0dc after 0x6bb725, 0x53265c after 0x531b22) were checked by
  hand: both take a stack source (`lea rdi,[rbp-0x28]`) or a kernel object
  field (`mov rdi,[r15+0x10]`), neither is uap-derived.
- Jump-table case blocks are the main residual blind spot in the image. 446 of
  the 539 image-wide copyout sites lie outside the 300 windows; 21 of them are
  within 0x2000 bytes after a window that ended at an indirect jmp, and 137
  have an indirect jmp within the preceding 0x800 bytes.
- No interprocedural closure. The census enumerates copyout calls lexically
  inside handler windows. A handler that calls a kernel function which then
  calls copyout is covered only where the chain itself was adjudicated (the
  helpers named in section 4: 0xc08b50, 0xb2ac60, 0x532e60, 0x533160, 0x34b950,
  0x8b2bbe70). The complementary interprocedural audit of 39 sites is recorded
  in docs/INTERPROC_COPYOUT_SOURCES.md and found no user-derived source.
- The absent-slot target 0x5620e0 is excluded by instruction (368 syscalls).
  It is a stub, not a handler, so it cannot be a read primitive.
- The image is 13.60, not 14.10. Any claim about 14.10 from this census is an
  inference by code shape, not an observation.

## 7. Reproducing this census

Python 3.11.9 with capstone 5.0.7. Run from C:\PS5contrib. All scripts and
outputs are in .local/.

| script | purpose | output |
|--------|---------|--------|
| .local/copyout_source_slice.py | main census, default target copyout 0x2591d0 | .local/copyout_source_slice.txt, .local/copyout_source_slice.json |
| .local/copyout_source_slice.py 0x259280 | copyin positive control | .local/copyout_source_slice_259280.txt/.json |
| .local/copyout_source_slice.py 0x259900 | copyinstr sibling sweep | .local/copyout_source_slice_259900.txt/.json |
| .local/copyout_source_slice.py 0x2599f0 | string variant sweep | .local/copyout_source_slice_2599f0.txt/.json |
| .local/copyout_source_audit.py | multi-entry, distance and provenance audit of the 93 sites | .local/copyout_source_audit.txt |
| .local/copyout_coverage.py | helper counts, stac, window stops and lengths | stdout |
| .local/_emit_rows.py, .local/_final_rows.py | appendix rows and manual adjudication overlay | .local/appendix_rows.txt |
| .local/_verify_walk.py | raw-byte cross-check that the walk finds 93 of 93 sites | stdout |
| .local/_patch1.py .. .local/_patch4.py | patches applied to the slicer during development | in place |

Rebuild order: slice, audit, coverage, verify, rows. The census takes about one
minute per run.

## Appendix A. Every copyout call site inside a handler body

93 sites. Columns: body RVA, call-site RVA, syscall number(s) sharing the body,
final class, resolved source origin, and the distance in instructions from the
call back to the defining instruction. Automatic classifications are shown after
the manual adjudication of section 4.

| body | call | sys | class | rdi origin | dist |
|------|------|-----|-------|------------|-------|
| 0x2ab690 | 0x2ab76d | 49 | B | &stk[-96] | 2 |
| 0x331100 | 0x331248 | 140 | B | &stk[-72] | 2 |
| 0x34ae90 | 0x34b2c9 | 591 | B | &stk[-2616] | 2 |
| 0x34c990 | 0x34ca11 | 598 | B | &stk[-40] | 2 |
| 0x34c990 | 0x34ca44 | 598 | B | &stk[-48] | 2 |
| 0x34ce50 | 0x34cf7e | 612 | B | &stk[-48] | 2 |
| 0x438c90 | 0x438d40 | 616 | B | &stk[-80] | 23 |
| 0x439150 | 0x439308 | 634 | B | &stk[-1328] | 27 |
| 0x4a0400 | 0x4a0523 | 466 | B | &stk[-52] | 2 |
| 0x4a0400 | 0x4a0642 | 466 | B | &stk[-52] | 2 |
| 0x4a13e0 | 0x4a1490 | 194 | B | &stk[-56] | 2 |
| 0x4a1ba0 | 0x4a1d01 | 117 | B | &stk[-192] | 2 |
| 0x4a2de0 | 0x4a30ba | 641 | B | &stk[-104] | 2 |
| 0x4a2de0 | 0x4a316a | 641 | B | &stk[-104] | 2 |
| 0x4e1a70 | 0x4e1bca | 587 | B | &stk[-176] | 2 |
| 0x4f7370 | 0x4f74c2 | 604 | B | &stk[-52] | 1 |
| 0x4f7370 | 0x4f75af | 604 | B | &stk[-52] | 1 |
| 0x531720 | 0x531a56 | 135 | B | &stk[-56] | 2 |
| 0x5329e0 | 0x532aad | 27 | B | &stk[-88] | 2 |
| 0x532cd0 | 0x532e32 | 118 | B | &stk[-108] | 2 |
| 0x533030 | 0x53312d | 32 | B | &stk[-60] | 2 |
| 0x533310 | 0x53340d | 31 | B | &stk[-60] | 2 |
| 0x5581e0 | 0x55859a | 202 | B | &stk[-248] | 2 |
| 0x55d0c0 | 0x55d57a | 416 | B | &stk[-112] | 2 |
| 0x55ddc0 | 0x55de76 | 340 | B | &stk[-80] | 2 |
| 0x55deb0 | 0x55dfab | 429 | B | &stk[-136] | 4 |
| 0x55e550 | 0x55e63c | 345 | B | &stk[-160] | 4 |
| 0x55e680 | 0x55e72f | 346 | B | &stk[-136] | 4 |
| 0x55ec90 | 0x55ed41 | 343 | B | &stk[-64] | 2 |
| 0x55f400 | 0x55f510 | 53 | B | &stk[-88] | 2 |
| 0x5a3b50 | 0x5a3c32 | 328 | B | &stk[-52] | 2 |
| 0x5a3f50 | 0x5a4032 | 334 | B | &stk[-64] | 2 |
| 0x6039d0 | 0x603c1c | 567 | B | &stk[-56] | 2 |
| 0x6bb670 | 0x6bb6c2 | 232 | B | &stk[-40] | 2 |
| 0x6bc4e0 | 0x6bc7b8 | 240 | B | &stk[-112] | 2 |
| 0x6bc800 | 0x6bc858 | 116 | B | &stk[-56] | 10 |
| 0x6bc800 | 0x6bc8a9 | 116 | B | &stk[-64] | 2 |
| 0x6bca20 | 0x6bca72 | 86 | B | &stk[-56] | 2 |
| 0x6bccc0 | 0x6bcdc2 | 83 | B | &stk[-96] | 2 |
| 0x6bd570 | 0x6bdd66 | 235 | B | &stk[-132] | 2 |
| 0x6bdfb0 | 0x6be19c | 237 | B | &stk[-112] | 2 |
| 0x6be1d0 | 0x6be30e | 238 | B | &stk[-80] | 2 |
| 0x6be5c0 | 0x6be767 | 638 | B | &stk[-56] | 2 |
| 0x6be5c0 | 0x6be79c | 638 | B | &stk[-48] | 2 |
| 0x6be5c0 | 0x6be7d1 | 638 | B | &stk[-60] | 2 |
| 0x6be800 | 0x6bea83 | 639 | B | &stk[-56] | 2 |
| 0x6be800 | 0x6beab8 | 639 | B | &stk[-48] | 2 |
| 0x6be800 | 0x6beaed | 639 | B | &stk[-60] | 2 |
| 0x72c150 | 0x72c362 | 189 | B | &stk[-184] | 2 |
| 0x7dcd40 | 0x7dcdb2 | 622 | B | &stk[-116] | 1 |
| 0x8340e0 | 0x8342d9 | 393 | B | &stk[-128] | 2 |
| 0x83d830 | 0x83d97b | 486 | B | &stk[-68] | 2 |
| 0x8d25a0 | 0x8d260b | 623 | B | &stk[-28] | 2 |
| 0x8f6120 | 0x8f6424 | 397 | B | &stk[-1008] | 15 |
| 0x8f8e20 | 0x8f8e8e | 188 | B | &stk[-144] | 2 |
| 0x8f9260 | 0x8f92e7 | 190 | B | &stk[-152] | 2 |
| 0x8fbbe0 | 0x8fbd8d | 196 | B | &stk[-80] | 2 |
| 0xa368e0 | 0xa36a5a | 602 | B | &stk[-560] | 2 |
| 0xa368e0 | 0xa36a9d | 602 | B | &stk[-560] | 2 |
| 0xaba540 | 0xaba6dd | 547 | B | &stk[-144] | 2 |
| 0xabac50 | 0xabb173 | 572 | B | &stk[-120] | 2 |
| 0xabb980 | 0xabbcd6 | 674 | B | &stk[-120] | 1 |
| 0xabc710 | 0xabc9f1 | 607 | B | &stk[-416] | 2 |
| 0xabca10 | 0xabcb7c | 613 | B | &stk[-64] | 2 |
| 0xabca10 | 0xabcbac | 613 | B | &stk[-56] | 2 |
| 0xabcc00 | 0xabcc5d | 615 | B | &stk[-208] | 2 |
| 0xabcc00 | 0xabcc93 | 615 | B | &stk[-200] | 4 |
| 0xabe1c0 | 0xabe22a | 646 | B | &stk[-1048] | 11 |
| 0xbafe50 | 0xbaff6e | 542 | B | &stk[-56] | 15 |
| 0xbb0030 | 0xbb00fb | 543 | B | &stk[-48] | 14 |
| 0xbb0280 | 0xbb0300 | 546 | B | &stk[-36] | 2 |
| 0xbe8290 | 0xbe83eb | 7 | B | &stk[-484] | 2 |
| 0xbe8290 | 0xbe843d | 7 | B | &stk[-480] | 2 |
| 0xbe9510 | 0xbe9893 | 652 | B | &stk[-52] | 2 |
| 0xbe9510 | 0xbe9a0e | 652 | B | &stk[-52] | 2 |
| 0xc163d0 | 0xc164a9 | 553 | B | &stk[-52] | 2 |
| 0xc16660 | 0xc166ed | 556 | B | &stk[-44] | 2 |
| 0xc37860 | 0xc37934 | 421 | B | &stk[-1328] | 37 |
| 0xc37a20 | 0xc37b03 | 423 | B | &stk[-1328] | 36 |
| 0xc434c0 | 0xc435d4 | 407 | B | &stk[-72] | 2 |
| 0x2a8de0 | 0x2a8e42 | 79 | C | kobj(kobj:td field) | 19 |
| 0x409790 | 0x409809 | 392 | C | ret(call@4097d3 -> ret of 0xc08b50) | 12 |
| 0x34b7b0 | 0x34b8e2 | 593 | C | kalloc 0xb2ac60 buffer | 1 |
| 0x34bc60 | 0x34bd8e | 660 | C | kalloc 0xb2ac60 buffer | 1 |
| 0x34bdc0 | 0x34c25d | 608 | C | kalloc 0xb2ac60 buffer | 0 |
| 0x34c350 | 0x34c647 | 656 | C | kalloc 0xb2ac60 buffer | 1 |
| 0x4ecf40 | 0x4ed0f5 | 54 | C | malloc/stack/uap+0x10 buffer | 26 |
| 0x4f7370 | 0x4f757f | 604 | E | null + zero length | 12 |
| 0x5328d0 | 0x5329b2 | 29 | B | &stk[-0x58] | 1 |
| 0x533030 | 0x5330d5 | 32 | C | sockaddr filled by 0x532e60 | 10 |
| 0x533310 | 0x5333b5 | 31 | C | sockaddr filled by 0x533160 | 10 |
| 0x8fbbe0 | 0x8fbd37 | 196 | C | malloc 0xc08b50 (0x10000) | 2 |
| 0xabb980 | 0xabbaff | 674 | B | &stk[-0x78] | 3 |

## Appendix B. How the copy helpers were identified

- 0x2591d0 (copyout). Prologue: push rbp; mov rbp,rsp; mov rax,gs:[0x20];
  installs a handler at [rax+0x108]; test rdx,rdx; je return; range checks on
  rsi+rdx against rsp and 0x800000000000; reads gs:[0] and tests a byte at
  +0x591; movabs rax,0x7fffffffffff; and rsi,rax; xchg rdi,rsi; stac; rep movsq;
  clac. The exchange is what fixes the direction: rdi is the kernel source and
  rsi the user destination, matching the task's stated signature. 539 direct
  callers image-wide.
- 0x259280 (copyin). 179 bytes later, checks rdi+rdx, masks rdi, exchanges, so
  arg1 is the user source. 432 direct callers, 47 of 60 in-body sources
  uap-derived, which is the control used in section 5.
- 0x259900 (copyinstr). Exchanges rdi/rsi at 0x259930, masks rsi after the
  exchange at 0x259979, lodsb/stosb loop with stac/clac, NUL termination. 74
  direct callers image-wide, 23 inside handler windows.
- 0x2599f0 (string variant). NUL-terminated loop, no SMAP bracket. 3 callers
  image-wide, 0 inside handler bodies.
- 0x2590b0 (bare memcpy). 3384 callers; kernel-to-kernel, no SMAP bracket.
- 0x258ff0 (bzero) and 0x259100 (0x4000-byte page fast copy with prefetchnta and
  movnti). Neither is used with a user source inside a handler window.
