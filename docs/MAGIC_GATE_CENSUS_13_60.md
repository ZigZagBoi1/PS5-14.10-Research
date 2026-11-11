# MAGIC GATE CENSUS - 13.60 kernel text

Status: static-only census, no console, no dynamic validation.
Scope image: docs/dumps_13.60/kernel_text.bin, 15,132,096 bytes, base 0xffffffff8a9c0000,
file offset == RVA (RVA = VA - base). All addresses below are RVAs unless written as
0x8xxxxxxx (low 32 bits of the VA), which is the convention the 674 note already uses.

Subject class: a compare of a 32-bit value against an immediate that is a *magic number*
rather than a length, count, mask or errno, where the compare gates a path that a caller
cannot reach while passing zeros. The calibration case is Sony syscall 674
(virtual_query_all): 0xabb9d3  cmp dword ptr [r14 + 0x20], 0x40000000 / je body / jmp EINVAL,
with r14 loaded from rsi (the uap) eight instructions earlier. With uap->field_0x20 == 0 the
syscall returns EINVAL(22) and every probe that passed a zeroed argument block measured a
dead syscall.

---

## 1. Method, and why it discriminates

Four passes, each written to a JSON intermediate so the numbers can be re-derived:

1. Function-start census (tools/_mg_gcall.py -> docs/_mg_starts.json).
   24,042 sites matching 55 48 89 e5 (push rbp; mov rbp,rsp) with the preceding byte in
   {c3, cc, 90, 5d, 00, e9, eb}, plus 5,838 int3-padded 16-byte-aligned starts, plus the 301
   distinct sysent bodies resolved from docs/dumps_13.60/sysent_index.json -> 29,890 starts.
   Validation: of 203,136 e8 rel32 call sites, 167,234 (82.3%) land exactly on a start.

2. Per-function linear sweep (tools/_mg_funcsweep.py -> docs/_mg_func_hits.json).
   For every start, decode [start, min(next_start, start+0x2000)) with capstone and keep every
   cmp whose second operand is an immediate >= 0x1000 over a 4-byte memory or 4-byte register
   operand. Result: 8,938 sites in 3,324 distinct functions. Decoding per function instead of
   per 16 KB chunk matters: the 674 gate sits 0x13 bytes past a branch table, and a chunked
   sweep desynchronises there and loses it. Per-function decoding recovers both 674 sites
   (0xabb9d3, 0xabb9ed) and every other site this census reports.

3. Argument derivation, "taint-lite" (tools/_mg_taint.py -> docs/_mg_taint.json).
   At function entry rdi..r9 are level 1. mov reg,reg and lea reg,[reg+disp] copy the level;
   mov reg,[reg+disp] increments it; every call clears the caller-saved set; any other write
   to a register clears that register. At each cmp the level of the compared base register is
   recorded. Level 1-2 means the compared dword is either the argument pointer itself or a
   field one load away - i.e. userland picks the value. This is the property that separates a
   674-class gate from a comparison of a kernel object constant: 674 scores level 1
   (mov r14, rsi at 0xabb9a3, cmp [r14+0x20]); 1,142 sites image-wide are level 1, 756 level 2.

4. Guard shape (tools/_mg_cls.py -> docs/_mg_cls.json).
   If the instruction after the cmp is a conditional branch, both sides are walked for up to
   0x60 bytes / 28 instructions, following one forward jmp. A side that ends in ret or reaches
   an epilogue while the other side issues calls is labelled GATE; a side that returns a
   lea rax,[rip+X] pointer is labelled LOOKUP; two sides that converge in under four
   instructions are labelled CLAMP. 1,247 sites are GATE, 51 CLAMP, 1,483 have no conditional
   branch at all, 6,157 do not fit the shape test (this bucket still contains real gates - all
   three state gates in section 3C/D land here because their bail block is further than 0x60
   bytes away - so the class column is triage, not ground truth).

Why the intersection discriminates: a magic compare only matters if (a) the constant is not a
size or a mask, (b) the compared value comes from the caller within two loads, and (c) the
failing side terminates while the passing side does work. All three together is exactly
"argument-gated, unreachable with zeroed arguments". Sizes and masks are the bulk of the
8,938 hits and are removed explicitly:

    8,938  cmp r/m32, imm32 >= 0x1000 (3,324 functions)
    3,284  sentinel: -1, -errno range 0xffff0000..0xffffffff, INT_MAX, 0x80000000
      548  contiguous bit-mask class (0xff, 0xffff, 0xff000000, 0x7fff, ...)
      232  float literal class (0x3f800000, 0xbf800000, 0x3f000000, 0x40800000, 0x7ff00000)
    1,247  GATE shape
      264  GATE and argument-derived level <= 2
       27  ... and reachable within 3 direct calls of a sysent body
       16  ... and imm >= 0x10000, non-power-of-two, non-mask, non-float

Reachability (tools/_mg_gcall.py + tools/_mg_rank.py): 100,013 function-to-function edges
across 18,626 callers, BFS depth <= 6 from the 301 sysent bodies reaches 2,466 functions
(590 at depth 1). That is only 8.2% of the start set, so "not reachable" below means "no direct
call edge found", never "unreachable in the running kernel".

---

## 2. Census table - top 25 gates

Class: GATE = guard shape plus argument derivation verified by hand or by the classifier;
STATE = guard on a field of a kernel object (same shape, needs another syscall to set it);
DISPATCH = one of N magics selecting one of N handlers (the 674 family writ large);
UNVERIFIED = automatic classification only, no hand read of the guarded block.
reach = syscall numbers that reach the enclosing function over the direct call graph
(depth in parentheses); "indirect" = no direct edge found.

| # | site RVA | VA (low 32) | imm | func RVA | class | guarded path | reach |
|---|----------|-------------|-----|----------|-------|--------------|-------|
| 1 | 0x00ae7028 | 0x8b4a7028 | 0x7802c500 | 0x00ae6f90 | GATE | cmd==0x7802c500 special-case inside a service RPC wrapper; other cmds skip it | sys 532 (1) |
| 2 | 0x00a36b23 | 0x8b3f6b23 | 0x780263ff | 0x00a36b00 | DISPATCH | first of five accepted cmd words; default is EINVAL 0x16 | sys 605 (0) |
| 3 | 0x00c9c4a6 | 0x8b65c4a6 | 0xa002c315 | 0x00c9c410 | DISPATCH | Sony status-code switch (0xa002xxxx window), picks recovery path | sys 341,431 (3) |
| 4 | 0x00abb9ed | 0x8b47b9ed | 0x40000000 | 0x00abb980 | GATE | CALIBRATION - 674: uap->0x20 must equal 0x40000000 or EINVAL | sys 674 (0) |
| 5 | 0x005f9f5b | 0x8afb9f5b | 0x10000000 | 0x005f9650 | GATE | argument-derived compare, work side calls 0x54a440 | sys 12,56,59 (2) |
| 6 | 0x002b1e21 | 0x8ac71e21 | 0x052b5120 | 0x002b1de0 | GATE | argument-derived r14d against 0x52b5120 (siblings 0x52b5110 at 0x2b1e2a, 0x52b5100 at 0x2b1e33) then calls 0x2aeb60/0x2af040 | indirect |
| 7 | 0x007b03e0 | 0x8b1703e0 | 0x00020000 | 0x007b0300 | GATE | argument-derived compare vs 0x20000, work side calls 0x4c7190 | sys 59 (2) |
| 8 | 0x0073b343 | 0x8b0fb343 | 0x00100000 | 0x0073b310 | GATE | 1 MB cap on an argument-derived value before 0xc08b50 | sys 622 (1) |
| 9 | 0x00c02a34 | 0x8b5c2a34 | 0x00100000 | 0x00c02a00 | GATE | same 1 MB cap before 0xc08b50, second site in the same worker family | sys 622 (1) |
| 10 | 0x0060eb3e | 0x8afceb3e | 0x00008001 | 0x0060ea90 | GATE | equality split on 0x8001 before 0x4c6fa0 | sys 622 (3) |
| 11 | 0x00313046 | 0x8acd3046 | 0x10000000 | 0x00312ed0 | STATE | [obj+0x5d8] >= 0x10000000 before a code whitelist {0,0x10000,0x10100,0x10200,0x10300} | sys 362 (0) |
| 12 | 0x003133be | 0x8acd33be | 0x10000000 | 0x00313160 | STATE | same field and threshold, second syscall body | sys 141 (0) |
| 13 | 0x00aba5e7 | 0x8b47a5e7 | 0x06000000 | 0x00aba540 | STATE | [obj+0x5d8] >= 0x60000000 before call 0xaba710 (real worker) | sys 547 (0) |
| 14 | 0x00a0b467 | 0x8b3cb467 | 0xa0020328 | 0x00a0b2c0 | UNVERIFIED | dword at [rax+0x36c] vs Sony status code 0xa0020328 | sys 1 (1) |
| 15 | 0x00aed25a | 0x8b4ad25a | 0x780287ff | 0x00aecd70 | DISPATCH | upper bound of the 0x7802xxxx command window in the service dispatcher | sys 532 (2) |
| 16 | 0x00aed36c | 0x8b4ad36c | 0x7802b200 | 0x00aecd70 | DISPATCH | one command word in the same dispatcher (six in this 2.5 KB slice) | sys 532 (2) |
| 17 | 0x009ebca2 | 0x8b3abca2 | 0x40000000 | 0x009eb210 | UNVERIFIED | cmp ecx,0x40000000 (same constant as 674, different consumer) | sys 37,652 (2) |
| 18 | 0x008eeef1 | 0x8b2aeef1 | 0x10000000 | 0x008ee780 | UNVERIFIED | cmp r10d,0x10000000 | sys 654,673 (2) |
| 19 | 0x008ee67d | 0x8b2ae67d | 0x10000000 | 0x008ee310 | UNVERIFIED | cmp ecx,0x10000000 in the same subsystem | sys 74,548 (3) |
| 20 | 0x009ed1e6 | 0x8b3ad1e6 | 0x10000000 | 0x009ed000 | UNVERIFIED | cmp r9d,0x10000000 | sys 74,548 (3) |
| 21 | 0x003b3bf4 | 0x8ad73bf4 | 0x11090000 | 0x003b3a90 | UNVERIFIED | dword at [rcx+0x5d4] vs 0x11090000 (note: 0x5d4, not 0x5d8) | indirect |
| 22 | 0x00af2dc7 | 0x8b4b2dc7 | 0x19800000 | 0x00af214e | UNVERIFIED | dword at [rcx] vs 0x19800000, same family as the sys 605 magics | indirect |
| 23 | 0x00749b80 | 0x8b109b80 | 0x19540119 | 0x00749b20 | UNVERIFIED | dword at [r9+0x55c] vs 0x19540119, Sony tag repeated 97x image-wide | indirect |
| 24 | 0x0096ee72 | 0x8b32ee72 | 0x54445344 | 0x0096ee20 | UNVERIFIED | ACPI signature "DSDT" compare, table locator | indirect |
| 25 | 0x00b56101 | 0x8b516101 | 0x50434146 | 0x00b55f40 | UNVERIFIED | ACPI signature "FACP" compare at [rcx+rdx+0x14] | indirect |

Reject cases that the pipeline found and the hand read threw out - worth keeping because they
are what a naive "imm >= 0x1000 and cmp" scan reports as a gate:

- 0x009fd1d0 (reached from sys 59): a 20-way switch on a small id (0xf000, 0xf100, 0x10000,
  0x10100, 0x1f300, 0x1f400, 0x2f000, 0x200f200, 0x3000000, ...) where each arm is
  lea rax,[rip+X]; ret. It is an id-to-pointer lookup, not a gate. 0x9fd1d0..0x9fd4a0.
- 0x0099c3c6: cmp edi,0x7e000000 / ja -> return 0; otherwise a multiply by 0x80808081 with
  shr 0x27 - a saturating fixed-point rescale, not a gate.
- 0x0045e4d0: an upper-bound check (uap->0x18 <= 0x10000) whose zero value passes;
  the 674 class is the opposite - zero fails.
- 0x0073b310/0xc02a00 and five siblings: 1 MB caps on copy/alloc sizes, all sizes.

---

## 3. The five most interesting candidates

### A. sys 605 - a five-word service command whitelist (0xa36b00, narg 1)

    0xa36b21  8b3e                mov edi, dword ptr [rsi]        ; uap->cmd
    0xa36b23  81ffff630278        cmp edi, 0x780263ff
    0xa36b29  7e1a                jle 0xa36b45
    0xa36b2b  81ff00640278        cmp edi, 0x78026400
    0xa36b31  7422                je  0xa36b55
    0xa36b33  81ff008a0278        cmp edi, 0x78028a00
    0xa36b39  741a                je  0xa36b55
    0xa36b3b  81ff00830278        cmp edi, 0x78028300
    0xa36b41  7412                je  0xa36b55
    0xa36b43  eb2b                jmp 0xa36b70                    ; EINVAL -> return
    0xa36b45  81ff00008119        cmp edi, 0x19810000
    0xa36b4b  7408                je  0xa36b55
    0xa36b4d  81ff0007c83c        cmp edi, 0x3cc80700
    0xa36b53  751b                jne 0xa36b70
    0xa36b55  488d75e4            lea rsi, [rbp - 0x1c]           ; out buffer, dword
    0xa36b59  c745e400000000      mov dword ptr [rbp-0x1c], 0
    0xa36b60  e85b050b00          call 0xae70c0                   ; service RPC
    0xa36b65  48634de4            movsxd rcx, dword ptr [rbp-0x1c]
    0xa36b69  48898b08040000      mov qword ptr [rbx + 0x408], rcx ; rbx = arg0

Reading: eax is preloaded with 0x16 (EINVAL) at 0xa36b1c and the function returns it for any
command word outside those five. Accepted words run a service RPC through 0xae70c0
(1, cmd, &out) -> 0xae70e0 -> 0xaee460 and store the returned dword into [arg0+0x408].
This is the cleanest 674 analogue in the image: one argument, a magic whitelist, EINVAL
otherwise, and a body that writes kernel state.

Lua probe sketch (rv oracle, no memory access needed):
  for cmd in {0, 1, 0x780263ff, 0x78026400, 0x78028a00, 0x78028300, 0x19810000,
              0x3cc80700, 0x7802c500, 0xffffffff} do
    rv = syscall(605, cmd)          -- one argument
    print(string.format("605(0x%x) -> %d / 0x%x", cmd, rv, rv & 0xffffffff))
  end
Differential: exactly five inputs should stop returning 22. Whatever they return (a Sony
0x8xxxxxxx code sign-extended into the return register) is the service layer's answer, and
the write to [arg0+0x408] is the observable side effect to chase next.

### B. sys 532 and the 0x7802xxxx command dispatcher (0xae6f90 -> 0xaecd70)

    0xae6f90  service RPC wrapper: (edi=subsystem, esi=cmd, edx=out)
      0xae6fb5  cmp dword ptr [rip+0x3210c44], 0          ; service-enabled flag
      0xae6fdd  mov r14d, 0x800d020d / 0x800d0201        ; Sony error returns
      0xae7010  call 0xaee460                            ; RPC to service layer
      0xae7019  mov eax, 0x800d00f0 ; and eax,[rbp-0x3c]
      0xae7021  cmp eax, 0x800d0000                      ; error-code family test
      0xae7028  cmp ebx, 0x7802c500                      ; <-- the magic
      0xae702e  jne 0xae7062                             ; skip the special case
      0xae7050  mov dword [rbp-0x38], 0
      0xae7057  lea rsi, [rbp-0x31] ; call 0x4c68e0      ; 1-byte out variant
      0xae7062  lea rdx, [rbp-0x38] ; mov ecx,4
      0xae706b  mov edi, r15d ; mov esi, ebx
      0xae7070  call 0xaecd70                            ; central dispatcher
      0xae7081  movzx edx, r14w ; mov edi,5 ; call 0x6aa500  ; error hook

Callers pass (1, 0x2460000, 0), (1, 0x2470000, 0) ... (0xae91cf..0xae9233, 0xaf0ba4,
0xaf0ef3), so the wrapper is generic and 0x7802c500 is one privileged command that gets an
extra pre-call. 0xaecd70 is the command switch itself; inside 0xaecd70..0xaed770 there are 32
cmp-esi-immediate comparisons, six of them in the 0x7802xxxx space:
0x78020200@0xaed272, 0x78020300@0xaed283, 0x780287ff@0xaed25a, 0x78028800@0xaed354,
0x7802a500@0xaed360, 0x7802b200@0xaed36c, plus a range ladder over 0x13fffff, 0x1400000,
0x2010000, 0x2130000, 0x245ffff, 0x19e02000 (0xaed266, 0xaed29e..0xaed2ca).

Probe sketch: sys 532 has narg 5, so sweep one uap dword at a time with the others zero:
  for i in 0..4 do for v in {0x7802c500, 0x78020200, 0x780287ff, 0x2460000, 0x2470000,
                             0x19e02000, 0x2130000} do
    uap = {0,0,0,0,0}; uap[i] = v; print(i, v, syscall(532, uap))
  end end
Any slot where the return leaves the -1/22 pattern identifies which uap field reaches
0xae6f90's esi and therefore which command words are accepted through sys 532.

### C. State gate on [obj+0x5d8] >= 0x10000000 - sys 362 and sys 141

    0x313042  488b7b08            mov rdi, qword ptr [rbx + 8]
    0x313046  81bfd805000000000010 cmp dword ptr [rdi + 0x5d8], 0x10000000
    0x313050  724a                jb 0x31309c                 ; skip the whole block
    0x313052  e8199c6e00          call 0x9fcc70               ; returns an object
    0x313057  4885c0 / 7450       test rax,rax ; je 0x31309c
    0x31305c  4889c7 / e83c9c6e00 mov rdi,rax ; call 0x9fcca0  ; returns a code in eax
    0x313064  3dff010100          cmp eax, 0x101ff
    0x313069  7f0d                jg 0x313078
    0x31306b  85c0                test eax,eax
    0x31306d  7417                je 0x313086                 ; code 0 accepted
    0x31306f  3d00000100          cmp eax, 0x10000 / je 0x313086
    0x313076  eb24                jmp 0x31309c
    0x313078  3d00030100          cmp eax, 0x10300 / je 0x313086
    0x31307f  3d00020100          cmp eax, 0x10200 / jne 0x31309c
    0x313086  488b4308            mov rax, qword ptr [rbx + 8]
    0x31308a  8bb8cc050000        mov edi, dword ptr [rax + 0x5cc]
    0x313090  e80b3b2900          call 0x5a6ba0
    0x313095  49898620010000      mov qword ptr [r14 + 0x120], rax

Two magics in a row: a state threshold (0x10000000) and a code whitelist
{0, 0x10000, 0x10100, 0x10200, 0x10300}. Both must pass before 0x5a6ba0 runs. 0x313160 (sys
141) repeats the identical block, so this is one policy applied to two entry points, and
0xaba5e7 (sys 547) applies the same offset with threshold 0x60000000. 0x5d8 is not a unique
field offset - the image stores to [reg+0x5d8] from 0x390509, 0x7a03a5, 0x887ed7, 0x8cbb8e,
0xb46c1b, 0xb47672 and initialises it to 0xffffffff at 0x5430b1 and to 0 at 0xb270a0 - so the
writers are the next static target, not the readers.

Probe: this one is not satisfiable from an argument. Probe the entry points for the shape of
the skip instead: call 362 (kqueue) and 141 with valid arguments and check whether the
0x120-offset store path is implied by the return value; then compare the return with the same
call made from a second process created over sys 601, where the [.. +8] object differs.

### D. Sony status-code switch (0xc9c410, reached from sys 341 and 431)

    0xc9c428  89f3                mov ebx, esi            ; status/error code
    0xc9c432  f7c600400000        test esi, 0x4000        ; <-- one flag bit
    0xc9c438  0f856e030000        jne 0xc9c7ac
    0xc9c442  81fb0d8302a0        cmp ebx, 0xa002830d
    0xc9c448  7e30                jle 0xc9c47a
    0xc9c44a  81fb14c302a0        cmp ebx, 0xa002c314
    0xc9c450  7f54                jg  0xc9c4a6
    0xc9c452  8d83f27cfd5f        lea eax, [rbx + 0x5ffd7cf2]   ; dense window base
    0xc9c458  83f814              cmp eax, 0x14 / ja 0xc9c767
    0xc9c464  b907001000          mov ecx, 0x100007            ; 3 bits set
    0xc9c46c  0fa3c1              bt ecx, eax / jb 0xc9c7ac
    0xc9c47a  81fb020102a0        cmp ebx, 0xa0020102 / je 0xc9c7ac
    0xc9c486  81fb110302a0        cmp ebx, 0xa0020311 / je 0xc9c7ac
    0xc9c495  81fb190302a0        cmp ebx, 0xa0020319 / je 0xc9c7ac
    0xc9c4a6  81fb15c302a0        cmp ebx, 0xa002c315 / je 0xc9c7ac

A jump-table-free membership test over the Sony 0xa002xxxx status family: explicit equals for
four codes, plus a 21-entry window tested with a 0x100007 bitmask (bt). Every accepted code
lands on 0xc9c7ac. This is the part of the kernel that decides what an error code *means*;
the whitelist is the interesting object because codes outside it take the 0xc9c767 default.

Probe: drive 341/431 with arguments whose failure modes produce codes inside and outside the
window (bad pointer, bad length, closed fd), and diff the return values; the accepted set is
what 0xc9c7ac turns into a different return.

### E. Reference - the 674 gate itself, as the census finds it

    0xabb9c8  498b4610            mov rax, qword ptr [r14 + 0x10]
    0xabb9cc  48898510ffffff      mov qword ptr [rbp-0xf0], rax
    0xabb9d3  41817e2000000040    cmp dword ptr [r14 + 0x20], 0x40000000
    0xabb9db  741e                je  0xabb9fb
    0xabb9dd  e94b030000          jmp 0xabbd2d            ; EINVAL path
    0xabb9e2  48c78510ffffff00000000 mov qword ptr [rbp-0xf0], 0
    0xabb9ed  41817e2000000040    cmp dword ptr [r14 + 0x20], 0x40000000
    0xabb9f5  0f8532030000        jne 0xabbd2d

Both sites are recovered by the per-function sweep, both are argument-derived level 1
(r14 = rsi at 0xabb9a3), and the constant 0x40000000 is also the IEEE-754 encoding of 2.0f -
which is exactly why the exclusion list must not drop powers of two blindly. Any census that
filters 0x40000000 as a float or as a size loses the founding example.

---

## 4. What could not be determined

1. Symbol names and struct layouts. There is no symbol table in the dump; "proc+0x408",
   "obj+0x5d8", "obj+0x5cc", "[r13+0x200]" are offsets only. The claim "state gate on a process
   object" is an inference from the call shape (rdi = first syscall argument), not from a type.
2. devfs ioctl reachability. docs/DEVFS_GAP_ANALYSIS_14_10.md section 11 already establishes
   that the cdevsw tables are not in these dumps (no name pointers, no cdevsw-shaped structs),
   so no row above can be tied to a /dev node ioctl handler. Every "reach" entry is the direct
   call graph only. A gate reached exclusively through an ioctl pointer table would show as
   "indirect" and stay unresolved.
3. Indirect dispatch in general. 100,013 direct call edges exist; 18,626 functions are callers.
   Anything reached through a stored function pointer, a thread callout or a kevent filter is
   invisible. Only 2,466 of 29,890 function starts are reachable from a sysent body at depth
   <= 6, i.e. 91.8% of the text is behind at least one non-direct edge.
4. Coverage of the start set. Per-function decoding covers each start up to the next start or
   0x2000 bytes. Functions without a prologue and without int3 padding (hand-written assembly,
   tail-called fragments) are not starts, so their cmps appear only if a neighbouring function's
   decode runs into them. Boundary desync is visible in one place: 0xaed250 begins two bytes
   before the real instruction boundary at 0xaed254.
5. Whether the magic is user-writable. Argument derivation proves the value comes from the uap
   within two loads; it does not prove the field is read from user memory by copyin rather than
   being an internal kernel field that userland can only influence. For 674 the answer is known
   (it is the documented uap field); for the rest it needs a copyin trace per candidate.
6. Nothing here was executed. No rv, no side effect and no reachability claim has been confirmed
   on a console; the entire document is a ranking of static candidates plus the exact byte
   sequences needed to probe them.
7. The census cannot distinguish "gate on a permission level" from "gate on a version or a
   capability number" when the constant is a round value such as 0x10000000 or 0x60000000.
   Both readings fit the compare; only the writer of the field resolves it.
