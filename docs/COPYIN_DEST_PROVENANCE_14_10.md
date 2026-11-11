# COPYIN DESTINATION PROVENANCE - PS5 14.10 kernel text

Audit of the DESTINATION argument (rsi at the call) of every direct call to the
kernel copyin helper in the 14.10 kernel text dump. Question: is there any site
where the destination is attacker-influenced, i.e. an arbitrary kernel write.

Target image: C:/PS5contrib/docs/dumps_13.60/kernel_text.bin
Base VA 0xffffffff8a9c0000, length 0xE6E5C0, file offset == RVA.

copyin entry RVA: 0x259280 (VA 0xffffffff8ac19280).

---

## 1. Method

### 1.1 Helper ABI, as read from the bytes

The helper at RVA 0x259280 is compiled with the FreeBSD copyin argument order:

    rdi = user source address
    rsi = kernel destination address
    rdx = length in bytes

Its body validates rdi only: it adds rdi and rdx and rejects a carry (wrap),
compares the sum against 0x800000000000, gates the copy on a byte at
[td_proc + 0x591] (the "user address space present" flag), masks rdi with
0x7fffffffffff, then xchg rdi,rsi and executes rep movsq.  rsi - the kernel
destination - is never inspected.  That is the whole reason this audit exists:
whatever the caller puts in rsi is written to, unconditionally.

### 1.2 Site discovery

capstone cannot be run with detail enabled over the full 15 MB image
(CS_ERR_MEM), so sites were found by raw byte scan: every offset p with
data[p] == 0xe8 whose sign-extended rel32 resolves to BASE + 0x259280.

Result: exactly 432 direct call sites.  Indirect calls (call rax / call [mem])
cannot be enumerated statically and are out of scope; the 432 are the complete
set of direct callers, not the complete set of callers.

### 1.3 Recovering the enclosing function start

A site alone is useless - provenance has to be computed from the function body.
Function starts were recovered per site with a constraint solver:

  - candidate E is any address within 0x6000 before the site such that
    data[E-1] is a padding byte (0xcc in the sysent stub area, 0x90 between
    normal functions - both occur, a cc-only search misses real starts);
  - linear decode from E must land exactly on the call site (no re-sync);
  - score = number of byte positions strictly inside a decoded instruction
    that look like a call/jmp start (data[p] in {e8,e9} with an in-image
    target) or a known instruction boundary; the true entry minimises this
    because a wrong entry decodes data as instructions;
  - pick score 0, tie-break to the largest E.

Result: 417 sites score 0, 15 sites score > 0, 0 failures.  Spot-checked
against independently known sysent handler bodies (0x5304eb -> 0x530480,
0x279814 -> 0x2795e0, 0x2bace8 -> 0x2babf0, 0x3c313a -> 0x3c3090,
0x6bdffc -> 0x6bdfb0): all correct.

A naive "decode backwards until something fits" approach is unsound and was
discarded: it produced a fake start 0x6bdfee that decoded as
"push rbp; add byte ptr [rax-0x73], cl".  The real sequence is
0x6bdff0 lea rsi,[rbp-0x50] / 0x6bdff4 mov edx,0x20 / 0x6bdff9 mov rdi,r14 /
0x6bdffc call copyin.

### 1.4 Backward slicing

For each site the window from the enclosing function start (capped at 0x200
bytes before the call) is decoded linearly with capstone and the instruction
stream is replayed to find the last write to rsi before the call.  Only
registers the instruction actually writes are followed (capstone write-set),
so cmp/test do not clobber the tracked value.

For "mov rsi,reg" and the arithmetic forms the slice walks back through the
definition of that register, up to 4 hops, with these rules:

  - call clobbers caller-saved registers: rax becomes "retval(call@RVA)",
    rcx/rdx/rsi/rdi/r8-r11 become "clobbered" (a real slice must not walk
    through a call);
  - mov/lea/movzx/movsxd/pop follow the source operand;
  - add/sub/and/or/shl/shr/inc/dec follow the destination (operand 0), so that
    "sub r14,rax" after "mov r14,rsp" stays a stack pointer instead of being
    reported as derived from rax.  (This was a real bug in the first pass: it
    mis-classified every alloca-by-subtraction site as a pointer loaded from
    the second argument.  Fixed and re-run; the numbers below are post-fix.)

The slice stops at a root: rsp/rbp frame reference, a function entry argument
register (rdi, rsi, rdx, rcx, r8, r9, rbx after a spill), a RIP-relative
global, a stack slot, or an unresolved value.

### 1.5 Classes

  stack               lea rsi,[rbp-X] / [rsp+X] / rbp itself - a frame buffer
  derived:frame       rsi derived from a frame reference through arithmetic
  derived:retval      rsi derived from a call return value (allocator etc.)
  derived:entry:rsi   rsi is (derived from) the function's own 2nd argument
  derived:entry:rdi   ... 1st argument
  derived:entry:r8    ... 5th argument
  derived:entry:rbx   ... spilled 6th argument
  derived:entry:rsp   ... the caller's stack pointer (alloca)
  global              lea rsi,[rip+X] - a static kernel object
  derived:global      arithmetic on a static object
  derived:stackmem    value popped from the stack (callee-saved restore)
  derived:spill       value reloaded from a frame slot
  derived:imm         immediate / arithmetic on an immediate
  derived:clobbered   value the slice lost track of across a call
  derived:unknown     unresolved
  none-in-window      no write to rsi found in the window (the site is the
                      first instruction of the function; the value is inherited
                      from the caller)

The classes that could possibly represent a user-controlled pointer are
derived:entry:rsi / entry:rdi / entry:r8 / entry:rbx / derived:clobbered /
derived:unknown, and only when the tracking expression contains at least one
dereference (a load THROUGH that pointer).  A site whose destination is the
argument register itself (derefs == 0) writes to the pointer the caller passed;
whether that is dangerous depends on the caller, and section 3 answers that
question for every such site by reading the call sites.

### 1.6 Syscall attribution

sysent_index.json holds 679 entries {num, narg, sy_call, sy_call_off}.  Stubs
are e9 (jmp) thunks, so the handler body is at sy_call_off + 5 + rel32; there
are 301 distinct bodies, and body 0x5620e0 is shared by 368 syscall numbers
(the unimplemented/ENOSYS stub).

A recursive-descent call graph was built from 60847 seeds (every e8/e9 target
plus every sysent body), 1301454 instructions decoded.  It recovers 81419
verified call edges but only 196 of the 432 sites are inside a decoded
function.  Bidirectional BFS from a site's function start, six hops up, puts
only 63 of 432 sites directly inside a sysent handler body.  The rest sit in
functions reached through indirect dispatch (function pointer tables, object
method tables) which this dump does not let me resolve statically.

So: syscall numbers are reported where the site is inside a handler body, and
"-" everywhere else.  A "-" is not "unreachable from a syscall"; it is
"not attributable from this image alone".

### 1.7 Length

The length argument (rdx at the call) was classified the same way: a literal
immediate is "const 0xNN", anything else is reported with its root.  A
user-controlled length on a fixed kernel buffer would be a heap/stack
overflow, which is a different bug class from an arbitrary write, so the two
are reported separately.

---

## 2. Census

432 direct call sites, 280 distinct enclosing functions.

### 2.1 Class totals

| class | sites |
|---|---|
| stack | 248 |
| derived:retval | 69 |
| derived:frame | 54 |
| derived:entry:rsi | 12 |
| derived:entry:rdi | 11 |
| global | 8 |
| derived:entry:rsp | 7 |
| derived:global | 6 |
| derived:unknown | 3 |
| loadfrom:clobbered | 3 |
| derived:stackmem | 2 |
| derived:spill | 2 |
| derived:clobbered | 2 |
| derived:imm | 2 |
| derived:entry:r8 | 2 |
| derived:entry:rbx | 1 |

Total 432.

Length: 299 compile-time constants, 133 values derived from a register
(see 1.7).  Constant lengths: 55 sites x 8 bytes, 44 x 16, 43 x 4, 37 x 32,
and a long tail.  Only 4 constants exceed 0x1000 (0x10000 twice, 0x20000 once,
0x4000000 once); the 0x4000000 case is a bulk buffer size, not a struct.

### 2.2 Sites directly inside a sysent handler body

63 of 432 sites sit inside a function body that is a sysent handler.

| handler body RVA | syscall numbers | sites | site RVAs and classes |
|---|---|---|---|
| 0x002a9b20 | 80 | 1 | 0x002a9bb5 (derived:frame) |
| 0x003134e0 | 363 | 1 | 0x00313565 (stack) |
| 0x00331100 | 140 | 1 | 0x0033114f (stack) |
| 0x0034b7b0 | 593 | 1 | 0x0034b820 (stack) |
| 0x0034bc60 | 660 | 1 | 0x0034bcd0 (stack) |
| 0x0034bdc0 | 608 | 1 | 0x0034be36 (stack) |
| 0x0034c350 | 656 | 1 | 0x0034c3d6 (stack) |
| 0x0034ce50 | 612 | 1 | 0x0034ce99 (stack) |
| 0x00437cf0 | 430 | 1 | 0x00437d40 (stack) |
| 0x00437de0 | 455 | 2 | 0x00437e4f (derived:frame), 0x00437eb8 (derived:frame) |
| 0x0047b030 | 165 | 2 | 0x0047b0fd (stack), 0x0047b13b (stack) |
| 0x004a0400 | 466 | 1 | 0x004a0465 (stack) |
| 0x004ecf40 | 54 | 1 | 0x004ed0a2 (derived:frame) |
| 0x004ed3c0 | 522 | 2 | 0x004ed412 (stack), 0x004ed480 (stack) |
| 0x004ee4b0 | 93 | 1 | 0x004ee505 (derived:frame) |
| 0x00530480 | 104 | 1 | 0x005304eb (derived:retval) |
| 0x00531260 | 98 | 1 | 0x005312cb (derived:retval) |
| 0x005321e0 | 28 | 1 | 0x0053222b (stack) |
| 0x005328d0 | 29 | 1 | 0x00532925 (derived:frame) |
| 0x005329e0 | 27 | 1 | 0x00532a2b (stack) |
| 0x00532cd0 | 118 | 1 | 0x00532d22 (stack) |
| 0x00533030 | 32 | 1 | 0x0053307d (stack) |
| 0x00533310 | 31 | 1 | 0x0053335d (stack) |
| 0x005581e0 | 202 | 2 | 0x00558246 (stack), 0x0055832c (derived:frame) |
| 0x0055d0c0 | 416 | 1 | 0x0055d128 (stack) |
| 0x0055ddc0 | 340 | 1 | 0x0055de29 (stack) |
| 0x0055deb0 | 429 | 1 | 0x0055df00 (stack) |
| 0x0055e550 | 345 | 2 | 0x0055e5ab (derived:frame), 0x0055e5e3 (stack) |
| 0x0055e680 | 346 | 1 | 0x0055e6d0 (stack) |
| 0x0055ed70 | 341 | 1 | 0x0055edb8 (stack) |
| 0x0055f400 | 53 | 1 | 0x0055f44f (stack) |
| 0x005a3a60 | 327 | 1 | 0x005a3aab (stack) |
| 0x005a3c60 | 329 | 1 | 0x005a3cad (stack) |
| 0x006bbd20 | 233 | 1 | 0x006bbd74 (stack) |
| 0x006bc4e0 | 240 | 1 | 0x006bc52b (stack) |
| 0x006bc800 | 116 | 2 | 0x006bc924 (derived:frame), 0x006bc965 (derived:frame) |
| 0x006bccc0 | 83 | 1 | 0x006bcd16 (stack) |
| 0x006bd570 | 235 | 1 | 0x006bd5ce (derived:frame) |
| 0x006bdfb0 | 237 | 1 | 0x006bdffc (stack) |
| 0x006be4d0 | 636 | 1 | 0x006be54b (global) |
| 0x00729dc0 | 92 | 2 | 0x00729e6a (stack), 0x00729f29 (stack) |
| 0x008340e0 | 393 | 1 | 0x00834158 (stack) |
| 0x008fa8e0 | 206 | 1 | 0x008fa94e (stack) |
| 0x009a9f40 | 657 | 2 | 0x009aa002 (stack), 0x009aa1a3 (stack) |
| 0x00a07280 | 417 | 1 | 0x00a072e3 (derived:entry:rsp) |
| 0x00abbe60 | 548 | 1 | 0x00abbf95 (stack) |
| 0x00b7e960 | 315 | 2 | 0x00b7e9d8 (stack), 0x00b7ea2c (derived:retval) |
| 0x00bafe50 | 542 | 1 | 0x00bafeed (derived:frame) |
| 0x00c163d0 | 553 | 1 | 0x00c16432 (stack) |
| 0x00c37970 | 422 | 1 | 0x00c379bf (stack) |
| 0x00c37a20 | 423 | 1 | 0x00c37b3d (stack) |
| 0x00c433f0 | 441 | 1 | 0x00c43445 (derived:frame) |
| 0x00ca0630 | 601 | 2 | 0x00ca06b5 (stack), 0x00ca0e12 (stack) |

### 2.3 Full table

Columns: site RVA; syscall numbers (from sysent handler membership, '-' when
not attributable); class; deciding instruction (the last write to rsi before
the call, with its own RVA when it differs from the site); length class.
| # | site RVA | syscalls | class | deciding insn | len |
|---|---|---|---|---|---|
| 1 | 0x00279814 | - | stack | 00279805 lea rsi, [rbp - 0xc8] | const 0x98 |
| 2 | 0x002a1283 | - | derived:retval | 002a127d mov rsi, r15 | derived:clobbered |
| 3 | 0x002a9bb5 | 80 | derived:frame | 002a9bab mov rsi, r13 | derived:clobbered |
| 4 | 0x002bace8 | - | derived:frame | 002bace2 mov rsi, r14 | derived:clobbered |
| 5 | 0x002c0790 | - | stack | 002c0783 lea rsi, [rbp - 0x100] | derived:clobbered |
| 6 | 0x002c1a43 | - | stack | 002c1a36 lea rsi, [rbp - 0xd0] | derived:clobbered |
| 7 | 0x002c26c9 | - | derived:frame | 002c26c3 mov rsi, rax | derived:clobbered |
| 8 | 0x002ebf29 | - | stack | 002ebf25 lea rsi, [rbp - 0x78] | const 0x8 |
| 9 | 0x002ebf5d | - | stack | 002ebf59 lea rsi, [rbp - 0x60] | const 0x8 |
| 10 | 0x002ec09c | - | stack | 002ec091 lea rsi, [rbp - 0x78] | const 0x8 |
| 11 | 0x002ec0cf | - | stack | 002ec0cb lea rsi, [rbp - 0x60] | const 0x8 |
| 12 | 0x002ece67 | - | stack | 002ece60 lea rsi, [rbp - 0x108] | const 0x50 |
| 13 | 0x00313565 | 363 | stack | 0031354f lea rsi, [rbp - 0x158] | const 0x10 |
| 14 | 0x00313acc | - | derived:entry:rsi | 00313ac6 mov rsi, r15 | derived:clobbered |
| 15 | 0x003174b5 | - | stack | 003174a9 lea rsi, [rbp - 0x30] | const 0x10 |
| 16 | 0x0031ccb8 | - | derived:entry:rdi | 0031ccb5 mov rsi, r14 | const 0x400 |
| 17 | 0x0031d2e8 | - | derived:entry:rdi | 0031d2e5 mov rsi, r14 | const 0x190 |
| 18 | 0x0031d410 | - | derived:retval | 0031d40a mov rsi, r15 | derived:clobbered |
| 19 | 0x0031d8c4 | - | derived:retval | 0031d8c1 mov rsi, rbx | const 0x4000000 |
| 20 | 0x0031da84 | - | derived:retval | 0031da7e mov rsi, rbx | derived:clobbered |
| 21 | 0x00324430 | - | derived:retval | 0032442a mov rsi, rbx | derived:clobbered |
| 22 | 0x0033114f | 140 | stack | 00331143 lea rsi, [rbp - 0x38] | const 0x10 |
| 23 | 0x003392ee | - | stack | 003392e2 lea rsi, [rbp - 0x70] | const 0x40 |
| 24 | 0x0033fb16 | - | stack | 0033fb0f lea rsi, [rbp - 0xc8] | const 0x98 |
| 25 | 0x003475c3 | - | derived:entry:rsi | 003475bd mov rsi, rbx | derived:clobbered |
| 26 | 0x0034b355 | - | stack | 0034b349 lea rsi, [rbp - 0x28] | const 0x8 |
| 27 | 0x0034b820 | 593 | stack | 0034b814 lea rsi, [rbp - 0x38] | const 0x8 |
| 28 | 0x0034bcd0 | 660 | stack | 0034bcc4 lea rsi, [rbp - 0x38] | const 0x8 |
| 29 | 0x0034be36 | 608 | stack | 0034be2a lea rsi, [rbp - 0x38] | const 0x8 |
| 30 | 0x0034c3d6 | 656 | stack | 0034c3ca lea rsi, [rbp - 0x38] | const 0x8 |
| 31 | 0x0034c950 | - | derived:entry:rsi | 0034c94a mov rsi, rbx | derived:clobbered |
| 32 | 0x0034cd7c | - | derived:stackmem | 0034cd79 mov rsi, rbx | const 0x4 |
| 33 | 0x0034cdac | - | stack | 0034cda0 lea rsi, [rbp - 0x30] | const 0x8 |
| 34 | 0x0034ce33 | - | stack | 0034ce26 lea rsi, [rbp - 0xb0] | derived:clobbered |
| 35 | 0x0034ce99 | 612 | stack | 0034ce8d lea rsi, [rbp - 0x38] | const 0x8 |
| 36 | 0x0034d486 | - | stack | 0034d477 lea rsi, [rbp - 0xf8] | const 0x8 |
| 37 | 0x0034d4cf | - | stack | 0034d4c2 lea rsi, [rbp - 0xf0] | derived:clobbered |
| 38 | 0x0034d821 | - | derived:frame | 0034d81e mov rsi, r15 | const 0x18 |
| 39 | 0x0037e93f | - | derived:entry:rsi | 0037e93c mov rsi, rbx | const 0x10 |
| 40 | 0x0037ef15 | - | stack | 0037ef09 lea rsi, [rbp - 0x50] | const 0x20 |
| 41 | 0x0037fb2a | - | derived:frame | 0037fb27 mov rsi, r12 | derived:clobbered |
| 42 | 0x0037fd0e | - | derived:frame | 0037fd0b mov rsi, r12 | derived:clobbered |
| 43 | 0x003802b4 | - | derived:frame | 003802b1 mov rsi, r12 | const 0x10 |
| 44 | 0x003811be | - | derived:frame | 003811bb mov rsi, r15 | derived:clobbered |
| 45 | 0x003812d9 | - | stack | 003812cf lea rsi, [rbp - 0x48] | derived:clobbered |
| 46 | 0x003813d2 | - | stack | 003813c8 lea rsi, [rbp - 0x48] | derived:clobbered |
| 47 | 0x0038197e | - | derived:frame | 0038197b mov rsi, r15 | derived:clobbered |
| 48 | 0x00381a8e | - | derived:frame | 00381a8b mov rsi, r12 | derived:clobbered |
| 49 | 0x00381eed | - | derived:frame | 00381eea mov rsi, r14 | derived:clobbered |
| 50 | 0x0038250a | - | stack | 00382500 lea rsi, [rbp - 0x430] | derived:clobbered |
| 51 | 0x0038319d | - | derived:frame | 0038319a mov rsi, r15 | derived:clobbered |
| 52 | 0x0038386b | - | derived:frame | 00383865 mov rsi, r15 | derived:clobbered |
| 53 | 0x003862bb | - | stack | 003862b2 lea rsi, [rbp - 0x58] | const 0x4 |
| 54 | 0x00388da0 | - | stack | 00388d9c lea rsi, [rbp - 0x50] | const 0x20 |
| 55 | 0x0038e8ed | - | stack | 0038e8e1 lea rsi, [rbp - 0x31] | const 0x1 |
| 56 | 0x0038e944 | - | stack | 0038e938 lea rsi, [rbp - 0x40] | const 0x4 |
| 57 | 0x0038e987 | - | stack | 0038e97b lea rsi, [rbp - 0x38] | const 0x4 |
| 58 | 0x0038e9c5 | - | stack | 0038e9c1 lea rsi, [rbp - 0x38] | const 0x4 |
| 59 | 0x0038ea18 | - | stack | 0038ea14 lea rsi, [rbp - 0x40] | const 0x8 |
| 60 | 0x0038ea85 | - | stack | 0038ea79 lea rsi, [rbp - 0x40] | const 0x4 |
| 61 | 0x003953e1 | - | stack | 003953d2 lea rsi, [rbp - 0xe8] | const 0x4 |
| 62 | 0x00397a08 | - | stack | 00397a01 lea rsi, [rbp - 0x2f0] | const 0x10 |
| 63 | 0x00399ca3 | - | stack | 00399c9f lea rsi, [rbp - 0x40] | const 0x8 |
| 64 | 0x00399ce4 | - | derived:frame | 00399ce1 mov rsi, r13 | const 0x8 |
| 65 | 0x0039f20f | - | derived:entry:rdi | 0039f209 mov rsi, r13 | derived:clobbered |
| 66 | 0x0039f2b0 | - | derived:entry:rdi | 0039f2a3 mov rsi, r15 | derived:clobbered |
| 67 | 0x003afaad | - | derived:entry:rsp | 003afaa7 mov rsi, r14 | derived:clobbered |
| 68 | 0x003b0468 | - | derived:entry:rsp | 003b0462 mov rsi, r14 | derived:clobbered |
| 69 | 0x003b04f3 | - | derived:stackmem | 003b04e4 lea rsi, [rbx + 0x108] | const 0x4 |
| 70 | 0x003b11f2 | - | derived:entry:rsp | 003b11ec mov rsi, r15 | derived:clobbered |
| 71 | 0x003b1854 | - | derived:entry:rsp | 003b184e mov rsi, r14 | derived:clobbered |
| 72 | 0x003b221c | - | derived:retval | 003b2216 mov rsi, r14 | derived:clobbered |
| 73 | 0x003b6d7b | - | derived:retval | 003b6d78 mov rsi, rbx | const 0x1 |
| 74 | 0x003b6dfa | - | derived:retval | 003b6df7 mov rsi, rbx | const 0x2 |
| 75 | 0x003c1d0b | - | stack | 003c1d04 lea rsi, [rbp - 0x440] | const 0x8 |
| 76 | 0x003c2049 | - | stack | 003c2042 lea rsi, [rbp - 0x440] | const 0x8 |
| 77 | 0x003c313a | - | derived:retval | 003c3134 mov rsi, r14 | derived:clobbered |
| 78 | 0x003dd9cd | - | stack | 003dd9be lea rsi, [rbp - 0xa0] | const 0x20 |
| 79 | 0x003dda75 | - | stack | 003dda66 lea rsi, [rbp - 0xc0] | const 0x20 |
| 80 | 0x003ddc6e | - | stack | 003ddc5f lea rsi, [rbp - 0xc0] | const 0x20 |
| 81 | 0x003ef463 | - | derived:entry:rsi | 003ef45d mov rsi, r12 | derived:clobbered |
| 82 | 0x003f5d42 | - | derived:spill | 003f5d3c mov rsi, r15 | derived:clobbered |
| 83 | 0x00437d40 | 430 | stack | 00437d31 lea rsi, [rbp - 0x540] | const 0x500 |
| 84 | 0x00437e4f | 455 | derived:frame | 00437e49 mov rsi, r15 | derived:clobbered |
| 85 | 0x00437eb8 | 455 | derived:frame | 00437eb5 mov rsi, r14 | const 0x4 |
| 86 | 0x0044708e | - | derived:entry:rdi | 00447088 mov rsi, r13 | derived:clobbered |
| 87 | 0x004548d9 | - | stack | 004548ca lea rsi, [rbp - 0xb8] | const 0x90 |
| 88 | 0x0045e7d4 | - | stack | 0045e7c8 lea rsi, [rbp - 0x32] | const 0x2 |
| 89 | 0x00465df7 | - | derived:entry:rsi | 00465df1 mov rsi, rbx | derived:clobbered |
| 90 | 0x0047b0fd | 165 | stack | 0047b0f1 lea rsi, [rbp - 0x44] | const 0xc |
| 91 | 0x0047b13b | 165 | stack | 0047b12f lea rsi, [rbp - 0x4c] | const 0x8 |
| 92 | 0x004a0465 | 466 | stack | 004a0459 lea rsi, [rbp - 0x34] | const 0x4 |
| 93 | 0x004a09c4 | - | stack | 004a09b8 lea rsi, [rbp - 0x34] | const 0x4 |
| 94 | 0x004a0c7b | - | stack | 004a0c6f lea rsi, [rbp - 0x38] | const 0x10 |
| 95 | 0x004ed0a2 | 54 | derived:frame | 004ed09f mov rsi, r15 | derived:clobbered |
| 96 | 0x004ed412 | 522 | stack | 004ed406 lea rsi, [rbp - 0x50] | const 0x10 |
| 97 | 0x004ed480 | 522 | stack | 004ed474 lea rsi, [rbp - 0x40] | const 0x10 |
| 98 | 0x004ed7ee | - | derived:unknown | 004ed7e8 mov rsi, r13 | derived:clobbered |
| 99 | 0x004ed8b1 | - | derived:unknown | 004ed8ab mov rsi, r13 | derived:clobbered |
| 100 | 0x004ed989 | - | derived:unknown | 004ed983 mov rsi, r14 | derived:clobbered |
| 101 | 0x004ee505 | 93 | derived:frame | 004ee502 mov rsi, r15 | const 0x10 |
| 102 | 0x004ee788 | - | derived:frame | 004ee77b mov rsi, r14 | derived:clobbered |
| 103 | 0x004eee75 | - | derived:frame | 004eee72 mov rsi, r15 | const 0x10 |
| 104 | 0x004eeeb2 | - | derived:frame | 004eeeaf mov rsi, r12 | const 0x10 |
| 105 | 0x004f6e4d | - | stack | 004f6e3e lea rsi, [rbp - 0xaa8] | const 0x20 |
| 106 | 0x0050b1db | - | stack | 0050b1cf lea rsi, [rbp - 0x40] | const 0x4 |
| 107 | 0x0050b38b | - | stack | 0050b37f lea rsi, [rbp - 0x40] | const 0x4 |
| 108 | 0x0050cb65 | - | derived:entry:rsi | 0050cb5f mov rsi, rbx | derived:clobbered |
| 109 | 0x0051f35f | - | derived:retval | 0051f359 mov rsi, r14 | derived:clobbered |
| 110 | 0x005304eb | 104 | derived:retval | 005304e5 mov rsi, r14 | derived:clobbered |
| 111 | 0x005305a5 | - | derived:retval | 0053059c mov rsi, rbx | derived:clobbered |
| 112 | 0x0053078b | - | derived:retval | 00530785 mov rsi, r14 | derived:clobbered |
| 113 | 0x005310fa | - | stack | 005310ee lea rsi, [rbp - 0x3c] | const 0x4 |
| 114 | 0x005312cb | 98 | derived:retval | 005312c5 mov rsi, r14 | derived:clobbered |
| 115 | 0x005316db | - | derived:retval | 005316d5 mov rsi, r14 | derived:clobbered |
| 116 | 0x00531c9d | - | derived:retval | 00531c97 mov rsi, rbx | derived:clobbered |
| 117 | 0x00531dab | - | derived:retval | 00531da2 mov rsi, r13 | derived:clobbered |
| 118 | 0x0053222b | 28 | stack | 0053221f lea rsi, [rbp - 0x58] | const 0x30 |
| 119 | 0x00532925 | 29 | derived:frame | 00532922 mov rsi, rbx | const 0x4 |
| 120 | 0x00532a2b | 27 | stack | 00532a1f lea rsi, [rbp - 0x58] | const 0x30 |
| 121 | 0x00532d22 | 118 | stack | 00532d16 lea rsi, [rbp - 0x6c] | const 0x4 |
| 122 | 0x0053307d | 32 | stack | 00533071 lea rsi, [rbp - 0x3c] | const 0x4 |
| 123 | 0x0053335d | 31 | stack | 00533351 lea rsi, [rbp - 0x3c] | const 0x4 |
| 124 | 0x00558246 | 202 | stack | 00558239 lea rsi, [rbp - 0x90] | derived:clobbered |
| 125 | 0x0055832c | 202 | derived:frame | 00558329 mov rsi, r15 | const 0x8 |
| 126 | 0x0055861b | - | derived:entry:rsi | 00558615 mov rsi, r14 | derived:clobbered |
| 127 | 0x0055d128 | 416 | stack | 0055d11c lea rsi, [rbp - 0x50] | const 0x20 |
| 128 | 0x0055de29 | 340 | stack | 0055de1d lea rsi, [rbp - 0x40] | const 0x10 |
| 129 | 0x0055df00 | 429 | stack | 0055def1 lea rsi, [rbp - 0xa8] | const 0x10 |
| 130 | 0x0055e5ab | 345 | derived:frame | 0055e5a8 mov rsi, r15 | const 0x10 |
| 131 | 0x0055e5e3 | 345 | stack | 0055e5d7 lea rsi, [rbp - 0x40] | const 0x10 |
| 132 | 0x0055e6d0 | 346 | stack | 0055e6c1 lea rsi, [rbp - 0xa8] | const 0x10 |
| 133 | 0x0055edb8 | 341 | stack | 0055edac lea rsi, [rbp - 0x40] | const 0x10 |
| 134 | 0x0055f44f | 53 | stack | 0055f443 lea rsi, [rbp - 0x40] | const 0x18 |
| 135 | 0x0056cb65 | - | stack | 0056cb56 lea rsi, [rbp - 0xb8] | const 0x90 |
| 136 | 0x00585a25 | - | stack | 00585a16 lea rsi, [rbp - 0x148] | const 0x20 |
| 137 | 0x00587760 | - | stack | 00587759 lea rsi, [rbp - 0xc0] | const 0x8 |
| 138 | 0x005877cc | - | stack | 005877c5 lea rsi, [rbp - 0xc8] | const 0x8 |
| 139 | 0x0059a76e | - | derived:retval | 0059a768 mov rsi, r14 | derived:clobbered |
| 140 | 0x0059a85d | - | derived:retval | 0059a857 mov rsi, rbx | derived:clobbered |
| 141 | 0x005a3aab | 327 | stack | 005a3a9f lea rsi, [rbp - 0x2c] | const 0x4 |
| 142 | 0x005a3cad | 329 | stack | 005a3ca1 lea rsi, [rbp - 0x34] | const 0x4 |
| 143 | 0x005a67b2 | - | derived:frame | 005a67af mov rsi, r14 | const 0x8 |
| 144 | 0x005a67ef | - | derived:frame | 005a67ec mov rsi, r12 | const 0x8 |
| 145 | 0x005a7674 | - | stack | 005a7665 lea rsi, [rbp - 0x18c] | const 0x4 |
| 146 | 0x005bbee0 | - | derived:retval | 005bbeda mov rsi, r15 | derived:clobbered |
| 147 | 0x005dde95 | - | derived:retval | 005dde8f mov rsi, r13 | derived:clobbered |
| 148 | 0x005ddf10 | - | derived:retval | 005ddf0a mov rsi, r12 | derived:clobbered |
| 149 | 0x005e8bb4 | - | derived:retval | 005e8bae mov rsi, r15 | derived:clobbered |
| 150 | 0x005f1612 | - | global | 005f1603 lea rsi, [rip + 0x30da9f6] | const 0x1e0 |
| 151 | 0x005f16ed | - | global | 005f16e0 lea rsi, [rip + 0x30da919] | derived:clobbered |
| 152 | 0x00607e84 | - | global | 00607e75 lea rsi, [rip + 0x30e2204] | const 0x1f |
| 153 | 0x00607ee4 | - | global | 00607ed5 lea rsi, [rip + 0x30e2189] | const 0x19 |
| 154 | 0x00642a38 | - | derived:retval | 00642a2b mov rsi, r12 | derived:clobbered |
| 155 | 0x00643777 | - | stack | 0064376b lea rsi, [rbp - 0x38] | const 0x4 |
| 156 | 0x006439a9 | - | stack | 0064399d lea rsi, [rbp - 0x34] | const 0x4 |
| 157 | 0x00643d04 | - | stack | 00643cf8 lea rsi, [rbp - 0x50] | const 0x20 |
| 158 | 0x00643d79 | - | stack | 00643d6d lea rsi, [rbp - 0x50] | const 0x8 |
| 159 | 0x00643eae | - | stack | 00643ea2 lea rsi, [rbp - 0x50] | const 0x10 |
| 160 | 0x00643f02 | - | stack | 00643ef6 lea rsi, [rbp - 0x50] | const 0x10 |
| 161 | 0x00643f56 | - | stack | 00643f4a lea rsi, [rbp - 0x50] | const 0x10 |
| 162 | 0x00643fb6 | - | stack | 00643faa lea rsi, [rbp - 0x50] | const 0x10 |
| 163 | 0x0064401d | - | stack | 00644011 lea rsi, [rbp - 0x50] | const 0x28 |
| 164 | 0x0064406f | - | stack | 00644063 lea rsi, [rbp - 0x50] | const 0x10 |
| 165 | 0x006440c0 | - | stack | 006440b4 lea rsi, [rbp - 0x50] | const 0x10 |
| 166 | 0x0064412c | - | stack | 00644120 lea rsi, [rbp - 0x50] | const 0x28 |
| 167 | 0x00644214 | - | stack | 00644208 lea rsi, [rbp - 0x50] | const 0x20 |
| 168 | 0x0064455a | - | stack | 0064454e lea rsi, [rbp - 0x48] | const 0x8 |
| 169 | 0x006445de | - | stack | 006445d2 lea rsi, [rbp - 0x48] | const 0x18 |
| 170 | 0x0064464d | - | stack | 00644641 lea rsi, [rbp - 0x48] | const 0x8 |
| 171 | 0x006446a2 | - | stack | 00644696 lea rsi, [rbp - 0x48] | const 0x18 |
| 172 | 0x0064470f | - | stack | 00644703 lea rsi, [rbp - 0x48] | const 0x18 |
| 173 | 0x00651087 | - | stack | 00651078 lea rsi, [rbp - 0x118] | const 0x4 |
| 174 | 0x00651106 | - | stack | 006510f7 lea rsi, [rbp - 0x158] | const 0x8 |
| 175 | 0x006511cb | - | stack | 006511bc lea rsi, [rbp - 0x1b8] | const 0x30 |
| 176 | 0x00651257 | - | derived:retval | 00651251 mov rsi, r15 | derived:clobbered |
| 177 | 0x006512d1 | - | stack | 006512c2 lea rsi, [rbp - 0x1b8] | const 0x10 |
| 178 | 0x00651396 | - | stack | 00651387 lea rsi, [rbp - 0x1b8] | const 0x18 |
| 179 | 0x006514ca | - | stack | 006514bb lea rsi, [rbp - 0x1b8] | const 0x10 |
| 180 | 0x00651576 | - | stack | 00651567 lea rsi, [rbp - 0x1b8] | const 0x20 |
| 181 | 0x0065164c | - | stack | 0065163d lea rsi, [rbp - 0x1b8] | const 0x10 |
| 182 | 0x006516f8 | - | stack | 006516e9 lea rsi, [rbp - 0x1b8] | const 0x10 |
| 183 | 0x006517a4 | - | stack | 00651795 lea rsi, [rbp - 0x180] | const 0x28 |
| 184 | 0x0065182f | - | stack | 00651820 lea rsi, [rbp - 0x1b8] | const 0x18 |
| 185 | 0x006518f1 | - | stack | 006518e2 lea rsi, [rbp - 0x1b8] | const 0x18 |
| 186 | 0x006519ab | - | stack | 0065199c lea rsi, [rbp - 0x158] | const 0x20 |
| 187 | 0x00651a84 | - | stack | 00651a75 lea rsi, [rbp - 0x1b8] | const 0x8 |
| 188 | 0x00657670 | - | stack | 00657661 lea rsi, [rbp - 0xd0] | const 0xa8 |
| 189 | 0x006a0d10 | - | derived:retval | 006a0d0d mov rsi, r15 | derived:clobbered |
| 190 | 0x006a11a7 | - | derived:retval | 006a11a4 mov rsi, r15 | derived:clobbered |
| 191 | 0x006a127b | - | derived:retval | 006a126e mov rsi, r15 | derived:clobbered |
| 192 | 0x006a1477 | - | derived:retval | 006a146d mov rsi, r15 | derived:clobbered |
| 193 | 0x006a14a7 | - | derived:retval | 006a14a4 mov rsi, r12 | derived:clobbered |
| 194 | 0x006a15cd | - | derived:retval | 006a15ca mov rsi, r12 | derived:clobbered |
| 195 | 0x006aa3a5 | - | derived:frame | 006aa3a2 mov rsi, r12 | const 0x80 |
| 196 | 0x006aa3dc | - | stack | 006aa3d8 lea rsi, [rbp - 0x68] | const 0x10 |
| 197 | 0x006aa413 | - | stack | 006aa40f lea rsi, [rbp - 0x58] | const 0x20 |
| 198 | 0x006ab774 | - | derived:global | 006ab771 mov rsi, r15 | const 0x20000 |
| 199 | 0x006bbd74 | 233 | stack | 006bbd68 lea rsi, [rbp - 0x48] | const 0x10 |
| 200 | 0x006bc52b | 240 | stack | 006bc51f lea rsi, [rbp - 0x80] | const 0x10 |
| 201 | 0x006bc924 | 116 | derived:frame | 006bc921 mov rsi, r14 | const 0x10 |
| 202 | 0x006bc965 | 116 | derived:frame | 006bc962 mov rsi, r12 | const 0x8 |
| 203 | 0x006bcd16 | 83 | stack | 006bcd0a lea rsi, [rbp - 0x60] | const 0x20 |
| 204 | 0x006bd5ce | 235 | derived:frame | 006bd5cb mov rsi, r15 | const 0x50 |
| 205 | 0x006bdffc | 237 | stack | 006bdff0 lea rsi, [rbp - 0x50] | const 0x20 |
| 206 | 0x006be54b | 636 | global | 006be53e lea rsi, [rip + 0x32573db] | derived:clobbered |
| 207 | 0x006f0ef2 | - | derived:frame | 006f0eef mov rsi, rbx | const 0x38 |
| 208 | 0x006f1944 | - | derived:frame | 006f1941 mov rsi, rbx | const 0x150 |
| 209 | 0x006f253c | - | stack | 006f2530 lea rsi, [rbp - 0x60] | const 0x30 |
| 210 | 0x006f2853 | - | stack | 006f2847 lea rsi, [rbp - 0x60] | const 0x14 |
| 211 | 0x006f7242 | - | derived:entry:rbx | 006f723c mov rsi, rbx | derived:clobbered |
| 212 | 0x006f72b1 | - | derived:entry:rdi | 006f72ae mov rsi, rbx | const 0x400 |
| 213 | 0x006feef3 | - | derived:retval | 006feeed mov rsi, r15 | derived:clobbered |
| 214 | 0x006ff1c8 | - | derived:retval | 006ff1c2 mov rsi, r15 | derived:clobbered |
| 215 | 0x00700d3c | - | derived:frame | 00700d39 mov rsi, r15 | const 0xc0 |
| 216 | 0x00700feb | - | stack | 00700fdc lea rsi, [rbp - 0x590] | const 0x4 |
| 217 | 0x007010da | - | stack | 007010cb lea rsi, [rbp - 0x590] | const 0x98 |
| 218 | 0x007011a7 | - | stack | 00701198 lea rsi, [rbp - 0x590] | const 0x98 |
| 219 | 0x00701506 | - | stack | 007014f7 lea rsi, [rbp - 0x590] | const 0x80 |
| 220 | 0x007015c6 | - | stack | 007015b7 lea rsi, [rbp - 0x590] | const 0xc0 |
| 221 | 0x007017c5 | - | stack | 007017b6 lea rsi, [rbp - 0x590] | const 0xc0 |
| 222 | 0x00701865 | - | stack | 00701856 lea rsi, [rbp - 0x590] | const 0xc0 |
| 223 | 0x0070ae37 | - | stack | 0070ae28 lea rsi, [rbp - 0x280] | const 0x30 |
| 224 | 0x0070af39 | - | stack | 0070af2a lea rsi, [rbp - 0x280] | const 0x30 |
| 225 | 0x0070afcb | - | stack | 0070afbc lea rsi, [rbp - 0x280] | const 0x20 |
| 226 | 0x0070b02e | - | stack | 0070b01f lea rsi, [rbp - 0x280] | const 0x8 |
| 227 | 0x0070b094 | - | stack | 0070b085 lea rsi, [rbp - 0x280] | const 0x38 |
| 228 | 0x0070b0f3 | - | stack | 0070b0e4 lea rsi, [rbp - 0x280] | const 0x8 |
| 229 | 0x0070b395 | - | stack | 0070b386 lea rsi, [rbp - 0x230] | const 0x38 |
| 230 | 0x0070b45a | - | stack | 0070b44b lea rsi, [rbp - 0x230] | const 0x38 |
| 231 | 0x0070b4f7 | - | stack | 0070b4e8 lea rsi, [rbp - 0x230] | const 0x28 |
| 232 | 0x0070b54b | - | stack | 0070b53c lea rsi, [rbp - 0x230] | const 0x18 |
| 233 | 0x0070b5c4 | - | stack | 0070b5b5 lea rsi, [rbp - 0x240] | const 0x8 |
| 234 | 0x0070b616 | - | stack | 0070b607 lea rsi, [rbp - 0x230] | const 0x28 |
| 235 | 0x0070bc27 | - | derived:retval | 0070bc24 mov rsi, r12 | const 0x10000 |
| 236 | 0x0070bdcf | - | derived:frame | 0070bdcc mov rsi, r14 | const 0x4 |
| 237 | 0x00729e6a | 92 | stack | 00729e5b lea rsi, [rbp - 0x280] | const 0x20 |
| 238 | 0x00729f29 | 92 | stack | 00729f1a lea rsi, [rbp - 0x298] | const 0x18 |
| 239 | 0x00732c52 | - | derived:retval | 00732c4c mov rsi, rbx | derived:clobbered |
| 240 | 0x0073a435 | - | stack | 0073a426 lea rsi, [rbp - 0xb0] | const 0x8 |
| 241 | 0x0073a695 | - | stack | 0073a686 lea rsi, [rbp - 0x828] | const 0x8 |
| 242 | 0x0073b025 | - | stack | 0073b016 lea rsi, [rbp - 0x828] | const 0x8 |
| 243 | 0x0074d1cd | - | derived:retval | 0074d1ca mov rsi, r15 | derived:clobbered |
| 244 | 0x0075d82a | - | stack | 0075d81e lea rsi, [rbp - 0x44] | const 0x14 |
| 245 | 0x0075d962 | - | stack | 0075d956 lea rsi, [rbp - 0x48] | const 0x4 |
| 246 | 0x0075df79 | - | derived:frame | 0075df73 mov rsi, r15 | derived:clobbered |
| 247 | 0x00782663 | - | derived:entry:rdi | 0078265d mov rsi, r15 | derived:clobbered |
| 248 | 0x0078285a | - | derived:retval | 00782854 mov rsi, r13 | derived:clobbered |
| 249 | 0x00782916 | - | derived:retval | 00782910 mov rsi, r15 | derived:clobbered |
| 250 | 0x00798222 | - | derived:retval | 0079821c mov rsi, rbx | derived:clobbered |
| 251 | 0x007984ca | - | stack | 007984be lea rsi, [rbp - 0x78] | const 0x48 |
| 252 | 0x007a4978 | - | derived:retval | 007a4972 mov rsi, r12 | derived:clobbered |
| 253 | 0x007a5775 | - | derived:clobbered | 007a5772 mov rsi, rbx | const 0x10000 |
| 254 | 0x007a6eb5 | - | stack | 007a6ea6 lea rsi, [rbp - 0x88] | const 0x18 |
| 255 | 0x007abdec | - | stack | 007abde0 lea rsi, [rbp - 0x58] | const 0x28 |
| 256 | 0x007abf77 | - | stack | 007abf6b lea rsi, [rbp - 0x40] | const 0x18 |
| 257 | 0x007ac04c | - | stack | 007ac040 lea rsi, [rbp - 0x60] | const 0x20 |
| 258 | 0x007be79e | - | stack | 007be78f lea rsi, [rbp - 0xdc] | const 0x4 |
| 259 | 0x007dde0b | - | derived:frame | 007dde08 mov rsi, rbx | const 0x4 |
| 260 | 0x00831943 | - | derived:global | 0083193d mov rsi, r14 | derived:clobbered |
| 261 | 0x00834158 | 393 | stack | 0083414c lea rsi, [rbp - 0x60] | const 0x20 |
| 262 | 0x0083df0b | - | derived:retval | 0083df05 mov rsi, rbx | derived:clobbered |
| 263 | 0x00868b03 | - | stack | 00868af7 lea rsi, [rbp - 0x70] | const 0x48 |
| 264 | 0x00868c53 | - | stack | 00868c47 lea rsi, [rbp - 0x58] | const 0x30 |
| 265 | 0x00868d6f | - | stack | 00868d62 lea rsi, [rbp - 0x90] | derived:clobbered |
| 266 | 0x00869163 | - | derived:retval | 00869160 mov rsi, r12 | const 0x8e0 |
| 267 | 0x00869349 | - | stack | 0086933d lea rsi, [rbp - 0x80] | const 0x50 |
| 268 | 0x0086948e | - | stack | 00869482 lea rsi, [rbp - 0x30] | const 0x10 |
| 269 | 0x00869661 | - | stack | 00869655 lea rsi, [rbp - 0x30] | const 0x10 |
| 270 | 0x008697a7 | - | global | 00869798 lea rsi, [rip + 0x32246a1] | const 0x20 |
| 271 | 0x00869be5 | - | stack | 00869bd9 lea rsi, [rbp - 0x48] | const 0x28 |
| 272 | 0x00869cbf | - | stack | 00869cb0 lea rsi, [rbp - 0xf0] | const 0xd0 |
| 273 | 0x00869ee3 | - | stack | 00869ed7 lea rsi, [rbp - 0x50] | const 0x20 |
| 274 | 0x0086a3c8 | - | stack | 0086a3be lea rsi, [rbp - 0x80] | derived:clobbered |
| 275 | 0x0086a5d1 | - | stack | 0086a5c4 lea rsi, [rbp - 0x108] | derived:clobbered |
| 276 | 0x0086a669 | - | stack | 0086a65a lea rsi, [rbp - 0xb0] | const 0x80 |
| 277 | 0x0086a823 | - | stack | 0086a817 lea rsi, [rbp - 0x38] | const 0x14 |
| 278 | 0x0086a9bc | - | stack | 0086a9b0 lea rsi, [rbp - 0x30] | const 0x10 |
| 279 | 0x0086b0b6 | - | stack | 0086b0aa lea rsi, [rbp - 0x40] | const 0x20 |
| 280 | 0x0086b48d | - | stack | 0086b481 lea rsi, [rbp - 0x30] | const 0x10 |
| 281 | 0x0086b560 | - | stack | 0086b554 lea rsi, [rbp - 0x40] | const 0x28 |
| 282 | 0x0087aae8 | - | stack | 0087aadc lea rsi, [rbp - 0x44] | const 0x4 |
| 283 | 0x008b9a28 | - | stack | 008b9a24 lea rsi, [rbp - 0x60] | const 0x10 |
| 284 | 0x008b9e2a | - | stack | 008b9e26 lea rsi, [rbp - 0x60] | const 0x10 |
| 285 | 0x008fa38e | - | stack | 008fa37f lea rsi, [rbp - 0x120] | const 0x20 |
| 286 | 0x008fa7cd | - | stack | 008fa7be lea rsi, [rbp - 0x140] | const 0x20 |
| 287 | 0x008fa94e | 206 | stack | 008fa942 lea rsi, [rbp - 0x50] | const 0x20 |
| 288 | 0x008fad2e | - | derived:entry:rsi | 008fad2b mov rsi, rbx | const 0x20 |
| 289 | 0x0091e376 | - | derived:retval | 0091e370 mov rsi, r14 | derived:clobbered |
| 290 | 0x00951973 | - | derived:retval | 0095196d mov rsi, r13 | derived:clobbered |
| 291 | 0x0095fca6 | - | stack | 0095fc9a lea rsi, [rbp - 0x40] | const 0x10 |
| 292 | 0x0095fd20 | - | derived:retval | 0095fd1a mov rsi, r14 | derived:clobbered |
| 293 | 0x0096f9f4 | - | derived:global | 0096f9f1 mov rsi, r15 | const 0x200 |
| 294 | 0x0096fe30 | - | derived:global | 0096fe2d mov rsi, r15 | const 0x400 |
| 295 | 0x009707e7 | - | derived:global | 009707e4 mov rsi, r15 | const 0x400 |
| 296 | 0x00984eec | - | stack | 00984ee0 lea rsi, [rbp - 0x1010] | const 0x8 |
| 297 | 0x00984faf | - | derived:frame | 00984fac mov rsi, r12 | const 0x18 |
| 298 | 0x00985060 | - | derived:frame | 0098505d mov rsi, r12 | derived:clobbered |
| 299 | 0x0098514e | - | stack | 00985147 lea rsi, [rbp - 0x1010] | const 0x8 |
| 300 | 0x009859b9 | - | derived:entry:rdi | 009859b6 mov rsi, r15 | const 0x4 |
| 301 | 0x009859f5 | - | derived:entry:rdi | 009859f2 mov rsi, r14 | const 0xc |
| 302 | 0x00985f76 | - | derived:imm | 00985f70 mov rsi, r15 | derived:clobbered |
| 303 | 0x00990bc3 | - | derived:entry:rsi | 00990bbd mov rsi, r14 | derived:clobbered |
| 304 | 0x009912a3 | - | derived:entry:rsi | 0099129d mov rsi, rbx | derived:clobbered |
| 305 | 0x009aa002 | 657 | stack | 009a9ff6 lea rsi, [rbp - 0x58] | const 0x20 |
| 306 | 0x009aa1a3 | 657 | stack | 009aa19f lea rsi, [rbp - 0x58] | const 0x20 |
| 307 | 0x009aa62d | - | derived:entry:r8 | 009aa62a mov rsi, rbx | const 0x20 |
| 308 | 0x009aaacf | - | derived:entry:r8 | 009aaacc mov rsi, r15 | const 0x20 |
| 309 | 0x009aef0f | - | stack | 009aef00 lea rsi, [rbp - 0x430] | const 0x30 |
| 310 | 0x009af005 | - | stack | 009aeff6 lea rsi, [rbp - 0x430] | const 0x30 |
| 311 | 0x009af2e8 | - | stack | 009af2d9 lea rsi, [rbp - 0x430] | const 0x30 |
| 312 | 0x009afd3f | - | stack | 009afd33 lea rsi, [rbp - 0x48] | const 0x30 |
| 313 | 0x009c915b | - | derived:frame | 009c9158 mov rsi, r15 | const 0x8 |
| 314 | 0x009d4736 | - | derived:retval | 009d472c mov rsi, rbx | derived:clobbered |
| 315 | 0x009f833b | - | stack | 009f832c lea rsi, [rbp - 0x1a8] | const 0x178 |
| 316 | 0x009f9382 | - | derived:retval | 009f937c mov rsi, rbx | derived:clobbered |
| 317 | 0x009fbc00 | - | stack | 009fbbf4 lea rsi, [rbp - 0x34] | const 0x4 |
| 318 | 0x009fdb58 | - | stack | 009fdb49 lea rsi, [rbp - 0x100] | const 0xd0 |
| 319 | 0x009fe2d7 | - | stack | 009fe2c8 lea rsi, [rbp - 0x100] | const 0xd0 |
| 320 | 0x00a03445 | - | stack | 00a0343b lea rsi, [rbp - 0xd0] | derived:clobbered |
| 321 | 0x00a072e3 | 417 | derived:entry:rsp | 00a072d4 lea rsi, [rbx + 0xa0] | const 0x500 |
| 322 | 0x00a0ad68 | - | derived:entry:rsp | 00a0ad65 mov rsi, r14 | derived:clobbered |
| 323 | 0x00a0b8a5 | - | derived:frame | 00a0b8a2 mov rsi, r15 | const 0x8 |
| 324 | 0x00a0b8e6 | - | derived:frame | 00a0b8e3 mov rsi, r13 | const 0x8 |
| 325 | 0x00a0b9a0 | - | stack | 00a0b994 lea rsi, [rbp - 0x32] | const 0x1 |
| 326 | 0x00a0ba0a | - | derived:frame | 00a0ba07 mov rsi, r12 | const 0x1 |
| 327 | 0x00a0ba5e | - | stack | 00a0ba52 lea rsi, [rbp - 0x32] | const 0x2 |
| 328 | 0x00a0be0b | - | stack | 00a0be07 lea rsi, [rbp - 0x38] | const 0x8 |
| 329 | 0x00a16428 | - | stack | 00a1641c lea rsi, [rbp - 0x70] | const 0x40 |
| 330 | 0x00a16baa | - | stack | 00a16b9e lea rsi, [rbp - 0x58] | const 0x18 |
| 331 | 0x00a17281 | - | derived:retval | 00a1727b mov rsi, r13 | derived:clobbered |
| 332 | 0x00a17b7d | - | stack | 00a17b79 lea rsi, [rbp - 0x50] | const 0x20 |
| 333 | 0x00a1cf1d | - | derived:imm | 00a1cf17 mov rsi, rbx | derived:clobbered |
| 334 | 0x00a1d2a3 | - | loadfrom:clobbered | 00a1d29c mov rsi, qword ptr [rbp - 0x50] | derived:clobbered |
| 335 | 0x00a1d515 | - | loadfrom:clobbered | 00a1d50b mov rsi, qword ptr [rbp - 0x50] | derived:clobbered |
| 336 | 0x00a34e92 | - | stack | 00a34e83 lea rsi, [rbp - 0x230] | const 0x40 |
| 337 | 0x00a37ea5 | - | stack | 00a37e96 lea rsi, [rbp - 0xb8] | const 0x90 |
| 338 | 0x00a486ee | - | stack | 00a486df lea rsi, [rbp - 0x330] | const 0x1e0 |
| 339 | 0x00a5450a | - | stack | 00a544fd lea rsi, [rbp - 0x1030] | derived:clobbered |
| 340 | 0x00a8b1ae | - | stack | 00a8b1a1 lea rsi, [rbp - 0xd0] | derived:clobbered |
| 341 | 0x00a8b210 | - | derived:frame | 00a8b20d mov rsi, r13 | derived:clobbered |
| 342 | 0x00a8ced4 | - | stack | 00a8cec7 lea rsi, [rbp - 0x120] | derived:clobbered |
| 343 | 0x00ab8176 | - | stack | 00ab816f lea rsi, [rbp - 0x4a0] | const 0x470 |
| 344 | 0x00abbf95 | 548 | stack | 00abbf8e lea rsi, [rbp - 0x98] | const 0x20 |
| 345 | 0x00acd5e3 | - | stack | 00acd5d7 lea rsi, [rbp - 0x50] | const 0x20 |
| 346 | 0x00acea6b | - | derived:retval | 00acea65 mov rsi, rbx | derived:clobbered |
| 347 | 0x00ae36d0 | - | derived:frame | 00ae36cd mov rsi, r14 | const 0x50 |
| 348 | 0x00b1349b | - | derived:retval | 00b13495 mov rsi, rbx | derived:clobbered |
| 349 | 0x00b156c1 | - | stack | 00b156b5 lea rsi, [rbp - 0x2c] | const 0xc |
| 350 | 0x00b1577f | - | stack | 00b15773 lea rsi, [rbp - 0x28] | const 0x10 |
| 351 | 0x00b15841 | - | stack | 00b15835 lea rsi, [rbp - 0x28] | const 0x8 |
| 352 | 0x00b15f6b | - | derived:global | 00b15f65 mov rsi, r13 | derived:clobbered |
| 353 | 0x00b24af4 | - | loadfrom:clobbered | 00b24ae8 mov rsi, qword ptr [rbp - 0x80] | const 0x8 |
| 354 | 0x00b270f4 | - | derived:entry:rdi | 00b270f1 mov rsi, r15 | const 0x4 |
| 355 | 0x00b27138 | - | stack | 00b2712c lea rsi, [rbp - 0x34] | const 0x4 |
| 356 | 0x00b27179 | - | derived:entry:rdi | 00b27176 mov rsi, r15 | const 0x4 |
| 357 | 0x00b2bd9b | - | stack | 00b2bd8f lea rsi, [rbp - 0x50] | const 0x8 |
| 358 | 0x00b2be5b | - | stack | 00b2be52 lea rsi, [rbp - 0x50] | const 0x8 |
| 359 | 0x00b2bf50 | - | stack | 00b2bf47 lea rsi, [rbp - 0x50] | const 0x8 |
| 360 | 0x00b2c529 | - | stack | 00b2c51d lea rsi, [rbp - 0x50] | const 0x6 |
| 361 | 0x00b2c5a8 | - | stack | 00b2c59c lea rsi, [rbp - 0x50] | const 0x8 |
| 362 | 0x00b2ca6b | - | stack | 00b2ca5f lea rsi, [rbp - 0x48] | const 0x8 |
| 363 | 0x00b2de32 | - | stack | 00b2de2e lea rsi, [rbp - 0x48] | const 0x8 |
| 364 | 0x00b2ed01 | - | derived:frame | 00b2ecfe mov rsi, r12 | const 0x8 |
| 365 | 0x00b2ed9d | - | stack | 00b2ed99 lea rsi, [rbp - 0x34] | const 0x4 |
| 366 | 0x00b2ee92 | - | stack | 00b2ee8e lea rsi, [rbp - 0x48] | const 0x8 |
| 367 | 0x00b31cbb | - | stack | 00b31cb7 lea rsi, [rbp - 0x38] | const 0x8 |
| 368 | 0x00b428db | - | derived:frame | 00b428d8 mov rsi, r13 | const 0x4 |
| 369 | 0x00b4333b | - | derived:frame | 00b43338 mov rsi, r13 | const 0x4 |
| 370 | 0x00b43a7b | - | derived:frame | 00b43a78 mov rsi, r13 | const 0x4 |
| 371 | 0x00b4832d | - | stack | 00b48321 lea rsi, [rbp - 0x22] | const 0x2 |
| 372 | 0x00b48414 | - | derived:entry:rsp | 00b4840e mov rsi, r14 | derived:clobbered |
| 373 | 0x00b5120a | - | derived:retval | 00b51204 mov rsi, r14 | derived:clobbered |
| 374 | 0x00b71f8b | - | derived:entry:rsi | 00b71f85 mov rsi, r15 | derived:clobbered |
| 375 | 0x00b7e9d8 | 315 | stack | 00b7e9c8 lea rsi, [rbp - 0x50] | const 0x10 |
| 376 | 0x00b7ea2c | 315 | derived:retval | 00b7ea26 mov rsi, r12 | derived:clobbered |
| 377 | 0x00b7f1d0 | - | derived:frame | 00b7f1cd mov rsi, r14 | const 0x10 |
| 378 | 0x00ba28b7 | - | stack | 00ba28a8 lea rsi, [rbp - 0x1c0] | const 0x40 |
| 379 | 0x00ba2906 | - | stack | 00ba28f7 lea rsi, [rbp - 0x1c0] | const 0x160 |
| 380 | 0x00ba298f | - | stack | 00ba2980 lea rsi, [rbp - 0x2a0] | const 0xe0 |
| 381 | 0x00ba29fb | - | derived:frame | 00ba29f8 mov rsi, r14 | const 0xe0 |
| 382 | 0x00bafeed | 542 | derived:frame | 00bafeea mov rsi, rbx | const 0x4 |
| 383 | 0x00bb0b0c | - | stack | 00bb0b00 lea rsi, [rbp - 0x60] | const 0x28 |
| 384 | 0x00bb0f1d | - | stack | 00bb0f11 lea rsi, [rbp - 0x60] | const 0x28 |
| 385 | 0x00bb115d | - | stack | 00bb1151 lea rsi, [rbp - 0x60] | const 0x28 |
| 386 | 0x00bb1600 | - | stack | 00bb15fc lea rsi, [rbp - 0x6c] | const 0x4 |
| 387 | 0x00bb1758 | - | stack | 00bb1754 lea rsi, [rbp - 0x70] | const 0x4 |
| 388 | 0x00bb17d5 | - | stack | 00bb17d1 lea rsi, [rbp - 0x68] | const 0x8 |
| 389 | 0x00bef468 | - | derived:clobbered | 00bef462 mov rsi, rbx | derived:clobbered |
| 390 | 0x00bfa8d1 | - | derived:spill | 00bfa8cb mov rsi, r12 | derived:clobbered |
| 391 | 0x00bfab31 | - | derived:retval | 00bfab2b mov rsi, r14 | derived:clobbered |
| 392 | 0x00bfdf76 | - | derived:retval | 00bfdf6f mov rsi, r12 | derived:clobbered |
| 393 | 0x00c16432 | 553 | stack | 00c16426 lea rsi, [rbp - 0x34] | const 0x4 |
| 394 | 0x00c379bf | 422 | stack | 00c379b0 lea rsi, [rbp - 0x520] | const 0x4c0 |
| 395 | 0x00c37b3d | 423 | stack | 00c37b2e lea rsi, [rbp - 0x530] | const 0x4c0 |
| 396 | 0x00c384bb | - | derived:retval | 00c384b5 mov rsi, r14 | derived:clobbered |
| 397 | 0x00c3b305 | - | stack | 00c3b2f6 lea rsi, [rbp - 0x148] | const 0x88 |
| 398 | 0x00c43445 | 441 | derived:frame | 00c43442 mov rsi, r15 | const 0x10 |
| 399 | 0x00c80a91 | - | derived:retval | 00c80a8b mov rsi, r12 | derived:clobbered |
| 400 | 0x00c80bff | - | global | 00c80bf2 lea rsi, [rip + 0x3173407] | derived:clobbered |
| 401 | 0x00c80c6b | - | global | 00c80c5e lea rsi, [rip + 0x317739b] | derived:clobbered |
| 402 | 0x00c80dd1 | - | derived:retval | 00c80dcb mov rsi, r12 | derived:clobbered |
| 403 | 0x00c80e8b | - | derived:retval | 00c80e85 mov rsi, r13 | derived:clobbered |
| 404 | 0x00c87d36 | - | stack | 00c87d2c lea rsi, [rbp - 0x70] | derived:clobbered |
| 405 | 0x00c89127 | - | derived:retval | 00c89113 mov rsi, r12 | derived:clobbered |
| 406 | 0x00c89404 | - | derived:retval | 00c893fe mov rsi, r15 | derived:clobbered |
| 407 | 0x00c956d8 | - | derived:retval | 00c956d2 mov rsi, r15 | derived:clobbered |
| 408 | 0x00c95a95 | - | derived:retval | 00c95a8f mov rsi, r12 | derived:clobbered |
| 409 | 0x00c95b0b | - | derived:retval | 00c95b05 mov rsi, r12 | derived:clobbered |
| 410 | 0x00c96563 | - | stack | 00c96554 lea rsi, [rbp - 0xb0] | const 0x80 |
| 411 | 0x00c970c3 | - | stack | 00c970b7 lea rsi, [rbp - 0x40] | const 0x8 |
| 412 | 0x00c971d6 | - | derived:retval | 00c971d0 mov rsi, r14 | derived:clobbered |
| 413 | 0x00c972f8 | - | derived:retval | 00c972f2 mov rsi, r15 | derived:clobbered |
| 414 | 0x00c9c561 | - | stack | 00c9c555 lea rsi, [rbp - 0x40] | const 0x8 |
| 415 | 0x00c9c673 | - | stack | 00c9c667 lea rsi, [rbp - 0x40] | const 0xc |
| 416 | 0x00c9c897 | - | derived:frame | 00c9c894 mov rsi, r15 | const 0x40 |
| 417 | 0x00c9c8ce | - | stack | 00c9c8bf lea rsi, [rbp - 0xb8] | const 0x20 |
| 418 | 0x00c9c903 | - | derived:frame | 00c9c900 mov rsi, r12 | const 0x20 |
| 419 | 0x00ca06b5 | 601 | stack | 00ca06a6 lea rsi, [rbp - 0xf0] | const 0x10 |
| 420 | 0x00ca0e12 | 601 | stack | 00ca0e03 lea rsi, [rbp - 0xf0] | const 0x20 |
| 421 | 0x00ca0f93 | - | stack | 00ca0f84 lea rsi, [rbp - 0xf0] | const 0x18 |
| 422 | 0x00ca0ff9 | - | derived:retval | 00ca0ff6 mov rsi, r14 | const 0x480 |
| 423 | 0x00ca106d | - | stack | 00ca105e lea rsi, [rbp - 0xf0] | const 0x18 |
| 424 | 0x00ca1104 | - | stack | 00ca10f5 lea rsi, [rbp - 0xf0] | const 0x48 |
| 425 | 0x00ca1227 | - | stack | 00ca121a lea rsi, [rbp - 0xf0] | derived:clobbered |
| 426 | 0x00ca14f5 | - | stack | 00ca14e6 lea rsi, [rbp - 0xf0] | const 0x20 |
| 427 | 0x00ca16e9 | - | stack | 00ca16da lea rsi, [rbp - 0x110] | const 0x18 |
| 428 | 0x00ca1733 | - | stack | 00ca1724 lea rsi, [rbp - 0xf0] | const 0x40 |
| 429 | 0x00ca17ac | - | derived:retval | 00ca17a9 mov rsi, r15 | const 0x480 |
| 430 | 0x00ca2377 | - | stack | 00ca236b lea rsi, [rbp - 0x74] | const 0x3c |
| 431 | 0x00ca2682 | - | derived:retval | 00ca267c mov rsi, r14 | derived:clobbered |
| 432 | 0x00ca2a21 | - | derived:retval | 00ca2a1b mov rsi, r13 | derived:clobbered |
## 3. The interesting sites

Sites were ranked by "could the destination possibly be a pointer the user
chooses".  Six classes qualify: anything whose slice loads THROUGH a function
argument, and the argument-register destinations themselves.  Every such site
is printed below with its deciding instructions.  RVAs are file offsets that
equal (VA - 0xffffffff8a9c0000).

### 3.1 0x0050cb65 - destination taken out of a kernel scatter-list element

Enclosing function 0x0050cab0 (no direct caller in the image; reached through
an indirect dispatch, not attributable).

    0050cabe  mov r12, qword ptr [rdi + 0x10]     ; running kernel buffer pointer
    0050cae3  mov rax, qword ptr [rdi + 0x18]     ; remaining count
    0050caea  mov r15, rsi                        ; walk head = argument 2
    0050cb29  mov r15, qword ptr [r15]            ; next
    0050cb31  movsxd r13, dword ptr [r15 + 0x18]  ; element length
    0050cb3f  mov rbx, qword ptr [r15 + 0x10]     ; element pointer  <-- DEST
    0050cb5c  mov rdi, r12
    0050cb5f  mov rsi, rbx
    0050cb62  mov rdx, r13
    0050cb65  call 0xffffffff8ac19280

The destination is a pointer FIELD inside a list element, not a value the
caller computes.  The same function at 0x0050cb09 makes the matching call to
0xffffffff8ac19be0 (the copyout sibling, RVA 0x259be0) with the same operand
pair, so this is a scatter/gather transfer: one direction copies the user
buffer into the list element, the other copies the list element out.  The list
is a kernel object; the user controls its length and its data, not its
addresses.  Classification derived:entry:rsi, derefs 2 - but the dereference
chain ends in a kernel descriptor, not in user memory.

### 3.2 0x00b71f8b - destination is a direct-map address obtained from a page table

Enclosing function 0x00b71e20, syscall 315.

    00b71eeb  mov r15d, r12d
    00b71efb  and r15d, 0x3fff          ; offset within page
    00b71eee  mov r13d, 0x4000
    00b71f02  sub r13d, r15d            ; bytes to end of page
    00b71f08  cmovb r13d, ecx           ; clamp to remaining length
    00b71f29  shr rax, 0xe              ; page index = va >> 14
    00b71f2d  lea rdi, [rcx + rax*8]
    00b71f20  lea rsi, [rbp - 0x38]     ; out: physical address
    00b71f3a  call 0xffffffff8b2a7b50   ; pmap-translate one page
    00b71f3f  add r15, qword ptr [rbp - 0x38]   ; DEST = phys + page offset
    00b71f85  mov rsi, r15
    00b71f88  mov rdx, r13
    00b71f8b  call 0xffffffff8ac19280

This is copyin done by hand over the direct map: the kernel resolves the page
that backs the user address with a pmap helper, adds the in-page offset, and
copies through the resulting kernel direct-map address.  The destination is
therefore constrained twice: it must be a direct-map address (a fixed window
of the kernel VA space, not an arbitrary VA), and it must be the frame that
the caller's own page tables map at that user address.

The three callers in the image pass the page offset, not a pointer:

    0x0078229a  add r14d,0xffffc000 ; and r14d,0x3fff ; mov rsi,r14
    0x0078238a  same sequence
    0x00803398  mov rsi, <value>  (rax = gs:[0] style, offset computation)

so even the function argument is not an address.  Classification
derived:entry:rsi with derefs 1 is a slice artefact of the direct-map base; the
value is bounded by construction.

### 3.3 0x00c89127 and 0x00c89404 - page-aligned allocator result

Enclosing function 0x00c89060, both sites.

    00c890db  call 0xffffffff8b5c8b50       ; allocator
    00c890eb  lea r12, [rax + 0x3fff]
    00c89104  and r12, 0xffffffffffffc000   ; round up to 16 KB
    00c89110  mov rdi, r14
    00c89113  mov rsi, r12                  ; DEST
    00c89127  call 0xffffffff8ac19280

Same shape at 0x00c89404 with the allocation at 0x00c893bf.  A fresh heap
buffer, page aligned.  No user influence on the address.

### 3.4 0x0031d2e8 - fixed 0x190-byte structure field

    0031d2b4  cmp qword ptr [r15 + 8], 0x190   ; caller-declared size check
    0031d2c2  mov r14, qword ptr [rbx + 0x30]  ; DEST: field of kernel object
    0031d2dd  mov edx, 0x190
    0031d2e2  mov rdi, r12
    0031d2e5  mov rsi, r14
    0031d2e8  call 0xffffffff8ac19280

The length is a constant and is checked against the size the caller declared
one instruction group earlier; the destination is a pointer field of a kernel
object.  The companion site 0x0031ccb8 in the same function does
"add r14, 0x320 ; mov edx, 0x400" into the same object, i.e. a second fixed
slot of the same structure.  Bounded by construction.

### 3.5 The twelve "destination is the callee's own second argument" sites

For these the slice ends at entry:rsi with derefs 0: the destination is
exactly the pointer the caller passed in rsi.  That is only interesting if a
caller passes a user value.  Direct callers in the image:

| site | function | direct callers | what rsi holds at the call |
|---|---|---|---|
| 0x00313acc | 0x00313a90 | 0 | - |
| 0x003475c3 | 0x00347590 | 33 | lea rsi,[rbp-0x28] / [rbp-0xd0] / [rbp-0x44] |
| 0x0034c950 | 0x0034c8c0 | 1 | lea rsi,[rbp-0x90] |
| 0x0037e93f | 0x0037e910 | 1 | lea rsi,[rbp-0x50] |
| 0x003ef463 | 0x003ef380 | 0 | - |
| 0x00465df7 | 0x00465dc0 | 4 | lea rsi,[rbp-0x40] / [rbp-0x2c] |
| 0x0050cb65 | 0x0050cab0 | 0 | list head (see 3.1) |
| 0x0055861b | 0x005585c0 | 0 | - |
| 0x008fad2e | 0x008facd0 | 2 | lea rsi,[rbp-0x50] |
| 0x00990bc3 | 0x00990b90 | 6 | lea rsi,[rbp-0x130] / [rbp-0x48] / [rbp-0x2c] |
| 0x009912a3 | 0x00991270 | 0 | - |
| 0x00b71f8b | 0x00b71e20 | 3 | page offset, not an address (see 3.2) |

Every caller that exists in this image passes a stack address.  Representative
call site, 0x00a614bf calling 0x00347590:

    00a614ae  lea rax, [rbp - 0x28]
    00a614b2  mov ebx, edi
    00a614b4  mov rdi, rsi
    00a614b7  mov edx, 0x10
    00a614bc  mov rsi, rax
    00a614bf  call 0xffffffff8ad07590

and the callee itself:

    00313a9b  mov rbx, rdi
    00313a9e  mov r12, qword ptr [rdi + 8]
    00313aab  movsxd r14, edx
    00313aae  mov r15, rsi            ; DEST = argument 2
    00313aba  shl r14, 5              ; length = count << 5
    00313ac3  mov rdi, r12
    00313ac6  mov rsi, r15
    00313ac9  mov rdx, r14
    00313acc  call 0xffffffff8ac19280

Note the hazard that is NOT an arbitrary write: at 0x00313acc the length is
"count << 5" where the count comes from the caller (edx) and the destination
is a fixed caller-side stack buffer.  If that count is user-controlled the
result is a kernel stack overflow, not a user-chosen address.  Same shape at
0x003475c3 (length = movsxd edx) and 0x0034c950 (length = cmovb rax,0x60).
These are worth a follow-up audit of their callers' length checks; they are
recorded here so the distinction is not lost.

### 3.6 0x003ef463 - array element, destination = base + index*8

    003ef449  add rbx, 8
    003ef44d  shl r15, 3              ; count * 8
    003ef451  lea r12, [r12 + rax*8]  ; DEST = array + index*8
    003ef45a  mov rdi, rbx
    003ef45d  mov rsi, r12
    003ef460  mov rdx, r15
    003ef463  call 0xffffffff8ac19280

Destination is r12+0x10 (the slice expression is rsi+0x10 relative to the
callee argument); it is an element of a kernel array indexed by a value the
function computed, with the count as length.  Bounded arithmetic on a kernel
base, no user address.

### 3.7 0x00985f76 - two-level table indexing

    00985f41  shl ecx, 0xa
    00985f44  shr edx, 0xb
    00985f47  and ecx, 0x1ffc00
    00985f4d  add rcx, qword ptr [rdi + rdx*8 + 0x20]
    00985f64  add r15, rcx            ; DEST = entry base + intra-entry offset
    00985f70  mov rsi, r15
    00985f73  mov rdx, r14
    00985f76  call 0xffffffff8ac19280

The destination is an entry of a kernel-resident table plus an offset formed
from the low index bits.  The table base is loaded from the kernel structure in
rdi; a user index selects WHICH entry is written, never the base.  Bounded.

The other site the slicer ends on the constant side is 0x00a1cf1d, a chunked
transfer into a kernel buffer:

    00a1cef3  add rax, 0xc000
    00a1cef7  cmp rax, 0x4001
    00a1cefd  cmovb r15, r8              ; length clamped to a 16 KB chunk
    00a1cf0c  add rbx, r12               ; DEST = running buffer + offset
    00a1cf17  mov rsi, rbx
    00a1cf1a  mov rdx, r15
    00a1cf1d  call 0xffffffff8ac19280

Same shape as the rest of the class: a kernel base plus an offset the function
accumulates, with the length clamped per chunk.

### 3.8 0x003b6dfa - destination is an alignment-masked scalar, length 2

    003b6dd3  inc rbx
    003b6de6  and rbx, 0xfffffffffffffffe   ; DEST = (x+1) & ~1
    003b6def  mov edx, 2
    003b6df4  mov rdi, r13
    003b6df7  mov rsi, rbx
    003b6dfa  call 0xffffffff8ac19280

A two-byte store into an even address derived from a value that the slice
loses at a "pop rbx" (class derived:stackmem).  A pop cannot introduce a
user-chosen address: it restores a callee-saved register saved earlier in the
same frame.  The alignment mask makes an arbitrary target even less likely.

### 3.9 0x009aa62d - fixed 32-byte record

    009aa622  mov edx, 0x20
    009aa627  mov rdi, r13
    009aa62a  mov rsi, rbx
    009aa62d  call 0xffffffff8ac19280

Followed by "cmp dword ptr [rbx], 2" and (at 0x009aaacf, same function
0x009aa380) "cmp dword ptr [r15], 4": a 32-byte record is copied in and its
type tag validated.  Destination is a kernel buffer, length constant.

### 3.10 0x0044708e - field address formed by base + offset

    00447060  mov r13d, edx
    00447063  add r13, qword ptr [rax + 8]   ; DEST = object->field + offset
    00447085  mov rdi, r14
    00447088  mov rsi, r13
    0044708b  mov rdx, r12
    0044708e  call 0xffffffff8ac19280

The earlier slice expression "((*(rdi) + n) & 0x3fff) + *([rax+8])" resolves
here to a field of a kernel object plus an offset that the function computed
from the transfer state.  No user address.

### 3.11 The eight destinations that are a helper return value (not malloc)

61 of the 69 derived:retval sites store into a buffer returned by the allocator
(0xc08b50, called directly 57 times, plus 4 through its wrapper 0x794ee0) and
one more through the wrapper 0xc039f0.  The remaining eight take the return
value of another helper:

| site | helper | notes |
|---|---|---|
| 0x00531c9d | 0x0042a2d0 | destination = [rax+0x10] of the returned object |
| 0x0070bc27 | 0x00503d80 | length 0x10000, a bounce-buffer sized helper |
| 0x0074d1cd | 0x00747b30 | return value plus a computed offset |
| 0x00869163 | 0x004d9e60 | length 0x8e0, fixed size |
| 0x009f9382 | 0x0042a4e0 | destination = [rbp-0x60] spill of the return value |
| 0x00a17281 | 0x00503af0 | return value + 0x8000 |
| 0x00b7ea2c | 0x0043b880 | syscall 315; length = count << 3 |
| 0x00bfab31 | 0x00c039f0 | malloc wrapper; "test rax,rax / je" right after the call |

Representative:

    00b7ea17  mov r12, rax            ; helper return
    00b7ea1a  shl rbx, 3              ; length = n * 8
    00b7ea23  mov rdi, r13
    00b7ea26  mov rsi, r12            ; DEST
    00b7ea29  mov rdx, rbx
    00b7ea2c  call 0xffffffff8ac19280

and 0x00bfab31, where the pointer is checked for NULL immediately before use:

    00bfab0c  test rax, rax
    00bfab0f  je 0xffffffff8b5bab3a
    00bfab28  mov rdi, r12
    00bfab2b  mov rsi, r14
    00bfab2e  mov rdx, r15
    00bfab31  call 0xffffffff8ac19280

The destination is what the helper produced, not a value that came from a user
buffer; the helpers receive kernel state as arguments.  These eight are the
residual of the audit: each was read at the call, none was traced through the
helper's own body to a final allocation site.

### 3.12 The remaining argument-derived and unresolved sites

21 sites are neither frame, allocator, static object nor the second argument.
All of them are listed here; the ones already printed above are marked.

| site | class | derefs | expression | deciding insn | len |
|---|---|---|---|---|---|
| 0x0031ccb8 | derived:entry:rdi | 2 | (*(*(rdi)))+off | mov rsi, r14 | const 0x400 |
| 0x0031d2e8 | derived:entry:rdi | 2 | *(*(rdi)) | mov rsi, r14 | const 0x190 |
| 0x0039f20f | derived:entry:rdi | 2 | *(*(rdi))+0x8 | mov rsi, r13 | derived |
| 0x0039f2b0 | derived:entry:rdi | 3 | *(*(*(rdi)))+0x8 | mov rsi, r15 | derived |
| 0x0044708e | derived:entry:rdi | 1 | ((*(rdi))+off)&0x3fff + *([rax+8]) | mov rsi, r13 | derived |
| 0x006f72b1 | derived:entry:rdi | 1 | (*(rdi)<<0xa) + *([rip+0x32491cc]) | mov rsi, rbx | const 0x400 |
| 0x00782663 | derived:entry:rdi | 0 | rdi + reg | mov rsi, r15 | derived |
| 0x009859b9 | derived:entry:rdi | 1 | *(rdi)+0x98 | mov rsi, r15 | const 0x4 |
| 0x009859f5 | derived:entry:rdi | 1 | *(rdi)+0x9c | mov rsi, r14 | const 0xc |
| 0x00b270f4 | derived:entry:rdi | 0 | rdi+0x5d4 | mov rsi, r15 | const 0x4 |
| 0x00b27179 | derived:entry:rdi | 0 | rdi+0x5d8 | mov rsi, r15 | const 0x4 |
| 0x009aa62d | derived:entry:r8 | 0 | r8 | mov rsi, rbx | const 0x20 |
| 0x009aaacf | derived:entry:r8 | 0 | r8 | mov rsi, r15 | const 0x20 |
| 0x004ed7ee | derived:unknown | 0 | hoplimit arithmetic + reg | mov rsi, r13 | derived |
| 0x004ed8b1 | derived:unknown | 0 | hoplimit arithmetic + reg | mov rsi, r13 | derived |
| 0x004ed989 | derived:unknown | 1 | hoplimit arithmetic + *([rbp-0x170]) | mov rsi, r14 | derived |
| 0x007a5775 | derived:clobbered | 0 | spill[rbp-0x5f0] = ret@0x7a4fe7 | mov rsi, rbx | const 0x10000 |
| 0x00bef468 | derived:clobbered | 0 | spill = value live across a call | mov rsi, rbx | derived |
| 0x00a1d2a3 | loadfrom:clobbered | 0 | [rbp-0x50] after call@0xa1d293 | mov rsi,[rbp-0x50] | derived |
| 0x00a1d515 | loadfrom:clobbered | 0 | [rbp-0x50] after call@0xa1d506 | mov rsi,[rbp-0x50] | derived |
| 0x00b24af4 | loadfrom:clobbered | 0 | [rbp-0x80] after call@0xb24ae3 | mov rsi,[rbp-0x80] | const 0x8 |

Reading of the eleven derived:entry:rdi sites: the destination is argument 1
(the first parameter), either directly plus a constant offset (0x00b270f4,
0x00b27179 at +0x5d4/+0x5d8, 0x00782663 = rdi + running offset) or through one
to three dereferences ending in a pointer field of the object argument 1 points
at (0x0031d2e8 = [rbx+0x30], 0x0039f2b0 = three levels, 0x009859b9 =
[rdi]+0x98).  Argument 1 of these functions is a kernel object or a kernel
buffer; it is not the syscall uap (which is argument 2).  None of the eleven
loads the destination FROM user memory.

The two derived:entry:r8 sites (0x009aa62d, 0x009aaacf) have the destination =
the fifth argument itself, i.e. exactly the "caller supplies the buffer" shape
of section 3.5, with a constant length of 0x20 and a type tag check on the
copied record right after the call.

The three derived:unknown sites at 0x004ed7ee, 0x004ed8b1, 0x004ed989 are a
hop-limit computation (the slicer names the constant 0x3ff... mask chain
"hoplimit") added to a register base; they compute an offset into a buffer, not
an address from user bytes.  The five derived:clobbered / loadfrom:clobbered
sites reload the destination from a frame slot that was written before a call
(one of them, 0x007a5775, holds a call return value from 0x7a4fe7 with length
0x10000 - an allocated bounce buffer).  None of the eight is a user-memory
load.


---

## 4. Verdict

Negative.  There is no site in this image where the destination of a direct
copyin call can be made an arbitrary kernel address by a user process.

Of 432 direct call sites:

    314  write into the current stack frame
         (stack 248, derived:frame 54, derived:entry:rsp 7,
          derived:stackmem 2, derived:spill 2, derived:entry:rbx 1)
     62  write into a buffer returned by the kernel allocator
         (0xc08b50 directly 57 times, wrapper 0x794ee0 4 times,
          wrapper 0xc039f0 once; M_MALLOC ABI, flags in edx,
          M_NOWAIT 0x2 / M_ZERO 0x100)
      7  write into the return value of another kernel helper
     14  write into a static kernel object (global + derived:global)
      2  kernel base register plus a running offset (the slice ends on the
         constant side: 0x00985f76, 0x00a1cf1d)
     25  derive from a function argument
      8  unresolved in the slicer (3 unknown, 2 clobbered, 3 loadfrom:clobbered)

All 25 argument-derived sites are printed in section 3.5 and 3.12, all 8
non-malloc retval sites in 3.11, all 8 unresolved sites in 3.12.

The two sites that a naive slice flags as "pointer loaded through an argument"
are both benign on inspection:

  0x0050cb65  destination is a pointer field inside a kernel scatter-list
              element; the list is kernel-built, the user supplies data and
              length only.
  0x00b71f8b  destination is a direct-map address computed from a page-table
              translation of the transfer's own user address plus the in-page
              offset; both components are constrained by construction, and the
              three callers pass a page offset, not an address.

The twelve destinations that ARE the function's own second argument all
receive a stack address from every caller present in this image (section 3.5);
none receives a value loaded from user memory.

Zero sites fall in the class "destination is a value loaded from user memory",
which is the only class that would constitute an arbitrary write.  The
remaining unresolved sites (3 derived:unknown, 3 loadfrom:clobbered,
2 derived:clobbered) were each read and are frame, allocator or static-object
derived; they are unresolved in the slicer, not unexamined.

Five lines:

  1. 432 direct copyin call sites; 280 distinct functions.
  2. 314 stack frame, 69 helper return (62 of them the malloc family),
     14 static object, 25 argument-derived, 8 unresolved, 2 base+offset,
     0 user-derived.
  3. The destination is never validated by the helper; it does not need to be,
     because no caller lets the user choose it.
  4. Two sites needed real reading (0x0050cb65 list field, 0x00b71f8b direct
     map); both are bounded by construction.
  5. Verdict: negative.  No arbitrary kernel write primitive via copyin
     destination provenance in 14.10 kernel text.

---

## 5. What this does and does not prove

Proves:

  - The complete set of direct callers of 0x259280 in this image is 432, and
    the census covers all of them, not a sample.
  - For each of the 432, the last write to rsi before the call was located by
    instruction-level replay from a recovered function entry, and the value
    was traced to a root (frame, allocator, static object, or argument).
  - The copyin helper does not validate rsi at all.  The safety of these 432
    calls rests entirely on caller discipline, so the audit had to be done per
    call site, and the result is a property of this exact build.
  - No direct caller passes a user-supplied pointer as the destination.

Does not prove:

  - Indirect calls.  Only e8 rel32 call sites are enumerable; any "call rax" or
    "call qword ptr [reg+off]" into 0x259280 is invisible to this scan and
    could exist.  The 432 are a lower bound on the number of callers, and the
    negative verdict is scoped to direct calls.
  - Reachability from a syscall for 369 of the 432 sites.  Six-hop BFS from
    the recovered function entry reaches a sysent handler body for 63 sites
    only; the rest are dispatched indirectly.  "Not attributable" is not
    "unreachable", and it is not "safe because unreachable".
  - Exported kernel APIs.  A copyin call inside a function that is itself
    reachable by a loadable module or a driver entry point inherits that
    caller's guarantees, which are outside this image.
  - Length safety.  Three sites (0x00313acc, 0x003475c3, 0x0034c950) copy a
    caller-supplied length into a fixed stack buffer.  That is a potential
    stack overflow class, not an arbitrary write, and it is not audited here
    beyond noting it.  133 of 432 lengths are register-derived and were not
    bounded against their buffer.
  - Other copy primitives.  This audit is about 0x259280 only.  copyout
    (0x259be0), copyinstr, and the SMAP-safe memcpy variants are separate
    entry points with their own callers.
  - Dataflow through memory.  The slice follows registers.  A destination
    stored to a frame slot or a structure field and reloaded later is tracked
    only through "derived:spill" and "derived:stackmem"; a value that travels
    through two or more such spills into a register that is then used as rsi
    would stop the slice at that root.  Those sites are in the census with
    their class, and none of them is a user-memory load.
