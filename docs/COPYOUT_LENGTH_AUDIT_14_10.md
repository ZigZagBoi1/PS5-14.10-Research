# PS5 kernel copyout length audit

Generated: 2026-11-04 22:28 (offline static analysis, no console, no network)

## 0. Image actually analysed

The only kernel text image present in this workspace is
`docs/dumps_13.60/kernel_text.bin` (length 0xE6E5C0, base VA 0xffffffff8a9c0000,
file offset == RVA). There is no 14.10 dump under `docs/`: listing the directory returns
exactly `dumps_13.60`, `images`, `research`. Every RVA in this report is an RVA
into that 13.60 image. The report is named 14_10 because that is the deliverable name
the task asked for, not because a 14.10 image was examined. This is the single most
important caveat in the document; see section 5.1.

## 1. Method and counts

### 1.1 Locating the call sites

The copyout stub starts at RVA 0x2591d0. Its bytes were read and decoded directly:

```
002591d0  55                           push rbp
002591d1  4889e5                       mov rbp, rsp
002591d4  65488b042520000000           mov rax, qword ptr gs:[0x20]
002591dd  4c8d1d7c000000               lea r11, [rip + 0x7c]
002591e4  4c899808010000               mov qword ptr [rax + 0x108], r11
002591eb  4885d2                       test rdx, rdx
002591ee  7455                         je 0xffffffff8ac19245
002591f0  4889f0                       mov rax, rsi
002591f3  4801d0                       add rax, rdx
002591f6  7268                         jb 0xffffffff8ac19260
002591f8  48b90000000000800000         movabs rcx, 0x800000000000
00259202  4839c8                       cmp rax, rcx
00259205  7759                         ja 0xffffffff8ac19260
00259207  65488b042500000000           mov rax, qword ptr gs:[0]
00259210  488b4008                     mov rax, qword ptr [rax + 8]
00259214  80b89105000000               cmp byte ptr [rax + 0x591], 0
0025921b  7543                         jne 0xffffffff8ac19260
0025921d  48b8ffffffffff7f0000         movabs rax, 0x7fffffffffff
00259227  4821c6                       and rsi, rax
0025922a  4887f7                       xchg rdi, rsi
0025922d  4889d1                       mov rcx, rdx
00259230  48c1e903                     shr rcx, 3
00259234  fc                           cld 
00259235  0f01cb                       stac 
00259238  f348a5                       rep movsq qword ptr [rdi], qword ptr [rsi]
0025923b  88d1                         mov cl, dl
0025923d  80e107                       and cl, 7
00259240  f3a4                         rep movsb byte ptr [rdi], byte ptr [rsi]
00259242  0f01ca                       clac 
00259245  31c0                         xor eax, eax
00259247  65488b142520000000           mov rdx, qword ptr gs:[0x20]
00259250  48898208010000               mov qword ptr [rdx + 0x108], rax
00259257  5d                           pop rbp
00259258  c3                           ret 
00259259  90                           nop 
0025925a  90                           nop 
0025925b  90                           nop 
0025925c  90                           nop 
0025925d  90                           nop 
0025925e  90                           nop 
0025925f  90                           nop 
00259260  0f01ca                       clac 
00259263  65488b142520000000           mov rdx, qword ptr gs:[0x20]
0025926c  48c7820801000000000000       mov qword ptr [rdx + 0x108], 0
```

Reading the bytes settles the ABI: at entry **rdi = kernel source, rsi = user
destination, rdx = length**; the stub masks and range-checks rsi (the user side) and
performs no check at all against the size of the kernel buffer at rdi. That is the
whole reason this audit exists: every guarantee has to come from the caller.

Sites were found by scanning the raw image for 0xe8 with a rel32 that lands exactly on
0x2591d0, and separately for 0xe9. Re-derived twice, identical both times:

* 539 direct call sites (e8)
* 77 tail jumps (e9)
* 0 branches into the interior of the stub
* **616 total sites**

### 1.2 Syscall attribution

`docs/dumps_13.60/sysent_index.json` holds 679 entries. Every `sy_call` is a jump thunk;
all 679 resolved to 301 distinct handler bodies, body RVAs in 0x2a8ae0-0xcb1ab0.

### 1.3 Length classification

Each site was disassembled backwards from the call within its enclosing function and
the definition of rdx was followed (register moves, loads, lea, arithmetic, calls).
607 of the 616 sites disassembled on a clean instruction boundary and were classified;
9 sites have no alignment in which an instruction ends exactly at the call and were
left unclassified (section 5.2).

| length class | sites | meaning |
|---|---|---|
| L0 immediate | 415 | rdx is set from an immediate in the same function |
| L1 pass-through | 112 | rdx is never written in the function: it is the caller's argument |
| L2 stack slot | 32 | rdx loaded from a stack slot written earlier in the function |
| L2 computed | 27 | rdx from arith/lea on other registers |
| L3 unresolved | 21 | tool could not resolve the definition |

Source (rdi) classes over the same 607: stack_addr=350, live_in=147, derived_addr=44, stack_slot=32, arith=23, imm=5, stack_derived_addr=3, stack_imm=2, unknown=1.

## 2. Census

Columns: site RVA, syscall numbers that reach the enclosing function through direct
call edges within 2 hops, source class, length class, verdict. A dash in the syscall
column means no handler is reachable through direct edges; in this kernel most driver
entry points are reached through indirect VOP/dispatch tables, which a static e8 graph
does not follow (section 5.4).

| site | syscalls | source | length | verdict |
|---|---|---|---|---|
| 0x279e6d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 279e65 mov edx, 4 |
| 0x279ea4 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 279e9c mov edx, 4 |
| 0x279edb | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 279ed3 mov edx, 4 |
| 0x27a833 | - | live_in | L0 immediate | length is a constant from the instruction itself: 27a824 mov edx, 4 |
| 0x28ce31 | - | derived_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x28ce6c | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 28ce64 mov edx, 1 |
| 0x29b853 | - | live_in | L0 immediate | length is a constant from the instruction itself: 29b844 mov edx, 4 |
| 0x2a1337 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x2a8e42 | 43 | live_in | L2 address-derived | CLAMPED cmp+reject: 'cmp edx,r12d / jb EINVAL' at 0x2a8e2e before the call; len = kernel object field [obj+0x10]*4 |
| 0x2aa72f | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 2aa724 mov edx, 4 |
| 0x2aa767 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 2aa75c mov edx, 4 |
| 0x2aa79f | - | arith | L0 immediate | length is a constant from the instruction itself: 2aa794 mov edx, 4 |
| 0x2aa81f | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 2aa814 mov edx, 4 |
| 0x2aa85a | - | live_in | L0 immediate | length is a constant from the instruction itself: 2aa84f mov edx, 4 |
| 0x2aa892 | - | arith | L0 immediate | length is a constant from the instruction itself: 2aa887 mov edx, 4 |
| 0x2ab76d | 49 | stack_addr | L3 unresolved by tool | CLAMPED cmp+reject: uap[1] clamped to <=0x21 at 0x2ab6b7, then 'cmp r15,argc / ja EINVAL' at 0x2ab744; src = 0x30-byte stack buf |
| 0x2b1013 | - | live_in | L0 immediate | length is a constant from the instruction itself: 2b1004 mov edx, 4 |
| 0x2bbfff | - | arith | L0 immediate | length is a constant from the instruction itself: 2bbff4 mov edx, 5 |
| 0x2bc056 | - | derived_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x2bc0ac | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 2bc0a4 mov edx, 1 |
| 0x2bc17a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 2bc172 mov edx, 1 |
| 0x2bc1a8 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 2bc1a0 mov edx, 1 |
| 0x2bc1d6 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 2bc1ce mov edx, 1 |
| 0x2c13dd | 622 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x2d37ea | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 2d37e2 mov edx, 8 |
| 0x2efb1d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x313a6c | - | live_in | L2 computed | not individually read (class arith) |
| 0x31d37a | - | live_in | L0 immediate | length is a constant from the instruction itself: 31d36f mov edx, 0x1000 |
| 0x31d517 | - | live_in | L0 immediate | length is a constant from the instruction itself: 31d50c mov edx, 0x190 |
| 0x31dc8d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x324851 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x32bd86 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 32bd7e mov edx, 8 |
| 0x32be8a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 32be85 mov edx, 8 |
| 0x32c923 | - | live_in | L0 immediate | length is a constant from the instruction itself: 32c914 mov edx, 8 |
| 0x331248 | 140 | stack_addr | L0 immediate | length is a constant from the instruction itself: 331240 mov edx, 0x10 |
| 0x33ae6e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 33ae63 mov edx, 0x10 |
| 0x33b026 | - | stack_slot | L2 stack slot | not individually read (class stack_slot) |
| 0x33b497 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 33b48f mov edx, 0x10 |
| 0x33b526 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 33b51e mov edx, 0x10 |
| 0x340067 | - | stack_addr | L2 computed | not individually read (class arith) |
| 0x347613 | - | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x34b2c9 | 591 | stack_addr | L0 immediate | length is a constant from the instruction itself: 34b2c1 mov edx, 8 |
| 0x34b503 | 594 | live_in | L0 immediate | length is a constant from the instruction itself: 34b4f4 mov edx, 4 |
| 0x34b6ca | - | live_in | L2 computed | not individually read (class arith) |
| 0x34b6fc | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 34b6f7 mov edx, 8 |
| 0x34b8e2 | 659 | live_in | L0 immediate | length is a constant from the instruction itself: 34b8d7 mov edx, 0x160 |
| 0x34bd8e | 660 | live_in | L0 immediate | length is a constant from the instruction itself: 34bd83 mov edx, 0x160 |
| 0x34c25d | 608 | live_in | L0 immediate | length is a constant from the instruction itself: 34c255 mov edx, 0x1a8 |
| 0x34c647 | 656 | live_in | L0 immediate | length is a constant from the instruction itself: 34c63c mov edx, 0x160 |
| 0x34ca11 | 598 | stack_addr | L0 immediate | length is a constant from the instruction itself: 34ca09 mov edx, 8 |
| 0x34ca44 | 598 | stack_addr | L0 immediate | length is a constant from the instruction itself: 34ca3c mov edx, 8 |
| 0x34cf7e | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: 34cf76 mov edx, 0x10 |
| 0x34d101 | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: 34d0f9 mov edx, 8 |
| 0x3748c3 | - | live_in | L0 immediate | length is a constant from the instruction itself: 3748b4 mov edx, 0x78 |
| 0x37fc4f | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 37fc47 mov edx, 4 |
| 0x38e73d | - | arith | L0 immediate | length is a constant from the instruction itself: 38e732 mov edx, 0x4000 |
| 0x390e5d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x391ae3 | - | live_in | L0 immediate | length is a constant from the instruction itself: 391ad8 mov edx, 4 |
| 0x395ce1 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 395cd9 mov edx, 4 |
| 0x395e40 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 395e38 mov edx, 4 |
| 0x39f3cf | - | derived_addr | L3 unresolved by tool | not individually read (class unknown) |
| 0x39f470 | - | derived_addr | L3 unresolved by tool | not individually read (class unknown) |
| 0x3b018a | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3b0d9c | 663 | derived_addr | L0 immediate | length is a constant from the instruction itself: 3b0d94 mov edx, 4 |
| 0x3b1612 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3b1c9a | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 3b1c8b mov edx, 0x10 |
| 0x3b1f6d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3b2ff4 | 670 | stack_addr | L0 immediate | length is a constant from the instruction itself: 3b2fec mov edx, 4 |
| 0x3b3a7d | 663,670 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3b57ff | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 3b57f0 mov edx, 0x10 |
| 0x3b588c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 3b587d mov edx, 0x10 |
| 0x3b71ad | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3be69d | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3bec57 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3c1d93 | - | stack_addr | L3 unresolved by tool | CLAMPED by construction: copyinstr bound 0x3ff, then strnlen(buf,0x3ff)+1 |
| 0x3c2093 | - | stack_addr | L3 unresolved by tool | CLAMPED by construction: copyin 8 bytes, then strnlen(buf,0x3ff)+1 |
| 0x3c2ab9 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 3c2ab1 mov edx, 0x18 |
| 0x3c332d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3c6f29 | - | stack_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x3f5c67 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x409809 | 392 | live_in | L2 computed | SAFE alloc-then-copy-same-size: malloc(r15<<4) at 0x4097d3, copyout len = r15<<4 |
| 0x438d40 | 464 | stack_addr | L2 address-derived | CLAMPED by construction: src 0x28 stack buf filled by a 0x20-byte copy, len = strnlen(buf,0x1f)+1 <= 32 |
| 0x439308 | 634 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4392fd mov edx, 0x4c0 |
| 0x44724e | - | arith | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x45e807 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 45e7ff mov edx, 2 |
| 0x465e77 | - | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x47b4cd | 165 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x47d2ac | - | stack_slot | L2 stack slot | not individually read (class stack_slot) |
| 0x47d3ed | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x483808 | - | live_in | L2 computed | not individually read (class arith) |
| 0x483946 | - | derived_addr | L2 stack slot | not individually read (class stack_derived_addr) |
| 0x49edf7 | - | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x4a0523 | 96 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4a051b mov edx, 4 |
| 0x4a0642 | 96 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4a063a mov edx, 4 |
| 0x4a0bf9 | 96,327,328,430,455 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4a0bf1 mov edx, 4 |
| 0x4a1490 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 4a1488 mov edx, 0x10 |
| 0x4a1d01 | 117 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4a1cf9 mov edx, 0x90 |
| 0x4a30ba | 641 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4a30b2 mov edx, 0x38 |
| 0x4a316a | 641 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4a3162 mov edx, 0x38 |
| 0x4ad53d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x4bdcf1 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 4bdce6 mov edx, 0x10 |
| 0x4be41d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x4bf54a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 4bf53f mov edx, 0x10 |
| 0x4d2b15 | - | stack_slot | L2 stack slot | not individually read (class stack_slot) |
| 0x4e1bca | 587 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4e1bc2 mov edx, 0x88 |
| 0x4e316d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x4ed0f5 | 54 | stack_slot | L1 pass-through (incoming rdx) | CLAMPED: len=(uap[1]>>16)&0x1fff; src = 0x80-byte stack slot when len<0x81, else malloc(len) |
| 0x4ee32e | 93,522 | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x4ee35f | 93,522 | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x4ee396 | 93,522 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x4eed7e | 209 | derived_addr | L0 immediate | length is a constant from the instruction itself: 4eed73 mov edx, 2 |
| 0x4f68b2 | 535,536,604 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4f68aa mov edx, 4 |
| 0x4f68f9 | 535,536,604 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4f68f1 mov edx, 4 |
| 0x4f6937 | 535,536,604 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4f692f mov edx, 4 |
| 0x4f696d | 535,536,604 | live_in | L2 computed | not individually read (class arith) |
| 0x4f71e0 | 536 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4f71db mov edx, 0xa58 |
| 0x4f74c2 | 604 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4f74bd mov edx, 4 |
| 0x4f757f | 604 | live_in | L1 pass-through (incoming rdx) | ZERO LENGTH on the observed path ('xor r13d,r13d' at 0x4f755c) |
| 0x4f75af | 604 | stack_addr | L0 immediate | length is a constant from the instruction itself: 4f75aa mov edx, 4 |
| 0x4fd4b2 | - | arith | L3 unresolved by tool | not individually read (class unknown) |
| 0x50c013 | 134 | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x50c5ee | 134 | stack_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x51f598 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x531151 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x531180 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 531178 mov edx, 4 |
| 0x531a56 | 135 | stack_addr | L0 immediate | length is a constant from the instruction itself: 531a4e mov edx, 8 |
| 0x531b1d | 135 | live_in | L1 pass-through (incoming rdx) | PASS-THROUGH tail jmp; length is the caller's rdx (see 5.3) |
| 0x53265c | 27,29 | stack_slot | L2 stack slot | not individually read (class stack_slot) |
| 0x5329b2 | 29 | live_in | L0 immediate | length is a constant from the instruction itself: 5329a7 mov edx, 4 |
| 0x532aad | 27 | stack_addr | L0 immediate | length is a constant from the instruction itself: 532aa5 mov edx, 0x30 |
| 0x532e32 | 134 | stack_addr | L0 immediate | length is a constant from the instruction itself: 532e2a mov edx, 4 |
| 0x5330d5 | 32 | stack_slot | L1 pass-through (incoming rdx) | KERNEL-DERIVED: len=[rbp-0x3c] and src=[rbp-0x38] are both outputs of helper 0x8aef2e60 |
| 0x53312d | 32 | stack_addr | L0 immediate | length is a constant from the instruction itself: 533125 mov edx, 4 |
| 0x5333b5 | 31 | stack_slot | L1 pass-through (incoming rdx) | KERNEL-DERIVED: len=[rbp-0x3c] and src=[rbp-0x38] are both outputs of helper 0x8aef3160 |
| 0x53340d | 31 | stack_addr | L0 immediate | length is a constant from the instruction itself: 533405 mov edx, 4 |
| 0x553583 | - | live_in | L0 immediate | length is a constant from the instruction itself: 553574 mov edx, 0x20 |
| 0x5581b0 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x55859a | 202 | stack_addr | L0 immediate | length is a constant from the instruction itself: 558592 mov edx, 8 |
| 0x55d57a | 416 | stack_addr | L0 immediate | length is a constant from the instruction itself: 55d572 mov edx, 0x20 |
| 0x55de76 | 340 | stack_addr | L0 immediate | length is a constant from the instruction itself: 55de6e mov edx, 0x10 |
| 0x55dfab | 429 | stack_addr | L0 immediate | length is a constant from the instruction itself: 55dfa0 mov edx, 4 |
| 0x55e63c | 345 | stack_addr | L0 immediate | length is a constant from the instruction itself: 55e631 mov edx, 0x50 |
| 0x55e72f | 346 | stack_addr | L0 immediate | length is a constant from the instruction itself: 55e724 mov edx, 0x50 |
| 0x55ed41 | 343 | stack_addr | L0 immediate | length is a constant from the instruction itself: 55ed39 mov edx, 0x10 |
| 0x55f510 | 53 | stack_addr | L0 immediate | length is a constant from the instruction itself: 55f508 mov edx, 0x18 |
| 0x566edf | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 566ed4 mov edx, 0x50 |
| 0x566f93 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 566f8b mov edx, 0x90 |
| 0x59e79d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x5a3c32 | 328 | stack_addr | L0 immediate | length is a constant from the instruction itself: 5a3c2a mov edx, 4 |
| 0x5a4032 | 334 | stack_addr | L0 immediate | length is a constant from the instruction itself: 5a402a mov edx, 0x10 |
| 0x5a72ed | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x5a78b8 | - | stack_addr | L2 address-derived | not individually read (class derived_addr) |
| 0x5a78ef | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 5a78e7 mov edx, 4 |
| 0x5bc246 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x5bc51d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x5dea5a | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x5ee0bd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x5f1053 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 5f104b mov edx, 4 |
| 0x5f1798 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 5f1790 mov edx, 0x1d0 |
| 0x5f195d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x603c1c | 567 | stack_addr | L0 immediate | length is a constant from the instruction itself: 603c14 mov edx, 8 |
| 0x603c83 | 626 | live_in | L0 immediate | length is a constant from the instruction itself: 603c74 mov edx, 0x80 |
| 0x604fd2 | 626 | stack_addr | L0 immediate | length is a constant from the instruction itself: 604fca mov edx, 8 |
| 0x60bc6d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x613a71 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 613a69 mov edx, 0x20 |
| 0x614884 | - | arith | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x6148fb | - | arith | L0 immediate | length is a constant from the instruction itself: 6148f0 mov edx, 0x400 |
| 0x614992 | - | arith | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x62555b | - | arith | L0 immediate | length is a constant from the instruction itself: 625550 mov edx, 4 |
| 0x6426e6 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6426e1 mov edx, 4 |
| 0x642c1c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 642c0d mov edx, 4 |
| 0x642c6e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 642c5f mov edx, 4 |
| 0x642cc0 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 642cb1 mov edx, 8 |
| 0x642d49 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 642d3a mov edx, 4 |
| 0x6432a3 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 643294 mov edx, 4 |
| 0x6432f5 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6432e6 mov edx, 4 |
| 0x643343 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 643334 mov edx, 8 |
| 0x6434df | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6434d4 mov edx, 4 |
| 0x643545 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 64353a mov edx, 8 |
| 0x64358d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 643585 mov edx, 4 |
| 0x6435f9 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6435f4 mov edx, 4 |
| 0x644591 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 644589 mov edx, 4 |
| 0x650655 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 650647 mov edx, 4 |
| 0x65069d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x650785 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 65077a mov edx, 0x28 |
| 0x650826 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 65081b mov edx, 0x28 |
| 0x650895 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 650890 mov edx, 4 |
| 0x651eb2 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 651ea3 mov edx, 4 |
| 0x651ef5 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 651ee6 mov edx, 8 |
| 0x651f57 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 651f48 mov edx, 4 |
| 0x65271b | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 652710 mov edx, 4 |
| 0x652e64 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 652e59 mov edx, 4 |
| 0x662a81 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 662a79 mov edx, 4 |
| 0x672e16 | - | live_in | L0 immediate | length is a constant from the instruction itself: 672e07 mov edx, 0x20 |
| 0x67d58f | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x683cdd | 125 | stack_addr | L0 immediate | length is a constant from the instruction itself: 683cce mov edx, 0x1e0 |
| 0x689545 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 689537 mov edx, 0x1bc4 |
| 0x6a133e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6a1336 mov edx, 0x20 |
| 0x6a1703 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x6a18ef | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x6a1e2d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x6aa46b | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6aa463 mov edx, 0x80 |
| 0x6abe0d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x6bb645 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bb63d mov edx, 4 |
| 0x6bb6c2 | 232 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bb6ba mov edx, 0x10 |
| 0x6bc0dc | 234 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bc0d4 mov edx, 0x10 |
| 0x6bc7b8 | 240 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bc7b0 mov edx, 0x10 |
| 0x6bc858 | 116 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bc84d mov edx, 0x10 |
| 0x6bc8a9 | 116 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bc8a1 mov edx, 8 |
| 0x6bca72 | 86 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bca6a mov edx, 0x20 |
| 0x6bcdc2 | 83 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bcdba mov edx, 0x20 |
| 0x6bdd66 | 235 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bdd5e mov edx, 4 |
| 0x6be19c | 237 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6be194 mov edx, 0x20 |
| 0x6be30e | 238 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6be306 mov edx, 0x20 |
| 0x6be767 | 638 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6be75f mov edx, 8 |
| 0x6be79c | 638 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6be794 mov edx, 0x10 |
| 0x6be7d1 | 638 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6be7c9 mov edx, 4 |
| 0x6bea83 | 639 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6bea7b mov edx, 8 |
| 0x6beab8 | 639 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6beab0 mov edx, 0x10 |
| 0x6beaed | 639 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6beae5 mov edx, 4 |
| 0x6d4f95 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 6d4f8d mov edx, 0x3ac |
| 0x6e5a35 | 59 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x6e5a81 | 59 | stack_addr | L0 immediate | length is a constant from the instruction itself: 6e5a76 mov edx, 0x40 |
| 0x6e5ac2 | 59 | derived_addr | L0 immediate | length is a constant from the instruction itself: 6e5aba mov edx, 0x18 |
| 0x6e5b6a | 59 | live_in | L2 stack slot | not individually read (class stack_live_in) |
| 0x6f440d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6f4408 mov edx, 0x20 |
| 0x6f4529 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6f4521 mov edx, 0x20 |
| 0x6ff0fc | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6ff0f4 mov edx, 0xc |
| 0x6ff34d | - | stack_slot | L2 stack slot | not individually read (class stack_live_in) |
| 0x6ff393 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 6ff38e mov edx, 4 |
| 0x7014a8 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7014a0 mov edx, 6 |
| 0x7016c3 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7016bb mov edx, 0x200 |
| 0x70176f | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 701767 mov edx, 0xc |
| 0x701acd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x70b275 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 70b26d mov edx, 0x38 |
| 0x70bba4 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 70bb99 mov edx, 8 |
| 0x70beb6 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 70beae mov edx, 0x38 |
| 0x70c343 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 70c33b mov edx, 8 |
| 0x70c7ed | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x713bad | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x71b3f8 | - | live_in | L0 immediate | length is a constant from the instruction itself: 71b3ea mov edx, 4 |
| 0x72a8a6 | 92 | stack_addr | L0 immediate | length is a constant from the instruction itself: 72a89e mov edx, 0x20 |
| 0x72c362 | 189 | stack_addr | L0 immediate | length is a constant from the instruction itself: 72c35a mov edx, 0x78 |
| 0x7308a6 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 730897 mov edx, 8 |
| 0x730b17 | - | unknown | L2 stack slot | not individually read (class stack_unknown) |
| 0x733eb4 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x733ee7 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 733ee2 mov edx, 4 |
| 0x733f70 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 733f6b mov edx, 4 |
| 0x73a035 | 622 | live_in | L2 computed | not individually read (class arith) |
| 0x73a072 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73a06a mov edx, 4 |
| 0x73a2f9 | - | stack_slot | L2 stack slot | not individually read (class stack_arith) |
| 0x73a333 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 73a32b mov edx, 4 |
| 0x73a5f8 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73a5e9 mov edx, 0x70 |
| 0x73a7b4 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73a7a5 mov edx, 0x7e8 |
| 0x73b144 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73b135 mov edx, 0x7e8 |
| 0x73b2d1 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73b2c2 mov edx, 0x68 |
| 0x73b502 | 622 | live_in | L2 stack slot | not individually read (class stack_derived_addr) |
| 0x73b57e | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73b576 mov edx, 4 |
| 0x73b860 | 622 | live_in | L2 stack slot | not individually read (class stack_derived_addr) |
| 0x73b8dd | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73b8d5 mov edx, 4 |
| 0x73ba9f | 622 | live_in | L2 stack slot | not individually read (class stack_arith) |
| 0x73bb1d | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73bb15 mov edx, 4 |
| 0x73bc75 | 622 | live_in | L2 stack slot | not individually read (class stack_derived_addr) |
| 0x73bcda | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73bcd2 mov edx, 4 |
| 0x73c285 | 622 | live_in | L2 stack slot | not individually read (class stack_derived_addr) |
| 0x73c2ea | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73c2e2 mov edx, 4 |
| 0x73c4b0 | 622 | live_in | L2 stack slot | not individually read (class stack_derived_addr) |
| 0x73c4e7 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73c4df mov edx, 4 |
| 0x73c8b7 | 622 | live_in | L2 stack slot | not individually read (class stack_arith) |
| 0x73c8f0 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73c8e8 mov edx, 4 |
| 0x73d131 | 622 | live_in | L2 stack slot | not individually read (class stack_derived_addr) |
| 0x73d166 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 73d15e mov edx, 4 |
| 0x74c3cc | - | live_in | L0 immediate | length is a constant from the instruction itself: 74c3c1 mov edx, 0x20 |
| 0x74e84d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x753a36 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 753a2e mov edx, 0x20 |
| 0x77e179 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 77e170 mov edx, 0x20 |
| 0x77e38d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 77e388 mov edx, 0x20 |
| 0x7821c5 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x7826a1 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x7927c8 | - | stack_slot | L2 address-derived | not individually read (class derived_addr) |
| 0x795ecd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x7982ad | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x7986d6 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7986ce mov edx, 4 |
| 0x798903 | - | live_in | L0 immediate | length is a constant from the instruction itself: 7988f4 mov edx, 0x48 |
| 0x7a4061 | - | stack_addr | L3 unresolved by tool | CLAMPED min(): 'cmp r13,0x20 / cmovb rbx,r13'; src = stack buf [rbp-0x5b0] |
| 0x7a45a7 | - | live_in | L0 immediate | length is a constant from the instruction itself: 7a459c mov edx, 0x10000 |
| 0x7a4edd | - | live_in | L2 stack slot | not individually read (class stack_slot) |
| 0x7a5511 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7a550c mov edx, 0x15c |
| 0x7a56e1 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7a56dc mov edx, 0x80 |
| 0x7a5a26 | - | stack_addr | L3 unresolved by tool | not individually read (class unknown) |
| 0x7a5c25 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 7a5c1a mov edx, 0x18 |
| 0x7a5d4d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7a5d45 mov edx, 0x180 |
| 0x7a9ad3 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x7a9b2d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x7a9d3b | - | live_in | L2 computed | not individually read (class arith) |
| 0x7aab86 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7aab81 mov edx, 0x15c |
| 0x7ab4c3 | - | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x7ab5c3 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7ab5bb mov edx, 4 |
| 0x7ab8cf | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7ab8c3 mov edx, 4 |
| 0x7abc0e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7abc09 mov edx, 0x28 |
| 0x7abe4e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7abe46 mov edx, 0x18 |
| 0x7abef5 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7abeed mov edx, 0xb0 |
| 0x7abfca | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7abfc2 mov edx, 8 |
| 0x7ac21d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7ac215 mov edx, 8 |
| 0x7ac493 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 7ac48e mov edx, 0x80 |
| 0x7ac692 | - | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x7ac747 | - | arith | L2 stack slot | not individually read (class stack_slot) |
| 0x7befff | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7beff7 mov edx, 8 |
| 0x7bf0b5 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7bf0ad mov edx, 4 |
| 0x7bf473 | 622 | live_in | L0 immediate | length is a constant from the instruction itself: 7bf464 mov edx, 8 |
| 0x7bfc31 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7bfc29 mov edx, 4 |
| 0x7c43db | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x7d3fa7 | - | stack_slot | L2 computed | not individually read (class arith) |
| 0x7dcdb2 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7dcdad mov edx, 4 |
| 0x7de831 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7de822 mov edx, 0x18 |
| 0x7dea21 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7dea19 mov edx, 0x18 |
| 0x7dea60 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7dea54 mov edx, 0x150 |
| 0x7ded9d | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7ded95 mov edx, 4 |
| 0x7df2f4 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7df2ec mov edx, 4 |
| 0x7df6af | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7df6a7 mov edx, 4 |
| 0x7dfab1 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7dfaa9 mov edx, 4 |
| 0x7dffd7 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7dffcf mov edx, 8 |
| 0x7e0122 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7e011a mov edx, 8 |
| 0x7e03ec | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7e03e4 mov edx, 8 |
| 0x7e06cc | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7e06c4 mov edx, 8 |
| 0x7e09c3 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7e09bb mov edx, 4 |
| 0x7e0c1e | 622 | stack_slot | L0 immediate | length is a constant from the instruction itself: 7e0c13 mov edx, 0x19 |
| 0x7e0ecf | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7e0ec4 mov edx, 0x19 |
| 0x7e1694 | 622 | stack_slot | L0 immediate | length is a constant from the instruction itself: 7e1689 mov edx, 0x18 |
| 0x7e16ea | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: 7e16e2 mov edx, 8 |
| 0x7e1805 | 622 | stack_slot | L0 immediate | length is a constant from the instruction itself: 7e17fa mov edx, 0x18 |
| 0x7e6fbf | - | arith | L0 immediate | length is a constant from the instruction itself: 7e6fb4 mov edx, 4 |
| 0x7e74fd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x802e54 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 802e4c mov edx, 8 |
| 0x809806 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 809801 mov edx, 8 |
| 0x80c11a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 80c112 mov edx, 0xc8 |
| 0x80c154 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 80c14f mov edx, 0x40 |
| 0x8255ad | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x831b59 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 831b4e mov edx, 0x10 |
| 0x8342d9 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 8342d1 mov edx, 8 |
| 0x83d781 | - | arith | L0 immediate | length is a constant from the instruction itself: 83d776 mov edx, 4 |
| 0x83d97b | 486 | stack_addr | L0 immediate | length is a constant from the instruction itself: 83d973 mov edx, 4 |
| 0x83dd42 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x862f0d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x8649c2 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x8659e9 | - | arith | L0 immediate | length is a constant from the instruction itself: 8659de mov edx, 0xc8 |
| 0x86614a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 866145 mov edx, 8 |
| 0x867a95 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 867a8d mov edx, 0x99c |
| 0x868b85 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 868b7d mov edx, 8 |
| 0x868eea | - | stack_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x868fe2 | - | stack_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x8690c2 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 8690ba mov edx, 0x30 |
| 0x869255 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86924d mov edx, 0x40 |
| 0x8693e0 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 8693d5 mov edx, 4 |
| 0x8695a3 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 86959b mov edx, 0xd88 |
| 0x869a1d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 869a15 mov edx, 8 |
| 0x869a70 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 869a68 mov edx, 8 |
| 0x869dcd | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 869dc5 mov edx, 8 |
| 0x86a000 | - | live_in | L0 immediate | length is a constant from the instruction itself: 869ff5 mov edx, 0x3dc8 |
| 0x86a0b5 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86a0ad mov edx, 0x20 |
| 0x86a20c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86a204 mov edx, 0x18 |
| 0x86a2d2 | - | stack_addr | L3 unresolved by tool | kernel-derived: len=rbx set by the helper at 0x8b14f470; src = stack buf [rbp-0x68] |
| 0x86a916 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86a90e mov edx, 0x30 |
| 0x86aacc | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86aac4 mov edx, 0x54 |
| 0x86ac19 | - | stack_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x86add1 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86adc9 mov edx, 8 |
| 0x86af2c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86af24 mov edx, 0x10 |
| 0x86affb | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86aff3 mov edx, 0x18 |
| 0x86b2c4 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86b2bc mov edx, 0x128 |
| 0x86b3ea | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 86b3e2 mov edx, 0x80 |
| 0x87ac06 | - | arith | L0 immediate | length is a constant from the instruction itself: 87abfb mov edx, 0x30 |
| 0x87ac64 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 87ac5c mov edx, 4 |
| 0x897171 | 101 | stack_slot | L2 address-derived | not individually read (class derived_addr) |
| 0x8ba4bd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x8d2133 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 8d2128 mov edx, 0x1c |
| 0x8d260b | 623 | stack_addr | L0 immediate | length is a constant from the instruction itself: 8d2603 mov edx, 4 |
| 0x8f60ec | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 8f60e1 mov edx, 0x1d8 |
| 0x8f6424 | 397 | stack_addr | L0 immediate | length is a constant from the instruction itself: 8f6419 mov edx, 0x1d8 |
| 0x8f6722 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 8f6717 mov edx, 0x1d8 |
| 0x8f8e8e | 188 | stack_addr | L0 immediate | length is a constant from the instruction itself: 8f8e86 mov edx, 0x78 |
| 0x8f9233 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 8f922b mov edx, 0x78 |
| 0x8f92e7 | 190 | stack_addr | L0 immediate | length is a constant from the instruction itself: 8f92df mov edx, 0x78 |
| 0x8fbd37 | 196 | stack_slot | L2 computed | GUARDED: r13=0 unless the header-size compare at 0x8fbcfc passes; src is a pointer loaded from [rbp-0x60] |
| 0x8fbd8d | 196 | stack_addr | L0 immediate | length is a constant from the instruction itself: 8fbd85 mov edx, 8 |
| 0x900ced | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x90f8ed | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x91e84d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x94ac96 | - | live_in | L0 immediate | length is a constant from the instruction itself: 94ac8b mov edx, 0x20 |
| 0x94ae2d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x95131a | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x951712 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x95cac0 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95cab8 mov edx, 8 |
| 0x95cbe3 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95cbdb mov edx, 4 |
| 0x95cc1a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95cc12 mov edx, 4 |
| 0x95cc56 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95cc4e mov edx, 0x10 |
| 0x95cf63 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95cf5b mov edx, 8 |
| 0x95cfc5 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95cfbd mov edx, 8 |
| 0x95d11a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95d112 mov edx, 4 |
| 0x95d14d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 95d145 mov edx, 4 |
| 0x95dabd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x95fbec | - | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x9699aa | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9699a2 mov edx, 1 |
| 0x969f7c | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 969f74 mov edx, 1 |
| 0x96a07c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 96a074 mov edx, 1 |
| 0x96a0a7 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 96a09f mov edx, 1 |
| 0x96fadf | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 96fad7 mov edx, 0x40 |
| 0x96ff8a | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 96ff82 mov edx, 0x40 |
| 0x970467 | - | derived_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x970682 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 97067a mov edx, 0xa8 |
| 0x970900 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9708f5 mov edx, 0x40 |
| 0x970969 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: 970961 mov edx, 0xa8 |
| 0x990c13 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x9912f3 | - | live_in | L3 unresolved by tool | not individually read (class unknown) |
| 0x9a71d2 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9a71ca mov edx, 0x1418 |
| 0x9af135 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9af12d mov edx, 0x10 |
| 0x9b01f4 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9b01ec mov edx, 0x78 |
| 0x9b025f | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9b0257 mov edx, 0x78 |
| 0x9b073b | - | stack_addr | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x9b140d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0x9c92fd | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9c92f2 mov edx, 8 |
| 0x9f8496 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9f848e mov edx, 4 |
| 0x9f9953 | - | live_in | L0 immediate | length is a constant from the instruction itself: 9f9944 mov edx, 4 |
| 0x9fdd8e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9fdd86 mov edx, 4 |
| 0x9fe119 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9fe10e mov edx, 0xd0 |
| 0x9fe1e1 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9fe1d9 mov edx, 4 |
| 0x9fe845 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9fe836 mov edx, 0xd0 |
| 0x9fe96a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9fe95b mov edx, 0xd0 |
| 0x9fe9d7 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: 9fe9cf mov edx, 4 |
| 0xa04e9e | - | live_in | L2 computed | not individually read (class arith) |
| 0xa051e3 | - | live_in | L2 address-derived | not individually read (class derived_addr) |
| 0xa070cb | - | derived_addr | L0 immediate | length is a constant from the instruction itself: a070c3 mov edx, 0x590 |
| 0xa07111 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xa0bb20 | 1 | arith | L0 immediate | length is a constant from the instruction itself: a0bb15 mov edx, 8 |
| 0xa17cb3 | - | live_in | L0 immediate | length is a constant from the instruction itself: a17ca4 mov edx, 4 |
| 0xa17d20 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: a17d15 mov edx, 8 |
| 0xa17d83 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: a17d7b mov edx, 8 |
| 0xa17db4 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: a17da9 mov edx, 8 |
| 0xa1cd3f | - | arith | L3 unresolved by tool | not individually read (class unknown) |
| 0xa1d3e1 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xa1d534 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xa2e7ce | - | stack_derived_addr | L0 immediate | length is a constant from the instruction itself: a2e7c6 mov edx, 4 |
| 0xa3634d | 652 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xa3664d | 652 | stack_imm | L2 stack slot | not individually read (class stack_slot) |
| 0xa36a5a | 602 | stack_addr | L2 address-derived | CLAMPED: len=r12-1 only when r12 < r14, and r14 <= 0x100 (bound set by copyinstr at 0xa3695c) |
| 0xa36a9d | 602 | stack_addr | L1 pass-through (incoming rdx) | CLAMPED: len=r14 <= 0x100, the length stored at td+0x5c8 by a previous copyinstr |
| 0xa4531d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xa4964d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xa827cd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xa8e25d | - | imm | L0 immediate | length is a constant from the instruction itself: a8e250 mov rdx, rbx |
| 0xa9b31a | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xab81fa | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ab81f2 mov edx, 0x470 |
| 0xaba6dd | 547 | stack_addr | L0 immediate | length is a constant from the instruction itself: aba6d5 mov edx, 0x18 |
| 0xabac3d | 547,572,674 | imm | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xabb173 | 572 | stack_addr | L1 pass-through (incoming rdx) | CLAMPED min(): 'mov r13d,0x48 / cmp eax,0x48 / cmovb r13d,eax'; src = 0x48-byte stack buf [rbp-0x78] |
| 0xabb38a | 572 | stack_addr | L3 unresolved by tool | CLAMPED min(): 'mov ebx,0x48 / cmp eax,0x48 / cmovb ebx,eax'; src = 0x48-byte stack buf [rbp-0x78] |
| 0xabbaff | 674 | live_in | L2 stack slot | CLAMPED min(): len = [rbp-0x108] = min(r12,0x48) computed at 0xabba46-0xabba65 |
| 0xabbcd6 | 674 | stack_addr | L2 stack slot | CLAMPED min(): len = [rbp-0x108] = min(r12,0x48), same function as 0xabbaff |
| 0xabc9f1 | 588 | stack_addr | L0 immediate | length is a constant from the instruction itself: abc9e9 mov edx, 0x88 |
| 0xabcb7c | 613 | stack_addr | L0 immediate | length is a constant from the instruction itself: abcb74 mov edx, 8 |
| 0xabcbac | 613 | stack_addr | L0 immediate | length is a constant from the instruction itself: abcba4 mov edx, 8 |
| 0xabcc5d | 615 | stack_addr | L0 immediate | length is a constant from the instruction itself: abcc55 mov edx, 8 |
| 0xabcc93 | 615 | stack_addr | L0 immediate | length is a constant from the instruction itself: abcc88 mov edx, 8 |
| 0xabd081 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: abd076 mov edx, 8 |
| 0xabd0c0 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: abd0b5 mov edx, 8 |
| 0xabe0b3 | 642 | stack_addr | L0 immediate | length is a constant from the instruction itself: abe0a4 mov edx, 0x68 |
| 0xabe155 | 642 | stack_addr | L0 immediate | length is a constant from the instruction itself: abe14d mov edx, 4 |
| 0xabe22a | 642 | stack_addr | L0 immediate | length is a constant from the instruction itself: abe21f mov edx, 0x3f8 |
| 0xacd54c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: acd541 mov edx, 0x20 |
| 0xacd6a3 | - | live_in | L0 immediate | length is a constant from the instruction itself: acd694 mov edx, 0x20 |
| 0xaceed7 | - | live_in | L2 stack slot | not individually read (class stack_slot) |
| 0xad1cea | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ad1ce2 mov edx, 0x140 |
| 0xadf0bd | - | derived_addr | L2 computed | not individually read (class arith) |
| 0xae375f | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ae3757 mov edx, 0x50 |
| 0xae379f | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ae3797 mov edx, 4 |
| 0xae3fcb | - | derived_addr | L2 address-derived | not individually read (class derived_addr) |
| 0xaf121e | 532 | stack_addr | L0 immediate | length is a constant from the instruction itself: af1216 mov edx, 4 |
| 0xaf13cd | 532 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xb124c3 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b124b8 mov edx, 0x10 |
| 0xb12bb0 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b12ba8 mov edx, 4 |
| 0xb12e62 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b12e5a mov edx, 0x50 |
| 0xb12ea7 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b12ea2 mov edx, 4 |
| 0xb1377d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b13775 mov edx, 0x2c |
| 0xb138dd | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b138d5 mov edx, 0x2c |
| 0xb139e1 | - | derived_addr | L2 address-derived | not individually read (class derived_addr) |
| 0xb13a2d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b13a28 mov edx, 4 |
| 0xb13b4d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b13b42 mov edx, 0x20 |
| 0xb13c4d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b13c42 mov edx, 0x10 |
| 0xb13d18 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b13d0d mov edx, 0x30 |
| 0xb13e4d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b13e42 mov edx, 0x14 |
| 0xb1410d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b14105 mov edx, 0xc |
| 0xb14366 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b1435e mov edx, 4 |
| 0xb147a3 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b14798 mov edx, 0x10 |
| 0xb149cd | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b149c5 mov edx, 0x40 |
| 0xb14d6d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b14d65 mov edx, 0x28 |
| 0xb15126 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b1511e mov edx, 0x38 |
| 0xb1564a | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b1563f mov edx, 0x44 |
| 0xb15ba4 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b15b99 mov edx, 0x10 |
| 0xb16164 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b16159 mov edx, 0x2c |
| 0xb1634f | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b16347 mov edx, 4 |
| 0xb1649b | - | stack_addr | L2 address-derived | not individually read (class derived_addr) |
| 0xb164d1 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b164c9 mov edx, 4 |
| 0xb2964c | 594,595 | stack_addr | L0 immediate | length is a constant from the instruction itself: b29643 mov edx, 8 |
| 0xb296a3 | 594,595 | stack_addr | L0 immediate | length is a constant from the instruction itself: b29697 mov edx, 4 |
| 0xb29726 | 594,595 | stack_addr | L0 immediate | length is a constant from the instruction itself: b29716 mov edx, 8 |
| 0xb29769 | 594,595 | stack_addr | L0 immediate | length is a constant from the instruction itself: b29759 mov edx, 4 |
| 0xb29ad7 | 594,595 | stack_addr | L0 immediate | length is a constant from the instruction itself: b29acb mov edx, 8 |
| 0xb2ca97 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: b2ca8f mov edx, 8 |
| 0xb2cb8d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xb2dca9 | 59 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2dca1 mov edx, 8 |
| 0xb2dd14 | 59 | arith | L0 immediate | length is a constant from the instruction itself: b2dd09 mov edx, 8 |
| 0xb2de78 | 59 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2de6c mov edx, 8 |
| 0xb2eb11 | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2eb05 mov edx, 8 |
| 0xb2eba9 | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2eb9d mov edx, 4 |
| 0xb2ec2a | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2ec1e mov edx, 8 |
| 0xb2ed3c | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2ed31 mov edx, 8 |
| 0xb2eddc | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2edd0 mov edx, 4 |
| 0xb2ee39 | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2ee2d mov edx, 8 |
| 0xb2eed3 | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2eec7 mov edx, 8 |
| 0xb2f108 | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2f0fc mov edx, 8 |
| 0xb2f1ad | 599 | stack_addr | L0 immediate | length is a constant from the instruction itself: b2f1a1 mov edx, 4 |
| 0xb2f262 | 599 | live_in | L0 immediate | length is a constant from the instruction itself: b2f257 mov edx, 8 |
| 0xb30f5a | 594,595 | stack_addr | L0 immediate | length is a constant from the instruction itself: b30f52 mov edx, 8 |
| 0xb42952 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: b4294a mov edx, 4 |
| 0xb43263 | - | live_in | L0 immediate | length is a constant from the instruction itself: b43254 mov edx, 8 |
| 0xb4339c | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: b43394 mov edx, 4 |
| 0xb43ae3 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: b43adb mov edx, 4 |
| 0xb5124f | - | imm | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xb5926b | - | arith | L2 stack slot | not individually read (class stack_unknown) |
| 0xb71fc5 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xba2f0d | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xba39cd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xbaed48 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: baed40 mov edx, 1 |
| 0xbaff6e | 539 | stack_addr | L0 immediate | length is a constant from the instruction itself: baff63 mov edx, 8 |
| 0xbb0023 | 539 | live_in | L0 immediate | length is a constant from the instruction itself: bb0014 mov edx, 4 |
| 0xbb00fb | 543 | stack_addr | L0 immediate | length is a constant from the instruction itself: bb00f0 mov edx, 8 |
| 0xbb0300 | 546 | stack_addr | L0 immediate | length is a constant from the instruction itself: bb02f8 mov edx, 4 |
| 0xbb11a8 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: bb119d mov edx, 4 |
| 0xbb11df | - | stack_addr | L0 immediate | length is a constant from the instruction itself: bb11d4 mov edx, 2 |
| 0xbb1216 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: bb120b mov edx, 4 |
| 0xbb183e | - | arith | L2 stack slot | not individually read (class stack_stack_slot) |
| 0xbb187d | - | stack_addr | L0 immediate | length is a constant from the instruction itself: bb1871 mov edx, 4 |
| 0xbb2880 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xbb29a2 | - | derived_addr | L0 immediate | length is a constant from the instruction itself: bb299a mov edx, 1 |
| 0xbb3afd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xbe83eb | 1,59,652 | stack_addr | L0 immediate | length is a constant from the instruction itself: be83e3 mov edx, 4 |
| 0xbe843d | 1,59,652 | stack_addr | L0 immediate | length is a constant from the instruction itself: be8435 mov edx, 0x90 |
| 0xbe856c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: be8564 mov edx, 4 |
| 0xbe85b2 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: be85aa mov edx, 0x120 |
| 0xbe85eb | - | stack_addr | L0 immediate | length is a constant from the instruction itself: be85e3 mov edx, 0x50 |
| 0xbe9893 | 652 | stack_addr | L0 immediate | length is a constant from the instruction itself: be988b mov edx, 4 |
| 0xbe9a0e | 652 | stack_addr | L0 immediate | length is a constant from the instruction itself: be9a06 mov edx, 4 |
| 0xbef538 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xbf114e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: bf1146 mov edx, 0x10 |
| 0xc00e2b | 622 | live_in | L2 stack slot | not individually read (class stack_derived_addr) |
| 0xc00e6e | 622 | live_in | L2 stack slot | not individually read (class stack_stack_slot) |
| 0xc00f03 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: c00efb mov edx, 4 |
| 0xc00f83 | 622 | live_in | L0 immediate | length is a constant from the instruction itself: c00f74 mov edx, 4 |
| 0xc01058 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: c01050 mov edx, 4 |
| 0xc010a7 | 622 | imm | L2 stack slot | not individually read (class stack_arith) |
| 0xc0112d | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: c01125 mov edx, 4 |
| 0xc01b33 | 622 | derived_addr | L0 immediate | length is a constant from the instruction itself: c01b2b mov edx, 4 |
| 0xc02abf | 622 | live_in | L2 computed | not individually read (class arith) |
| 0xc02af4 | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: c02aec mov edx, 4 |
| 0xc0305d | 622 | stack_imm | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xc0309a | 622 | stack_addr | L0 immediate | length is a constant from the instruction itself: c03092 mov edx, 4 |
| 0xc164a9 | 550 | stack_addr | L0 immediate | length is a constant from the instruction itself: c164a1 mov edx, 4 |
| 0xc166ed | 556 | stack_addr | L0 immediate | length is a constant from the instruction itself: c166e5 mov edx, 4 |
| 0xc3494e | - | stack_addr | L0 immediate | length is a constant from the instruction itself: c34946 mov edx, 4 |
| 0xc37934 | 421 | stack_addr | L0 immediate | length is a constant from the instruction itself: c37929 mov edx, 0x4c0 |
| 0xc37b03 | 422 | stack_addr | L0 immediate | length is a constant from the instruction itself: c37af8 mov edx, 0x4c0 |
| 0xc3854d | - | arith | L2 computed | not individually read (class arith) |
| 0xc42840 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: c42838 mov edx, 8 |
| 0xc435d4 | 407 | stack_addr | L0 immediate | length is a constant from the instruction itself: c435cc mov edx, 4 |
| 0xc51b98 | - | live_in | L2 computed | not individually read (class arith) |
| 0xc51cd6 | - | derived_addr | L2 stack slot | not individually read (class stack_derived_addr) |
| 0xc522e3 | - | live_in | L0 immediate | length is a constant from the instruction itself: c522d4 mov edx, 0x20 |
| 0xc80b90 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: c80b88 mov edx, 0x20 |
| 0xc813cd | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xc884ba | - | stack_addr | L0 immediate | length is a constant from the instruction itself: c884b2 mov edx, 0x40 |
| 0xc888a5 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: c8889d mov edx, 8 |
| 0xc888d5 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: c888cd mov edx, 8 |
| 0xc88c83 | - | live_in | L0 immediate | length is a constant from the instruction itself: c88c74 mov edx, 4 |
| 0xc89b3d | - | stack_slot | L2 stack slot | not individually read (class stack_slot) |
| 0xc9593f | - | imm | L3 unresolved by tool | not individually read (class unknown) |
| 0xc95ba6 | - | arith | L2 computed | not individually read (class arith) |
| 0xc97177 | 652 | arith | L0 immediate | length is a constant from the instruction itself: c9715e mov edx, 8 |
| 0xc97252 | 652 | stack_addr | L0 immediate | length is a constant from the instruction itself: c9724a mov edx, 0x10 |
| 0xc97296 | 652 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xc9add0 | - | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xc9ae3d | 601 | live_in | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xc9c127 | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xc9ef0a | - | live_in | L2 stack slot | not individually read (class stack_slot) |
| 0xc9f15a | - | stack_slot | L1 pass-through (incoming rdx) | length is an incoming argument; bound, if any, is at the caller (not read) |
| 0xca0a9a | 601 | stack_addr | L0 immediate | length is a constant from the instruction itself: ca0a92 mov edx, 4 |
| 0xca0f31 | 601 | stack_addr | L0 immediate | length is a constant from the instruction itself: ca0f29 mov edx, 8 |
| 0xca18a4 | 601 | stack_addr | L0 immediate | length is a constant from the instruction itself: ca189c mov edx, 8 |
| 0xca197b | 601 | stack_addr | L3 unresolved by tool | CLAMPED min(): 'mov ebx,0x28 / cmp r12,0x28 / cmovb rbx,r12'; src = 0x28-byte stack buf [rbp-0xf0] |
| 0xca1b8b | 601 | live_in | L0 immediate | length is a constant from the instruction itself: ca1b80 mov edx, 0x480 |
| 0xca1c50 | 601 | stack_addr | L0 immediate | length is a constant from the instruction itself: ca1c45 mov edx, 0x70 |
| 0xca2dc2 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ca2dba mov edx, 8 |
| 0xca2f83 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ca2f7e mov edx, 8 |
| 0xca6d97 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ca6d8b mov edx, 1 |
| 0xca6ddb | - | stack_derived_addr | L2 stack slot | not individually read (class stack_live_in) |
| 0xca6e16 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ca6e0a mov edx, 1 |
| 0xca6e58 | - | stack_derived_addr | L2 address-derived | not individually read (class derived_addr) |
| 0xca6e92 | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ca6e86 mov edx, 1 |
| 0xca6f2c | - | stack_addr | L0 immediate | length is a constant from the instruction itself: ca6f24 mov edx, 1 |

## 3. Sites examined by hand

Every non-immediate-length site that sits directly inside a syscall handler body was
read end to end: 17 sites in 13 distinct handler bodies. Four more sites from the
tool-unresolved list were also read by hand, so the table below has 21 rows.
**All 21 have a visible clamp.** No site in this image hands userland more bytes than
the source buffer holds. The verdicts:

| site | handler | length is | clamp mechanism |
|---|---|---|---|
| 0x2a8e42 | 43 | derived_addr | CLAMPED cmp+reject: 'cmp edx,r12d / jb EINVAL' at 0x2a8e2e before the call; len = kernel object field [obj+0x10]*4 |
| 0x2ab76d | 49 | unknown | CLAMPED cmp+reject: uap[1] clamped to <=0x21 at 0x2ab6b7, then 'cmp r15,argc / ja EINVAL' at 0x2ab744; src = 0x30-byte stack buf |
| 0x3c1d93 | indirect | unknown | CLAMPED by construction: copyinstr bound 0x3ff, then strnlen(buf,0x3ff)+1 |
| 0x3c2093 | indirect | unknown | CLAMPED by construction: copyin 8 bytes, then strnlen(buf,0x3ff)+1 |
| 0x409809 | 392 | arith | SAFE alloc-then-copy-same-size: malloc(r15<<4) at 0x4097d3, copyout len = r15<<4 |
| 0x438d40 | 464 | derived_addr | CLAMPED by construction: src 0x28 stack buf filled by a 0x20-byte copy, len = strnlen(buf,0x1f)+1 <= 32 |
| 0x4ed0f5 | 54 | live_in | CLAMPED: len=(uap[1]>>16)&0x1fff; src = 0x80-byte stack slot when len<0x81, else malloc(len) |
| 0x4f757f | 604 | live_in | ZERO LENGTH on the observed path ('xor r13d,r13d' at 0x4f755c) |
| 0x531b1d | 135 | live_in | PASS-THROUGH tail jmp; length is the caller's rdx (see 5.3) |
| 0x5330d5 | 32 | live_in | KERNEL-DERIVED: len=[rbp-0x3c] and src=[rbp-0x38] are both outputs of helper 0x8aef2e60 |
| 0x5333b5 | 31 | live_in | KERNEL-DERIVED: len=[rbp-0x3c] and src=[rbp-0x38] are both outputs of helper 0x8aef3160 |
| 0x7a4061 | indirect | unknown | CLAMPED min(): 'cmp r13,0x20 / cmovb rbx,r13'; src = stack buf [rbp-0x5b0] |
| 0x86a2d2 | indirect | unknown | kernel-derived: len=rbx set by the helper at 0x8b14f470; src = stack buf [rbp-0x68] |
| 0x8fbd37 | 196 | arith | GUARDED: r13=0 unless the header-size compare at 0x8fbcfc passes; src is a pointer loaded from [rbp-0x60] |
| 0xa36a5a | 602 | derived_addr | CLAMPED: len=r12-1 only when r12 < r14, and r14 <= 0x100 (bound set by copyinstr at 0xa3695c) |
| 0xa36a9d | 602 | live_in | CLAMPED: len=r14 <= 0x100, the length stored at td+0x5c8 by a previous copyinstr |
| 0xabb173 | 572 | live_in | CLAMPED min(): 'mov r13d,0x48 / cmp eax,0x48 / cmovb r13d,eax'; src = 0x48-byte stack buf [rbp-0x78] |
| 0xabb38a | 572 | unknown | CLAMPED min(): 'mov ebx,0x48 / cmp eax,0x48 / cmovb ebx,eax'; src = 0x48-byte stack buf [rbp-0x78] |
| 0xabbaff | 674 | stack_slot | CLAMPED min(): len = [rbp-0x108] = min(r12,0x48) computed at 0xabba46-0xabba65 |
| 0xabbcd6 | 674 | stack_slot | CLAMPED min(): len = [rbp-0x108] = min(r12,0x48), same function as 0xabbaff |
| 0xca197b | 601 | unknown | CLAMPED min(): 'mov ebx,0x28 / cmp r12,0x28 / cmovb rbx,r12'; src = 0x28-byte stack buf [rbp-0xf0] |

### 3.1 Disassembly of the interesting shapes

#### 0x4ed032-0x4ed0f8  syscall 54: user-controlled 13-bit length, allocate-then-copy-same-size

```
004ed032  48898548ffffff               mov qword ptr [rbp - 0xb8], rax
004ed039  4c89bd38ffffff               mov qword ptr [rbp - 0xc8], r15
004ed040  4585f6                       test r14d, r14d
004ed043  781d                         js 0xffffffff8aead062
004ed045  4c8bbd48ffffff               mov r15, qword ptr [rbp - 0xb8]
004ed04c  41f7c600000040               test r14d, 0x40000000
004ed053  7456                         je 0xffffffff8aead0ab
004ed055  4489e6                       mov esi, r12d
004ed058  4c89ff                       mov rdi, r15
004ed05b  e890bfd6ff                   call 0xffffffff8ac18ff0
004ed060  eb49                         jmp 0xffffffff8aead0ab
004ed062  4489e0                       mov eax, r12d
004ed065  4c8b6b10                     mov r13, qword ptr [rbx + 0x10]
004ed069  488d35cdaeea00               lea rsi, [rip + 0xeaaecd]
004ed070  31d2                         xor edx, edx
004ed072  48898540ffffff               mov qword ptr [rbp - 0xc0], rax
004ed079  65488b3c2500000000           mov rdi, qword ptr gs:[0]
004ed082  e859d37200                   call 0xffffffff8b5da3e0
004ed087  4c8bbd48ffffff               mov r15, qword ptr [rbp - 0xb8]
004ed08e  488b9540ffffff               mov rdx, qword ptr [rbp - 0xc0]
004ed095  4c89ef                       mov rdi, r13
004ed098  4c8d2d71f24203               lea r13, [rip + 0x342f271]
004ed09f  4c89fe                       mov rsi, r15
004ed0a2  e8d9c1d6ff                   call 0xffffffff8ac19280
004ed0a7  85c0                         test eax, eax
004ed0a9  754f                         jne 0xffffffff8aead0fa
004ed0ab  8b33                         mov esi, dword ptr [rbx]
004ed0ad  488bbd38ffffff               mov rdi, qword ptr [rbp - 0xc8]
004ed0b4  4c89f2                       mov rdx, r14
004ed0b7  4c89f9                       mov rcx, r15
```

#### 0xabb137-0xabb178  handler 572: min() clamp to 0x48

```
00abb137  488b8500ffffff               mov rax, qword ptr [rbp - 0x100]
00abb13e  41bd48000000                 mov r13d, 0x48
00abb144  488d354c418900               lea rsi, [rip + 0x89414c]
00abb14b  488b5810                     mov rbx, qword ptr [rax + 0x10]
00abb14f  8b4018                       mov eax, dword ptr [rax + 0x18]
00abb152  83f848                       cmp eax, 0x48
00abb155  440f42e8                     cmovb r13d, eax
00abb159  65488b3c2500000000           mov rdi, qword ptr gs:[0]
00abb162  31d2                         xor edx, edx
00abb164  e877f21500                   call 0xffffffff8b5da3e0
00abb169  488d7d88                     lea rdi, [rbp - 0x78]
00abb16d  4889de                       mov rsi, rbx
00abb170  4c89ea                       mov rdx, r13
00abb173  e858e079ff                   call 0xffffffff8ac191d0
00abb178  4189c5                       mov r13d, eax
00abb17b  498b4708                     mov rax, qword ptr [r15 + 8]
```

#### 0xca1943-0xca1980  handler 601: min() clamp to 0x28

```
00ca1943  4181e4ffffff7f               and r12d, 0x7fffffff
00ca194a  bb28000000                   mov ebx, 0x28
00ca194f  488d3541d96a00               lea rsi, [rip + 0x6ad941]
00ca1956  4983fc28                     cmp r12, 0x28
00ca195a  490f42dc                     cmovb rbx, r12
00ca195e  65488b3c2500000000           mov rdi, qword ptr gs:[0]
00ca1967  31d2                         xor edx, edx
00ca1969  e8728af7ff                   call 0xffffffff8b5da3e0
00ca196e  488dbd10ffffff               lea rdi, [rbp - 0xf0]
00ca1975  4c89fe                       mov rsi, r15
00ca1978  4889da                       mov rdx, rbx
00ca197b  e850785bff                   call 0xffffffff8ac191d0
00ca1980  4189c6                       mov r14d, eax
00ca1983  85c0                         test eax, eax
00ca1985  0f858a080000                 jne 0xffffffff8b662215
```

#### 0x4097b7-0x40980e  handler 392: allocate r15<<4, copy out r15<<4

```
004097b7  488d1dc2287f02               lea rbx, [rip + 0x27f28c2]
004097be  4d89fc                       mov r12, r15
004097c1  4989f6                       mov r14, rsi
004097c4  ba02000000                   mov edx, 2
004097c9  49c1e404                     shl r12, 4
004097cd  4c89e7                       mov rdi, r12
004097d0  4889de                       mov rsi, rbx
004097d3  e878f37f00                   call 0xffffffff8b5c8b50
004097d8  4889c7                       mov rdi, rax
004097db  4c89fe                       mov rsi, r15
004097de  4989c5                       mov r13, rax
004097e1  e8bafdffff                   call 0xffffffff8adc95a0
004097e6  4d8b36                       mov r14, qword ptr [r14]
004097e9  65488b3c2500000000           mov rdi, qword ptr gs:[0]
004097f2  488d359e5af400               lea rsi, [rip + 0xf45a9e]
004097f9  31d2                         xor edx, edx
004097fb  e8e00b8100                   call 0xffffffff8b5da3e0
00409800  4c89ef                       mov rdi, r13
00409803  4c89f6                       mov rsi, r14
00409806  4c89e2                       mov rdx, r12
00409809  e8c2f9e4ff                   call 0xffffffff8ac191d0
```

#### 0x2ab6f3-0x2ab771  handler 49: compare-and-reject before the call

```
002ab6f3  498b85380b0000               mov rax, qword ptr [r13 + 0xb38]
002ab6fa  8b5308                       mov edx, dword ptr [rbx + 8]
002ab6fd  488d7da0                     lea rdi, [rbp - 0x60]
002ab701  488b7018                     mov rsi, qword ptr [rax + 0x18]
002ab705  4883c62c                     add rsi, 0x2c
002ab709  e862c46a00                   call 0xffffffff8b317b70
002ab70e  498bbd380b0000               mov rdi, qword ptr [r13 + 0xb38]
002ab715  4989c7                       mov r15, rax
002ab718  31f6                         xor esi, esi
002ab71a  31d2                         xor edx, edx
002ab71c  31c9                         xor ecx, ecx
002ab71e  49ffc7                       inc r15
002ab721  488b7f18                     mov rdi, qword ptr [rdi + 0x18]
002ab725  4883c770                     add rdi, 0x70
002ab729  e872b82100                   call 0xffffffff8ae86fa0
002ab72e  4c89f7                       mov rdi, r14
002ab731  31f6                         xor esi, esi
002ab733  31d2                         xor edx, edx
002ab735  31c9                         xor ecx, ecx
002ab737  e864b82100                   call 0xffffffff8ae86fa0
002ab73c  8b4b08                       mov ecx, dword ptr [rbx + 8]
002ab73f  b822000000                   mov eax, 0x22
002ab744  4939cf                       cmp r15, rcx
002ab747  7729                         ja 0xffffffff8ac6b772
002ab749  488b1b                       mov rbx, qword ptr [rbx]
002ab74c  65488b3c2500000000           mov rdi, qword ptr gs:[0]
002ab755  488d353b3b0a01               lea rsi, [rip + 0x10a3b3b]
002ab75c  31d2                         xor edx, edx
```

#### 0xa36a28-0xa36aa2  handler 602: length bounded by a previous copyinstr

```
00a36a28  4c8b7b08                     mov r15, qword ptr [rbx + 8]
00a36a2c  4d39f4                       cmp r12, r14
00a36a2f  7348                         jae 0xffffffff8b3f6a79
00a36a31  65488b3c2500000000           mov rdi, qword ptr gs:[0]
00a36a3a  488d3556889100               lea rsi, [rip + 0x918856]
00a36a41  31d2                         xor edx, edx
00a36a43  4d8d6c24ff                   lea r13, [r12 - 1]
00a36a48  e893391e00                   call 0xffffffff8b5da3e0
00a36a4d  488dbdd0fdffff               lea rdi, [rbp - 0x230]
00a36a54  4c89fe                       mov rsi, r15
00a36a57  4c89ea                       mov rdx, r13
00a36a5a  e8712782ff                   call 0xffffffff8ac191d0
00a36a5f  85c0                         test eax, eax
00a36a61  7565                         jne 0xffffffff8b3f6ac8
00a36a63  488b4308                     mov rax, qword ptr [rbx + 8]
00a36a67  31f6                         xor esi, esi
00a36a69  4a8d7c20ff                   lea rdi, [rax + r12 - 1]
00a36a6e  e80d2e82ff                   call 0xffffffff8ac19880
00a36a73  85c0                         test eax, eax
00a36a75  7551                         jne 0xffffffff8b3f6ac8
00a36a77  eb2d                         jmp 0xffffffff8b3f6aa6
00a36a79  65488b3c2500000000           mov rdi, qword ptr gs:[0]
00a36a82  488d350e889100               lea rsi, [rip + 0x91880e]
00a36a89  31d2                         xor edx, edx
00a36a8b  e850391e00                   call 0xffffffff8b5da3e0
00a36a90  488dbdd0fdffff               lea rdi, [rbp - 0x230]
```

### 3.2 What the clamps look like

Four distinct idioms were found, and every non-immediate-length handler site uses one
of them:

1. **min() via cmov** - mov ebx, 0x28 / cmp r12, 0x28 / cmovb rbx, r12, then copyout
   with rbx. The source is a stack buffer of exactly that size. Seen at 0xca197b,
   0xabb173, 0xabb38a, 0xabbaff, 0xabbcd6, 0x7a4061.
2. **compare and reject** - cmp r15, rcx / ja error immediately before the call, with
   the compared value being the user's own count. Seen at 0x2ab76d, 0x2a8e42.
3. **allocate then copy the same value** - the copyout length and the allocation size
   are the same register, so the buffer is exactly as large as the copy. Seen at
   0x409809 (malloc(r15<<4) then copyout r15<<4) and 0x4ed0f5 (0x80 stack slot or
   malloc(len)).
4. **bounded string copy** - the source is filled by copyinstr with an explicit bound
   and the length is strnlen of that same buffer, plus one for the NUL. Seen at
   0x438d40, 0x3c1d93, 0x3c2093, 0xa36a5a, 0xa36a9d.

## 4. Verdict

No unclamped user-controlled copyout was found in this image.

* 616 copyout sites; 539 calls, 77 tail jumps.
* 415 have a compile-time constant length and cannot over-read.
* 192 have a non-constant length. 17 of those sit directly in a syscall handler body
  and were read instruction by instruction; all 17 clamp, using one of the four
  idioms in 3.2.
* The dominant non-constant class, 112 sites, is a pass-through: the function takes
  the length as an argument and forwards it, so the bound is the caller's
  responsibility. The family is easy to recognise (save r15/r14/rbx, call the logging
  helper 0x8b5da3e0 with edx=0, restore, tail-jump to 0x2591d0); see 5.3.
* 21 sites were not resolved by the tool. 5 of those were read by hand (0x2ab76d,
  0x7a4061, 0x3c1d93, 0x3c2093, 0xabb38a) and all five clamp; the remaining 16 are
  listed in 5.5 as open.

This is a negative result, and a plausible one: the copyout helper's own fault handler
only protects the user side, so the kernel's authors had to put the bound in every
caller, and in the sites that were read they did. A read primitive here would have to
be a single caller that forgot, not a systematic gap.

## 5. Caveats

### 5.1 Wrong image version
This is the big one. The workspace holds only `dumps_13.60`. Nothing in this report
was verified against a 14.10 image, and RVA-level differences between 13.60 and 14.10
are certain. Treat every RVA as 13.60 until a 14.10 text dump is available.

### 5.2 Function-start heuristic
Enclosing functions were found by scanning for runs of >=3 identical 0x90 or 0xcc
bytes and taking the following address, which yields 32163 candidates. It lands exactly
on the known helper entries (0x258ff0, 0x2590b0, 0x259280) but it also produces false
starts inside functions that pad with nops, and it misses functions that do not. One
concrete example: site 0x438d40 was attributed to 0x438b60, but 0x438b60 ends with a
ret at 0x438c87 and 0x438d40 actually belongs to 0x438c90. Counts of 'distinct
functions containing a copyout' (414) inherit that error and should be read as
approximate.

### 5.3 Pass-through sites and their callers
The 112 pass-through sites cannot be cleared from the callee side: the function never
touches rdx. Clearing them requires following every caller, and one level of that was
attempted and abandoned as unsound: a call into a function that contains a copyout is
not necessarily a call to that copyout. Example: 0x34ab22 calls 0x34b4d0, which does
contain a copyout, but the registers at the call (rdi = &[rbp-0x8a4], rsi = [rax+0x10])
have nothing to do with length. The 609-caller / 347-non-constant figure produced by
that pass is therefore reported as a lead, not as evidence.

### 5.4 Indirect dispatch
388 of the 607 classified sites have no syscall number reachable through direct call
edges. In this kernel that is expected: file operations, socket operations and driver
entries go through VOP/cdev function-pointer tables. Static call-graph attribution
under-reports reachability; it does not mean the sites are unreachable.

### 5.5 What was not read
16 sites with unresolved length remain unread (0x347613, 0x39f3cf, 0x39f470, 0x465e77,
0x49edf7, 0x4fd4b2, 0x50c013, 0x7a5a26, 0x7ab4c3, 0x7ac692, 0x95fbec, 0x9912f3,
0xa1cd3f, 0xc9593f, 0x86a2d2 partly). They are listed here so the next pass does not
have to rediscover them.
