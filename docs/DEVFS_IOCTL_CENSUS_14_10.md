# DEVFS / cdev-method census -- PS5 14.10 (13.60 text capture)

Scope: C:\PS5contrib\docs\dumps_13.60\kernel_text.bin (base 0xffffffff8a9c0000,
file offset == RVA, len 0xE6E5C0). One pass of byte/pointer matching over the raw
image, capstone only on windows <= 0x400 starting at function entry. Every
instruction quoted below was re-decoded from the image.

## 1. Verdict

The /dev method surface cannot be completed on this capture: there is no cdevsw
array, no devfs node table and no d_name string in the file. The image holds no
ASCII device names at all (b"/dev/", b"tty", b"cdev", b"FreeBSD" each occur 0
times in 15 MB), so the classic "node -> cdev -> cdevsw -> d_methods" walk has no
anchor. Absence of the table is a property of the capture, not evidence that the
drivers are unreachable.

What the capture does contain is one 28-slot method vector at 0xe6baa0 -- the
only pointer array in the image whose members are device-style bodies that take
user memory. 14 of its 28 slots reach copyin, 1 reaches copyout. All 15 copies are
bounded or fixed-length; every copyin destination is a stack buffer, and the
single copyout sources from a stack dword. No kernel-memory disclosure site was
found in this vector.

Two sites are worth probing first because they accept caller-shaped input:
  * 0x382480 (slot 0x2656a8) takes a user array of path pointers plus a count,
    copyin's it 128 entries at a time and opens each path in kernel context.
  * 0x383800 (slot 0x2656d8) copyin's a length-prefixed header and stores the
    copied qword into a kernel object at +0x3d8.

## 2. Table inventory

Scan: qwords whose value lands in [0xffffffff8a9c0000, 0xffffffff8b82e5c0-0x1000).
604 such qwords exist (0.032% of the file); 23 runs of >= 4 consecutive; grouped
at gap <= 0x40 into 44 clusters, 520 slots. All of them live in the final 0x64 KB
of .data, RVA 0xe56fc0..0xe6d390. There is no run of code pointers anywhere else
in the image, and none in the 0x0-0x250000 region (that region is 0xCC filler
with ~2.3% non-CC -- an uncaptured area, not code).

Slot targets: 454 point into text (0x250000-0xCC0000), 42 into data, 24 into the
uncaptured low region. Cross-check against docs/dumps_13.60/sysent_index.json
(679 entries, sy_call_off 0x25dc28..0x265fa8): the overlap between the 520 slots
and any sy_call_off is 0 -- these are not sysent entries.

Largest / most regular clusters (rva, slots, stride):

  0xe5fd80  104 16        0xe60d70   66 16        0xe5f630  62 8/16 mixed
  0xe605b8   41 16        0xe6d148   40 mixed     0xe61cf8  28 mixed
  0xe6baa0   28  8 (contiguous)      0xe5fc08  25 16
  0xe6bc40   24 mixed     0xe5eee8   16 16

Median stride over 44 clusters: 16 (x13), 8 (x12), mixed/0 (x11), 24 (x8). The
stride-16 clusters read as 2-qword records (id, fn), not as method vectors. Only
0xe6baa0 is a dense array of 28 consecutive function pointers.

Vector 0xe6baa0, 28 slots, 0x265608,0x265608,0x265610..0x2656d8. Every slot is an
8-byte stub whose bytes are "e9 rel32" (e.g. slot 0x265760 elsewhere in the same
stub band: e9 7b c9 2f 00 cc cc cc -> 0x5600e0), so the stub adds no marshalling
and the bodies are entered with the caller's rdi/rsi intact. Slot targets
0x37faa0..0x383800 form one contiguous driver body range.

Call mix over all 520 decoded bodies: copyin 14, copyout 1, memcpy 6, bzero 6.

## 3. Per-site findings (all 15 user-memory copies in the image)

arg = the second-argument descriptor at rsi; fields referenced are [arg+0x00],
[arg+0x10], [arg+0x18], [arg+0x20].

| slot     | body     | copy (dir)            | length provenance           | source / dest                             | bound |
|----------|----------|-----------------------|-----------------------------|-------------------------------------------|-------|
| 0x265610 | 0x37faa0 | copyin @0x37fb2a      | imm 0x10 (r13d)             | user ptr [arg+0x20] -> stack [rbp-0x48]   | YES   |
| 0x265618 | 0x37fbc0 | copyout @0x37fc4f     | imm 0x4                     | stack [rbp-0x1c] -> user ptr [arg+0x18]   | n/a   |
| 0x265620 | 0x37fc70 | copyin @0x37fd0e      | 0x10 normal / 0x18 diag     | user ptr [arg+0x20] -> stack [rbp-0x48]   | YES   |
| 0x265628 | 0x37fc90 | copyin @0x37fd0e(same)| 0x10 / 0x18                 | same tail as above                        | YES   |
| 0x265640 | 0x380260 | copyin @0x3802b4      | imm 0x10 (edx)              | user ptr [arg+0x20] -> stack [rbp-0x78]   | fixed |
| 0x265658 | 0x381140 | copyin @0x3811be      | 0x10 normal / 0x18 diag     | user ptr -> stack [rbp-0x48]              | YES   |
| 0x265660 | 0x381230 | copyin @0x3812d9      | 0x18 (diag arm only)        | user ptr [arg+0x20] -> stack [rbp-0x48]   | YES   |
| 0x265668 | 0x381330 | copyin @0x3813d2      | 0x10 normal / 0x18 diag     | user ptr [arg+0x20] -> stack [rbp-0x48]   | YES   |
| 0x265678 | 0x381900 | copyin @0x38197e      | 0x10 / 0x18                 | user ptr -> stack [rbp-0x48]              | YES   |
| 0x265680 | 0x3819f0 | copyin @0x381a8e      | 0x10 / 0x18                 | user ptr -> stack [rbp-0x48]              | YES   |
| 0x265688 | 0x381a10 | copyin @0x381a8e(same)| 0x10 / 0x18                 | shared tail with 0x3819f0                 | YES   |
| 0x265698 | 0x381e70 | copyin @0x381eed      | 0x10 / 0x18                 | user ptr -> stack [rbp-0x80]              | YES   |
| 0x2656a8 | 0x382480 | copyin @0x38250a      | count [arg+0x10], clamp 0x80| base [arg+0x00]+idx*8 -> stack [rbp-0x430]| YES   |
| 0x2656c0 | 0x383120 | copyin @0x38319d      | 0x10 / 0x18                 | user ptr -> stack [rbp-0x78]              | YES   |
| 0x2656d8 | 0x383800 | copyin @0x38386b      | field [arg+0x10] <= 0x18    | user ptr [arg+0x18] -> stack [rbp-0x48]   | YES   |

Bound checks, re-decoded:

  37faa0: cmp qword ptr [r14 + 0x18], 0x10 ; ja 0x37fb93
  381330: cmp qword ptr [rsi + 0x18], 0x10  ; ja 0x3813a5
  383800: cmp qword ptr [rsi + 0x10], 0x18  ; ja 0x383897
  382480: cmp r13d, 0x80 ; mov ebx, 0x80 ; cmovb ebx, r13d  ("chunk = min(count,128)")

The 0x10/0x18 pairs are one code path: the normal arm sets r13d/r15d = 0x10, the
rejection arm sets 0x18 and still copies 0x18 bytes from the user pointer into the
same stack slot. The destination is sized for 0x18, so this is a diagnostic copy,
not an overflow.

Kernel-memory disclosure: none. The only copyout (0x37fbc0) is
  lea rdi, [rbp - 0x1c] ; mov edx, 4 ; mov rsi, rbx ; call 0x2591d0
with rbx derived from [arg+0x18] as the user destination. Source is a stack
dword; no kernel object field is exposed.

Body 0x382480 (slot 0x2656a8) in full shape:

  3824a2 mov  r13d, dword ptr [rsi + 0x10]     ; count, caller-controlled
  3824af mov  rax, qword ptr [rsi]             ; base (user pointer)
  3824c0 cmp  r13d, 0x80
  3824c7 mov  ebx, 0x80
  3824d3 movsxd rax, r14d
  3824dd cmovb ebx, r13d                       ; chunk = min(count, 128)
  3824ec lea  r12d, [rbx*8]                    ; len = chunk * 8 (<= 0x400)
  3824f4 lea  r15, [rcx + rax*8]               ; src = base + index*8
  3824fd mov  rdi, r15 ; lea rsi,[rbp-0x430] ; mov rdx, r12 ; call 0x259280
  382520 mov  rsi, qword ptr [rbp + r12*8 - 0x430]   ; walk copied qwords
  382528 mov  edx, 0x7fffffff
  38252d mov  ecx, 1
  382532 xor  r8d, r8d
  382535 call 0x37e2f0

0x37e2f0 is a pathname helper: it calls 0x37de50 (lookup) and 0x37dfa0, then
0x4c6a00 on [rax+0x18]. So the batched copyin brings in an array of user string
pointers that are then opened with a 0x7fffffff maximum length. This is a
user-controlled path-array open executed in kernel context -- the most useful
surface in the vector, because it is not obviously restricted to the node the fd
came from.

Body 0x383800 (slot 0x2656d8):

  383820 mov  eax, 0x16
  383825 cmp  qword ptr [rsi + 0x10], 0x18 ; ja 0x383897
  383836 mov  esi, 0x18 ; mov rdi, r15 ; call 0x258ff0   (bzero stack, 0x18)
  383843 mov  r12, qword ptr [r14 + 0x10]     ; len <= 0x18
  383847 mov  r14, qword ptr [r14 + 0x18]     ; user pointer
  38386b call 0x259280                        ; copyin(user ptr, stack, len)
  383874 mov  rax, qword ptr [rbp - 0x48]
  383878 mov  qword ptr [rbx + 0x3d8], rax    ; copied qword stored into kernel object

## 4. Probe these first, and how

The vector is not bound to a device name in this capture, so the first step is
attribution, not exploitation: find the fd whose read/write/ioctl reaches
0xe6baa0. The copyout slot gives a cheap fingerprint.

Step 0 -- build the two argument descriptors in user memory:
  descA (16 bytes):  +0x00 = 0 (unused)          +0x08 = 0
                     +0x10 = 0x4 (count)         +0x18 = &canary (dest ptr)
  descB (0x28 bytes): +0x00 = base array ptr     +0x10 = dword 1
                      +0x18 = 0x18 (len)         +0x20 = &src16
  base array: 128 qwords, entry[i] = pointer to the string to open.

Step 1 -- enumerate: take the 34 openable nodes from
docs/DEVFS_NAMESPACE_14_10.md, open each with make_syscall(open), and for every
fd issue, in order, read(fd, descA, n) then ioctl(fd, cmd, descA) for
cmd in 0x00..0x40. Set canary = 0x4141414141414141 before each call.

Step 2 -- fingerprint: if the 4-byte copyout arm is reached, the low dword at
&canary is overwritten with a non-canary value and the call returns 0. That
identifies the fd and cmd bound to slot 0x265618 in the same vector.

Step 3 -- on that fd, repeat with descB where base[0] points at a string the game
process itself is denied, e.g. "/dev/deci_tty" or "/app0/eboot.bin". If the
path-array open runs with kernel credentials, later slots in the same vector
(0x2656a8 walk, 0x2656d8 header copyin) become reachable with kernel-side effect.
Record the returned values, not an interpretation.

Step 4 -- only after the fd is pinned: probe 0x383800 (slot 0x2656d8) with
desc at +0x10 = 0x18, +0x18 = a 0x18-byte user buffer; watch whether the value
at kernel object +0x3d8 influences the next call (the store at 0x383878 is the
only visible side effect in that body).

If no fd produces the canary overwrite, the vector is not reachable from the
14.10 game process at all and the probe direction closes.

## 5. Limits of this method

- The capture has no strings, no cdevsw, no devfs node array. No claim is made
  about which driver 0xe6baa0 belongs to, how many devices exist, or which of the
  78 enumerated /dev names map to it. The 28 slots are an upper bound on what the
  vector exposes, not a cdevsw d_methods count.
- xrefs are unavailable: all bodies begin with lea r13/r12,[rip+0x359xxxxx] and a
  log call to 0xc1a3e0 with rdi = gs:[0] (curthread). The pointed-to global and
  every string live outside the captured file, so callers and diagnostics cannot
  be resolved from this image.
- 24 slots and all 454 non-vector cluster members target addresses that are not
  decoded further here; the 0x0-0x250000 region is filler in this capture.
- Only direct "call 0x259280 / 0x2591d0" sites were counted. Indirect calls,
  inlined copies and memcpy-based copies (6 bodies use memcpy) are outside the
  census; a memcpy from a kernel field would not be flagged by this method.
- "Bound" means a compare on the length or index in the same body before the
  copy. It does not assert the destination is correctly sized for every path, and
  it says nothing about races or refcount lifetime.
- Runtime reachability is unverified: nothing in this analysis shows that the
  vector is callable from the game process.
