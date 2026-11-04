# The privilege mask: reader at 0x8b4ebb00, writer at sys 597

**Status:** STATIC (13.60 image, `docs/dumps_13.60/kernel_text.bin`, base `0xffffffff8a9c0000`,
file offset == RVA). The behavioural half of this note is staged as probe 1199a and is **not
measured**; the console was unreachable (ICMP "destination host unreachable") when it was written.

## The reader

`0x8b4ebb00` (RVA `0xb2bb00`) is the level query every Sony gate in the 600..680 range funnels
through:

```
b2bb00  push rbp ; mov rbp,rsp
b2bb04  mov rax, gs:[0]              ; curthread
b2bb0d  mov rax, [rax+8]             ; td_proc
b2bb11  mov rcx, [rax+0x3e8]         ; the loader / dynlib context hanging off the proc
b2bb18  test rcx,rcx ; je ret1       ; no context -> return 1
b2bb1d  xor eax,eax
b2bb1f  test dword ptr [rcx+0x140], edi    ; <-- THE MASK, edi = level
b2bb25  setne al ; ret
```

So "privilege" is a 32-bit bitmask at `[[td_proc+0x3e8]+0x140]`, tested against a level argument.
No context at all means *privileged*, which is why a process without a loader context passes gates.

Seven call sites exist in the whole 15.1 MB image, with these levels:

| site | level | owner |
|---|---|---|
| `0x34afb3` | `0x10` | dynlib range, 0x34a4d0 body |
| `0x34ba3f` | 1 | 608 `dynlib_get_info_ex` (detailed segment filler) |
| `0x34bf8d` | 2 | 608 (module-name zeroing) |
| `0x34c045` | 2 | 608 (segment sets vs zeros) |
| `0xaba591` | 8 | 0xa397b0 body |
| `0xabace4` | 4 | 0xa397b0 body |
| `0xabb9ad` | 4 | 0xa397b0 body |

## The writer: sys 597 `dynlib_prepare_dlclose`

Thunk `0x2655c0` is `e9 5b 72 0e 00` → `0x8ad0c820`, body **RVA 0x34c820**. In full:

```
34c839  mov  r14, [rdi+8]          ; td_proc
34c83d  call 0x8b48ce10            ; GATE A
34c844  mov  eax, 0x2d             ; EOPNOTSUPP
34c849  cmp  ecx, 1
34c84c  jne  return                ; gate A not satisfied -> 0x2d
34c85f  call 0x8b3b81c0            ; GATE B: proc, &v
34c868  test ecx, ecx
34c86a  jne  return                ; gate B refused -> 0
34c86c  cmp  dword [rbp-0x1c], 0xffffff
34c873  ja   return                ; v > 16 MB -> 0
34c875  mov  rcx, [r14+0x3e8]      ; the loader context
34c87c  mov  dword [rcx+0x150], 1
34c886  mov  rcx, [r14+0x3e8]
34c88d  or   dword [rcx+0x140], 0x40    ; <-- THE GRANT
```

**There is no privilege check before the grant.** The two gates are cheap:

- **Gate A `0x8b48ce10`** (RVA `0xacce10`) calls three predicates —
  `0x8afa2da0`, `0x8afa2cc0`, `0x8afa30c0` — and returns
  `(f2() != 0 || f3() != 0) && !*(u32*)(rip+0x31f4557)`; the referenced global is at
  RVA `0x3cc1390` (`0xffffffff8dcc1390`), i.e. outside every dump. It is a *global* configuration
  bit, not a per-process one — if it is set, 597 answers `0x2d` (EOPNOTSUPP) for every caller.
- **Gate B `0x8b3b81c0`** (RVA `0x9f81c0`) is a three-instruction reader:
  `if (!proc) return 2; obj = proc->[0x578]; if (!obj) return 2; *out = obj->[0x118]; return 0`.
  The grant therefore needs `td_proc->[0x578]` to be a live object and its `+0x118` word to be
  `<= 0xffffff` (16 MB). Both are properties of our own process.

## Why this matters even though nothing queries bit 0x40

Every reader in the image tests bits 1, 2, 4, 8, 0x10. Bit 0x40 has no in-image consumer, so the
grant is either (a) a state flag for a handler family whose body is not in any dump (the same wall
as 601's command and type tables at RVA `0x1a51160` / `0xef1234`), or (b) read by inline code that
the `disp32` scan cannot attribute, because `+0x140` is one of the most crowded offsets in the
image: 2,340 accesses, used by at least nine unrelated object types.

## A userland oracle for the mask: the 608 record

608 `dynlib_get_info_ex` calls `0x8b4ebb00(2)` at `0x34c045` and, **when it returns 1, zeroes
`rec+0x128`, `rec+0x130` and `rec+0x1a0`** instead of filling the segment sets. So dumping a 0x1a8
record for module `0x13` before and after a candidate call is a direct, userland-visible oracle for
level 2 of the mask, in the same process. Probe `1199a` does exactly that around three 597 shapes.

Two caveats that shaped the probe:

- **The mask is per-process.** `ctx` hangs off `td_proc`, so the grant does not survive a new TCP
  connection. The grant and the oracle must run in one connection, which is why 597 is the *last*
  phase of 1199a — every earlier phase still reports if 597 kills the process.
- **597 kills on six zero arguments on 14.10** (`docs/SYSENT_PRESENCE_14_10.md`, row 597 = "kills").
  Its 13.60 body never touches `uap`, so the zero-argument kill must come from gate A's predicate
  calls or from a changed 14.10 body. That is the open question the probe answers: if the three
  shapes all die, 597 is unusable as a grant, and the mask has no reachable writer in this image.

## Two mistakes this note exists to prevent

- **`+0x140` on a record buffer is not `+0x140` on the context.** `0x34bff7` in 608 is
  `mov qword [r14+0x140], 0` where `r14` is the freshly `malloc`'d 0x1a8 record — a field in the
  copyout buffer, not the mask. Only `0x34c88d` in this range actually writes the context word.
- **sys 643 `set_chicken_switches` writes `proc+0xa34`**, one hop *above* the loader context:
  `mov rcx,[r14+8]; or dword [rcx+0xa34], eax` at `0x3f7683`. That is why 643(`0xFFFFFFFF`) never
  re-enabled anything in probes 55a and 356a: it ORs a different field from the one every
  interesting gate reads.
