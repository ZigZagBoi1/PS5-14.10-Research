# thr_create(430): what a valid `ucontext_t` has to contain

Status: **static decode of the 13.60 handler.** Every address below is an RVA
into `docs/dumps_13.60/kernel_text.bin` unless it names `kernel_data.bin`. No
console was contacted, no 14.10 artifact exists in this repository, and nothing
here claims a 14.10 behaviour or a vulnerability.

## Conclusion

1. Syscall 430 is `thr_create` (`docs/sysent-names-13.60.csv:432`). Its 13.60
   body copies exactly `0x500` bytes from arg0, stores arg1 (the id
   out-pointer) at `ctx+0x500` in its own frame, and calls the worker shared
   with 455. That worker allocates a thread, runs a CFI check, and calls the
   ops entry `0x265fc8`, which copies the new thread id out and tail-jumps to a
   machine-context consumer with `ctx+0x40`.
2. On the common path the consumer rejects the context unless three fields
   match: `ctx+0x108 == 0x480`, `ctx+0x0d0 <= 7`, and `ctx+0x110` in
   `{0x10000, 0x10002}` (with a fourth field, `ctx+0x118`, checked only for
   `0x10002`). §5 lists the two further gates that sit behind these.
3. The corpus has never passed a readable context to 430. Probe 54b Phase 2
   passed `arg0 = 0` under a `thr_new` label and got `-1`; with `arg0 = 0` the
   entry's first act is a `copyin` from NULL, so that row is not a threading
   verdict. 430 is `thr_create`; 455 is `thr_new`.
4. The id copyout happens **before** the machine-context validation, so a
   user-supplied id pointer is a positive oracle for "reached thread
   allocation" even when the call still fails. Probe 58e uses that.

## 1. Where the code is

| item | value |
|---|---|
| sysent slot | `0x265c10`, bytes `e9 db 20 1d 00 cc cc cc` |
| E9 target (body) | `0x437cf0` |
| head bytes | `55 48 89 e5 41 57 41 56 41 54 53 48 81 ec 20 05 00 00` |
| next sysent body start | `0x437de0` (455) |

Function boundaries inside that extent — the seam this repository warns about
is real here:

| function | range | role |
|---|---|---|
| 430 entry | `0x437cf0`-`0x437d8c` | copyin, arg1 stash, worker call |
| 430 ops helper | `0x437d90`-`0x437dd5` | id copyout, tail-jump to the consumer |
| 455 entry | `0x437de0`-`0x437f2a` | `thr_new` |
| shared worker | `0x437f30`-`0x43827e` | thread alloc, CFI check, indirect call |
| 455 ops helper | `0x438280`-`0x4383ba` | `thr_param` consumer |

`0x437d90` sits inside 430's sysent extent, while the worker and 455's helper
sit inside 455's. Citing "offset X of the 430 handler" without resolving the
owner crosses a function seam; the padding between these functions is `nop`.

## 2. The entry, `0x437cf0`

```
0x437cf0  push rbp; mov rbp,rsp; push r15,r14,r12,rbx; sub rsp,0x520
0x437d02  lea r12,[rip+0x34e4607]          ; -> 0x391c310 (guard global)
0x437d09  mov rbx,rdi                      ; td
0x437d0c  mov r14,rsi                      ; uap
0x437d11  mov rax,[r12]; mov [rbp-0x28],rax
0x437d19  mov r15,[rsi]                    ; arg0 = ctx
0x437d1c  mov rdi,gs:[0]                   ; curthread
0x437d25  lea rsi,[rip+0xf60211]           ; -> 0x1397f3d in kernel_data.bin
0x437d2c  call 0xc1a3e0                    ; (curthread, "copyin", 0)
0x437d31  lea rsi,[rbp-0x540]              ; dst = rsp
0x437d38  mov edx,0x500                    ; len
0x437d3d  mov rdi,r15                      ; src = ctx
0x437d40  call 0x259280                    ; copyin(ctx, rsp, 0x500)
0x437d45  test eax,eax
0x437d47  jne 0x437d6c                     ; fault -> guard check -> return eax
0x437d49  mov rax,[r14+8]                  ; arg1 = id out-pointer
0x437d4d  lea rdx,[rip-0x1d1d8c]           ; -> 0x265fc8 (ops entry)
0x437d54  lea rcx,[rbp-0x540]              ; ctx base
0x437d5b  mov rdi,rbx; xor esi,esi; xor r8d,r8d
0x437d63  mov [rbp-0x40],rax               ; ctx+0x500 = id pointer
0x437d67  call 0x437f30                    ; shared worker
0x437d6c  mov rcx,[r12]; cmp rcx,[rbp-0x28]
0x437d74  jne 0x437d86                     ; -> 0x6fd6b0, ud2
0x437d76  add rsp,0x520; pop...; ret        ; returns eax
```

Four facts follow from the bytes:

- **The copyin is user→kernel and is labelled as such.** `0x259280` masks the
  source to the user range (`and rdi,0x7fffffffffff`, `0x2592f3`), then does
  `stac; rep movsq; clac` (`0x25930d`-`0x25931a`) with `rsp` as the destination
  bound check (`0x25928c`). The call immediately before it passes the literal
  string `copyin` (RVA `0x1397f3d` in `kernel_data.bin`, offset `0x397f3d`).
- **The frame is exactly the copyin.** `sub rsp,0x520` plus the four pushes
  puts `rsp` at `rbp-0x540`; the `0x500`-byte buffer ends at `rbp-0x40`, which
  is where arg1 is stored. The consumer's `ctx+0x500` read (`0x437d9a`) is
  therefore this frame slot, not part of the copied region.
- **arg2 is never read.** The body loads `[rsi]` at `0x437d19` and `[r14+8]` at
  `0x437d49` and no third uap field. `sysent_index.json` records `narg=3`; the
  third argument has no reader in `0x437cf0`-`0x437d8c`.
- **Failure returns the errno directly.** A copyin fault jumps to the guard
  check and returns `eax` unchanged (`0x437d6c`-`0x437d85`). What the Lua layer
  does with a nonzero return is a loader question this artifact cannot answer;
  the corpus records `-1` for failing calls, and this note does not assume that
  `-1` means EFAULT rather than EINVAL.

## 3. The shared worker, `0x437f30`

430 calls it at `0x437d67` with `(td, 0, ops=0x265fc8, ctx, 0)`; 455 calls the
same address at `0x437f19` with `(td, param_size, ops=0x265fd0, &ctx_copy,
&outbuf)`. One function, two context shapes.

```
0x437f41  mov r15,[rdi+8]                  ; proc
0x437f57  test rsi,rsi; je 0x437ffb        ; 430 passes rsi=0, skips mode checks
0x437ffb  mov eax,[r15+0xb48]; cmp eax,[rip+0x1689560]; jge 0x4380e7
0x438010  call 0xb90ab0                    ; allocate a thread; -1 -> EPERM path
0x4380a7  lea rax,[rip-0x1d10a6]           ; -> 0x267008 (table top)
0x4380ae  sub rax,r13; ror rax,3
0x4380b5  cmp rax,0x3a5; ja 0x43826a       ; CFI: index <= 0x3a5
0x4380c8  call r13                         ; ops entry (new_thread, ctx)
```

The CFI check bounds `ops` to the 934 entries in `[0x2652e0, 0x267008)`. Index
for `0x265fc8` is 520, for `0x265fd0` is 519; both pass, `0x265000` (index
1025) does not. The two entries are themselves E9 trampolines:

| entry | bytes | resolves to |
|---|---|---|
| `0x265fc8` | `e9 c3 1d 1d 00 cc cc cc` | `0x437d90` |
| `0x265fd0` | `e9 ab 22 1d 00 cc cc cc` | `0x438280` |

On the failure path the worker runs two teardown calls on the thread
(`0xb90960`, `0xb909a0` at `0x4380cf`-`0x4380dd`) and returns the status it
recorded.

## 4. The 430 ops helper, `0x437d90`

```
0x437d90  push rbp; mov rbp,rsp; push r14,rbx
0x437d97  mov r14,rdi                      ; new thread
0x437d9a  mov rdi,[rsi+0x500]              ; id pointer from 430's frame slot
0x437da4  test rdi,rdi; je 0x437dc3
0x437da9  movsxd rsi,[r14+0x9c]            ; thread id
0x437db0  call 0x259720                    ; store qword to user
0x437db5  test eax,eax; je 0x437dc3
0x437db9  mov eax,0xe                      ; EFAULT
0x437dc3  add rbx,0x40
0x437dd1  jmp 0xa0ac60                     ; (new thread, ctx+0x40)
```

`0x259720` is a 2-argument user store: range check at `0x25973b`, then
`stac; mov [rdi],rsi; clac` at `0x25976d`-`0x259773`.

**Order matters for the probe:** the id is written before `0xa0ac60` runs. A
call that later fails the context checks still leaves the id in user memory if
it reached thread allocation, so the id distinguishes "failed before
allocation" from "failed at the context".

## 5. The machine-context consumer, `0xa0ac60`

Called as `(new_thread, ctx+0x40)`. Context-relative offsets below are
`consumer_offset + 0x40`:

| field | ctx offset | read at | test | reject |
|---|---|---|---|---|
| magic | `+0x108` (qword) | `0xa0ac8c` `cmp [rsi+0xc8],0x480` | `== 0x480` | `0xa0afeb` (`eax=0x16`) |
| flags | `+0x0d0` (dword) | `0xa0ac9d` `mov r10d,[rsi+0x90]` | `<= 7` (`ja`) | `0xa0afeb` |
| type | `+0x110` (qword) | `0xa0ae03` `mov rdx,[rsi+0xd0]` | `== 0x10000` or `0x10002` | `0xa0afeb` |
| subtype | `+0x118` (qword) | `0xa0ae24` `mov r10,[rsi+0xd8]` | `0x20000`, `0x20001`, `0x20002` | `0xa0afeb` |

The subtype check is an unsigned range test and is simulated, not read off the
mnemonic: `lea rdx,[r10-0x20001]; cmp rdx,2; jae 0xa0ae76` sends
`0x20000` to the alternate path and everything else above `0x20002` to the
reject. `0x20001` and `0x20002` continue on the main path.

Two further gates sit between the magic and the register copy:

- `cmp byte [proc+0xc81],0; je 0xa0ad93` (`0xa0acd6`). If the byte is **zero**,
  control goes to `0xa0ad93`, which requires `flags <= 3` (`cmp r10d,3; ja`),
  copies `0x140` bytes from the user context at `ctx+0x340` into a stack buffer
  (`0xa0adb5`-`0xa0add0`; `0x259be0` takes the user source first and the kernel
  destination second, the same order as `0x259280`), zeroes three qwords in
  that buffer (`0xa0add5`-`0xa0adfb`), and continues at `0xa0ae03`.
- If the byte is **nonzero**, control falls to `0xa0aceb`: `cmp r10d,4; jb`
  skips to `0xa0ae03` unless `flags >= 4`. On that path only, the stack size at
  `ctx+0x498` must be `<= [global]-0x200` (`0xa0acf5`), and the value at
  `ctx+0x490` is the source of a `copyin` of `ctx+0x498` bytes
  (`0xa0ad68`, preceded again by the literal `copyin` at `0xa0ad3e`).

With `flags = 0` neither the stack-size check nor the user `copyin` runs, but
the `ctx+0x340` copy still runs whenever `proc+0xc81` is zero.

After the checks the consumer copies a register block into `[new_thread+0x460]`
(`0xa0aca4`, the field `docs/VERIFIED_HANDLER_ANALYSIS.md:312` calls the trap
frame). Offsets below are relative to the pointer the consumer receives
(`ctx+0x40`), so add `0x40` for context-relative:

```
+0x08->+0x00  +0x10->+0x08  +0x18->+0x10  +0x20->+0x18
+0x28->+0x20  +0x30->+0x28  +0x38->+0x30  +0x40->+0x38
+0x48->+0x40  +0x50->+0x48  +0x58->+0x50  +0x60->+0x58
+0x68->+0x60  +0x70->+0x68  +0x78->+0x70  +0xa0->+0xe8
+0xb8->+0x100 +0xc0->+0x108
```

plus `[+0x90]&7` into `[+0x88]` low bits (`0xa0af63`-`0xa0af7b`), and, when
`[+0x90]&1`, four 16-bit fields at `+0x84`, `+0x86`, `+0x94`, `+0x96`
(`0xa0af83`-`0xa0afbc`). Register names are not assigned here: the destination
offsets are trap-frame offsets, and this dump does not carry the PS5
`mcontext_t` definition.

## 6. What probe 58e passes

`probes/phase15_native_sysent/58e_thr_create_ucontext.lua` (PREPARED — NOT RUN,
`CRASH_CLASS: RISKY`):

| section | arg0 | arg1 | purpose |
|---|---|---|---|
| A | 0 | 0 | is 430 reachable through `make_syscall` at all |
| B | zeroed `0x500` | 0 | copyin succeeds, magic check fails |
| C | zeroed `0x500` | id slot | id oracle with an invalid context |
| D | `+0x108=0x480, +0x0d0=0, +0x110=0x10000` | id slot | first reachable thread creation |
| E | `+0x110=0x10002, +0x118=0x20001` | id slot | alternate type |

The id slot is pre-filled with `0xDEADBEEF_DEADBEEF`; a change proves the
handler reached allocation. D and E leave the register block zero, so a created
thread would start at `RIP=0` and may kill the process before its `[RETURNED]`
line prints.

## 7. What this does not establish

- **13.60 only.** The dump's acquisition authenticity is unresolved, and no
  verified 14.10 image exists in this repository. 430 on 14.10 may be a
  different body, may be filtered by the loader, or may not exist.
- **No thread has been created.** A successful D/E would be the first
  observation of that on any firmware in this repository, and it would not
  establish anything about privilege, memory access, or KASLR.
- **Field names are labels.** `magic`, `flags`, `type`, `subtype` name offsets
  and comparisons; they are not symbol names from the artifact.
- **The worker's proc offsets** (`proc+0xb48`, `proc+0xc81`, `proc+0x580`,
  `proc+0x5d8`) are read but not identified here; they are cited only as the
  offsets the code touches.
