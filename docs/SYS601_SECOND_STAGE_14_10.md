# 601's second stage: a full command interface, one thread-flag bit away

Written 2026-11-04 (seventh boot) from `docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`).
Everything below is static, from the 13.60 text dump, plus the measured 601 map in
`docs/MDBG_601_COMMAND_MAP_14_10.md`. No new console result is claimed here; 1192a died before it
could report (see the last section).

## 1. The dispatcher has exactly one entry

The 601 handler starts at `0xca0630` and is one function up to `0xca2320`: the region
`0xca1000-0xca1a00` contains **no** `push rbp; mov rbp,rsp` prologue, so the case bodies and the
shared exits all belong to 601 itself.

Command dispatch is the classic shape:

```
ca0644  lea r9, [rip + 0x2c7bcc5]      ; stack canary
ca064b  mov r14d, 0x4e                 ; ENOSYS is the default return
ca0651  mov rax, [r9]
ca0654  mov [rbp - 0x30], rax
ca0658  mov eax, dword ptr [rsi]       ; cmd = uap[0]
ca065a  cmp rax, 0x27
ca065e  ja  0xca221c                   ; out of range -> return r14d
ca0664  lea rcx, [rip + 0xdb0af5]      ; jump table at RVA 0x1a51160
ca066b  mov r15, [rsi + 8]             ; arg2
ca066f  mov r12, [rsi + 0x10]          ; arg3
ca0673  mov r8, rdi                    ; r8 = td, kept for the whole function
ca0676  movsxd rdx, dword ptr [rcx + rax*4]
ca067a  add rdx, rcx
ca067d  jmp rdx
```

The jump table lives at RVA `0x1a51160`, i.e. **outside** the 15.1 MB text dump, so command-to-case
attribution cannot be read statically. It has to be measured.

Every exit funnels through `0xca2229 mov eax, r14d; add rsp,0xf8; pop...; ret`, so **the handler's
own return value is always <= 0x4e**. It can never be -1.

## 2. One branch reaches the second stage, and it is a thread flag

Scanning the whole dump for `jmp`/`jcc` into `0xca180c` (the tail-call epilogue) and into
`0xca2320` (the second stage) returns exactly one hit each:

```
0xca180c <- jcc @ 0xca0ce2
0xca2320 <- jmp @ 0xca1833
```

The condition:

```
ca0cda  test byte ptr [r8 + 0x529], 1    ; r8 = td; bit 8 of the dword at td+0x528
ca0ce2  jne  0xca180c                    ; flag set  -> tail-call the second stage
ca0ce8  mov  rdi, [r8 + 0x140]           ; flag clear -> credential path
ca0cf2  mov  r14, r8
ca0cf5  call 0xffffffff8afc8f90          ; the bit-62 authority test
ca0cfa  test eax, eax
ca0cfc  je   0xca1a45                    ; -> mov r14d, 1 (EPERM), return
```

and the tail-call itself:

```
ca180c  mov rax, [r9] / cmp rax, [rbp-0x30]   ; canary
ca1819  mov rdi, r8                            ; td
ca181c  mov rsi, r15                           ; arg2
ca181f  mov rdx, r12                           ; arg3
ca1822  add rsp, 0xf8; pop rbx/r12/r13/r14/r15/rbp
ca1833  jmp 0xca2320
```

So `601(cmd, arg2, arg3)` for **one** command becomes `sub_0xca2320(td, arg2, arg3)`, and only when
`(*(u32*)(td+0x528) & 0x100) != 0`. Without the flag the answer is EPERM(1) unless the process holds
credential bit 62 (we hold bit 61).

## 3. What the second stage actually is

`0xca2320(td, in, out)`:

```
copyin(in, rbp-0x74, 0x3c)          ; a 60-byte user struct
struct layout (base = rbp-0x74):
  +0x08  dword   field A
  +0x0c  qword   key
  +0x14  dword   flags      (must be 0 on the unprivileged path)
  +0x18  qword   pointer B  (used as a copyin source)
  +0x20  dword   length B
  +0x24  dword   TYPE
mov rax, [r14+0x528]; test eax, 0x100; jne 0xca2530
cmp type, 7; ja  ret 1              ; bad type -> 1
bt 0xb8, type; jae ret 1            ; only 3,4,5,7 pass
and type, 0xfe; cmp type, 4
jne 0xca2530                        ; types 3 and 7 go to the MAIN body anyway
                                    ; types 4 and 5 take the unprivileged list-unlink path
```

The unprivileged path (types 4/5) locks `proc+0x148`, walks the list at `ctx+0x40`, matches
`entry+0x14 == key && entry+0x2c == type && entry+0x10 == field A`, unlinks and frees the entry,
decrements `ctx+0xf8`. No pointer is written anywhere. Returns 0.

The main body (`0xca2530`) requires the same bit 0x100 (it re-tests it) and adds:

* cap `ctx+0x30 < 0x100` (the same 0x100 that cmd 0x00 reports as `{0x100, 0}`);
* **type 1**: allocates a per-process 0x80000 kernel buffer at `ctx+0x58` on first use, then
  `copyin(struct+0x0c, heap, len)` and appends it with `memcpy(ctx+0x58 + ctx+0x50, heap, len)`
  (plain `0x8ac190b0`, no stac — kernel to kernel), advancing the 32-bit used counter at `ctx+0x50`
  behind a `used + len < 0x80001` signed check;
* **type 100**: `malloc(min(len,0x1000)+1)` + copyin + `call 0x8b170ae0(heap, len)`;
* **type 3**: `malloc(len+1)` + `copyin(struct+0x18, heap, len)` + `call 0x8b663e30(td, heap, len)`
  (a kernel-side blob processor) and returns 1 if that returns 0;
* every successful path allocates a 0x58-byte list entry, copies the struct fields into it, links it
  at `ctx+0x48` and bumps `ctx+0x30`;
* **the out-parameter**: `if (out) copyout(&[rbp-0x38], out, 8)` — 8 bytes, from a kernel stack slot.
  `arg3` of the syscall is a **pointer** on this path, not a length.

That is a second, richer command interface (blob ingest, kernel-side parser, per-process 0x80000
scratch buffer) hanging off a single bit in the thread's flag word, entirely separate from the
`0x00-0x27` case table that the measured map covers.

## 4. The flag has a setter inside 601, and it is not what the corpus said

Scanning the whole text for displacement `0x528` (148 references) turns up the writers:

| site | instruction | meaning |
|---|---|---|
| `0xca131f` | `or qword ptr [rax + 0x528], 0x100` | **sets the second-stage flag** |
| `0xca13fa` | `or byte ptr [r12 + 0x529], 8` | sets bit 11 of the same dword |
| `0xca145a` | `and rax, 0xfffffffffffffdff; mov [r13+0x528], rax` | clears bit 9, not bit 8 |
| `0xa3598c` / `0xb4774f` | `or byte [..+0x528], 0x80` / `4` | unrelated threads |

The setter at `0xca131f` sits in a case body that starts at `0xca12d5`:

```
ca12d5  mov  r14, [r8 + 8]        ; td_proc, read from the CURRENT THREAD
ca12e0  call 0x8b65afc0           ; proc reference
ca1303  call 0x8ae86a00           ; lock(proc+0x148)
ca130f  mov  r13, [r14 + 0x568]   ; the mdbg ctx
ca131f  or   qword [td + 0x528], 0x100
ca132a  call 0x8ae86fa0           ; unlock
ca132f  lock(ctx+0x28)
ca1348  mov  eax, [td + 0x9c]     ; td_tid
ca134e  mov  [ctx + 0x94], eax
```

**Correction to `docs/MDBG_601_COMMAND_MAP_14_10.md` and everything downstream of it:** the attach
path takes *no* kernel pointer. It reads `td_proc` from the calling thread. The "attach needs a
kernel `struct proc*`" claim came from commands 0x03/0x04, which really do dereference an argument as
a `struct proc*` and panic; that is a different command family.

After the flag is set, the same case copies out up to 0x28 bytes of ctx state to `arg2` with length
`min(arg3 & 0x7fffffff, 0x28)` — but only when `[ctx+0x38] == 0`, otherwise it returns EINVAL(22).

## 5. The measured map is errno-blind, and that hid all of this

The loader's syscall path is `native.fcall_with_rax` on `libkernel gettimeofday+7`, i.e. the real
libkernel wrapper body. That wrapper returns **-1 for every error**; the errno is only available from
libc's `errno`, which the loader already exposes as `get_error_string()`
(`.local/loader_payload/misc.lua:156`).

Both probes behind the map (`1170a`, and the earlier sweep) printed only `rv`. Every "-1" in that
table therefore conflates EPERM(1), EINVAL(22) and ENOSYS(78). The dispatcher's no-flag path returns
**1**, the attach path in the wrong ctx state returns **22**, and out-of-range commands return **78**.
All three printed as -1.

The handler cannot return -1 itself: `mov eax, r14d` with `r14d` only ever 0, 1, 4, 0x16, 0x1c, 0x23,
0x3f, 0x4e. So any claim of the form "601 returns -1, therefore the gate rejected it" is unsupported;
it needs the errno.

## 6. 1192a: a new way to wedge the loader, and it is one call

`probes/phase17_new_vectors/1192a_601_dispatcher_command.lua` swept commands with a zeroed struct in
`arg2` and a **pointer** in `arg3`. It printed its setup line and then stopped:

```
[A] struct=0x0000000310B9C600 out=0x0000000310B9CDE0
-- phase A: type 0 (invalid: bit0 of 0xb8 is clear) --
[*] IDLE_TIMEOUT waiting for more data
```

The first call was `601(0x00, struct, out)`, i.e. cmd 0x00 with a non-zero `arg3`. `port_witness`
then returned `LOADER-STUCK accepted, no reply` twice, 45 s apart: the Lua VM never services another
connection. The kernel is alive (the TCP handshake completes), so this is the same class of wedge as
637's mid-range value — an unprivileged single call that permanently costs the loader.

Two things changed at once between this call and the safe `1170a` call (`601(0x00, buf, 0x4000)`):
`arg3` (0x4000 -> a pointer) and the struct contents (0xA5A5A5A5 -> zero). The next probe varies them
one at a time.

## 7. The next probe, and what would finish this

`probes/phase17_new_vectors/1193a_601_errno_attach_flag.lua` (written, not yet run):

1. sweep every non-lethal command 0..0x2F with `arg3 = 0`, printing `rv`, the raw `tostring(uint64)`
   and `get_error_string()`;
2. call `601(0x00, mapped buffer, 0)` — the known-safe attach attempt;
3. repeat the sweep; the command whose `rv`/`errno` flips is the second-stage entry.

If a candidate appears, a follow-up calls it with a real 8-byte out pointer and dumps the qword, then
walks the type space (1, 3, 4, 5, 7, 100) with a crafted 0x3c struct.

What is still missing is the jump table at RVA `0x1a51160`, which the 15.1 MB text dump does not
cover. With it, the attach command number and the dispatcher command number would be known exactly
instead of measured by bisection.

## 8. Measured on 14.10, 2026-11-04 18:16-18:18 (five probes, one loader death)

Every number below is from `results/phase17_new_vectors/119*a_*_2026110*.txt`. The console was rebuilt
between 1192a and 1193c, so all of it is one process lineage.

**1193c settled the 1192a wedge.** `601(0x00, zeroed struct, 0)` and `601(0x00, 0xA5 struct, 0)` both
return 0 and both write `0x0000000000000100` into `arg2`: the struct contents are irrelevant, and the
wedge came from handing `arg3` a non-zero value. That call is the only 601 command that leaves a
measurable out-parameter with a zero `arg3`.

**1193a produced the first real errno map** (the handler can only return 0, 1, 4, 0x16, 0x1c, 0x23,
0x3f, 0x4e, so these are exact):

| errno | commands |
|---|---|
| 0 (success) | 00, 07, 09, 0B, 0D, 0E, 13, 14, 19, 1A, 1D, 20 |
| EINVAL 22 | 01, 10, 11, 12, 1E, 21, 23 |
| ENOSYS 78 | 02, 05, 06, 16, 17, 22, 28-2F |
| EPERM 1 | 0A, 0F, 15, 18, 24, 25, 26 |
| EFAULT 14 | 1C, 1F |

`0x28`-`0x2F` are ENOSYS because the entry itself rejects `cmd > 0x27`. The EPERM set is exactly what
the *flag-clear* arm of the second-stage gate produces (`mov r14d,1` at `0xca1a45`), so those seven are
the candidates for the command that owns the branch at `0xca0cda`.

**1194b: only two commands write into a 0xA5-filled `arg2`** — `0x0E` writes 8 bytes of zero and
`0x1A` writes 4 bytes of zero. Neither leaks a kernel pointer: every byte past the fixed size stayed
at the sentinel, so there is no 0x28-byte ctx copyout and no pointer disclosure on this path.

**1194c: the type-gate discriminator produced zero flips.** All 40 non-lethal commands answered
identically for an all-`0xA5` struct (type field `0xA5A5A5A5`, out of range) and a well-formed type-4
struct. Whatever reaches `0xca2320`, it is not any of them — at least not with a type-4 struct.

**1194d: the struct consumers are 01, 0E, 1A, 1C, 1F, 24 and 25.** With `arg2 = 0x500000000000`
(in-range, unmapped) those seven answer EFAULT(14); everything else ignores `arg2`. The stage-two
entry `0xca2320` starts with `copyin(arg2, ..., 0x3c)`, so if it were reached by a command in this
space, that command would be in this set.

**1194e killed the loader on command 0x1C.** Sweeping with a type-4 struct in `arg2` and a mapped
0x20 sentinel in `arg3`: no command wrote anything to `arg3` (which is what a reached stage two would
do — its only copyout is 8 bytes to `arg3`), and `0x1C` died outright. `port_witness` then said
`LOADER-DEAD connect refused`, so this was a process death, not a park. `0x1C` already returned
EFAULT(14) with a *mapped* zeroed struct in 1193a, i.e. it dereferences a field inside the struct
rather than the struct itself, and a mapped `arg3` changes what it does with it.

### What this rules out

Types 3, 4, 5 and 7 all reach the main body when `(td_flags & 0xfe) != 4`, and the gate's first test is
`flags & 0x100`. Since no command in 0..0x27 shows any type-dependent answer, the flag is **clear** for
our thread and no command in that space reaches `0xca180c` yet. The attach that sets it is therefore
either (a) one of the seven EPERM commands with a different `arg2` shape, or (b) invisible because
attach's own copyout is length-gated: `rbx = min(arg3 & 0x7fffffff, 0x28)`, so with `arg3 = 0` it
copies nothing and looks identical to a no-op.

### 1195a, the probe that follows

`probes/phase17_new_vectors/1195a_601_attach_hunt.lua` runs the whole space with `arg3 = 0x28` (the
1170a shape, safe for 0x00) and dumps 0x28 bytes of `arg2` after each call, then re-runs the seven
EPERM commands. An attach shows up as 0x28 bytes written; if it sets the thread flag, one of the seven
EPERM commands should change its answer in the second phase.

## 9. 1195a: the attach is not there, and neither is the dispatcher (measured 2026-11-04 18:44)

Capture: `results/phase17_new_vectors/1195a_601_attach_hunt_20261104_184447.txt`, 3248 bytes,
`=== DONE ===`, `[Z] alive`, loader alive afterwards. Phase A swept every non-lethal command with
`arg3 = 0x28` and an `0xA5`-filled `arg2`, dumping 0x28 bytes of `arg2` after each call. Phase B
re-ran the seven EPERM commands.

| quantity | result |
|---|---|
| commands that wrote anything into a 0x28-byte `arg2` | `0x00` (8 B: `00000100 00000000`), `0x0E` (8 B: zero), `0x1A` (4 B: zero) |
| commands that wrote exactly 0x28 bytes | **none** |
| commands that wrote anything into `arg3` | **none** |
| EPERM set after a full pass | unchanged: `0A, 0F, 15, 18, 24, 25, 26` |
| loader state | alive, `[Z] alive` |

`[SUMA]` printed `0x28-byte writers = 0,14,26` — that is the probe counting *any* non-sentinel byte
in the 0x28-byte window, and its own dump strings show `0` = 8 bytes and `14`/`26` = 4 to 8 bytes.
The attach's copyout is `min(arg3, 0x28) = 0x28` bytes of five ctx qwords, so a reached attach would
have produced a full 0x28-byte window. None did.

A reading caveat that applies to this whole table: the probe prints `get_error_string()` after every
call and **never resets errno**, so rows with `rv=0` carry the *previous* call's errno. Only `rv` is
trustworthy for the success rows; `errno` is meaningful only where `rv=-1`.

### The structural finding that closes 601 as a route

Scanning all 15,132,096 bytes of text for `e8 rel32` with a target of `0xffffffff8b662320`
(stage two), `0xffffffff8b66180c` (the shared tail that jumps to it) or `0xffffffff8b6612d5`
(the attach body) returns **zero call sites**. All three are reachable only as entries of the 0x28-slot
command jump table at RVA `0x1a51160`, which lies outside every 13.60 dump region.

So the command number *is* the table index, and there are exactly 0x28 of them. 1195a measured all 0x28:
none writes 0x28 bytes, none writes `arg3`, and 1194c measured that none has any type-dependent answer.
Both of the bodies we wanted are therefore absent from the 14.10 table — either Sony removed those
cases, or the 13.60 table we disassembled has been rebuilt. The interval is exhausted: there is no
untested `arg2` shape left to try, because the type field is the *only* discriminator and 1194c varied it.

601 is closed. `docs/MDBG_601_COMMAND_MAP_14_10.md` keeps the behavioural map — it is still the most
detailed description of a 14.10 mdbg surface we have, and `0x00` answering `{0x100, 0}` is a usable
capability query — but it is not a kernel-R/W route and nothing further should be spent on it.

### Correction, 2026-11-10: the closure is stronger than "no call sites", and here is why

The argument above leans on a scan for direct `e8 rel32` calls to the second-stage bodies. That test is
weak on its own, because the command dispatch is an indirect jump table and a table entry is not a
direct call. The closure does hold, but for a better reason.

The second-stage function at `0xffffffff8b662320` reads a 60-byte struct from `arg1` with
`copyin(arg1, [rbp-0x74], 0x3c)` at `0x8b662377`, takes the type from `struct+0x24`, and its **first**
decision is:

```asm
0x8b6623bf  mov     eax, [rbp - 0x50]      ; type
0x8b6623c2  mov     r15d, 1
0x8b6623c8  cmp     eax, 7
0x8b6623cb  ja      0x8b662383             ; return 1
0x8b6623d2  bt      ecx, eax               ; ecx = 0xb8
0x8b6623d5  jae     0x8b662383             ; return 1
```

`1195a` called every slot as `601(cmd, B, 0x28, 0, 0, 0)` with `B` a mapped page filled with
`0xA5A5A5A5`. So for any slot that were this function, `copyin` would have succeeded, the type would
have been `0xA5A5A5A5`, and the answer would have been **`rv = 1`** — because every path through the
type gate ends at `0x8b662383`, which returns `r15d`.

No slot in `0x00`-`0x27` returned `1`. The six slots `1195a` did not measure are `0x03`, `0x04`
(panic on a raw `struct proc *`), `0x08`, `0x0C` (park forever) and `0x1B`, `0x27` (kill), and none of
those behaviours is "return 1 on a bad type". So the second stage is not reachable from the 14.10
table, and the reason is behavioural rather than structural.

The same reading retires a follow-up that looked promising: the *inner* table at `0x8e031234` (seven
cases, index `type-1`) contains a case at `0x8b6629e0` that does

```asm
0x8b6629ef  lea     edi, [rdi + 1]         ; size = struct[0x20] + 1
0x8b6629f1  call    malloc
0x8b6629fa  mov     r12, [rbp - 0x5c]     ; source = struct[0x18]
0x8b662a21  call    copyin                 ; length = struct[0x20]
```

which is a `malloc(size+1)` followed by a `copyin(size)` — one off the usual shape, and if `size` were
`0xffffffff` the allocation would be zero bytes and the copy four gigabytes. It is harmless for two
independent reasons: the case is type 3, and types 3 and 4 pass `cmp dword [rbp-0x54], 0x10000;
ja 0x3f` at `0x8b6625ed` before the table dispatch, so `size` is capped at 64 KiB; and type 3 is not in
the unprivileged mask `0xb8` in the first place. Types 4 and 5 are the unprivileged pair
(`and eax, 0xfffffffe; cmp eax, 4` at `0x8b6623d7` sends 3 and 7 to the privileged continuation), and
the gate also forces `struct+0x14 == 0` for them, which is exactly the field that the other ingest case
at `0x8b662aea` uses as both its allocation size and its copy length.

The dump at `results/kernel_handlers/asm/sys_601_deep.asm` prints addresses in a frame based at
`0x8a9c0000`; add that to every address in that file to get the VA. The table at `0x8e031234` and the
one at `0x8e031160` are both past the end of `kernel_text.bin`, so op-to-case mapping has to be
measured, never read.

### The two-step composition was already measured and fails (2026-11-10)

The 13.60 attach body at `0x8b6612d5` calls the context creator **unconditionally**
(`0x8b6612e3 call 0xffffffff8b65afc0`) and only afterwards fails with EINVAL(22) from
`0x8b6613b0 cmp dword [r13+0x38],0`, so on 13.60 a *failed* attach still leaves
`proc+0x568` set. That raised the obvious composition: call `601(0x01,...)` to create the
context, then call a write-bearing command such as `0x1B`, whose body dereferences
`[[proc+0x568]+0xf0]` and stores caller qwords at `+0x00/+0x08/+0x10/+0x18/+0x30/+0x60/
+0x68/+0x90/+0xb0` — an arbitrary-qword write if the pointer chain is live.

**That experiment has already been run.** `results/phase35_dead_end_reruns/
1355a_sys601_cmd12_shape_20261109_110324.txt` is a consumer sweep in one process: it calls
`0x01` early (`0x01 -1 ch=0`), then `0x02 0x05 0x06 0x07 0x09 0x0A 0x0B 0x0D 0x0E 0x0F
0x10 0x11 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1A`, and then `calling 0x1B ...` with
nothing after it — the process died there. So on 14.10 a failed attach does **not** leave a
usable context: `0x1B` dereferences the same NULL chain it does in a fresh process.

Two consequences, and they settle the family:

1. **No probe needs to be spent on the two-step.** The capture exists; it is the exact
   shape that would have been written for it.
2. **The context is never created on 14.10.** Either `0x01` returns EINVAL/EPERM before the
   creator runs, or the creator itself fails; either way `proc+0x568` stays NULL for every
   argument shape `1384a` swept (32 flag words x 24 struct shapes). With the context
   unreachable, the write-bearing commands cannot be reached either, because every one of
   them dereferences it before it reads an argument.

The second-stage remnants stay as recorded above: the blob-ingest function is unreachable
because no table slot reaches it, and the type gate it needs (`td+0x528 & 0x100`, set at
`0x8b66131f` in the attach body) never becomes true either.
