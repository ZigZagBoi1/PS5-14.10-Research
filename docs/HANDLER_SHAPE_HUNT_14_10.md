# HANDLER_SHAPE_HUNT_14_10 — syscall 601 (mdbg_service) and corpus shape scan

Scope: static, code-level hunt in `results/kernel_handlers/` (fw 13.60 dump corpus; 14.10 handler bodies assumed identical
where the 601 body matches the 14.10 offsets already used by the team). No console access used.
Labels: **STATIC** = read directly out of a dump/asm line quoted here. **INFERRED** = follows from code shape but not executed.

Corpus/mapping notes (needed to reproduce every quote):
- `docs/dumps_13.60/kernel_data.bin` covers RVA 0x1000000–0x1400000; **file offset = RVA − 0x1000000**
  (verified: "mDBG: Invalid syscall…" RVA 0x12c892a = file 0x2c892a).
- `results/kernel_handlers/asm/sys_601_deep.asm` is a raw objdump of the 601 body, RVA 0xca0600–0xca6a00, 4017 lines.
  Quotes below are `L<line> @0x<rva>`.
- 601 entry: `L21 @0xca065a cmp rax,0x27` → `L23 @0xca0664 lea rcx,[rip+0xdb0af5] # 0x1a51160` →
  `L27 @0xca0676 movsxd rdx,DWORD PTR [rcx+rax*4]` / `L29 @0xca067d jmp rdx`. **STATIC**: 40-entry self-relative
  command table at 0x1a51160, i.e. every command is a direct jump into the body. Table contents are outside every
  retained dump (0x1a51160 > 0x1400000), so **command numbers cannot be bound to bodies from this corpus** (unchanged
  from the prior audit; nothing below depends on knowing a number).

---

## 0. HARD CONSTRAINT discovered first: SMAP is ON (kills the pointer-injection class)

**STATIC.** `docs/dumps_13.60/kernel_text.bin` contains 17 `stac` (0f 01 cb) and 46 `clac` (0f 01 ca) instructions;
the dense cluster at 0x259235/0x25930d/0x2593b7/0x259428/0x2594a7/0x259517 sits exactly in the copyin/copyout helpers
used by 601 (`call 0x259280` = copyin, `call 0x2591d0` = copyout).

Consequences, and they are load-bearing for the ranking:
1. Any 601 command that dereferences a **user** pointer as a kernel pointer is a #PF panic, not a primitive.
2. This is the correct explanation of the previously recorded "601 cmd 0x03/0x04 lethal": those bodies take a raw
   `struct proc *` (see §2). They were not lethal because of a deep bug — they were lethal because the argument was
   not a kernel pointer.
3. Therefore the only 601 commands reachable *today* (uid 1, bit 61, no leak) are the ones that move data through
   copyin/copyout/uiomove. Everything pointer-taking is **post-leak** only.

---

## 1. FINDING 1 (top): a 601 command drains the kernel mdbg log to userland — no credential gate

**Body: 0xca32b0, `L2681`–`L2800`. STATIC.** No call to the bit-62 predicate (0x608f90) anywhere in it.

    L2681 @0xca32b0 push rbp                       ; fn(uio *rsi)  — r14 = rsi
    L2689 @0xca32c1 lea rdi,[rip+0x316a5a0] # 0x3e0d868   ; static mutex
    L2698 @0xca32d9 cmp QWORD PTR [rip+0x316a58f],0x0 # 0x3e0d870   ; log-list head == NULL?
    L2706 @0xca330a call 0xc06260                  ; log_create(0x3e0d880, &0x3e0d850, 0x1000, "mdbglog", 0,0, 0x100)
                                                    ;   rcx = 0x1305178 = "mdbglog"
    L2716 @0xca333a mov r12,QWORD PTR [r14+0x18]    ; uio_resid
    L2726 @0xca3360 cmp r12,0x4000 ; cmovae       ; clamp to 0x4000-byte bounce buffer
    L2737 @0xca3392 movsxd rax,DWORD PTR [rbx+0x10] ; entry->read_off
    L2738 @0xca3396 mov r15d,DWORD PTR [rbx+0x14]   ; entry->len
    L2749 @0xca33b0 call 0x2590b0                   ; memcpy(bounce, entry->buf + off, n)
    L2759 @0xca33bf mov QWORD PTR [rip+0x316a4aa],rax # 0x3e0d870  ; unlink consumed entry
    L2766 @0xca33fc call 0xc08df0                   ; free(entry->buf)
    L2785 @0xca3451 call 0x782520                   ; uiomove(bounce, n, uio)  -> userland
    L2788 @0xca3456 mov r12,QWORD PTR [r14+0x18]    ; loop while resid > 0

**Mechanism.** The handler owns a kernel log (`0x3e0d870` list head, `0x3e0d868` mutex, created lazily as a
0x1000-byte / 0x100-entry `log(9)` object named "mdbglog"). One command walks that list, memcpy's each entry into a
0x4000 kmalloc buffer and uiomoves it to the caller's uio. The log is fed by `log_printf` calls throughout mdbg, and
the format strings are in the data dump:

- `0x1359707` = "mDBG: Debughandler starting(%d:%s)\n" (emitted at `L1076 @0xca1833`, immediately before the request
  dispatcher is called — **every 601 call writes a log record**),
- `0x12c9cb5` = "mDBG: Kernel Build ID = %lx\n",
- `0x12c892a` = "mDBG: Invalid syscall on debughandler (%d)\n",
- and the %p-bearing dump formats at 0x12ed609 / 0x13218a4 / 0x136ae93 recorded in the prior audit.

**Why it matters.** This is a kernel→userland read channel that exists *today*, is not behind bit 62, and carries text
produced by code that formats kernel pointers. It is the cheapest candidate for the KASLR defeat the project still
needs, and it is a different mechanism from the two public 2026 tricks (no AF_ROUTE, no race).

**Falsification (1 syscall once the number is known).** `cmd(arg1 = mapped user buffer, arg2 = 0x1000, arg3 = 0)`:
- CONFIRM: return 0 and the buffer contains ASCII beginning "mDBG:" (or any prior log text); a second call returns 0
  with resid consumed.
- KILL: EINVAL/ENOSYS, or a zero-length result on every argument shape, or (after the sweep) no command produces
  "mDBG:" text.
Note the zero-length case is a *useful* fingerprint: with arg2 = 0 the loop never runs, the log is still created and
the call returns 0 — so the command is "harmless with len 0, produces text with len 0x1000".

**INFERRED (not executed):** that the 601 wrapper builds the uio from uap[1]/uap[2] (the same wrapper pattern is
**STATIC** for 667, which passes uap[1] + a clamped count into 0x782520). If the drain command instead takes a raw
`struct uio *`, SMAP turns it into a panic — that outcome is itself the kill signal.

---

## 2. FINDING 2: the attach command takes a raw `struct proc *` from userland and runs a write chain

**Body: 0xca12d5 (`L756`–`L809`). STATIC.** Reached only from the command table (zero branch references to 0xca12d5 in
the body) — i.e. it *is* a command, not a helper.

    L756  @0xca12d5 push rbp
    ...   r14 = uap[1] ; call 0xc9afc0(r14)        ; get-or-create ctx:
                                                     mtx_lock(proc+0x148); ctx = *(proc+0x568);
                                                     if (ctx==0) { ctx = malloc(0x1f0); *(proc+0x568) = ctx; }
    L773  @0xca131f or QWORD PTR [rax+0x528],0x100 ; *** current td state bit set ***
    L775  @0xca132f lea rbx,[r13+0x28] ; mtx_lock(ctx+0x28)
    L783  @0xca134e mov DWORD PTR [r13+0x94],eax  ; ctx->field = td->td_tid (from [td+0x9c])
    L786  @0xca135f cmp DWORD PTR [r13+0x88],0x0
    L789  @0xca1362 mov DWORD PTR [r13+0x34],0x2 ; ctx->state = 2 ; call 0x73ef00(ctx)
    L794  @0xca1388 mov DWORD PTR [r13+0x34],0x1 ; ctx->state = 1
    L797  @0xca1383 call 0x73e780(ctx, ctx+0x10, 0)
    L803  @0xca13b6 mov DWORD PTR [r13+0x88],0x0 ; ctx->field = 0

**Mechanism.** `uap[1]` is used verbatim as a `struct proc *`: the kernel takes a mutex inside it, reads a pointer out
of it (+0x568), takes a second mutex through *that* pointer, and then writes three fields through it (+0x94, +0x34,
+0x88) plus two calls. There is no validation, no credential test, and no copyin.

**With SMAP on, this is only usable with a valid kernel pointer** — which is exactly why it panics today. Once ANY
kernel read/leak exists (§1), the chain is an **arbitrary kernel write primitive**:
choose X = any readable kernel address; the kernel does `mtx_lock(X+0x148)` and loads `ctx = *(X+0x568)`; if we can
plant a qword at X+0x568 (or find an X whose +0x568 already points where we want), the kernel then writes
`ctx+0x94`, `ctx+0x34`, `ctx+0x88` and calls through `ctx`. That is a write-what-where-ish primitive of a shape the
project currently lists as "kernel WRITE: none".

**Side effect worth its own line:** `L773 or QWORD [td+0x528],0x100` is a *self-state escalation* performed by a
command. It is the flag that unlocks the request types in §3.

**Falsification (post-leak, 1 syscall).** With a leaked pointer to our own `struct proc` (or any kernel object with a
controlled +0x568): `cmd(arg1 = that pointer, arg2 = 0, arg3 = 0)` → CONFIRM if return 0 and the process continues to
run/debug normally (ctx installed); KILL if EINVAL or a #PF panic naming a kernel address.
Pre-leak version: `arg1 = 0` panics (already observed) — that only proves the raw deref, not exploitability.

---

## 3. FINDING 3: the request dispatcher is gated by a *thread state bit*, and 3 of its 7 types have no validation

**Body: sub_00ca2320 @0xca2320 (`L1680`–`L2390`), called from `L1076 @0xca1833`. STATIC.**

    L1726 @0xca23cd mov ecx,0xb8                  ; allowed-type mask {3,4,5,7} when the state bit is CLEAR
    L2101 @0xca29d0 lea rcx,[rip+0xdae85d] # 0x1a51234   ; 7-entry type table, indexed by type 1..7
    L1355 @0xca1cfb lea rcx,[rip+0xdaf4fe] # 0x1a51200   ; second table (type-1 append path)
    L1529 @0xca2048 lea rcx,[rip+0xdaf1c1] # 0x1a51210   ; third table (type-100 parser path)

Validation matrix (all STATIC):
| type | pre-dispatch validation | body |
|---|---|---|
| 3, 4 | `local_5c <= 0x10000` else 0x3f | copyout 8 bytes from stack `local_40` via 0x2591d0 |
| 7 | `local_68 <= 0x100` && `local_74 <= 0xf` else 0x16 | table 0x1a51234 |
| 1 | length clamped to 0x80000−used, copyin 0xc9c9a0, memcpy to ctx+0x58+used | table 0x1a51234 |
| 100 | `copyin(min(len,0x1000))` then `func_0x007b0ae0(buf,len)`, **return value discarded**, returns 0 | parser |
| **2, 5, 6** | **none** | table 0x1a51234 |

The gate itself: if `(*(u64*)(td+0x528) & 0x100) == 0` the type must be in 0xb8, else EPERM(1); if the bit **is** set the
mask is skipped entirely, so 1, 2, 6 and 100 become reachable — and 2/5/6 then go to the type table with no length,
count or pointer check in this function.

**Why it is novel.** Privilege here is not a credential — it is a *per-thread flag set by another command of the same
handler* (§2, L773). That means the handler is an ordered state machine: command A flips the thread into "trusted"
mode, command B then accepts request types that are otherwise EPERM. No public 2026 technique uses this shape
(command-sequenced state, not a race and not a parser bug).

**Falsification (2 syscalls, needs the two command numbers).** Call the type-request command with `type=2, len=0x10000,
buf=mapped` **before** attach → expect EPERM(1). Then attach (arg1 = 0 is a panic, so this specific chain is
post-leak). Cheaper pre-leak variant: sweep the type-request command with type ∈ {3,4,5,7} and observe EINVAL vs 0;
the EPERM-vs-EINVAL boundary identifies the gate, and the absence of a length check for type 5 can be shown by
`type=5, len=0x10000` returning something other than 0x3f/0x16.

---

## 4. FINDING 4: a 9-slot named object registry + a 256-entry user-object table (category "user data into a kernel object")

**STATIC.** Registry creation/registration strings resolved from `kernel_data.bin` (RVA−0x1000000):

    0x1382c26 "Sce.PSM:SdbInfo"      0x13251a9 "Sce.PSM:LogArea"     0x1305161 "Sce.Debug:UserObjArray"
    0x12dc08b "Sce.Debug:Gnm"        0x13641af "Sce.Debug:Gn2"       0x13251b9 "Sce.Debug:Gn3"
    0x12c6e96 "Sce.Debug:Gn4"        (9 slots total: kmalloc 0xd8, anchored at ctx+0xf0; per-slot name/slot/flags)

    L3663 @0xca40b3 mov r15,QWORD PTR [rdi+0xa8]        ; descriptor (user-controlled fields)
    L3665 @0xca40c0 test BYTE PTR [r15+0xc],0x1         ; flag consistency check on the descriptor
    L3681 @0xca40f7 call 0xc08b50                        ; malloc(0x30, M_WAITOK|M_ZERO)
    L3688 @0xca411f movzx eax,BYTE PTR [r15+0x10]        ; user byte copied into the kernel object
    L3695 @0xca4127 call 0xca64b0                        ; validate/attach
    L3725 @0xca41a8 mov rsi,QWORD PTR [r15+r13*8+0x2c0]  ; 256-entry pointer table, index from a user byte
    L3731 @0xca41b5 movzx edx,WORD PTR [rsi+0x11c]       ; u16 id compare
    L3736 @0xca41c0 cmp QWORD PTR [rsi+0xf0],0x0

**Mechanism.** A command takes a user descriptor, allocates a 0x30 kernel object, copies user dwords/bytes into it
(+0x18, +0x1c, +0x20, +0x28), validates it, then walks a 256-entry table of pointers at ctx+0x2c0 matching a u16 id at
+0x11c and a non-null field at +0xf0 — insert/replace semantics. This is the mechanism by which libmdbg registers
per-process debug buffers with the kernel. It is the mission's category (c) "store user data/pointers in a kernel
object for later use" in its purest form; the open question is whether any later consumer dereferences the stored
pointer as a *kernel* pointer (SMAP makes that a panic) or copies into it (safe, and a candidate kernel→user channel).

**Falsification (1–2 syscalls).** Register a descriptor with id 0x1234 and a pointer to our own buffer, then trigger
the log/printf path and see whether our buffer receives text (consumer is a copyout) or the call panics (consumer is a
raw deref). CONFIRM = bytes appear in our buffer without a 601 log-drain call.

---

## 5. Negatives from the corpus-wide shape scan (do not re-derive)

**STATIC.** Indirect-dispatch census over all 145 handlers: tables exist in 601 (×4: 0x1a51160, 0x1a51200, 0x1a51210,
0x1a51234), 622 (×5 @0x178xxxx), 532 (×2 @0x18de2xx), 630 (0x181d504), 643 (0x18d3f38), 646/647
(0x18dbfdc/0x18dc304/0x18dc244), 649/656/659/660/672 (0x14c02b0), 650/651/652/654/655 (0x159b8b0, 0x159ba7c,
0x159bb38, 0x18cdb30, 0x1a477b8/0x1a477ec/0x1a4785c/0x1a48030/0x1a480b8/0x1a480a8), 667 (0x1592fe8 + 6),
673 (0x18cdc98), 674 (0x18dbf54/0x18dbf68), 676 (0x172bf7c/0x172bf8c/0x172c134/0x172c144).
- **Every one of these tables lies outside the retained dumps** (all > 0x1400000 except 0x14c02b0, also outside), so no
  table index can be bound to a body statically. One heuristic hit at 0x13b9ed0 decoded as nonsense (not a table).
- No handler anywhere takes a function pointer or ops-table pointer from user memory and calls it (the only
  user-influenced indirect control transfer found is 601's own command table, where the index is range-checked by
  `cmp rax,0x27`).
- 601's copyin/copyout sites are all preceded by a log call naming the direction ("copyin" 0x1397f3d, "copyout"
  0x134f297, "copyinstr" 0x135a084 — **STATIC** strings, so the log records every transfer); no site uses a
  caller-supplied length without a clamp in this function.
- 601 registers deferred/event handlers at init, not from user input: 0x73dd40 is called with
  "process_exit"/"procexit_handler", "process_exec"/"procexec_handler", "process_exec_end", "procfork_handler",
  "process_suspend_phase2"/"_handler", "process_resume_phase2" (priority 20000). No user-influenced callout.
- 667's 0x28-byte thread records (u32 proc+0xbc, u32 thread+0x9c, 4×u64 thread+0x5b0..+0x5c8) remain behind the
  bit-62 predicate 0x608f90 (which is `(*(u64*)(cred+0x60) >> 62) & 1`), i.e. unreachable from bit 61.

---

## 6. Ranking

| # | finding | reachable now (bit 61) | yield | probe cost |
|---|---|---|---|---|
| 1 | log drain 0xca32b0 (§1) | **yes** (no gate in body) | kernel→user read; KASLR candidate | 1 syscall after number is known |
| 2 | attach 0xca12d5 (§2) | no — needs a valid kernel pointer (SMAP) | arbitrary kernel write | 1 syscall post-leak |
| 3 | type-gate state machine (§3) | partly (types 3/4/5/7 today) | unvalidated types 2/5/6 after attach | 2 syscalls, ordered |
| 4 | user-object registry (§4) | unknown (body has no credential test) | user data into kernel object; possible copyout channel | 1–2 syscalls |

Recommended order of work: (i) find the drain command number by sweep (§1 fingerprint), (ii) if the log carries a %p,
the project has KASLR and §2/§3 open up, (iii) otherwise try §4's register-then-trigger.

## 7. The one measurement per finding

1. **Drain:** `cmd(buf=0x1000 mapped, len=0x1000, 0)` → does the buffer start with "mDBG:"?
2. **Attach:** `cmd(arg1=<kernel pointer>, 0, 0)` → return 0 (ctx installed) vs #PF at arg1+0x148?
3. **Type gate:** `type=2,len=0x10000` before vs after the state-bit command → EPERM(1) vs dispatch?

## Measured correction (2026-11-04 16:10): finding 1 is not reachable from uid 1

Finding 1 (the unprivileged log drain) was a static read of the body. It has now been swept behaviourally
over the whole command space with the sweep in `docs/MDBG_601_COMMAND_MAP_14_10.md`:

* 0x00-0xFF all measured, seven argument shapes tried on the ten commands that return 0 (`1179a`), buffer
  in argument 1 and length in argument 2 confirmed by shape C/D/E returning -1.
* **No command ever wrote ASCII**, `grep -r mDBG results/` is still zero, and the three writing commands
  emit fixed out-params (0x100/0, 0/0, 0) that do not vary with buffer, length or flags.

So the drain body exists but is behind the type gate at `0xca2320`, which is unlocked by attach - and
attach needs a kernel `struct proc*`. Finding 2 (attach) is therefore the only live item in this document,
and it is post-leak only.

## Update 2026-11-09 — pointer chasing out of copied user bytes, swept and empty

The audits this document collected up to now each answered a different question: `WriteSites` asked
whether a handler stores to an argument-derived destination, `UnprivCopyDst` whether a destination comes
out of a caller structure, `OffsetWrites` whether a caller value indexes a kernel array, and `KptrSource`
whether a copyout source is caller-selected. None of them asked the simplest question of all: **does any
handler load a pointer out of a buffer it copied from the caller and then dereference it?**

`.local/ptrchase2.py` answers it over the linear decode of the 13.60 text
(`.local/ktext_ins.pkl`, 5 343 048 instructions):

1. all 432 call sites of `copyin` (`0xffffffff8ac19280`) are located;
2. for each, the destination is resolved from the `lea rXX, [rbp - N]` / `mov rsi, rXX` pair that
   precedes the call (297 of 432 resolve; the rest pass a heap pointer or a register set out of sight)
   and the copy length from the following `mov edx, imm` (constant lengths only, `0 < len <= 0x400`);
3. registers loaded with a **qword from inside `[rbp-N, rbp-N+len)`** are tainted, a clobber model drops
   them at calls and rewrites, and any subsequent instruction with a memory operand based on a tainted
   register is reported.

790 field loads and 173 deref-shaped hits came back. Bounding the window by the real copy length cuts
them to one, and that one is a `lea` (`0xffffffff8b344fc3`, `lea rcx, [rax - 1]` — a range check,
`cmp rcx, [rbp-0x1018]; jae fail`, followed by an alignment test), not a dereference. The other 172 were
stack locals adjacent to the buffer being mistaken for fields of it: `kevent` (363) reads its `struct
file *` from `[rbp-0x148]`, four bytes above a 0x10-byte copyin at `[rbp-0x158]`, and `shutdown` (134),
`setsockopt` (105) and `getsockopt` (118) do the same thing with their own locals.

**Result: no syscall body reachable on 14.10 follows a pointer taken from caller bytes**, at depth 1 and
with constant copy lengths. Combined with the four audits above, the syscall boundary on this firmware is
closed for both directions — nothing writes to a caller-chosen address, nothing reads from one, nothing
indexes a kernel array with a caller value, and nothing chases a caller pointer.

Two limits on that statement, both deliberate:

* the 135 copyin sites whose destination is not a stack local were not followed (they copy into a
  `kmalloc`ed object, where a field read is a fixed-offset load from a heap base rather than an `rbp`
  displacement — the taint model would need to track the allocation instead);
* depth 2 was not swept for this pattern. The 13.60 `PtrChase` scout that was meant to do it died on an
  upstream model error, and the mechanical scan above replaced it at depth 1.

Correcting the earlier reading of `results/phase36_realargs/1473a_evfilt_aio_lifetime_20261109_181742.txt`:
that capture's `rv=1` values on `EVFILT_AIO` are `EV_ERROR` echoes, not delivered events. A change-only
`kevent` on a live AIO identifier returns `-1`/EPERM (`1473b`), so the filter does not exist here and the
"stale knote" reading is withdrawn.

## Update 2026-11-09 — the copyout LENGTH axis, and the socket-name clamps

The sweeps above all asked "can the caller choose the *address*". They never asked "can the caller choose
the *length*", which is a different bug: `copyout(kernel_src, user_dst, len)` validates only the
destination, so a caller-chosen `len` over a fixed kernel buffer is an over-read — a stack or heap
disclosure — with no address control at all.

That question was opened by a corrected reading of the two helpers. The project had the argument order
backwards:

* **`0xffffffff8ac191d0` is copyout `(kernel_src = rdi, user_dst = rsi, len = rdx)`.** It validates and
  masks `rsi` (`add rax, rsi+rdx`, `jb` overflow, `ja 0x800000000000`, `and rsi, 0x7fffffffffff` at
  `0x8ac19227`), then `xchg rdi, rsi` and `rep movsq`. So the unvalidated register is `rdi`.
* **`0xffffffff8ac19280` is copyin `(user_src = rdi, kernel_dst = rsi, len = rdx)`**, masking `rdi` at
  `0x8ac192fd`.

A register-provenance scan over every call site (`.local/copy_dst_scan.py`, 140-instruction backward walk,
`lea` vs `mov` distinguished — conflating them produces 47 and 81 false hits) gives:

| helper | sites | caller value reaches the unvalidated register | verdict |
|---|---|---|---|
| copyin, kernel destination `rsi` | 432 | 0 | no caller-chosen kernel write |
| copyout, kernel source `rdi` | 539 | 3 | all three in the socket-name family, all safe (below) |

The three survivors are `0xffffffff8aef1151` (accept), `0xffffffff8aef30d5` (getsockname) and
`0xffffffff8aef33b5` (getpeername). In each one `rdi` is written by an inner helper that returns a kernel
pointer, and the slot was only matched because a larger `copyin` range overlapped it — the source is not
caller-derived.

**But the same three sites did expose a caller-controlled *length*.** The pattern in all three handlers is

```
copyin(4 bytes from uap[2], &len)        ; the caller's *namelen
helper(td, fd, &sa, &len)                ; fills sa, and clamps len
copyout(sa, uap[1], len)                 ; len is now the clamped value
copyout(&len, uap[2], 4)                 ; write the clamped length back
```

and the clamp is present in every one of them:

* getsockname, helper `0xffffffff8aef2e60`: `mov edx,[r15]` / `movzx eax,byte [rcx]` (sa_len) /
  `cmp edx,eax` / `cmovb eax,edx` / `mov [r15],eax` at `0x8aef2f9c`-`0x8aef2fb2` — `min(sa_len, caller_len)`.
* accept, helper `0xffffffff8aef08a0`: `mov rcx,[rbp-0x98]` / `cmp dword ptr [rcx],eax` / `jbe` /
  `mov dword ptr [rcx],eax` at `0x8aef0ef6`-`0x8aef0f01`.
* getpeername shares getsockname's helper shape.

So an oversized `namelen` is capped at the sockaddr's own length: **the socket-name family is not an
over-read**. The lesson is that the clamp lives one call down, inside the helper, not between the `copyin`
and the `copyout` in the handler — a scan that only reads the handler body would report these as unclamped
and be wrong.

`probes/phase36_realargs/1520a_sockname_namelen_overflow.lua` was written to measure this on 14.10 and
then deleted unsent once the clamps were found statically; no console run was spent on it.

Still open: the same length question for every other stack-source copyout. That sweep is running; the
candidate shape is a frame local as `rdi` with an `rdx` that traces to a `copyin` or to `[uap+N]` and no
compare in between.

## Update 2026-11-10 - the copyout LENGTH axis, swept separately from the pointer axis

The earlier section swept the SOURCE pointer at all 539 `copyout` sites and found
no site whose source is caller-selected. That leaves a different question open:
the source is a kernel stack buffer, and **the length** is the caller's. A kernel
stack buffer copied out at a length the caller chose discloses stack residue -
return addresses, saved registers, pointers into kernel data - which would be the
project's first kernel read.

Re-swept from `.local/ktext_ins.pkl`. Filter: the instruction that last sets
`rdi` before the call must be `lea rdi,[rbp-N]` (a real stack buffer address,
**not** `mov rdi,[rbp-N]`, which loads a pointer *stored* on the stack - that
distinction is the same `lea`-vs-`mov` bug that produced 47 false hits in the
first pass), and the instruction that last sets `rdx` must not be a constant
under 0x10000. Result: **20 sites**. Of those, 8 also have a `copyin` within 200
instructions, i.e. the length plausibly originates in user memory.

Every one is clamped, and the idiom is consistent - `mov reg,SIZE; cmp
caller_len,SIZE; cmovb reg,caller_len`, i.e. `min(caller_len, sizeof(buffer))`:

| site | stack buffer | clamp |
|---|---|---|
| `0xffffffff8b228ddf`-`0x8b228de8` | `[rbp-0xa8]` (0xa8 B) | `mov r14d,0x80` + `cmovb r14d,edx` |
| `0xffffffff8b228f47`-`0x8b228f4d` | `[rbp-0x60]` (0x60 B) | `mov r14d,0x40` + `cmovb r14d,edx` |
| `0xffffffff8b1659f5` | `[rbp-0x5b0]` (0x148 B) | `cmp r12,r14; cmovb r14,r12` then `shl r14d,2` - bounded by the entries actually filled |
| `0xffffffff8b66195a` | `[rbp-0xf0]` (0x40 B) | `and r12d,0x7fffffff; mov ebx,0x28; cmovb rbx,r12` (601 body, unreachable anyway) |
| `0xffffffff8ad81d63`-`0x8ad81d7e` | `[rbp-0x430]` | formatter `0x8ae04eb0(buf, 0x3ff)` returns its length, `inc eax`, `movsxd r14,eax` |

Two points worth keeping:

- **`movsxd r14,eax` after a formatter is not a bug.** A negative return would
  sign-extend to a huge length, but `copyout` bounds `dst+len` against
  `0x800000000000` and fails, so the outcome is EFAULT rather than a leak.
- **`0x8b1659f5` is the only site where the length tracks a counter rather than
  a constant.** It is safe in the copyout direction because the copyout is
  limited to the entries the loop filled; whether the loop itself can index past
  `0x148` bytes is a separate question and is not a copyout issue.

Conclusion: on the 13.60 text, **no reachable copyout exposes kernel stack
residue**. Combined with the pointer sweep (no caller-selected source) and the
copyin sweep (no caller-chosen destination), the three axes of the copy-helper
surface are each empty.

## Update 2026-11-10 - the one status-array candidate is bounded

`0xffffffff8b1659c0` writes `0x1000000N` status dwords through
`mov dword ptr [rbp+r12*4-0x5b0], 0x100000NN` into what looks like an unbounded
loop, and `0x8b165a26` then copies `min(r12,r14)*4` bytes of that array to a user
pointer. It read as a stack overflow candidate because the array is only
`0x148` bytes. It is not one:

- Function start `0xffffffff8b163d80`: `push rbp; mov rbp,rsp; push r15/r14/r13/
  r12/rbx; sub rsp,0x638`. Canary installed at `0x8b163da1`-`0x8b163da5`
  (`mov [rbp-0x30],rax`), so the array at `[rbp-0x5b0]` spans exactly
  `0x148` bytes and the locals between it and the canary are untouched.
- The block is **unrolled, not looped**: `0x8b1658c5 mov r12d,1`, then eight
  guarded `inc r12` (`0x8b1658e6`, `0x8b16590c`, `0x8b16592c`, `0x8b16594c`,
  `0x8b16596c`, `0x8b16598c`, `0x8b1659ac`, `0x8b1659cc`), each behind
  `test eax,eax; jne` after `call 0xffffffff8b65fc00(obj,n)`. Highest store
  index is 8 of 82.
- The copyout length is `min(r12,r14)` with `r12 <= 9` unconditionally
  (`0x8b1659eb cmp r12,r14` / `0x8b1659f5 cmovb r14,r12`), so it can never
  exceed 36 bytes whatever `r14` holds.
- The `jmp 0xffffffff8b165850` loop that does iterate (`cmp r12,r9`,
  `mov [r13+r9*4],r10d`) writes a different array based at `r13`, not the stack.

Verdict: bounded, 89% of the array unused.

## Update 2026-11-10 - the signed-compare length bug cannot become a copy

`LenAudit` swept all 971 `call` sites (539 copyout, 432 copyin) for two classes
the earlier pointer/destination/length axes did not cover: a **signed** compare on
the length (48 sites have one; 132 have only an unsigned one) and a **multiplied**
length (36 sites). 709 of the 971 lengths are compile-time constants.

One site has a genuinely broken test - `0xffffffff8aef265c`, in the socket layer
near `0xffffffff8aef22a0`:

```asm
0x8aef2617  mov    r13d, dword ptr [rax+0x28]   ; budget, zero-extended
0x8aef262f  movsxd r12, dword ptr [r15+0x18]    ; length, SIGN-extended from 32 bits
0x8aef2633  cmp    r13, r12
0x8aef2636  jl     0xffffffff8aef2683           ; signed: a negative r12 never takes it
0x8aef2659  mov    rdx, r12
0x8aef265c  call   copyout
```

`[r15+0x18]` is stored as a qword at `0x8aef24ac` (`r14 - [rbp-0x58]`, the bytes
moved) and read back as a **32-bit sign-extended** value, so a single transfer of
2 GiB or more would make `r12` negative and skip the budget test entirely.

**It still cannot leak.** `copyout` itself validates first thing:

```asm
0x8ac191f0  mov  rax, rsi          ; dst
0x8ac191f3  add  rax, rdx          ; dst + len
0x8ac191f6  jb   0x8ac19260        ; carry -> clac + EFAULT
0x8ac191f8  movabs rcx, 0x800000000000
0x8ac19205  ja   0x8ac19260        ; above the user half -> EFAULT
```

A sign-extended negative length always carries, so it fails before a byte moves.
The only shape that would survive is a large *positive* length (e.g. `0x7fffffff`),
which needs the same 2 GiB single transfer the budget test exists to prevent.

Verdict: a real correctness wart on the socket path, not a copy primitive. The
signed-compare and multiplied-length classes both close empty.

### Correction: syscall 573 has a native body, so "nosys" was the wrong table

`StatusArray` traced the 0x80-byte stack array to its entry point and found the
project's own negative was built on the wrong row:

- `docs/sysent-names-13.60.csv:575` -> `573,mdbg_call,0x266360`; the thunk at
  `0xffffffff8ac26360` is `jmp 0xffffffff8b65c830`, and that body copyins three
  user structs (`0x40` from `uap+8`, `0x20` from `uap+0x10`, `0x20` from `uap+0`)
  and dispatches into `0xffffffff8b163d80` at `0x8b65c934` with selector 1.
- `docs/sysent-compat-names-13.60.csv:575` gives `0x265760`, which is the shared
  `nosys` trampoline. `results/kernel_handlers/analysis/sys_573.md` was generated
  from that compat slot, so its "unimplemented / ENOSYS" verdict describes the
  wrong table.

`337a` measured 573 killing the process (and once powering the console off), and
under the project's own rule a kill is a result about the call, never proof the
slot is absent. The two facts are consistent: the native body exists and faults on
the shapes 337a tried. **The recorded dead-end bullet "573 mdbg_call is the nosys
trampoline" is withdrawn as a claim about the handler; what survives is "573 kills
on the shapes tried so far, including a console power-off."**

No probe was written for it. The body's dispatch table (`0x8b0f0600`, 49 cases) is
undumped in the same way 601's tables are, and 337a's power-off makes it a poor
first target while cheaper static lines remain.

### The signed-length site is reachable and still an EFAULT

`LenAudit` closed the last question on `0xffffffff8aef265c` - the site is on the
**`recvmsg`** path (sysent entry 27, stub `0xffffffff8ac25840 jmp 0xffffffff8aef29e0`),
and the accumulator it sign-extends is genuinely caller-shaped:

```asm
0x8aef237f  (zero)  [rbp-0x58]
0x8aef23a0  add     rdx, qword ptr [rax]     ; over [rsi+0x18] iovecs, step 0x10
0x8aef23a7  js      fail                     ; the only guard
```

The iovec array lives in the 0x30-byte descriptor the handler copies in at
`0xffffffff8aef2a2b`, so the total can exceed 2 GiB and bit 31 of the delta at
`0x8aef24ac` can be set. The budget word `[rax+0x28]` read at `0x8aef2617` is
caller bytes too, and the `jl` at `0x8aef2636` is signed, so a negative length
skips it even after the budget has been reset to 0 at `0x8aef261b`.

It still cannot read. Nothing between `0x8aef2636` and the call touches `rdx`, but
`copyout` validates before moving a byte:

```asm
0x8ac191f3  add rax, rdx          ; dst + len
0x8ac191f6  jb  0x8ac19260        ; carry -> clac, then
0x8ac19205  ja  0x8ac19260        ; above 0x800000000000 -> clac
0x8ac19277  mov rax, 0xe          ; EFAULT
```

`and rsi,0x7fffffffffff` and the `rep movsq` are never reached. `copyin` carries
the identical test at `0x8ac1928a`.

**Consequence for the whole class**: only a positive, zero-extended length
(<= 0x7fffffff) can over-copy, and every such length has to pass the same
`dst+len` test - so a top-bit-set length is always an EFAULT and the signed-compare
family contributes no primitive. Verdict: reachable EFAULT.

### The string axis closes too: all 74 copyinstr sites bounded

`StrAudit` swept the last helper (`0xffffffff8ac19900`, `copyinstr`) and first
pinned its semantics, which decide every verdict:

```asm
0x8ac19930  xchg   rdi, rsi                  ; rdi = kernel dst, rsi = user src
0x8ac19987  inc    rdx; cld
0x8ac1998b  dec    rdx; je done              ; budget charged BEFORE each byte
0x8ac19993  lodsb  al, [rsi]
0x8ac19994  stosb  [rdi], al
0x8ac19995  or     al, al; jne loop          ; NUL is charged too
done: 0x8ac1999c dec rdx; xor eax,eax        ; success
      0x8ac199a3  cmp rsi, 0x800000000000; jae -> EFAULT(14) else ENAMETOOLONG(0x3f)
```

So the maximum written offset is `len-1`, the terminator counts against the
budget, `len=0` writes nothing, and there is no `dst+len` off-by-one.

**All 74 sites are bounded.** The failure mode the audit was looking for - a
constant `MAXPATHLEN 0x400` written into a smaller stack slot or struct field -
does not exist: every `0x400` bound lands in an exactly-`0x400` allocation, a
`0x400` UMA zone item, a `>=0x408` stack slot, or a `0x44000` kmem buffer. The
`0x20`-style bounds land in `0x50`/`0x130` slots or `0x20`/`0x10` mallocs. Two
sites are the only shapes worth naming: `0x8ad81d49` appends with a budget that
already shrank (`mov edx,0x400; sub edx,eax`), and `0x8ae3d33a` allocates and
copies with the same `cmovb`-selected length.

The single site with an unproven capacity - `0x8aeefc6e`, `copyinstr(user, obj+0x4e0, 0x20)`
- is a field on an object the same function already writes a dword at `+0x440`
of, so the struct is at least `0x444` and a `0x4e0` field is plausible by design.
No evidence of a bug; the capacity is unproven rather than violated.

**Result: the copy and string helper surface is empty on every axis** - source
pointer (539 copyout), destination (432 copyin), length (539), signed compare
(48), multiplied length (36), string bound (74).

