# Top 5 Ranked Syscall Handlers — Caller-Controlled Kernel Primitives

Firmware 13.60 static analysis (REA/Ghidra), 14.10 runtime observations.
Kernel base `0xffffffff8a9c0000`, AMD Zen 2, 16 KB pages.
`ucred+0x58` = `cr_sceAuthId`, `ucred+0x60/+0x68` = `cr_sceCaps`.

---

## Cross-Cutting Gate Facts

| Gate question | Corpus answer |
|---|---|
| Any handler checks `authid == 0x4800000000010003`? | **Only sys 532** (helper `0x609080` at RVA `af0123`). None of the top 5 does. |
| Any handler checks capability bits at `cred+0x80`? | **None.** The only `cred+0x80`-family tests are jail-style double tests at `0x609540`/`0x609560`/`0x6095a0` (`cred+0x82`). |
| Any handler directly dereferences a raw caller pointer (no copyin/copyout)? | **None** in their analysed bodies. Every user-memory access goes through copyin (`0x259280`/`0x2591d0`/`0x8ac191d0`) or copyout (`0x8aa63960`). |

The handlers below rank on: caller-supplied **length/index/offset used unchecked**, and caller-supplied **values stored into kernel objects by caller-determined index**, rather than raw-pointer dereference.

---

## #1 — sys 601 `mdbg_service` — CRITICAL

| Field | Value |
|---|---|
| Syscall | **601** |
| Handler RVA | **`0xca0630`** (image VA `0xffffffff8c660630`) |
| narg | **3** |
| Argument offsets | `uap+0x00` = cmd (32-bit, range 0x00-0x27); `uap+0x08` = arg2 (64-bit, pointer or scalar); `uap+0x10` = arg3 (64-bit, length or pointer depending on path) |

### Missing Checks (quoted)

**V1 — Unchecked process structure write (cmd 0x12)**
> `sys_601_deep.md:40-51`
> ```
> test eax, 0x400        ; one-shot gate (bit 10)
> jne  SKIP
> or   rax, 0x1000000    ; set bit 24 in proc flags
> mov  [r8+0x528], rax   ; write flags
> mov  rax, [rbp-0xf0]   ; user_data[0]
> mov  [r8+0x578], rax   ; WRITE arbitrary value
> mov  rax, [rbp-0xe8]   ; user_data[8]
> mov  [r8+0x580], rax   ; WRITE arbitrary value
> ```
> "Zero credential checks. First call always succeeds (one-shot bit only prevents re-execution."
> — `sys_601_deep.md:51`

Teardown confirms these are freed as kernel heap pointers:
> "Teardown confirms +0x578/+0x580 are kernel heap pointers freed via `0xfffffffffff687c0` (kfree). Cmd 0x12 writes user-controlled values there without auth → use-after-free or arbitrary kfree primitive."
> — `sys_601_deep.md:79`

**V2 — Ring buffer signed comparison bypass**
> `sys_601_deep.md:59-66`
> ```
> movsxd rdi, DWORD PTR [rbx+0x50]  ; SIGNED extend current offset
> lea    eax, [rdi+r12*1]           ; offset + new_size
> cmp    eax, 0x80001               ; compare against max
> jl     WRITE_OK                   ; SIGNED comparison!
> ```
> "Negative offset at +0x50 passes this check → heap underflow write."
> — `sys_601_deep.md:66`

**V3 — Second-stage signed length overflow**
> `SYS601_SECOND_STAGE_14_10.md:104-107`
> "type 1: allocates a per-process 0x80000 kernel buffer … `memcpy(ctx+0x58 + ctx+0x50, heap, len)` … behind a `used + len < 0x80001` signed check"

> `SYS601_SECOND_STAGE_14_10.md:109`
> "type 3: `malloc(len+1)` + `copyin(struct+0x18, heap, len)` — len wraps to 0"

### Gate Status

| Check | Present? | Detail |
|---|---|---|
| `authid == 0x4800000000010003` | **NO** | — |
| `cred+0x58` | Partial | Tag `0x4800000000000007` on some paths (`SYS601_SECOND_STAGE_14_10.md:56-59`) |
| `cred+0x80` capability bits | **NO** | — |
| Thread flag at `td+0x528` | Yes | Bit 0 at `td+0x529` selects second stage; bit 8 (`0x100`) unlocks second-stage body |
| Process flag at `proc+0x563` | Yes | Bit 2 (`&4`) on some case bodies |

**Alternative selector avoiding gate:** cmd 0x12 (V1) has **no credential check at all** — the only gate is the one-shot bit 0x400, which passes unconditionally on first invocation. The second stage is locked behind `td+0x528 bit 8`, but 601 itself sets that flag at `0xca131f: or qword [rax+0x528], 0x100` — a **self-bypass** via the attach case body, which reads `td_proc` from the calling thread (`SYS601_SECOND_STAGE_14_10.md:131-143`).

### Lua Call Shape

```lua
local sc601 = make_syscall(601)

-- V1: cmd 0x12, write arbitrary values to proc+0x578/+0x580
local buf = memory.alloc(0x100)
memory.write_qword(buf, uint64(ARBITRARY_KADDR_1))     -- -> proc+0x578
memory.write_qword(buf + 8, uint64(ARBITRARY_KADDR_2)) -- -> proc+0x580
sc601(uint64(0x12), uint64(buf), uint64(0x28))
-- args: cmd=0x12, arg2=buf (copyin source), arg3=length

-- Second stage: cmd that sets td+0x528 bit 8 (attach)
sc601(uint64(CMD_ATTACH), uint64(0), uint64(0))
-- then: second stage type 1 with negative len
sc601(uint64(CMD_SECOND), uint64(buf), uint64(out_ptr))
```
*(CMD_ATTACH and CMD_SECOND are unknown numerically — the jump table at RVA `0x1a51160` is outside the text dump; `SYS601_SECOND_STAGE_14_10.md:33-34`)*

### Observable Proving Success

- cmd 0x12: process teardown calls `kfree(proc+0x578)` and `kfree(proc+0x580)` — observable as crash/panic on process exit when caller values are non-heap addresses (`sys_601_deep.md:72,79`)
- Second stage type 1: 8-byte kernel-stack copyout to `arg3` when non-null (`SYS601_SECOND_STAGE_14_10.md:113-114`)
- Second stage type 3: `malloc(len+1)` with wrapping length → heap metadata corruption observable via subsequent allocations

### 14.10 Status

**CLOSED as a kernel-R/W route** via the 0x00-0x27 case table — capture `1195a` (tenth boot) confirms no command writes `arg3` bytes, no command writes `0x28` bytes, the EPERM set never flips, and the three targeted case bodies have zero direct callers in 14.10's image (`ATTACK_SURFACE.md:86`).

**Second stage is LIVE** on 13.60 — the flag setter at `0xca131f` exists and the second-stage dispatcher at `0xca2320` has exactly one inbound branch. Whether the attach case's numeric command is present in 14.10's jump table is **unmeasured** (`SYS601_SECOND_STAGE_14_10.md:33`, `ATTACK_SURFACE.md:86`).

### Citations

- `results/kernel_handlers/analysis/sys_601_deep.md:40-51` (V1 — cmd 0x12)
- `results/kernel_handlers/analysis/sys_601_deep.md:59-66` (V2 — signed compare)
- `results/kernel_handlers/analysis/sys_601_deep.md:72,79` (teardown kfree)
- `docs/SYS601_SECOND_STAGE_14_10.md:104-114` (V3 — second stage types 1/3)
- `docs/SYS601_SECOND_STAGE_14_10.md:131-143` (self-bypass setter)
- `docs/ATTACK_SURFACE.md:86` (14.10 closure)

---

## #2 — sys 622 `ipmimgr_call` (Device Control Multiplexer) — HIGH

| Field | Value |
|---|---|
| Syscall | **622** |
| Handler RVA | **`0x7dcd40`** (image VA `0xffffffff8c19cd40`) |
| narg | **6** |
| Argument offsets | `uap+0x00` (slot 0, `r14d`) = command (32-bit); `uap+0x08` (slot 1, `r15d`) = sub-command / device index; `uap+0x10` (slot 2, `[rbp-0x80]`) = user buffer pointer; `uap+0x18` (slot 3, `r13`) = copyin source; `uap+0x20` (slot 4, `r12`) = size (max 0x40); `uap+0x28` (slot 5) = extra |

### Missing Checks (quoted)

**V1 — 292+ commands with no privilege check**
> `sys_622_deep.md:131-140`
> | Range | # Commands | Notes |
> | 0x200-0x270 | 113 | Direct copyin + dispatch, zero auth |
> | 0x302-0x320 | 31 | Direct copyin + dispatch, zero auth |
> | 0x400-0x493 | 148 | Direct copyin + dispatch, zero auth |
>
> "CRITICAL: Over 300 command codes have NO privilege check whatsoever."
> — `sys_622_deep.md:140`

**V2 — Integer underflow in buffer size check**
> `sys_622_deep.md:250-256`
> ```
> r15 = [rax+0x10]        ; buffer limit
> add r15, -0x18           ; subtract header
> cmp rbx, r15             ; check user size vs limit
> ```
> "If `[rax+0x10] < 0x18`, the subtraction underflows to ~0xFFFFFFFFFFFFFFE8, bypassing the bounds check completely."
> — `sys_622_deep.md:256`

**V7 — Unvalidated callback function pointer storage**
> `sys_622_deep.md:326-330`
> "8 global callback slots at 0x32582B0-0x32582E8. Scans for first NULL slot, stores function pointer. … No validation of the function pointer stored."
> — `sys_622_deep.md:330`

### Gate Status

| Check | Present? | Detail |
|---|---|---|
| `authid == 0x4800000000010003` | **NO** | — |
| `cred+0x58` | Partial | Tags `0x4800000000000007`/`0x4800000000000006` via bitmap on commands `0x100-0x133` only (`sys_622_deep.md:68-78,118-129`) |
| `cred+0x80` capability bits | **NO** | — |
| Bitmap gate | Yes | First bitmap `0xF8FFF000000D5` on `0x100-0x133`; second `0x600000000000` on `0x12D-0x12E`; ~15 commands in `0x100-0x133` also skip auth |

**Alternative selector avoiding gate:** Commands `0x200-0x270`, `0x302-0x320`, `0x400-0x493` (292 commands) need **zero authentication** — no credential read, no bitmap, no custom check (`sys_622_deep.md:131-140`). The gate applies only to `0x100-0x133`.

### Lua Call Shape

```lua
local sc622 = make_syscall(622)
local buf = memory.alloc(0x40)

-- V1+V2: unauthenticated command reaching type-0x10 ioctl with underflow
-- cmd in 0x200-0x270, sub-cmd = device index, buf = copyin source
sc622(uint64(0x200), uint64(DEVICE_INDEX), uint64(buf), uint64(buf), uint64(0x40), uint64(0))
-- args: cmd, sub-cmd, user-buf, copyin-src, size, extra

-- V7: callback registration (if reachable from an unauthenticated path)
-- slot 0x55A0 stores caller pointer into global at 0x32582B0
sc622(uint64(CMD_CALLBACK_REG), uint64(0), uint64(FUNC_PTR), uint64(0), uint64(0), uint64(0))
```

### Observable Proving Success

- Commands 0x200-0x270: reach device manipulation code; on slot-0 layout, `0x300/0x301` return `0` and write `0xFFFFFFFF` to the result field (`ATTACK_SURFACE.md:85`)
- V2 underflow: if a device descriptor has `buffer_limit < 0x18`, the bounds check passes for any size → kernel heap overflow, observable as corruption/panic
- V7: callback invocation on the next device event would jump to the stored pointer

### 14.10 Status

On slot-0 layout (the measured device context): commands `0x201-0x271` are mapped, with only `0x271` returning `0x8002004E` (credential predicate); all others return default error `0x800E0001` ("no device context"). `0x302` is **lethal** for every input tested (kills process). Slots 1, 5, 6 are **untested** — a device context on a different slot could unlock the 292 unauthenticated commands. Capture: `1152a` (2026-11-04), `1039a`/`1053a`/`1054a` for 0x302 (`ATTACK_SURFACE.md:85`).

### Citations

- `results/kernel_handlers/analysis/sys_622_deep.md:131-140` (V1 — no auth on 292 commands)
- `results/kernel_handlers/analysis/sys_622_deep.md:250-256` (V2 — integer underflow)
- `results/kernel_handlers/analysis/sys_622_deep.md:326-330` (V7 — callback storage)
- `results/kernel_handlers/analysis/sys_622_deep.md:68-78,118-129` (gate bitmap)
- `docs/ATTACK_SURFACE.md:85` (14.10 status)

---

## #3 — sys 669 `_aio_submit_cmd` — HIGH

| Field | Value |
|---|---|
| Syscall | **669** |
| Handler RVA | **`0x3b2060`** (image VA `0xffffffff8ad72060`) |
| narg | **5** |
| Argument offsets | `uap+0x00` = cmd/flags (32-bit); `uap+0x08` = user descriptor array (64-bit pointer); `uap+0x10` = count (32-bit, bounded 1-128); `uap+0x18` = queue class (32-bit, 1-3); `uap+0x20` = user output pointer (64-bit) |

**Descriptor stride 0x28:**
| Offset | Width | Field |
|---|---|---|
| `+0x00` | 64 | signed I/O offset |
| `+0x08` | 64 | byte count |
| `+0x10` | 64 | data/buffer pointer |
| `+0x18` | 64 | result pointer |
| `+0x20` | 32 | file descriptor |

### Missing Checks (quoted)

**V1 — Caller-addressed 4-byte atomic decrement via delete path**
> `AIO_RANGE_14_10_EVIDENCE.md:1234-1246`
> "the reclaim primitive exists inside the family. After one duplicate free in the 48-byte class, a later create can land `C1 == D2`: the descriptor bytes written for object 2 become the context of object 1 … The delete of object 1 then reads `[C+0x10]`, which is descriptor offset `0x10` — the **buffer** field — and passes it to `0x8ac69670`, whose body is `lock xadd dword [rdi], -1` plus, when the old value was 1, a free chain over `+0x20..+0x38` and `+0x118`. That is a caller-addressed 4-byte decrement reachable from a caller-controlled field."

The descriptor's `+0x10` field (the data pointer) is copied verbatim from userspace with no address validation in the delete path. The static analysis window notes:
> "No arbitrary-memory primitive, exploit, or runtime failure is established by this static window."
> — `sys_669_deep.md:91`

### Gate Status

| Check | Present? | Detail |
|---|---|---|
| `authid == 0x4800000000010003` | **NO** | — |
| `cred+0x58` | **NO** | No credential helper anywhere in the submission body |
| `cred+0x80` capability bits | **NO** | — |
| Boot-state global | Yes | `0xb078d0` (sysctl tunable at `0xffffffff8c2a446c`) — returns 1 when state is 3 or 4 |
| File-level auth | Deferred | To the enqueue helper at `+0x1a30`, not the submission entry |

**Alternative selector avoiding gate:** There is **no credential gate** to avoid. The boot-state global passes on 14.10 (state == 3 or 4, `AIO_RANGE_14_10_EVIDENCE.md:1279`). `cmd & 0xfff` must be 1 or 2 (`sys_669_deep.md:34`).

### Lua Call Shape

```lua
local sc669 = make_syscall(669)
local data = memory.alloc(0x4000)
local ids  = memory.alloc(0x100)

-- Fill one descriptor at stride 0x28:
-- +0x00: offset, +0x08: byte_count, +0x10: data_pointer,
-- +0x18: result_pointer, +0x20: fd
memory.write_qword(data + 0x00, uint64(0))              -- offset
memory.write_qword(data + 0x08, uint64(LENGTH))          -- byte_count
memory.write_qword(data + 0x10, uint64(USER_BUFFER))     -- data pointer
memory.write_qword(data + 0x18, uint64(RESULT_PTR))      -- result pointer
memory.write_dword(data + 0x20, FD)                      -- file descriptor

-- Submit: flags=1 (read), descriptors, count=1, class=1, output ids
local rv = sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(ids))
```

### Observable Proving Success

- Create/submit: returns a positive 32-bit identifier; bytes land in the caller buffer from `/dev/urandom` reads (`AIO_RANGE_14_10_EVIDENCE.md:1279-1284`)
- Poll (sys 664): returns `3` for completed, `0x10003` for stale (`AIO_RANGE_14_10_EVIDENCE.md:1299`)
- Delete race: capture `568a` recorded 100/100 ids with duplicate status 0 by racing helpers (`AIO_RANGE_14_10_EVIDENCE.md:1323`)

### 14.10 Status

**WORKS.** Create and submit confirmed; the request runs in kernel context. The delete-path dereference via descriptor `+0x10` is reachable after a UAF race in the 48-byte slab class. Not established: that the allocator actually duplicates the chunk (capture `568a` needed), and that `C1 == D2` can be forced (`AIO_RANGE_14_10_EVIDENCE.md:1248-1249`). The concurrent second delete takes the status-only branch and does not free — the measured double-zero is a **benign duplicate status**, not a second free (`AIO_RANGE_14_10_EVIDENCE.md:1321-1324`).

### Citations

- `results/kernel_handlers/analysis/sys_669_deep.md:23-29` (argument layout)
- `results/kernel_handlers/analysis/sys_669_deep.md:36` (count bound 1-128)
- `results/kernel_handlers/analysis/sys_669_deep.md:50` (descriptor stride)
- `results/kernel_handlers/analysis/sys_669_deep.md:91` (static limitation)
- `docs/AIO_RANGE_14_10_EVIDENCE.md:1234-1246` (delete-path decrement)
- `docs/AIO_RANGE_14_10_EVIDENCE.md:1279-1284` (boot gate passes)
- `docs/AIO_RANGE_14_10_EVIDENCE.md:1321-1324` (race outcome)

---

## #4 — sys 625 `opmc_set_hw` — HIGH

| Field | Value |
|---|---|
| Syscall | **625** |
| Handler RVA | Trampoline **`0x265eb0`**, body **`0x603c90`** (image VA `0xffffffff8afc3c90`) |
| narg | **4** |
| Argument offsets | `args+0x00` = command (32-bit, range 1-23); `args+0x08` = domain (32-bit, 1-3); `args+0x10` = index (32-bit, -1..5 or -1..7); `args+0x18` = raw_value (64-bit, full caller-controlled MSR payload) |

### Missing Checks (quoted)

> "There is **no explicit credential read/test in this root** and direct hardware writes occur in its visible blocks."
> — `sys_625.md:46`

**Caller value → MSR write paths:**
> "The indexed counter-write block writes odd addresses 0xc0010231+2*index; index -1 writes all six odd addresses through 0xc001023b."
> — `sys_625.md:38`

> "Helper 0xffffffff8afc4990 … writes index<=3 at 0xc0010240+2*index … The low32 payload is value low32; high32 is `(((value & 0x1800000000000000)*4)+(value & 0xf00000000))>>32`"
> — `sys_625.md:40`

> "Helper 0xffffffff8afc4c50 writes raw64 to odd counterpart addresses 0xc0010241+2*index for index<=3"
> — `sys_625.md:42`

### Gate Status

| Check | Present? | Detail |
|---|---|---|
| `authid == 0x4800000000010003` | **NO** | — |
| `cred+0x58` | **NO** | No credential read in root body |
| `cred+0x80` capability bits | **NO** | — |
| Dispatcher policy | Unknown | "dispatcher policy is outside the target, and the missing table prevents definitive numeric command mapping" (`sys_625.md:46`) |

**Alternative selector avoiding gate:** There is **no credential gate in the root body**. Domain/index bounds are the only restriction (domain 1-3, index -1..5 or -1..7 depending on hardware ID). The command `(command-1) <= 22` range check is unsigned (`sys_625.md:12`).

### Lua Call Shape

```lua
local sc625 = make_syscall(625)

-- Write a 64-bit value to counter MSR 0xc0010231+2*index (domain 1):
sc625(uint64(CMD_COUNTER_WRITE), uint64(1), uint64(INDEX), uint64(VALUE),
      uint64(0), uint64(0))
-- args: command, domain, index, raw_value64 (+ 2 unused slots)

-- Measured working pairs on 14.10:
-- sc625(uint64(0x0D), uint64(1), uint64(0), uint64(0))  -> returns 0
-- sc625(uint64(0x0E), uint64(2), uint64(0), uint64(0))  -> returns 0
```
*(CMD_COUNTER_WRITE is unknown numerically — jump table at `0x8c0e3560` is outside available data; `sys_625.md:14`)*

### Observable Proving Success

- 14.10: commands `0x0D, 0x0E, 0x0F, 0x10` with domain `{1, 2, 3}` return `0` (`ATTACK_SURFACE.md:233-234`)
- sys 626 (getter): returned `-1` for all 1270 shapes, including the exact pairs 625 accepts — **no readback** (`ATTACK_SURFACE.md:235-236`)
- MSR writes are to AMD performance counter registers (L2 PMC); observable effect requires PMC-level side-channel measurement

### 14.10 Status

**PARTIALLY OPEN.** The setter accepts a narrow window (`cmd ∈ {0x0D-0x10}`, `domain ∈ {1,2,3}`) and returns 0. The getter (sys 626) never answers, so there is no readback. Hardware-level effects (PMC configuration) are real but **no MSR read, no KASLR leak, and no privilege bypass is established** from 14.10 probes. Captures: `180a`, `181a`, `182a` (`ATTACK_SURFACE.md:237-240`).

### Citations

- `results/kernel_handlers/analysis/sys_625.md:6` (RVA and narg)
- `results/kernel_handlers/analysis/sys_625.md:12` (command range)
- `results/kernel_handlers/analysis/sys_625.md:16` (argument layout)
- `results/kernel_handlers/analysis/sys_625.md:27,38-42` (MSR write paths)
- `results/kernel_handlers/analysis/sys_625.md:46` (no credential test)
- `docs/ATTACK_SURFACE.md:233-240` (14.10 probes)

---

## #5 — sys 648 `app_state_change` (GPU/Display Context Manager) — MEDIUM

| Field | Value |
|---|---|
| Syscall | **648** |
| Handler RVA | **`0x9f81f0`** (image VA `0xffffffff8c3b81f0`) |
| narg | **1** |
| Argument offsets | `uap+0x00` = user pointer to 376-byte (0x178) parameter structure (64-bit) |

### Missing Checks (quoted)

**V2 — Scatter-gather size validation gap**
> `sys_648_deep.md:148-160`
> ```
> offset 0x10c2: cmp rsi, 0x100001         ; max size 1MB + 1
>                jb  0x10eb                 ; ok
> ```
> "Size is validated against 0x100001 but … the allocation call at 0xffffffffffa322f0 uses the uncapped size directly. If the allocator returns fewer pages than needed, the copy loop could read past allocated memory."
> — `sys_648_deep.md:354-356`

**V4 — Race condition in context bitmask (caller-indexed slot)**
> `sys_648_deep.md:362-364`
> "The free context bitmask at `[rip+0x31bbf3c]` is read, modified (TZCNT + BTR), and written back without holding a lock. If two threads enter 0x2020 simultaneously, they could both claim the same context slot, leading to a use-after-free or double-free condition."

**V5 — Non-atomic refcount**
> `sys_648_deep.md:366-368`
> "Event handler objects are referenced via increment (`lea ecx, [rax+0x1]; mov [rbx+0xc], ecx`) and decremented after iteration (`dec eax; mov [rbx+0xc], eax`). These increments/decrements are NOT atomic."

### Gate Status

| Check | Present? | Detail |
|---|---|---|
| `authid == 0x4800000000010003` | **NO** | — |
| `cred+0x58` | Indirect | Four custom `priv_check` helpers at `0xffffffffffc10f20`, `0xffffffffffc10ee0`, `0xffffffffffc10eb0`, plus one more — OR-gated (`sys_648_deep.md:34-56`) |
| `cred+0x80` capability bits | **NO** | — |
| Privilege model | OR-based | "A process needs only ONE of four different privileges to access the handler" (`sys_648_deep.md:56`) |

The four `priv_check` calls compare `ucred+0x58` against tags `0x4800000000000007`, `0x4800000000000022`/`0x480000000000002E`/`0x480000000000101F`, `0x4800000000000021`/`0x480000000000002D` (inferred from the OR gate structure). **None is 0x10003.**

**Alternative selector avoiding gate:** No bypass — all four checks must fail to be rejected. However, the OR-gate makes it easier: any one of ~6 auth-ID values suffices. There is no cmd-0 / arg-0 / self path that skips the gate entirely.

### Lua Call Shape

```lua
local sc648 = make_syscall(648)
local buf = memory.alloc(0x200)  -- 0x178 struct + padding

-- Fill the 0x178-byte user structure (field layout not fully recovered)
-- The scatter-gather path is reached through a specific display mode code
-- in the structure's command/type field
for i = 0, 0x174, 4 do memory.write_dword(buf + i, 0) end
sc648(uint64(buf))
```

### Observable Proving Success

- Zero-arg call: returns `-1` (`ATTACK_SURFACE.md:212`)
- V4: two concurrent threads entering `0x2020` claim same context slot → observable as crash on teardown
- V5: concurrent event handler iteration corrupts refcount → premature free → crash

### 14.10 Status

**UNTESTED beyond zero-arg.** Returns `-1` with null/zero argument; no probe with a valid 0x178-byte structure has been attempted (`ATTACK_SURFACE.md:212`). The gate status under the loader's auth-ID is unknown — the four priv_check predicates have not been mapped to specific tag values in the runtime. The scatter-gather and race vulnerabilities are **structurally present** in the 13.60 code and there is no evidence of 14.10 patching.

### Citations

- `results/kernel_handlers/analysis/sys_648_deep.md:3` (narg, handler size)
- `results/kernel_handlers/analysis/sys_648_deep.md:34-56` (four-layer gate)
- `results/kernel_handlers/analysis/sys_648_deep.md:148-160` (V2 — scatter-gather)
- `results/kernel_handlers/analysis/sys_648_deep.md:354-356` (V2 detail)
- `results/kernel_handlers/analysis/sys_648_deep.md:362-364` (V4 — race)
- `results/kernel_handlers/analysis/sys_648_deep.md:366-368` (V5 — refcount)
- `docs/ATTACK_SURFACE.md:212` (14.10 zero-arg result)

---

## Summary Table

| Rank | Syscall | Name | RVA | Class | Gate Bypassed? | 14.10 |
|---|---|---|---|---|---|---|
| **1** | 601 | `mdbg_service` | `0xca0630` | Unchecked length + caller value → kernel object | Yes (cmd 0x12: no cred check; self-bypass for second stage) | Case table **CLOSED** (1195a); second stage **unmeasured** |
| **2** | 622 | `ipmimgr_call` | `0x7dcd40` | Unchecked length (underflow) + caller pointer → global slot | Yes (292 commands: zero auth) | Error on slot-0; slots 1/5/6 **untested** |
| **3** | 669 | `_aio_submit_cmd` | `0x3b2060` | Caller value → kernel object via UAF race | Yes (no credential gate at all) | **WORKS** — create/submit/delete confirmed |
| **4** | 625 | `opmc_set_hw` | `0x603c90` | Caller value → indexed MSR (hardware register) | Yes (no credential test in root) | **Partially open** — narrow cmd window returns 0 |
| **5** | 648 | `app_state_change` | `0x9f81f0` | Unchecked size + race on caller-indexed slot | Unknown (OR-gate, 4 priv_checks) | **Untested** beyond zero-arg → -1 |
