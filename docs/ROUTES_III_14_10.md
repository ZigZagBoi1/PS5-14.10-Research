# ROUTES_III_14_10 — ten kernel-R/W candidates for FW 14.10, ranked

Status: static work only. No console was contacted, no probe was sent, no existing file was modified.
Image: `docs/dumps_13.60/kernel_text.bin`, base `0xffffffff8a9c0000`, length `0xE6E5C0`,
file offset == RVA. Every instruction quoted below was decoded **in this session** with capstone
5.0.7 (`Cs(CS_ARCH_X86, CS_MODE_64)`, 64 KB chunks) and is given with its RVA. Where a claim is
inherited from another document it says so. The 14.10 delta is never in this dump: any route that
depends on a 14.10 field still existing has to be settled by the probe, not by the bytes.

Runtime assumptions (given, not derived): userland exec through the Lua 5.1 loader on TCP 9026;
6-argument raw syscall primitive that does deliver r10; `thr_create(430)` with a controlled
ucontext; GPU/direct-memory mmap heap; sys 674 full VM map; sys 547/572/674 queries; no kernel
pointers; libkernel .text execute-only; eboot .text readable and free of `syscall`; 663 mode 0
count>1 = EINVAL; mtypeprotect and W^X dead.

---------------------------------------------------------------------------
## 0. Structural results of this session

Five facts were established or corrected while building this document. They are load-bearing for
the ranking, so they come before the routes.

**F1 — vm_object type 0xb (11) is the single key that 547, 654 and 673 all turn on.**
`0xaba5d4 cmp byte ptr [rax + 0x9d], 0xb` in 547's body (0xaba540), `0x9a96cf cmp byte ptr
[rsi + 0x9d], 0xb` in 654's body (0x9a9560), `0x9ab2d7 cmp byte ptr [rsi + 0x9d], 0xb` in 673's
body (0x9ab1f0). The first makes 547 return PTE-derived data, the other two let the blockpool
machinery touch pages. No document in either tree connects these three checks to each other: the
local 547 note treats 0x9d as "an object type test" and the blockpool notes never mention 547.

**F2 — the type-0xb object is constructed by blockpool code, and the constructor call site is
documented nowhere.**
`0x9a77c7 mov edi, 0xb`; `0x9a77cc sar rsi, 0xe` (page count); `0x9a77d0 call 0x8ae21ac0`;
`0x9a77d5 lock add dword ptr [rbx + 0x58], 1`. `0x8ae21ac0` is RVA `0x461ac0`, which allocates a
vm_object (`call 0x8adfb880`) and then calls the initialiser `0x461670`, which stores the type at
`0x461695 mov byte ptr [rdx + 0x9d], r15b` (r15b = edi, the constructor's first argument). The
initialiser then indexes a jump table on the type: `0x46169c cmp edi, 0xc ; ja reject`. So every
object class in this kernel is one constructor argument; of the 22 direct callers of `0x461ac0`,
only `0x9a77d0` passes `0xb` (the rest pass 0, 1, 4 or 9).

**F3 — blockpool_open (653) has no capability test, returns a handle, and links its object into a
global list.** Body 0x9a7d10: `0x9a7d37 test r15d, 0xffafffff` (flag mask), `0x9a7d5c mov edi,
0x410b0 / 0x9a7d6d call 0x8b5c8b50` (0x410b0-byte allocation), `0x9a7d66 mov r13d, [rax + 0x5d0]`
and `0x9a7d90 mov edi, [rax + 0x5c4]` (the blockpool class and the dmem container are copied in
from `struct proc`), `0x9a7e49 mov qword ptr [rip + 0x31fe038], r14` (global list head),
`0x9a7e55 lock add dword ptr [r14 + 0x58], 1` (refcount), `0x9a7e6c call 0x8b0ec7a0` (allocates
the returned number), `0x9a7ec9 mov edx, 0x11` + `0x9a7ed1 call 0x8b0ee000` (registers the object
with type 0x11), `0x9a7ef5 movsxd rax, [rbp - 0x3c]` + `0x9a7ef9 mov qword ptr [rbx + 0x408], rax`
(writes the handle into `td_retval[0]`). Upstream already knows 653 returns a descriptor — its heap
spray table lists `close(fd)` as the release method — but nobody mmap'd that descriptor.

**F4 — 654's three predicates are *negative* tests, so an ordinary game process passes them.**
`0x9a95aa call 0x8afc9560` → `0x9a95b6 je 0x9a95c1` continues when the predicate returns 0;
the same shape at `0x9a95d7 call 0x8afc95a0 / jne error` and `0x9a95e4 call 0x8afc92d0 / je
continue`. Those stubs are state tests, not the credential bit: `0x609560 test byte ptr [rdi +
0x6f], 0x40 ; 0x60956a test byte ptr [rdi + 0x82], 0x80`, `0x6095a0` the same pair with
`0x82,0x40`, and `0x6092d0` is an equality test on the tag at `[ctx + 0x58]` against
`0x4800000000001010`. Upstream's live result (654 returns -1 on a GPU mapping, 93a) is therefore
**not** a credential refusal; the wall must be the type-0xb check at 0x9a96cf or a later step.

**F5 — the capability context has no writer anywhere in 15.1 MB, now with call-kill.**
A nearest-writer dataflow over every store to `[reg+0x58]`/`[reg+0x60]` (1,812 sites) found one
candidate, `0x283633 mov dword ptr [rax + 0x58], 1`; the register is the return value of
`0x2835ee call 0x8b5429c0`, i.e. a call clobbers it before the store. With calls treated as
clobbers the count is **zero**. The earlier local claim ("zero within 0x140 bytes") was
window-limited; the answer survives the wider test. Everything behind `0x608f90` (bit 62 of
`[ctx+0x60]`) — 508 call sites, including 623, 636, 641, 642, 646, 618 and 604's second gate —
is closed by construction, not by measurement.

### What this document does not re-propose

379 `mtypeprotect` as a mutation (ROUTE_379_547), 547 as a PTE reader *without* a type-0xb
mapping (same), aio 661-670 (AIO_MODE0_GUARD, AIO_BATCH_14_10), umtx 454 and PI ops
(UMTX_454_EVIDENCE, upstream 941a), the capability bit (CAPABILITY_CONTEXT, F5 above),
621/622 device mux and 601 mdbg (DEVICE_MUX_622, SYS601_SECOND_STAGE), 674 as a leak
(VIRTUAL_QUERY_ALL_674), devfs ioctl (DEVFS_NAMESPACE), the copy-helper family and copy sites
(COPYOUT_CLASS_CLOSED, INTERPROC_COPYOUT_SOURCES, COPYIN_DEST_PROVENANCE), jitshm (upstream 251a:
533/534 return -1), evf_* (upstream ATTACK_SURFACE §413-455), MAP_FIXED-over-exec (upstream
951a/952a/953a), and the blockpool range/batch guards (HANDLER_CLAIM_CORRECTIONS §10.6).

---------------------------------------------------------------------------
## R1 — blockpool_open(653) → mmap the handle → a type-0xb vm_object → 547 returns PTE data
**EV: highest. Kill risk: medium (one bad mmap). First syscall: 653.**

### Mechanism
653 allocates a 0x410b0-byte blockpool object, registers it with type 0x11, links it into a global
list and returns a small handle in `td_retval[0]` (F3). The blockpool code contains the only
construction of a vm_object of class 0xb in the image (F2), and class 0xb is the object 547 will
report PTE data for and the object 654/673 will move pages in (F1). If the handle is a descriptor
that `mmap` accepts, then `mmap(0, len, prot, flags, fd = handle, 0)` runs the blockpool pager,
allocates the type-0xb object and installs it in our vm_map. From that moment 547 on the returned VA
takes the branch at `0xaba5dd`, calls `0x8b47a710` (`0xaba607`) and copies 0x18 bytes back that
contain a 4 KB-masked physical base and PTE flags. That is a physical-address read of our own page —
the first half of a physmap primitive; 654 then maps blockpool pages into the same object and 673
moves ranges inside it.

### Static evidence (verified here)
- 653 body `0x9a7d10`: `0x9a7d37 test r15d, 0xffafffff`; `0x9a7d5c mov edi, 0x410b0`;
  `0x9a7d66 mov r13d, dword ptr [rax + 0x5d0]`; `0x9a7d90 mov edi, dword ptr [rax + 0x5c4]`;
  `0x9a7e4d mov qword ptr [rip + 0x31fe038], r14`; `0x9a7e55 lock add dword ptr [r14 + 0x58], 1`;
  `0x9a7ec9 mov edx, 0x11`; `0x9a7ed1 call 0x8b0ee000`; `0x9a7ef5 movsxd rax, [rbp - 0x3c]`;
  `0x9a7ef9 mov qword ptr [rbx + 0x408], rax`; `0x9a7f00 xor eax, eax ; ret`.
- Type-0xb construction: `0x9a77c7 mov edi, 0xb`; `0x9a77cc sar rsi, 0xe`; `0x9a77d0 call
  0x8ae21ac0`; `0x9a77d5 lock add dword ptr [rbx + 0x58], 1`.
- Constructor `0x461ac0`: `0x461ace mov r12d, edi`; `0x461ae7 call 0x8adfb880`;
  `0x461afe call 0x8ae21670`; inside it `0x461695 mov byte ptr [rdx + 0x9d], r15b` and
  `0x46169c cmp edi, 0xc ; ja` (a jump table on the class).
- Consumer 547 `0xaba540`: `0xaba5d4 cmp byte ptr [rax + 0x9d], 0xb`;
  `0xaba5dd cmp byte ptr [r13 + 0xc81], 0`; `0xaba5e7 cmp dword ptr [r13 + 0x5d8], 0x6000000`;
  `0xaba607 call 0x8b47a710`; the 0x18-byte answer is assembled at `0xaba60c-0xaba62c`.
- Consumer 654 `0x9a9560`: `0x9a96cf cmp byte ptr [rsi + 0x9d], 0xb`;
  `0x9a96dc mov rdx, [rcx + 0x28] ; sub rdx, r14 ; cmp rdx, r12 ; jb`.
- Consumer 673 `0x9ab1f0`: `0x9ab2d7 cmp byte ptr [rsi + 0x9d], 0xb`;
  `0x9ab330 shr r12, 0x10`; `0x9ab337 shr r14, 0x10`; `0x9ab33b shr r15, 0x10`;
  `0x9ab348 call 0x8b36b370` (the page worker).

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x9a77c7" origin/master -- docs      -> empty
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x461ac0" origin/master -- docs      -> empty
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x9a7600" origin/master -- docs      -> empty
    Select-String C:\PS5contrib\docs\*.md -SimpleMatch "0x9a77c7"                      -> empty
The only upstream statement about the family is `docs/DEAD_ENDS.md:107` (657 "still writes after
close(h) but the write is worthless") and `docs/STRATEGY.md:199` ("blockpool no mapping"); both
tested *existing* GPU mappings, never an mmap of 653's handle. `0x5c4` (the dmem container field
653 copies into its object) is absent from both trees as well.

### First live probe (one connection, in this order)
1. `653(0, 0)` — flags 0, second word 0. Expect a non-zero handle. The loader maps a failing call
   to 0, so treat 0 as failure and read `get_error_string()` once.
2. `547(0x10000000, buf24)` on an existing anonymous page as a control: expect 0 with a zero
   physical half (the pre-type-0xb shape).
3. `477(0, 0x4000, 3 /*RW*/, 0x1002 /*ANON|PRIVATE*/, handle, 0)` — the blockpool descriptor as
   fd. Record rv; on failure retry flags `0x0002` (MAP_PRIVATE, no ANON) and prot `0x33`.
4. `547(returned_va, buf24)` and print all 0x18 bytes. If the physical half is non-zero you have
   passed `0xaba5d4` and every byte of the answer is new.
5. `654(returned_va, 0x4000, 0, 0, 0)` — expected 22 (EINVAL) at the type check *before* the
   mapping exists and non-22 after; this is the cheapest object-class oracle in the image.
6. `674` for the full map, to see the new region's protection word (the record at +0x18).

### Most likely failure
The descriptor 653 returns is a *named object* handle in the 16901-style handle space (like
evf/namedobj), not a file descriptor, and `mmap` rejects it with EBADF before any pager runs. The
cheapest discriminator is step 5: if 654 still answers 22 after a successful mmap, no type-0xb
object was created and the remaining place to look is the pager's `d_mmap` path. Second failure:
`proc+0x5d8 < 0x6000000` still blocks 547 at `0xaba5e7` even with the right object — one
`547(va,buf)` after a successful mmap, compared against the same call on a normal page, tells the
two apart with no risk.

---------------------------------------------------------------------------
## R2 — dmem_container(586) + mmap_dmem(628): choose the memory container, then map it
**EV: high if 586's write lands. Kill risk: low. First syscall: 586.**

### Mechanism
586 writes a caller-chosen 32-bit container index into `proc+0x5c4` after checking that the table
slot exists, and 628 maps a dmem range with the length/protection rules of the blockpool family.
653 copies `proc+0x5c4` into its object (F3), so the container index is a process-wide selector
for the direct-memory window. If 586's `priv_check(0x2ad)` passes for a game process, the pair is
"select any populated container, map it" — and a container that is populated by a system process
turns into a window over memory we do not own.

### Static evidence
- 586 body `0x3ce150`: `0x3ce166 mov eax, dword ptr [rax + 0x5c4]`; `0x3ce16c dec eax`;
  `0x3ce16e cmp eax, 3 ; setb cl` (the "already set" predicate returned in `td_retval[0]`);
  `0x3ce18a mov esi, 0x2ad ; 0x3ce18f call 0x8b49fa30` (privilege check);
  `0x3ce19d cmp r14d, 4 ; ja`; `0x3ce1a3 imul rcx, r14, 0x138`;
  `0x3ce1b1 cmp qword ptr [rcx + rdx + 0x38], 0` (slot-populated test);
  `0x3ce1bd mov dword ptr [rax + 0x5c4], r14d` (the write).
- 628 body `0xabd540`: `0xabd634 shl rax, 0x32 ; jne` (arg0 must be a clean low address);
  `0xabd642 test esi, 0x3fff ; setne` and `0xabd64b cmp rsi, 0x4000 ; setb` (length page-aligned,
  at least 0x4000); `0xabd6af test edi, 0x9fdf2f ; sete` (prot mask); `0xabd6ca test dil, 0x40`;
  `0xabd6e8 test edi, 0x200000`; the container path reads `proc+0x5c0`/`proc+0x5d0`.
- 559 body `0xabc510` (the sibling): `0xabc52d mov r14d, dword ptr [rax + 0x5c0]`;
  `0xabc551 mov esi, 0x2ad ; call 0x8b49fa30`; `0xabc570 mov dword ptr [rcx + 0x5c0], r14d`;
  `0xabc5b0 lea rcx, [rip + 0x2a798e9]` + `0xabc5b7 shl rax, 7 ; lea rax, [rax + r14*8]`
  (a 0x88-stride table) + `0xabc5bf cmp dword ptr [rcx + rax + 0x70], 0`.

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x5c4" origin/master -- docs   -> empty
    Select-String C:\PS5contrib\docs\*.md -SimpleMatch "0x5c4"                   -> empty
586 and 559 appear only as addresses in `TIER2_CLAIMS_AUDIT.md` (a claims list, not a body read).
`mmap_dmem` appears in ATTACK_SURFACE/DEAD_ENDS only as a name; the only live statement about
dmem is `/dev/dmem0` reads zeros (DEAD_ENDS), which is the device node, not syscall 628.

### First live probe
1. `586(0xFFFFFFFF)` — query form; expect `td_retval[0]` = 0 or 1 (the "container already set"
   predicate). If it returns 0x10 or EINVAL, the priv check refused and the route ends here for
   free.
2. `586(1)`, `586(2)`, `586(3)`, `586(4)` — one per connection; record rv and errno for each.
   A success at index k is the first write to `proc+0x5c4` this project has made.
3. `628(0, 0x4000, 3, 0, 0, 0)` before and after a successful 586; compare the returned VA and
   the 547 record for it (start/end/prot at +0x18).
4. If 628 returns a VA, `547(va, buf)` and hexdump 0x18 bytes, then `654(va, 0x4000, ...)` as the
   type-0xb oracle (R1 step 5).

### Most likely failure
`priv_check(0x2ad)` is a real PRIV_* test and a game process does not hold it; 586 then returns
EPERM for every index and nothing is written. That is a clean, cheap negative — and it makes the
`0x2ad` privilege number itself a target for a future grant hunt.

---------------------------------------------------------------------------
## R3 — set_vm_container(559): the second half of the same selector
**EV: medium-low, cheap. Kill risk: low. First syscall: 559.**

### Mechanism
559 is 586's sibling for `proc+0x5c0` (the container, not the dmem index). Its argument is
range-restricted to {0, 1, -1} by an unsigned trick, the same `priv_check(0x2ad)` gates it, and
the write is the same shape. Two containers exist, indexed by a 0x88-stride table; `-1` is a
query that returns 0. If container 1 is the "system" container, selecting it changes what every
subsequent direct-memory mmap resolves to.

### Static evidence
- 559 body `0xabc510`: `0xabc52d mov r14d, dword ptr [rax + 0x5c0]`;
  `0xabc539 lea edx, [r14 - 2] ; 0xabc53d cmp edx, -3 ; jb` (only 0/1/-1 survive);
  `0xabc551 mov esi, 0x2ad ; call 0x8b49fa30`; `0xabc570 mov dword ptr [rcx + 0x5c0], r14d`;
  `0xabc58b mov r14d, dword ptr [rsi]` (the argument); `0xabc5b0-0xabc5bf` the 0x88-stride
  table test; `0xabc5cf mov dword ptr [rax + 0x5c0], r14d` (the second write site).

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0xabc510" origin/master -- docs  -> only TIER2_CLAIMS_AUDIT
559 is listed by name in ATTACK_SURFACE/SYSENT_PRESENCE and never read as a body in either tree;
the `0x88` table and the `0x2ad` privilege are undocumented.

### First live probe
1. `559(0)` → expect 0 or EINVAL (index 0 may be "no container").
2. `559(1)` → the interesting one.
3. `559(0xFFFFFFFF)` → query; expect 0.
4. After a success, `628(0, 0x4000, 3, 0, 0, 0)` then `547` on the result.

### Most likely failure
Same `priv_check(0x2ad)` as R2; and even if it passes, only two containers exist and neither is
likely to be populated for a game.

---------------------------------------------------------------------------
## R4 — thr_get_ucontext(634) across threads, with the td+0x4e8 frame selector
**EV: medium (a kernel-saved context, not a stack leak). Kill risk: low on self. First syscall: 430 then 634.**

### Mechanism
634 looks a thread up by (tid, pid), takes its lock, requires the target to be in state 2..4, and
copies 0x4c0 bytes out of a frame that a filler builds from `[td+0x460]` or `[td+0x4e8]` according
to a selector argument. The local CR-I route only asked whether the second frame object is
reachable; the new part here is that the lookup key is the *pair* (tid, pid) with pid taken from
our own proc, so a sibling thread we created with 430 is addressable, and that the copy is a fixed
0x4c0 with no user pointer in it at all. If the second selector value exists on 14.10, the copy
returns the kernel-side saved context of a thread, which is the object a stack pivot would need.

### Static evidence
- 634 body `0x439150`: `0x43917d mov edi, dword ptr [rsi]` (tid); `0x43917f mov esi, dword ptr
  [rax + 0xbc]` (pid); `0x439185 call 0x8b552420` (lookup); `0x4391c2 test byte ptr [r12 + 0x529], 1`
  (the debug bit on *our* thread); `0x4391cd test byte ptr [r14 + 0xe8], 0x20`;
  `0x4391e5 mov eax, dword ptr [r14 + 0x400] ; lea ecx, [rax - 2] ; cmp ecx, 3 ; jae` (state gate);
  `0x4391f4-0x439218` lock/unlock of `[thr+0x18]` and `[thr_proc+0x148]`.
- The sibling 632 body `0x438e30` is the same shape with no copyout (CR-II R6).

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x439150" origin/master -- docs  -> only ps5_13.60_sysent.json
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x438e30" origin/master -- docs  -> only ps5_13.60_sysent.json
Upstream has no body read of 634/632 at all (the address appears only in the sysent JSON). Locally
it is CR-I Route 2 and CR-II R6 — proposed, never run; `docs/COPYOUT_PARTIAL_STACK_AUDIT.md`
closes the *stack* reading, not the frame-object one.

### First live probe
1. `430(ucontext)` to start a child that spins on one instruction (the verified 156c/156d context,
   CS 0x43, SS 0x3b, gates +0x108=0x480, +0x0d0<=7, +0x110=0x10000).
2. `634(child_tid, out, 0)` with a 0x4c0 buffer poisoned with 0xAB; hexdump and scan for
   `0xffff8`/`0xffffffff8` qwords.
3. Repeat with the selector word set to 1 and 2 (the `cmp ecx, 3` at 0x4391ef bounds it).
4. `632(child_tid)` then `634` again to see whether suspension changes the copied state.

### Most likely failure
The debug bit at `td+0x529` is clear for a game thread (it is the same bit 601's attach sets), so
634 returns before the copy. The 0x4c0 copy is also the *user* trapframe, whose contents are ours.

---------------------------------------------------------------------------
## R5 — debug_init(560): a one-shot, unprivileged dword into a kernel global
**EV: medium if the global is a gate; zero effort to kill. Kill risk: low. First syscall: 560.**

### Mechanism
560 is four instructions of work: take `uap[0]`, read a global; if the global is zero, store the
argument into it and return 0; if it is non-zero, return `(global != arg) << 4`. No privilege
check, no lock, no bound. That is a write-once, caller-chosen 32-bit value at a fixed kernel
address, and the return value is a two-state oracle on whether someone wrote it first. Every
"debug enabled" flag in this kernel is a candidate reader; if this global is one, a single
unprivileged call flips a subsystem for the life of the process.

### Static evidence
- 560 body `0x4f5e60`: `0x4f5e64 mov ecx, dword ptr [rsi]`; `0x4f5e66 mov edx, dword ptr
  [rip + 0x304dbf0]`; `0x4f5e6e je -> store path`; `0x4f5e72 cmp edx, ecx ; setne al ; shl eax, 4`;
  `0x4f5e7c mov dword ptr [rip + 0x304dbda], ecx` (the store); `0x4f5e82 xor eax, eax ; ret`.
  The two displacements differ by 0x16, i.e. they are two adjacent globals, not the same one.

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x4f5e60" origin/master -- docs  -> only KERNEL_DUMP_ANALYSIS (offset table)
    Select-String C:\PS5contrib\docs\*.md -SimpleMatch "0x4f5e60"                  -> only KERNEL_DUMP_ANALYSIS
No document in either tree describes 560 as a write; it is a row in a syscall table.

### First live probe
1. `560(0x41)` on a fresh connection → expect 0 (first writer) on a process that has not called it.
2. `560(0x41)` again → expect 0 (same value).
3. `560(0x42)` → expect 0x10, which proves the value stuck and the oracle works.
4. Re-run the standard battery (601 type sweep, 634 self, 654 type oracle) before and after the
   write and diff; the interesting outcome would be any handler that changes state.

### Most likely failure
The global is a boot-time diagnostic level that nothing in a game process reads; the call is then
inert but its oracle (0 vs 0x10) still tells us whether the loader process already initialised it.

---------------------------------------------------------------------------
## R6 — dynlib_get_info2(660) / get_list2(659): the 0x160 record and its sentinel
**EV: medium-low (leak, not R/W). Kill risk: very low. First syscall: 660.**

### Mechanism
660 and 659 require the first qword of the user buffer to be 0x160, copy it in, allocate a
0x160-byte kernel buffer, fill it through the dynlib record filler, copy all 0x160 bytes back and
free. The sentinel is consumed by the output, so the caller must re-arm it each call; the buffer is
filled by a function whose write coverage is unknown, so any unwritten tail is kernel heap residue.
The 0x160 buffer is allocated with flags 0xa and is not obviously zeroed. A single 0x160 dump with
a real module id is the whole experiment.

### Static evidence
- 660 body `0x34bc60`: gate `0x34bc84 mov r14, [rax + 0x3e8]` / `0x34bc98 cmp qword ptr
  [rax + 0x148], 0`; `0x34bcd0 call 0x8ac19280` (copyin 8); `0x34bce0 cmp qword ptr [rbp - 0x38], 0x160`;
  `0x34bcf9 call 0x8b4eac60` (malloc 0x160); `0x34bd0c call 0x8ad0b950` (filler, edx=0);
  `0x34bd72 mov qword ptr [r15], rax` (re-writes the sentinel); `0x34bd8e call 0x8ac191d0`
  (copyout 0x160); `0x34bda2 call 0x8b4e4250` (free).
- 659 body `0x34b790` tail-jumps to `0x8ad0b540` with (lib, uap[0], uap[1], uap[2]) and edx=1 —
  a different filler, same 0x160 contract.

### Why not closed
Upstream `OFFLINE_HANDLER_DECODE_2026-10-23.md` says 660 is "NO gate" and "untested real-args",
and lists "dump all 0x160 bytes, sentinel-scanned for kernel pointers" as an open next step; its
own table says 659 "works" and 660 is untested. Locally `DYNLIB_608_649_14_10.md` covers 608/649,
not 659/660, and probe 339a (the only 637/598/659 run) died at 637 before its 659 section.

### First live probe
1. `593(module_handle, info)` to learn a valid module id (the loader already has one).
2. `660(id, buf)` with `buf[0..8) = 0x160` and the rest 0xA5; hexdump all 0x160 bytes.
3. Scan for `0xffff8`/`0xffffffff8` qwords; diff against 593's 0x160-byte record field for field.
4. Repeat with `659(id, buf, 0)`.
5. Call twice in a row without re-arming the sentinel: the second call must return 22, which
   proves the aliasing; then re-arm and call again to prove the state machine.

### Most likely failure
The filler zeroes or fully writes its 0x160 bytes (593's record was verified userland-only), so the
dump is a clean record and this degrades to "nothing new".

---------------------------------------------------------------------------
## R7 — dynlib_get_info_for_libdbg(656): the debug-unit predicate as a one-call oracle
**EV: medium as an oracle (unlocks 672 and re-opens 601 stage two). Kill risk: low. First syscall: 656.**

### Mechanism
656 is the libdbg twin of 593 with the same 0x160 record contract, but its gate is the pair
`0xacce10() != 0 || 0xacce50() != 0` — the "debug unit present" predicates, not the credential
bit and not the dynlib context. A single call therefore answers "is the debug unit visible to this
process", which is the precondition for 672 (dynlib_get_list_for_libdbg, which returns -1 today)
and one of the preconditions the 601 second stage wants.

### Static evidence
- 656 thunk `0x2655a0` -> body `0x34c350`; verified instructions: `0x34c382 call 0x8b48ce10`
  (RVA 0xacce10), `0x34c387 test eax, eax ; jne 0x34c398` (A != 0 continues), `0x34c38b call
  0x8b48ce50` (RVA 0xacce50), `0x34c390 test eax, eax ; je 0x34c5be` (B == 0 is the failure exit).
  That is exactly A || B, and both predicates take no argument: the answer is a property of the
  process, not of the call.

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0xacce10" origin/master -- docs   -> empty
    Select-String C:\PS5contrib\docs\*.md -SimpleMatch "0xacce10"                  -> empty
The predicates are unnamed in both trees. Upstream's `OFFLINE_HANDLER_DECODE` lists "656 — single
call determines whether the debug-unit predicates pass on this console" as an open item (planned,
not run).

### First live probe
1. `656(id, buf)` with `buf[0]=0x160` and id from 593.
2. If 0: dump 0x160 and compare to 593's record (the libdbg variant may carry fields 593 omits).
3. If -1: `672(buf)` in the same connection must also be -1; that cross-check confirms the
   predicate is the discriminator rather than the record size.

### Most likely failure
The debug-unit predicates are false in a retail game process; 656 and 672 both return -1 and the
result is a clean negative that also explains 672's -1 (which no document currently does).

---------------------------------------------------------------------------
## R8 — virtual_query(572): the deep branch under proc+0xc81
**EV: low-medium (VM metadata, possibly physical). Kill risk: low. First syscall: 572.**

### Mechanism
572 masks its flag word differently depending on the process policy byte `proc+0xc81`: with
c81 == 0 only bit 0 survives, with c81 != 0 the mask is `0xfffcfffe` (bits 0, 1 and 16). It then
bounds the VA against `vmspace+0x28`, takes the map lock and calls the lookup. The interesting
part is that the two legal flag sets select different downstream code, and the earlier live sweeps
that returned "0 with an empty buffer" passed the output buffer as the first argument (the
(outbuf, cmd, size) layout), so they never presented a VA to this handler at all.

### Static evidence
- 572 body `0xabac50`: `0xabac79 movzx edx, byte ptr [rax + 0xc81]`;
  `0xabac86 test dl, dl ; je 0xabaca4`; `0xabac96 test ecx, 0xfffcfffe ; jne` (strict mask);
  `0xabaca4 and ecx, 1` (loose mask); `0xabacc0 and r12, 0xffffffffffffc000`;
  `0xabacc7 cmp r12, qword ptr [r14 + 0x28] ; ja`; `0xabacd8 mov edi, 4 ; call 0x8b4ebb00`
  (the lock-order probe).

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0xabac50" origin/master -- docs  -> CROSS_FIRMWARE_PATTERN_RESEARCH only
The only upstream hit is a cross-firmware pattern note; the local `CREATIVE_ROUTES_II` R3 proposed
572 with the wrong flag emphasis and the local dead-end list records "returns 0 but empty buffers"
for layouts that predate the mask analysis.

### First live probe
1. `572(va_owned, 0, out, 0)` as the baseline; record rv and the first 0x40 bytes.
2. `572(va_owned, 1, out, 0)` and `572(va_owned, 2, out, 0)` — the two legal loose values.
3. `572(va_owned, 0x10000, out, 0)` and `0x10002` which only pass under the strict mask.
4. `572(0x7ffffffff000, 0, out, 0)` (bound reject) and `572(0, 0, out, 0)` as controls.
5. If any call writes anything but zeros, sweep 0x40 VAs across one mapping to see the field
   pattern before touching a kernel address.

### Most likely failure
The handler's output is protection metadata identical to 547's cheap branch; the physical half is
only filled on the type-0xb path (F1), which R1 must supply first.

---------------------------------------------------------------------------
## R9 — dl_get_metadata(604): a 5-argument getter behind a tag equality
**EV: low (tag-gated), but it is a cheap identity oracle. Kill risk: low. First syscall: 604.**

### Mechanism
604 takes five arguments, requires the process tag at `[ctx+0x58]` to be exactly
`0x4800000000000007`, computes a value with `0x8ac2d0a8`, looks a process up by id and copies
metadata out. The tag test is the important part: it is an oracle for *which process kind we are*,
the same question 597 answered from the other side (its grant had no readers). If our tag happens
to be 07, the entire dl_get_metadata path is open with no further gate.

### Static evidence
- 604 body `0x4f7370`: `0x4f739d mov r12d, dword ptr [rsi]`; `0x4f73a0 mov r13, [rsi + 8]`;
  `0x4f73a4 mov r15, [rsi + 0x10]`; `0x4f73a8 mov r14d, [rsi + 0x18]`;
  `0x4f73b0 call 0x8ac2d0a8`; `0x4f73c0 call 0x8afc9040` then `jne error`;
  `0x4f73d0 call 0x8afc9110` then `je 0x8aeb752c`; `0x4f73e7 call 0x8aeb6700` (pfind-style).
- The predicates resolve to `0x609040` (`cmp qword ptr [rdi + 0x58], 0x4800000000000006`) and
  `0x609110` (`cmp qword ptr [rdi + 0x58], 0x4800000000000007`), both decoded here.

### Why not closed
    git -C C:\tmp\wt-run grep -n --fixed-strings "0x4f7370" origin/master -- docs  -> empty
    Select-String C:\PS5contrib\docs\*.md -SimpleMatch "0x4f7370"                 -> empty
No document in either tree reads 604's body; it exists only as a name in ATTACK_SURFACE.

### First live probe
1. `604(0, 0, 0, 0, 0)` → expect 22 or -1; record errno.
2. If the tag test is the failing gate the answer is 22 for every shape, which is itself the
   measurement: our tag is not 07.
3. If anything else, pass a valid pid in arg0 and a 0x100 buffer in arg1 and hexdump.

### Most likely failure
Our process tag is the game tag (likely `0x4800000000001010` per the 654 predicate at 0x6092d0),
not 07; 604 returns EINVAL before any work.

---------------------------------------------------------------------------
## R10 — set_phys_fmem_limit(637): a pinned qword write one bad branch away
**EV: low and dangerous; last. Kill risk: HIGH (wedges the loader). First syscall: 637.**

### Mechanism
637 writes a caller-chosen qword into the current process's child object at +0x280 with no
capability check on the self path, but the same function calls `0x8aefaa10(p)` under the process
lock unless `proc flags & 0x10000000` is set, and that call wedges the console (measured
repeatedly). The route is therefore not "call 637 harder" but "find the state that skips the call",
and there is exactly one such state bit, named in the decompile the local doc quotes. Any syscall
that sets `proc+0xb0` bit 28 converts a wedging console-killer into a pinned qword write.

### Static evidence
- Thunk `0x265f08` -> body `0x8b47d930` (RVA 0xabd930), verified here: `0xabd93e cmp qword ptr
  [rsi + 8], 0x11`; `0xabd943 mov r14d, 0x16`; `0xabd949 jl 0x8b47da80` (the value < 17 EINVAL
  guard that the live map reproduced); `0xabd94f mov eax, dword ptr [rsi]` (pid); `0xabd965 cmp
  eax, dword ptr [rcx + 0xbc]` (self check); `0xabd984 lea rdi, [rbx + 0x148]` (the process lock
  whose held state is the wedge).
- Local decompile of the same body (`PROC_LOCK_WEDGE_637_14_10.md`): `if ((flags & 0x2200) ||
  U32(p,0xb8) != 1) return 3; ++U32(p,0x358); if (!(flags & 0x10000000)) sub_ffffffff8aefaa10(p);`
  then `U64(child, 0x280) = value`.

### Why not closed
    git -C C:\tmp\wt-run grep -n -i "0x10000000" origin/master -- docs/OBJECT_FAMILIES_14_10.md -> mentions 637, not the flag
Upstream lists 637 as "measured, wedges"; no document looks for the flag that skips
`0x8aefaa10`. Locally the wedge is documented and the write is explicitly called "untested".

### First live probe
Do not run this until a session can be lost. One call, in a sacrificial `thr_create` child:
1. `637(0, 0x40000000)` (a value above the wedge window) — must return 0 and prove the child path.
2. In a *separate* connection, `637(0, 17)` — the known wedge; expected to hang. Only run this if
   the operator accepts a relaunch.
3. Any future attempt must first find and set `proc+0xb0` bit 28, which no current syscall is known
   to do.

### Most likely failure
The wedge. This is the only route in the document that has already cost sessions.

---------------------------------------------------------------------------
## 11. The first three instructions and the first syscall, per route

| # | first syscall | instruction 1 | instruction 2 | instruction 3 |
|---|---|---|---|---|
| R1 | 653(0,0) | 0x9a7d37 test r15d,0xffafffff | 0x9a7d5c mov edi,0x410b0 | 0x9a7e55 lock add [r14+0x58],1 |
| R2 | 586(0xFFFFFFFF) | 0x3ce166 mov eax,[proc+0x5c4] | 0x3ce18f call 0x8b49fa30 | 0x3ce1bd mov [proc+0x5c4],r14d |
| R3 | 559(1) | 0xabc52d mov r14d,[proc+0x5c0] | 0xabc53d cmp edx,-3 | 0xabc570 mov [proc+0x5c0],r14d |
| R4 | 430(ucontext) then 634 | 0x43917d mov edi,[uap] | 0x439185 call 0x8b552420 | 0x4391c2 test byte [td+0x529],1 |
| R5 | 560(0x41) | 0x4f5e64 mov ecx,[uap] | 0x4f5e66 mov edx,[global] | 0x4f5e7c mov [global],ecx |
| R6 | 660(id,buf) | 0x34bcd0 call 0x8ac19280 | 0x34bce0 cmp qword [rbp-0x38],0x160 | 0x34bd8e call 0x8ac191d0 |
| R7 | 656(id,buf) | 0x34c382 call 0x8b48ce10 | 0x34c38b call 0x8b48ce50 | 0x34c390 test eax,eax ; je |
| R8 | 572(va,0,out,0) | 0xabac79 movzx edx,[proc+0xc81] | 0xabac96 test ecx,0xfffcfffe | 0xabacc7 cmp r12,[vmspace+0x28] |
| R9 | 604(0,0,0,0,0) | 0x4f739d mov r12d,[uap] | 0x4f73c0 call 0x8afc9040 | 0x4f73d0 call 0x8afc9110 |
| R10 | 637(0,0x40000000) | 0xabd93e cmp qword [rsi+8],0x11 | 0xabd949 jl (EINVAL) | 0xabd984 lea rdi,[rbx+0x148] |

## 12. Dependency graph and probe order

R1 is the only route whose success changes the value of another route (it supplies the type-0xb
object that R8 and 547 need). Run R1 first, then R2/R3 (cheap, independent), then R5 (cheap,
independent), then R4/R6/R7 (cheap reads), and leave R9/R10 last. R10 is the only one that can
cost the session.

Every probe above is one syscall per connection where the argument shape is new, per the
one-syscall-per-number rule this corpus already uses, and every buffer is written by the main
thread (SACRIFICIAL_THREAD_14_10).

## 13. Method notes

- capstone was run with `detail=False` and textual operand parsing; `detail=True` over a whole
  64 KB chunk is fine but unnecessary for this work, and over the image it is fatal.
- Two decode traps that produced false starts in this session and are worth recording: a linear
  decode that begins mid-instruction prints a plausible `add byte ptr [rax], al` prologue (0x542f80
  was that trap), and `mov eax, dword ptr [0x5c4]` in the 586 tail is a real absolute-form
  instruction in dead code, not a rip-relative load.
- The "nearest writer" dataflow in F5 must treat every `call` as clobbering rax/rcx/rdx/rsi/rdi/r8-r11,
  otherwise it produces the same false positive (0x283633) it produced here on the first pass.
