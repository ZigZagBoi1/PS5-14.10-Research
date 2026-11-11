# KERNEL LIFETIME CENSUS - 13.60 kernel text, for PS5 14.10

Written 2026-11-05. Static only: no probe was run, nothing under probes/ or results/ was touched.

Image: `docs/dumps_13.60/kernel_text.bin`, base VA `0xffffffff8a9c0000`, file offset == RVA,
length `0xE6E5C0`. Sysent: `docs/dumps_13.60/sysent_index.json` (679 entries, `sysent_rva` 0xE6E5C0).
Scripts: `C:\PS5contrib\.local\life_census\` (inventory in section 8).

This is a new axis. Previous audits covered copy semantics (copyin/copyout provenance and lengths)
and indexed loads/stores. This one asks a different question of every syscall body: is an object
freed while something still points at it, freed twice, or used after a free.

---

## 1. Verdict

**One survivor, and it is the known one.** Over all 301 distinct syscall bodies in the 13.60 text,
the census produces exactly one lifetime defect of the three requested shapes: the syscall 663
(`aio_multi_wait`) waiter-node array escape at body `0x3b01f0` / shared implementation `0x3b0210`,
freed at `0x3b0f9e` while earlier requests still hold `request->waiters == node[0]`. That is the
Bagagwa/Relapse shape, it is present in this image, and on 14.10 it is closed for the measured
value `mode == 0` at `count > 1` (see `docs/AIO_MODE_GUARD_GAP_14_10.md`). Modes 3 and above were
never measured on 14.10 and reach the same instructions in 13.60.

**No new survivor.** Zero double-free rows and zero use-after-free events survive validation across
the corpus. The escape arm found five candidate units and four of them died on path disjointness,
self-reference, or an explicit link-clear; each dismissal is recorded with the instruction that
kills it in section 4.

**Coverage is real, not nominal.** 46 of 301 bodies allocate and 35 free. The model saw 66,211
allocation events and 44,464 free events. 55,172 memory operands were classified during the run,
4,850 of them with an allocation as the base register, and none of those 4,850 touched a freed
allocation. The detector is therefore exercised on real allocation pointers, not reporting zero
because it never looked.

**The 13.60 image cannot answer 661, 665 and 668 at all.** In this capture those three sysent slots
resolve to a 5-instruction stub that tail-jumps to the shared nosys target `0x5620e0`. They have no
body here to census. Their 14.10 lethality on zeroed arguments is consistent with either a real
handler that faults or with the nosys path, and this image cannot distinguish those.

---

## 2. Survivors, ranked

| # | syscall | body (stub / impl) | shape | link RVAs | free RVA | steering argument | live on 14.10 |
|---|---|---|---|---|---|---|---|
| 1 | 663 `aio_multi_wait` | `0x3b01f0` / `0x3b0210` | ESCAPE (Bagagwa/Relapse) | `0x3b0969`, `0x3b096d` | `0x3b0f9e` | arg3 `mode` = 0 (or >= 3) with arg1 `count` >= 2 | handler works; mode 0 at count > 1 now returns EINVAL; modes >= 3 unmeasured |

Nothing else ranks. Ranks 2..n are empty by measurement, not by assumption.

### 2.1 Survivor 1: syscall 663, shared waiter node linked to every request, array freed

Argument unpacker (`0x3b01f0`) marshals uap[0] ids, uap[8] count, uap[0x10] status out,
uap[0x18] mode and uap[0x20] timeout pointer, then tail-jumps to `0x3b0210`. On 13.60 the two
bounds are: count in [1, 0x80], and mode < 3.

    003b0384  488b4b70                 mov rcx, qword ptr [rbx + 0x70]      ; count
    003b0388  8d817fffffff             lea eax, [rcx - 0x81]
    003b038e  3d7fffffff               cmp eax, 0xffffff7f
    003b0393  7723                     ja 0xffffffff8ad703b8                 ; count in [1,0x80] ok
    003b0395  488d3d6cbbf600           lea rdi, [rip + 0xf6bb6c]             ; else EINVAL
    003b03a3  41be16000000             mov r14d, 0x16
    003b03b8  4183fd03                 cmp r13d, 3                           ; mode
    003b03bc  7350                     jae 0xffffffff8ad7040e                ; mode >= 3 rejected

Two allocations, both sized by count. The status array is `count*0x18` at `0x3b0540`; the waiter
node array is `count*0x38` at `0x3b0586`, and its base is pinned in the frame:

    003b0576  496bfe38                 imul rdi, r14, 0x38
    003b057a  488d35cf547001           lea rsi, [rip + 0x17054cf]
    003b0581  ba02010000               mov edx, 0x102                        ; M_WAITOK|M_ZERO
    003b0586  e8c5858500               call 0xffffffff8b5c8b50               ; malloc
    003b058b  4989c6                   mov r14, rax

The single-request path (count < 2, or mode 1 / mode 2) links one node per request and is
self-consistent:

    003b08b1  488b4150                 mov rax, qword ptr [rcx + 0x50]       ; request->waiters
    003b08bc  49894630                 mov qword ptr [r14 + 0x30], rax       ; node->next = old head
    003b08c0  4c897150                 mov qword ptr [rcx + 0x50], r14       ; request->waiters = node
    003b08c4  49894e18                 mov qword ptr [r14 + 0x18], rcx       ; node->owner = request

Mode 0 and every mode >= 3 take a different branch (`0x3b0844 jne 0x3b08e5`) and the loop reloads
`rcx = [rbx+0x40]` on every iteration, so it relinks **node[0]** to each request in turn:

    003b08e5  488b4358                 mov rax, qword ptr [rbx + 0x58]
    003b08f0  488b4028                 mov rax, qword ptr [rax + 0x28]
    003b08f4  488b04d0                 mov rax, qword ptr [rax + rdx*8]      ; request for index i
    003b08f8  4c8b6820                 mov r13, qword ptr [rax + 0x20]       ; request inner object
    003b0924  488b4b40                 mov rcx, qword ptr [rbx + 0x40]       ; node[0] EVERY iteration
    003b093a  488901                   mov qword ptr [rcx], rax              ; node->lock = &frame[0x104]
    003b0944  48894110                 mov qword ptr [rcx + 0x10], rax       ; node->chan = &frame[0xe0]
    003b0965  48894130                 mov qword ptr [rcx + 0x30], rax       ; node->next = old head
    003b0969  49894d50                 mov qword ptr [r13 + 0x50], rcx       ; request->waiters = node[0]
    003b096d  4c896918                 mov qword ptr [rcx + 0x18], r13       ; node->owner = LAST request

Cleanup unlinks the node only from the request named by `node[i].owner`, which after the loop is
the last request:

    003b0e2d  498b4d18                 mov rcx, qword ptr [r13 + 0x18]      ; node[i].owner
    003b0e31  488b4150                 mov rax, qword ptr [rcx + 0x50]      ; that request's list
    003b0e35  4c39e8                   cmp rax, r13
    003b0e38  7437                     je 0xffffffff8ad70e71                ; remove head
    003b0e40  4889c1                   mov rcx, rax
    003b0e43  488b4030                 mov rax, qword ptr [rax + 0x30]
    003b0e47  4c39e8                   cmp rax, r13
    003b0e4a  75f4                     jne 0xffffffff8ad70e40
    003b0e79  49c7451800000000         mov qword ptr [r13 + 0x18], 0        ; clear owner only

and then the array is freed with the other requests still pointing into it:

    003b0f82  488b7b68                 mov rdi, qword ptr [rbx + 0x68]
    003b0f8e  e8fd2bcfff               call 0xffffffff8aa63b90               ; side-object release
    003b0f93  488b7b40                 mov rdi, qword ptr [rbx + 0x40]       ; node array base
    003b0f97  488d35b24a7001           lea rsi, [rip + 0x1704ab2]
    003b0f9e  e84d7e8500               call 0xffffffff8b5c8df0               ; free(node array)

**Why this counts as dominance and not as a coincidence.** The free at `0x3b0f93` sits on the single
exit corridor of the body: mode 0, count >= 2, request loop, cleanup, free. The link stores at
`0x3b0924`-`0x3b096d` execute unconditionally on every iteration of that same loop. The only unlink
(`0x3b0e2d`-`0x3b0e79`) walks the list of `node[i].owner`, and `owner` was overwritten on every
iteration, so requests 0..i-1 keep `request->waiters == node[0]` when the array is freed. No
instruction between the link loop and the free clears those earlier links.

**What the path explorer could and could not show.** The escape arm records 21 stores of the
node-array pointer into foreign request slots for this unit, and the known-bug unit reproduces as a
census hit, which is the calibration. The path explorer alone never produced a single tagged state
that both linked and freed: the request chain introduces a fresh unknown-token id per iteration, so
per-RVA state growth hits `state_cap` after a handful of iterations (15,052 path ends: 62 returned,
12,144 state-capped, 2,846 revisit-capped). The claim therefore rests on the straight-line block
reading above, not on an exhibited path. That is stated here rather than hidden: the census is a
static argument, and its value is that the same static argument, applied to 300 other bodies,
produces nothing.

### 2.2 14.10 status and what would confirm it

Measured on 14.10 (probes 1219a/1221a, recorded in `docs/AIO_MODE_GUARD_GAP_14_10.md`): mode 0 with
count 2 or 3 returns -1 EINVAL before the id list is copied; modes 1 and 2 work at count 2. The
guard is a value test on `mode == 0`, and 14.10 never measured modes 3 and above, which in 13.60
share the exact instructions of mode 0.

To confirm or kill the survivor on 14.10, one non-blocking call decides it, because an id of 0 is
skipped with status `0x80020003` and the call returns without sleeping:

    663(ids = {0,0}, count = 2, out = buffer, mode = M, timeout = NULL)   for M in 3..8, 0x10, 0x40, 0xFF

-1 EINVAL for every M means the guard tests the path and the class is closed on 14.10.
0 with two `0x80020003` status words means the guard tests only the value 0, and the shared-node
link of section 2.1 is reachable through mode 3 on 14.10 with the same consequences: two requests
whose `waiters` lists still name a freed node whose lock and channel words are a departed thread's
stack addresses (`&frame[0x104]`, `&frame[0xe0]`).

---

## 3. Method

Every choice below is here because the alternative produced a wrong row at some point in this
project. Nothing is a fixed-window scan.

### 3.1 Resolution: sysent to body

All 679 entries carry `sy_call_off`; each is an `e9 rel32` thunk in the `0x265xxx` slot table.
Following one rel32 yields 301 distinct bodies. `0x5620e0` is the shared nosys target (368 entries)
and is excluded; `0x8fc810` is shared by 10 entries and `0x8fc820` by 3.

Capstone returns `rel32` as a signed 64-bit immediate. Every branch target is masked to 64 bits
before the base-range test, otherwise targets become negative and silently resolve to None. That
bug cost one full day in this project; it is fixed in `lc_common.py` (`imm_branch_target`).

### 3.2 Unit = stub plus tail-jump closure, and extents by recursive descent

A body's own extent ends at its first unconditional tail jump, but the work usually continues in a
shared implementation. The analysis unit is therefore the `sy_call` target plus its tail-jump
closure to depth 5: 663's unit is `0x3b01f0` and contains `0x3b0210`; 669's is `0x3b2060` and
contains `0x3b2080`; 662's is `0x3af900` and contains `0x3af920`.

Extent is recursive descent from the unit start: stop at `ret`/`retf`/`iret`/`ud2`/`hlt`/`int3`/
`sysret`, do not cross a different known function start, and let a tail jump leave the function.
The start set has 893 entries (301 bodies plus every call target plus every tail target), which is
what keeps adjacent-function extents from creating phantom rows.

Resulting extents are sane: 663 = 811 instructions ending at `ud2` `0x3b0fad`; 662 = 533 ending at
`ud2` `0x3b01e6`; 669 = 503; 664 = 396; 666 = 588; 667 = 289; 670 = 263. No extent is a fixed
`0x400` or `0x1000` window.

### 3.3 ABI

At handler entry `rdi` = `struct thread *td`, `rsi` = `struct syscall_args *uap`; `uap+0` is arg0,
`+8` arg1, `+0x10` arg2, `+0x18` arg3, `+0x20` arg4. `rdi` is never tainted: the thread pointer is
a kernel object, not an attacker-controlled value, and tainting it turns every `[td+...]` access
into noise. Tail-jumped implementations receive the same `rdi` (the stubs only rewrite `rsi`/`rdx`/
`rcx`/`r8`/`r9`), so the model holds for the shared implementations too.

### 3.4 Allocation and free helpers

Helpers were clustered by observation, not assumed:

All addresses in this document are RVAs (file offsets from the image base `0xffffffff8a9c0000`).
Capstone prints branch targets as VAs, so a quoted `call 0xffffffff8b5c8b50` is RVA `0xC08B50` and a
quoted `call 0xffffffff8ac25760` is RVA `0x265760`. Everything outside the operand text of a quote
is an RVA.

| helper | signature | evidence |
|---|---|---|
| `0xC08B50` | `malloc(size=rdi, type=rsi, flags=edx)` | 58 call sites in 42 bodies; returns rax |
| `0xC08DF0` | `free(ptr=rdi)` | 102 call sites in 54 bodies |
| `0x794EE0` | malloc wrapper | `mov edx,esi; lea rsi,type; jmp 0xC08B50` |
| `0xb2ac60` | `kalloc(size=rdi, type=esi)` | calls `0xC08B50` with flags `0x8002`; sys 593 returns a `0x160` buffer |
| `0x259280` | `copyin(udst=rdi, ksrc=rsi, len=rdx)` | entry RVA documented in `docs/COPYIN_DEST_PROVENANCE_14_10.md` |
| `0x2591d0` | `copyout(k=rdi, u=rsi, len=rdx)` | as above |
| `0x258ff0` | `bzero(dst=rdi, len=rsi)` | call sites immediately after fresh allocations |

The two AIO helpers named in the brief (`0x8b5c8b50` and `0x8b5c8df0` as VAs) are the same malloc
and free: `0xC08B50` is `malloc`, `0xC08DF0` is `free`. That is why the node array of 663 is `count*0x38` and the `aio` node array
in 669 and 664 is `count*0x18`: both are `malloc` at the same helper with different multipliers.

### 3.5 Three arms on one path explorer

`lc_taint.py` models a value as `('A',alloc_id,off)`, `('ARG',n,off)`, `('TD',off)`, `('UAP',off)`,
`('STK',frame_id,off)`, `('GLB',addr)`, `('C',v)`, `('M',slot,0)` (a pointer loaded from kernel
memory) and `('TOP',)` for anything unknown. State carries registers, a memory map keyed by
`(base_key, offset)`, freed allocations, pending stores and a per-path event log. `lc_paths.py`
enumerates paths with a DFS, a revisit cap of 3 per (instruction, state signature) and a state cap
of 48 per instruction, seeding `rdi=('TD',0,0)`, `rsi=('UAP',0,0)`.

Three events are derived from that model:

1. **Double free** - a free of an allocation already in `freed` on the same path, or a second free
   of the same memory slot (`twice=True`).
2. **Use after free** - any load or store whose base is a freed allocation, and any dereference of
   a pointer read out of a slot that was freed (`deref_check`, called from both `rd` and `wr`).
3. **Escape** - a store of an allocation-derived pointer into a slot whose base is not that
   allocation and not a stack frame (the Bagagwa shape). `stage_esc.py` collects these per
   allocation id, with alloc site, size, clear stores and frees.

### 3.6 Degradation filter, and why it is mandatory

Any token containing `TOP` or `UNK` anywhere in its tree is treated as degraded. A free whose `rdi`
is degraded is ignored, and so is a dereference of a degraded slot. This is not cosmetic: a
call-clobbered register collapses to `TOP`, every later load through an unknown base memoises to
one shared `('UNK',n)` token, and two unrelated frees then look like a double free of one slot.
Before this filter the census produced exactly that phantom three times (662 at
`0x3b00a3`/`0x3b00b4`/`0x3b00c8`, 669 at `0x3b27e1`/`0x3b27f4`). With it, the corpus has zero
double-free rows.

A second classifier rule killed a whole family of false escapes: a link only counts as live if the
holder is reachable from a global or absolute slot at the time of the free. An allocation that is
only held by an object that is itself freed a few instructions later is a doomed holder, not a
leak and not a UAF. The counters are `nlive` (published), `nlocal` (held by an unpublished object),
`nself` (self-reference only) and `ndead` (held only by an already-freed object).

### 3.7 Totals

| quantity | value |
|---|---|
| sysent entries / distinct bodies | 679 / 301 |
| bodies that allocate / free | 46 / 35 |
| allocation events modelled | 66,211 |
| free events modelled | 44,464 |
| double-free rows after filtering | 0 |
| use-after-free events | 0 |
| memory operands classified | 55,172 |
| of those, allocation as base | 4,850 (all live) |
| escape-arm candidates (escape + free in one unit) | 5 |
| escape-arm survivors | 1 (syscall 663, the known bug) |
| frees with a published (global-reachable) live link at the free | 0 |
| whole-corpus run time | about 3.3 s |

---

## 4. Dismissed candidates

Each row names the instruction that kills it. Quoted windows are reproducible with
`python stage_quote.py` (writes `life_quotes.txt`).

| candidate | unit | shape claimed | why it died |
|---|---|---|---|
| sys 662 `aio_multi_wait`-family, 4 frees at `0x3b00a3`,`0x3b00b4`,`0x3b00c8`,`0x3b00d3` | `0x3af900` | double free | four distinct fields of one object, each freed once per path; the row only appeared because two different unknown-base loads memoised to one token. Killed by the degradation filter; with it, zero rows |
| sys 662 sub-object free `0x3afee8` | `0x3af900` | escape | owner slot is cleared immediately after the free: `0x3afef5 mov qword ptr [r12+0x18],0` |
| sys 669 node array / job nodes | `0x3b2060` | escape, triple free | array slots are cleared (`0x3b2765`), the job's external ref is cleared (`0x3b2749`), and mutex/refcount teardown precedes each free. The 93 local-live frees are dangling links inside holders that were already freed a few instructions earlier |
| sys 669 argument size wrap | `0x3b2060` | (lead, not lifetime) | withdrawn: count is bounded to [1,0x80] by `0x3b217e lea eax,[r14-0x81]` / `0x3b2185 cmp eax,0xffffff7f` / `0x3b218a ja 0x3b21aa`, so `count*0x28` cannot wrap |
| sys 235 node publish + free | `0x6bd570` | escape | mutually exclusive branches: `0x6bd80e cmp qword [rbx+0x3b8],0` then `je 0x6bd837` publishes at `0x6bd83a`; the `free` at `0x6bd830` is the other arm. The earlier self-reference row was the same slot holding itself |
| sys 141 object publish | `0x313160` | escape | publish stores at `0x31343e`/`0x313444`/`0x31344c` are on the success path; the free at `0x313360` is the early error path (unlock, release `[r14+0xf0]`, free). Cross-path artifact |
| sys 653 table buffer | `0x9a7d10` | escape | the free at `0x9a7eaf` is the ENOSPC branch (`0x9a7e1b jbe 0x9a7e93`) taken before publication; the publish at `0x9a7e46`/`0x9a7e49` takes the other branch and its drop is refcounted (`0x9a7e55 lock add [r14+0x58],1`; `0x9a7e7a lock xadd -1`; `0x8b367c00` when old == 1) |
| sys 557 `umtx`-shaped submit | `0xac7240` | escape / UAF | B->f0 points at A when A is freed at `0xac7382`, but B is unpublished (only in r13) and freed at `0xac738d` two instructions later; nothing loads through B->f0 in between |
| sys 533 range object | `0x705880` | escape / early free | publication and free are disjoint: pre-publication error path frees the array at `0x705a3e` and the node at `0x705a49`; after publication the failure path calls `0x8b0c57a0` (unlink and release) at `0x705ba3` before `free(C)` at `0x705bb2` |
| sys 667 | `0x4a31a0` | any | 16,984 alloc / 16,791 free events, no escape and no freed-base dereference: churn-heavy but balanced |
| sys 664 | `0x3b0fb0` | any | one allocation (`count*0x18` at `0x3b126d`), one free site (`0x3b15ba`), no escape |
| sys 666 | `0x3b1680` | any | one allocation (`count*0x18` at `0x3b18ae`), one free site (`0x3b1dde`), no escape |
| sys 661, 665, 668 | `0x3af8f0`, `0x3b1670`, `0x3af8e0` | any | 5-instruction stubs: `push rbp; mov rbp,rsp; xor esi,esi; pop rbp; jmp 0x265760`, which is the slot table entry for the shared nosys target `0x5620e0`. No body exists in this image |

Two dismissal notes worth keeping visible:

- 669 looks like the Bagagwa shape at first read because it allocates a job array and frees it in
  teardown, but the asymmetry that creates Bagagwa is absent: the code clears the array slot after
  each free (`0x3b2765 mov qword ptr [rax+r15*8],0`) and clears the node's external ref
  (`0x3b2749 mov qword ptr [r12+0x40],0`). 663 clears nothing.
- 662 is the strongest near miss for a double free because four `free` calls sit within 0x40 bytes
  of each other. Reading the block shows they free four different fields of one object
  (`[r8+0x10]`, `[r12+0x20]`, `[r12+0x28]`, then `r12` itself), and the array slot that named the
  object is zeroed just before (`0x3b0097 mov qword ptr [rax+rcx*8],0`). That is correct teardown.

---

## 5. AIO cluster coverage (660-676), explicitly

| sys | sy_call slot | body | insns | alloc / free events | 14.10 measured | census result |
|---|---|---|---|---|---|---|
| 660 | `0x265590` | `0x34bc60` | 88 | 4 / 0 | not measured | no free, nothing to shape |
| 661 | `0x265710` | `0x3af8f0` | 5 | nosys alias | kills on zeros | no body in 13.60 |
| 662 | `0x265718` | `0x3af900` | 533 | 1,171 / 12 | works | dismissed, see section 4 |
| 663 | `0x265720` | `0x3b01f0` (impl `0x3b0210`) | 811 | 3,486 / 930 | works; mode 0 count>1 EINVAL | **survivor 1** |
| 664 | `0x265728` | `0x3b0fb0` (impl `0x3b0fd0`) | 396 | 621 / 15 | works | dismissed, balanced |
| 665 | `0x265730` | `0x3b1670` | 5 | nosys alias | kills on zeros | no body in 13.60 |
| 666 | `0x265738` | `0x3b1680` (impl `0x3b16a0`) | 588 | 1,792 / 624 | -1 on zeros (present) | dismissed, balanced |
| 667 | `0x265f88` | `0x4a31a0` | 289 | 16,984 / 16,791 | -1 on zeros (present) | dismissed, balanced churn |
| 668 | `0x265708` | `0x3af8e0` | 5 | nosys alias | kills on zeros | no body in 13.60 |
| 669 | `0x265740` | `0x3b2060` (impl `0x3b2080`) | 503 | 6,400 / 97 | works | dismissed, links cleared |
| 670 | `0x265748` | `0x3b28d0` | 263 | 0 / 0 | returns 0 | no allocation at all |

The four shared implementations the brief names were each reached by their stub and analysed as
part of the unit: `0x3af920` inside `0x3af900`, `0x3b0fd0` inside `0x3b0fb0`, `0x3b16a0` inside
`0x3b1680`, `0x3b2080` inside `0x3b2060` (669's stub rewrites esi/rdx/ecx/r8d/r9 before jumping).

---

## 6. Where the 13.60 image is the limiting factor

1. **661, 665 and 668 have no body here.** They resolve to a stub that jumps to the nosys slot
   `0x5620e0`. Any 14.10 lifetime question about them needs a 14.10 image. Their killing on zeroed
   arguments cannot be attributed to a handler from this corpus: a nosys path that delivers SIGSYS
   and a real handler that dereferences a null aiocb look identical from userland.
2. **All 14.10-only guards are invisible.** The mode guard that closes 663 exists only as measured
   behaviour; the 13.60 text has no equivalent check. Whether the guard tests `mode == 0` or the
   path `mode not in {1,2}` cannot be read from this image.
3. **Interprocedural publication is invisible.** If a handler hands an object to a helper that
   stores it in a table the handler does not own, the escape arm cannot see the store. 663's escape
   is visible only because the handler performs the linking itself. A helper-side table with a
   missing unlink would be silent in this model. The mitigation used here is the free-side live
   check (`nlive`), which does catch a free while a *global* still points at the object.
4. **Data layouts are inferred, not known.** Field offsets come from the code that uses them; a
   lifetime bug that depends on two fields aliasing in a structure the handler only passes through
   would not be visible.

---

## 7. Reproduce list

All commands run from `C:\PS5contrib\.local\life_census`. Requires python 3.11 and capstone 5.0.7.
Nothing writes outside `.local\life_census`.

1. `python stage_life2.py` - per-unit census over all 301 units; writes `life_all.json`.
   Expected: 301 units, 46 allocating, 35 freeing, 66,211 alloc events, 44,464 free events,
   `uaf` 0 in every unit.
2. `python stage_esc.py` - escape arm; writes `life_esc.json`.
   Expected: five units with an escape and a free (`0x3b01f0`, `0x705880`, `0x313160`, `0x9a7d10`,
   `0x6bd570`), of which only `0x3b01f0` (sys 663) survives reading.
3. `python stage_twice.py` - double-free arm; writes `life_twice.json`.
   Expected: `units with twice rows: 0`.
4. `python stage_quote.py > life_quotes.txt` - every disassembly window quoted in this document.
5. Spot checks used while triaging: `_dbg32.py` (141/653/533 escape detail), `_dbg33.py` and
   `_dbg34.py` (escape and free windows), `_dbg47.py` (full 660-676 chain and stats),
   `_dbg48.py` (663 windows), `_dbg49.py` (663 guards), `_dbg50.py` (totals).

Sanity checks that must hold if the engine is rebuilt:

- 663's unit contains `0x3b0210`, `0x3b0586`, `0x3b08e5`, `0x3b0e31`, `0x3b0f93` and ends at `ud2`
  `0x3b0fad`.
- 662's unit contains the documented sub-object free `0x3afee8`.
- The escape arm must flag 663. If it does not, the engine is broken, not the corpus clean.

---

## 8. Script inventory

| file | role |
|---|---|
| `lc_common.py` | image load, `BASE`/`DATA`, `md`, `dec_one`, `imm_branch_target`, `extent`, `fmt` |
| `lc_taint.py` | value model, `St`, `Engine`, `deref_check`, `degraded`, `reachable` |
| `lc_paths.py` | helper signatures, `build_starts`, `unit_insns`, `seed`, `run`, `probe_mayfree` |
| `stage_life.py`, `stage_life2.py` | first pass and aggregate census |
| `stage_esc.py` | escape arm |
| `stage_twice.py` | double-free arm |
| `stage_quote.py` | quoted disassembly for this document |
| `call_targets.json` | 578 call targets with call-site counts |
| `life_all.json`, `life_esc.json`, `life_twice.json`, `life_quotes.txt` | results |
| `full_557.txt`, `full_533.txt`, `full_663.txt`, `full_669.txt`, `skel_*.txt` | full listings used for triage |

---

## 9. One-line answer for the parent agent

The 13.60 text yields no new lifetime bug in the 301 syscall bodies: zero double frees, zero
use-after-frees, one escape, and that escape is syscall 663's shared waiter node, the known
Bagagwa/Relapse defect, still reachable in 13.60 at mode 0 count >= 2 and closed on 14.10 only for
the measured value mode 0. The one experiment that would settle whether 14.10 is still exposed is a
mode >= 3 call at count 2 with two zero ids.

---

## 9. 14.10 measurement: the guard covers every mode, not just 0 (probe 1244a)

`probes/phase17_new_vectors/1244a_aio_mode_guard_coverage.lua`
(`results/phase17_new_vectors/1244a_aio_mode_guard_coverage_20261105_141334.txt`, status COMPLETE)
sent the unmeasured modes with ids `{0,0}` so id 0 is skipped with `0x80020003` and the call returns
without ever waiting:

| mode | count | ret | out[0..1] |
|---|---|---|---|
| 1 | 2 | 0 | `80020003 80020003` |
| 2 | 2 | 0 | `80020003 80020003` |
| 0 | 2 | -1 | untouched |
| 3, 4, 5, 6, 7, 8, 0x10, 0x40, 0xFF | 2 | -1 | untouched |
| 3 with `timeout=50` pointer | 2 | -1 | untouched |

The two controls at the end of the run repeat the 1 and 2 results, so the -1 rows are the handler
refusing the call and not a damaged loader. Modes 3 and above return the same value as mode 0, with
the output array untouched: **the 14.10 guard rejects every mode outside {1,2} at count > 1**, which
is the instruction path the 13.60 body uses for all of them (`0x3b078c mov eax,[rbx+0x2c] ;
`cmp eax,1 ; jne 0x3b0839`, `cmp eax,2 ; jne 0x3b08e5`).

That closes survivor 1 on 14.10: the shared-node link, the owner overwrite at `0x3b096d` and the array
free at `0x3b0f9e` are unreachable at `count > 1` for every mode value, and at `count == 1` the loop
links a single node that cleanup unlinks from the same request. The Bagagwa/Relapse AIO class is
patched on this firmware in both the mode-0 and the mode>=3 direction.

