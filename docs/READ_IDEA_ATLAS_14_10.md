# READ IDEA ATLAS -- 14.10 -- every kernel-read idea this repo has had, and what is left

Scope: static + documentary only. Nothing here was measured this session; no probe was sent and no file
outside this one was written. Corpus: 154 local docs/*.md plus 231 docs under origin/master (tip
a4e87b46; merge base 860ecbcf; fork/master carries an identical doc set). Image facts are 13.60 facts
(docs/dumps_13.60/kernel_text.bin, base 0xffffffff8a9c0000, offset == RVA, len 0xE6E5C0); only the probe
results quoted are 14.10 measurements.

## Verdict

The most promising untried idea is not a new syscall, it is the gate byte at proc+0xc81. One byte in the
whole image writes it -- `mov [rax+0xc81],cl` at RVA 0x38f7bf with cl set to 1 immediately before -- and
that byte is the only thing standing between us and the one genuine arbitrary kernel read in this table:
sys 532 cmd 0x31, `movzx eax,word ptr [rax+rcx*2+4]` at 0xaf06d9, an unchecked index into one of seven
kernel tables (+-4 GB, 2 bytes read, 4 bytes returned to userland at 0xaf121e). Every doc so far treats
proc+0xc81 as an opaque 'debug byte', and every doc so far has therefore closed 532 on reachability rather
than on the instruction. The scan below shows the byte is not a constant: it is written 1 by a conditional
branch (cmp r12d,2 / jne) inside a kernel state machine at 0x38f3a0, reached only by two jmp rel32 and by
no call, no pointer table and no rip-relative lea. Finding which syscall drives that state machine to the
branch is pure static work with zero console risk, and it is the cheapest path in this atlas to a read that
returns attacker-chosen kernel bytes.

## Status corrections (2026-11-05, static only)

The Verdict above predates its own P2 entry. **P2 is CLOSED, not the top lead**: `priv_check(td,0x2aa)`
at 0xaf00e6 sits in front of the whole 532 cmd 0x31 path and probe 1242a measured EPERM for uid 1
(`docs/SYS532_OOB_GATE_14_10.md` section 6, `docs/UACCESS_HELPERS_14_10.md` section 6). Read the table,
not the Verdict.

Four rows that this atlas lists as OPEN or as the next step were closed elsewhere in the tree:

| row | closed by |
|---|---|
| 601 read-back / log drain | 2026-11-04, `docs/SYS601_SECOND_STAGE_14_10.md` section 9 - the second stage does not open for an unprivileged process |
| 604 dl_get_metadata | 2026-11-05, CHANGELOG "604, 656 and 560 close; 572 stays silent" |
| P5 / H1 YMM residue | measured negative, probe 1191a, `docs/YMM0_CLOBBER_14_10.md`; the offline byte-scan it asked for is in `docs/CREATIVE_ROUTES_14_10.md` line 114 |
| the "1 unknown" row of the indexed-load census | 2026-11-05, `docs/SYS341_INDEXED_LOAD_CLOSURE_14_10.md` - linear-sweep artefact, the index is an id-table iteration |

Closed since this atlas was written, not listed above: 532 cmd 0x31 (priv gate), 629 (vm_object has no
pager), 674's max and stride (min(stride,0x48) copyout into a fixed 0x48 stack slot), capability-tag
provenance (239 call sites, every tag read from a proc field), the Spectre v1 transmitter census (one
hit image-wide, and it is a load), and PROT_EXEC for vnode mappings.

Still genuinely unrun, and every one of them is a console measurement: **P1** (CR2 tracer), **P4**
(suspend-in-kernel + 634), **P8** (body x slot fault sweep), **P9** (624 deltas + 632 suspend).
Zenbleed needs a native-exec primitive that does not exist on 14.10.

## 1. Idea table

Status is CLOSED only where a document quotes the killing instruction or a probe result. line numbers are
blob lines of the cited doc.

| idea | first appears | status | the single closing fact | what would re-open it |
|---|---|---|---|---|
| copy source/destination derived from an argument | docs/INTERPROC_COPYOUT_SOURCES.md | CLOSED-BY-PROOF | "0 of 301 bodies performs a raw memory access whose base derives from a syscall argument" | a 14.10 image, or a body outside the 301 |
| copyin destination provenance | docs/COPYIN_DEST_PROVENANCE_14_10.md sec.4 | CLOSED-BY-PROOF | 432 sites, 314 write into the current stack frame; 0 arbitrary kernel destinations | the same two conditions |
| uninitialised stack copyout | docs/UNINIT_COPYOUT_SCAN_14_10.md sec.2 | CLOSED-BY-PROOF | 450 stack-source immediate-length copyouts, 0 survivors after 4 passes | a clearing helper the scanner did not model |
| copyout length taken from the caller | docs/COPYOUT_CLASS_CLOSED.md Verdict | CLOSED-BY-PROOF | "caller-controlled or global length 0/15" | the 638/639 table count becoming attacker-controlled |
| inline (non-helper) copy to a uap-derived destination | docs/COPYOUT_INLINE_MOVE_AUDIT.md | CLOSED-BY-PROOF | "inline moves writing to a uap-derived destination 0/21" | a second inline-move idiom |
| an argument value dereferenced as a pointer | docs/KERNEL_READ_SEARCH_14_10.md sec.5 | CLOSED-BY-PROOF (heuristic) | 10/10 candidates are kernel loads, e.g. 0x3b0247 `lea rax,[rip+0x356c0de]` global canary | a reload the taint pass dropped -- see P1/P8 |
| double fetch of a user length or pointer | docs/KERNEL_READ_SEARCH_14_10.md sec.9 | CLOSED-BY-PROOF | 29 body 0x5328D0 copyins the length once at 0x532925 and writes back the kernel copy; 41/90/92 and 165 use constant sizes | a race on the socket-address family on a real console |
| aio as a kernel-address source or destination | docs/KERNEL_READ_SEARCH_14_10.md sec.2 | CLOSED-BY-MEASUREMENT | 669(cmd 0x1002) with +0x10 = 0xFFFFFFFF85000000: accepted, state 3, zero bytes delivered (mask `and rdi,0x7fffffffffffff`) | a command whose mask is absent |
| indexed-load OOB (sys 532) | docs/SYS532_OOB_GATE_14_10.md | CLOSED-BY-MEASUREMENT | 14.10 reachable commands 0x18-0x1E/0x20/0x2F; priv 0x2aa refused; the OOB path needs proc+0xc81 != 0 | proc+0xc81 becoming nonzero -- see P2 |
| indexed loads generally | docs/KERNEL_INDEXED_LOAD_CENSUS_14_10.md | CLOSED-BY-PROOF | 176 sites: 24 immediate-bounded, 11 sound count checks, 140 kernel-computed, 1 unknown (sys 341, 0x55f0cb) | the sys 341 block that crosses a function boundary |
| indexed stores | docs/KERNEL_INDEXED_STORE_CENSUS_14_10.md | CLOSED-BY-PROOF | recorded as bounded-or-gated; not re-read line by line here | a bound read out of a field we can resize |
| object lifetime (UAF / double free) | docs/KERNEL_LIFETIME_CENSUS_14_10.md sec.1 | CLOSED-BY-PROOF + MEAS | 1 survivor: 663 waiter-node escape, freed at 0x3b0f9e; 14.10 mode 0 count>1 EINVAL | modes >=3 were never measured on 14.10 |
| thr_*/mcontext path to CPL0 | docs/MCONTEXT_INSTALL_14_10.md | CLOSED-BY-PROOF | the installer never loads CS, so iret to CPL0 is impossible by construction | nothing (structural) |
| 634 cross-thread context leak | docs/THR_LOOKUP_14_10.md sec.2 | CLOSED-BY-PROOF | resolver 0xb92420 is process-scoped: `mov ebx,esi` with esi=[curproc+0xbc], so a kernel tid is not in the table | a target thread suspended inside the kernel -- see P4 |
| blockpool class 0xb mapping | docs/BLOCKPOOL_ROUTE_14_10.md sec.2 | CLOSED-BY-MEASUREMENT | 654 EINVAL 12/12; body 0x9a9560 calls vm_map_lookup at 0x9a96a0, it does not create | anything that installs a type-0xb object |
| devfs as a surface | docs/DEVFS_GAP_ANALYSIS_14_10.md | CLOSED-BY-MEASUREMENT | 78 nodes enumerated; every read/ioctl/mmap is -1 or inert; dmem0 mmap returns GPU bus space | a node whose mmap returns non-aperture data |
| 587 credential record | docs/PRIV_CHECK_CENSUS_14_10.md | CLOSED-BY-MEASUREMENT | priv 0x2ae refused; the record carries one capability bit at +0x0C | a credential-context change |
| the privilege-gate census | docs/PRIV_CHECK_CENSUS_14_10.md | CLOSED-BY-PROOF | 99 sites, all still correct | a 14.10 site that the census does not contain |
| 637's stored qword as a primitive | docs/FMEM_LIMIT_637_14_10.md sec.4-5 | CLOSED-BY-PROOF | `cmp qword [r14+0x280],rax` at 0x691919 is the only qword reader; never deref, never an index, never copied out; the field is a 16 KiB page count | a dword reader whose base really is p_vmspace |
| 637 A/B on the allocation ceiling | docs/STATE_AND_PLAN_2026_11_05.md item 4 | RETRACTED | withdrawn in FMEM sec.6: every effectual value enters the reclaim loop | nothing |
| the 17 OBJECT-sourced copyouts | docs/KPTR_HUNT_OBJECT_COPYOUT_AUDIT_2026-11-05.md | CLOSED-BY-MEASUREMENT | 7 unique sites; 660 on 13.40 fills 44 qwords with kernel-band count 0 | a handler whose 14.10 body diverged |
| 566/567 slot index OOB | docs/POST_SURVEY_CLOSURES_2026-11-03.md sec.1 | CLOSED-BY-MEASUREMENT | idx 6,7,8,9,0x10,0x40,0x100,0x1000,0x7FFFFFFF,0xFFFFFFFF all leave 0xEEEEEEEEEEEEF000 | a slot count change in a later firmware |
| uap over-read as a leak | docs/UAP_OVERREAD_SCAN_14_10.md | CLOSED-BY-PROOF | 665/668 read [uap+0x10] and 113 reads [uap+0x20], but the slot sits at a fixed frame depth and holds our own earlier argument | a kernel-authored value on a recycled kernel stack -- see P3 |
| KASLR through a syscall | docs/UPSTREAM_STATE_2026_11_05.md C1/C24 | CLOSED-BY-MEASUREMENT | ~400 BSD syscalls, zero supervisor-range values; AF_ROUTE payload entirely zeroed | a handler nobody has called |
| kld* family and sysctlbyname | docs/UPSTREAM_STATE_2026_11_05.md C13 | CLOSED-BY-MEASUREMENT | shared nosys trampoline raises SIGSYS; -1 and process alive with SIG_IGN | nothing |
| W^X / fn_addr / ROP chain | docs/UPSTREAM_STATE_2026_11_05.md C14/C15 | CLOSED-BY-MEASUREMENT | 45c; 548 op2 refuses prot=7 on anon, file-shared and GPU mappings; 588 inert | an exec bit that survives creation |
| AIO double free | docs/AIO_DOUBLE_FREE_14_10.md | RETRACTED | a boot tunable never opens the submit path; the 'double' was double-status | nothing |
| umtx SHM (CVE-2024-43102) | docs/UPSTREAM_STATE_2026_11_05.md C12 | CLOSED-BY-MEASUREMENT | every sub-op returns 0 for any address, -1 for unmapped | nothing |
| a protection query as a KASLR oracle | docs/POST_SURVEY_CLOSURES_2026-11-03.md sec.3 | CLOSED-BY-MEASUREMENT | 547/639/638 return -1 for every kernel VA and leave the output page untouched | nothing |
| the fault oracle as a READ | docs/FAULT_CODE_ORACLE_14_10.md 'Is not' | CLOSED-BY-MEASUREMENT | 1006a: every kernel address faulted and left the 0xDEADBEEF sentinel intact; CS 0x43/0x40/0x00 all read the user buffer | a handler that opens a SMAP window -- see P1 |
| Spectre v1 against 638/639 | docs/MICROARCH_FEASIBILITY_14_10.md H5 | CLOSED-BY-PROOF | the disassembly has no second (gathering) load | nothing |
| 601 read-back / log drain | docs/CREATIVE_ROUTES_14_10.md Route 8 | OPEN | cmd 0x12 returns -1 (no session installed); the site is a paired read-back of a buffer cmd 0x11 installs | one command that appends kernel-authored bytes to +0x578 |
| 604 dl_get_metadata | docs/STATE_AND_PLAN_2026_11_05.md item 7 | OPEN | never called; the gate is ctx+0x58 == 0x4800000000000007 | one call with the five-argument shape |
| 653 precondition | docs/STATE_AND_PLAN_2026_11_05.md item 2 | OPEN | handles 0x17/0x18/0x19 then -1 for identical arguments | four calls in one process |
| YMM cross-privilege residue | docs/MICROARCH_FEASIBILITY_14_10.md H1 | OPEN | IMPLEMENTABLE-IF, never measured | one probe plus a ymm-store gadget |
| PMC-timed cache oracle | docs/MICROARCH_FEASIBILITY_14_10.md H2/H3 | OPEN | IMPLEMENTABLE-IF; wall-clock timing floor is 92 us | probe 1072a |
| Zenbleed CVE-2023-20593 | docs/MICROARCH_FEASIBILITY_14_10.md H4 | OPEN | needs native exec, and the target is not the kernel | a native-exec primitive |

## 2. New permutations

Each entry: mechanism / exact interface / what could go wrong / cost.

**P1 -- CR2 as a taint tracer (make the closed deref class empirical).**
Mechanism: the fault oracle already returns the #PF address at ctx+0xC8 and the error byte at ctx+0x130; a
handler that dereferences a caller-supplied value will fault AT that value, so CR2 is a receipt that the
dereference happened and its displacement is the struct offset. Interface: from a thr_create(430) child set
RIP = the loader syscall trampoline with RAX = body number and the argument slot = 0x0000000100000000 (an
absent user address); parent parses ctx+0xC8. What could go wrong: a handler faults on something else first
(then CR2 is not our value and the hit is a false negative, not a false positive); the sentinel can hit a
handler that legitimately checks the range first. Cost: one probe for eight candidate slots (reuse 1000a).

**P2 -- CLOSED 2026-11-05: dead behind priv 0x2aa.** Disassembling 532 from the body start (0xaf0040) shows `mov esi,0x2aa; call priv_check` at 0xaf00e6 with `je 0xaf011c` taking the SUCCESS path; the `proc+0xc81` clamp, the indexed load at 0xaf06d9 and the ±4 GB read are all inside that granted path, and probe 1242a measured priv 0x2aa as REFUSED for uid 1. See docs/UACCESS_HELPERS_14_10.md section 6. The original text follows for the record.

**P2 -- drive the proc+0xc81 setter, then use 532 as a +-4 GB reader.**
Mechanism: 0xaf0673 clamps the index to 2 only when proc+0xc81 is zero, so a nonzero byte removes the clamp.
Interface: identify the syscall that reaches 0x38f7bf (two jmp rel32 sources: 0x38f39a, a tail jump, and
0x39067a, a real internal jump), call it, then call 532(0x31, out, {idx}) and read 4 bytes. What could go
wrong: the branch is a one-way state transition in the process-exit or exec path and cannot be reached while
running; or the byte is set but the ID table gate (0x3CF7E38) rejects the handle first. Cost: zero console
risk to map, then one probe.

**P3 -- 665/668 ghost third argument.**
Mechanism: both bodies declare narg 2 but read [uap+0x10]; the argument block is memcpy'd at a fixed depth
in syscall()'s frame, so a prior call on the same thread writes that slot with a value we choose and 665/668
hands it to 0xad6f920 / 0xad716a0 as a third argument the sysent table says does not exist. Interface: on one
thread call a >=3-argument syscall whose slot 2 is a chosen qword, then call 665 (or 668) with two arguments.
Risk: if the target routine treats it as a pointer, the child dies (acceptable, parent survives); a bad value
could wedge inside the parked routine. Cost: one probe, two children.

**P4 -- suspend a thread inside the kernel, then read its context.**
Mechanism: 634 copies 0x4c0 bytes of thread context; the only measured case was a child in user mode, where
the copy is the caller's own user trap frame. A thread parked INSIDE the kernel has no live user trap frame,
so whatever 634 copies then comes from pcb/kernel-stack state, which holds a kernel RSP at minimum.
Interface: park a child with 632 or a blocking syscall (sacrificial thread primitive), then 634(tid, buf) from
the parent, and scan the 0x4c0 bytes for 0xFFFF8xxx. Risk: 634 on a kernel-mode thread may fault the
process rather than the child. Cost: one probe with the sacrificial-thread harness.

**P5 -- YMM residue after a kernel-to-kernel bcopy.**
Mechanism: if the kernel's bcopy uses AVX and never issues vzeroupper, the tail of the last kernel buffer
copied stays live in YMM0-15 across the syscall return; userland reads it with a ymm store. Interface: pick
the syscall with the largest kernel-to-kernel copy (674, 593's 0x160 records, or sysctl kinfo_proc), run it,
then execute an existing eboot gadget that stores ymm to our buffer (byte-scan for c5 fc 11 / c5 fe 7f, and
for cpuid 0f a2). Risk: the kernel may already vzeroupper, or the loader clobbers YMM first. Cost: one
offline byte-scan, then one probe.

**P6 -- full #PF error byte as a page-table side channel.**
Mechanism: the oracle masks (v>>8)&0xF, discarding the W (bit 1) and I/D (bit 4) bits, which the captures
show are really there (child instruction faults report 0x150E, i.e. err 0x15). Interface: three children per
address -- data read, data write, instruction fetch -- and record the whole byte. What it actually buys: the
error word reports the ATTEMPTED access type, not the PTE's RW bit, and the U/S check fires before the NX
check, so a present supervisor page reads 0x05, 0x07, 0x15 in the three cases and nothing more. The side
channel therefore carries no information beyond presence, and presence is already exhausted because the
direct map is not in our page tables. Cost: one probe to confirm the negative and stop anyone repeating it.

**P7 -- errno as a branch tracer for gated handlers.**
Mechanism: the Lua return value is 0 on every failure and the real code lives in get_error_string(), which
is only written on failure, so a stale code survives a success. The ordered sequence of stale errno values
across four calls is a readable trace of which branch a gated handler took, without a crash. Interface:
prime errno with a known failure, then call the target and record get_error_string() per call (653's
precondition, 604's identity gate, 601's 48 commands). Risk: none to the loader. Cost: one probe per handler.

**P8 -- body x slot fault sweep (P1 generalised to the whole table).**
Mechanism: for every present syscall number and every argument slot 0..5, run the body once from a child with
that slot set to an absent address and CR2-checked against it. This measures, rather than reasons about, the
class that was closed by a taint heuristic. Interface: 1000a's harness plus a per-slot table; keep one child
per (body, slot) so a fault costs a thread. Risk: bodies that park (601 0x08/0x0C) need one spawn budget
each; bodies that panic on a raw struct proc* (601 0x03/0x04) must be excluded by list. Cost: one long
connection, roughly 301 x 6 children.

**P9 -- allocation-free detector from 624 deltas plus 632 suspend.**
Mechanism: 624 is a VM-operation counter with zero jitter (+5 per mmap), so a suspend inside a syscall that
allocates a vm_object followed by a 624 delta reads out whether the object was created and whether closing
the parked thread releases it. Interface: park N children inside the target call, read 624, kill the parked
threads, read 624 again. Risk: parked threads outlive the probe. Cost: one probe per candidate body.

**P10 -- 637 as a page-out pump against a file pager.**
Mechanism: a value below capacity-usage forces the 0x6918a0 reclaim loop to page out our own entries by
protection (test dword [rax+0x60],0x40102) and object type (cmp ecx,8), so 637 becomes a way to make the
kernel free pages on command while a second thread holds a reference. Interface: mmap a file-backed object,
hold it in a second thread, call 637(0,17..cap). Risk: HIGH -- the documented wedge is an unbounded reclaim
under a held mutex, and it costs a relaunch. Cost: one probe, one relaunch.

**P11 -- 598/599 short second copy into a copied-out object.**
Mechanism: 598/599 copy a descriptor struct twice from one register (0x20 then 0x18); a short second copy
leaves 8 bytes of the destination from the first pass or from stack, and 608/656 show these records do get
returned to userland. Interface: call 598 with a 0x20-byte struct whose tail differs between the two calls
if a race is possible, else just read the returned record and compare against a zero baseline. Risk: low.
Cost: one probe.

**P12 -- 653 handle churn as a reference-count probe.**
Mechanism: 653 returns handles until -1 and 654 can close them; if the handle table entry is refcounted and
close frees it while a 654-built mapping still points at the object, the fourth failure is a signal that the
table is not a counter but a resource. Interface: create 3 handles, close 2, create 4, 654 the stale handle.
Risk: a UAF here could panic rather than fault. Cost: one probe.

## 3. Ranking

| rank | idea | chance of a read | cheapness | loader risk | note |
|---|---|---|---|---|---|
| 1 | P2 proc+0xc81 setter | high if the branch is reachable while running | offline first, then 1 probe | none until the probe | the only gate in front of a real OOB read; start with 0x39067a's function and its callers |
| 2 | P8 body x slot fault sweep | moderate -- it re-measures a class closed by heuristic | 1 long connection | low (child threads only) | the static close itself says the heuristic is defeated by register reloads |
| 3 | P1 CR2 tracer on the four real over-reads | moderate | 1 probe | low | 665/668/113 are the only bodies that read past narg, and 665/668 pass the value to a routine |
| 4 | P4 suspend-in-kernel + 634 | low-moderate | 1 probe | medium (634 on a kernel-mode thread) | the only untested half of a family already proven to copy 0x4c0 bytes |
| 5 | P5 YMM residue | low but all-or-nothing | 1 scan + 1 probe | low | needs a ymm-store gadget in eboot, which is readable |

Deliberately not ranked: P10 (documented wedge), P6 (recorded as a negative so nobody spends a probe),
P3/P11/P12 (cheap, low ceiling).

## 4. Method and limits

* The c81 census is this session's one new measurement: a single byte-pattern pass over the 15 MB image for
  disp32 0x00000c81 behind a mod=10 modrm gives 72 sites -- 60 `cmp byte [reg+0xc81],imm8` (all group /7),
  7 movzx loads, 1 store, 1 false positive (`jg 0xc81` at 0x4bd6e1). The store is RVA 0x38f7bf, bytes
  `88 88 81 0c 00 00` = `mov [rax+0xc81],cl`, preceded by `b1 01` (mov cl,1) and followed by `e8 56 0d 00 00`
  (call) / `85 c0`. Enclosing prologue 0x38f3a0, store at +0x41f; zero e8 callers; no 8-byte absolute
  pointer to 0xffffffff8ad4f3a0 anywhere; no rip-relative lea; two jmp rel32 (0x38f39a, 0x39067a).
* Scripts: .local/atlas/scan_c81.py, .local/atlas/scan_c81b.py, .local/atlas/who_writes_c81.py,
  .local/atlas/callers_c81setter.py, .local/atlas/refs_c81setter.py. Each is a single process, seconds each.
* Every instruction quoted above was re-decoded from the bytes in this session except the ones quoted from
  docs (0x691919, 0xaf06d9, 0x9a96a0, 0x3b0247), which are cited to their document rather than re-derived.
* Standing caveat the tree applies to itself and this table inherits: no verified 14.10 kernel image exists
  in this repository, so every body-level claim is a 13.60 claim about a 14.10 console.
