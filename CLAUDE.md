# PS5 14.10 Kernel Research — AI Guide

## What This Project Is

Systematic kernel exploit research on PlayStation 5 firmware 14.10. The goal is: **userland code exec → kernel R/W → hypervisor bypass**. We have userland code execution via a Lua 5.1 loader on TCP 9026. We need kernel memory access.

## Session Protocol — read this first

Context compacts; memory does not survive it, files do. Two files carry a session:
`results/STATE.md` (mutable, one block, rewritten in place) and `results/INDEX.md`
(append-only, one line per console run). Everything below keeps facts in those
files instead of in a conversation.

**Start, in this order:**

1. `python tools/state.py check --ip <console>` — prints the state block, the last ten
   ledger rows, and whether 9026 answers. Unreachable means the game process is dead:
   ask the user to relaunch; do not send probes.
2. Re-measure the kernel base with `.local/1331a.lua`. It re-randomises on every console
   reboot, and `STATE.md` only holds the last measurement, never the current truth.
3. `grep -rn "<syscall number or topic>" results/INDEX.md docs/ probes/` before writing
   a probe. Paste the hits into the probe header as `-- prior art:`. No prior-art line,
   no send.
   Grep a **clean clone** as well as this working tree — a scratch tree drifts, and the
   docs that close a question are the ones upstream has merged. Pull the clone first,
   then `python tools/state.py seed` so its new captures join the ledger.

**After every run:** `python tools/state.py row <probe> --claim "..." --result "..." --grade M|V|S|D`
then `python tools/state.py set last_probe=... next_action=...`

**Using the two files:**

- `STATE.md` is **not a diary**. Overwrite each line; if it grows past ~12 lines,
  something belongs in a doc instead. Every value is the *last measurement*, so a
  reader must be able to date it — put the time inside the value when it matters.
- `INDEX.md` takes **one row per run, written right after that run**, while the
  capture is still the newest file for that probe (that is how `row` finds it).
  `--claim` is one sentence saying what the run shows; `--result` is the number or
  the return code; point at the capture and let it carry the rest.
- Run `seed` after pulling upstream, so newly merged captures get indexed. It is
  idempotent: a second run adds nothing, and it never rewrites history.
- Never edit or delete an indexed row. A wrong row is corrected by appending a
  newer row that says so, exactly as `results/INDEX.md` does for 55c.

**Grades.** `M` measured on the console this session · `S` read from a source file or dump ·
`I` inference · `V` **void** — the probe died, or never reached the handler, so the row
proves nothing · `D` dead end, with the reason in `--result`. A negative without a capture
path does not exist; a `V` row is not a dead end and must never be cited as one.

**Known void captures:** `results/phase14_final_push/55c_sys622_careful_20261018_095816.txt`
— every call passed `arg4=0x100`, rejected at the 622 entry check, so no command ever
dispatched. The "all 400+ commands return 0x800E0001" reading came from that capture; the
sys 622 entry below already corrects it, and any pre-2026-11-06 622 number elsewhere in this
file should be treated as suspect. Also void: 54o/54p/55g (no post-call marker) and 1334a's
budget rows (died at 568). Re-running a void probe is a correction, not a discovery, and
correcting one is a publishable contribution.

## Critical Context

## Current Evidence Correction — 2026-10-18

This section scopes the current claims; older notes describe their cited probe sets. See [the ledger guide](docs/RESEARCH_EVIDENCE.md). A writable pointer, a truncated write, a returned Lua value, and an identified dispatcher implementation are different evidence.

- **KASLR is defeated for the image base** (2026-11-04, `docs/FAULT_CODE_ORACLE_14_10.md`): the loader's `SIGSEGV` handler receives the faulting thread's context, and `ctx+0x130` holds the x86 page-fault error word, whose `(value >> 8) & 0xF` is 5 for a mapped supervisor page and 4 for an absent one. A child thread can fault on a kernel-half candidate and die alone, so the range is sweepable in one connection. Two boots gave `0xFFFFFFFF91800000` (98 MB image, 2 MB aligned) and `0xFFFFFFFFD8000000`, a slide of `0x46800000`. This is presence, not content: no kernel byte is read and kernel R/W is still missing.
- Probe 45c recorded sysctl/getpid results persisting after selected fn_addr changes and corruption of chain entries 0–7 in one run. This contradicts the earlier dependency model for those tested calls; it does not identify the complete dispatch implementation or establish that every path ignores those fields.
- Probe 46b reports a shared C-function __call address, but its log is truncated and does not establish the function's implementation or a redirection primitive.
- Probes 54o and 54p are incomplete: 54o stops immediately after writing the candidate `+0x20` field, while 54p stops after printing the `xor eax,eax;ret` gadget address. The captures contain no post-call marker, restore confirmation, or returned Lua value. Probe 55g changes to binary output after its write marker, and 54r reads target bytes; neither alone identifies executed instructions. The 54q timeout has no returned-call evidence. Later 56c supplies discriminating output after selected +0x20 target changes.
- **Selected userland CClosure redirects are supported** (56c/56f, 2026-10-18): 56c records rawequal→rawget and rawget→type with distinguishing outputs and restoration; its tostring targets print 42 without a return-type check. 56f adds string.len/math.abs target-like values. General executable-target support, native-register argument control and internal calls to type() remain unverified. A 14.10 kernel vulnerability and kernel read/write are not demonstrated.
- Probes 43o, 43p, 43a/43b, and 47b have evidence gaps. Retest 53d established qword writability/restoration across the tested CClosure offsets; 54o/54p remain incomplete redirect experiments. The older audit predates the saved 52a/52b outputs noted next.
- Scripts 52a/52b now have saved outputs (2026-10-18): 52a crashed at sys 631 (627-630 PCALL-FAIL); 52b confirmed sys 624 as a VM operation counter (+5 per mmap, zero jitter).
- **thr_create(430) kernel panic root cause identified** (PRs #30/#31, 2026-10-19): 13.60 Ghidra decompile of 22 functions shows `set_mcontext()` copies CS register from user ucontext without OR-ing `SEL_RPL_MASK` (0x3). CS=0 from zeroed context → `ISPL(0)=0` → kernel-mode fault path → `pcb_onfault==NULL` → `trap_fatal` → panic. Fix hypothesis: CS=0x43/SS=0x3B should produce a user-mode thread. This is a 13.60 analysis; behavioral match with 14.10 panic (rv=0, TID returned, delayed panic, entry point irrelevant) is strong but identical code is not proven. Probe 80a tests the CS=0x43 fix on 14.10. **The selector question is measured (448a-452a, 2026-10-23)**: `CS = 0x40` starts a child that executes (448a), but `in al, dx` - illegal at CPL 3 - faults in that child (452a), so the thread stays ring 3. 14.10 replaces or masks the selector; a bad context can only panic, never raise CPL. The earlier "probe 189a" line had no probe, capture or commit behind it and is replaced by these measurements. **Capture re-read (2026-10-21, `docs/THR_CREATE_SETMCONTEXT_COPYMAP_13_60.md`): the 13.60 set_mcontext never reads the context CS field (+0xC0) at all** — it copies GPRs, RIP, RSP, SS (raw, unvalidated) and masked rflags; tf_cs is inherited from the parent frame. 189a's CS=0x40 result is therefore predicted by the copy map, not a divergence; the zeroed-context panic is better explained by SS=0 copied raw into tf_ss (or RIP/RSP=0). Probe 274a discriminates CS=0 vs SS=0 live.
- **The "umtx" probes called syscall 557, not `_umtx_op(454)** (2026-10-19): phase-1/2 probes 04/10-13 and the first revision of 82a bound `sc_umtx_op` to 557 (namedobj_create in the 13.60 capture). 56i2's section [F] is the only saved 454 execution (ops 5/21 ret=0, op 5 wrote a TID-shaped owner word). UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) were never exercised on 454, and FreeBSD 11 reads their key/params pointer from uaddr1. Do not treat probe 10's SHM/robust findings as umtx evidence. Probe 110a prepared; see docs/UMTX_454_EVIDENCE.md.
- The captures labeled 13.60 are fixed ranges, not complete kernel sections; acquisition authenticity remains unresolved; no verified 14.10 kernel image is present in this repository.


### The Environment
- **Target:** PS5 at YOUR_PS5_IP:9026, firmware 14.10
- **Kernel:** FreeBSD r230171 (Sep 28 2026), 16KB pages
- **Entry:** Lua 5.1 scripts sent over TCP (8-byte LE length prefix + raw source)
- **Tool:** `python tools/send_probe.py --save probes/<path>.lua` (writes a JSON run record; `tools/run_probe_batch.py` provides bounded sequential execution)
- **Per-connection ASLR:** Fresh process spawns for every TCP connection. All addresses must be re-derived each run.

### What We Have (Confirmed Working)
| Primitive | How |
|-----------|-----|
| Tested raw syscall invocation | make_syscall(N) bypasses the Lua syscall.resolve() filter for tested numbers; kernel-side restrictions still apply |
| Heap R/W (256+ pages) | GPU mmap adjacency, no guard pages |
| Userland module-base discovery | dynlib_get_info(593) returned base information for 39 userland modules; kernel ASLR is separate |
| Kernel image base per boot | Fault-context oracle: `ctx+0x130` page-fault error word distinguishes mapped from absent supervisor pages, so a one-connection sweep yields base and extent (995a-1006a, 1008a-1010a; `docs/FAULT_CODE_ORACLE_14_10.md`) |
| eboot gadget catalog | Readable candidate bytes; 56e records nil gadget-test returns, but no working general ROP chain is established |
| Network packet injection | RAW socket + IP_HDRINCL, TCP connect-back with ARP responder |
| sys 649 module member query | Returns userland addresses for member types 1-4, 7, 8 across module handles (no kernel pointers). Probe 54k, 2026-10-18 |
| CClosure function redirect | Selected existing Lua C targets produced target-like outputs and restore checks (56c/56f); eboot gadget execution confirmed via +0x20 redirect (56d-56d7); arbitrary native-register argument control and ROP chain remain unverified |
| Eboot gadget catalog (rax=N) | rax=0 (+0x471), rax=1 (+0x1AB0C6), rax=6 (+0xCEF50), rax=7 (+0xDBF50), rax=8 (+0x8D2D4); no rax=2,3,4,5 in 1.5MB scan. Gadgets control Lua return count for stack reads (probes 56d5-56d7) |
| native.fcall_with_rax | Arbitrary userland function calls: getpid=0x22a, socket=0x16, close=0x0 confirmed (probe 129b) |
| Native syscall chains | `thr_create(430)` starts a child at a gadget chain in eboot's RX text: `RIP = pop rax; ret` (eboot+0x992), stack `[num][syscall;ret][pop rax][num]...`, `pop rdi; ret` (eboot+0x75DFE) for per-link arguments, `pop rax; 431; syscall` to exit. 2 MiB stack, `RFLAGS=0x202` at +0x0F0. Probes 404a-422b, `docs/CHAIN_14_10.md` |
| C11 threading (Thrd_create) | 5+ concurrent threads with join; Atomic_fetch_add_8 as thread entry verified (probes 126g/126h) |
| UMTX_OP functional (op 5/21) | UMTX_OP_WAIT blocks correctly on value match; NWAKE_PRIVATE returns 0; MUTEX_LOCK writes owner TID (probes 56i2, 152k) |
| Device inventory (34/76 nodes) | 34 of 76 `/dev` nodes open from game process (`gc`, `dce`, `ajm`, `dmem0`-`2`, `camera`, `usb`, `hid`, `bt`, `rng`, `gic`, `notification*`, HMD sets); ioctl reaches drivers, they reject commands. 32-bit dirent layout. Probes 259a-268a, PR #74 ng643, 2026-10-21 |
| thr_new(455) with arg delivery | `start_func(arg)` where `arg` arrives in `rdi`. `struct thr_param` (0x38 bytes): start_func(+0), arg(+8), stack_base(+0x10), stack_size(+0x18), child_tid(+0x30). Much simpler than thr_create(430) ucontext. Gadget `mov [rdi],rax;ret` at eboot+0x92C67. Probe 56l, 2026-10-23 |
| Child thread ROP syscalls (5-arg) | thr_new child with controlled stack executes arbitrary 5-arg syscalls via ROP. Full gadget catalog: pop_rax_ret(+0x992), pop_rdi_ret(+0xC9DFE), pop_rsi_ret(+0xD77D), pop_rdx_ret(+0x3B02D7), pop_rcx_ret(+0xE64), pop_r8_ret(+0x991), pop_rdi_rbp_ret(+0x169), pop_rsi_rbp_ret(+0x78), bare_ret(+0x42). pop_r8 is bytes `47 58 C3` (REX.RXB encoding, mid-instruction at +0x990); 386a missed it searching only for `41 58 C3`. Verified from child thread (396f). No pop_r9 — max 5 controlled args; R9 possible via `mov r9, r13; call [rax+8]` trampoline. RSP = ((stack_base + stack_size) & ~0xF) - 8. Probes 271g/272a/396f, 2026-10-23 |
| EVFILT_TIMER + socketpair | kqueue(362) + kevent(363) with EVFILT_TIMER(-7) works at 1ms resolution. AF_UNIX socketpair (SOCK_DGRAM) works: write/kevent pipeline confirmed. Probe 271i, 2026-10-23 |
| Child thread fake TCB fix | fn_addr stub error path accesses `%fs:0` for errno — child without TLS crashes on ANY failing syscall. Fix: prepend `sysarch(SET_FSBASE=129, &fake_tcb)` to child ROP chain. Fake TCB = 4KB self-referencing pointer buffer. After fix, `close(-1)` returns -1 normally, sysctl returns -1 (EFAULT). Probe 384b, 2026-10-23 |
| Child multi-arg confirmed | getpid(0-arg)=pid, write(3-arg)=8 bytes via socketpair, socketpair(4-arg)=ret 0 fds created, setsockopt(5-arg) via pop_r8 — all from child thread. sysctl(6-arg) fails EFAULT (no pop_r9; R9 possible via mov r9,r13 trampoline). pop_r8_ret at eboot+0x991 (bytes 47 58 C3, REX.RXB encoding; 386a searched only 41 58 C3 and missed it). Verified child execution by 396f. Max controlled: 5 args. Probes 384b/386a/396f, 2026-10-23 |
| Concurrent child races clean | Double-close (100 iter), UMTX trylock (50×4), socket write+close (50 iter) — zero kernel pointers, zero anomalies, zero corruption. fd table lock solid. UMTX trylock(op 6) always returns -1 from child (may need full umutex struct or unsupported). Probe 385a, 2026-10-23 |
| POSIX shm (shm_open/ftruncate/mmap) | shm_open(482) works: SHM_ANON, named objects, O_CREAT\|O_RDWR, ftruncate, mmap(MAP_SHARED). sendfile(393) on shm fds sends 16KB/page with interleaved drain. shm_open2(571) is nosys — no largepage objects. Probes 391a-391d, 2026-10-23 |
| mlock(203) heap pages | mlock returns 0 on heap pages — prevents paging, ensures residency. munlock(204) also works. Probe 392f, 2026-10-23 |
| stat(188) filesystem enumeration | stat works on /, /dev, /dev/*, /app0, /app0/*, /system_tmp. mode=0x0000 everywhere (Sony zeroes). Other paths (/system, /data, /proc, /tmp) return -1. Probe 392f, 2026-10-23 |
| **aio_multi_delete TOCTOU double-free** | Two child threads calling 662(ids, N, states) concurrently on the same polled ID array produce double-deletes: 65/480 IDs freed by BOTH threads across 30 iterations (26/30 iters hit). Requires: submit individually via 669, poll via 664 (prerequisite — unpolled requests return 0x80020010), NO 670 init (poisons delete path). 662 works without sysarch (no errno touch). Probes 65d-65l, confirmed 65l. See `docs/AIO_DOUBLE_FREE_14_10.md` |
| **Canvas2D UAF bidirectional R/W** | Desynchronized getter on `canvas.getContext('2d', opts)` → stale wrapper (`inner`) points to freed CanvasRenderingContext2D → same-type spray with 80 canvas contexts reclaims. `setTransform`/`getTransform` gives 6 doubles (48B) R/W channel. Also aliases lineWidth, globalAlpha, shadowBlur, shadowOffsetX/Y, miterLimit, lineDashOffset. save/restore works. Cross-canvas drawing, DOM identity confusion, JS object sharing all confirmed. Cross-firmware: elanonimo832 confirmed on PS5 Pro 14.20 (3/3 cold boots). Cross-type reclaim (AB→Canvas2D) is DEAD — different bmalloc size classes. Probes p553/p554d, 2026-11-04 |
| **WebKit JSC JIT active (DFG)** | 5M integer loop in 49ms → unmistakably JIT-compiled native code. DFG tier confirmed; FTL likely absent. `new Function()` IS JIT-compiled. Probe p602, 2026-11-04 |
| **WebKit JS features inventory** | ResizableArrayBuffer (resize + maxByteLength), BigInt, BigUint64Array ALL available. WebAssembly ABSENT. SharedArrayBuffer ABSENT. Workers, fetch, WeakRef, structuredClone available. Probes p601/p605, 2026-11-04 |
| **iframes fully functional** | `document.createElement('iframe')` + contentWindow/contentDocument, cross-realm eval, srcdoc, about:blank + script injection, cross-realm array access. `mainInstanceof=false, iframeInstanceof=true` confirms separate JSGlobalObjects. Probe p640, 2026-11-05 |
| **FontFace T-determinism** | HashTable address T=0x10001cbad0 is 100% stable across 18 warm reloads on our bench. Lane b59 also 100%. Bake approach viable for FontFace if needed. Probe p612, 2026-11-04 |
| **KASLR defeat (fault oracle)** | x86 #PF error code from signal handler discriminates mapped (supervisor) from unmapped kernel pages. thr_create(430) child with RIP=kernel VA faults, rebuilt signal handler writes mcontext to socket, thr_exit(431) ends child, parent survives. 512 probes/connection in 33s. Discriminator at ucontext+0xD8: `(value & 0xF)` = 5 (present) or 4 (not present). This boot: stub at `0xFFFFFFFFC0000000` (2 MB), kernel image `0xFFFFFFFFD4000000`–`0xFFFFFFFFDA5FFFFF` (102 MB, 2 MB aligned both edges). KASLR slide `+0x54000000`. No KPTI — kernel pages visible in userland page tables. NOT a read primitive: supervisor bit enforced, content unreadable. Probes 1199a/1199b/1199c, `tools/decode_fault_scan.py`, 2026-11-04 |
| **Canvas2D getContext reentry UAF** | CVE-2026-43720: bitmaprenderer outer + alpha getter creates 2d inner → 768B freed, 150-context spray reclaims at spray[9], full bidirectional R/W (lineWidth, miterLimit, globalAlpha, fillStyle, transform, save/restore). Pixel data NOT shared (per-canvas). stateStack OOB dead (reclaim reinitializes). Probe p635, 2026-11-05 |
| **WebProcess text base leak (FontFace walk chain)** | FontFace UAF + 192B AB spray → 4 forgeRead+readStyle calls walk: hash table → WeakPtrImpl → CSSFontFaceSet → vtable pointer (VP). VP is a code-segment address with offset `0x1B28` (mod `0x4000`) — 1 boot confirmed in committed beacon data; 14/14 resolved samples at 16 KiB resolution (1 truncated excluded). VP = WebProcess_base + CSSFontFaceSet_vtable_RVA. 9 vtable function pointers also leaked (s0-s8). VP leaked; RVA not yet determined — text base not yet computable. Probe p691, 2026-11-09 |

### What's Blocked (Hard Walls)
- **fn_addr/ROP execution is not demonstrated** — 45c undermines that earlier model for tested calls. Later selected CClosure redirects are separate userland evidence; neither identifies the complete syscall dispatcher
- **W^X enforced, refused bit named** — `mprotect` accepts exactly the values with bit 2 clear (32768 of 65536, probe 423a); bit `0x4` (execute) is the only one refused. `mmap` with `prot=0x7` maps a writable page and a child jumping to it faults on its first instruction, as with `0x33`; `prot=0x5` maps but cannot be written (424a-424c). No protection this process can request is executable.
- **Execute-only memory (XOM)** — system lib .text is XO (reading crashes); eboot is RX
- **Threading works via `thr_create(430)` and `thr_new(455)`** — `fork`, `rfork` stay blocked, but both `thr_create(430)` and `thr_new(455)` start userland threads. `thr_new` is simpler: `start_func(arg)` with arg in rdi, no ucontext gates. `thr_create(430)` starts a second userland thread when the context carries the handler's three gates (`+0x108 = 0x480`, `+0x0d0 <= 7`, `+0x110 = 0x10000`) plus `CS = 0x43` at `+0x0c0`, `RIP` at `+0x0e0`, `RSP` at `+0x0f8`, `SS = 0x3b` at `+0x100`; GP registers come from `+0x048..+0x0b8`. Probes 156c/156d: `rv = 0`, `thr_kill(tid, 0) = 0`, and the child executed `mov [rdi], rax; ret` in eboot and wrote `0xdeadbeefcafe` into a mapped page. The `+0x90..+0xb0` offsets used by 80a are not the fields the handler reads; that context is rejected at `+0x108` (`rv = -1`) with a TID written before validation. `thr_suspend(442)` returns -1 for the child, so a spinning thread outlives the probe; no kernel primitive and no TLS inside the child yet. See `docs/THREADING_ALIVE_14_10.md`.
- **Thread ucontext read is available, write is not** (325a/326a, 2026-10-22): 632 suspends, 633 resumes, and 634 copies 0x4c0 bytes of a suspended thread's saved registers (RIP at `+0xE0`, CS at `+0xE8`, RFLAGS at `+0xF0`, RSP at `+0xF8`) with no kernel pointer in the copy. 635 `thr_set_ucontext` returns `-1`, although its 13.60 dossier describes a stub returning 78, so register rewrite of an existing thread is unavailable.
- **mmap_dmem (628) refuses every shape** (330a/331a, 2026-10-22): the dossier's "descriptor -1 bypasses the device lookup" made it a physical-memory candidate, but 24 calls across descriptor `-1`, a `/dev/dmem0` fd, a `/dev/zero` fd and `0`, three protections, flag `0x40`, a nonzero address hint and two offsets all return `-1`. The refusal is independent of the descriptor, so the entry rejects before the lookup. The nodes themselves open (dmem0-2, dce, gic, gc, zero, fds 22-35 in both modes).
- **The authid gates hold** (332a/333a, 2026-10-22): 535, 536 and 563-566 compare `cred+0x58` against identity values and return `-1` when the caller names its own pid, while selector `0` (which skips the check) returns `0`. Sys 587 is the only reader of the credential record and exposes just the capability word on a game process (`+0x0C` = `0x20000000`; system pids show `0x40000000`), with `cred+0x60` zero, so bit 62 - the gate on 618/646/671 - is clear and unreadable.
- **CVE-2026-49418 (device pager page-list UAF) is not reachable** - `msync(MS_INVALIDATE)`, the call the advisory needs, returns `EINVAL` on every mapping a game process can create (anonymous, GPU-shaped, `/dev/dmem0`/`/dev/gc` `MAP_SHARED`, vnode-backed game files), while `MS_ASYNC`/`MS_SYNC` return 0. `msync` is 65 (`narg 3`); 226 is the shared nosys stub. Probes 455a-455d, `docs/MSYNC_CVE_2026_49418.md`.
- **A kill does not prove the slot is absent** (2026-10-20). It did, by the 173a reading: `make_syscall(4095)` kills and 4095 cannot have a handler. But 622 `ipmimgr_call` kills on six zeros and, with the size field at or below `0x40`, dispatches and writes `0xFFFFFFFF` into the caller's buffer (`1335a`, 2026-11-06; `55c` is **void** - it passed `0x100` and recorded the entry-check reject), so a present handler that faults on the arguments dies the same way, and a kernel that kills on a forbidden call would look identical. A kill is a result about the call, never about the handler. The range 661-670: 662, 663, 664, 666, 667, 669 return `-1` to six zeros, 670 returns `0`, and 661/665/668 kill on zeros. With the shape their contract names (an id array, a count and an output array) 662/663/664 return `0` and write one Sony status per id - `0x80020003`, unknown id - so they are working batch calls whose ids can only come from the submit path that kills (301a-303a). See `docs/SYSCALL_ABSENT_VS_LETHAL.md` and `docs/AIO_RANGE_14_10_EVIDENCE.md`.
- **The measured sysent ends at 676** (2026-10-20): 677 through 707 each killed the process, thirty-one consecutive numbers including the five `nosys` slots, which reads as past-the-end rather than thirty-one hostile handlers. The 13.60 capture has 735 entries and names the tail (`wait6`, `pipe2`, `ppoll`, `get_phys_page_size`, `ioreq`, `mmap2`, `virtual_query_by_pid`), so either 14.10 dropped it or the tables number differently; it cannot be settled without a 14.10 image. Names above 676 are unverified on 14.10, but the 13.60 CSV thunks all resolve to real code for 677-694 and 700-734 (53 real, 695-699 nosys) — so the 14.10 kill range needs real-args probes (275a) before 'past-the-end' is accepted. See `docs/SYSENT_PRESENCE_14_10.md`.
- **No kernel pointers found** — extensive scanning has found none. AF_ROUTE retest 53b confirmed kernel sanitizes route messages (zero kernel pointers). kldstat/kldnext/kldsym terminate the caller under the default `SIGSYS` disposition and return -1 with `SIG_IGN` installed, so those slots are absent rather than hostile (56k4/56k5, 171a, 710a/711a). **KASLR defeated via fault oracle** (probes 1199a-1199c): kernel image location known per-boot, but no kernel data pointer has been leaked from any syscall or info-leak channel. See `docs/FAULT_CODE_ORACLE_14_10.md`.
- **ROP-shaped metadata role is unknown** — tested calls persisted after selected fn_addr and chain mutations; do not treat the fields as a function-call primitive

### Tested raw syscall behavior
The Lua loader's resolver filter blocks some syscall names. Selected calls still returned results through make_syscall(); this bypasses the Lua-side filter only for those tested calls, and kernel-side restrictions remain. The full dispatch implementation is unknown.

## How to Write Probes

### Probe Template
```lua
-- CRASH_CLASS: LOW | MODERATE | HIGH | RISKY
-- PROBE XX: one-line description
--
-- Context: what we know, what we're testing, why

print("=== PROBE XX: TITLE ===")
print("")

-- Standard helpers (ALWAYS include these)
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
```

### Lua 5.1 Constraints (MUST follow)
1. **uint64 for all addresses >32 bits:** `uint64(string.format("0x%X%08X", hi, lo))`
2. **pcall everything risky:** `pcall(function() return memory.read_qword(addr) end)`
3. **No `goto`/labels** — Lua 5.1 doesn't have them. Use `repeat...until true` + `break`
4. **XO pages kill past pcall** — reading execute-only memory terminates the process. Never read system lib .text sections. Eboot .text is RX and safe to read.
5. **Fresh ASLR every connection** — never hardcode addresses. Always re-derive from `dynlib_get_info` or `tostring(syscall.pipe)`.
6. **memory.alloc(N)** for heap buffers. Always zero them before use.
7. **Kernel pointer detection:** `h >= 0xFFFF8000` where `h, l = get_hi_lo(val)`. Values like `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF` are bitmasks/sentinels, NOT real kernel pointers.

### How make_syscall Works
```lua
local sc = make_syscall(202)  -- sysctl
local ret = sc(arg1, arg2, arg3, arg4, arg5, arg6)
-- Arguments are uint64 values
-- Returns: the syscall return value
```
Historical hypothesis only: the heap contains writable ROP-shaped metadata and argument slots. Probe 45c recorded tested calls continuing after selected mutations, so this does not establish that the loader calls fn_addr or executes the chain.

### Getting Key Addresses
```lua
-- Userland module-base discovery; this does not defeat kernel ASLR
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(handle), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

-- Historical metadata addresses; not established as execution controls
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

-- GPU mmap (heap R/W primitive)
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(512*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
```

### Sysctl Pattern
```lua
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 1)   -- KERN_PROC_PID
safe_wd(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
local ret = sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
    uint64(oldlenp), uint64(0), uint64(0))
```

## Repository Layout

```
probes/
  phase1_identity_layout/    # 01-08: system ID, syscalls, memory
  phase2_kernel_objects/     # 09-21: UMTX, nwake, dmem, AIO, kqueue
  phase3_signals_codexec/    # 22-26: signals, sigaltstack, W^X, XOM
  phase4_ipc_network/        # 27-31: threading, fd passing, sockets
  phase5_buffer_io/          # 32-33: buffer stress, MSG_DONTWAIT
  phase6_raw_packets/        # 34-39: RAW sockets, fragments, IP options
  phase7_heap_exploitation/  # 40-41: GPU mmap, heap R/W, ROP, ASLR bypass
  phase8_live_network/       # 40tcp, 42: TCP fuzz, ktimer, live testing
  phase9_kaslr_defeat/       # 42b-42j: KASLR attempts (mostly failed)
  phase10_untested_theories/ # 43a+: theory-driven probes (results recorded; 2026-10-17 audit)
  phase11_network_attacks/   # 48a-50d: SCTP, IPv6, TCP inject, exotic protocols
  phase12_kernel_analysis/   # 51a+: kernel dump sysent analysis, Sony syscall survey
  phase13_52batch/           # 52a+: Sony syscall survey 627-676 + 624 oracle (written, queued)
phase13_53batch/           # 53a-53d: evidence-audit retests (AIO, AF_ROUTE, kldstat, CClosure)
results/                     # Output logs (same phase structure)
tools/                       # send_probe.py, run_session40.py, tcp_fuzz_server.py
docs/
  ATTACK_SURFACE.md          # Complete syscall status map
  FINDINGS.md                # Detailed technical findings
  PROBE_INDEX.md             # Every probe with status and key result
  STRATEGY.md                # Exploit strategy and dead ends
  UNTESTED_THEORIES.md       # 17 theories ranked by priority
```

## Known Dead Ends (Don't Repeat These)

- **The /system_tmp sockets** — `GnmCompositorRestricted`, `VrTracker2DomainSock` and `AgcCompositorSppSocket` accept a connection from the game's jail; the other four refuse on a fresh boot. The compositor protocol is `{u32 size; u32 command; ...}` in a message of at least 0x30 bytes, one request per connection, answered by `{u32 type=1; u32 flags; u32 payload_len; u32 status; payload}` for commands 0-6 (`0x80FF` for 7+); command 1 is the only one without `0x80D40009`, and nothing in the header except its size and the command word changes a reply. **Writing 8 KiB to a compositor socket stops the daemon listening until the game restarts and blacks the screen** (a loader relaunch with no console reboot brings them back) — an unprivileged DoS, no crash address and nothing reclaimed (361b-362b). Library `.rodata` is `p=0x1` and a read at `libSceNpGameIntent.sprx 0x4E8000` kills the process, so the client cannot be found and the rest of the protocol cannot be recovered (374a-377a). See `docs/SYSTEM_SOCKETS_14_10.md`.
- **Module data is unreadable** — the 674 map shows module text `p=0x4`, `.rodata` `p=0x1`, writable data `p=0x3`. Only `p=0x3` and `p=0x5` (eboot text) can be read: a `.sprx` `p=0x1` region faults past `pcall` and takes the loader with it (377a). `memory.read_buffer` exists but does not change that.
- **GPU device mappings** — `SceGnmTrapCode`/`TrapData`/`AgcDdid`/`EopFifo`/`ShadowRegInfo`/`Cwsr`/`Misc`/`AcqRb` (`p=0x33`) and `SceGnmDriver` (`p=0x10`) are mapped in the game process, but reading any of them kills the process past `pcall` (376a, 380a), and the write path swallows faults, so a store to an unmapped address also reports success (381a). No store into GPU memory can be confirmed and the ring cannot be driven blind.

> Note (2026-10-17 evidence audit): entries marked inconclusive / "not established" reflect claim downgrades — see docs/EVIDENCE_AUDIT_2026-10-17.md.

- **sigaltstack kernel write** — copyout() validates destinations
- **mprotect(EXEC)** — always fails, hard W^X
- **XOM gadget scan** — reading XO pages crashes past pcall
- **Threading via resolve()** — fork/rfork/thr_new all -1. `thr_create(430)` via make_syscall starts a real thread once the gates and the `CS`/`RIP`/`RSP`/`SS` offsets are right (156c/156d); a zeroed ucontext still panics. See `docs/THREADING_ALIVE_14_10.md`.
- **AIO (sys 661)** — 661 is the shared `nosys` trampoline and dies by SIGSYS (353a). The batch submit is **669**, and it works: `669(cmd, reqs, count 1..128, class 1..3, ids)`, stride `0x28`, `cmd=1` read / `cmd=2` write, result word = bytes moved, destination range-checked but **count not clamped to buffer** (0x14000 into 4KB overwrites heap — self-corruption, not boundary break). 662/664/666 drive and reap requests (probes 352a-352k, 2026-10-22). Read the result word, not the return value: 669 returns `0` even when it queued nothing. See `docs/AIO_BATCH_14_10.md`.
- **kqueue** — fd allocates; kevent works with zero timeout (split and combined calls, probes 20/21), only the 100ms-timeout call returns -1 (probe 30c). See `docs/KEVENT_TIMEOUT_VARIABLE.md`.
- **ioctl via resolve()** — all blocked (untested via make_syscall)
- **sysctl kernel pointer leaks** — all scanned pointers are sentinels (0xFFFFFFFF_*)
- **TCP_INFO** — 236 bytes, no kernel pointers
- **minherit** — outcome unresolved: probe 38 ends at the minherit section header; no call result or termination cause recorded.
- **msync via syscall 226** — 226 is a nosys stub. Real msync is syscall 65 (PR #70, DEM9N101). Earlier probes called dead air. Probe 58a corrected and queued.
- **memfd_create** — stub, does nothing
- **/dev/dmem0** — opens but all operations fail (GPU partition only)
- **kenv** — outcome unverified: 42a/42g2 captures stop at the kenv header without a call result or kill record
- **TCB (FS base)** — userland only (0x88xxxxxxxx)
- **libkernel data segment scan** — no kernel pointers
- **kldstat at syscall 306** — 306 is `kldfind` (crashed on bad arg). Real FreeBSD `kldstat` is 308; sweep 02 had 367. Probe 43a tests both.
- **sysarch command confusion** — 129 is `SET_FSBASE` (calling with 0 crashes userland). Real `GET_GSBASE` is 130.
- **/dev/dmem0 physical memory** — GPU aperture only; phys 0 = GPU HW reg `0x80000000_C0012800`, 4GB+ unmapped/zeros. Retested 2026-10-21 with the working shape (`O_RDWR`, `PROT_READ`, `MAP_SHARED`): `dmem0` and `dmem1` both map and both read all-zero above offset 0, `dmem2` refuses every shape, and `PROT_READ|PROT_WRITE` is rejected unless the open used `O_RDWR` (probes 262a/263a).
- **pipe(42) via make_syscall** — returns fds 0,0 (dead)
- **ROP chain hijack / fn_addr redirect** — 45c observed tested calls returning normally after selected metadata mutations; no arbitrary function-call primitive is established and the full dispatch path is unknown
- **W^X bypass via mtypeprotect + fn_addr** — earlier code-execution claim is unsupported; mtypeprotect returns did not prove code-page execution, and 45c undermines the proposed dependency for tested calls
- **Shellcode execution via fn_addr** — proposed writes did not land and results do not establish shellcode execution; the evidence does not prove every path is incapable of executing code
- **AF_ROUTE KASLR (Relapse technique)** — **CONFIRMED DEAD**: retest 53b delivered RTM_GET (hdr=152, write ret=168), received valid 136-byte response (version=5, type=4, pid=112), but all payload is zeroed sockaddr structures — zero kernel pointers. Kernel sanitizes route messages on 14.10. (probes 43o, 53b retest 2026-10-18)
- **The whole `kld*` family plus `sysctlbyname`** — 307 (`kldnext`), 308 (`kldstat`), 337 (`kldsym`) and 570 (`sysctlbyname`) die on touch by raising SIGSYS from the shared `nosys` trampoline; with SIGSYS ignored they return `-1`, and 570's 13.60 body is that trampoline byte for byte (353a/353b). 308/307/337 also return `-1` for every shape tried, including `kld_file_stat` with version `0x81C`/`0x60`/`0x1C`, but have no 13.60 dossier. `docs/SYSCALL_ABSENT_VS_LETHAL.md`.
- **kinfo_proc kernel pointers** — full 1096B dump: only sentinels, no real kernel pointers.
- **kern.proc.filedesc/vmmap** — blocked (ret=-1)
- **sysctl operations (43f)** — the write labeled `kern.securelevel` returned -1. Reads labeled `kern.coredump`, `security.bsd.unprivileged_proc_debug` and `kern.maxproc` returned -1, so their conditional writes were not reached. `kern.somaxconn` read returned 0/value 1024; no write was attempted. See `results/43f_sysctl_write_20261016_180756.txt`; these labels follow the probe's assumed MIB mappings.
- **sysarch GET_GSBASE** — returns 0, no kernel pointer
- **ioctl via make_syscall** — the syscall works (FIOCLEX/FIONCLEX return 0 on every node, FIONBIO distinguishes `/dev/dce` from the simple devices), and the command space is now measured end to end: ~32 million calls over 31 nodes, every direction, the whole 14-bit length field. `/dev/dce` answers one inert 8-byte command (`0x80088209`); `/dev/gc` answers twenty-five struct-filling commands in group `0x81` (lengths 4-0x888) that write small constants and reject a null pointer. No command follows an address taken from the struct, none changes behaviour when the struct bytes change, and every write stays inside its declared length. One command, `0xC0048125`, blocks the calling thread forever (app renders, exit fails with a black screen). See `docs/DEVICE_IOCTL_14_10.md`; probes 273a-287a.
- **dup/dup2 via make_syscall** — returns -1
- **thr_new via make_syscall** — **WORKS**: `455(param, 0x38)` with a real `struct thr_param` returns 0 and starts a thread. `start_func(arg)` delivers arg in rdi. `mov [rdi],rax;ret` at eboot+0x92C67 confirmed write via child (marker changed from sentinel to rax=455). `param_size = 0x100` returns -1 (bounded). Simpler than thr_create(430): no ucontext gates. Thread budget 25/11/9 per loader (242a/244a/245a). (probes 383a, 56l)
- **kern.msgbuf** — returns only 8 bytes (filtered)
- **mincore KASLR oracle** — all kernel VA probes return -1
- **sockopt overflow** — kernel clamps copy length, not exploitable
- **/dev/hid ioctl** — Sony error 0x80740004 on all codes
- **Syscall 557** — saved 46a/47a tests show argument-dependent returns, including a linear version pattern for tested positive versions in 47a and a special version-zero result. No kernel pointer or exploit was demonstrated; full semantics and exploitability remain unresolved.
- **Syscall 620** — the saved 46a re-run returns 0 for its tested inputs; sentinel checks report no changes in their monitored windows. The zero-struct dump used the same incorrect baseline as 557 and is not write evidence. Full semantics remain unresolved; see `docs/SYSCALL_557_14_10_EVIDENCE.md`.
- **CClosure C function pointer redirect (pre-55g)** — retest 53d confirmed ALL 7 offsets (+0x00 through +0x30) are writable with successful restore. 55g records a boundary after the +0x20 write; 54r records target bytes. These do not identify the crash instruction or a successful 54q redirect. Later 56c/56f returned target-like results for selected existing Lua C targets; broader execution support remains unverified.
- **SCTP chunk fuzzing** — 39 variants via loopback raw socket, zero crashes (probe 48b)
- **IPv6 extension header fuzzing** — 83 variants, zero crashes (probe 48c)
- **TCP state machine injection** — 182 crafted segments into ESTABLISHED loopback connection (RST, SACK, PAWS, option parser len=0/255, URG, zero-window, ACK storm, SYN flood). The saved run reached COMPLETE. TCP_INFO values at +108/+112 tracked sequence numbers in that run; this does not establish TCP hardening or RFC compliance. (probe 49a)
- **IPv6 fragment reassembly attacks** — 280 fragments targeting ip6_reass() (overlapping/teardrop, queue exhaustion 50+101-bomb, huge totals 65535+, atomic frags, interleaving, ext hdr combos, nested frag-in-frag). The saved run reached COMPLETE; fragment-drop behavior and RFC 5722 compliance were not independently established. (probe 49b)
- **Exotic protocols (IGMP/GRE/ESP/AH/PIM/OSPF/VRRP)** — 86 packets, zero crashes (probe 50a)
- **Sony syscall info leak** — 11 accessible syscalls deep-tested with output buffers, no kernel pointers in any output (probes 51a, 51b)
- **Port binding ≥40000** — bind() returns -1 for ports ≥40000. Use 1024-32767 range.
- **sys 572 VM info query** — returns -1 for (addr, outbuf, size) layout; returns 0 but empty buffers for (outbuf, cmd, size) layout across cmds 0-5. No useful VM metadata extracted. (probes 54i, 2026-10-18)
- **sys 626 RDMSR precise (cmd=1 + cmd=4)** — cmd=1 returns -1 for all 16 PMC indices (MSR 0xC0010231+); cmds 1-6 all return -1 for idx=0; narg sensitivity 0-8 all -1. cmd=4 returns 0 but output is all zeros (counters not running). WRMSR (cmd=2) returns -1. No MSR data accessible. (probe 54a2, 2026-10-18)
- **sys 629 jail bypass** — all arg patterns (direct values, pointer-to-value for arg1/arg2) return -1. No fast path. Process crashed on kld* retests. (probe 54b, 2026-10-18)
- **sys 626 RDMSR** — returns -1 for all 11 MSR indices (TSC, APIC_BASE, SYSENTER_EIP, EFER, STAR, LSTAR, CSTAR, SFMASK, FS_BASE, GS_BASE, KERNEL_GS_BASE) across 3 arg layouts. Blocked on 14.10. (probes 54k, 2026-10-18)
- **sys 567 RDMSR read** — returns -1 for all MSR indices with both flat and struct arg layouts. (probe 54k, 2026-10-18)
- **sys 612** — returns -1 for all tested member values 0-8. (probe 54k, 2026-10-18)
- **sys 598 dynlib context** — returns -1 for all arg patterns tested. (probe 54f section A, 2026-10-18)
- **sys 639/638 memory region** — returns -1 for all address ranges including zero, low, heap, module, libkernel, and kernel VA. (probe 54f section C, 2026-10-18)
- **net.route.iflistl kernel pointer scan** — returned 6536 bytes but all values are sockaddr/MAC/interface structures, no kernel pointers. (probe 54f section D, 2026-10-18)
- **sys 593 deep struct scan (+0x148/+0x150)** — values across all 39 modules are NID hashes/fingerprints (random high bits but not in kernel VA range 0xFFFF8xxx), not kernel pointers. (probe 54f section F, 2026-10-18)
- **sys 643 chicken switches** — all 32 bits accepted (ret=0 for each), 0xFFFFFFFF OR'd into process+0xa34. No observable effect: mprotect(RWX) still fails, fork still blocked, kldstat still blocked. Field does not control W^X, sandbox, or syscall filtering. (probe 55a, 2026-10-18)
- **sys 588 DMEM page attribute modify** — returns 0 with prot=RWX on GPU mmap pages but sys 547 shows protection UNCHANGED (still 0x3 = RW). Executing shellcode on the "modified" page kills the process. The handler accepts the call but the hypervisor enforces W^X below the kernel — the PTE never gets the execute bit. All kernel-level permission handlers are dead for code execution. (probes 54d, 124a, 2026-10-22)
- **sys 637 set_phys_fmem_limit** — writes caller-chosen qword to `child+0x280` (physical memory limit) with no capability check for self (pid=0), but the field is fixed (not a general write), foreign PIDs require bit 62 (blocked), and values below current physical memory usage block the kernel thread irrecoverably (value=17 caused PS5 hard hang requiring power cable disconnect). Not exploitable. (probe 123a, 2026-10-22)
- **physhm (sys 629) mmap** — fd opens, mmap "succeeds" (returns VA), but pages aren't backed — no PTEs installed. Reading the mapped VA kills past pcall. All arg/offset/length/prot combinations produce the same result. (probes 122a-122a4, 2026-10-22)
- **msync(MS_INVALIDATE) CVE-2026-49418** — **CONFIRMED DEAD**: msync(65) with MS_INVALIDATE returns -1 on ALL mapping types: anonymous GPU (fd=-1), /dev/dmem0 device fd, /dev/dmem1 device fd, /dev/zero fd. MS_SYNC and MS_ASYNC return 0 on the same mappings. The kernel rejects MS_INVALIDATE before reaching the vulnerable vm_object_page_remove() in the device pager. (probes 58a/58b, 2026-10-22)
- **CVE-2026-49412 IPV6_MSFILTER UAF** — **CONFIRMED DEAD**: Sony removed the entire RFC 3678 multicast source filtering API. `setsockopt` works for standard IPv6 options (4/10/11/27 all ret=0), but `IPV6_MSFILTER(74)`, `MCAST_MSFILTER(72)`, `MCAST_JOIN_GROUP(42)`, `MCAST_BLOCK_SOURCE(43)` all return -1. `getsockopt(74)` also returns -1. UDPv6 socket creation and `IPV6_JOIN_GROUP(12)` work fine, so the rejection is option-specific. All sizes (4-512) rejected uniformly. The vulnerable `in6p_set_source_filters()` path is unreachable. (probes 50e2/50e3, 2026-10-22)
- **CVE-2026-45257 KTLS page-cache overwrite** — **DEAD**: Sony did not include KTLS. `TCP_TXTLS_ENABLE(0x21)`, `TCP_TXTLS_MODE(0x22)`, `TCP_RXTLS_ENABLE(0x23)`, `TCP_RXTLS_MODE(0x24)` all return -1 (both set and get). `SOL_TLS=282` also -1. Standard TCP options work (NODELAY, MAXSEG, NOOPT, NOPUSH all ret=0). sendfile(393) returns -1 but this may be due to invalid args rather than absence. (probe 50f, 2026-10-22)
- **sys 548 batch VM ops** — all operation codes (0=new mapping, 2=protection update, 3=anonymous mapping) return ret=-1, processed=0. Different code path from mprotect but equally blocked. W^X not bypassable via this route. (probe 55b, 2026-10-18)
- **sys 622 device control multiplexer** — the 2026-10-18 reading ("every command returns 0x800E0001, no device context") came from passing the arguments in the wrong slots. The 13.60 handler reads `arg0 cmd, arg1 sub, arg2 user buffer, arg3 secondary user address, arg4 size <= 0x40, arg5 extra`, and with that layout the size gate and the credential predicate are separately visible: size `0x41` returns `0x800E0001`, size `0x40` returns `0x8002004E`. The 113 commands in `0x200-0x270` and `0x813` then execute past the auth gate and return `0` with `0xFFFFFFFF` written to the buffer, which is a not-found answer, not data. The `0x400-0x493` group returns `-1` when the `copyin` from `arg3` fails and kills the process whenever that copy succeeds - at any size, including 1, and including size 0 with a null pointer - so the fault is in the code after the copy and is independent of the copied bytes. Nothing in 622 produced a kernel pointer, an overrun, or a write primitive. (probes 241a-247a, 2026-10-21; `docs/SYSCALL_CONTRACTS_13_60.md`)
- **sys 601 process control multiplexer** — a debugger service with no session. cmd 0x00 ret=0 and writes 0x100; 0x01/0x02/0x05/0x06/0x0a/0x12/0x10 return -1; 0x07/0x09/0x0d/0x13/0x14/0x19 return 0 and write nothing; **0x03 and 0x04 terminate the process** (probes 322a-324a, 2026-10-22; 55d on 2026-10-18 never called 0x02-0x04). The dossier's leak commands are gated, so this is not a leak surface.
- **sys 674 VM map kernel pointer search** — 317 regions enumerated with full 72-byte records. All addresses are userland VA (max 0xF_E0400000). Zero kernel pointers found at any offset. Record layout decoded: +0x00 start addr, +0x08 end addr, +0x18 protection, +0x20 name string. GPU/device regions at 0x8-0xF range are userland device-mapped memory. (probes 55e/55f, 2026-10-18)
- **sys 672 dynlinker library list** — ret=-1 (predicate gate failed). Dead. (probe 55e, 2026-10-18)
- **sys 676 CPU mode update** — ret=-1 (process+0xc81 gate). Dead. (probe 55e, 2026-10-18)
- **sys 673 page remap** — ret=-1. GPU mmap backing object isn't type 11 required by the handler. (probe 55e, 2026-10-18)
- **sys 675 reset global state** — ret=0, resets 3 globals. mprotect(RWX) still fails after reset. Does not control W^X. (probe 55e, 2026-10-18)
- **sys 587 credential metadata** — ret=0, returns 0x88 bytes. Only +0x0C = 0x20000000 (single capability bit). No kernel pointers. (probe 55e, 2026-10-18)
- **sys 671 resource class query** — sel=-1 mode=1: A=6144, B=3948. mode=2: A=2560, B=2014. Explicit selectors 0-10 all failed (needs credential bit 62). Memory budget values only. (probe 55e, 2026-10-18)
- **sys 631** — kills the caller immediately on 14.10 under the default disposition. Not retested with `SIG_IGN` installed, so this is a death, not proof the slot is absent. (probe 52a, 2026-10-18; see `docs/SYSCALL_ABSENT_VS_LETHAL.md`)
- **sys 627-630** — 627-629 return PCALL-FAIL (exception/crash caught by pcall). 630 returns -1 for every tested shape: zeros, sentinels 1-10, path strings ("/", "/dev", "/app0", "/system", "/data"), struct pointers with cmds 0-10. The mount handler exists but is credential-gated. (probes 52a, 122b2, 2026-10-22)
- **sys 662 AIO batch delete** — returns 0 but every ID gets status 0x80020003 (unknown). No AIO jobs can be created (661 kills), so the pointer leak path is unreachable. count>=129 returns -1 on 14.10 (stack clash guard tightened from 13.60). sys 670 AIO init works (ret=0) but is useless without 661. (probe 125a, 2026-10-22)
- **sys 677** — kills the caller AND the game (the loader stops accepting connections). Recorded as a death, not as proof the slot is absent; a call that faults on its arguments dies the same way. (syscall_isolation_sweep, 2026-10-20)
- **sys 678** — same behavior as 677, including the game crash. (syscall_isolation_sweep, 2026-10-20)
- **physhm_open (629) gives a descriptor but no usable memory** — `629(1, 2, any, 0..3)` returns a descriptor, and `mmap(..., MAP_SHARED, fd, 0)` succeeds, but the first read at the returned address kills the process even inside `pcall` (probes 315a/316a/318a/321a), and `read`, `write`, `FIODTYPE`, `FIONBIO` and `628 mmap_dmem` all refuse the descriptor. The path branch is closed: every path form and every `/dev/physhm*` open returns `-1`, so only the sentinel branch is reachable. See `docs/ATTACK_SURFACE.md`.
- **UMTX_OP_SHM (op 25 on syscall 454)** — **CONFIRMED STUB**: all sub-ops (create=1, destroy=4, alive=8) return 0 for any valid mapped address, -1 for unmapped addresses. Invalid sub-ops (0, 16) also return 0. Zero VM ops (sys 624 delta=0). alive() returns 0 even for never-created keys. No fd allocation, no vm_object creation, no slab allocation. Sony stubbed out the SHM subsystem. **CVE-2024-43102 is NOT exploitable** on 14.10 — the vulnerable umtx_shm_create_reg/unref_reg race path is unreachable. (probes 151a–152k, 2026-10-20)
- **Object handles are predictable and generation-checked** (435a-445a, 2026-10-23): all families share one table, ids are `generation << 13 | slot`, reuse is LIFO and exact, and a stale id resolves to nothing. Second release of a handle returns `-1`; names past `0x20` are refused, not truncated. Placement can be predicted, the kernel address cannot. See `docs/OBJECT_TABLE_14_10.md`.
- **fstat(189) via make_syscall** — **retracted**: 189 is present. `fstat(fd, buf)` on an open `/app0/eboot.bin` descriptor returns `0` and writes a stat record with the default signal disposition, and `189(0,0,0,0,0,0)` returns `-1` and the process survives (353c/353d). The 152j kill was not this call.
- **Ignore SIGSYS before probing a possibly-absent slot** — the `nosys` trampoline raises signal 12, whose default action terminates, so a serial probe destroys its own result. `sigaction(12, SIG_IGN)` is syscall 416 with handler 1; after it, absent slots return `-1` instead of dying (353a/353b). Real handlers that fault still kill (601 commands 3/4), so a kill under `SIG_IGN` now means fault, not absence.
- **The `-1` column in `docs/SYSENT_PRESENCE_14_10.md` is not a verdict** (334a-342a, 2026-10-22): a six-zero sweep cannot tell "handler rejected this call" from "no handler". Called with real pointers, 538/540/557 (evf and namedobj creation, registry lookup), 598/659 (dynlib copy-out) and 572 all answer. Every `-1` row is an untested contract, the same way 622, 532 and 654 were.
- **637 `set_phys_fmem_limit` writes a caller-chosen qword into a kernel object** with no capability check when the target id is 0: the value lands at `parent+0x200 -> child+0x280`. Foreign ids are refused. It also blocks the caller when the value is below current physical memory usage (`637(0,17)` never returns), so a small value and six zeros both look like `-1`. (probes 339a/340a)
- **Named evf/namedobj objects do not outlive their process** (342a): 538 with attribute `0x100` registers a name and 540 resolves it in-process, but after a relaunch every registered name returns `-1`. No cross-process handle.
- **573 `mdbg_call` is the nosys trampoline and kills the process**; it powered the console off once during 334a and did not reproduce in a fresh process (337a). Do not include it in sweeps - `docs/SYSENT_PRESENCE_14_10.md` already marked it a kill row.
- **netcontrol(99) netevent queue UAF** — **CONFIRMED DEAD on 14.10**: register takes a socket reference; close-before-unregister leaks it instead of freeing. No double-free, no dangling pointer. The public Poops/ExploitNetControlImpl chain's precondition (close frees socket while registered) does not hold. ifindex -1 queue is permanently wedged. (probes 223a–234a, PR #69 ng643, 2026-10-21)
- **jitshm (533 `jitshm_create`, 534 `jitshm_alias`)** — `533` returns -1 for sizes `0`, `0x1000`, `0x4000`, `0x100000` and flags `0`, `1`, `0xFFFFFFFF`, so no descriptor exists to alias; `534` returns -1 for a socket fd and for fd `0xFFFF`. `535 dl_get_list` and `536 dl_get_info` return -1 with a zeroed struct carrying only its size at `+0` and write nothing. (probe 251a, 2026-10-21)
- **osem (549-556)** — `549 osem_create` returns -1 for eight scalar shapes (`0`, `1`, `2`, `0x10`, `(0,0)`, `(1,0)`, `(0,1)`, `(0x10,0,0)`) and for a NUL-terminated name pointer in either slot, so the family is unreachable and its wait/post/cancel calls were never exercised. (probes 252a, 253a, 2026-10-21)
- **namedobj (557 `namedobj_create`, 558 `namedobj_delete`)** — `557(name)` returns a handle, but four calls on the *same* name return four distinct objects (`0x208`-`0x20B`), so the name is not a key and no lookup exists to aim at a freed object. `558` frees by handle (`0`), reissues the index (`0x220B`), and returns -1 for `0xDEAD` and `0`. (probe 254a, 2026-10-21)
- **559 `set_vm_container`** — returns -1 for ids `0`-`8`, `0xF`, `0x100`, `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFE` and `0x100000000`; only `0xFFFFFFFF` returns `1` (the current container), and it changes nothing: mappings made before and after keep identical `547` records and mmap keeps allocating in the same region. (probes 255a/256a, 2026-10-21)
- **560 `debug_init`** — `560(1)` returns `0` where `0`, `0x10`, `(0,0x10)` and `(0x1000,0x1000)` return -1, and it opens nothing: `656`, `593` mode 1, `634`, `mprotect` to RX and to RWX and `643` all answer exactly as they did before it. (probes 257a/258a, 2026-10-21)
- **561 `suspend_process`** — kills the process at touch (`561(0)`), so `562 resume_process` was never reached. (probe 257a, 2026-10-21)
- **thr_get_ucontext(634)** — writes nothing for any arg shape even with alive child TID. (PR #71 ng643, 2026-10-21)
- **blockpool_batch(657)** — returns status dword 0 only; still writes after close(h) but the write is worthless. (PR #71 ng643, 2026-10-21)
- **query_memory_protection(547)** — userland-only VM lookup. All 32 kernel addresses return -1. No KASLR oracle. (PR #71 ng643, 2026-10-21)
- **Device ioctl sweep (34 open /dev nodes)** — ioctl(54) reaches all 34 drivers but every command (0x00-0xFF with buffer, TIOCGETA, FIONBIO on dce) returns -1. Command encoding is not small integers; needs driver table from kernel image. (PR #74 ng643, 2026-10-21)
- **The GPU pool zeroes pages on allocation** — a dense scan of one complete 64 MiB chunk (8 388 608 qwords) and 49 152 samples across the 384 MiB a fresh process can map found zero nonzero words, zero kernel-shaped values and zero strings. The uninitialised-page KASLR leak is dead on 14.10, and the pool is never returned within a process (probe 348a, 2026-10-22).
- **sys 637's store is inert** — the value lands at `child+0x280` and the call returns 0, but mapping three chunks, storing `0xFFFFFFFF` and mapping again reaches the same six-chunk GPU ceiling. Any earlier reading that attributed a ceiling change to the store was the pool already being consumed (probe 346b, 2026-10-22).
- **AIO(661) with real fd** — `/dev/zero` fd + full aiocb struct still kills. Third argument shape to die there. Dead. (probe 266a, PR #74, 2026-10-21)
- **UMTX ops 18-21 (high ops)** — all block unreadably; sentinel words untouched, blocked and returned threads indistinguishable. op 19 wrote 0x1 non-deterministically in one run. (probes 269a/270a, PR #74, 2026-10-21)
- **WebKit popup isolation** — all popup methods (STATIC/BLANK/about:blank) kill WebProcess. Crash corpus must run inside single document. (PR #75 ng643, 2026-10-21)
- **Object lifetimes hold at native speed** — seven races with native children on both sides (AIO submit/cancel, submit/delete, submit/poll/delete on one id slot, fstat vs close, kevent vs close, 500 close/open cycles, semaphore open vs create/delete) are all clean on 14.10; the descriptor number is provably reused and the objects stay usable (probes 410a-422b, 2026-10-22).
- **Sys 532 handle forgery** — the decode is reachable with `532(cmd, 0, out, inp, size, 0)` and the checksum `byte[3]+byte[0]+byte[1]+byte[2]+byte[5]*byte[4]`, but bytes 0-3 change nothing and the registration table is empty for a game process, so every forged handle answers `0x800D0203` (probes 429a-433a, 2026-10-22).
- **NET_RT_DUMP kernel pointer search** — 4968 bytes, 17 routing messages. 5 values matched kernel pointer pattern (`0xFFFF8xxx+`) at non-aligned offsets. Full hexdump (56e2) proved ALL are false positives: sockaddr boundary crossings where netmask `FF FF FF` bytes combine with adjacent sockaddr `sa_len`/`sa_family` fields. Padding after sockaddr_in6 is `0xFF` (not zeroed) but contains no real kernel addresses. RTM_GET is deterministic (10 calls, zero varying bytes). (probes 56e/56e2, 2026-10-23)
- **CVE-2026-3038 sa_len=127 routing socket overflow** — sa_len=127 write accepted (279 bytes), kernel returned normal 272-byte response without panic. Either Sony patched the `rtsock_msg_buffer()` validation (build Sep 2026, fix Feb 2026) or the overflow doesn't reach the stack canary for this code path. (probe 56e section F, 2026-10-23)
- **CClosure deep Lua stack read** — rax=0,1,6,7,8 gadgets found in eboot (no rax=2,3,4,5 in 1.5MB scan). rax=N redirected rawequal reads N values from Lua stack: args, function objects, caller local variables. rax=8 with 0 args reads caller's `nret` and `args_str` locals. ALL values are userland heap objects (0x310xxxxxxx) or eboot pointers (0x532xxxxxxx). Zero kernel pointers in the Lua stack. (probes 56d5-56d7, 2026-10-23)
- **sys 624 side channel** — madvise distinguishes user/kernel (delta=1 vs 0) but ALL kernel addresses give identical delta. No intra-kernel discrimination. mincore/547/674/msync: delta=0 always. (probe 56f, 2026-10-23)
- **Sysctl deep scan** — zero kernel pointers across ALL accessible CTL_* subtrees (kern/vm/net/hw/machdep/debug/proc). Only hw.model (48B) and kinfo_proc (1096B) return data. kern.proc.auxv not available. (probe 56g3, 2026-10-23)
- **Timing KASLR via mprotect** — batch timing (2000 calls × 5 rounds) showed peaks that move between runs — scheduling noise, not signal. mprotect on kernel addrs returns 0 immediately (early return, no page table walk). No clean `rdtsc; ret` gadget in eboot. clock_gettime overhead (~90μs) drowns sub-microsecond signals. (probes 56h-56i2, 2026-10-23)
- **ioctl over-copy scan (/dev/gc, /dev/dce)** — all 23 data-returning `/dev/gc` group 0x81 commands and `/dev/dce` command `0x80088209` tested with 4KB sentinel-filled buffers. Zero bytes modified past declared length. Zero kernel pointers anywhere. The Praetorian ioctl is not in these two devices. (probe 56m, 2026-10-23)
- **Thread ucontext kernel pointer scan** — sys 634 copies 0x4c0 bytes of a suspended child's registers. All 304 dwords scanned. Only userland addresses: eboot pointers, heap, stack. `0xFFFFFFFF` at `+0xA0` is the `-1` sentinel. Zero real kernel pointers. Confirms register layout (RDI=arg at +0x48, RIP at +0xE0). (probe 56n, 2026-10-23)
- **getsockopt kernel pointer scan** — SOL_SOCKET (SO_TYPE/ERROR/SNDBUF/RCVBUF/LINGER/PEERLABEL/LISTENQ*), IPPROTO_TCP (NODELAY/MAXSEG/INFO/CONGESTION/CCALGOOPT/KEEP*/FUNCTION_BLK), LOCAL_PEERCRED. Only SO_LINGER(8B), TCP_INFO(236B), TCP_CONGESTION(8B) returned data. Zero kernel pointers, zero over-copy. (probe 56n, 2026-10-23)
- **Unix socket SCM_CREDS credential leak** — `socketpair(AF_UNIX)` + `LOCAL_CREDS` setsockopt + sendmsg/recvmsg. Kernel attaches 40-byte `cmsgcred` (level=0xFFFF/SCM_CREDS=3): pid=0, uid=1, euid=1, gid=1, ngroups=1, groups[0]=1. All small integers, zero kernel pointers in data or padding. No uninitialized kernel stack leak via cmsg. (probe 56o, 2026-10-23)
- **sigaction struct kernel pointer scan** — read old disposition for signals 1,2,10,12,14,17,20,30,31 via sigaction(416). All handler addresses are userland (0x73ECxxxx) or SIG_DFL(0). Signal mask fields are bitmasks (0xFFFEFEFF, 0xFFFFFFFF). No kernel pointers. (probe 56o section B, 2026-10-23)
- **fstat deep scan + overcopy check** — fstat(189) on eboot.bin: standard 120-byte stat struct (dev=0x17, mode=0x816D, size=0x63192E, timestamps). Sentinel-filled 512-byte buffer — zero bytes modified past 120B. No overcopy, no kernel pointers. (probe 56o section C, 2026-10-23)
- **getdirentries kernel pointer scan** — getdirentries(272) on /app0: 232 bytes of standard 32-bit dirent records (`.`, `..`, `movie`, etc). All inode numbers small (2-5). Zero kernel pointers in data or trailing padding. (probe 56o section D, 2026-10-23)
- **getrusage padding scan** — getrusage(117) for RUSAGE_SELF and RUSAGE_THREAD. FreeBSD struct is 144 bytes (not 128) — the +0x80..+0x8C "overcopy" is actually `ru_ixrss`/`ru_idrss` fields. All values are resource counters. Zero kernel pointers. No actual overcopy past 144B. (probe 56p section A, 2026-10-23)
- **SO_TIMESTAMP / SO_BINTIME ancillary data** — UDP loopback with both `SO_TIMESTAMP(0x400)` and `SO_BINTIME(0x2000)` enabled. Kernel attached two 32-byte cmsgs: SCM_BINTIME (sec+frac) and SCM_TIMESTAMP (timeval). All fields are valid timestamps, frac bytes are precise binary fraction. Zero kernel pointers. (probe 56p section B, 2026-10-23)
- **procctl(544) output scan** — all 7 status commands (REAP_STATUS, TRAPCAP, ASLR, STACKGAP, NO_NEW_PRIVS, WXMAP, PDEATHSIG) return -1 with zero bytes written. Completely blocked for game process. (probe 56p section C, 2026-10-23)
- **getrlimit overcopy + kptr scan** — 12 resource types tested. Non-infinite limits: MEMLOCK=32GiB, SBSIZE=2MiB, NOFILE=1604, NPROC=13952. Zero overcopy past 16-byte struct rlimit. Zero kernel pointers. (probe 56p section D, 2026-10-23)
- **kevent output scan** — kqueue(362) + kevent(363) with EVFILT_READ on socket and EVFILT_TIMER. Both return 0 events with zero timeout. No data written to output buffer. (probe 56q section A, 2026-10-23)
- **SCM_RIGHTS fd passing** — unix socketpair sendmsg with SCM_RIGHTS succeeds (ret=4) but recvmsg returns controllen=0: kernel strips fd-passing ancillary data in the game jail. No cmsg to scan. (probe 56q section B, 2026-10-23)
- **sendfile error path data leak** — sendfile(393) returns -1 on unconnected TCP socket. sbytes output pointer left completely unmodified (sentinel intact). No partial write, no kernel stack data leak on error. (probe 56q section C, 2026-10-23)
- **poll output overcopy** — poll(209) on UDP socket with zero timeout. revents=0, zero bytes modified past 8-byte pollfd struct. (probe 56q section D, 2026-10-23)
- **Signal delivery frame (sendsig) kernel stack residue** — sigframe is 2128 bytes (0x850), 486 modified dwords, all zeros and userland addresses. sendsig() zero-initializes the frame. No kernel pointers in padding. (probe 56r, 2026-10-23)
- **Eboot syscall instruction scan** — full 4.6MB .text scanned for 0F 05. 18 hits, all in data/immediates, zero followed by C3 (ret). No `syscall;ret` gadget exists in eboot. However, child threads CAN make kernel calls via ROP using `fn_addr` (the libkernel syscall stub) directly — close(fd) confirmed (probe 271g). The 56s conclusion about "no child syscall capability" is superseded. (probe 56s, 2026-10-23)
- **Kqueue race condition (ZDI-26-784)** — exhaustive testing with child thread concurrent close via ROP across 4 race variants: empty-socket close (200 races), data-bearing socket close (5000), EV_ONESHOT close (5000), close-kqueue-fd (50), timer+close-kqueue (100), socket+timer combo (100). >10,000 total race attempts, 0 anomalies, 0 kernel pointer leaks. Kernel kqueue locking is solid on PS5 14.10. Child thread closes fd before kevent accesses it — knote detached cleanly. (probes 271g/271h/271i, 2026-10-23)

## Sending Probes

```bash
# Via Python (if installed):
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua

# Via native PowerShell (no Python required):
.\tools\send_probe.ps1 probes\<phase>\<name>.lua -Save

# For TCP connect-back fuzzing:
python tools/run_session40.py --ps5-ip YOUR_PS5_IP --fake-ip YOUR_TEST_HOST_IP
```

Results are saved to `results/<phase>/<name>_<timestamp>.txt`.

## Current Attack Priority (Updated 2026-11-04 — Null-spray test: 80B spray unnecessary, freed memory benign)

**SOLE ACTIVE VECTOR: WebKit FontFace UAF** — CSSFontFace freed by cascade rebuild inside `.then` trap; 192B `ArrayBuffer` spray reclaims the slot with 100% reliability (20+ landings, always lanes 32-39). Engine writes into attacker-owned bytes; the `addClient` insertion destination is controlled via the forged `+0x58` table pointer (an 8-byte value we type), but **the chunk's own address is not known to JS** — the primitive needs a target VA (ng643 framing correction, issue #181). This is a **write primitive first** — the walk (virtual dispatch through forged vtable) is the second half. WebKit 605.1.15 / Safari 17.0 confirmed on PS5 14.10 (p573). All three upstream FontFace UAF fixes (commits 312202, 313577, 322233) were committed in 2026, ~3 years after the 605.1.15 branch point — **PS5 14.10 is vulnerable**. WebProcess restarts on every navigation, so everything must be **single-shot, single-page** (p584). ng643 independently reproduced the UAF on their 14.10 bench (8/14 landings, guide WebKit 616.1.27.211.1).

**Measured on 14.10 (device-confirmed):**
- Reclaim: `m_refCount` goes 0→1, live `WeakPtrImpl*` appears at `+0x68` — engine's own write at CSSFontFace.cpp:526 (p580/p581)
- Status-byte discriminator: seeded `m_status=3` survives the walk — confirms UAF, not reconstruction
- `addClient` writes fresh `WeakPtrImpl*` into forged bucket at `T+0`, increments `keyCount` at `T-0xC` — `kc 0→1` is the no-crash oracle
- CSSFontFace has NO vtable pointer at +0x00 (p567) — refcount at +0x00, no 8B shift
- Engine writes only 4 fields into the reclaimed buffer, all others stay as sprayed (p581)
- HashTable is NOT inline — `+0x58 = m_table` (pointer to lazily-allocated impl), metadata as negative-index prefix: `deletedCount(T-0x10), keyCount(T-0x0C), tableSizeMask(T-0x08), tableSize(T-0x04)`. Fresh table = 80B (16B metadata + 8×8B buckets)
- Neighbors clean, re-trigger dead — second `fonts.load()` does not touch the reclaimed buffer (p583)
- **`backing()` null gates ALL JS APIs** (v6/v7, 2026-11-03): zeros at +0x08..+0x50 survive `face.style = "italic"` — the setter never reaches CSSFontFace::setStyle because the FontFace wrapper's `backing()` WeakPtr is null after the UAF. `load()`, `add()`, `style` all gate identically. The mutableProperties() dereference at :265, slope check at :268, and fontPropertyChanged at :273-275 are ALL unreachable from JS.
- **FontFaceSet paths gate on set membership** (p589, 2026-11-03): BETA_GATE confirmed. After trap, FontFaceSet.size=0, forEach=empty. `document.fonts.load('sa')` resolves with 0 faces, `document.fonts.load('pa')` with re-added gPa resolves with 1 face (gPa only), `forEach` sees only gPa, `ready` resolves OK — all four triggers leave +0x58=DEAD, +0x85=0xAA, rc=3 untouched. The freed CSSFontFace is not reachable from FontFaceSet.cpp:101/:189/:206 or FontFace::adopt :325-330.
- **The walk (iterateClients) is UNREACHABLE from any known JS path**: setStatus() does not run during continuation (v8b: +0x82 stayed 0), property setters gate on backing() null (v6/v7), FontFaceSet methods gate on set membership (p589: set is empty). The only controllable writes are from the trap continuation: rc increment at +0x00, T (HashTable*) at +0x58, W (FontFace*) at +0x68, m_mayBePurged=0x00 at +0x85.
- **GC destructor path CONFIRMED (p599 v1/v2/v4a, 2026-11-04)**: GC collects JSFontFace wrapper → `~FontFace()` → `removeClient(*this)` reads m_table from +0x58 → `deref()` decrements rc at +0x00. DEAD at +0x58 crashes 4/4; valid T survives rc 3→2; NULL survives rc 3→2 (removeClient skips null). This is a C++ path reachable WITHOUT JS intervention — the GC runs as a background task during allocation pressure.
- **Complete CSSFontFace memory map (p599 v4b)**: engine writes ONLY +0x00(rc=3), +0x58(T), +0x68(W), +0x85(0x00). All other 172 of 192 bytes remain spray-controlled. NO inline hash table data in the buffer.
- **B ≠ T - 0x60 for 192B spray (p599 v4c/v4d, 2026-11-04)**: the P588b formula `B = T - 0x60` applies to the 80B size class (wrapper block + table block consecutive), NOT to the 192B ArrayBuffer spray. The 192B and 80B allocations are in different bmalloc heap regions. Forging the table requires knowing the spray buffer's absolute VA, which cannot be computed from T. v4c (T-0x20 with zeros) and v4d (T-0x20 with valid metadata dc=0/kc=0/mask=7/size=8) BOTH crash identically — the address is outside the spray buffer.
- **★ Two-phase UAF with forged table SURVIVED (p599 v4f run 3, 2026-11-04)**: Phase 1 UAF reads T1, nulls +0x58, GC1 frees wrapper (80B at T1-0x60), sprays 4096×80B with forged table (dc=0/kc=0/mask=7/size=8, empty buckets). Phase 2 UAF redirects +0x58 to T1-0x50 (forged bucket start). GC2 → removeClient reads empty table → skip → deref() → rc 3→2 → ALIVE. T1=0x10001cb9e0, forge=0x10001cb990. Reliability: 1/3 completed redirects survived (33%); crashes when T1 is in a non-"low" region (0x1000b4xxxx). The formula B=T-0x60 IS correct for the 80B class when bmalloc LIFO aligns. **SUPERSEDED by v4i null-spray test** — the 80B spray is unnecessary and actively harmful (v4f crashed 1/3, v4i 0/7).
- **★ Null-spray test: 80B spray UNNECESSARY (p599 v4i, 2026-11-04)**: two-phase UAF redirect survives WITHOUT any 80B spray — freed bmalloc memory at T1-0x60 is benign (all zeros = empty hash table: mask=0, size=0 → 1-slot table, slot[0]=0 → empty). removeClient reads zeros, finds nothing, returns safely. 7/7 runs survived = **100% reliability** on completed redirects (vs 33% with 80B spray). The 80B spray was actively harmful.
- **★ Two-phase forge write CONFIRMED (p656, 2026-11-05)**: Phase 2 UAF redirects +0x58 to T1 (Phase 1 hash table address). Beacon-observed (n=1): forged +0x58 retained == T1, W2 nonzero, rc seed+1 — pins the adopt path (retained +0x58 refutes the fresh-face `create()` writer). The T1-block write itself (WeakPtrImpl* into target bucket, kc increment) is source-inferred, not beacon-observed. The write is BLIND (needs target address to be useful) but the forge mechanism works. Upgrade lane: reclaim T1's 80B block and read T+0x08 == W2 (pre-registered discriminator). (probe p656; graded per cobrajet302gt review, PR #236)
- **★ rc=2 is PERMANENT (p599 v4i, 2026-11-04)**: engine calls ref() once (seed 2→3) during continuation, GC2 calls deref() once (3→2). Net zero engine refs. rc=2 = spray seed. fonts.clear() + heavy GC does NOT trigger additional deref() through 11 seconds of polling. The destructor is **UNREACHABLE through normal refcount mechanics** — nobody will call deref() again.
- **★ W2 ≠ T2-0x60 (p599 v4i, 2026-11-04)**: W2 (WeakPtrImpl* at +0x68) is ~5.2-5.3 MB from T2. WeakPtrImpl is ~16B class, hash table is 80B class — completely different bmalloc regions. This explains v4h's NO-BUCKET-CHANGE: the bucket-match probe was checking the wrong address.
- **+0x85 = `m_mayBePurged`** (cobrajet, issue #181): `initializeWrapper()` at CSSFontFace.cpp:515 is the only false-writer. Seed 0xAA → read 0x00 = wrapper path ran. The status-byte discriminator (+0x82) is VOID: the wrapper route never calls setStatus(), so the seed returns unchanged regardless.
- **Field poisoning map** (ng643 independent bench): `+0x18`/`+0x20`/`+0x50` survive poisoning (engine write still lands). `+0x28`–`+0x48` are **followed/dereferenced** — kill even with valid heap pointer; forged face must carry sane values across that range. `+0x68` non-null must be valid `WeakPtrImpl*` (source: `WeakPtr::get()` reads `m_impl->get<T>()`, `operator bool` reads `m_ptr`). `+0x58` = 1 kills (table pointer must be valid or null).
- **Lattice law for `+0x58`** (ng643, 18 landings): table pointer oscillates in an 8-value family (n=0…6 with two `+0x50` in-span offsets) on `0x4000` stride, non-monotonic with repeats. NOT constant load-to-load. Load-1 of a fresh process is byte-constant (`0x10001cb0d0`, 16/16 cold boots on cobrajet bench); subsequent loads drift across lattice set. α/β/γ protocol: α = first landing after kill is byte-constant (bake lives); β = lands in family but never collapses (bake dead, engine-named destination needed); γ = landing outside known lattice (law doesn't port). β confirmed at n=14 (ng643). Dominant value appears ~70% of series. Bake dominant = 47-70% success as retry oracle; bake beats leak-chain ~2.5:1. **T-stability is era-dependent**: 14.00 bench reports same T across 4+ warm reloads (100% chain); 14.10 lattice drifts. Lattice is era-portable; T-stability is not.
- **dynlib_get_info(593) is loader-process only** — returns bases for the Lua loader, a different address space from WebProcess. Cannot derive WebProcess VA from it.

**Forge geometry resolved (issues #179/#181):**
- `fontStateChanged` is at `V+0x18`, `fontPropertyChanged` at `V+0x20` (README law 10 "+0x28" retracted). `ref()` at `V+0x30`, `deref()` at `V+0x38`. Declaration order: dtor pair (+0x00/+0x08), fontLoaded (+0x10), fontStateChanged (+0x18), fontPropertyChanged (+0x20)
- **`addClient` caller set is FOUR sites** [S]: `create()` CSSFontFace.cpp:86; wrapper ctors FontFace.cpp:162/:170; adopt FontFace.cpp:328; and `CSSFontFaceSet::add` → `face.addClient(*this)` CSSFontFaceSet.cpp:203 (set becomes client when face enters). The walk (`iterateClients`) never calls `addClient`, never allocates — it only reads buckets and refs clients (CSSFontFace.cpp:55-57). All `+0x58` fresh-table signatures reduce to creator writes; route (d) lives under BOTH branches of P588
- `WeakPtrImpl` layout: `{+0x00: refcount(4B), +0x08: m_ptr}` — no vtable (chain doc correct, README law "+0x00: vtable" retracted)
- The `+0x68` kill mechanism: first deref happens in `wrapper()`/`existingWrapper()` inside the getter continuation BEFORE any weak-set walk — `0x1+0x08` = death (law 3 explained)
- HashTable grow to 144B: 6th insertion trips expand (75% load factor on 8-slot table). JS route via wrapper churn: `load()` → GC tombstone → re-add × 3 rounds pushes deletedCount to trigger. 144B hole admits 129-144B spray requests (cobrajet302gt, issue #181)
- In-document free of wrapper block: `font-display: fallback` (~3.1s → Failure) or `optional` (~0.1s → Failure) triggers `faceFinished()` → releases both GC pin and C++ strong refs. Forge of +0x68 must happen AFTER unpin (cobrajet302gt, issue #178)

**Traps that cost runs:**
1. **Timer trap**: `setStatus` → `startOneShot`/`stop` → `RELEASE_ASSERT(canCurrentThreadAccessThreadLocalData(m_thread))` — plain address compare; zeroed `m_thread` traps in same task. Suppressor is Cocoa-gated (`#else return false`), so trap is live on PlayStation port. Needs `Thread::current()` VA to survive.
2. **`addClient` does not walk** — it only inserts (CSSFontFace.cpp:483-486). The walk is `iterateClients` in `setStatus` / property setters.
3. **`m_ranges` is NOT a reader** — inline `Vector<UnicodeRange>` member, face must be alive and in-set, 3 independent structural locks prevent attacker-bytes + in-set simultaneously (issue #178)
4. **`face.style=...` landmines are MOOT** (v6/v7, 2026-11-03): the 3 landmines at :265/:268/:273 (cobrajet302gt, issue #181) are unreachable because `backing()` returns null after the UAF — the setter early-returns at the FontFace JS wrapper before any CSSFontFace member access. Documented for reference only.

**HARD BLOCKERS:**
1. **★ WebProcess text base — VP leaked (p691, 2026-11-09)**: FontFace UAF walk chain leaks CSSFontFaceSet vtable pointer (VP). VP = WebProcess_base + vtable_RVA. VP offset `0x1B28` (mod `0x4000`) — 1 boot confirmed in committed beacon data; 14/14 resolved samples at 16 KiB resolution (1 truncated excluded). 9 vtable slot function pointers also leaked. **Remaining**: determine vtable RVA via measured anchor (e.g. `/proc` auxv AT_PHDR) — RVA is a link-time fact, not derivable from source alone (cobrajet302gt, PR #240). The walk chain works in 4 reads (IHT→IM→FO→VP); the original "3-read limit" was a VP threshold bug (`> 0x1000000000n` rejected code pointers at `0x8xxxxxxxxx`; fixed to `> 0x100000000n`).
2. **Heap NX** — source-confirmed (`zero PROT_EXEC` in bmalloc/libpas, Sony `vss` API has no exec flag, `OSAllocatorPlayStation` asserts `!executable`; note `OSAllocatorPlayStation` and `vss` flag are closed-port Sony files, not in the OSS drop). No JIT. Dispatch through forged vtable dies on NX heap. Need a code-reuse chain or existing code pointer.
3. **80B table block — MOOT (v4i, 2026-11-04)** — the 80B spray is unnecessary. Freed memory at T1-0x60 is benign zeros; the two-phase redirect survives without reclaiming the 80B slot (7/7 = 100%). The earlier 80B race analysis (JS spray can't win the LIFO hole) is still correct but irrelevant: survival comes from freed-memory-is-benign, not forged-table-reclaim. Route (d) address leak (`B = T - 0x60`) was confirmed (P588b) but the walk arm is dead (all JS paths gated).
4. **Destructor unreachable** — rc=2 is the spray seed with zero live engine refs. GC collected both wrappers. fonts.clear() + aggressive GC does not trigger deref(). No known path fires ~CSSFontFace(). The free-what-where primitive (point +0x58 at target, trigger destructor → frees target) requires a new ref+deref trigger.
5. **Buffer absolute VA — discovered (p690/p691, 2026-11-09)**: SELF discovered via h3 back-pointer at FO+0x10 (CSSFontFaceSet stores the CSSFontFace pointer, which IS the spray buffer). SELF = 0x1000384480 in the successful run. Also discoverable via pattern-match oracle on +0x38 marker. VTAB (adjacent buffer) at SELF-0x380 also known.
6. **14.10 offset table mostly wrong** — constant drain campaign (probes p588-p591) tested 25 constants: only 1/25 confirmed valid (`lk__thread_list`), 7 confirmed WRONG, 2 crash, 3 untestable. See `docs/CONSTANT_DRAIN_HYPOTHESIS_14_10.md`.

**REMAINING PRIMITIVES (Lua-side, still useful for kernel path later):**
- **★ KASLR defeat (fault oracle)** — kernel image base, size and slide recovered per-boot in one connection (33s, 512 probes). This boot: image at `0xFFFFFFFFD4000000` (102 MB), stub at `0xFFFFFFFFC0000000`. Presence-only oracle — content unreadable (supervisor bit enforced). Probes 1199a-1199c, 2026-11-04
- **★ WebKit FontFaceSet / Canvas UAF** — browser-side heap leak and same-type reclaim; needs a browser entry from the game process and an info leak before arbitrary R/W. See `docs/EXPLOITATION_STATUS.md` and `docs/PROGRESS_AUDIT.md`.
- **CClosure +0x20 function redirect (selected targets)** — Lua arguments, target-like output and restore checks are recorded for rawequal/rawget/select changes (56c/56f); machine-register arguments and general native targets are not established
- `native.fcall_with_rax` — arbitrary userland function calls: getpid=0x22a, socket=0x16, close=0x0 confirmed (probe 129b)
- Tested syscall invocation via `make_syscall(N)`; the exact C-level dispatcher implementation is unidentified
- Heap R/W via GPU mmap (256+ pages)
- Userland ASLR bypass via `dynlib_get_info(593)`
- Full process VM map via sys 674 (317 named regions with protections)
- Network packet injection (RAW socket + IP_HDRINCL, TCP connect-back)
- Child thread ROP syscalls (5-arg) via `thr_new(455)` — full gadget catalog confirmed
- **Syscall 624** — confirmed VM operation counter: +5 per mmap, stable (zero jitter over 100 samples), monotonic. Useful as side channel for counting kernel VM ops. (probe 52b)
- **11 accessible Sony syscalls** — 596, 585, 572, 624, 563-566, 606, 643, 640

**Closed vectors (details in Dead Ends / docs/DEAD_ENDS.md):**
- **aio_multi_delete (syscall 662)** — initially reported as TOCTOU double-free (probe 65l), but follow-up probes 75c-75e proved the race is a double-STATUS-report, not a double-free: the exclusive lock in `entry_dispose` serializes actual frees. Only one thread frees; the second finds the slot cleared. Zone-64 target with type-partitioned UMA makes spray structurally impossible. **Dead.** (probes 65d-75e, docs/AIO_DOUBLE_FREE_14_10.md, docs/AIO_GATE_14_10.md)
- msync(65) device-pager UAF (CVE-2026-49418) — MS_INVALIDATE returns -1 on all mappings (58a/58b)
- Sysent 679-734 — kernel-side credential gate, all return -1 even from child thread via sa (275b-275d)
- Device ioctl research — ~32M calls across 31 nodes, zero exploitable commands (273a-287a)
- UMTX PI mutex ownership fraud — DoS only (crash after 5-7 rounds, system hang), no kptr leak, no controlled write (160f-160j)
- CVE-2026-58093 (tty race) — no /dev/tty* access (58d)
- CVE-2026-58099 (kqueue fork race) — no fork() (58d)
- CVE-2026-58090 (unix socket UAF) — FreeBSD 15.0+ only (58d)
- AIO fd-close race — kernel fhold() prevents UAF (353b)
- AIO batch races (cancel, unmap, gen counter) — all safe (353c-353e)
- netcontrol(99) netevent queue UAF — close-before-unregister leaks ref instead of freeing; public ExploitNetControlImpl chain precondition does not hold on 14.10 (223a-234a)
- NET_RT_DUMP kernel pointer search — all false positives, sockaddr boundary artifacts (56e/56e2)
- CVE-2026-3038 sa_len=127 routing overflow — accepted without panic, likely patched (56e)
- CClosure deep Lua stack read — only userland pointers, zero kernel addresses (56d5-56d7)
- sys 624 side channel — no intra-kernel discrimination, all kernel addrs identical (56f)
- Sysctl deep scan — zero kernel pointers in ALL CTL_* trees (56g3)
- Timing KASLR (mprotect batch + stability) — scheduling noise only (56h-56i2)
- Syscalls 530/531/537 — all nosys stubs, return -1 with SIGSYS ignored, zero VM ops (56j)
- mprotect ret=0 on kernel/unmapped addresses — early-return without VM map check; 547 confirms no protection change (56k)
- Ioctl overcopy full sweep — ALL 34 /dev nodes clean (387a/387c)
- CVE-2026-49427/49428 (posixshm largepage UAF) — shm_open2(571) is nosys (391a-391d)
- CVE-2026-49419 (jail refcount underflow) — all jail syscalls -1 (392a)
- CVE-2026-58094 (ZDI-26-785, FIOSSHMLPGCNF TOCTOU) — requires absent largepage infra (392a)
- BSD-native syscall range (1-530) exhausted — zero kernel pointers across ~400 tested syscalls (388a-392f)
- Kqueue race (ZDI-26-784) — 10,000+ races, 0 anomalies, kernel locking solid (271g/271h/271i)
- /system_tmp compositor sockets — DoS only, client unreadable (361b-377a)
- GPU device mappings — all read/write paths dead (376a-381a)
- **Gigacage active (JSArray butterfly isolation)** — 4 runs × 3072 JSArrays (22-23 elements = 184-192B butterflies), zero corruption across ~24,576 scans. ArrayBuffer(192) reclaims CSSFontFace slots (v4i proven), but JSArray butterflies never did. The separation is an allocator-path difference, not proven to be a distinct bmalloc heap: `IsoMalloc` is off in this port (see the p613 correction below). Type confusion via butterfly reclaim is closed on the tested route. (p600, 2026-11-04)
- **ArrayBuffer(80) spray did not reclaim the WTF::HashTable block** — 4096 ArrayBuffer(80) allocations left 0/4096 signature bytes modified in the 80B table block measured by p588. The earlier "different bmalloc iso-heaps" reading is **retracted**: upstream source shows `IsoMalloc` OFF (`OptionsPlayStation.cmake:211`) and `libpas` OFF (:284/:286), so allocations come from standard bmalloc pools. The observation stands, the mechanism is open — candidates are size-class admission, a separate ArrayBuffer allocation path, or the block not being free during the spray. Do not build on the iso-heap explanation. (p613, 2026-11-04; corrected 2026-11-08)
- **FontFace family() after UAF** — saRef.family returns "sa" (not "normal") post-UAF with SPRAY-HITS=0. Either FontFace caches family as a JS String member, or CSSFontFace stays alive via wrapper Ref. No read primitive via family(). (p614, 2026-11-04)
- **CVE-2023-42917 (flattenDictionaryStructure race)** — 8000 flatten triggers (4 strategies × 2000 rounds), zero anomalies, zero crashes. Likely cherry-picked by Sony (trivial single-file fix, high-profile zero-day from Dec 2023). (p602/p602b, 2026-11-04)
- **CVE-2024-23222 (DFG constant property folding TOCTOU)** — 467 fine-grained DFG race attempts (PIVOT 60-5000), zero type confusion. No constant folding detected. FTL absent on PS5. (p606/p607, 2026-11-04)
- **DFG NaN confusion (Exodus Dec 2023 pattern)** — all 10 impure NaN bit patterns purified to NaN by boxDouble(). No type confusion. (p604, 2026-11-04)
- **DataView integer overflow** — bounds checking uses correct arithmetic. offset 0xFFFFFFFE → RangeError. No 32-bit wrap. (p601, 2026-11-04)
- **WebAssembly** — completely absent from PS5 14.10 WebKit (typeof WebAssembly === "undefined"). (p601, 2026-11-04)
- **SharedArrayBuffer** — absent (typeof SharedArrayBuffer === "undefined"). No cross-worker shared memory. (p601, 2026-11-04)
- **Canvas2D state stack realloc reclaim** — save()×128 reallocates the state stack, and a later ArrayBuffer spray did not reclaim the freed buffer (p555). The earlier "freed buffer goes to IsoHeap" explanation is **retracted** (`IsoMalloc` is off in this port). Second desynchronized trigger impossible (one-shot UAF). RAB bounds checking is spec-compliant. (p555, 2026-10-27; mechanism corrected 2026-11-08)
- **Resizable ArrayBuffer GC crash** — JSC GC crashes at ~20,340 dead resizable ABs. DoS only: zero real corruption (p608r discriminator: 100MB normal ABs survive, 6.4MB resizable crash). (p608 series, 2026-11-04)
- **MetadataTable overflow (JSC Bug 317632) — PRACTICALLY DEAD** — the 32-bit overflow in `UnlinkedMetadataTable::finalize()` IS real: 38,348,816 op_call sites compile in ~7s and JSC allocates only 100KB for 4.3GB of metadata. But the function is UNEXECUTABLE: CodeBlock linking for 38M bytecodes takes ~7 minutes (super-linear O(N^~1.7) scaling), WebProcess is killed before the first callback fires. Scale test: 1M OK (0.1s), 2M OK (1.7s), 5M OOM (560MB metadata), 10M OOM (1.12GB), 38M timeout/killed (100KB metadata but ~7 min linking). The OOB writes (starting at entry 894) are never reached. (probes p615-p615e, 2026-11-04)
- **sys 608 `dynlib_get_info_ex` kernel qword leak** — **DEAD on 14.10**: 608 works (rv=0 on 8 modules × 4 flags) and returns extended module info (segment base/size/protection at +0x160/+0x170), but ALL addresses at the upstream "critical offsets" (+0x110, +0x128, +0x130, +0x148, +0x150) are userland VA. Zero kernel pointers across 32 calls. Sony sanitized the output or the upstream 13.60 analysis was wrong. (probe 1198b, 2026-11-04)
- **CVE-2024-44308 (DFG PutByVal uninitialized register on ResizableArrayBuffer)** — **DEAD on PS5 14.10**: all triggers (INT32MAX+1, NaN, Infinity, -Infinity, 1e20, 0xFFFFFFFF) survived with correct ToUint32 values. Resize-during-DFG variant also survived. Sony patched. (probe p621, 2026-11-04)
- **CVE-2023-41993 (DFG GetByOffset CSE type confusion)** — **DEAD on PS5 14.10**: DFG returned normal value=1, no type confusion. Sony patched. (probe p622, 2026-11-04)
- **Canvas2D valueOf crash backtrace** — `createLinearGradient` with valueOf removing canvas SURVIVED, no crash, no backtrace frames captured. (probe p620, 2026-11-04)
- **CVE-2023-28204 (Yarr regex BOL/EOL readChecked OOB read)** — **DEAD on PS5 14.10**: BOL/EOL assertions patched (count=3/3 correct on surrogate lines). Two `u`-flag conformance bugs confirmed: (1) AdvanceStringIndex does not advance for empty matches (engine advance=0, infinite loop), (2) lone trail surrogate `\uDE00` matches inside valid pairs with `u` flag. Both are spec violations, NOT memory safety: string bounds check operates at memory level, zero OOB reads across all test paths (F-HEAP=0, I-BIG=0). `.replace()` with `gmu` on surrogate strings hangs (infinite loop from advancement bug). (probes p627/p628/p628b, 2026-11-05)
- **Syscall info-leak path exhausted for kernel pointers** — all remaining kernel read candidates tested with real arguments: sys 660 (3 handles, userland only), sys 591 (completely dead, zero symbols resolve), sys 547 (returns -1 on all kernel VAs), sys 656/659/647/623/641/642/611/613 (all -1 or userland). **Correction (2026-11-06):** sys 615 is NOT closed — 1300a's 615 line was a foreign-path call (output buffer in the id slot, `1300a_kread_survey.lua:404`), and the Oct 19-20 committed record (113a/185a/186a) shows its self path (`615(0,&a,&b)` / self pid) skipping the credential gate on 14.10 and writing the class-0 resident count into the first output pointer (the `-1` there is copyout 2 faulting on the size slot). It is a credential-free self-stat channel, not a kernel-pointer surface. See `docs/SYS_611_613_615_STATS_FAMILY_13_60.md`. ~400 BSD + all Sony syscalls tested across entire project, zero kernel pointers in ANY output. (probes 1300a/1300b, 2026-11-05; 615 correction 2026-11-06)
- **Canvas2D UAF internal struct pointer leak** — comprehensive offset mapping: all 13 readable numeric properties (6 transform doubles + lineWidth, globalAlpha, shadowBlur, shadowOffsetX/Y, miterLimit, lineDashOffset) match spray values EXACTLY. ALL reads go through C++ state stack API, no raw struct fields accessible. `inner.canvas` follows reclaimed C++ object (no dimension mismatch OOB). 30× `save()` deep: NO-CHANGE in readable values (Vector realloc invisible). Interleaved save/restore confirms shared state stack. getImageData uses reclaimed canvas dimensions. String properties normal post-UAF. The Canvas2D UAF is a same-type R/W alias, NOT an info-leak. (probe p629, 2026-11-05)
- **p630 text base leak survey — 8 routes DEAD** (p630, 2026-11-05): Error.stack has url:line:col only, zero native addresses. performance.now() heavily quantized (100 calls = 0 deltas, ~1ms+ resolution). DFG type confusion (double[] vs object[] addrof): OSR exit works correctly, all 3 variants returned proper types. Debug APIs ($vm, gc, addressOf): ALL absent, production build. Native toString: standard `[native code]`, no hex. Regex match array under DFG (CVE-2025-31277 simple trigger): no anomalies. Performance entries: navigation timing zeroed. performance.memory NOT available. Useful primitives confirmed: structuredClone+transfer, BigUint64Array, FinalizationRegistry, WeakRef, Proxy traps.
- **CVE-2023-4863 (libwebp VP8L Huffman heap overflow)** — **DEAD on 14.10**: WebP decode IS supported (p630 confirmed), but all 4 PoC crash files (mistymntncop, talbeerysec, NSO/BLASTPASS, Apple/LiveOverflow) handled without crash. talbeerysec variant got explicit decode error (rejected). PS5 14.10 build (Sep 2026) updated libwebp past the 1.3.2 fix (Sep 2023). (probe p631, 2026-11-05)
- **CVE-2025-43529 (DFG escape analysis StoreBarrier missing)** — **DEAD**: vulnerable code introduced after 605.1.15 branch point. PS5 has older WebKit. (probe p632, 2026-11-05)
- **DOM stale pointers + CSS side channels** — **DEAD**: routes (d) and (e) both closed. No DOM object exposes uninitialized/stale pointers readable from JS; CSS computed style timing shows zero discrimination. (probe p633, 2026-11-05)
- **CVE-2018-4416 (StructureID reuse type confusion)** — **DEAD on 14.10**: 0/450 hits across 6 phases (basic, 2-prop, JSFunction, ID burn, double proto, cross-type cache). Sony patched for-in enumerator or implemented StructureID randomization. (probe p634, 2026-11-05)
- **CVE-2025-31277 (RegExp HABT type confusion)** — **DEAD on 14.10**: exhaustive 4-probe campaign. p637: initial detection (FALSE POSITIVE — own properties shadow getters in all indexing modes). p638: DFG escalation (all 10 OSR exits correct). p639: CORRECT hole-write discriminator proves match arrays ARE SlowPut (setter fires on hole write). p640: cross-realm double array (CVE-2017-7005 PS4 technique) — iframes work, arrays cross realms, but zero type confusion (objects store/read correctly, no addrof). All array ops (push/sort/reverse/from/slice/concat/spread) respect HABT. (probes p637-p640, 2026-11-05)
- **Canvas2D UAF stale read without spray** — **CRASHES (4/4 runs)**: CVE-2026-43720 UAF trigger works (v2: getter=true, inner=true, outer=true), but reading innerCtx.lineWidth after free without reclaim crashes WebProcess immediately — freed CanvasRenderingContext2D vtable is invalid, C++ virtual dispatch dies. Same-type reclaim needed (p635 pattern), but with reclaim all reads return spray values (p629). The Canvas2D UAF is a CONTROL primitive, NOT an info-leak primitive. (probe p641 v2, 2026-11-05)
- **CVE-2019-8623/8671 (DFG LICM uninitialized variable)** — **DEAD on 14.10**: 6 sections tested: basic dead-branch hoisting, Object.is(-0,0) trick, var TDZ reset, array access in dead branch, stack residue after deep call chain, try-catch variant. ALL returned `undefined`. DFG LICM correctly tracks initialization state. No stale stack data leak. (probe p646, 2026-11-05)
- **CVE-2020-9802 (DFG ArithNegate CSE OOB — P0 JITSploitation)** — **DEAD on 14.10**: 7 sections tested: INT_MIN overflow baseline, CSE ArithNegate with |0, double negation + CheckBounds, Math.abs range analysis, negative zero, TypedArray OOB edge values (INT_MIN/INT_MAX/-1/16/17/256/65536/-INT_MAX), and OSR hot loop with INT_MIN injection. All bounds checks hold. DFG range analysis does NOT eliminate checks for Math.abs(INT_MIN). Section B "ANOMALY" was a false positive (ToInt32(2^31)=-2^31 is correct JS). Zero OOB in any variant. (probe p645, 2026-11-05)
- **CVE-2021-1789 (JSPropertyNameEnumerator OOB read)** — **DEAD on 14.10**: for...in with Proxy getPrototypeOf trap deleting properties during enumerator construction. 4 variants tested: basic deletion (3/10 keys correct), Proxy trap (5/20 correct), DFG-compiled (5/20 correct), flatten dictionary (64/128 correct). Zero OOB reads in any variant — enumerator correctly re-checks property count after deletion, even in DFG. Sony backported the fix. (probe p644, 2026-11-05)
- **CVE-2018-4233 (DFG CreateThis Proxy type confusion)** — **DEAD on 14.10**: 0/70 type confusion across 5 variants (Proxy constructor, Reflect.construct, call-warmed Victim, multi-attempt with varying fillers). DFG correctly observes Structure change made by Proxy trap during CreateThis. Sony backported the clobberWorld fix. v2 retested with correct wrapper-function pattern (warm `trigger(ctor, arg)` 50K then swap ctor to Proxy): 0/169 confusion across 10 patterns including OSR entry. Definitively dead. (probes p643/p643v2, 2026-11-05)
- **Relapse exploit primitives (ntfargo/Relapse-Exploit, FW 7.00-13.60)** — ALL THREE primitives **DEAD on 14.10**: (A) Symbol.prototype.toString heap byte leak: returns standard 12-13 char string, no 924K heap dump. (B) Structured clone corruption via history.replaceState: clone[1]===clone[2] in ALL attempts, 0/10 corrupted — object pool deduplication works correctly, 65537-element array roundtrips clean. (C) Scope object leak via class super+Proxy: returns `this` (instance), not scope object. Stress tests (1000 refs, nested, circular) all robust. The Relapse exploit cannot work on 14.10. (probe p642, 2026-11-05)
- **Cross-frame GC destructor trigger** — iframe with separate JSGlobalObject doesn't trigger ~FontFace() on the spray buffer. Separate realm GC is independent. Destructor path remains one-shot and unreachable. (probe p655 v2, 2026-11-05)
- **APNG overread heap leak (pastawithpesto V674)** — 7 malformed APNG variants tested: fcTL larger than fdAT (200x1/48x1), IHDR larger than IDAT, no fdAT, offset OOB, tEXt padding. ALL variants return expected red pixels or zeros. Decoder shows frame 1 on frame 2 failure, produces transparent on insufficient IDAT. Zero heap residue, zero leaked pointers. pastawithpesto's "1651 heap pointers" claim not reproducible on 14.10. (probe p657, 2026-11-05)
- **Canvas2D state stack realloc → AB aliasing (pastawithpesto chain)** — Canvas2D UAF stale ref with save()×64 (forces Vector<State> realloc), then 400 AB spray across 25 size classes (128B-16KB). Zero matches for marker doubles, all ABs zero-filled: the spray did not alias the freed state stack. "IsoHeap isolation holds" is **not** the explanation and is retracted — `IsoMalloc` is OFF in this port; whatever separates the two allocations is unresolved (path or size class). With p613 and p600, no measured AB spray aliases those buffers, so pastawithpesto's chain is dead as written. (probe p658, 2026-11-05; mechanism corrected 2026-11-08)
- **Canvas2D cross-type forge campaign (p647-p650, 13 probes) — 100% DEAD** — p647 same-type sentinel→AB reclaim to map field offsets in the 768B struct; p648 DAZ/denormal float + AB(768) cross-type forge; p649-p649j ten forge variants — getters AND setters crash on `m_canvas` binding access. Cross-type reclaim between bitmaprenderer and Canvas2D is structurally impossible. p650 setter-first also crashes. (2026-11-05)
- **FontFace address-leak campaign (p651-p653)** — p651: T-W delta varies 808K-841K across runs, too unstable to derive AB address from T. Dead. p652: load-1 heap determinism CONFIRMED — hit_index=4 across 9 cold-boot load-1 samples, but T has three modes (`0x10008a8100` ×6, `0x10008ac100` ×1, `0x10008b0100` ×2) at exactly +0x4000/+0x8000 allocator-span steps; bake carries the three modes (±0x8000 window), ~67% dominant (6/9) is not a baked address. p653 v1-v5: GC free-list leak via ~FontFace deref DEAD by design — `fonts.load()` creates an internal Promise.all over face loaded promises; the freed "sa" CSSFontFace's promise never settles → LoadRequest holds refs → GC blocked. The UAF creates the condition preventing GC collection. (2026-11-05)
- **WebKit cherry-pick cutoff fingerprinted (p659-p671, 2026-11-06)** — Safari 26.3 (Feb 2026) fixes INCLUDED; Safari 26.4 (Mar 2026) NOT included. CVE-2026-43740 (YARR, Feb 2026) PATCHED (p659). API fingerprint (p660): TransformStream, ResizableArrayBuffer, Set.union, RegExp.v present; WebAssembly, SharedArrayBuffer, ClipboardItem, Temporal absent — but the first three absent-rows are flag/option artifacts (Wasm hard-OFF with JIT; SAB default-false option string; ClipboardItem a runtime setting; Temporal ungraded), so the cutoff rests on the presence rows + p659 alone (cobrajet302gt review, PR #236). Details: `docs/WEBKIT_CVE_SAFARI_26_2_3_4.md`, `docs/WEBKIT_CVE_REGRESSION_TESTS_2026.md`, `docs/WEBKIT_CVE_REMAINING_2026.md`. Self-reported campaign (4TheDoctor bench); beacon logs in `tools/browser_runner/beacon_logs/`.
- **CVE-2026-84635 (TypedArray Reflect.set spec violation) — VULNERABLE but NOT weaponizable** — valueOf fires, but `toNativeFromValue` coercion + post-coercion bounds check block every OOB write path (resize, detach, proto chain TOCTOU). (probes p661/p662, 2026-11-06)
- **CVE-2026-28905 (FTL PhantomNewArrayWithButterfly) — confirmed live, not a leak** — stale slots contain the previous iteration's own map callback results, not heap data. No pointer disclosure. (probes p663-p666, 2026-11-06)
- **OOB state stack read (p667-p669) — DEAD** — state API is typed; no OOB index reachable through last()/save() on the stale ref. **DataList UAF (p670) — DEAD** — datalist not supported on PS5 WebKit. **Private fields seal/freeze JIT confusion (p671) — PATCHED**. (2026-11-06)
- **CVE-2026-45251 poll/close UAF (500a-500o) — confirmed but unexploitable** — 500c: seldrain absent 150/150. 0/35 reclaim across same-CPU readback and safe-reclaim oracles (500n/500o). Zone isolation blocks every spray path tried. Recommend closing this line; return to WebKit FontFace/Canvas UAF. See `docs/CVE_2026_45251_POLL_CLOSE_UAF.md`, `docs/SESSION_HANDOFF_500_SERIES.md`. (2026-11-06)

**NEXT STEPS:**
1. **★ KASLR defeat — DONE** (probes 1199a-1199c, 2026-11-04): kernel image base, size, slide recovered per-boot. Loader-side KASLR is solved. Oracle is presence-only (content unreadable).
2. **★ WebProcess text base — VP leaked (p691)** (2026-11-09): FontFace UAF walk chain leaks CSSFontFaceSet vtable pointer (VP) in 4 reads. VP = WebProcess_base + vtable_RVA. VP offset `0x1B28` (mod `0x4000`) — 1 boot confirmed in committed beacon data; 14/14 resolved samples at 16 KiB resolution (1 truncated excluded). 9 vtable slot function pointers also leaked. **Open**: determine vtable RVA via measured anchor (AT_PHDR from `/proc` auxv, or empirical base-search). RVA is a link-time fact — "605.1.15" is the UA token, not the source tree; actual fork is WebKit 616 internally (cobrajet302gt, PR #240). The bug that blocked this for days was a threshold check (`VP > 0x1000000000n` rejected code pointers at `0x8xxxxxxxxx`; fixed to `> 0x100000000n`).
3. **★ Canvas2D getContext reentry UAF CONFIRMED** (p635, 2026-11-05) — CVE-2026-43720 gives full state R/W (transform 48B + 7 doubles + fillStyle + save/restore). Pixel buffer NOT shared, stateStack OOB dead. This is a CONTROL primitive — needs info-leak (text base) to escalate. p629 struct mapping also confirmed all reads are state-stack mediated.
4. **★ Kernel read primitive** — fault oracle gives image location; next step is a kernel read. Candidates: (a) sysctl with controlled MIB pointing into kernel image (needs kernel pointer), (b) device ioctl that copies from kernel VA, (c) race condition in a kernel copyin/copyout path. The oracle cannot read content (supervisor bit enforced).
5. **★ Butterfly/Gigacage test — DEAD** (p600, 2026-11-04): no butterfly reclaimed a CSSFontFace slot in ~24,576 scans. The allocator separation observed is real; calling it "Gigacage" or "iso-heap" is interpretation, not measured (`IsoMalloc` is off). Type confusion via butterfly reclaim is closed as tested.
6. **★ Route (d) discriminator — DONE** (P588/P588b, 2026-11-03): Route (d) is viable on 14.10.
7. **★ Second walk via face.style — RETRACTED** (v6/v7/p589 2026-11-03): Unreachable from ALL known JS entry points.
8. **★ C++ path to freed buffer — CONFIRMED** (p599 v1/v2/v4a, 2026-11-04): GC destructor path works but one-shot.
9. **★ Null-spray survival — CONFIRMED** (p599 v4i, 2026-11-04): 80B spray unnecessary. 100% survival.
10. **Probe-ID collision fix** — rename p563/p564 FontFace references to p563-html/p564-html (issue #180)

## When Analyzing Results

1. **Kernel pointers** are in the `0xFFFF8xxx_xxxxxxxx` range. Values like `0xFFFFFFFF_00000000` are bitmasks, not pointers.
2. **ret=0** means success for most syscalls. **ret=-1** means failure. **ret=-999** means the pcall itself failed (crash or exception).
3. **Always cross-reference** against docs/FINDINGS.md and the dead ends list above before declaring something new.
4. **Update UNTESTED_THEORIES.md** when a theory is tested — mark it confirmed, dead, or partially tested.
5. **Update CHANGELOG.md** with each phase's findings.

## Git Conventions

- **Author:** commit as the contributor doing the work (Rithik Janarthanan
  <janarthananrithik@gmail.com>), never as the repository owner
- **No AI attribution** in commits, PRs, or code.
- Commit messages should be short and descriptive of what changed.
