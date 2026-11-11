# Creative-idea swarm, 2026-11-10

Six lenses were spawned with the same brief — find a kernel R/W primitive by
combining what is already measured, not by sweeping more surface — and each
returned ten ranked ideas. This file records what came back, what was checked
against the corpus, and what survived. Nothing here is a measurement; every row
that cites a capture is a claim about that capture, and the rest are static
reads of the 13.60 image or proposals.

The triage column is the point of the file: of sixty ideas, four are still
proposals worth a console life, three are already answered by an existing
capture, and the rest need a second fact that one probe can falsify.

## Ranked short list

| # | Idea | Source | Cost | Status |
|---|---|---|---|---|
| 1 | `pipe(42)` returns fd0 in rax and leaves `fildes[]` unwritten — the dead-end row is a probe artefact | LensLoader | 0 lives | **CONFIRMED (`1550a`, M)**: `rv=22`=fd0, pair 22/23, both-direction byte round trip |
| 2 | `548 op 2` RO→RW on a `MAP_PRIVATE` vnode page: does it break COW? | LensFreeBSD | 0 lives | **DEAD (`1552a`, M)**: op 2 granted W (1→3) and COW still broke — store landed in V1, V2 and a fresh V3 both read the page-cache byte |
| 3 | `548 op 1` delete vs a store from a native child on the same page | LensRaces + §13.1 | 1 life | `1553a` written, in review — uses 157a's sustained-loop instrument |
| 4 | `/dev/gc` group 0x81 with an in-range *index* field instead of a uniform sentinel | LensSony | 1 life | proposal |
| 5 | Device-page lifetime under a sibling mapping | LensCompose | 1 life | rejected: content oracle cannot discriminate |
| 6 | 601 stage two armed by the attach command | LensSony | 1 life | **already falsified by `1538b`** |
| 7 | PKTOPTIONS getsockopt over-read | mine | 0 lives | **already answered by `09`/`981a`** |
| 8 | `mlock` against `548 op 1` delete | LensRaces | 1 life | proposal, weak oracle |
| 9 | `634 thr_get_ucontext` torn frame | LensRaces | 1 life | proposal, low prior |
| 10 | `0x80108002` on `/dev/dmem1` | LensHardware | console death | **closed: 13.60 `ud2`, deliberate trap** |

## What each lens actually found

### LensLoader (the loader's own machinery)
- `kernel.lua:327 initialize_kernel_rw()` is gated on `storage.get("kernel_rw")`,
  and `initialize_kernel_rw` only **consumes** a state the exploit produces —
  `state.ipv6_kernel_rw_data` and `state.kernel_addr` are copied into
  `ipv6_kernel_rw.data` and `kernel.addr` (`.local/build/SAVEDATA/kernel.lua:333-345`).
  `storage` is a plain global table (`misc.lua:595-611`), so a chunk *can* set
  the key, but the value it would have to supply is the exploit's output. There
  is no shortcut here.
- `417 sigreturn` from inside the loader's SIGSEGV handler is the reason every
  fault kills today: the handler returns without sigreturn. A working 417 gives
  fault *containment*, which changes what every later probe may attempt.
- `copyout` into a `p=0x33` GPU window via `421 getcontext`: the device pager
  refuses a user *load* from those windows (`376a`/`380a`), but whether a kernel
  copyout is admitted is a different permission check and has never been asked.
- `430`'s pre-validation tid write and the loader's single pivot chain / stale
  `signal.fd_addr` are two state-ordering ideas that need no new syscall.

### LensFreeBSD (subsystem invariants)
The COW write-through (ranked 2) is the strongest: it needs no race, no
children, and its oracle is a second mapping of the probe's own file. The rest
of the list is TCP urgent-pointer bookkeeping (`TH_URG` has never been set by
any probe here), the `MSG_OOB`/`so_oobmark` credit, and two fault-race shapes.

### LensRaces (races the old instrument could not build)
The load-bearing static correction: **§19 closed the wrong function.**
`vm_map_protect` (`0x8ac8bdb0`) has no retry window, but the path a `548` op
actually applies through is the batch applier `0x8ac8dc10`, and that body
provably drops the map lock (`0x8ac8defe` `vm_map_unlock`, `0x8ac8df4d` re-lock
on `map+0x170` or `0x8ac8e041` on `map+0x1a8`) and takes an
`IN_TRANSITION` wait path at `0x8ac8dfa0` with a timestamp + re-lookup at
`0x8ac8e01a`. Entry bookkeeping is timestamp-guarded and the 0x20-byte user
entries are copyin'd into kernel nodes before dispatch (`0x8b47bf68`), so there
is **no double-fetch** — the unprotected thing is the pmap, because a fault's
`pmap_enter` runs with only the pmap lock.
It also retires `docs/VM_LAYER_14_10.md` §13's third ground for closing the
axis: probe `157a` measured a `thr_new` child looping the libkernel syscall stub
for ~21 ms, so a sustained native loop *is* an instrument, not a 30-instruction
chain.

### LensHardware (DMA, GPU, MMIO)
`/dev/dmem1`'s `0x80108002` is the only ioctl that takes a genuine device
address and a length, and it panics on every legal range — but
`docs/DMEM1_COMMAND_14_10.md:188` already records that 13.60 reaches a `ud2`
there, i.e. a deliberate trap for an impossible state, not a memory-safety bug.
Four console deaths already paid for that answer. Do not re-run it.
The rest is the `SceGnmDingDong` window (mapped RW without `0x10`, reads all
`0xFF`, swallows stores) and the dmem read counters as an oracle.

### LensCompose (pairings of measured primitives)
Idea 1 (device page survives its mapping's termination) reads well but its
oracle does not work: device content is a function of the aperture *offset*, so
two mappings of one offset always agree by construction, and a freed device page
returned to the device pool is invisible through content. Rejected on the
oracle, not on the mechanism.
The useful part of that lens is the composition discipline — first op creates
non-default state, second op acts on it, third observation must be a value the
default state cannot produce.

### LensSony (Sony-added subsystems)
Idea 1 (601 stage two armed by the attach command) is the one to check first and
it is already checkable: `1538b` ran `0x23` to `rv=0` twice, and every command
after it in the same connection still answered exactly as before — `0x24`,
`0x25` and `0x26` stayed `EPERM(1)`, and `[E]`'s `0x11` answered `EINVAL(22)`
rather than entering the stage-two blob parser (which returns `1` on a type
mismatch, not `-1`). So the arm bit `[td+0x529] & 1` is **not** what `0x23`
sets, and the command that owns the store at `0x8b66131f` remains unidentified
because the dispatch table at `0x8e031160` is outside every dump. 601 stays
closed.
Idea 7 is the only genuinely untested variation in the ioctl corpus: all 25
`/dev/gc` group `0x81` commands were measured with a *uniform* byte fill, which
makes every index field `0xA5A5A5A5` — out of range — so "ignores content" and
"rejects an out-of-range index" are indistinguishable in that corpus. A sweep
with in-range indices at dword 0 and dword 1 is cheap and has never been run.

## Ideas already answered, so nobody re-spends a life

- **PKTOPTIONS over-read.** `probes/phase1_identity_layout/04_kernel_surface.lua`
  never initialised its 4096-byte buffer and printed the caller's own `optlen`
  back, which is why it looks unmeasured; but `docs/ALL_RESULTS.md:15159` records
  `PKTOPTIONS: 8192B, 0 nonzero` on a zero-filled buffer and
  `results/phase11_network_attacks/981a_ipv6_pktoptions_connected_20261103_150254.txt`
  poisons the destination with `0xA5` first. Both say the kernel writes nothing
  past the chain. `1551a` was written and deleted unspent.
- **`0x80108002`**: deliberate `ud2` in 13.60.
- **601 attach-as-arm**: falsified by `1538b` as above.

## Two facts worth carrying forward

- `42,compat10.pipe` in `docs/sysent-names-13.60.csv` — the slot really is the
  old ABI, which is why the two descriptors come back in rax/rdx and why
  `.local/build/SAVEDATA/misc.lua:391` documents exactly that.
- `close` is **6**, not 0. Two probes written today used `mk(0)` for close,
  which is the nosys slot and kills the caller; both are fixed. Any probe that
  wants to close a descriptor must use `mk(6)`.
