# Sysent tail (677–734): 13.60 contracts for the 14.10 kill range

> **Date:** 2026-11-05. Source: `docs/dumps_13.60/kernel_text.bin`,
> `docs/dumps_13.60/sysent_raw.bin`, `docs/sysent-names-13.60.csv` (13.60
> labeled capture; acquisition authenticity unresolved — see
> `docs/dumps_13.60/README.md`). All addresses are 13.60 RVAs from kernel
> base `0xffffffff8a9c0000`. **14.10 status: every slot 677–707 kills the
> process on any call** (syscall isolation sweep, 2026-10-20; SIGSYS-ignored
> retests 275b–275d), and 708+ were never reached because the loader died
> first. The `-1`-row rule applies in reverse here: a kill is an untested
> contract, and these are the contracts to test if a real-args probe ever
> runs. Probe 275a is PREPARED — NOT RUN (`docs/PROBE_INDEX.md` line 6).

## Capture inventory limits (verified this session)

- `sysent_raw.bin` holds **679 entries** (32,592 bytes, 48-byte stride),
  so the parsed index ends at **678** — entries 679–734 were never
  captured. `docs/SYSENT_PRESENCE_14_10.md` says "the 13.60 capture has
  735 entries"; that is the CSV's row count, not the captured table's.
- The CSV names 677–734 with thunk RVAs, but only 677–678 have captured
  sysent entries behind them. The 679–734 names/thunks come from the
  accompanying CSV (built from the same dump session's symbol walk, per
  its header), not from `sysent_raw.bin`.

## Thunk resolution check (verified this session)

Resolving every CSV thunk RVA in 677–734 against `kernel_text.bin`
(`E9 rel32` decode, same routine as `tools/offline/handler_extract.py`):

- **58 of 58 resolve to real code** (53 real handlers + the 5 slots
  695–699, whose thunk address `0x265760` is the shared nosys
  trampoline and which resolve to the stub body at `0x5620e0`).
- All handler targets lie inside the retained text (< `0xe6e5c0`), so
  every 677–734 handler body is disassemblable offline. The full
  resolution table (num → name → thunk → handler RVA) is reproduced by
  the same decode loop and is omitted here for size; spot rows:

| num | 13.60 name | thunk RVA | handler RVA |
|---|---|---|---|
| 677 | `wait6` | `0x266378` | `0xbe8480` |
| 687 | `pipe2` | `0x2663c8` | `0x802df0` |
| 690 | `ppoll` | `0x2663e0` | `0x4eee20` |
| 705 | `get_phys_page_size` | `0x265460` | `0x2d3730` |
| 713 | `get_ppr_sdk_compiled_version` | `0x266468` | `0xabe830` |
| 715 | `ioreq` | `0x266478` | `0x5f0fc0` |
| 725 | `mmap2` | `0x2664c8` | `0xab8ae0` |
| 728 | `virtual_query_by_pid` | `0x2664d0` | `0xabb660` |
| 733 | `get_resident_fmem_count2` | `0x2664f8` | `0xabd000` |
| 734 | `trace_ctrl` | `0x266500` | `0xfc890` |

## Contracts for probe 275a's five "fault-proof" members

275a was designed around calls that are read-only and take simple
buffers, so that any returned value proves the 14.10 table extends past
676. The 13.60 bodies bear the design out:

### 705 `get_phys_page_size` (handler `0x2d3730`, 0xe6 bytes) — the cleanest discriminator

- Zero-arg-tolerant: with arg1 (user dst) NULL it returns `EINVAL`
  (0x16) *without touching memory* (`0x2d3767`–`0x2d376f`); with a
  valid dst it copyouts exactly **8 bytes** (`0x2d37ea`, `mov edx, 8`).
- The value comes from helper `0x8ed710` keyed by arg0, under a lock —
  no privilege check anywhere in the body; the only gate is an
  early feature test (`call 0x609940`; if it returns 0, return 1).
- **Discriminating power:** on 14.10, `make_syscall(705)` with
  `(0, &u64)` returning 0 or even EINVAL proves the table extends;
  a kill is the strongest table-end signal available. Six-zeros is
  already safe on 13.60 (EINVAL, no fault), so the 2026-10-20 kill on
  zeros is itself evidence against table extension.

### 713 `get_ppr_sdk_compiled_version` (handler `0xabe830`, 0x79 bytes)

- No user pointer at all: it writes the result into `td+0x408` (the
  syscall return-value slot) via helper `0xabe260` with 5 selector
  values; gated only by a credential-like check (`call 0x608f90`).
- Returns 0 on success, 1 on gate failure. Completely fault-proof for
  any argument values — ideal first call in the probe.

### 733 `get_resident_fmem_count2` (handler `0xabd000`)

- Arg contract: `[rsi]` = selector dword (must be 0 or 0xa, else
  EINVAL at `0xabd024`–`0xabd033`), `[rsi+8]` = output size,
  `[rsi+0x10]` = user buffer. Calls helper `0xabccc0` then copyouts.
- Six-zeros hits the `test ecx,ecx; jne` path (selector 0 is legal),
  so zeros do not fault on 13.60 — again, the observed 14.10 kill
  predates any body logic.

### 687 `pipe2` (handler `0x802df0`) and 690 `ppoll` (handler `0x4eee20`)

- `pipe2`: flags mask check `test edx, 0xffeffffb` on arg1's low dword
  — six-zeros passes the mask, then creates a real pipe and copyouts
  8 bytes (two fds). Not fault-proof (allocates fds), but a return of
  0 with two valid fds is unambiguous evidence of table extension.
- `ppoll`: standard 4-arg shape (`fds, nfds, timeout, sigmask`); with
  arg2 (timeout pointer) NULL it takes the poll-forever path
  (`0x4eee4a`–`0x4eee4d`). Zeros = `poll(NULL, 0, NULL, NULL)`, a
  legal no-op on FreeBSD.

## The two interpretations, and what each costs

1. **14.10 dropped the tail.** The measured table ends at 676; the
   677–707 kills are out-of-range dispatch, same as 4095. Cost of
   accepting this without 275a: none — the tail stays unreachable.
2. **The tables number differently** (e.g., 14.10 renumbered the Sony
   tail, or the 14.10 sysent is shorter because Sony moved these
   handlers elsewhere). Cost: the 13.60 names above 676 stay
   "unverified and unreachable" (current `SYSENT_PRESENCE_14_10.md`
   language), and any capability they name (`mmap2`,
   `virtual_query_by_pid`, `get_phys_page_size`) is lost as a lead
   even though its handler might live at a different number on 14.10.

Probe 275a discriminates the two for five slots. A return value from
*any* of 705/713/733/687/690 with the shapes above proves
interpretation 2 (and immediately reopens `mmap2`/`virtual_query_by_pid`
as targets); kills on all five, with 705 called the no-fault way
(`(0, &u64)` first, then six-zeros as control), is the strongest
available confirmation of interpretation 1 short of a 14.10 image.

## Corrections this doc makes to the existing record

- `docs/SYSENT_PRESENCE_14_10.md` ("the 13.60 capture has 735 entries"):
  the captured table (`sysent_raw.bin`) has **679** entries; 735 is the
  CSV row count. Entries 679–734 have names and thunk RVAs from the CSV
  but no captured sysent entry behind them.
- `docs/ATTACK_SURFACE.md` line 125 ("Native sysent 677-734 — 58
  untested entries … posix_fadvise(727), cpuset_getaffinity(734)"):
  the 13.60 CSV names 727 `get_aio_debug_request_info` and 734
  `trace_ctrl`, not posix_fadvise/cpuset_getaffinity; and the slots are
  not "untested" — the 2026-10-20 isolation sweep killed 677–707 on
  zeros, which is the whole reason 275a exists.
- `docs/PROBE_INDEX.md` line 6 ("53 real handlers in 677-734"): the
  verified count is **58 resolving thunks = 53 real handlers + 5 nosys
  (695–699)**; all 58 handler bodies are inside the retained text.

## Notes for whoever runs 275a

- Call 713 first (no pointers, no allocation), then 705 with
  `(0, &buf)`, then 733 `(sel=0, size, buf)`, then 690
  `(NULL,0,NULL,NULL)`, then 687 `(&fds, 0)`.
- Ignore SIGSYS first (sigaction 416, handler 1) per the repo rule —
  if the table truly ends at 676, these are nosys kills; with SIG_IGN
  they return -1 instead of dying and the probe survives to try all
  five in one connection.
- A returned value must be cross-checked against the 13.60 contract
  (e.g., 705's 8-byte copyout, 687's two fresh fds) before claiming
  table extension — a `-1` under SIG_IGN only proves *something*
  answered.
