# The executable surface of a 14.10 process, and why the current CPU route is the wrong CPU bug

Measured 2026-11-05 17:07 on 192.168.1.121:9026, fw 14.10, loader pid fresh per
connection. Probes `1251a_674_calibration.lua`, `1252a_exec_surface_map.lua`.
Logs `results/phase17_new_vectors/1251a_674_calibration_20261105_170708.txt`,
`1252a_exec_surface_map_20261105_170742.txt`.

## 1. 674 is a working, calibrated oracle, and it reports EFFECTIVE protection

One call, 55f's shape `674(buf, 72, 512, countp, 0x40000000)`, `STRIDE*MAX+0x100`
buffer: `rv = 0`, `count = 322`. Record layout confirmed self-describing:

| offset | content |
|---|---|
| +0x00 | start VA (qword) |
| +0x08 | end VA (qword) |
| +0x10 | zero in every record seen |
| +0x18 | protection dword |
| +0x20 | **length-prefixed name**: byte 0x11 then `anon:00000127599e`, byte 0x0B then `executable` |

The decisive calibration: the same run created an anon `prot=7` mapping, a file-backed
`prot=1`, `prot=5` and `prot=7` mapping of `/app0/eboot.bin`, and reported
eboot's own `.text` as a control.

| mapping requested | recorded prot | meaning |
|---|---|---|
| anon `prot=3` | `0x3` rw- | unchanged |
| anon `prot=7` | **`0x3` rw-** | **EXEC dropped** |
| file `prot=1` MAP_PRIVATE | `0x1` r-- | unchanged |
| file `prot=5` MAP_PRIVATE | **`0x1` r--** | **EXEC dropped** |
| file `prot=7` MAP_PRIVATE | **`0x3` rw-** | **EXEC dropped** |
| eboot `.text` (ground truth executable) | `0x5` r-x | oracle says exec |

So 674 reports the protection the kernel actually installed, not the one requested, and
it separates a known-executable region from a known-dead one. **The oracle is usable.**

## 2. PROT_EXEC is dropped for vnode-backed mappings too - 1248a's premise is dead

`docs/SPECULATION_READ_14_10.md` §4 left one live candidate: "PROT_EXEC being dropped
for anonymous memory does not imply it is dropped for a vnode object, and a COW mapping
would be writable as well". That is now measured and it is false. A `MAP_PRIVATE`
mapping of `/app0/eboot.bin` with `prot=7` is recorded as `rw-`, and with `prot=5`
as `r--`. The kernel strips `PROT_EXEC` at `mmap()` time for both `OBJT_DEFAULT`
and vnode objects.

Consequence: **probe 1251b must not be run.** It was written to write
`mov eax,0x1234; ret` into a `prot=7` eboot mapping and call it; the oracle already
says the page is `rw-`, so the call would be a guaranteed loader kill for a known
answer. 1248a's fcall branch now skips in every case, which is correct.

## 3. The whole executable surface, measured

322 regions. Protection histogram:

| prot | meaning | regions |
|---|---|---|
| `0x0` | --- | 12 |
| `0x1` | r-- | 80 |
| `0x3` | rw- | 170 |
| `0x4` | --x | 37 |
| `0x5` | r-x | 4 |
| `0x10` | --- (extra Sony flag bit) | 1 |
| `0x23` | rw- + flag 0x20 | 1 |
| `0x33` | rw- + flags 0x20,0x10 | 17 |

**41 executable regions, 0xBBC000 bytes (11.7 MB), and exactly zero of them are
writable.** W+X does not exist anywhere in this process. The four `r-x` regions:

- `0x10B4000 - 0x1548000` len `0x494000` `executable` - eboot's own text. Its first
  dword is `0x62696C2F` = `"/lib"`, so the segment starts with a string, not code.
- `0x14A2AC000` `libc.prx`, `0x15BC68000` `libSceFios2.prx`, and an unnamed
  `0x7EF9F0000` 0x4000 page.

The 37 `--x` regions are the XOM system libraries (`libkernel.sprx` at
`0x827848000`, `libSceLibcInternal.sprx` at `0x822754000`, and 35 more). They can be
**called** but not read - which is why `native.fcall_with_rax` reaches libkernel
functions (probe 129b: getpid, socket, close) even though the bytes are invisible.

Also of note: `0xF0000000 - 0xF0004000` is a 16 KB `rw-` mapping named
`(NoName)eboot.bin`, and `0x800000000 - 0x800004000` is a 16 KB `--x` page with an
empty name.

## 4. The CPU route in the doc is a Meltdown-class design, and Zen 2 is not Meltdown

`docs/SPECULATION_READ_14_10.md` §5 builds a 164-byte **userland** gadget whose
attack phase is:

    movzx eax, [rbx]      ; rbx = a supervisor address
    shl   eax, 9
    mov   [rsi+rax], 1    ; probe array in user memory

and §5 asserts "the load never retires, but it has already forwarded its byte". That
assertion is the definition of **Meltdown (CVE-2017-5754)**: a faulting load whose data
is forwarded before the fault retires. AMD's Zen family does not do this - AMD's own
whitepaper states its processors do not speculate past a permission fault, and Zen 2
(Oberon) is not on any Meltdown-affected list.

Spectre v1 (CVE-2017-5753) is a different bug: the out-of-bounds load must be
**architecturally legal for the code that executes it**, and only the bounds check is
mispredicted. A userland gadget's own bounds check can only be bypassed for user data.
So no amount of training lets a ring-3 gadget read a supervisor address, whether or not
the kernel is mapped in the user page tables.

**Therefore the exec-page hunt was chasing a requirement of the wrong bug.** Finding a
writable executable page would not make §5 work on Zen 2, and losing it costs nothing.

## 5. What the correct design looks like

A Spectre v1 kernel read needs the *kernel* to run the mispredicted bounds check. The
shape is:

    ; kernel, reachable from a syscall, index i attacker-controlled
    cmp  i, n            ; attacker trains this branch
    jae  skip
    mov  eax, [karray + i*4]    ; secret, architecturally legal in ring 0
    shl  eax, 12
    mov  [user_buf + rax], 1    ; transmitter: the attacker's own buffer

The transmitter writes into a user buffer the attacker already owns, so the side channel
is observed by timing the probe lines after the syscall returns. **This needs no
executable user page, no writable kernel page, and it is unaffected by PTI**, because the
code doing the speculative read is the kernel's own.

The work is therefore a static hunt, not a console hunt: find a syscall body in the
kernel image with (a) a bounds check on a user-controlled index, (b) a dependent load
whose value is scaled and used as an index into a pointer the caller controls, and
(c) a path where the second load is a store into user memory. Candidate shapes include
the fd-table lookups (`cmp idx,[table] / jae`) that the indexed-load census already
enumerated, and the `copyout`-adjacent loops.

Caveat carried from the rest of the repo: the only image available is the 13.60 capture
`docs/dumps_13.60/kernel_text.bin`, base `0xffffffff8a9c0000`, and no verified 14.10
image exists. A candidate found there is a hypothesis about 14.10, testable only by the
timing behaviour itself.

## 6. Corrections this measurement forces

- `docs/SPECULATION_READ_14_10.md` §4's "live candidate is a file-backed MAP_PRIVATE
  mapping of /app0/eboot.bin" - **measured false**, PROT_EXEC is dropped there too.
- `docs/SPECULATION_READ_14_10.md` §5's "the load never retires, but it has already
  forwarded its byte" - **not a property of Zen 2**; the gadget tests a Meltdown
  behaviour on a non-Meltdown CPU.
- "Do not run probe 1246a before 1248a succeeds" - 1246a should now be considered void
  as written, for the reason above rather than for lack of an exec page.

## 7. Three follow-ups measured the same session (all negative, all cheap)

**(a) Spectre v1 transmitter census, whole 13.60 text.** Linear capstone sweep,
6,134,149 instructions, searching for the only shape that can serve as a transmitter:
indexed load -> `shl reg,k` (k in 6..12) -> indexed store using the *same* register,
within three instructions of each other. **One** hit image-wide:
`0xFFFFFFFF8AEB405A` `movsxd rcx,[r12+r8*4+0x4d0]; shl rcx,7; mov esi,[r14+rcx+0x38]` -
a 128-byte struct-array lookup whose second access is a **load**, not a store. There is
no classic user-probe transmitter in this image. Script `.local/spectre_gadget_census2.py`.

**(b) 674's handler is bounded by construction.** Thunk `0x265FA0` -> body `0xABB980`
(`narg=5`). Decoded:
- `cmp dword [uap+0x20], 0x40000000; jne -> EINVAL` - arg5 is an exact flag, as 55f found.
- `mov r12,[uap+8]` (stride), then `cmp r12,0x48; mov eax,0x48; cmovb rax,r12` ->
  **copyout length = min(stride, 0x48)**, stored at `[rbp-0x108]`.
- `mov rax,[uap+0x10]` (max) -> `[rbp-0xf0]`, used only as `cmp r13,[rbp-0xf0]; jae` -
  a loop bound, never an allocation size.
- The record is a **fixed 0x48-byte stack slot** at `[rbp-0x78]`, memset then filled.
So neither `max` nor `stride` can overflow anything: stride is clamped, max only limits
iterations, and the source buffer is a fixed local. 674 is a dead end for memory safety.

**(c) Every capability tag is read from a kernel credential, never from user memory.**
239 call sites to the 45 tag helpers. `rdi` provenance: 148 sites load
`[reg+0x140]`, 11 load `[reg+0x40]` (`reg` always derived from `gs:[0]` -> `[td+8]` ->
proc), 15 pass a register set from one of those, 85 inherit. The two offsets are both
proc fields (`[proc+0x40]` and `[proc+0x140]`), so no call site lets us forge a tag.
The 607-unlock idea is closed. Script `.local/tag_arg_source.py`, `.local/tag_40_sites.py`.
