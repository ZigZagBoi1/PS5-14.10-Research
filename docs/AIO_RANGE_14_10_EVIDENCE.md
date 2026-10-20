# The AIO 661-670 "hard wall" rests on one syscall

Status: **scope correction.** No new console evidence. This note re-reads the
captures the current verdict is built on and shows that nine of the ten
numbers in the range have no recorded results in these captures.

Earlier summaries generalized the range 661-670 as a confirmed hard wall on
14.10. The supporting citations are probe 54c and section G of probe 54f.
Neither capture records a returned result for 661 or any later entry.

**Capture boundary, not a termination diagnosis:** 54c prints a marker before
calling 661; 54f stops at a section header before its loop prints any call
result. The source identifies the intended first call, but missing output
alone cannot establish whether it began or why capture stopped. No independent
console-side termination evidence is added here.

---

## 1. What the captures actually contain

| capture | last line |
|---|---|
| [`54c_aio_full_attack_20261018_090527.txt`](../results/54c_aio_full_attack_20261018_090527.txt) | `  [BEFORE] sys 661 (event_create, narg=4)` |
| [`54f_kaslr_deep_20261018_090603.txt`](../results/54f_kaslr_deep_20261018_090603.txt) | `--- G: AIO event subsystem (661/662/668 — obfuscated kptr leak) ---` |

For byte-independent checkout comparison, SHA-256 after replacing CRLF with LF:

- 54c: `93a5383eda17cc06dbaeba193789d1583cb9806f250f62deca6298fdacbf2926`
- 54f: `de9354b8cc61a18db6affbb63b13179e3f1bfd8b375fac3838f7260dc223f270`

These hashes identify the saved text, not its hardware provenance. Historical
byte counts varied with checkout line endings and are not used as an oracle.

The 54c matrix prints `[BEFORE] sys N`, then calls, then prints either
`[RETURNED]` or `[ERROR]` (`probes/phase14_final_push/54c_aio_full_attack.lua:180-193`).
The capture contains the `[BEFORE]` line for 661 and no result line for it and
nothing at all for 662-670. Section G of 54f iterates `for num = 661, 670`
(`probes/phase14_final_push/54f_kaslr_deep.lua:461`) and prints a result line
per iteration; the capture ends at the section header, before the first result.

So the evidence is:

- 54c reached its pre-call marker for 661 without a saved returned-call marker.
  The sources intend two different first-call shapes (all-zero in 54c;
  `(0, outbuf, 0x200, 0, 0, 0)` in 54f), but source intent is not execution proof.
- 662, 663, 664, 665, 666, 667, 668, 669 and 670 have **no recorded results in
  these captures**; no range-wide behavior follows.

The missing matrix rows establish a coverage gap, not its cause. In particular,
section G has no output after its header.

The same truncation pattern appears in probe 52a
(`results/phase13_52batch/52a_survey_627_676_20261018_103436.txt`), whose
capture ends at `P1 num=631 calling now...` after 627-630 returned
`PCALL-FAIL`. One lethal number ends the connection, so every number after it
in that connection is unmeasured.

## 2. Why the truncation is structural, not bad luck

`tools/send_probe.py` opens one TCP connection per probe, and the loader spawns
a fresh process per connection (`docs/USERLAND_ENTRY.md`). A probe that walks a
range inside a single connection therefore has exactly one lifetime to spend.
If the first number terminates the process, the remaining numbers have no
recorded results in that capture — no output, no error, no record that they
were skipped.

That is one explanation consistent with these capture boundaries, not an
independently diagnosed outcome. An in-connection range walk cannot provide
later measurements if its connection or process ends at an earlier entry.

## 3. What this does and does not show about 14.10

**Shown:** neither saved capture records a 661 result. 54c reached a pre-call
marker; 54f reached a section header whose first intended call is 661.

**Not shown:** anything about 662-670. The current verdict generalizes from 661
to the whole range on the assumption that the numbers form one subsystem with
uniform behaviour.

That assumption is already questionable from the 13.60 artifacts. Resolving
every thunk in `docs/dumps_13.60/sysent_index.json` gives:

| syscall | 13.60 body | first instructions | classification |
|---|---|---|---|
| 661 | `0x3af8f0` | `push rbp; mov rbp,rsp; xor esi,esi; pop rbp; jmp 0x265760` | nosys stub |
| 662 | `0x3af900` | arg shuffle from `[rsi]`/`[rsi+8]`/`[rsi+0x10]`, then `jmp 0x3af920` | AIO batch delete |
| 663 | `0x3b01f0` | arg shuffle, `jmp 0x3b0210` | AIO batch wait |
| 664 | `0x3b0fb0` | arg shuffle, `jmp 0x3b0fd0` | AIO batch poll |
| 665 | `0x3b1670` | `jmp 0x265760` | nosys stub |
| 666 | `0x3b1680` | arg shuffle, `jmp 0x3b16a0` | batch cancellation |
| 667 | `0x4a31a0` | own prologue, five callee-saved pushes | process/thread record enumeration |
| 668 | `0x3af8e0` | `jmp 0x265760` | nosys stub |
| 669 | `0x3b2060` | `mov eax,[rsi]; mov rdx,[rsi+8]; ...` | separate body |
| 670 | `0x3b28d0` | own prologue | separate body |

Three of the ten are unsupported-syscall stubs and one (667) is not part of the
AIO cluster at all. The range is not homogeneous in 13.60, so "AIO 661-670" is
a label, not a subsystem.

**Cross-firmware limit:** the 13.60 static classification cannot be assumed to
describe 14.10. A missing returned-call result is not enough to establish a
different handler, a changed sysent layout, or an ENOSYS-versus-kill distinction.

**Counter-check that the range is not simply unreachable:** high syscall
numbers do work on 14.10. Probe 55e calls 674 and gets `ret=0` with 316 VM
regions; probe 54f's section B calls 649 and gets `ret=0` with module
addresses. Lethality at 661 is specific to that entry, not a property of the
number being large.

## 4. The probe labels in 54c are also wrong

`probes/phase14_final_push/54c_aio_full_attack.lua:165-176` labels the range
`event_create`, `event_query`, `aio_multi_wait`, `event_signal`, and so on.
Those names came from the handler analysis that
[HANDLER_CLAIM_CORRECTIONS.md](HANDLER_CLAIM_CORRECTIONS.md) corrects. Per the
repo's own `results/kernel_handlers/INDEX.md:144-151`, the names are batch
delete / batch wait / batch poll / cancellation propagation, and 667 is not in
the cluster. Any follow-up sweep should use the index names, not the probe's.

## 5. What to do instead

Run one number per connection. `tools/syscall_isolation_sweep.py` does that:

```bash
python tools/syscall_isolation_sweep.py --ps5-ip 10.0.0.96 --range 661-670 --repeat 2 --save
```

Each number gets its own connection, its own sentinel line printed before the
call, and a classification:

| status | meaning |
|---|---|
| `RETURNED` | the call returned; the value is recorded |
| `RAISED` | `pcall` caught a Lua error |
| `KILLED_IN_CALL` | legacy tool label: sentinel present without a result; not independently confirmed process death |
| `NO_OUTPUT` | connected and sent, nothing came back |
| `CONNECT_FAILED` | could not open a connection; the sweep stops rather than misreporting |

The sentinel narrows the last observed source boundary. It does not distinguish
a slow handler, transport loss, Lua error, process termination, or capture
truncation. Correlate independent console-side observations before diagnosing
a kill, even when the tool's historical status label says `KILLED_IN_CALL`.

Expected outcomes worth distinguishing:

- 661 kills and the others return → the range was closed on one number; the
  rest are measurable and should be probed on their own terms.
- 661 kills and 662-670 also kill → the range verdict was right, and now it has
  ten data points instead of one.
- Some numbers return → the range verdict is wrong and there is a new attack
  surface.

## 6. Limits

- Static artifact analysis plus re-reading existing captures. No console was
  contacted; no probe was sent for this note.
- The 13.60 dumps are an unverified acquisition (`docs/dumps_13.60/README.md`),
  and no authenticated 14.10 kernel image exists in the repository.
- The two sources specify different first-call argument shapes, but neither
  capture records a return or an independent cause of termination.
- `NO_OUTPUT` and `KILLED_IN_CALL` are transport/marker classifications. Neither
  establishes console health or a crash cause; a slow handler after a sentinel
  can receive the latter label too.

## Second sweep: 666 and 667 return, 668 kills (2026-10-20)

Same driver, `--range 666-670`, after a relaunch.

| syscall | status | detail |
|---|---|---|
| 666 | RETURNED | `-1` |
| 667 | RETURNED | `-1` |
| 668 | KILLED_IN_CALL | process terminated inside the call |
| 669-670 | not measured | the process was already gone |

The lethal numbers are now 665 and 668, and both are the ones the 13.60 capture labeled
`nosys` stubs jumping to `0x265760`. The seven numbers that are not stubs (662, 663, 664,
666, 667 measured so far) all return `-1` to six zero arguments and leave the process
alive. One lethal stub could be a mislabel; two matching labels make the stub path itself
the suspect, and testing 668 against a second argument shape would separate "the stub
kills on any call" from "the stub kills on this argument shape".

Capture: `results/phase15_native_sysent/syscall_isolation_sweep_20261020_183119.txt`.

## Third sweep and the stub question: 669 returns, 670 returns 0, 668 kills on any shape

| syscall | status | detail |
|---|---|---|
| 669 | RETURNED | `-1` |
| 670 | RETURNED | `0` |

670 returning `0` to six zero arguments is the only success in the range; it does not
prove the call did anything, only that the handler accepted the arguments.

Then 668 was called again from a probe with a valid writable page in `RDI` and `RSI`
(instead of the sweep's zeros). The process died before the after-line, so 668 is lethal
for at least two different argument shapes. The stub therefore kills on entry or early in
the body rather than only when handed a degenerate argument.

## The range, as measured on 14.10

| syscall | 13.60 label | 14.10 |
|---|---|---|
| 661 | AIO submit | kills |
| 662 | AIO batch delete | `-1` |
| 663 | AIO batch wait | `-1` |
| 664 | AIO batch poll | `-1` |
| 665 | `nosys` stub | kills |
| 666 | batch cancellation | `-1` |
| 667 | process/thread enumeration | `-1` |
| 668 | `nosys` stub | kills (zeros and valid pointers) |
| 669 | separate body | `-1` |
| 670 | separate body | `0` |

The "AIO 661-670 is a hard wall" reading is wrong as stated: seven of the ten numbers were
called and seven returned and left the process alive. What is lethal is 661 and the two
`nosys` stub slots.

## 670's return value is not a side effect (170a, 2026-10-20)

670 returns `0`, but four measurements taken before and after the call are identical:

| measurement | before | after |
|---|---|---|
| `mprotect(RWX)` on a GPU-mapped page (sys 74) | `-1` | `-1` |
| `fork` (sys 2) | `-1` | `-1` |
| sys 587 with a 0x100 buffer | `-1` | `-1` |
| sys 629 | `-1` | `-1` |

So the success return does not unlock W^X, does not unlock process creation and does not
change the credential or sandbox paths tested here. 670 joins 675 in the "returns 0 and
changes nothing observable" group.

Capture: `results/phase17_new_vectors/170a_sys_670_side_effects_20261020_183724.txt`.
