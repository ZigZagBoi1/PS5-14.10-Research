# Corrected sysctl MIBs and ktimer numbering (firmware 14.10, offline review)

Status: corrections + prepared probe. No console was contacted, no capture
was produced, and no kernel read, leak, or vulnerability is established.

Two committed "blocked" verdicts rest on identifiers that are wrong under
the project's own upstream reference (FreeBSD releng/9.0, the maintained
baseline in `docs/STRATEGY.md` and `docs/ATTACK_SURFACE.md`):

1. TCP pcblist and kernel-stack "blocked" rows were recorded against
   sysctl MIBs that are not the upstream leaves for those objects.
2. The ktimer "odd split" (settime works, gettime/delete blocked) follows
   directly from its own transposed syscall numbers — see the 42a
   re-read below.

The fix is a new prepared probe. It is written, sandboxed, and offline-
regressed, but NOT RUN: section D of `docs/PROGRESS_AUDIT.md` explains
that prepared means unrun.

What this note does NOT do: claim a leak, claim the correct leaves will
succeed on 14.10 (Sony's sandbox may refuse them too), re-run or
reinterpret any kernel behavior, or alter any committed capture.

## Contents

- [A. pcblist: the wrong-tree MIB](#a-pcblist-the-wrong-tree-mib)
- [B. kstack: the never-sent leaf](#b-kstack-the-never-sent-leaf)
- [C. ktimer: the transposed pair](#c-ktimer-the-transposed-pair)
- [D. Prepared probe 56l](#d-prepared-probe-56l)
- [E. Offline verification](#e-offline-verification)
- [F. What would change which verdict](#f-what-would-change-which-verdict)
- [G. Deliberately out of scope](#g-deliberately-out-of-scope)

## A. pcblist: the wrong-tree MIB

Prior art: `probes/42h2_rop_exploit2.lua:276` sends

```lua
{{4, 1, 6, 1}, 4, "net.inet.tcp.pcblist"},      -- tcp PCB list
```

and the capture `results/42h2_rop_exploit2_20261016_070945.txt:46`
records `net.inet.tcp.pcblist: blocked (size=0)`. That label feeds the
Dead Ends row `docs/STRATEGY.md:103`, which lists `tcp.pcblist` among
paths that are `ALL blocked`.

Upstream releng/9.0 says the second element is wrong:

- `sys/sys/socket.h`: `AF_UNIX=1`, `AF_INET=2`.
- `sys/netinet/tcp_var.h`: `#define TCPCTL_PCBLIST 11`, registered via
  `SYSCTL_PROC(_net_inet_tcp, TCPCTL_PCBLIST, pcblist, ...)`.

`{4,1,6,1}` walks the PF_LOCAL (AF_UNIX) tree, not the PF_INET tree.
The correct leaf for TCP connection-table records is `{4,2,6,11}` —
`CTL_NET=4, AF_INET=2, IPPROTO_TCP=6, TCPCTL_PCBLIST=11`. No committed
probe or capture sends it: the committed "blocked" verdict was returned
for a query that never addressed the TCP pcblist.

Why it still matters if 14.10 refuses the right leaf: the refusal itself
would be new information — the first verdict attributed to the correct
query instead of the wrong one. The probe's MIB echo makes that
attribution checkable in the capture.

## B. kstack: the never-sent leaf

Prior art sends five different non-kstack leaves under kstack-adjacent
labels:

- `probes/42h2_rop_exploit2.lua:271-274` sends leaves 9, 35, 36, 38.
  Three record `blocked (size=0)`; the leaf-36 rlimit row instead
  returns 4 bytes with 0 kptrs
  (`results/42h2_rop_exploit2_20261016_070945.txt:41-44`).
- `probes/phase9_kaslr_defeat/42d_dmem_kaslr.lua:270-274` sends leaves
  38 and 42 under explicit "kstack" labels.
- `probes/phase14_final_push/56i3_kaslr_deep_scan.lua:287` sends leaf 35
  for "VMMAP" and records
  `KERN_PROC_VMMAP size query ret=0 len=0`
  (`docs/ALL_RESULTS.md:8283`).

Upstream releng/9.0 `sys/sys/sysctl.h` (verified byte-for-byte from the
tag):

| Leaf | Name | Meaning here |
|------|------|--------------|
| 9 | KERN_PROC_SV_NAME | syscall-vector name — not a stack |
| 15 | KERN_PROC_KSTACK | **kernel stacks (never sent)** |
| 32 | KERN_PROC_VMMAP | VM map (not 35) |
| 33 | KERN_PROC_FILEDESC | file descriptors |
| 34 | KERN_PROC_GROUPS | process groups |
| 35 | — | **absent from the upstream table** |

So the committed kstack verdict rests on leaf 9 (a name query), leaf 35
(which upstream does not define), and leaves 36/38/42 (undefined too) —
never leaf 15, the actual `KERN_PROC_KSTACK` whose handler dumps
`struct kinfo_kstack` records (`KINFO_KSTACK_SIZE=1096`, trace strings,
not pointers — `sys/sys/user.h`).

The 56i3 line is the false-negative mechanism demonstrated in committed
captures: querying a nonexistent leaf returned `ret=0 len=0`, exactly the
signature a reader would file under "blocked/empty". Any verdict built
on that shape without a MIB echo cannot distinguish refusal from
misaddressing.

Related damage already found and bounded: 56i3's leaf-33 filedesc
retest IS correct and genuinely returned -1
(`docs/ALL_RESULTS.md:8280`), so that verdict stands. 56i3's leaf-12
pathname and leaf-34 groups sends are also correct. And probe 03's
correct-OID vmmap retest works: 44496 bytes
(`docs/ALL_RESULTS.md:10754-10755`).

## C. ktimer: the transposed pair

Probe 42a binds (`probes/phase8_live_network/42a_ktimer_deep.lua:11-18`):

```lua
sc_ktimer_settime = 236,
sc_ktimer_delete = 237,
```

Upstream releng/9.0 `sys/kern/syscalls.master` numbers them the other
way: `236=ktimer_delete` (1 arg), `237=ktimer_settime` (4 args)
(`238=ktimer_gettime`, agreed by both sides).

The capture then reads differently
(`results/phase8_live_network/42a_ktimer_deep_20261015_233834.txt`):

- `:25-27`: "settime(1s oneshot)" (actually 237/Delete with 4 args)
  returns rv=0, and the immediately following gettime returns rv=-1 —
  exactly what deleting the timer would produce.
- `:39-40`: "delete(real)" (actually 236/Settime with 1 arg) returns
  rv=-1 twice — exactly what calling a 4-arg entry with 1 arg would
  produce.
- `:42`: "create after delete" returns timerid 3 — consistent with the
  id having been freed by the :25 call.

This re-read does not prove upstream numbering on 14.10: the loader or
Sony's table could differ, and both bindings could be stubs. It only
shows the committed "odd split" is what a transposition predicts, which
is why the dead-end row needs the differential, not a verdict flip.

## D. Prepared probe 56l

`probes/phase14_final_push/56l_corrected_mib_probe.lua`
(CRASH_CLASS: LOW, prepared — not run):

- [B] sends `{4,2,6,11}`: size query, bounded data read, kernel-band
  qword scan (`0xFFFF8000 <= hi < 0xFFFFFFFF`, `CLAUDE.md` rule).
- [C] sends `{1,14,15,pid}`: size query, bounded read, parses each
  1096-byte record as tid/state/tracelen (symbol strings, never
  treated as pointers).
- [D] ktimer differential: 4-arg call on 237 against fresh timer A with
  a 238 gettime follow-up, then 1-arg call on 236 against fresh timer B
  with a 238 follow-up. Verdicts are decided from observed returns on
  the console, not from numbering assumptions.

Every sysctl section echoes the MIB back from its own send buffer, so
the capture attributes each result to the leaves actually queried —
the check 42h2 and 56i3 both lacked.

Footprint: read-only except creating/arming/deleting its own POSIX
timers, the same footprint as the already-run 42a. No exploit attempt.

## E. Offline verification

`tools/test_probe56l.lua` loads the probe unmodified (`loadfile` +
`setfenv`) into the `tools/test_probe46a.lua` sandbox convention and
runs three scripted handlers (46 assertions, all passing):

1. Upstream-shaped: correct size/data call shapes, both MIB echoes,
   one kernel-band qword found and echoed, adjacent non-kernel qword
   ignored, one kstack record parsed (`tid=4242 state=0(STACKOK)`),
   both ktimer verdicts from scripted returns.
2. All-refused: MIBs still echoed, every section COMPLETEs, only
   INCONCLUSIVE ktimer verdicts, `=== 56l DONE ===` reached.
3. All-empty (`ret=0 len=0` everywhere): takes the EMPTY branches and
   attributes them to the echoed MIBs — the 56i3 false-negative shape.

The harness caught one real probe bug during development: the early-
return path discarded the size-query return, so `ret=0 len=0` from the
size query never reached the EMPTY branch. Fixed before this note.

```bash
python -c "from lupa.lua51 import LuaRuntime; LuaRuntime().globals().dofile('tools/test_probe56l.lua')"
# test_probe56l: 46 assertions, 0 failures / test_probe56l: OK
```

The sandbox proves probe-internal logic (MIB bytes, branching,
parsing, verdict text) only. It says nothing about 14.10 kernel
behavior, which only a console run can supply.

## F. What would change which verdict

| Console result | Verdict affected | Change |
|----------------|------------------|--------|
| `{4,2,6,11}` returns records | STRATEGY.md:103 pcblist entry | "blocked" → observed behavior |
| `{4,2,6,11}` refused | STRATEGY.md:103 pcblist entry | "blocked (wrong leaf)" → "refused (correct leaf)" |
| `{1,14,15}` returns records | STRATEGY.md:103 kstack entry | "blocked" → observed behavior |
| `{1,14,15}` refused | STRATEGY.md:103 kstack entry | "blocked (wrong leaves)" → "refused (correct leaf)" |
| 237 arms / 236 deletes | STRATEGY.md:100, ATTACK_SURFACE.md:79-83 | relabel to upstream numbering |
| 236 arms / 237 deletes | STRATEGY.md:100, ATTACK_SURFACE.md:79-83 | keep 42a labels, verdict stands |
| mixed | ktimer rows | record per-call behavior, no blanket label |

The correct-leaf sysctl sends are also the missing first step of the
kevent-oracle and sysctl-matrix tracks ranked by the offline
reachability review; they stay unrun until a console is available.

## G. Deliberately out of scope

- kern.proc.all `{1,14,0,0}` and kern.file `{1,15}` keep their correct
  OIDs and their refused verdicts
  (`results/42h2_rop_exploit2_20261016_070945.txt:33-38`): valid dead
  ends, untouched.
- kern.proc.filedesc leaf-33 refusal stands (`docs/ALL_RESULTS.md:8280`).
- The 13.60 sysent arity table is cited only as a second witness for the
  ktimer transposition hypothesis, never as 14.10 kernel fact.
- No scores, captures, or milestones change. New probe file count: 231
  Lua probes, and the manifest is refreshed to match (the 247 text-file
  figure keeps its pre-existing upstream drift, disclosed in the PR).
