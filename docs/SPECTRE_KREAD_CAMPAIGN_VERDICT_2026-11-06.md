# Spectre v1 campaign (1199d-1199q) and kread survey (1300a/1300b) — verdict

**Date:** 2026-11-06. Static review of the saved captures from two campaigns that
landed via PR #195 (4TheDoctor, 2026-11-05) and are not yet indexed in
`docs/PROBE_INDEX.md` or `docs/CHANGELOG.md`. No probe was executed and no
console was contacted; every claim below cites a saved capture.

## Verdict (one line)

Both campaigns are **dead ends for a kernel read**: Spectre v1 shows no
speculative signal across dispatch, OOB-sysent, and fd-table shapes, and the
kread/dlsym survey produced zero kernel pointers and zero symbol resolutions.
Neither campaign yields the read the chain still needs.

## Campaign 1 — Spectre v1 / cache timing (probes 1199d-1199q)

Series goal (from the probe headers): build a working cache-timing primitive in
a `thr_new` child thread, then use it to detect Spectre-v1-style speculative
reads across the syscall boundary — first against the sysent bounds check, then
against the fd-table lookup.

What the captures show, in execution order:

- **1199m cache timing works.** Cold/warm clearly distinguishable: hot avg 4.9
  ticks, cold avg 9.4 ticks (ratio 1.9x), warm ≈ 27 ns, cold ≈ 53 ns at
  5.6 ns/tick. Verdict in-capture: "Spectre PRIME+PROBE is feasible with this
  timer." (`results/phase9_kaslr_defeat/1199m-cache-timing_20261105_151615.txt`)
- **1199n kernel cache footprint detected.** A syscall adds ~2.8 ticks (~15 ns)
  to the probe delta; 2/8 L1 sets evicted after getpid. This proves the timer
  can see the kernel's cache effects — the prerequisite — but it is a
  footprint, not a disclosure. (`1199n-kernel-cache-footprint_20261105_153031.txt`)
- **1199o OOB-syscall discriminator: no speculative signal.** Trained
  `50×getpid + 1×sys(677)` gives avg 0.0 ticks vs 3.3 for trained-valid; but
  the untrained baseline is also ~3.3, so OOB ≈ valid, not OOB < valid.
  In-capture verdict: "Kernel may have Spectre v1 mitigations (LFENCE/barrier)."
  (`1199o-spectre-v1-discriminator_20261105_153500.txt`)
- **1199p true OOB sysent range: no speculative signal.** sys(695), sys(735),
  sys(800), sys(4095) all return -1 with avg 0.0-1.0 ticks; getpid avg 2.3.
  In-capture verdict: "OOB syscalls are LIGHTER than getpid — nosys fast path
  confirmed... No speculative signal — kernel likely has Spectre v1 mitigation
  (LFENCE/barrier after bounds check, or AMD microcode fix)."
  (`1199p-spectre-oob-range_20261105_153930.txt`)
- **1199q fstat fd + Zenbleed scan: no speculative signal, no Zenbleed
  gadget.** `fstat(0)` valid avg 1.3 vs `fstat(9999)` untrained 2.5 vs
  `50×fstat(0)+fstat(65000)` 0.0 — the deltas are within noise of the
  `close(-1)` baseline (1.0) and the `50×close(-1)+close(9999)` control (3.0).
  In-capture verdict: "**NO SPECULATIVE SIGNAL in fd lookup** — Both syscall
  dispatch AND fd table lookup are mitigated. Spectre v1 kernel read is DEAD on
  PS5 14.10." The Zenbleed half found zero `vzeroupper` in the 1.5 MB eboot
  scan, so that gadget is unavailable.
  (`1199q-spectre-fstat-fd_20261105_154802.txt`)
- **1199e gadget scan** (prerequisite): rdtsc found at 7 eboot offsets, one
  `clflush` (any), zero `clflush [rdi];ret`, zero `lfence;ret`,
  zero `mfence;ret`, zero `clflushopt`. So the timing primitive is rdtsc-based
  and there is no `clflush;ret` flush gadget — consistent with the series
  falling back to prime+probe rather than flush+reload.
  (`1199e-spectre-gadget-fast_20261105_090851.txt`)

**Assessment.** The timer is real and the kernel cache footprint is measurable
(1199m/1199n), which is the strongest microarch result the project has. All
three disclosure shapes (OOB sysent, deep OOB, fd table) show **no observable
speculative channel**. The instrument cannot separate the two explanations:
a mitigated bounds check (LFENCE / microcode) and an unmitigated-but-channelless
window both read as "OOB lighter than valid" on this timer — on an unmitigated
window the speculated continuation past the bounds check is the same nosys
EINVAL return, which is strictly less architectural work than getpid, hence
strictly less eviction. So the record is "no observable speculative channel in
these shapes; mitigation vs window-too-shallow is not separable by this
instrument", not "mitigations present". This matches the earlier timing-KASLR
closure (56h-56i2: scheduling noise only). Spectre v1 as a kernel read on
14.10 is closed by these captures on measurement; the two intermediate
"footprint detected" results are timing oracles, not disclosures, and do not
change that. (Attribution correction per cobrajet302gt's review on PR #214.)

The Zenbleed caveat is narrower than the in-capture wording: 1199q scanned the
1.5 MB **eboot** for `vzeroupper` and found none, but a syscall-boundary
Zenbleed read rides `vzeroupper` executed by the **resident kernel**, not by
eboot. The right scan is on the kernel image: cobrajet302gt's byte-count of the
retained 13.60 kernel capture finds `C5 FC 77` (vzeroupper) = **0 hits** across
every retained byte (one `C5 FE 77` vzeroall occurrence; raw byte count, no
disassembly). So the Zenbleed closure on 14.10 is **corroborated** by the
13.60 kernel scan, pending the same scan on a 14.10 kernel image — the eboot
scan alone does not close it. One-line reproduction on any capture:
`python3 -c "print(open('kernel.bin','rb').read().count(b'\xc5\xfc\x77'))"`.

Note: 1199d's capture is binary/truncated (536 bytes) and 1199f-1199l are the
child-thread timer plumbing (counting-thread POCs, timer resolution, context).
None of them is a disclosure attempt; the disclosure attempts are 1199o/p/q.

## Campaign 2 — kread survey (probes 1300a/1300b, phase34_kread_survey)

Series goal: sweep the remaining syscall-side read candidates with real
arguments, including the dynlib family with real handles from `get_list2(659)`.

What the captures show:

- **1300a:** `660 dynlib_get_info2` answers for 3 handles (userland segment
  bases only, `kp=0`); `591 dynlib_dlsym` yields 0 kernel pointers;
  `547 query_memory_protection` on kernel VA returns -1 for both the stub page
  and the measured image base (consistent with the fault-oracle finding that
  supervisor pages are present but unreadable); `656` after `debug_init(1)`
  returns -1 for handles 0-5; and the untested-with-real-args batch
  (`647 sdk_ver`, `623 get_gpo`, `641 cpu_usage`, `642 map_stats`,
  `611 paging_stats`, `613 resident_count`, `615 fmem_count`) all return -1.
  Summary: "Total kernel pointers: 0".
  (`results/phase34_kread_survey/1300a_kread_survey_20261105_015027.txt`)
- **1300b:** `659 get_list2` returns 3 handles (0x0, 0x13, 0x14 = eboot.bin,
  libSceFios2.prx, libc.prx); `660` resolves all three with names and segment
  ranges (all userland VAs); `591 dynlib_dlsym` with the real handles resolves
  **0/72 symbols per handle**, and 0 with 593-style handles 0-5. Summary:
  "Total resolved: 0. Kernel pointers: 0".
  (`results/phase34_kread_survey/1300b_dlsym_real_handles_20261105_015555.txt`)

**Assessment.** The 0/72 dlsym result with real handles is the significant new
negative: `dynlib_dlsym` is not merely name-blocklisted (the 591 blocklist we
recovered from the 13.60 capture), it resolves nothing at all from a game
process on 14.10 — so it is not a symbol-resolution path to userland module
addresses either. Combined with 593 (39 userland bases, no kptrs) and 660
(userland segments, no kptrs), the dynlib family's copyouts are confirmed
userland-only across three independent entry points. 547 refusing the measured
kernel image base closes the "read the page you just found" follow-up to the
fault oracle.

## What this changes

- The kernel-read blocker stands. The fault-code oracle still gives presence
  (base + slide per boot) and no content; these campaigns did not add a read.
- The live-vector priority is unchanged: WebKit FontFace (primary) / Canvas
  (secondary), with the second-reclaim page-shape distinction recorded in
  `docs/FONTFACE_SECOND_RECLAIM_RECONCILIATION_2026-11-06.md`.
- Housekeeping: 1199d-1199q and 1300a/1300b are absent from
  `docs/PROBE_INDEX.md` and `docs/CHANGELOG.md`. They should be indexed as
  closed (Spectre v1: no observable speculative channel in the tested shapes —
  mitigation vs channelless window not separable by this instrument; dlsym:
  resolves 0 symbols with real handles) so they are not re-proposed.

## Review-correction ledger

Two instrument corrections from cobrajet302gt's bench review of PR #214/#215
(2026-11-06), both adopted above:

1. **Reconciliation mechanism is in source, not just observed.** The page-shape
   split is enforced by `CSSFontFace::setStatus` status guards, not heap luck:
   every `setStatus` call site in the load pump is guarded by the face's own
   `m_status` (`→Loading` requires `Pending`, `→Success`/`→Failure` require
   `Loading|TimedOut`), and a terminal-`Success` face satisfies no guard, so a
   repeat `document.fonts.load()` on the same faces **cannot** re-arm the walk —
   `S2-b` = 0 is predicted, not observed-once. The fresh-face-per-phase +
   intervening-GC shape manufactures new `Pending` actors whose transitions do
   walk. Design rule this licenses: *the actor in a claim window must be an
   object whose status machine transitions inside it*; repeat-call negatives are
   predicted-silent and must not close a reclamation premise.
   (`Source/WebCore/css/CSSFontFace.cpp` :571, :591-593, :644-704;
   `FontFaceSet.cpp` :153, :207-215; cobrajet302gt/PS5-14.10-Jailbreak-Research
   issue #9.)
2. **Zenbleed scans the wrong binary; Spectre attribution overclaims.** Both
   corrected in the Assessment above: Zenbleed belongs to a kernel-image scan
   (13.60: `C5 FC 77` = 0 hits), and the Spectre record reads "no observable
   speculative channel; mitigation vs channelless window not separable by this
   instrument" rather than "mitigations present".

## Sources

- `results/phase9_kaslr_defeat/1199e-spectre-gadget-fast_20261105_090851.txt`
- `results/phase9_kaslr_defeat/1199m-cache-timing_20261105_151615.txt`
- `results/phase9_kaslr_defeat/1199n-kernel-cache-footprint_20261105_153031.txt`
- `results/phase9_kaslr_defeat/1199o-spectre-v1-discriminator_20261105_153500.txt`
- `results/phase9_kaslr_defeat/1199p-spectre-oob-range_20261105_153930.txt`
- `results/phase9_kaslr_defeat/1199q-spectre-fstat-fd_20261105_154802.txt`
- `results/phase34_kread_survey/1300a_kread_survey_20261105_015027.txt`
- `results/phase34_kread_survey/1300b_dlsym_real_handles_20261105_015555.txt`
- `docs/FAULT_ORACLE_KASLR_14_10.md` (the base/slide oracle these follow up)
