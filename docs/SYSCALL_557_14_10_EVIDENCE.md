# Syscall 557 on 14.10 — evidence correction: the struct-modification alert is a probe artifact

**Status:** research note, read-only. This note re-reads already-saved probe sources and captures. It records no new console output. It reports (in §9) two offline, sandboxed harness executions of the probe source — one before and one after the helper correction — as a local offline verification of the change-detection helper's classification logic only; they are not console output and carry no evidence about kernel behavior. It does not claim a vulnerability, a writable kernel primitive, an errno value, a fixed interface, or a cross-process cause. Firmware attribution is project provenance, not per-run image authentication (see [§7 Provenance and limitations](#7-provenance-and-limitations)).

**Citation conventions.** Probe-source line numbers in this note are pinned to commit `a14f2792781900c950c6e468843f3698f3acd488` and use immutable GitHub links, because the helper correction described in §8 shifted the later lines in the working tree by one; the resulting shift is recorded in §9. The two probe permalinks are:

- 46a: [`probes/phase11_network_attacks/46a_sony_syscall_deep.lua` @ a14f279](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/a14f2792781900c950c6e468843f3698f3acd488/probes/phase11_network_attacks/46a_sony_syscall_deep.lua)
- 47a: [`probes/phase11_network_attacks/47a_dispatch_deep.lua` @ a14f279](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/a14f2792781900c950c6e468843f3698f3acd488/probes/phase11_network_attacks/47a_dispatch_deep.lua)

A source citation such as `46a:L95-L101` means that permalink with the `#L95-L101` anchor appended. One citation intentionally points at an earlier revision: the `%b` crash line named by the 194741 traceback matches the pre-fix source at commit `6cbdc80` ([`46a_sony_syscall_deep.lua` @ 6cbdc80](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/6cbdc80/probes/phase11_network_attacks/46a_sony_syscall_deep.lua#L283)), but the capture alone does not prove which revision was executed. The raw captures under `results/` are unchanged and are cited repo-relative.

**Subject (historical revision and current state).** This note was drafted against `docs/FINDINGS.md` at the pinned revision `a14f2792781900c950c6e468843f3698f3acd488`, where the 46a-related Finding 57 occupied lines `710-720` and the 46a part of Finding 60 occupied `742-751`. At that revision Finding 57 stated that `(0, {size=0x160})` returned `-1` but "**kernel modified the struct** — first dword changed to `0x160`", and concluded "The struct modification proves the kernel reads AND writes to our buffer." Both quotations are the historical text of that revision, not the current file. That struct-modification claim is a deterministic artifact of the probe's own change-detection helper, not an observation of a kernel write. This note supplies the exact source and capture citations for that correction and bounds what can and cannot be claimed from the remaining records; the current `docs/FINDINGS.md` already carries the corrections recorded in §10 (Finding 57 now at `docs/FINDINGS.md:710-718`, Finding 60 now spanning `docs/FINDINGS.md:740-759`).

## 1. Exact records cited

| Record | Path | Key lines |
|---|---|---|
| 46a helper `fill_dead` | `46a:L91-L93` | `for i = 0, len - 1, 4 do safe_wd(addr + i, 0xDEADDEAD) end` |
| 46a helper `check_modified` | `46a:L95-L101` | `if v and v ~= 0xDEADDEAD then return true end` (default compared value `0xDEADDEAD`) |
| 46a first 557 `{size=0x200}` pattern | `46a:L242-L256` | zero-fill `0..0x1FF`; `safe_wd(st, 0x200)` → header `[0]=0x200`, `[4]=0` (`:244`); `sc557(uint64(st))` (`:245`); check `if st0 ~= 0x200 or st4 ~= 0 or st8 ~= 0` (`:250`) |
| 46a second 557 pattern (`{ver=1,size=0x200}`) | `46a:L257-L262` | zero-fill `0..0x1FF`; `safe_wd(st, 1)`; `safe_wd(st + 4, 0x200)`; `sc557(uint64(st))` |
| 46a `(0, {size=0x160})` pattern + alert | `46a:L264-L272` | `:265` zero-fill; `:266` `safe_wd(st, 0x160)`; `:267` `sc557(uint64(0), uint64(st))`; `:269` `if check_modified(st + 4, 0x50) then`; `:270` `print("  struct modified after offset 4!")`; `:271` `hexdump(st, 64, "  dump")` |
| 46a 620 `{size=0x200}` zero-baseline caller | `46a:L355-L363` | `:356` zero-fill `0..0x1FF`; `:357` `safe_wd(st, 0x200)`; `:358` `sc620(uint64(st))`; `:360` `if check_modified(st + 4, 0x50) then`; `:361-362` `hexdump(st, 64, "  620 struct")` + `scan_kptrs(st, 0x200, ...)` |
| 46a 620 struct dump | `results/46a_sony_syscall_deep_20261016_195704.txt` | `:59` `620(0): ok=true ret=0`; `:68` `620({size=0x200}): ret=0`; `:69-74` `620 struct:` dump (`00 02 00 00` then zeros) and `620 struct: no kernel pointers` |
| 46a run, aborted on `%b` | `results/46a_sony_syscall_deep_20261016_194741.txt` | `:3` `pid: 135`; `:35` `557({size=0x200}): ret=16901`; `:36` `557({ver=1,size=0x200}): ret=518`; `:37` `557(0, {size=0x160}): ret=-1`; `:38` `  struct modified after offset 4!`; `:49` `[string "-- CRASH_CLASS: LOW..."]:283: invalid option '%b' to 'format'` (line 283 of the pre-fix source at commit `6cbdc80`) |
| 46a re-run, completed further | `results/46a_sony_syscall_deep_20261016_195704.txt` | `:3` `pid: 142`; `:35` `557({size=0x200}): ret=1038`; `:36` `557({ver=1,size=0x200}): ret=1039`; `:37` `557(0, {size=0x160}): ret=-1`; `:38` `  struct modified after offset 4!`; `:40-43` dump = `60 01 00 00` at `+000` then zeros |
| 47a struct-input sweep | `47a:L317-L374` | `:326-327` `safe_wd(st, ver)` / `safe_wd(st + 4, 0x200)`; `:341` sentinel refill; `:346-350` monitor `i = 8, 0x1FF` for `v ~= 0xDEADDEAD` |
| 47a capture | `results/47a_dispatch_deep_20261016_195632.txt` | `:3` `pid: 142`; `:64` `ver=0 → ret=16901 (0x4205)`; `:65` `ver=1 → ret=518 (0x206)`; `:319` `ver=255 → ret=772 (0x304)`; `:320` `valid versions found: 256`; `:323-578` `ver=N: no modification` for every tested version; `:580-589` size sweep with ver=0 (`0x10 → 1029` … `0x1000 → 1037`); `:591-593` `557(pid, buf{size=0x200}): ret=-1` and `557(0, buf, 0x400): ret=-1` |

## 2. Observed text, checker mechanism, and unknown hardware effects are three different things

**Observed text (from the captures only).** In both 46a runs the printed lines for the `(0, {size=0x160})` pattern are: `557(0, {size=0x160}): ret=-1`, then `  struct modified after offset 4!`, then a 64-byte dump whose first dword is `60 01 00 00` (`0x160`) and whose remaining shown bytes are `00` (`results/46a_sony_syscall_deep_20261016_195704.txt:37-43`, identical wording at `results/46a_sony_syscall_deep_20261016_194741.txt:37-43`).

**Deterministic checker mechanism (fully explained by the source).** No kernel write is needed to produce this alert:

- `check_modified` (`46a:L95-L101`) returns `true` as soon as it reads one dword that is **not** `0xDEADDEAD`. It is a sentinel-equality test, valid only if the region was first written with `0xDEADDEAD` by `fill_dead` (`46a:L91-L93`).
- The `(0, {size=0x160})` pattern never calls `fill_dead`. It first **zeroes** `st[0..0x1FF]` (`46a:L265`) and then writes `0x160` to `st+0` (`46a:L266`).
- It therefore calls `check_modified(st + 4, 0x50)` (`46a:L269`) on a region that the probe itself left as `0`. Reading `0` gives `0 ~= 0xDEADDEAD`, so the helper returns `true` and the alert at `46a:L270` prints even when the call changed nothing. The warning therefore cannot distinguish "no write" from "some writes". With successful reads throughout the checked window, only an all-`0xDEADDEAD` readback would avoid the alert; read failures are ignored by this helper.
- The same defect appears once more in Section E: the 620 `{size=0x200}` caller (`46a:L355-L363`) also zero-fills `st[0..0x1FF]`, writes `0x200` at `+0`, then calls `check_modified(st + 4, 0x50)` (`46a:L360`). Its conditional dump (`46a:L361-L362`) is therefore printed on the same unchanged zero-filled buffer. This caller prints no "modified" text line; the capture shows only the dump and `620 struct: no kernel pointers` (`results/46a_sony_syscall_deep_20261016_195704.txt:69-74`). The 620 dump is thus a checker artifact too, not evidence of a 620 write.

Consequently the "struct modified after offset 4!" line is produced by the probe's own initialization for an unchanged, zero-filled buffer; it carries no information about kernel writes and cannot distinguish a no-write run from a run that wrote somewhere. The `0x160` in the dump is likewise the value the probe wrote at `46a:L266`, not a kernel-supplied value.

**Unknown hardware effects.** Whether the 14.10 kernel read or wrote this buffer during the call is **not determined** by these records. The saved captures contain no before/after byte comparison that could establish a write, and the alert is explained without one. The corrected claim is narrower than Finding 57's: the record shows a `-1` return and a probe-generated dump; it does not show a kernel write.

**The helper is not universally broken.** Section B and the other `buf` patterns do call `fill_dead(buf, 0x400)` before `check_modified(buf, 0x100)` (e.g. `46a:L166-L169`), and the captures print no `*** BUFFER MODIFIED ***` line for those `-1` returns. The defect is specific to the two zero-baseline callers — the 557 `(0, {size=0x160})` pattern (`46a:L269`) and the 620 `{size=0x200}` pattern (`46a:L360`) — which use the sentinel-based checker on a zero-initialized buffer. Every other `check_modified` call is preceded by `fill_dead` on the same buffer, so it keeps the default `0xDEADDEAD` expectation. The `{size=0x200}` 557 pattern instead compares three explicit expected values (`if st0 ~= 0x200 or st4 ~= 0 or st8 ~= 0`, `46a:L250`) — a different, expected-value style of check.

## 3. Why the alert's invalidity does not prove "no writes anywhere"

The printed dump is `hexdump(st, 64, "  dump")` (`46a:L271`), i.e. bytes `+0x00..+0x3F`. The checked window is `check_modified(st + 4, 0x50)` (`46a:L269`), whose dword reads span `st+4` through `st+0x53` (loop `i = 0, 0x4C, 4` over `addr = st+4`). So:

- the checked window (`+4..+0x53`) extends `0x14` bytes past the 64-byte dump (`+0x3F`); the dump does not even display everything the checker examined;
- the checker examined a region the probe had zero-filled, so its verdict reflects initialization, not kernel behavior;
- nothing in this pattern observes `st+0x54..st+0x1FF` or any address outside `st`.

Therefore the corrected reading is: this record does **not** establish that the kernel wrote, and it also does **not** establish that the kernel wrote nothing anywhere. The alert is uninformative in both directions for the unobserved ranges. The 620 caller's dump (`46a:L361`) is the same `hexdump(st, 64, ...)` size, so it carries the identical 64-byte limitation.

## 4. The two 46a runs and their captured return pairs

The two saved 46a captures come from two separate runs whose observed output differs in format-code behaviour — the earlier capture aborts on `%b`, the later one runs past that point. The captures do not authenticate the executed source byte-for-byte, so this note does not assert that both runs executed an identical revision; it records only what each capture shows:

- `results/46a_sony_syscall_deep_20261016_194741.txt` (`pid: 135`, `:3`): `{size=0x200} → 16901` (`:35`; raw header `[0]=0x200`, `[4]=0`, single-arg `sc557(uint64(st))`), `{ver=1,size=0x200} → 518` (`:36`; raw header `[0]=1`, `[4]=0x200`). This run aborts during Section D on `invalid option '%b' to 'format'` (`:49`). The traceback names line 283 of the executed source. That line number matches the pre-`%b`-fix revision `6cbdc80`, where line 283 is `print("16901 binary = " .. string.format("%016b", 16901))`, and the pinned revision `a14f279` already contains the manual `to_bin` replacement there (`46a:L283-L291`, with `46a:L283` a comment). The match is consistent with that revision having been executed, but the log alone does not prove which commit ran. This run never reached Sections E/F.
- `results/46a_sony_syscall_deep_20261016_195704.txt` (`pid: 142`, `:3`): `{size=0x200} → 1038` (`:35`; same raw header `[0]=0x200`, `[4]=0`), `{ver=1,size=0x200} → 1039` (`:36`; header `[0]=1`, `[4]=0x200`). This run passes Section D and Section E and its capture ends inside Section F.

The captured return pairs therefore differ between the two runs: **16901/518** in the earlier capture versus **1038/1039** in the re-run. The saved logs contain no per-run state that identifies why; neither a fixed interface nor a fixed errno is established by them, and the two captures must not be merged into one "557 returns X" statement. (Only `16901 = 0x4205` is printed by a capture, at `results/46a_sony_syscall_deep_20261016_195704.txt:46`; `518 = 0x206`, `1038 = 0x40E`, and `1039 = 0x40F` are conversions computed offline for this note, not values printed in that capture.)

**The two 46a calls are not a version sweep.** Their raw header words differ: the first pattern writes `[0]=0x200`, `[4]=0` (`46a:L244`), whereas the second writes `[0]=1`, `[4]=0x200` (`46a:L259-L260`) — and both use the single-argument call `sc557(uint64(st))` (`46a:L245`, `46a:L261`). Because the header layout is not held constant across the pair, the return pair carries no linear or monotonic meaning: `16901`/`1038` (first pattern) must not be labelled "version 0" evidence, and no base value may be inferred by differencing the two numbers. The numeric coincidence with 47a's version-zero return (`16901`, §5) is likewise not a shared layout — 47a writes `[0]=0`, `[4]=0x200` for that call (`47a:L326-L327`), which is the opposite arrangement from 46a's first pattern.

## 5. What the 47a "no modification" checks actually bound

`47a` runs the version sweep with version at `+0` and size `0x200` at `+4` (`47a:L326-L327`), i.e. header `[0]=ver`, `[4]=0x200`, single-arg `sc557(uint64(st))` (`47a:L328`). For `ver = 1..255` the recorded return is `517 + ver` (`ver=1 → 518` at `results/47a_dispatch_deep_20261016_195632.txt:65`, through `ver=255 → 772` at `:319`); `ver=0 → 16901` (`:64`) is a single exception to that pattern, not its base. Note this 16901 is the return for header `[0]=0`, `[4]=0x200`, which is a different layout from 46a's first pattern (`[0]=0x200`, `[4]=0`, §4) despite the matching number. Its per-version output-buffer check (`47a:L339-L374`) refills `st[0..0x3FF]` with `0xDEADDEAD` (`47a:L341`), rewrites `st+0`/`st+4` with the tested values, calls `sc557`, then counts dwords in `i = 8, 0x1FF` that differ from `0xDEADDEAD` (`47a:L346-L350`); every version prints `ver=N: no modification` (`results/47a_dispatch_deep_20261016_195632.txt:323-578`).

That result is bounded as follows, and should not be stated as a universal negative:

- it covers only the dword-sampled window `st+8..st+0x1FF` of the `0x400` allocation; `st+0..st+7` (probe-written values) and `st+0x200..st+0x3FF` are not monitored;
- it is still a sentinel-equality test, so a kernel write whose value equals `0xDEADDEAD` would not be detected;
- it reports one probe run's sampled dwords, not an exhaustive byte comparison.

Within those bounds, the 47a record is a cleaner negative than 46a's pattern 3, because 47a did prefill the monitored window with the sentinel it compares against. The 47a Section E patterns (`47a:L391-L439`; sentinel refill `:393`/`:419`, monitors `i = 8, 0xFF` at `:401-L403` and `i = 0, 0xFF` at `:423-L425`; `results/47a_dispatch_deep_20261016_195632.txt:591-593`) likewise return `-1` with no modification reported for `557(pid, buf{size=0x200})` and `557(0, buf, 0x400)`, again only over their sampled windows.

## 6. Same-header return confound (optional, causality unknown)

Within the compared set — the two 46a 557 patterns and 47a's version sweep — the only header that is byte-identical is 46a's second pattern (`[0]=1`, `[4]=0x200`, `46a:L259-L260`) and 47a's `ver=1` step (`[0]=1`, `[4]=0x200`, `47a:L326-L327`); both call `sc557(uint64(st))` with a single argument (`46a:L261`, `47a:L328`). And 46a's *first* pattern (`[0]=0x200`, `[4]=0`, `46a:L244`) is a different layout from 47a's `ver=0` step, so its numbers cannot be compared with the version sweep. For the one identical header, `results/46a_sony_syscall_deep_20261016_194741.txt:36` and `results/47a_dispatch_deep_20261016_195632.txt:65` both report `518`, while `results/46a_sony_syscall_deep_20261016_195704.txt:36` reports `1039`.

The same PID (142) is recorded for the 195704 re-run (`results/46a_sony_syscall_deep_20261016_195704.txt:3`) and for 47a (`results/47a_dispatch_deep_20261016_195632.txt:3`), yet for the one identical header (`[0]=1`, `[4]=0x200`) those two runs recorded `1039` and `518` respectively. Only that identical-header pair is compared here; the other numbers (`1038`, `16901`) belong to different header layouts and are not mixed in. These are cross-run observations only: the saved logs do not contain the run state needed to explain the difference, and no dependence on PID, connection identity, or a fixed interface is established here. **Causality is unknown.** This is recorded only because the identical struct header produced different returns across runs, which is a reason to treat the numeric returns as run-dependent observations rather than a characterized interface.

## 7. Provenance and limitations

- The 14.10 label is project/loader provenance, not per-run firmware attestation. The identity capture `results/phase1_identity_layout/01_identity_20261015_184244.txt:1-7` opens with `=== 14.10 RECON: IDENTITY ===` and records `PLATFORM: ps5` and `FW_VERSION: 14.10` at `:6`, and `README.md:1-11` frames the work as `# PS5 Firmware 14.10 - Kernel Research` while stating that **no verified 14.10 kernel image is available here**.
- The 46a/47a captures themselves contain no firmware banner or image digest; they record only the loader-reported PID and the probe's own output. The "14.10" attribution for these runs is therefore the recorded project provenance, not original-image authentication of the console that produced them.
- No 13.60 artifact is used to infer 14.10 behavior here, and no new console run was performed for this note. The repository's 13.60 range-based captures are separately flagged as having unresolved acquisition authenticity (`README.md:9-11`) and cannot supply 14.10 handler behavior.
- `syscall 620` returned `0` for every tested input (`results/46a_sony_syscall_deep_20261016_195704.txt:59-68`); that return behavior is out of scope for this 557 correction. Its zero-baseline struct caller (`46a:L355-L363`, `:360`) shares the same checker defect as 557 pattern 3, so the 620 dump in the capture is not evidence of a 620 write either.

## 8. Controlled 14.10 retest plan (not run here)

The following is a plan described in prose for a real 14.10 console run. It is **not** a new probe file and it has not been executed; no console output from it exists in this note. The separate local offline harness outcome (which validates only the checker logic) is recorded in §9.

**Applied source correction** (already present in the working tree at `probes/phase11_network_attacks/46a_sony_syscall_deep.lua`): the helper is now `check_modified(addr, len, expected)`, which defaults `expected` to `0xDEADDEAD` only when `expected` is `nil` and compares each dword to `expected` instead of to the literal sentinel; **both** zero-baseline call sites — the 557 `(0, {size=0x160})` pattern (`46a:L269`) and the 620 `{size=0x200}` pattern (`46a:L360`) — now call `check_modified(st + 4, 0x50, 0)`. Every sentinel caller (which passes no third argument) keeps the default `0xDEADDEAD` expectation, and read-failure semantics are unchanged; the only changed callers are the two that zero-initialize instead of sentinel-filling. All syscall numbers and input arguments stay unchanged.

The controlled retest, using the corrected source, should:

1. **Keep the call shape identical** to `46a:L264-L267`: a `0x200`-byte allocation, zero-fill `st[0..0x1FF]`, write `0x160` to `st+0`, then `sc557(uint64(0), uint64(st))`; and record the raw returned value unchanged.
2. **Keep the initialized bytes identical** to that pattern (all-zero region plus the probe's own `0x160` at `+0`), so the corrected check's `expected = 0` matches the actual pre-call contents.
3. **Capture before/after bytes of the full region**, not a 64-byte dump: snapshot at least `st[0..0x1FF]` immediately before and immediately after the single call, and print the two snapshots plus the list of offsets whose value changed. The comparison is before/after, so the verdict does not depend on any sentinel value.
4. **Include a same-process no-call control**: perform the identical zero-fill and the `0x160` write, print the before/after snapshots, and read the region again without invoking 557, to establish the probe-only baseline for the same process.
5. **Include same-process repeated controls**: repeat the identical call several times in the same session and record each raw return and each before/after delta, so run-to-run variation within one process is visible.
6. **Report the raw return and the raw before/after bytes**, without converting a `-1` return into an errno and without attributing any difference to a named interface.

Interpretation rules for that retest: a pre/post byte difference inside the observed region would show the probe observed the buffer change, still without identifying the interface; a `-1` return alone identifies no errno; and only the observed region can be reported, not "the buffer" or "the kernel" as a whole.

## 9. Local offline harness outcome (sandbox, not hardware)

The probe source was run locally offline under a Lua 5.1 sandbox (Lupa 2.8, `from lupa.lua51 import LuaRuntime`) with:

```
python -c "from lupa.lua51 import LuaRuntime; LuaRuntime().globals().dofile('tools/test_probe46a.lua')"
```

**Before the helper fix** (original sentinel-only `check_modified`) the run reported:

```
test_probe46a: 8 assertions, 3 failures
```

with these failing labels in the harness stdout:

```
nowrite: zero-baseline pattern3 not reported
nowrite: 620 zero struct not reported
zero inject just outside range: not reported
```

The first two are exactly the false positives analysed in §2: the harness expects an unchanged, zero-initialized buffer to be left unreported, and the sentinel-only helper instead classifies it as modified because the checked dwords (`0`) differ from `0xDEADDEAD`. The third is the same baseline false positive persisting alongside an injected write at `+0x54`, just outside the checked `+4..+0x53` window: the pre-fix checker already ignores that offset, so the failure is again the unconditional `0xDEADDEAD` comparison and not a bounds failure of the original checker. The harness's positive cases — writes injected inside the checked window — are reported as modified in the pre-fix run and remain so after the fix.

**After the helper fix** (helper accepts an `expected` baseline, defaulting to `0xDEADDEAD`, with explicit `0` at both zero-baseline callers) the same command reported:

```
test_probe46a: 8 assertions, 0 failures
test_probe46a: OK
```

**Independent throwaway run of the actual probe source.** A separate one-off Lua 5.1 execution of `probes/phase11_network_attacks/46a_sony_syscall_deep.lua` itself (not the permanent harness file) reproduced both directions: the no-write control emitted `557(0, {size=0x160}): ret=-1` with no alarm and no 620 struct dump, while an injected `0xA5A5A5A5` at `st+4` emitted the alert and a dump beginning `60 01 00 00 a5 a5 a5 a5`. These runs are local and offline: no console was contacted and no files were created.

**Scope.** The harness executes the actual probe source in a sandbox, so it exercises the probe's own change-detection and bounds logic; it does not execute syscall 557, does not touch a console, and carries no information about kernel behavior (§2, §7). It confirms only that the corrected helper classifies unchanged buffers as unmodified and honours the checked window.

**Line-number note.** The applied fix shifted the later source lines by one relative to the pinned revision cited throughout this note. In the current working tree: the helper is `46a:L95-L102`; the 557 `(0, {size=0x160})` syscall call `sc557(uint64(0), uint64(st))` is `46a:L268` and its change-detector call `check_modified(st + 4, 0x50, 0)` is `46a:L270`; the 620 syscall call `sc620(uint64(st))` is `46a:L359` and its detector call `check_modified(st + 4, 0x50, 0)` is `46a:L361`. Every citation in this note remains pinned to commit `a14f2792781900c950c6e468843f3698f3acd488`, where the helper is `46a:L95-L101` and the two detector calls are `46a:L269` and `46a:L360`; the pinned citations therefore stay correct as written.

## 10. Applied finding corrections

- Finding 57 (historical `docs/FINDINGS.md:710-720`; now `docs/FINDINGS.md:710-718`): the kernel-modified-the-struct claim and the "proves the kernel reads AND writes" conclusion are removed; the `-1` return and the `0x160`-first-dword observation are kept, with the first dword stated to be the value the probe wrote at `46a:L266` and the alert stated to be a checker artifact.
- Finding 60 (historical `docs/FINDINGS.md:742-751`; now `docs/FINDINGS.md:740-759`): the run-dependent return observations and the "limited observations / no exploit demonstrated" framing are kept, with the added statement that the struct-modification claim there derives from the same checker artifact and with the two 46a runs kept distinct and their return pairs separate. The 620 zero-baseline caller (`46a:L355-L363`) is corrected alongside the 557 caller, but the core retraction in this note remains the 557 struct-modification claim.
- Finding 60 layout precision (applied): each 557 call is labelled by its raw header words and call shape (§4). 46a's first pattern is `[0]=0x200`, `[4]=0` (`46a:L244`), not a "version 0" case, and the 46a pair (`16901`/`518`, `1038`/`1039`) is not presented as a version sweep or used to infer a base value, because the header layout is not held constant across the two calls. Within the compared set, the only header shared byte-for-byte with the 47a version sweep is `[0]=1`, `[4]=0x200` (§6).
