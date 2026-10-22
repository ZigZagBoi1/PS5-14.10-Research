# Remaining CVEs: reachability triage for PS5 14.10

Status: **triage, not assessment.** `docs/research/scene_research_oct2026.md`
lists seven CVEs. Four already have notes on master:
[CVE-2026-49412](CVE-2026-49412-PS5-14.10.md),
[CVE-2026-45258](CVE-2026-45258-PS5-14.10.md),
[CVE-2026-58083](CVE-2026-58083-PS5-14.10.md) and
[CVE-2026-7270](CVE-2026-7270-ASSESSMENT.md). This note covers the four that do
not, and answers one question per CVE: **is its precondition reachable by any
path this repository has actually tested?**

No console was contacted. Upstream descriptions are taken from
`docs/research/scene_research_oct2026.md` and are not independently re-verified
here.

## Verdict table

| CVE | subject | PS5 precondition | tested? | verdict |
|---|---|---|---|---|
| 49417 | `/dev/dsp` close-while-mapped UAF | open a sound device, `mmap` it, close | open only (54a) | **blocked at the tested open path**; absence vs denial unresolved |
| 45257 | KTLS receive page-cache overwrite | KTLS active on a socket + `sendfile` over loopback | two basic `sendfile` shapes returned `-1`; no KTLS loopback test | **untested**, KTLS availability unresolved |
| 49416 | `vt(4)` CONS_HISTORY ioctl overflow | open a virtual terminal, `ioctl` it | never (open blocked) | **blocked at the tested open path** |
| 49414 | ELF ASLR disabled for setuid PIE | execute a setuid PIE binary | never | **untested**, precondition itself unestablished |

Two of the four are blocked by earlier results, not by the CVE's difficulty.
Two are genuinely untested, and for both the first unknown is not the CVE
mechanism but a simpler precondition.

## CVE-2026-49417 — `/dev/dsp` close-while-mapped UAF

**Upstream, as recorded:** a UAF when a sound device is closed while a buffer
mapping remains (`docs/research/scene_research_oct2026.md:87-89`).

**Precondition:** an open descriptor on a sound device, a mapping from it, then
`close()` with the mapping still live.

**Repo evidence.** Probe 54a ran twice on 2026-10-18 and tested `open()` only,
with `/dev/null` as a positive control:

```
/dev/null:     OPEN_OK fd=22
/dev/dsp:      OPEN_DENIED_OR_ABSENT ret=0xffffffffffffffffffffffff
/dev/dsp0.0:   OPEN_DENIED_OR_ABSENT ret=0xffffffffffffffffffffffff
/dev/sndstat:  OPEN_DENIED_OR_ABSENT ret=0xffffffffffffffffffffffff
```

(`results/54a_dsp_access_check_20261018_032254.txt:3-7`, source
`probes/phase10_untested_theories/54a_dsp_access_check.lua:24-42`.)

The probe records the limit itself: "accessibility only; CVE trigger and patch
state not tested". Three sound paths failed to open while the control opened,
so the first step of this CVE is not demonstrated. The result does not separate
"no such device" from "open denied", so it also does not prove a sound device
is absent under another name.

**Verdict:** blocked at the tested open path. The same status as
[CVE-2026-45258](CVE-2026-45258-PS5-14.10.md), which shares the precondition.

## CVE-2026-45257 — KTLS receive page-cache overwrite

**Upstream, as recorded:** `sendfile` over loopback with KTLS overwrites page
cache (`docs/research/scene_research_oct2026.md:95-97`).

**Precondition, in order:** (1) a socket with KTLS enabled in receive mode;
(2) `sendfile` from a file into that socket over loopback; (3) the receive
side's page cache as the overwrite target.

**Repo evidence.** The full KTLS loopback path remains untested:

1. **Two basic `sendfile` shapes were issued on 14.10.** The [58d live capture](../results/phase15_native_sysent/58d_shm_sendfile_reachability_20261019_185429.txt)
   records `-1` for flags `0` and `SF_NOCACHE`. Neither call used a KTLS-enabled
   loopback socket, and a `-1` alone does not identify the rejection stage.
2. **KTLS leaves no trace in the artifacts this repository holds.** The
   strings `ktls`, `KTLS` and `SO_TXTLS` do not occur in
   `docs/dumps_13.60/kernel_data.bin` (4 MB, first RVA `0x1000000`). That range
   is a fixed capture, not the whole data segment, so this is a **scope limit,
   not evidence of absence**. `tools/test_tier3_claim_audit.py` pins the
   observation so it cannot drift into a stronger claim.

What the 13.60 sysent does establish: sendfile is a live entry. Slot
`0x265b88` -> body `0x8340e0`, `narg=7`, and the body copies in a 0x20-byte
structure from arg4 (`0x834150` `mov edx,0x20`, `0x834158` call `0x259280`),
which matches `struct sf_hdtr`. That says the number is a sendfile-shaped
handler in 13.60. It says nothing about whether KTLS is compiled into the PS5
kernel, which is the actual gate.

**Verdict:** the CVE path remains untested, and the first unknown is KTLS availability, not the
CVE mechanism. A probe that cannot establish (1) cannot reach (3).

## CVE-2026-49416 — `vt(4)` CONS_HISTORY ioctl overflow

**Upstream, as recorded:** an ioctl overflow in the `vt(4)` console driver
(`docs/research/scene_research_oct2026.md:101-102`).

**Precondition:** an open descriptor on a virtual terminal, then the
`CONS_HISTORY` ioctl with an oversized length.

**Repo evidence.** The open step is already blocked for the console devices
that were tested: "`/dev/console`, `/dev/tty`, `/dev/bpf`, `/dev/crypto`,
`/dev/pf` all blocked" (`docs/FINDINGS.md:616`). The device survey that line
belongs to also records `/dev/null`, `/dev/zero` and `/dev/urandom` opening
successfully, so the block is specific to those nodes rather than to `open()`.

Separately, `ioctl` (54) itself is listed as blocked in
`docs/ATTACK_SURFACE.md:59`, and probe 55c showed the one ioctl multiplexer
that was reachable (sys 622) returning Sony error `0x800E0001` for every
command (`docs/PROBE_INDEX.md:169`). So both halves of the precondition have
failed on tested paths.

**Verdict:** blocked at the tested open path. The specific `CONS_HISTORY`
command has never been issued, and no vt device has been opened.

## CVE-2026-49414 — ELF ASLR disabled for setuid PIE

**Upstream, as recorded:** ASLR can be disabled for setuid PIE binaries
(`docs/research/scene_research_oct2026.md:104-105`).

**Precondition:** execution of a setuid PIE ELF through the normal exec path.

**Repo evidence.** Nothing in this repository addresses either half:

- No probe in `probes/**/*.lua` issues `execve` (59) or any `exec*` variant,
  and no result records one.
- No document records a setuid binary on the PS5 filesystem, an ELF header
  with the setuid bit, or a PIE binary reachable for exec.

The loader's execution model is "send Lua source to a listening process", not
"exec a file"; the process's own entry is the game/loader ELF. Whether any
setuid binary exists on the mounted filesystem is unknown, and the repository
has no filesystem-listing evidence that would answer it.

**Verdict:** untested, with the precondition unestablished. This CVE is also
the lowest-value of the four: it is an information leak (ASLR disable), not an
escalation, and it still requires a setuid binary.

## What a probe would have to establish

In dependency order, so a failure at step 1 stops the chain:

| CVE | step 1 | step 2 | step 3 |
|---|---|---|---|
| 49417 | `open()` succeeds on some sound device path, with errno distinguished | `mmap` that fd and keep the mapping | `close()` with the mapping live, then touch it |
| 45257 | KTLS is present and settable on a socket (`setsockopt` SOL_TLS), or a kernel-side KTLS string/behaviour | `sendfile` from a file into a loopback socket, once, non-destructively | the receive-side page cache as the target |
| 49416 | `open()` succeeds on a vt device | the ioctl number is accepted | an oversized length reaches the copy |
| 49414 | a setuid PIE binary exists and is enumerable | `execve` reaches it through the loader | ASLR state is observable for that image |

None of these is prepared here. Writing one before its step 1 is known would
produce a probe that cannot distinguish "blocked" from "wrong precondition" —
the failure mode behind the 54b syscall-430 mislabel and the AIO 661-670 range
generalization, both corrected on open branches rather than in this note.

## What this note does not establish

- **No CVE is assessed here.** Upstream descriptions are quoted from the
  scene-research note, not re-verified; PS5 patch state is unknown for all four.
- **"Blocked at the tested open path" is not "unreachable".** Probe 54a's
  failure returns no errno, so absence and denial are indistinguishable, and
  an untested device name would not appear in its result.
- **13.60 artifacts say nothing about 14.10.** The sendfile handler shape and
  the absent KTLS strings are 13.60 observations over an unresolved
  acquisition.
- **Absence of a corpus mention is not evidence of absence in the kernel.** It
  is evidence that this repository has not tested the path.
