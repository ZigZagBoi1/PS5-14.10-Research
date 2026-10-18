# Evidence-audit retest plan (53a–53d)

**Status:** probe sources are prepared and statically reviewed (2026-10-18; no defects found; sources unchanged); none of these probes has been run on the console. The plan tests specific evidence gaps from the 2026-10-17 audit. It does not presume a jailbreak or vulnerability.

## Evidence rules for every run

Save the exact probe source, its SHA-256, the full unedited output, the console firmware/version banner, date/time, and whether the loader or console restarted. Keep each run in its own log. Record the last emitted `BEFORE` marker if output stops. A missing completion marker is **incomplete**, not proof of a crash or kill. A Lua `pcall` error is a Lua-visible error, not proof the kernel terminated the process. A syscall return of `-1` is a return; record `errno` only when the wrapper provides a reliable value.

Do not combine two probes in one request. Probe 53a can stop the current loader session; run it only when the console can be reinitialized. Run 53d after the read-only probes because it briefly writes sentinels into the current process's Lua CClosure and immediately attempts restoration. Preserve a log and check restoration status before interpreting any offset.

## Probe matrix

| Probe | Question reopened | Evidence anchor | Planned result that would advance the claim | What does not count |
|---|---|---|---|---|
| 53a AIO | Does each listed raw AIO syscall return through `make_syscall()`? | `results/43p_aio_bypass_20261016_180656.txt` ends before call 1; `results/phase2_kernel_objects/19g_aio_debug_20261015_193320.txt` shows `aio_error rv=-1` | A complete per-call log with return values, followed by a separate, validly constructed request if a specific API merits deeper testing | `rv=-1` does not mean kill or exploit. A missing tail does not identify a killer. A returned null-pointer call does not establish a usable race primitive. |
| 53b AF_ROUTE | Can a corrected RTM_GET request be delivered and produce a non-echo response? | `results/43o_afroute_kaslr_20261016_180647.txt` has write `ret=-1` and a 108-byte read with zero detected pointers and unresolved attribution | Positive write, followed by a structurally valid response that is not the sent request; retain the complete bytes and classify each variant separately | Socket creation, positive write alone, a request echo, or an unvalidated pointer-shaped qword does not establish a leak or KASLR defeat. Uses `recvmsg(MSG_DONTWAIT)` because prior probes found `F_SETFL(O_NONBLOCK)` cosmetic. |
| 53c kldstat/kldsym | Do the syscall candidates return structured module or symbol data? | `results/43a_kldstat_kaslr_20261016_180703.txt` (145 B) and `results/43b_kldsym_resolve_20261016_180719.txt` (116 B) are header-only | Complete call markers, a successful return, changed output fields, and a candidate address consistent with independently authenticated 14.10 evidence | A `pcall` result, nonzero buffer bytes, or address-shaped number by itself does not establish a kernel pointer disclosure. A 13.60 image cannot validate a 14.10 address. |
| 53d CClosure | Is the candidate C function pointer at `+0` writable, and can each tested value be restored? | `results/47b_cclosure_hijack_20261016_200459.txt`; the write loop omitted `+0` and contains conflicting interpretations | `+0` sentinel readback, immediate restoration, and a subsequent read matching the saved value; report the other offsets independently | Writability alone does not prove that the field controls dispatch or enables code execution. This probe does not attempt a redirect. It stops Lua GC for the brief write/restore sequence, then restarts it. |

## Prepared source SHA-256 (2026-10-18)

Recompute each hash immediately before a run and record it with the raw output. If a probe is edited, the hash below no longer identifies that edited source; record the new value rather than relying on this table.

| Probe | SHA-256 |
|---|---|
| `53a_aio_retest.lua` | `47EC18E10E7D570CCC235D5C37C14D5026AA96242B97515EDFB20A68B27BD01F` |
| `53b_afroute_retest.lua` | `A859041417853BB7E13E4F52C69427126C0599E68F73EF8238C5A529FCC45292` |
| `53c_kldstat_retest.lua` | `0C6A5751A48BB948365176FC5B7E490630C0A21490457349A9F6853801E20E1A` |
| `53d_cclosure_retest.lua` | `3B8268CA694731114DE3090D0F70BD93291E59AB32637B042C5E1933E39638D9` |

## Supplemental incomplete probes

The audit also found two older probes whose source or capture was incomplete:

- **42g:** the original Lua run hit an undefined `MB` before its high-physical scan; the declaration is now present. The source now prints a marker per offset, rejects all-ones/high invalid mmap returns before reading, and reports completion of the 16-offset scan. Its scan logic and offsets are otherwise unchanged.
- **46a:** run 1 stopped on Lua 5.1's unsupported `%b` format option. Run 2 reached Section F but its output ends during the 550–625 neighbor sweep. The source now prints each syscall before invocation, counts tested and live calls, and marks Section G buffer tests.

Run these only when their earlier incomplete coverage matters to the chosen research question. Neither is a replacement for the four focused 53x probes.

## After collection

Update the matching rows in `PROBE_INDEX.md`, append the raw output without editing it, and add a short adjudication to `EVIDENCE_AUDIT_2026-10-17.md`. Keep three levels distinct: **observed behavior**, **interpretation supported by the bytes**, and **unresolved hypothesis**. If evidence contradicts a prior claim, correct the claim and preserve the original log and correction history.
