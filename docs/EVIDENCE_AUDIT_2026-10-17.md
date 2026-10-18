# Evidence audit — PS5 14.10 kernel research

This note reconciles the current probe records and the 13.60 syscall dump against claims in the research plan. It is an evidence audit, not an exploit claim.

## Conclusion

The material currently in this repository does not establish a kernel exploit for firmware 14.10. It establishes userland memory access, module information disclosure, and the ability to invoke raw syscall numbers from the Lua loader. It does not establish kernel read/write, an arbitrary kernel function call, or native kernel code execution.

The user’s 13.60 console can provide useful firmware-specific reference data. It cannot, by itself, provide 14.10 handler bytes or prove that a 13.60 vulnerability remains on 14.10. Because there is no separate test console, firmware changes or risky kernel experiments should not be treated as required inputs to this audit.

## 2026-10-18 follow-up

The 45c row above is clarified to separate the saved observations from the probe author's inference. The run exercised selected metadata mutations in one session; the raw log does not identify the complete dispatch implementation. See Finding 56 and the current probe index for the corrected scope. No new console results were collected.

## What the evidence says

| Claim or path | Recorded evidence | Assessment |
|---|---|---|
| Writable fn_addr/ROP chain calls an arbitrary function | Probe 45c recorded sysctl/getpid results persisting after selected fn_addr changes and corruption of chain entries 0–7 in one run | This contradicts the earlier dependency model for those tested calls; it does not identify the full dispatch implementation or prove every path ignores those fields. No call primitive is established. |
| W^X bypass or shellcode execution through `fn_addr` | Probes 44a and 45a–45c saw no execution or shellcode effects; a return value alone did not prove executable permissions | Not demonstrated |
| AF_ROUTE reveals kernel pointers on 14.10 | Probe 43o's RTM_GET write returned `-1`; its 108-byte read echoed the sent request. The sockaddr begins at `+0x5C`, matching the probe's 92-byte header. | The request was not delivered; the leak behavior and any 14.10 patch status are **not established**. |
| AIO raw syscalls expose an exploitable race | Probe 43p stops immediately before its first standard AIO call. Separate probe 19g records `aio_error: rv=-1`, which is a returned error, not a kill. | 43p's outcome is unknown; 19g shows that one `aio_error` invocation returned. No race primitive is demonstrated, and syscall 663 has no recorded 14.10 result. |
| kldstat/kldsym reveal module or symbol addresses | Probes 43a/43b are header-only logs (145 B / 116 B), with no result, error, or kill record. | The cause of truncation and syscall outcomes are unknown; a kernel-level kill is not evidenced. |
| CClosure `+0` controls the Lua C function pointer | Probe 47b's write loop tested `{16,24,32,40,48}`; its notes disagree about `+0`. | `+0` is untested. Neither writable nor read-only is established. |
| Syscall 557 is a vulnerability | Later runs characterize its return as formula/version-dependent; the initial 46a record also had a `%b` formatting error | Behavior to explain, not an exploit primitive |
| Syscall 624 exposes a counter or side channel | Return varied from 3377 to 3376 across separate connections | Insufficient evidence for a counter, side channel, or disclosure |
| Sony syscall surveys cover 532–676 | Saved 51a/51c logs contain fewer records than their attempted counts | Partial coverage only; neither successful return values nor `-1` with invalid arguments prove a vulnerability or a blocked handler |

The raw logs remain authoritative. In particular, `results/51a_sony_syscall_survey_20261016_214814.txt` contains 55 per-call records despite a stated 110 attempts; the later 51a run has 29 records and stops at 560; and `results/51c_sony_survey_part2_20261016_215838.txt` contains results for 625 and 626 only. It does not show syscall 661 being reached. `results/43p_aio_bypass_20261016_180656.txt` stops immediately before the first standard AIO call; it does not show that call killing the process. The separate 19g log records `aio_error` returning `-1`. The 51b report counts 30 call patterns; counting its raw call records including the E/F sweeps yields 47. Neither count establishes a kernel pointer disclosure: the exercised output buffers contained no observed kernel pointers.

## Evidence contradictions and test failures

The following prior statements exceed what their cited artifacts show:

- **AIO kill claim:** documentation said AIO was sandbox-killed, including `aio_error` via `make_syscall`. The 43p log has no call result or kill record; 19g records `aio_error rv=-1`. A process kill is not established.
- **AF_ROUTE patched claim:** documentation said the 14.10 information leak was patched. Probe 43o's RTM_GET write failed (`ret=-1`), and its read returned an echo of the probe's own request. The request did not exercise the alleged disclosure.
- **kldstat/kldsym kill claim:** the 43a and 43b logs contain only their headers. No kill record or syscall result was captured.
- **CClosure read-only claim:** the 47b test omitted offset `+0`; it also labels `+16` writable in one section and describes `+0` inconsistently elsewhere. The C function pointer's writability is unknown.
- **README status conflict:** older text said probes 43a–43p were ready to send while another section said their results were already recorded. Both cannot describe the same state.

Relevant incomplete runs include 42g (the original source failed at an undefined `MB`; that declaration has since been added, but the probe was not rerun), 46a run 1 (Lua 5.1 does not support the `%b` format option), 46a run 2 (truncated during Section F without a completion marker), 42f (one result from an 80-offset scan), 43a/43b (header-only), 43p (stops at the first call marker), and multiple partial 51a/51c syscall surveys. A truncated log cannot distinguish a console crash, loader exit, connection loss, or capture failure without separate console-side evidence.

## Artifact identity and source versions

- The purported kernel ELF is 47,451,147 bytes and its executable segment hash matches the public PS5 13.60 capture. Its strings include `13.60` and omit `14.10`; it is not evidence of 14.10 kernel code.
- A separate `kernel_text.bin` is also identified in the project as a 13.60 capture. The repository has no authenticated 14.10 kernel image; the live console evidence is a FreeBSD `r230171/releases/14.10` version banner.
- The 13.60 syscall dump is useful for comparison and hypothesis formation only. It cannot establish the 14.10 syscall table or prove a 13.60 bug survived an update.
- Full hashes, ELF-header checks, per-claim adjudication, survey counts, source provenance, and the missing-evidence register are in [the detailed independent audit](INDEPENDENT_EVIDENCE_AUDIT_2026-10-17.md).
- The four retests are prepared, not run; their exact questions, evidence anchors, result criteria, and interpretation limits are in [the retest plan](RETEST_PLAN_53.md).

## 13.60 table comparison

The newly captured `docs/dumps_13.60/sysent_index.json` matches the existing 13.60 index in this repository over syscall numbers 0–676 for `narg` and normalized `sy_call_off`. Absolute handler addresses differ as expected when the KASLR base differs. This adds no 14.10 comparison and no new handler layout relative to the repository’s existing 13.60 baseline.

Do not rely on entries 677 and 678 until validated: their `narg` values are implausibly large. The separate `docs/ps5_13.60_sysent.json` name map also needs reconciliation: its `syscalls` object has 308 keys, but only 306 keys in 1–676, and it omits active entries 515, 619, and 635 while including questionable trailing entries. Aggregate syscall counts and names should therefore be treated as provisional until rebuilt from the raw table and checked against the parsed index.

## What is missing for a 14.10 comparison

The repository contains a 13.60 kernel data dump, not a verified 14.10 kernel-code image. The Lua loader on the retail 14.10 console offers no demonstrated kernel read/write or native ELF/kernel execution path, so the existing probes cannot produce a trustworthy 14.10 `.text` dump. A matching decrypted 14.10 firmware image or a verified live 14.10 kernel dump would allow static handler comparison; without one, 14.10-specific handler changes remain unknown.

The public [PS5 vulnerability notes](https://www.psdevwiki.com/ps5/index.php?section=242&title=Vulnerabilities) list Relapse’s AIO issue through 13.60 with a potential patch at 14.00, and mark the Byepervisor suspend/resume issue patched at 14.00 or 14.10. These public entries are useful context, but they do not substitute for a local 14.10 code artifact or establish that the same exploit chain works on 14.10.

## Sensible next work

1. Reconcile the 13.60 name map and entry counts against `sysent_index.json` and the raw `sysent_raw.bin`; validate or exclude entries 677–678.
2. Preserve the exact 14.10 probe inputs, outputs, and crash boundaries, and distinguish observed return behavior from exploitability.
3. If firmware comparison is pursued, obtain and verify a 14.10 kernel-code artifact before attributing any handler difference to that firmware. Do not repeat already-recorded probes without a concrete reason to change their inputs or interpretation.

Until a new artifact or a reproducible primitive appears, the accurate status is: **14.10 kernel exploit not demonstrated by the evidence currently documented here.** The AIO, AF_ROUTE, kldstat/kldsym, and CClosure questions remain open for the prepared probes 53a–53d; those probes have not yet been run.

## Follow-up correction: Sony AIO family

The captured 13.60 table maps syscall 663 to a five-argument wrapper at TEXT+`0x3b01f0`, which jumps to implementation code at TEXT+`0x3b0210`. The AIO family is therefore a legitimate static-review surface. The 14.10 probe source planned a later 532–700 scan containing 663, but the saved run never got past its first standard AIO call (317); planned code is not an observed test. See [the secondary exploit audit](SECONDARY_EXPLOIT_AUDIT_13.60.md) for corrected coverage and limitations.
