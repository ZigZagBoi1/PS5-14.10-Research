# Private 14.10 kernel primitive triage — 2026-10-21

Scope: offline review of saved 14.10 captures. No new console test was run for this note. Keep this note and any positive kernel address/read/write capture on the private `staging` remote until the owner chooses publication.

## Current result

There is **no verified 14.10 kernel pointer or kernel read/write primitive** in the saved results. A kernel-looking value is not enough: it must be shown to originate from a kernel object or text, survive a repeat within the same boot, and exhibit a plausible KASLR change across boots. A claimed read/write primitive also needs a bounded, reversible read and write with independent verification. Do not infer either capability from a process exit, timeout, or an all-zero response.

## Reconciled evidence

| Path | Saved evidence | Assessment |
| --- | --- | --- |
| AF_ROUTE RTM_GET | `results/53b_afroute_retest_20261018_091257.txt` | A 168-byte request was accepted and returned 136 bytes; the response contains no pointer-shaped qword. Deprioritize. |
| Corrected kstack and TCP pcblist MIBs | `results/phase14_final_push/56l_corrected_mib_probe_20261019_184914.txt` | Both corrected size queries returned -1 with no data. Deprioritize. |
| EVFILT_PROC and other kqueue filters | `results/phase17_new_vectors/119a_evfilt_proc_leak_no_self_signal_20261019_185317.txt`; `results/phase17_new_vectors/109a_kernel_infoleak_sweep_20261019_185105.txt` | Registrations and event returns worked, but reported fields are user-controlled or ordinary event data; zero verified pointers. Deprioritize. |
| Direct kldsym(337) | `results/phase15_native_sysent/57c_kldsym_direct_20261019_194850.txt` | Capture ends immediately before the first symbol call. This is an unsafe termination boundary, not a leak. Do not repeat the same call as a first step. |
| Native syscall survey 677–734 | `results/phase15_native_sysent/57a_native_survey_677_734_20261019_195140.txt` | Capture ends before the first per-syscall result. The remaining entries were not surveyed; the first call likely ended the process. Split any future survey into isolated single-call probes with a before/after canary. |
| `virtual_query_by_pid` candidate (728) | `probes/phase15_native_sysent/57a_native_survey_677_734.lua`, `57b_deep_test_natives.lua`; `docs/sysent-names-13.60.csv` | The name and call layouts come from 13.60. No saved 14.10 result shows syscall 728 returned. Even a successful VM query would likely disclose user virtual addresses; require proof before treating it as KASLR evidence. |
| IPv6 MSFILTER | `results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261019_185451.txt` | Join succeeded; all MSFILTER calls returned -1. No reachable read/write path shown. |
| GPU mmap + msync | `results/phase15_native_sysent/58a_msync_reachability_20261019_185431.txt` | Capture ends at the first msync call. No exploit primitive established. |

The broad probe index and strategy still label some of these tests “not run.” Use the individual timestamped captures above for decisions.

## Next 14.10 test order

1. **Establish a safe syscall-dispatch baseline.** In a fresh loader process, run an existing harmless syscall before and after one candidate call, log both results and a server-side termination reason. One candidate per process. The 57a/57c cutoffs show that `pcall` does not protect against native termination.
2. **Deprioritize 728 as an address-leak candidate.** Offline disassembly of the 13.60 `kernel_text.bin` (SHA-256 `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`) confirms the CSV's slot 728 stub at RVA `0x2664d0` jumps to RVA `0xabb660`. The handler reads a PID from argument offset `+0`, an address from `+8`, flags from `+0x10`, and an output pointer/length from `+0x18/+0x20`. At RVA `0xabb8dc` it caps copyout to `0x18` bytes. Earlier it checks a flag bit at `+0x12`, plus two helper gates, and looks up the target process's VM map. This is consistent with a bounded user VM-query record, not a raw kernel-pointer disclosure. The 14.10 slot and gates remain unverified; do not run `57b`'s speculative multi-layout sweep as a KASLR test. If version-matched evidence later supports it, isolate one call with the 13.60 layout and reject userland-only output.
3. **If a repeatable address disclosure appears, validate provenance.** Capture multiple reads during one boot, then across boots; align against a version-matched kernel reference if available. Preserve raw output and hashes privately. Only then investigate a bounded kernel read path. A write test comes last, after read verification and a reversible target are known.

Do not run concurrent races or malformed packet fuzzing to answer the address-disclosure question. Their crash risk and ambiguous output make them poor first tests. No physical PS5 test is authorized by this note.

## Private publication gate

Keep `origin` untouched. Commit selected private files on `private/kernel-leak-triage-20261021` and push that branch to `staging` only. Before any public merge, inspect the branch diff for exploit primitives, console identifiers, network addresses, and captured firmware material. The owner decides when to publish.
