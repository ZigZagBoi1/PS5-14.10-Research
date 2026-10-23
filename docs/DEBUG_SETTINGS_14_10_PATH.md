# PS5 14.10 Debug Settings: offline path

## Finding

The public PS5 UMTX jailbreak demonstrates that the native Debug Settings entry can be enabled after its kernel exploit obtains arbitrary kernel read/write. Its README explicitly says to fully exit Settings and reopen it to see the entry. etaHEN takes a different approach: its Toolbox replaces the Debug Settings entry and patches ShellUI. Neither is a public 14.10 solution.

This repository has a Lua userland entry on 14.10, but no verified 14.10 kernel read/write primitive, no verified 14.10 kernel image, and no 14.10-specific Debug Settings patch. Accordingly, the menu cannot currently be made to appear from the established capabilities alone. Userland Lua execution and edits to syscall-object metadata are insufficient evidence for kernel flag changes or a ShellUI patch.

**20 October 2026 public-status update:** Gezine [posted a video](https://x.com/gezine_dev/status/2112279793911968218) showing firmware 14.10 and the Debug Settings entry. This is evidence that a private method can expose the menu. The post does not disclose an exploit, source, kernel memory read/write traces, or a reproducible primitive. The visible result alone cannot establish arbitrary kernel read/write; a ShellUI change could also expose an entry. Gezine [subsequently stated](https://x.com/gezine_dev/status/2112305945187692606) that the kernel exploit used on 13.xx was patched on 14.00 and that this is not Relapse. The public demonstration changes the status of *menu visibility*, but does not meet this repo's kernel read/write verification criteria.

## Implementation path once prerequisites exist

1. Establish a reproducible 14.10 kernel read/write primitive or an independently verified 14.10 ShellUI process patch capability.
2. Obtain an authenticated 14.10 kernel or ShellUI artifact and identify the precise menu gate. Do not reuse offsets from another firmware.
3. Port the smallest visibility change from a public implementation. Prefer a volatile change, with original bytes/values recorded and a restore path.
4. Audit all reads/writes and firmware guards offline before any console execution. Treat menu visibility and functionality as separate outcomes; the entry may appear while debug functions remain unavailable.
5. Only after physical testing is authorized, evaluate on the console and fully exit/reopen Settings to refresh the menu.

## Sources and limits

- [PS5Dev PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak): documents arbitrary kernel read/write followed by enabling Debug Settings, including Settings refresh.
- [etaHEN](https://github.com/etaHEN/etaHEN): documents its Toolbox as a Debug Settings replacement.
- Local `README.md` and `docs/KERNEL_TARGET_EVIDENCE_REVIEW_2026-10-20.md`: scope of demonstrated 14.10 capabilities and absence of a verified 14.10 kernel image.
- `results/phase1_identity_layout/08_read_offsets_20261015_185427.txt`: captured older-firmware offset table and QA/security/target-ID relationships; these are **not** validated 14.10 offsets.

No physical PS5 testing was performed for this finding.

## Offline candidate review, 20 October 2026

The available captures do not yet support a reproducible path to kernel R/W. The most useful next *offline* work is to obtain an authenticated 14.10 kernel image and compare `exec_args_adjust_args()` with the upstream CVE-2026-7270 fix. That CVE has a precise source-level defect and is single-threaded, but this checkout cannot establish whether Sony's 14.10 code contains it or whether the game-loader context can reach the vulnerable path. See `docs/CVE-2026-7270-ASSESSMENT.md`.

The apparently strong `msync`/CVE-2026-49418 path is weaker than the older notes state: `results/phase15_native_sysent/58a_msync_reachability_20261019_185431.txt` stops before the first `msync(MS_SYNC)` return, and its anonymous `fd=-1` mapping has not been shown to use an unmanaged device pager. The critical `MS_INVALIDATE` path was never observed.

The 14.10 AIO capture establishes a completed one-byte transfer via syscalls 669/664/662, which is a functional I/O path, not a stale-object access. The Relapse AIO race is reported patched on 14.00, and this checkout does not contain evidence for a distinct AIO defect on 14.10. `docs/AIO_14_10_LIVE_2026-10-19.md` records the exact boundary. Syscall 628 mapping sweeps in `results/phase17_new_vectors/101a_*` returned failure for every attempted anonymous and RWX mapping, so that route has no demonstrated W^X bypass.

The next evidence gate is therefore a firmware-matched code finding or a public disclosure with verifiable kernel read and write observations. A visible Settings entry, a userland memory read, or a successful AIO transfer does not satisfy that gate.

## 21 October 2026: PUP result and practical next step

The 13.60 console completed outer decryption of the official 14.10 recovery PUP. The extracted 32,689,664-byte `kernel.bin` exactly matches its decrypted PUP segment, but its whole-file entropy is 7.999994 bits/byte and it has no ELF header or recognizable kernel strings. It is not a verified plaintext image. See [the byte-level extraction analysis](PUP14_EXTRACTION_ANALYSIS_2026-10-21.md). Repeating this outer decryption will not yield 14.10 kernel offsets or a live 14.10 kernel pointer.

The immediate research target is a **reproducible 14.10 kernel-address disclosure** from the existing userland entry. Any candidate must return an address-shaped value, survive controlled repetition across sessions, vary with KASLR as expected, and have a justified link to a kernel object rather than a userland address or unchanged sentinel. A pointer alone is not kernel read/write. A second, separately verified primitive must read and write kernel memory before the native Debug Settings kernel-gate route can be attempted. If a firmware-matched plaintext kernel becomes available from a legitimate dump or independently validated decryption, use it for code/offset analysis; it does not replace the live primitive.

The saved direct `kldsym(337)` capture stops at its first call, and the 677–734 survey stops before a result table. Neither is a positive leak. The 13.60 Relapse primitive is reported patched on 14.00, and no public 14.10 kernel read/write implementation is established in this checkout. A private 14.10 menu demonstration is a useful lead to watch, not a reproducible method.
